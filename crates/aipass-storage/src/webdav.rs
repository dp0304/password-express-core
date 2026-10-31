// SPDX-License-Identifier: Apache-2.0
//! `WebDavStore` — WebDAV backend. **Experimental (V1.1, 实验性)**, design doc §10.1:
//! "检验 ETag、条件请求和并发语义；不合格服务仅支持备份".
//!
//! * `GET` / `PUT` / `DELETE` on `<base>/<key>`; `PUT` sends `If-None-Match: *` or
//!   `If-Match: "<etag>"`; `412` → [`PutOutcome::PreconditionFailed`].
//! * Missing parent collections (`409` on `PUT`) are created top-down with `MKCOL`.
//! * Listing walks the tree with `PROPFIND Depth: 1` (many servers disable
//!   `Depth: infinity`) and parses the `multistatus` with `quick-xml`.
//! * When a server returns no `ETag` on `PUT`, the store asks with `PROPFIND Depth: 0`.
//!   That read is not atomic with the write; servers that need it are expected to also
//!   fail the conditional-update probes of the capability test.
//! * WebDAV servers differ widely in how (and whether) they honour conditional requests.
//!   **Only the capability test decides**: anything that does not prove atomic create-only
//!   and compare-and-swap is reported `backup_only` (仅可备份).
//!
//! Authentication: HTTP Basic (username + password, over https only) or none. Passwords
//! are zeroized and never appear in `Debug`, errors or [`ObjectStore::describe`].

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use aipass_crypto::SecretString;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use percent_encoding::percent_decode_str;
use reqwest::Method;
use reqwest::header::{HeaderMap, HeaderValue};
use tokio::sync::Mutex;
use url::Url;

use crate::httputil::{self, quote_etag, response_etag, transport_error};
use crate::{
    Object, ObjectMeta, ObjectStore, PutCondition, PutOutcome, StorageDescription, StorageError,
    validate_key, validate_prefix,
};

const PROPFIND_BODY: &str = r#"<?xml version="1.0" encoding="utf-8"?><d:propfind xmlns:d="DAV:"><d:prop><d:resourcetype/><d:getetag/><d:getcontentlength/><d:getlastmodified/></d:prop></d:propfind>"#;

/// Maximum number of collections visited by one listing.
const MAX_LIST_COLLECTIONS: usize = 100_000;

/// Non-secret WebDAV settings plus the (secret) password.
#[derive(Clone)]
pub struct WebDavConfig {
    /// Collection URL dedicated to AI Pass, e.g. `https://dav.example.com/remote.php/dav/files/me/aipass/`.
    pub base_url: Url,
    /// Basic-auth username.
    pub username: Option<String>,
    /// Basic-auth password / app password.
    pub password: Option<SecretString>,
    /// Permit plain `http` to non-loopback hosts (development only).
    pub allow_http: bool,
    /// Per-request timeout.
    pub timeout: Duration,
}

impl core::fmt::Debug for WebDavConfig {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("WebDavConfig")
            .field("base_url", &self.base_url.as_str())
            .field("username", &self.username)
            .field("password", &self.password.as_ref().map(|_| "[REDACTED]"))
            .finish()
    }
}

impl WebDavConfig {
    /// Settings without credentials.
    pub fn new(base_url: Url) -> Self {
        Self {
            base_url,
            username: None,
            password: None,
            allow_http: false,
            timeout: httputil::DEFAULT_TIMEOUT,
        }
    }

    /// Basic-auth credentials.
    pub fn with_basic_auth(mut self, username: impl Into<String>, password: SecretString) -> Self {
        self.username = Some(username.into());
        self.password = Some(password);
        self
    }
}

/// WebDAV object store (experimental).
#[derive(Clone)]
pub struct WebDavStore {
    cfg: Arc<WebDavConfig>,
    base: Url,
    http: reqwest::Client,
    known_collections: Arc<Mutex<HashSet<String>>>,
}

impl core::fmt::Debug for WebDavStore {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("WebDavStore")
            .field("base", &self.base.as_str())
            .finish_non_exhaustive()
    }
}

struct DavEntry {
    /// Path relative to the base collection, without a trailing slash.
    rel: String,
    is_collection: bool,
    etag: Option<String>,
    size: u64,
    modified_at: Option<DateTime<Utc>>,
}

fn method(name: &str) -> Method {
    Method::from_bytes(name.as_bytes()).unwrap_or(Method::GET)
}

impl WebDavStore {
    /// Create with a default client.
    pub fn new(cfg: WebDavConfig) -> Result<Self, StorageError> {
        let http = httputil::build_client(cfg.timeout)?;
        Self::with_client(cfg, http)
    }

    /// Create with a caller-supplied client (should not follow redirects).
    pub fn with_client(cfg: WebDavConfig, http: reqwest::Client) -> Result<Self, StorageError> {
        httputil::check_url(&cfg.base_url, cfg.allow_http)?;
        if cfg.password.is_some()
            && cfg.base_url.scheme() != "https"
            && !cfg.allow_http
            && !httputil::is_loopback(&cfg.base_url)
        {
            return Err(StorageError::Backend {
                status: None,
                message: "WebDAV credentials require https".into(),
            });
        }
        let mut base = cfg.base_url.clone();
        if !base.path().ends_with('/') {
            let p = format!("{}/", base.path());
            base.set_path(&p);
        }
        base.set_query(None);
        base.set_fragment(None);
        Ok(Self {
            cfg: Arc::new(cfg),
            base,
            http,
            known_collections: Arc::new(Mutex::new(HashSet::new())),
        })
    }

    fn url(&self, rel: &str) -> Result<Url, StorageError> {
        self.base.join(rel).map_err(|_| StorageError::InvalidKey)
    }

    fn auth_header(&self) -> Option<HeaderValue> {
        let user = self.cfg.username.as_deref()?;
        let pass = self.cfg.password.as_ref().map(|p| p.expose()).unwrap_or("");
        let raw = zeroize::Zeroizing::new(format!("{user}:{pass}"));
        let token = zeroize::Zeroizing::new(standard_b64(raw.as_bytes()));
        let mut v = HeaderValue::from_str(&format!("Basic {}", token.as_str())).ok()?;
        v.set_sensitive(true);
        Some(v)
    }

    async fn send(
        &self,
        m: Method,
        rel: &str,
        mut headers: HeaderMap,
        body: Vec<u8>,
    ) -> Result<(u16, HeaderMap, Vec<u8>), StorageError> {
        let url = self.url(rel)?;
        if let Some(a) = self.auth_header() {
            headers.insert(reqwest::header::AUTHORIZATION, a);
        }
        let resp = self
            .http
            .request(m, url)
            .headers(headers)
            .body(body)
            .send()
            .await
            .map_err(|e| transport_error(&e))?;
        let status = resp.status().as_u16();
        let h = resp.headers().clone();
        let b = resp.bytes().await.map_err(|e| transport_error(&e))?;
        Ok((status, h, b.to_vec()))
    }

    /// Create every collection on the path to `key` (top-down).
    async fn ensure_collections(&self, key: &str) -> Result<(), StorageError> {
        let segs: Vec<&str> = key.split('/').collect();
        let mut cur = String::new();
        for seg in &segs[..segs.len().saturating_sub(1)] {
            cur.push_str(seg);
            cur.push('/');
            if self.known_collections.lock().await.contains(&cur) {
                continue;
            }
            let (status, _, _) = self
                .send(method("MKCOL"), &cur, HeaderMap::new(), Vec::new())
                .await?;
            match status {
                // created / already exists (405 per RFC 4918 §9.3.1; some servers 301/409)
                200 | 201 | 204 | 301 | 405 => {
                    self.known_collections.lock().await.insert(cur.clone());
                }
                401 | 403 => return Err(StorageError::Unauthorized),
                s => {
                    return Err(StorageError::Backend {
                        status: Some(s),
                        message: "could not create collection".into(),
                    });
                }
            }
        }
        Ok(())
    }

    async fn propfind(
        &self,
        rel: &str,
        depth: &str,
    ) -> Result<Option<Vec<DavEntry>>, StorageError> {
        let mut h = HeaderMap::new();
        h.insert(
            "depth",
            HeaderValue::from_str(depth).unwrap_or(HeaderValue::from_static("1")),
        );
        h.insert(
            reqwest::header::CONTENT_TYPE,
            HeaderValue::from_static("application/xml; charset=utf-8"),
        );
        let (status, _, body) = self
            .send(
                method("PROPFIND"),
                rel,
                h,
                PROPFIND_BODY.as_bytes().to_vec(),
            )
            .await?;
        match status {
            207 => {}
            404 => return Ok(None),
            s => return Err(httputil::status_error(s, None)),
        }
        let text = std::str::from_utf8(&body).map_err(|_| StorageError::Backend {
            status: Some(207),
            message: "multistatus is not UTF-8".into(),
        })?;
        let root = crate::xml::parse(text).map_err(|_| StorageError::Backend {
            status: Some(207),
            message: "multistatus is not valid XML".into(),
        })?;
        let base_path = percent_decode_str(self.base.path())
            .decode_utf8_lossy()
            .into_owned();
        let mut out = Vec::new();
        for r in root.children_named("response") {
            let Some(href) = r.child_text("href") else {
                continue;
            };
            // href may be an absolute URL or an absolute path
            let path = match Url::parse(href) {
                Ok(u) => u.path().to_owned(),
                Err(_) => href.to_owned(),
            };
            let path = percent_decode_str(&path).decode_utf8_lossy().into_owned();
            let Some(rel_path) = path.strip_prefix(&base_path) else {
                continue;
            };
            let is_collection_href = rel_path.ends_with('/');
            let rel_path = rel_path.trim_end_matches('/').to_owned();
            let mut entry = DavEntry {
                rel: rel_path,
                is_collection: is_collection_href,
                etag: None,
                size: 0,
                modified_at: None,
            };
            for ps in r.children_named("propstat") {
                let ok = ps
                    .child_text("status")
                    .is_none_or(|s| s.split_whitespace().nth(1) == Some("200"));
                if !ok {
                    continue;
                }
                let Some(prop) = ps.child("prop") else {
                    continue;
                };
                if let Some(rt) = prop.child("resourcetype")
                    && rt.child("collection").is_some()
                {
                    entry.is_collection = true;
                }
                if let Some(e) = prop.child_text("getetag").filter(|e| !e.is_empty()) {
                    entry.etag = Some(httputil::unquote_etag(e));
                }
                if let Some(n) = prop
                    .child_text("getcontentlength")
                    .and_then(|s| s.parse().ok())
                {
                    entry.size = n;
                }
                if let Some(d) = prop
                    .child_text("getlastmodified")
                    .and_then(|s| DateTime::parse_from_rfc2822(s).ok())
                {
                    entry.modified_at = Some(d.with_timezone(&Utc));
                }
            }
            out.push(entry);
        }
        Ok(Some(out))
    }

    async fn current_etag(&self, key: &str) -> Result<Option<String>, StorageError> {
        Ok(self
            .propfind(key, "0")
            .await?
            .and_then(|v| v.into_iter().find(|e| e.rel == key).and_then(|e| e.etag)))
    }
}

/// Standard base64 with padding (HTTP Basic).
fn standard_b64(input: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(input)
}

#[async_trait]
impl ObjectStore for WebDavStore {
    async fn get(&self, key: &str) -> Result<Option<Object>, StorageError> {
        validate_key(key)?;
        let (status, headers, body) = self
            .send(Method::GET, key, HeaderMap::new(), Vec::new())
            .await?;
        match status {
            200 => {
                let etag = response_etag(&headers)
                    .unwrap_or_else(|| format!("local-{}", crate::etag_for(&body)));
                Ok(Some(Object { bytes: body, etag }))
            }
            404 | 410 => Ok(None),
            s => Err(httputil::status_error(s, None)),
        }
    }

    async fn put(
        &self,
        key: &str,
        bytes: Vec<u8>,
        cond: PutCondition,
    ) -> Result<PutOutcome, StorageError> {
        validate_key(key)?;
        let mut h = HeaderMap::new();
        h.insert(
            reqwest::header::CONTENT_TYPE,
            HeaderValue::from_static("application/octet-stream"),
        );
        match &cond {
            PutCondition::None => {}
            PutCondition::IfAbsent => {
                h.insert(
                    reqwest::header::IF_NONE_MATCH,
                    HeaderValue::from_static("*"),
                );
            }
            PutCondition::IfMatch(e) => {
                let v =
                    HeaderValue::from_str(&quote_etag(e)).map_err(|_| StorageError::Backend {
                        status: None,
                        message: "invalid etag".into(),
                    })?;
                h.insert(reqwest::header::IF_MATCH, v);
            }
        }
        if key.contains('/') {
            self.ensure_collections(key).await?;
        }
        let mut attempt = 0;
        loop {
            attempt += 1;
            let (status, headers, _) = self
                .send(Method::PUT, key, h.clone(), bytes.clone())
                .await?;
            match status {
                200 | 201 | 204 => {
                    let etag = match response_etag(&headers) {
                        Some(e) => e,
                        None => self
                            .current_etag(key)
                            .await?
                            .unwrap_or_else(|| format!("local-{}", crate::etag_for(&bytes))),
                    };
                    return Ok(PutOutcome::Written { etag });
                }
                412 => return Ok(PutOutcome::PreconditionFailed),
                404 if matches!(cond, PutCondition::IfMatch(_)) => {
                    return Ok(PutOutcome::PreconditionFailed);
                }
                409 if attempt == 1 => {
                    // parent collection missing (cache stale): recreate and retry once
                    self.known_collections.lock().await.clear();
                    self.ensure_collections(key).await?;
                }
                s => return Err(httputil::status_error(s, None)),
            }
        }
    }

    async fn delete(&self, key: &str) -> Result<(), StorageError> {
        validate_key(key)?;
        let (status, _, _) = self
            .send(Method::DELETE, key, HeaderMap::new(), Vec::new())
            .await?;
        match status {
            200 | 202 | 204 | 404 | 410 => Ok(()),
            s => Err(httputil::status_error(s, None)),
        }
    }

    async fn list(
        &self,
        prefix: &str,
        start_after: Option<&str>,
        limit: usize,
    ) -> Result<Vec<ObjectMeta>, StorageError> {
        validate_prefix(prefix)?;
        if limit == 0 {
            return Ok(Vec::new());
        }
        let dir_part = match prefix.rfind('/') {
            Some(i) => &prefix[..i + 1],
            None => "",
        };
        let mut keys: Vec<ObjectMeta> = Vec::new();
        let mut queue: Vec<String> = vec![dir_part.to_owned()];
        let mut visited = 0usize;
        while let Some(coll) = queue.pop() {
            visited += 1;
            if visited > MAX_LIST_COLLECTIONS {
                return Err(StorageError::Backend {
                    status: None,
                    message: "listing too large".into(),
                });
            }
            let Some(entries) = self.propfind(&coll, "1").await? else {
                continue;
            };
            let self_rel = coll.trim_end_matches('/');
            for e in entries {
                if e.rel == self_rel || e.rel.is_empty() {
                    continue;
                }
                if e.is_collection {
                    let sub = format!("{}/", e.rel);
                    if (sub.starts_with(prefix) || prefix.starts_with(&sub))
                        && sub.len() > coll.len()
                    {
                        queue.push(sub);
                    }
                } else if e.rel.starts_with(prefix)
                    && start_after.is_none_or(|s| e.rel.as_str() > s)
                    && validate_key(&e.rel).is_ok()
                {
                    keys.push(ObjectMeta {
                        key: e.rel,
                        etag: e.etag.unwrap_or_default(),
                        size: e.size,
                        modified_at: e.modified_at,
                    });
                }
            }
        }
        keys.sort_by(|a, b| a.key.cmp(&b.key));
        keys.dedup_by(|a, b| a.key == b.key);
        keys.truncate(limit);
        Ok(keys)
    }

    fn describe(&self) -> StorageDescription {
        StorageDescription {
            kind: "webdav".into(),
            endpoint: Some(self.base.as_str().trim_end_matches('/').to_owned()),
            detail: Some("experimental (V1.1)".into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_b64() {
        assert_eq!(
            standard_b64(b"Aladdin:open sesame"),
            "QWxhZGRpbjpvcGVuIHNlc2FtZQ=="
        );
        assert_eq!(standard_b64(b"a"), "YQ==");
        assert_eq!(standard_b64(b"ab"), "YWI=");
        assert_eq!(standard_b64(b"abc"), "YWJj");
        assert_eq!(standard_b64(b""), "");
    }

    #[test]
    fn debug_redacts_password() {
        let c = WebDavConfig::new(Url::parse("https://dav.example.com/x/").unwrap())
            .with_basic_auth("me", SecretString::from("hunter2-very-secret"));
        assert!(!format!("{c:?}").contains("hunter2"));
    }
}
