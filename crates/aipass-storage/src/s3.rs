// SPDX-License-Identifier: Apache-2.0
//! `S3Store` — S3-compatible backend (design doc §10.1–§10.3, A15).
//!
//! * Requests are signed with SigV4 ([`crate::sigv4`], signed payload, `host`, all
//!   `x-amz-*` and the conditional headers are signed).
//! * Addressing: path-style (`https://host/bucket/key`) or virtual-host
//!   (`https://bucket.host/key`).
//! * Conditional writes: `If-None-Match: *` (create-only) and `If-Match: "<etag>"`
//!   (compare-and-swap). `412 Precondition Failed` and `409 ConditionalRequestConflict` map to
//!   [`PutOutcome::PreconditionFailed`]; so does `404` for an `If-Match` on a missing key.
//!   Services that silently ignore these headers are caught by the capability test and
//!   reported `backup_only` — "S3 compatible" is never assumed (§10.1).
//! * Listing: ListObjectsV2 with `start-after` and continuation tokens.
//! * Credentials: static access keys or temporary (STS) credentials with a session token,
//!   supplied through [`S3CredentialProvider`]. Secrets are zeroized and never appear in
//!   `Debug`, errors or [`ObjectStore::describe`].
//! * TLS: rustls (aws-lc-rs) via reqwest; plain `http` only for loopback endpoints or when
//!   [`S3Config::allow_http`] is explicitly set. Redirects are never followed.

use std::sync::Arc;
use std::time::Duration;

use aipass_crypto::SecretString;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use reqwest::Method;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use url::Url;

use crate::httputil::{self, quote_etag, response_etag, safe_code, transport_error};
use crate::sigv4::{self, SigningInput};
use crate::{
    Object, ObjectMeta, ObjectStore, PutCondition, PutOutcome, StorageDescription, StorageError,
    normalize_root_prefix, validate_key, validate_prefix,
};

/// Maximum keys per ListObjectsV2 page.
pub const MAX_KEYS_PER_PAGE: usize = 1000;

/// Static or temporary S3 credentials.
#[derive(Clone)]
pub struct S3Credentials {
    /// Access key id.
    pub access_key_id: String,
    /// Secret access key.
    pub secret_access_key: SecretString,
    /// STS session token (temporary credentials).
    pub session_token: Option<SecretString>,
}

impl S3Credentials {
    /// Static credentials.
    pub fn new(access_key_id: impl Into<String>, secret_access_key: SecretString) -> Self {
        Self {
            access_key_id: access_key_id.into(),
            secret_access_key,
            session_token: None,
        }
    }

    /// Temporary credentials with a session token.
    pub fn with_session_token(mut self, token: SecretString) -> Self {
        self.session_token = Some(token);
        self
    }
}

impl core::fmt::Debug for S3Credentials {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("S3Credentials")
            .field("access_key_id", &"[REDACTED]")
            .field("secret_access_key", &"[REDACTED]")
            .field(
                "session_token",
                &self.session_token.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

/// Source of credentials (static, or refreshed temporary credentials).
#[async_trait]
pub trait S3CredentialProvider: Send + Sync {
    /// Current credentials.
    async fn credentials(&self) -> Result<S3Credentials, StorageError>;
}

#[async_trait]
impl S3CredentialProvider for S3Credentials {
    async fn credentials(&self) -> Result<S3Credentials, StorageError> {
        Ok(self.clone())
    }
}

/// Non-secret S3 configuration.
#[derive(Debug, Clone)]
pub struct S3Config {
    /// Service endpoint, e.g. `https://s3.eu-central-1.amazonaws.com` or
    /// `https://minio.example.net:9000` (no path, no credentials).
    pub endpoint: Url,
    /// Signing region (`us-east-1` for most non-AWS services).
    pub region: String,
    /// Bucket.
    pub bucket: String,
    /// Key prefix dedicated to AI Pass (`""` or e.g. `"aipass/vault-1"`).
    pub prefix: String,
    /// Path-style addressing (`host/bucket/key`) instead of virtual-host (`bucket.host/key`).
    pub path_style: bool,
    /// Permit plain `http` for non-loopback endpoints (development only).
    pub allow_http: bool,
    /// Per-request timeout.
    pub timeout: Duration,
    /// Optional per-object size limit enforced client-side.
    pub max_object_size: Option<u64>,
}

impl S3Config {
    /// Configuration with defaults: path-style, https only, 30 s timeout.
    pub fn new(endpoint: Url, region: impl Into<String>, bucket: impl Into<String>) -> Self {
        Self {
            endpoint,
            region: region.into(),
            bucket: bucket.into(),
            prefix: String::new(),
            path_style: true,
            allow_http: false,
            timeout: httputil::DEFAULT_TIMEOUT,
            max_object_size: None,
        }
    }

    /// Set the key prefix.
    pub fn with_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.prefix = prefix.into();
        self
    }

    /// Choose virtual-host addressing.
    pub fn virtual_host(mut self) -> Self {
        self.path_style = false;
        self
    }
}

/// S3-compatible object store.
#[derive(Clone)]
pub struct S3Store {
    cfg: Arc<S3Config>,
    prefix: String,
    creds: Arc<dyn S3CredentialProvider>,
    http: reqwest::Client,
}

impl core::fmt::Debug for S3Store {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("S3Store")
            .field("endpoint", &self.cfg.endpoint.as_str())
            .field("bucket", &self.cfg.bucket)
            .field("prefix", &self.prefix)
            .finish_non_exhaustive()
    }
}

fn bucket_ok(b: &str, path_style: bool) -> bool {
    let len_ok = (3..=63).contains(&b.len());
    let chars_ok = b.bytes().all(|c| {
        c.is_ascii_lowercase()
            || c.is_ascii_digit()
            || c == b'-'
            || c == b'.'
            || (path_style && (c == b'_' || c.is_ascii_uppercase()))
    });
    len_ok && chars_ok && !b.starts_with('.') && !b.ends_with('.') && !b.contains("..")
}

struct S3Response {
    status: u16,
    headers: HeaderMap,
    body: Vec<u8>,
}

impl S3Response {
    fn error_code(&self) -> Option<String> {
        let text = std::str::from_utf8(&self.body).ok()?;
        let root = crate::xml::parse(text).ok()?;
        root.child_text("Code").and_then(safe_code)
    }
}

impl S3Store {
    /// Create with a default rustls client.
    pub fn new(cfg: S3Config, creds: Arc<dyn S3CredentialProvider>) -> Result<Self, StorageError> {
        let http = httputil::build_client(cfg.timeout)?;
        Self::with_client(cfg, creds, http)
    }

    /// Create with a caller-supplied reqwest client (custom roots, DNS overrides in tests).
    /// The client should not follow redirects.
    pub fn with_client(
        cfg: S3Config,
        creds: Arc<dyn S3CredentialProvider>,
        http: reqwest::Client,
    ) -> Result<Self, StorageError> {
        httputil::check_url(&cfg.endpoint, cfg.allow_http)?;
        if !(cfg.endpoint.path() == "/" || cfg.endpoint.path().is_empty())
            || cfg.endpoint.query().is_some()
        {
            return Err(StorageError::Backend {
                status: None,
                message: "S3 endpoint must not contain a path or query".into(),
            });
        }
        if !bucket_ok(&cfg.bucket, cfg.path_style) {
            return Err(StorageError::Backend {
                status: None,
                message: "invalid bucket name".into(),
            });
        }
        if cfg.region.is_empty()
            || !cfg
                .region
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'-')
        {
            return Err(StorageError::Backend {
                status: None,
                message: "invalid region".into(),
            });
        }
        let prefix = normalize_root_prefix(&cfg.prefix)?;
        Ok(Self {
            cfg: Arc::new(cfg),
            prefix,
            creds,
            http,
        })
    }

    /// `(scheme://authority, host header value, canonical uri base)`.
    fn host_parts(&self) -> (String, String) {
        let ep = &self.cfg.endpoint;
        let host = ep.host_str().unwrap_or_default();
        let port = ep.port().map(|p| format!(":{p}")).unwrap_or_default();
        let authority = if self.cfg.path_style {
            format!("{host}{port}")
        } else {
            format!("{}.{host}{port}", self.cfg.bucket)
        };
        (format!("{}://{authority}", ep.scheme()), authority)
    }

    /// Canonical URI (already encoded) for an object key or the bucket root.
    fn canonical_uri(&self, full_key: Option<&str>) -> String {
        let key_part = full_key
            .map(|k| sigv4::uri_encode(k, false))
            .unwrap_or_default();
        if self.cfg.path_style {
            match full_key {
                Some(_) => format!("/{}/{key_part}", sigv4::uri_encode(&self.cfg.bucket, true)),
                None => format!("/{}", sigv4::uri_encode(&self.cfg.bucket, true)),
            }
        } else {
            format!("/{key_part}")
        }
    }

    async fn send(
        &self,
        method: Method,
        full_key: Option<&str>,
        query: &[(String, String)],
        extra: &[(&'static str, String)],
        body: Vec<u8>,
    ) -> Result<S3Response, StorageError> {
        let creds = self.creds.credentials().await?;
        let (base, authority) = self.host_parts();
        let uri = self.canonical_uri(full_key);
        let cq = sigv4::canonical_query(query);
        let url_s = if cq.is_empty() {
            format!("{base}{uri}")
        } else {
            format!("{base}{uri}?{cq}")
        };
        let url = Url::parse(&url_s).map_err(|_| StorageError::InvalidKey)?;
        let payload_hash = sigv4::hex_sha256(&body);
        let amz_date = sigv4::amz_date(&Utc::now());
        let mut sign_headers: Vec<(String, String)> = vec![
            ("host".into(), authority),
            (sigv4::CONTENT_SHA256_HEADER.into(), payload_hash.clone()),
            (sigv4::DATE_HEADER.into(), amz_date.clone()),
        ];
        if let Some(tok) = &creds.session_token {
            sign_headers.push((sigv4::SECURITY_TOKEN_HEADER.into(), tok.expose().to_owned()));
        }
        for (k, v) in extra {
            sign_headers.push(((*k).to_owned(), v.clone()));
        }
        let signed = sigv4::sign(
            &SigningInput {
                access_key_id: &creds.access_key_id,
                secret_access_key: creds.secret_access_key.expose(),
                region: &self.cfg.region,
                service: "s3",
                amz_date: &amz_date,
            },
            method.as_str(),
            &uri,
            query,
            &sign_headers,
            &payload_hash,
        );
        let mut headers = HeaderMap::new();
        for (k, v) in sign_headers.iter().filter(|(k, _)| k != "host") {
            let name = HeaderName::from_bytes(k.as_bytes()).map_err(|_| StorageError::Backend {
                status: None,
                message: "bad header".into(),
            })?;
            let mut val = HeaderValue::from_str(v).map_err(|_| StorageError::Backend {
                status: None,
                message: "bad header value".into(),
            })?;
            if k == sigv4::SECURITY_TOKEN_HEADER {
                val.set_sensitive(true);
            }
            headers.insert(name, val);
        }
        let mut auth =
            HeaderValue::from_str(&signed.authorization).map_err(|_| StorageError::Backend {
                status: None,
                message: "bad header value".into(),
            })?;
        auth.set_sensitive(true);
        headers.insert(reqwest::header::AUTHORIZATION, auth);
        if method == Method::PUT {
            headers.insert(
                reqwest::header::CONTENT_TYPE,
                HeaderValue::from_static("application/octet-stream"),
            );
        }
        let resp = self
            .http
            .request(method, url)
            .headers(headers)
            .body(body)
            .send()
            .await
            .map_err(|e| transport_error(&e))?;
        let status = resp.status().as_u16();
        let headers = resp.headers().clone();
        let body = resp
            .bytes()
            .await
            .map_err(|e| transport_error(&e))?
            .to_vec();
        Ok(S3Response {
            status,
            headers,
            body,
        })
    }

    fn generic_error(r: &S3Response) -> StorageError {
        let code = r.error_code();
        match (r.status, code.as_deref()) {
            (404, Some("NoSuchBucket")) => StorageError::LocationNotFound,
            (400, Some("EntityTooLarge")) => StorageError::TooLarge { limit: 0 },
            (s, c) => httputil::status_error(s, c),
        }
    }

    fn full_key(&self, key: &str) -> Result<String, StorageError> {
        validate_key(key)?;
        Ok(format!("{}{key}", self.prefix))
    }

    async fn list_page(
        &self,
        full_prefix: &str,
        start_after: Option<&str>,
        token: Option<&str>,
        max_keys: usize,
    ) -> Result<(Vec<ObjectMeta>, Option<String>), StorageError> {
        let mut q: Vec<(String, String)> = vec![
            ("list-type".into(), "2".into()),
            ("max-keys".into(), max_keys.to_string()),
            ("prefix".into(), full_prefix.to_owned()),
        ];
        if let Some(t) = token {
            q.push(("continuation-token".into(), t.to_owned()));
        } else if let Some(s) = start_after {
            q.push(("start-after".into(), s.to_owned()));
        }
        let r = self.send(Method::GET, None, &q, &[], Vec::new()).await?;
        if r.status != 200 {
            return Err(Self::generic_error(&r));
        }
        let text = std::str::from_utf8(&r.body).map_err(|_| StorageError::Backend {
            status: Some(200),
            message: "listing is not UTF-8".into(),
        })?;
        let root = crate::xml::parse(text).map_err(|_| StorageError::Backend {
            status: Some(200),
            message: "listing is not valid XML".into(),
        })?;
        if root.name != "ListBucketResult" {
            return Err(StorageError::Backend {
                status: Some(200),
                message: "unexpected listing document".into(),
            });
        }
        let mut out = Vec::new();
        for c in root.children_named("Contents") {
            let Some(full) = c.child_text("Key") else {
                continue;
            };
            let Some(rel) = full.strip_prefix(&self.prefix) else {
                continue;
            };
            if validate_key(rel).is_err() {
                continue; // foreign object under the prefix
            }
            let size = c
                .child_text("Size")
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(0);
            let etag = c
                .child_text("ETag")
                .map(httputil::unquote_etag)
                .unwrap_or_default();
            let modified_at = c
                .child_text("LastModified")
                .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                .map(|d| d.with_timezone(&Utc));
            out.push(ObjectMeta {
                key: rel.to_owned(),
                etag,
                size,
                modified_at,
            });
        }
        let truncated = root
            .child_text("IsTruncated")
            .is_some_and(|v| v.eq_ignore_ascii_case("true"));
        let next = if truncated {
            root.child_text("NextContinuationToken")
                .filter(|t| !t.is_empty())
                .map(str::to_owned)
        } else {
            None
        };
        if truncated && next.is_none() {
            return Err(StorageError::Backend {
                status: Some(200),
                message: "truncated listing without continuation token".into(),
            });
        }
        Ok((out, next))
    }
}

#[async_trait]
impl ObjectStore for S3Store {
    async fn get(&self, key: &str) -> Result<Option<Object>, StorageError> {
        let full = self.full_key(key)?;
        let r = self
            .send(Method::GET, Some(&full), &[], &[], Vec::new())
            .await?;
        match r.status {
            200 => {
                let etag = response_etag(&r.headers).unwrap_or_else(|| crate::etag_for(&r.body));
                Ok(Some(Object {
                    bytes: r.body,
                    etag,
                }))
            }
            404 => match r.error_code().as_deref() {
                Some("NoSuchBucket") => Err(StorageError::LocationNotFound),
                _ => Ok(None),
            },
            _ => Err(Self::generic_error(&r)),
        }
    }

    async fn put(
        &self,
        key: &str,
        bytes: Vec<u8>,
        cond: PutCondition,
    ) -> Result<PutOutcome, StorageError> {
        let full = self.full_key(key)?;
        if let Some(limit) = self.cfg.max_object_size
            && bytes.len() as u64 > limit
        {
            return Err(StorageError::TooLarge { limit });
        }
        let extra: Vec<(&'static str, String)> = match &cond {
            PutCondition::None => vec![],
            PutCondition::IfAbsent => vec![("if-none-match", "*".into())],
            PutCondition::IfMatch(e) => vec![("if-match", quote_etag(e))],
        };
        let fallback_etag = crate::etag_for(&bytes);
        let r = self
            .send(Method::PUT, Some(&full), &[], &extra, bytes)
            .await?;
        match r.status {
            200 | 201 | 204 => Ok(PutOutcome::Written {
                etag: response_etag(&r.headers).unwrap_or(fallback_etag),
            }),
            412 => Ok(PutOutcome::PreconditionFailed),
            409 if !matches!(cond, PutCondition::None) => Ok(PutOutcome::PreconditionFailed),
            404 if matches!(cond, PutCondition::IfMatch(_))
                && r.error_code().as_deref() != Some("NoSuchBucket") =>
            {
                Ok(PutOutcome::PreconditionFailed)
            }
            _ => Err(Self::generic_error(&r)),
        }
    }

    async fn delete(&self, key: &str) -> Result<(), StorageError> {
        let full = self.full_key(key)?;
        let r = self
            .send(Method::DELETE, Some(&full), &[], &[], Vec::new())
            .await?;
        match r.status {
            200 | 202 | 204 => Ok(()),
            404 if r.error_code().as_deref() != Some("NoSuchBucket") => Ok(()),
            _ => Err(Self::generic_error(&r)),
        }
    }

    async fn list(
        &self,
        prefix: &str,
        start_after: Option<&str>,
        limit: usize,
    ) -> Result<Vec<ObjectMeta>, StorageError> {
        validate_prefix(prefix)?;
        let full_prefix = format!("{}{prefix}", self.prefix);
        let full_after = start_after.map(|s| format!("{}{s}", self.prefix));
        let mut out: Vec<ObjectMeta> = Vec::new();
        let mut token: Option<String> = None;
        let mut pages = 0usize;
        while out.len() < limit {
            let want = (limit - out.len()).min(MAX_KEYS_PER_PAGE);
            let (page, next) = self
                .list_page(&full_prefix, full_after.as_deref(), token.as_deref(), want)
                .await?;
            out.extend(page);
            pages += 1;
            match next {
                Some(t) if pages < 100_000 => token = Some(t),
                _ => break,
            }
        }
        // defensive: enforce ordering / start_after / prefix even if the service does not
        out.retain(|m| m.key.starts_with(prefix) && start_after.is_none_or(|s| m.key.as_str() > s));
        out.sort_by(|a, b| a.key.cmp(&b.key));
        out.dedup_by(|a, b| a.key == b.key);
        out.truncate(limit);
        Ok(out)
    }

    fn describe(&self) -> StorageDescription {
        StorageDescription {
            kind: "s3".into(),
            endpoint: Some(self.cfg.endpoint.as_str().trim_end_matches('/').to_owned()),
            detail: Some(format!(
                "bucket={}, prefix={}, region={}, {}",
                self.cfg.bucket,
                if self.prefix.is_empty() {
                    "/"
                } else {
                    &self.prefix
                },
                self.cfg.region,
                if self.cfg.path_style {
                    "path-style"
                } else {
                    "virtual-host"
                }
            )),
        }
    }
}
