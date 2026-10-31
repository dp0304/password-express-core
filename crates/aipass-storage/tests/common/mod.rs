// SPDX-License-Identifier: Apache-2.0
//! In-process mock servers for backend tests: an S3 mock that **verifies SigV4** and
//! implements (or deliberately ignores) conditional writes, and a WebDAV mock with
//! `PROPFIND`/`MKCOL` and strict or lax conditional semantics. Servers bind to
//! `127.0.0.1:0` inside the test runtime and stop when it shuts down.

#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use aipass_storage::sigv4;
use axum::Router;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use tokio::sync::Mutex;

pub async fn serve(router: Router) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    addr
}

pub fn test_client() -> reqwest::Client {
    reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .unwrap()
}

fn hex_etag(b: &[u8]) -> String {
    hex::encode(&aipass_crypto::sha256(b)[..16])
}

// ======================================================================================
// S3 mock
// ======================================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S3Mode {
    /// Honors If-None-Match / If-Match atomically (412).
    Strict,
    /// Honors conditions but answers 409 ConditionalRequestConflict for failed creates.
    Conflict409,
    /// Accepts the headers but ignores them (non-compliant service).
    IgnoreConditions,
}

pub struct MockS3 {
    pub access_key: String,
    pub secret: String,
    pub session_token: Option<String>,
    pub region: String,
    pub bucket: String,
    pub virtual_host: bool,
    pub mode: S3Mode,
    pub page_cap: usize,
    pub objects: Mutex<BTreeMap<String, (Vec<u8>, String)>>,
    pub requests: AtomicUsize,
    pub sig_failures: AtomicUsize,
}

impl MockS3 {
    pub fn new(mode: S3Mode) -> Arc<Self> {
        Arc::new(Self {
            access_key: "AKIDMOCKACCESSKEY".into(),
            secret: "mock/secret+key/value".into(),
            session_token: None,
            region: "eu-test-1".into(),
            bucket: "aipass-test".into(),
            virtual_host: false,
            mode,
            page_cap: 1000,
            objects: Mutex::new(BTreeMap::new()),
            requests: AtomicUsize::new(0),
            sig_failures: AtomicUsize::new(0),
        })
    }
}

fn s3_error(status: StatusCode, code: &str) -> Response {
    let body = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Error><Code>{code}</Code><Message>mock</Message><RequestId>1</RequestId></Error>"
    );
    (status, [("content-type", "application/xml")], body).into_response()
}

fn decode(s: &str) -> String {
    percent_encoding::percent_decode_str(&s.replace('+', "%20"))
        .decode_utf8_lossy()
        .into_owned()
}

fn verify_sigv4(
    m: &MockS3,
    method: &Method,
    path: &str,
    query: Option<&str>,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<(), &'static str> {
    let auth = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or("no authorization")?;
    let p = sigv4::parse_authorization(auth).ok_or("bad authorization")?;
    if p.access_key_id != m.access_key {
        return Err("InvalidAccessKeyId");
    }
    if p.region != m.region || p.service != "s3" {
        return Err("bad scope");
    }
    for required in ["host", "x-amz-date", "x-amz-content-sha256"] {
        if !p.signed_headers.iter().any(|h| h == required) {
            return Err("required header not signed");
        }
    }
    if headers.contains_key("if-none-match")
        && !p.signed_headers.iter().any(|h| h == "if-none-match")
    {
        return Err("conditional header not signed");
    }
    if headers.contains_key("if-match") && !p.signed_headers.iter().any(|h| h == "if-match") {
        return Err("conditional header not signed");
    }
    match (&m.session_token, headers.get("x-amz-security-token")) {
        (Some(t), Some(v)) if v.to_str().ok() == Some(t.as_str()) => {
            if !p.signed_headers.iter().any(|h| h == "x-amz-security-token") {
                return Err("token not signed");
            }
        }
        (Some(_), _) => return Err("missing/invalid session token"),
        (None, Some(_)) => return Err("unexpected session token"),
        (None, None) => {}
    }
    let payload_hash = headers
        .get("x-amz-content-sha256")
        .and_then(|v| v.to_str().ok())
        .ok_or("no payload hash")?;
    if payload_hash != sigv4::hex_sha256(body) {
        return Err("payload hash mismatch");
    }
    let amz_date = headers
        .get("x-amz-date")
        .and_then(|v| v.to_str().ok())
        .ok_or("no date")?;
    if !amz_date.starts_with(&p.date) {
        return Err("date mismatch");
    }
    let mut hs: Vec<(String, String)> = Vec::new();
    for name in &p.signed_headers {
        let vals: Vec<String> = headers
            .get_all(name.as_str())
            .iter()
            .filter_map(|v| v.to_str().ok().map(str::to_owned))
            .collect();
        if vals.is_empty() {
            return Err("signed header missing from request");
        }
        for v in vals {
            hs.push((name.clone(), v));
        }
    }
    let pairs: Vec<(String, String)> = query
        .unwrap_or("")
        .split('&')
        .filter(|s| !s.is_empty())
        .map(|kv| match kv.split_once('=') {
            Some((k, v)) => (decode(k), decode(v)),
            None => (decode(kv), String::new()),
        })
        .collect();
    let signed = sigv4::sign(
        &sigv4::SigningInput {
            access_key_id: &p.access_key_id,
            secret_access_key: &m.secret,
            region: &p.region,
            service: "s3",
            amz_date,
        },
        method.as_str(),
        path,
        &pairs,
        &hs,
        payload_hash,
    );
    if signed.signature != p.signature {
        return Err("SignatureDoesNotMatch");
    }
    Ok(())
}

async fn s3_handler(State(m): State<Arc<MockS3>>, req: Request) -> Response {
    m.requests.fetch_add(1, Ordering::SeqCst);
    let (parts, body) = req.into_parts();
    let body = axum::body::to_bytes(body, 64 * 1024 * 1024)
        .await
        .unwrap()
        .to_vec();
    let path = parts.uri.path().to_owned();
    let query = parts.uri.query().map(str::to_owned);
    if let Err(why) = verify_sigv4(
        &m,
        &parts.method,
        &path,
        query.as_deref(),
        &parts.headers,
        &body,
    ) {
        m.sig_failures.fetch_add(1, Ordering::SeqCst);
        let code = if why == "InvalidAccessKeyId" {
            "InvalidAccessKeyId"
        } else {
            "SignatureDoesNotMatch"
        };
        return s3_error(StatusCode::FORBIDDEN, code);
    }
    // bucket + key from host or path
    let host = parts
        .headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned();
    let (bucket, key) = if m.virtual_host {
        let b = host.split('.').next().unwrap_or("").to_owned();
        (b, path.trim_start_matches('/').to_owned())
    } else {
        let rest = path.trim_start_matches('/');
        match rest.split_once('/') {
            Some((b, k)) => (b.to_owned(), k.to_owned()),
            None => (rest.to_owned(), String::new()),
        }
    };
    if bucket != m.bucket {
        return s3_error(StatusCode::NOT_FOUND, "NoSuchBucket");
    }
    let key = decode(&key);
    let q: BTreeMap<String, String> = query
        .as_deref()
        .unwrap_or("")
        .split('&')
        .filter(|s| !s.is_empty())
        .map(|kv| match kv.split_once('=') {
            Some((k, v)) => (decode(k), decode(v)),
            None => (decode(kv), String::new()),
        })
        .collect();
    match (parts.method.clone(), key.is_empty()) {
        (Method::GET, true) if q.get("list-type").map(String::as_str) == Some("2") => {
            let prefix = q.get("prefix").cloned().unwrap_or_default();
            let max = q
                .get("max-keys")
                .and_then(|s| s.parse::<usize>().ok())
                .unwrap_or(1000)
                .min(m.page_cap);
            let after = q
                .get("continuation-token")
                .and_then(|t| t.strip_prefix("tok:").map(str::to_owned))
                .or_else(|| q.get("start-after").cloned());
            let objs = m.objects.lock().await;
            let mut items: Vec<(&String, &(Vec<u8>, String))> = objs
                .iter()
                .filter(|(k, _)| k.starts_with(&prefix))
                .filter(|(k, _)| after.as_ref().is_none_or(|a| k.as_str() > a.as_str()))
                .collect();
            let truncated = items.len() > max;
            items.truncate(max);
            let mut xml = String::from(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?><ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">",
            );
            xml.push_str(&format!("<Name>{}</Name><Prefix>{prefix}</Prefix><KeyCount>{}</KeyCount><MaxKeys>{max}</MaxKeys><IsTruncated>{truncated}</IsTruncated>", m.bucket, items.len()));
            for (k, (b, e)) in &items {
                xml.push_str(&format!(
                    "<Contents><Key>{k}</Key><LastModified>2026-10-30T12:00:00.000Z</LastModified><ETag>&quot;{e}&quot;</ETag><Size>{}</Size><StorageClass>STANDARD</StorageClass></Contents>",
                    b.len()
                ));
            }
            if truncated && let Some((k, _)) = items.last() {
                xml.push_str(&format!(
                    "<NextContinuationToken>tok:{k}</NextContinuationToken>"
                ));
            }
            xml.push_str("</ListBucketResult>");
            (StatusCode::OK, [("content-type", "application/xml")], xml).into_response()
        }
        (Method::GET, false) => {
            let objs = m.objects.lock().await;
            match objs.get(&key) {
                Some((b, e)) => {
                    (StatusCode::OK, [("etag", format!("\"{e}\""))], b.clone()).into_response()
                }
                None => s3_error(StatusCode::NOT_FOUND, "NoSuchKey"),
            }
        }
        (Method::PUT, false) => {
            let mut objs = m.objects.lock().await;
            let inm = parts
                .headers
                .get("if-none-match")
                .and_then(|v| v.to_str().ok());
            let im = parts
                .headers
                .get("if-match")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.trim_matches('"').to_owned());
            if m.mode != S3Mode::IgnoreConditions {
                if inm == Some("*") && objs.contains_key(&key) {
                    return if m.mode == S3Mode::Conflict409 {
                        s3_error(StatusCode::CONFLICT, "ConditionalRequestConflict")
                    } else {
                        s3_error(StatusCode::PRECONDITION_FAILED, "PreconditionFailed")
                    };
                }
                if let Some(want) = im {
                    match objs.get(&key) {
                        None => return s3_error(StatusCode::NOT_FOUND, "NoSuchKey"),
                        Some((_, e)) if *e != want => {
                            return s3_error(StatusCode::PRECONDITION_FAILED, "PreconditionFailed");
                        }
                        _ => {}
                    }
                }
            }
            let e = hex_etag(&body);
            objs.insert(key, (body, e.clone()));
            (StatusCode::OK, [("etag", format!("\"{e}\""))], "").into_response()
        }
        (Method::DELETE, false) => {
            m.objects.lock().await.remove(&key);
            StatusCode::NO_CONTENT.into_response()
        }
        _ => s3_error(StatusCode::BAD_REQUEST, "InvalidRequest"),
    }
}

pub fn s3_router(m: Arc<MockS3>) -> Router {
    Router::new().fallback(s3_handler).with_state(m)
}

// ======================================================================================
// WebDAV mock
// ======================================================================================

pub struct MockDav {
    /// Honor If-None-Match / If-Match atomically.
    pub strict: bool,
    /// Return ETag on PUT responses.
    pub etag_on_put: bool,
    /// Required `Authorization` header value, if any.
    pub required_auth: Option<String>,
    pub files: Mutex<BTreeMap<String, (Vec<u8>, String)>>,
    pub collections: Mutex<BTreeSet<String>>,
    pub mkcols: AtomicUsize,
}

impl MockDav {
    pub fn new(strict: bool) -> Arc<Self> {
        Arc::new(Self {
            strict,
            etag_on_put: true,
            required_auth: None,
            files: Mutex::new(BTreeMap::new()),
            collections: Mutex::new(BTreeSet::from([String::new()])),
            mkcols: AtomicUsize::new(0),
        })
    }
}

const DAV_BASE: &str = "/dav/files/me/aipass/";

fn dav_rel(path: &str) -> Option<String> {
    let p = percent_encoding::percent_decode_str(path)
        .decode_utf8_lossy()
        .into_owned();
    p.strip_prefix(DAV_BASE).map(str::to_owned)
}

async fn dav_handler(State(d): State<Arc<MockDav>>, req: Request) -> Response {
    let (parts, body) = req.into_parts();
    if let Some(want) = &d.required_auth
        && parts
            .headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            != Some(want.as_str())
    {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let body = axum::body::to_bytes(body, 64 * 1024 * 1024)
        .await
        .unwrap()
        .to_vec();
    let Some(rel) = dav_rel(parts.uri.path()) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let m = parts.method.as_str().to_owned();
    match m.as_str() {
        "GET" => match d.files.lock().await.get(&rel) {
            Some((b, e)) => {
                (StatusCode::OK, [("etag", format!("\"{e}\""))], b.clone()).into_response()
            }
            None => StatusCode::NOT_FOUND.into_response(),
        },
        "PUT" => {
            let parent = match rel.rfind('/') {
                Some(i) => rel[..i + 1].to_owned(),
                None => String::new(),
            };
            if !d.collections.lock().await.contains(&parent) {
                return StatusCode::CONFLICT.into_response();
            }
            let mut files = d.files.lock().await;
            if d.strict {
                let inm = parts
                    .headers
                    .get("if-none-match")
                    .and_then(|v| v.to_str().ok());
                if inm == Some("*") && files.contains_key(&rel) {
                    return StatusCode::PRECONDITION_FAILED.into_response();
                }
                if let Some(im) = parts.headers.get("if-match").and_then(|v| v.to_str().ok()) {
                    let want = im.trim_matches('"');
                    match files.get(&rel) {
                        Some((_, e)) if e == want => {}
                        _ => return StatusCode::PRECONDITION_FAILED.into_response(),
                    }
                }
            }
            let existed = files.contains_key(&rel);
            let e = hex_etag(&body);
            files.insert(rel, (body, e.clone()));
            let status = if existed {
                StatusCode::NO_CONTENT
            } else {
                StatusCode::CREATED
            };
            if d.etag_on_put {
                (status, [("etag", format!("\"{e}\""))]).into_response()
            } else {
                status.into_response()
            }
        }
        "DELETE" => {
            if d.files.lock().await.remove(&rel).is_some() {
                StatusCode::NO_CONTENT.into_response()
            } else {
                StatusCode::NOT_FOUND.into_response()
            }
        }
        "MKCOL" => {
            d.mkcols.fetch_add(1, Ordering::SeqCst);
            let rel = if rel.ends_with('/') {
                rel
            } else {
                format!("{rel}/")
            };
            let mut cols = d.collections.lock().await;
            if cols.contains(&rel) {
                return StatusCode::METHOD_NOT_ALLOWED.into_response();
            }
            let parent = match rel.trim_end_matches('/').rfind('/') {
                Some(i) => rel[..i + 1].to_owned(),
                None => String::new(),
            };
            if !cols.contains(&parent) {
                return StatusCode::CONFLICT.into_response();
            }
            cols.insert(rel);
            StatusCode::CREATED.into_response()
        }
        "PROPFIND" => {
            let depth = parts
                .headers
                .get("depth")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("infinity");
            if depth == "infinity" {
                return StatusCode::FORBIDDEN.into_response();
            }
            let files = d.files.lock().await;
            let cols = d.collections.lock().await;
            let coll = if rel.is_empty() || rel.ends_with('/') {
                rel.clone()
            } else {
                format!("{rel}/")
            };
            let mut xml = String::from(
                "<?xml version=\"1.0\" encoding=\"utf-8\"?><d:multistatus xmlns:d=\"DAV:\">",
            );
            let file_resp = |k: &str, b: &[u8], e: &str| {
                format!(
                    "<d:response><d:href>{DAV_BASE}{k}</d:href><d:propstat><d:prop><d:resourcetype/><d:getetag>\"{e}\"</d:getetag><d:getcontentlength>{}</d:getcontentlength><d:getlastmodified>Fri, 30 Oct 2026 12:00:00 GMT</d:getlastmodified></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>",
                    b.len()
                )
            };
            if let Some((b, e)) = files.get(&rel) {
                // Depth 0/1 on a file
                xml.push_str(&file_resp(&rel, b, e));
            } else if cols.contains(&coll) {
                xml.push_str(&format!("<d:response><d:href>{DAV_BASE}{coll}</d:href><d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>"));
                if depth == "1" {
                    for c in cols.iter() {
                        if let Some(rest) = c.strip_prefix(&coll)
                            && !rest.is_empty()
                            && rest.trim_end_matches('/').find('/').is_none()
                        {
                            xml.push_str(&format!("<d:response><d:href>{DAV_BASE}{c}</d:href><d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>"));
                        }
                    }
                    for (k, (b, e)) in files.iter() {
                        if let Some(rest) = k.strip_prefix(&coll)
                            && !rest.contains('/')
                        {
                            xml.push_str(&file_resp(k, b, e));
                        }
                    }
                }
            } else {
                return StatusCode::NOT_FOUND.into_response();
            }
            xml.push_str("</d:multistatus>");
            Response::builder()
                .status(207)
                .header("content-type", "application/xml; charset=utf-8")
                .body(Body::from(xml))
                .unwrap()
        }
        _ => StatusCode::METHOD_NOT_ALLOWED.into_response(),
    }
}

pub fn dav_router(d: Arc<MockDav>) -> Router {
    Router::new().fallback(dav_handler).with_state(d)
}

pub fn dav_base(addr: SocketAddr) -> url::Url {
    url::Url::parse(&format!("http://{addr}{DAV_BASE}")).unwrap()
}
