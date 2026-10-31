// SPDX-License-Identifier: Apache-2.0
//! Streamable HTTP transport (MCP 2025-03-26+; CONTRACTS §9).
//!
//! * `POST /mcp` — one JSON-RPC message (or, for 2025-03-26 / 2024-11-05 sessions, a batch).
//!   Requests get `application/json` (or a single-event `text/event-stream` when the client
//!   only accepts SSE); notifications/responses get `202 Accepted` with no body.
//! * `initialize` creates a session and returns `Mcp-Session-Id` (192 random bits); later
//!   requests without it get `400`, unknown/expired ones `404`. Sessions are bound to the
//!   authenticated principal — another principal presenting the id gets `404`.
//! * `MCP-Protocol-Version` must, when present, equal the negotiated version (else `400`).
//! * `DELETE /mcp` ends the session (`204`); `GET /mcp` → `405` (no server-initiated stream).
//! * **Local mode**: `Origin` (when present) must be allow-listed and `Host` must be the
//!   loopback listen address (DNS-rebinding defence) — otherwise `403`.
//! * **Remote mode**: `Authorization: Bearer` is required; missing/invalid tokens get `401`
//!   with `WWW-Authenticate: Bearer resource_metadata="<url>"`. `Origin`, when present, must
//!   be allow-listed.
//!
//! [`StreamableHttp::handle_for_principal`] exposes the same logic without HTTP for embedders
//! that authenticate elsewhere (the node serving cloud-tunnel `mcp` frames).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use aipass_client::BrokerApi;
use aipass_types::{ApiError, ErrorCode, signing};
use async_trait::async_trait;
use axum::body::{Body, Bytes};
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use serde_json::{Value, json};

use crate::protocol::{self, INVALID_REQUEST, PARSE_ERROR, ProtocolVersion};
use crate::server::{MAX_MESSAGE_BYTES, McpContext, McpServer, McpSession};

/// Session id header.
pub const SESSION_HEADER: &str = "mcp-session-id";
/// Protocol version header.
pub const VERSION_HEADER: &str = "mcp-protocol-version";

/// An authenticated caller.
#[derive(Clone)]
pub struct Principal {
    /// Stable, non-secret key sessions are bound to (connection id, or token hash).
    pub key: String,
    /// Broker API bound to this caller.
    pub broker: Arc<dyn BrokerApi>,
}

impl std::fmt::Debug for Principal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Principal").field("key", &self.key).finish_non_exhaustive()
    }
}

/// Resolves a bearer token (remote mode). Return `IDENTITY_UNVERIFIED` for unknown tokens.
#[async_trait]
pub trait BearerResolver: Send + Sync {
    /// Resolve `token` to a principal.
    async fn resolve(&self, token: &str) -> Result<Principal, ApiError>;
}

/// Authentication mode.
#[derive(Clone)]
pub enum HttpMode {
    /// Loopback bridge for local hosts: no bearer; `Origin` / `Host` validated.
    Local {
        /// Broker for every request (the bridge's own connection).
        broker: Arc<dyn BrokerApi>,
        /// Allowed `Origin` values (exact, case-insensitive). Requests without `Origin` pass.
        allowed_origins: Vec<String>,
        /// Allowed `Host` header values (e.g. `127.0.0.1:7879`, `localhost:7879`).
        allowed_hosts: Vec<String>,
    },
    /// Remote MCP: bearer required.
    Remote {
        /// Token resolver.
        resolver: Arc<dyn BearerResolver>,
        /// URL of the OAuth protected-resource metadata advertised in `WWW-Authenticate`.
        resource_metadata_url: String,
        /// Allowed `Origin` values.
        allowed_origins: Vec<String>,
    },
}

/// Transport configuration.
#[derive(Clone)]
pub struct HttpConfig {
    /// Mode.
    pub mode: HttpMode,
    /// Idle session lifetime.
    pub session_idle_ttl: Duration,
    /// Maximum sessions.
    pub max_sessions: usize,
    /// Maximum sessions per principal.
    pub max_sessions_per_principal: usize,
    /// Maximum request body.
    pub max_body_bytes: usize,
    /// Optional protected-resource metadata document served at
    /// `/.well-known/oauth-protected-resource` and `/.well-known/oauth-protected-resource/mcp`.
    pub protected_resource_metadata: Option<Value>,
}

impl HttpConfig {
    /// Defaults for `mode`.
    pub fn new(mode: HttpMode) -> Self {
        Self {
            mode,
            session_idle_ttl: Duration::from_secs(30 * 60),
            max_sessions: 1024,
            max_sessions_per_principal: 16,
            max_body_bytes: MAX_MESSAGE_BYTES,
            protected_resource_metadata: None,
        }
    }

    /// Loopback `Host` values for a listen address.
    pub fn loopback_hosts(port: u16) -> Vec<String> {
        vec![
            format!("127.0.0.1:{port}"),
            format!("localhost:{port}"),
            format!("[::1]:{port}"),
        ]
    }
}

/// HTTP-like reply (also used for tunnel `mcp_result` frames).
#[derive(Debug, Clone, PartialEq)]
pub struct HttpReply {
    /// Status.
    pub status: u16,
    /// Headers (lower-case names).
    pub headers: Vec<(String, String)>,
    /// Body.
    pub body: Option<Vec<u8>>,
}

impl HttpReply {
    fn json(status: u16, v: &Value) -> Self {
        Self {
            status,
            headers: vec![("content-type".into(), "application/json".into())],
            body: Some(serde_json::to_vec(v).unwrap_or_default()),
        }
    }

    fn sse(v: &Value) -> Self {
        let data = serde_json::to_string(v).unwrap_or_default();
        Self {
            status: 200,
            headers: vec![
                ("content-type".into(), "text/event-stream".into()),
                ("cache-control".into(), "no-cache".into()),
            ],
            body: Some(format!("event: message\ndata: {data}\n\n").into_bytes()),
        }
    }

    fn empty(status: u16) -> Self {
        Self {
            status,
            headers: vec![],
            body: None,
        }
    }

    fn rpc_error(status: u16, code: i64, message: &str) -> Self {
        Self::json(status, &protocol::error(&Value::Null, code, message))
    }

    fn with_header(mut self, k: &str, v: impl Into<String>) -> Self {
        self.headers.push((k.to_owned(), v.into()));
        self
    }

    /// Convert to a tunnel `mcp_result` payload (JSON body, lower-case headers).
    pub fn into_tunnel_response(self) -> aipass_client::tunnel::McpResponse {
        let body = self.body_json().unwrap_or(Value::Null);
        aipass_client::tunnel::McpResponse {
            status: self.status,
            headers: self
                .headers
                .into_iter()
                .filter(|(k, _)| k != "content-type" && k != "cache-control")
                .collect(),
            body,
        }
    }

    /// Header value by (lower-case) name.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// Body parsed as JSON (SSE `data:` lines are decoded).
    pub fn body_json(&self) -> Option<Value> {
        let body = self.body.as_ref()?;
        if self.header("content-type").is_some_and(|c| c.starts_with("text/event-stream")) {
            let text = String::from_utf8_lossy(body);
            let data: String = text
                .lines()
                .filter_map(|l| l.strip_prefix("data:"))
                .map(str::trim_start)
                .collect();
            return serde_json::from_str(&data).ok();
        }
        serde_json::from_slice(body).ok()
    }
}

struct SessionEntry {
    session: Arc<McpSession>,
    principal_key: String,
    last_seen: Instant,
}

/// Request metadata relevant to MCP (already authenticated).
#[derive(Debug, Clone, Default)]
pub struct McpHttpRequest<'a> {
    /// `POST` or `DELETE` (anything else → 405).
    pub method: &'a str,
    /// `Mcp-Session-Id`.
    pub session_id: Option<&'a str>,
    /// `MCP-Protocol-Version`.
    pub protocol_version: Option<&'a str>,
    /// `Accept`.
    pub accept: Option<&'a str>,
    /// `Content-Type`.
    pub content_type: Option<&'a str>,
    /// Body.
    pub body: &'a [u8],
}

/// The Streamable HTTP transport (shareable).
pub struct StreamableHttp {
    server: Arc<McpServer>,
    config: HttpConfig,
    sessions: Mutex<HashMap<String, SessionEntry>>,
}

fn header_str<'a>(h: &'a HeaderMap, name: &str) -> Option<&'a str> {
    h.get(name).and_then(|v| v.to_str().ok())
}

fn accepts(accept: Option<&str>) -> Result<bool, ()> {
    // Ok(true) → reply with SSE; Ok(false) → JSON; Err → 406
    let Some(a) = accept else { return Ok(false) };
    let a = a.to_ascii_lowercase();
    let json = a.contains("application/json") || a.contains("application/*") || a.contains("*/*");
    let sse = a.contains("text/event-stream");
    match (json, sse) {
        (true, _) => Ok(false),
        (false, true) => Ok(true),
        (false, false) => Err(()),
    }
}

fn is_initialize(v: &Value) -> bool {
    v.get("method").and_then(Value::as_str) == Some("initialize") && v.get("id").is_some()
}

fn new_session_id() -> Option<String> {
    aipass_types::crypto::rng::try_random_array::<24>()
        .ok()
        .map(aipass_types::crypto::b64u::encode)
}

impl StreamableHttp {
    /// New transport.
    pub fn new(server: Arc<McpServer>, config: HttpConfig) -> Arc<Self> {
        Arc::new(Self {
            server,
            config,
            sessions: Mutex::new(HashMap::new()),
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, SessionEntry>> {
        match self.sessions.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        }
    }

    /// Live sessions.
    pub fn session_count(&self) -> usize {
        self.lock().len()
    }

    fn prune(&self, now: Instant) {
        let ttl = self.config.session_idle_ttl;
        self.lock().retain(|_, e| now.duration_since(e.last_seen) < ttl);
    }

    fn insert_session(&self, id: String, principal_key: &str, session: Arc<McpSession>) {
        let mut map = self.lock();
        let evict_oldest = |map: &mut HashMap<String, SessionEntry>, only: Option<&str>| {
            let victim = map
                .iter()
                .filter(|(_, e)| only.is_none_or(|k| e.principal_key == k))
                .min_by_key(|(_, e)| e.last_seen)
                .map(|(k, _)| k.clone());
            if let Some(v) = victim {
                map.remove(&v);
            }
        };
        while map.values().filter(|e| e.principal_key == principal_key).count()
            >= self.config.max_sessions_per_principal
        {
            evict_oldest(&mut map, Some(principal_key));
        }
        while map.len() >= self.config.max_sessions {
            evict_oldest(&mut map, None);
        }
        map.insert(
            id,
            SessionEntry {
                session,
                principal_key: principal_key.to_owned(),
                last_seen: Instant::now(),
            },
        );
    }

    fn session_for(&self, id: &str, principal_key: &str) -> Option<Arc<McpSession>> {
        let mut map = self.lock();
        let e = map.get_mut(id)?;
        if e.principal_key != principal_key {
            return None; // no existence leak: same as unknown
        }
        e.last_seen = Instant::now();
        Some(e.session.clone())
    }

    /// Handle an authenticated request (no Origin/Host/bearer checks — the caller did them).
    pub async fn handle_for_principal(&self, principal: &Principal, req: McpHttpRequest<'_>) -> HttpReply {
        self.prune(Instant::now());
        match req.method {
            "POST" => self.post(principal, req).await,
            "DELETE" => {
                let Some(sid) = req.session_id else {
                    return HttpReply::rpc_error(400, INVALID_REQUEST, "Missing Mcp-Session-Id");
                };
                if self.session_for(sid, &principal.key).is_none() {
                    return HttpReply::rpc_error(404, INVALID_REQUEST, "Session not found");
                }
                self.lock().remove(sid);
                HttpReply::empty(204)
            }
            _ => HttpReply::empty(405).with_header("allow", "POST, DELETE"),
        }
    }

    async fn post(&self, principal: &Principal, req: McpHttpRequest<'_>) -> HttpReply {
        if let Some(ct) = req.content_type
            && !ct.to_ascii_lowercase().starts_with("application/json")
        {
            return HttpReply::rpc_error(415, INVALID_REQUEST, "Content-Type must be application/json");
        }
        let Ok(sse) = accepts(req.accept) else {
            return HttpReply::rpc_error(406, INVALID_REQUEST, "Accept must include application/json or text/event-stream");
        };
        if req.body.len() > self.config.max_body_bytes {
            return HttpReply::rpc_error(413, INVALID_REQUEST, "Request body too large");
        }
        let value: Value = match serde_json::from_slice(req.body) {
            Ok(v) => v,
            Err(_) => return HttpReply::rpc_error(400, PARSE_ERROR, "Parse error"),
        };
        let reply = |v: Value| if sse { HttpReply::sse(&v) } else { HttpReply::json(200, &v) };

        if is_initialize(&value) {
            let session = McpSession::new();
            let ctx = McpContext {
                broker: principal.broker.clone(),
                session: session.clone(),
            };
            let Some(resp) = self.server.handle_value(value, &ctx).await else {
                return HttpReply::empty(202);
            };
            if resp.get("result").is_none() {
                return reply(resp);
            }
            let Some(sid) = new_session_id() else {
                return HttpReply::rpc_error(500, protocol::INTERNAL_ERROR, "Internal error");
            };
            self.insert_session(sid.clone(), &principal.key, session);
            return reply(resp).with_header(SESSION_HEADER, sid);
        }

        let Some(sid) = req.session_id else {
            return HttpReply::rpc_error(400, INVALID_REQUEST, "Missing Mcp-Session-Id (send initialize first)");
        };
        let Some(session) = self.session_for(sid, &principal.key) else {
            return HttpReply::rpc_error(404, INVALID_REQUEST, "Session not found; initialize a new session");
        };
        if let Some(pv) = req.protocol_version {
            let negotiated = session.protocol_version();
            let ok = ProtocolVersion::parse(pv).is_some_and(|v| Some(v) == negotiated);
            if !ok {
                return HttpReply::rpc_error(400, INVALID_REQUEST, "Unsupported or mismatched MCP-Protocol-Version");
            }
        }
        let ctx = McpContext {
            broker: principal.broker.clone(),
            session,
        };
        match self.server.handle_value(value, &ctx).await {
            Some(resp) => reply(resp),
            None => HttpReply::empty(202),
        }
    }

    fn origin_allowed(origin: Option<&str>, allowed: &[String]) -> bool {
        match origin {
            None => true,
            Some(o) => allowed.iter().any(|a| a.eq_ignore_ascii_case(o.trim_end_matches('/'))),
        }
    }

    /// Serve a cloud-tunnel `mcp` frame (CONTRACTS §13) for `principal` — the node resolves
    /// `frame.connection_id` to an active `remote_gateway` connection *before* calling this.
    pub async fn handle_tunnel_frame(
        &self,
        principal: &Principal,
        frame: &aipass_client::tunnel::McpFrame,
    ) -> aipass_client::tunnel::McpResponse {
        let body = frame.body_bytes();
        let method = frame.http_method.as_deref().unwrap_or("POST").to_ascii_uppercase();
        let reply = self
            .handle_for_principal(
                principal,
                McpHttpRequest {
                    method: &method,
                    session_id: frame.session_id.as_deref(),
                    protocol_version: frame.protocol_version.as_deref(),
                    accept: None,
                    content_type: None,
                    body: &body,
                },
            )
            .await;
        reply.into_tunnel_response()
    }

    /// Full HTTP handling: Origin/Host (local) or bearer (remote) checks, then MCP.
    pub async fn handle(&self, method: &Method, headers: &HeaderMap, body: &[u8]) -> HttpReply {
        let origin = header_str(headers, "origin");
        let principal = match &self.config.mode {
            HttpMode::Local {
                broker,
                allowed_origins,
                allowed_hosts,
            } => {
                if !Self::origin_allowed(origin, allowed_origins) {
                    return HttpReply::rpc_error(403, INVALID_REQUEST, "Forbidden origin");
                }
                let host = header_str(headers, "host").unwrap_or("");
                if !allowed_hosts.iter().any(|h| h.eq_ignore_ascii_case(host)) {
                    return HttpReply::rpc_error(403, INVALID_REQUEST, "Forbidden host");
                }
                Principal {
                    key: "local".into(),
                    broker: broker.clone(),
                }
            }
            HttpMode::Remote {
                resolver,
                resource_metadata_url,
                allowed_origins,
            } => {
                if !Self::origin_allowed(origin, allowed_origins) {
                    return HttpReply::rpc_error(403, INVALID_REQUEST, "Forbidden origin");
                }
                let challenge = |extra: &str| {
                    format!("Bearer {extra}resource_metadata=\"{resource_metadata_url}\"")
                };
                let token = header_str(headers, "authorization").and_then(|v| {
                    let (scheme, t) = v.trim().split_once(' ')?;
                    scheme.eq_ignore_ascii_case("bearer").then(|| t.trim())
                });
                let Some(token) = token.filter(|t| !t.is_empty()) else {
                    return HttpReply::rpc_error(401, INVALID_REQUEST, "Unauthorized")
                        .with_header("www-authenticate", challenge(""));
                };
                match resolver.resolve(token).await {
                    Ok(p) => p,
                    Err(e) if e.code == ErrorCode::IdentityUnverified => {
                        return HttpReply::rpc_error(401, INVALID_REQUEST, "Invalid token")
                            .with_header("www-authenticate", challenge("error=\"invalid_token\", "));
                    }
                    Err(e) if e.code == ErrorCode::ConnectionPaused || e.code == ErrorCode::Forbidden => {
                        return HttpReply::rpc_error(403, INVALID_REQUEST, "Connection paused or forbidden");
                    }
                    Err(_) => {
                        return HttpReply::rpc_error(503, protocol::INTERNAL_ERROR, "Broker unavailable");
                    }
                }
            }
        };
        let req = McpHttpRequest {
            method: method.as_str(),
            session_id: header_str(headers, SESSION_HEADER),
            protocol_version: header_str(headers, VERSION_HEADER),
            accept: header_str(headers, "accept"),
            content_type: header_str(headers, "content-type"),
            body,
        };
        self.handle_for_principal(&principal, req).await
    }

    /// axum router serving `/mcp` (and the protected-resource metadata when configured).
    pub fn router(self: &Arc<Self>) -> axum::Router {
        let mut r = axum::Router::new().route(
            "/mcp",
            axum::routing::any(mcp_endpoint).with_state(self.clone()),
        );
        if let Some(meta) = self.config.protected_resource_metadata.clone() {
            let m2 = meta.clone();
            r = r
                .route("/.well-known/oauth-protected-resource", get(move || async move { axum::Json(meta) }))
                .route("/.well-known/oauth-protected-resource/mcp", get(move || async move { axum::Json(m2) }));
        }
        r.layer(axum::extract::DefaultBodyLimit::max(self.config.max_body_bytes + 1024))
    }
}

async fn mcp_endpoint(
    State(t): State<Arc<StreamableHttp>>,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    to_response(t.handle(&method, &headers, &body).await)
}

/// Convert an [`HttpReply`] to an axum response.
pub fn to_response(r: HttpReply) -> Response {
    let mut resp = match r.body {
        Some(b) => Response::new(Body::from(b)),
        None => Response::new(Body::empty()),
    };
    *resp.status_mut() = StatusCode::from_u16(r.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    for (k, v) in r.headers {
        if let (Ok(name), Ok(val)) = (header::HeaderName::try_from(k.as_str()), HeaderValue::from_str(&v)) {
            resp.headers_mut().append(name, val);
        }
    }
    resp.into_response()
}

/// Remote-mode resolver for the `aipass-mcp http --remote` front end: the bearer token is an
/// `aipc_…` connection token, forwarded to the broker as the request credential (the bridge
/// stores nothing). Valid tokens are cached for 60 s by hash.
pub struct BrokerBearerResolver {
    client: aipass_client::BrokerClient,
    cache: Mutex<HashMap<String, Instant>>,
}

impl BrokerBearerResolver {
    /// Resolver against `client`'s endpoint.
    pub fn new(client: aipass_client::BrokerClient) -> Self {
        Self {
            client,
            cache: Mutex::new(HashMap::new()),
        }
    }
}

#[async_trait]
impl BearerResolver for BrokerBearerResolver {
    async fn resolve(&self, token: &str) -> Result<Principal, ApiError> {
        if !token.starts_with(signing::token_prefix::CONNECTION) || token.len() > 512 {
            return Err(ApiError::identity_unverified());
        }
        let key = signing::token_hash(token);
        let client = self.client.with_auth(aipass_client::Auth::bearer(token.to_owned()));
        let fresh = {
            let mut c = match self.cache.lock() {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };
            c.retain(|_, t| t.elapsed() < Duration::from_secs(60));
            c.contains_key(&key)
        };
        if !fresh {
            client.list_resources(None, None).await.map_err(|e| e.to_api_error())?;
            let mut c = match self.cache.lock() {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };
            if c.len() >= 1024 {
                c.clear();
            }
            c.insert(key.clone(), Instant::now());
        }
        Ok(Principal {
            key,
            broker: Arc::new(client),
        })
    }
}

/// Protected-resource metadata document (RFC 9728) for a public MCP URL.
pub fn protected_resource_metadata(mcp_url: &str, authorization_servers: &[String]) -> Value {
    json!({
        "resource": mcp_url,
        "authorization_servers": authorization_servers,
        "scopes_supported": ["aipass.tools"],
        "bearer_methods_supported": ["header"],
    })
}
