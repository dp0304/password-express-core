// SPDX-License-Identifier: Apache-2.0
//! In-process **mock broker** for tests (feature `test-support`; never part of a release).
//!
//! Implements the public pairing endpoints and the AI-facing **C** endpoints of CONTRACTS
//! §6.3 with real `AIPass-Sig` verification (±300 s skew, per-kid nonce replay cache, exact
//! path+query and body hash) and `Bearer aipc_…` connection tokens (stored as SHA-256
//! hashes). Business logic is deliberately simple: operations need an approval (granted by the
//! test via [`MockBroker::approve`]) unless the connection already holds a grant for the
//! resource; IDs owned by another connection answer `NOT_FOUND`.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use aipass_crypto::b64u;
use aipass_types::models::{
    AccessRequest, AccessRequestResponse, ApprovalStatus, CancelResponse, ConnectionStatus,
    Environment, ExecutorStatus, GrantStatus, HealthResponse, OperationRequest, OperationResponse,
    OperationResult, OperationStatus, OperationView, PairConnectionRequest,
    PairConnectionResponse, PairStatus, PairStatusResponse, ProtectionLevel, ReleaseResponse,
    ResourceStatus, ResourceView, ResourcesResponse, SideEffectClass, SideEffects,
};
use aipass_types::signing::{self, Authorization, NonceCache};
use aipass_types::{
    ApiError, ApprovalRequestId, ConnectionId, ErrorCode, GrantId, Lang,
    OperationId, PairingId, ProjectId, ResourceId,
};
use axum::body::Bytes;
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use serde_json::{Value, json};

/// A recorded request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeenRequest {
    /// Method.
    pub method: String,
    /// Path + query as received.
    pub path_and_query: String,
    /// Authenticated principal (`conn_…`), if any.
    pub principal: Option<String>,
}

#[derive(Debug, Clone)]
struct Conn {
    public_key: [u8; 32],
    status: ConnectionStatus,
}

#[derive(Debug, Clone)]
struct Op {
    owner: ConnectionId,
    request: OperationRequest,
    digest: String,
    response: OperationResponse,
}

#[derive(Debug, Clone)]
struct Approval {
    owner: ConnectionId,
    resource_id: ResourceId,
    status: ApprovalStatus,
    grant_id: Option<GrantId>,
    operation_id: Option<OperationId>,
}

#[derive(Debug, Clone)]
struct Grant {
    owner: ConnectionId,
    resource_id: ResourceId,
    status: GrantStatus,
}

struct State {
    conns: HashMap<String, Conn>,
    pairings: HashMap<String, (ConnectionId, PairStatus)>,
    tokens: HashMap<String, ConnectionId>,
    resources: Vec<ResourceView>,
    ops: HashMap<String, Op>,
    idem: HashMap<(String, String), String>,
    approvals: HashMap<String, Approval>,
    grants: HashMap<String, Grant>,
    result_data: Value,
    seen: Vec<SeenRequest>,
    nonces: NonceCache,
}

/// The mock broker. Cheap to clone (shared state).
#[derive(Clone)]
pub struct MockBroker {
    state: Arc<Mutex<State>>,
}

impl Default for MockBroker {
    fn default() -> Self {
        Self::new()
    }
}

/// A demo resource view (`postgres.query_view`, test environment).
pub fn demo_resource(project: &ProjectId) -> ResourceView {
    ResourceView {
        resource_id: ResourceId::generate(),
        alias: "路亚站测试库".into(),
        service: "postgres".into(),
        project_id: project.clone(),
        environment: Environment::Test,
        operations: vec![OperationView {
            name: "postgres.query_view".into(),
            description: "查询允许的统计视图".into(),
            side_effect: SideEffectClass::Read,
            parameters_schema: json!({
                "type": "object",
                "properties": {
                    "view": {"type": "string"},
                    "fields": {"type": "array", "items": {"type": "string"}},
                    "period_days": {"type": "integer"}
                },
                "required": ["view", "fields"]
            }),
        }],
        status: ResourceStatus::Available,
        protection_level: ProtectionLevel::Compatible,
        executor_status: ExecutorStatus::Online,
    }
}

impl MockBroker {
    /// Empty broker with one demo resource in a fresh project.
    pub fn new() -> Self {
        let project = ProjectId::generate();
        Self {
            state: Arc::new(Mutex::new(State {
                conns: HashMap::new(),
                pairings: HashMap::new(),
                tokens: HashMap::new(),
                resources: vec![demo_resource(&project)],
                ops: HashMap::new(),
                idem: HashMap::new(),
                approvals: HashMap::new(),
                grants: HashMap::new(),
                result_data: json!([{"day": "2026-10-01", "plan": "pro", "subscriptions": 42}]),
                seen: Vec::new(),
                nonces: NonceCache::default(),
            })),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        match self.state.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        }
    }

    /// Register an **active** connection with this public key.
    pub fn add_connection(&self, id: &ConnectionId, public_key: [u8; 32]) {
        self.lock().conns.insert(
            id.as_str().to_owned(),
            Conn {
                public_key,
                status: ConnectionStatus::Active,
            },
        );
    }

    /// Register a bearer connection token (`aipc_…`) for `id` (stored hashed).
    pub fn add_token(&self, id: &ConnectionId, token: &str) {
        let mut s = self.lock();
        s.conns.entry(id.as_str().to_owned()).or_insert(Conn {
            public_key: [0u8; 32],
            status: ConnectionStatus::Active,
        });
        s.tokens.insert(signing::token_hash(token), id.clone());
    }

    /// Change a connection's status.
    pub fn set_connection_status(&self, id: &ConnectionId, status: ConnectionStatus) {
        if let Some(c) = self.lock().conns.get_mut(id.as_str()) {
            c.status = status;
        }
    }

    /// Resources served by `GET /v1/resources`.
    pub fn resources(&self) -> Vec<ResourceView> {
        self.lock().resources.clone()
    }

    /// Replace the result data of succeeded operations.
    pub fn set_result_data(&self, data: Value) {
        self.lock().result_data = data;
    }

    /// Requests seen so far.
    pub fn seen(&self) -> Vec<SeenRequest> {
        self.lock().seen.clone()
    }

    /// Approve a pending pairing of `connection_id` (as a trusted device would).
    pub fn approve_pairing(&self, connection_id: &ConnectionId) -> bool {
        self.finish_pairing(connection_id, PairStatus::Approved)
    }

    /// Deny a pending pairing.
    pub fn deny_pairing(&self, connection_id: &ConnectionId) -> bool {
        self.finish_pairing(connection_id, PairStatus::Denied)
    }

    fn finish_pairing(&self, connection_id: &ConnectionId, status: PairStatus) -> bool {
        let mut s = self.lock();
        let mut found = false;
        for (cid, st) in s.pairings.values_mut() {
            if cid == connection_id && *st == PairStatus::Pending {
                *st = status;
                found = true;
            }
        }
        if found && let Some(c) = s.conns.get_mut(connection_id.as_str()) {
            c.status = if status == PairStatus::Approved {
                ConnectionStatus::Active
            } else {
                ConnectionStatus::Removed
            };
        }
        found
    }

    /// Pending connection ids awaiting pairing approval.
    pub fn pending_pairings(&self) -> Vec<ConnectionId> {
        self.lock()
            .pairings
            .values()
            .filter(|(_, st)| *st == PairStatus::Pending)
            .map(|(c, _)| c.clone())
            .collect()
    }

    /// Approve an approval request: creates a grant and completes a waiting operation.
    pub fn approve(&self, id: &ApprovalRequestId) -> Option<GrantId> {
        let mut s = self.lock();
        let data = s.result_data.clone();
        let apr = s.approvals.get_mut(id.as_str())?;
        if apr.status != ApprovalStatus::Pending {
            return None;
        }
        let grant = GrantId::generate();
        apr.status = ApprovalStatus::Approved;
        apr.grant_id = Some(grant.clone());
        let (owner, resource, op_id) = (apr.owner.clone(), apr.resource_id.clone(), apr.operation_id.clone());
        s.grants.insert(
            grant.as_str().to_owned(),
            Grant {
                owner,
                resource_id: resource,
                status: GrantStatus::Active,
            },
        );
        if let Some(op_id) = op_id
            && let Some(op) = s.ops.get_mut(op_id.as_str())
        {
            op.response = succeeded(op_id.clone(), &data);
        }
        Some(grant)
    }

    /// Deny an approval request.
    pub fn deny(&self, id: &ApprovalRequestId) -> bool {
        let mut s = self.lock();
        let Some(apr) = s.approvals.get_mut(id.as_str()) else {
            return false;
        };
        apr.status = ApprovalStatus::Denied;
        if let Some(op_id) = apr.operation_id.clone()
            && let Some(op) = s.ops.get_mut(op_id.as_str())
        {
            op.response = OperationResponse {
                status: OperationStatus::Denied,
                operation_id: op_id,
                approval_request_id: Some(id.clone()),
                expires_in_seconds: None,
                message: None,
                result: None,
                error: Some(ApiError::new(ErrorCode::ApprovalDenied).to_object(Lang::ZhCn)),
            };
        }
        true
    }

    /// axum router (fallback handler doing its own routing so the raw URI is verified).
    pub fn router(&self) -> axum::Router {
        let me = self.clone();
        axum::Router::new().fallback(move |method: Method, uri: Uri, headers: HeaderMap, body: Bytes| {
            let me = me.clone();
            async move { me.handle(method, uri, headers, body) }
        })
    }

    /// Serve on `127.0.0.1:0`; returns the bound address.
    pub async fn serve_tcp(&self) -> std::io::Result<(SocketAddr, tokio::task::JoinHandle<()>)> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let router = self.router();
        let join = tokio::spawn(async move {
            let _ = axum::serve(listener, router).await;
        });
        Ok((addr, join))
    }

    /// Serve on a Unix domain socket.
    #[cfg(unix)]
    pub async fn serve_unix(
        &self,
        path: &std::path::Path,
    ) -> std::io::Result<tokio::task::JoinHandle<()>> {
        let listener = tokio::net::UnixListener::bind(path)?;
        let router = self.router();
        Ok(tokio::spawn(async move {
            let _ = axum::serve(listener, router).await;
        }))
    }

    fn handle(&self, method: Method, uri: Uri, headers: HeaderMap, body: Bytes) -> Response {
        let lang = Lang::from_accept_language(
            headers
                .get("accept-language")
                .and_then(|v| v.to_str().ok()),
        );
        let pq = uri
            .path_and_query()
            .map(|p| p.as_str().to_owned())
            .unwrap_or_else(|| "/".into());
        match self.route(&method, &uri, &pq, &headers, &body) {
            Ok((status, v)) => (status, axum::Json(v)).into_response(),
            Err(e) => {
                let status = StatusCode::from_u16(e.http_status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
                (status, axum::Json(e.to_body(lang))).into_response()
            }
        }
    }

    fn authenticate(
        &self,
        method: &Method,
        pq: &str,
        headers: &HeaderMap,
        body: &[u8],
        allow_pending: bool,
    ) -> Result<ConnectionId, ApiError> {
        let raw = headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .ok_or_else(ApiError::identity_unverified)?;
        let auth = Authorization::parse(raw).map_err(ApiError::from)?;
        let s = self.lock();
        let (id, conn) = match auth {
            Authorization::Sig(h) => {
                let conn = s
                    .conns
                    .get(&h.kid)
                    .cloned()
                    .ok_or_else(ApiError::identity_unverified)?;
                signing::verify_request_with_nonce(
                    &h,
                    &conn.public_key,
                    method.as_str(),
                    pq,
                    body,
                    aipass_types::time::unix_now(),
                    &s.nonces,
                )?;
                (ConnectionId::parse(&h.kid)?, conn)
            }
            Authorization::Bearer(t) => {
                let id = s
                    .tokens
                    .get(&signing::token_hash(&t))
                    .cloned()
                    .ok_or_else(ApiError::identity_unverified)?;
                let conn = s
                    .conns
                    .get(id.as_str())
                    .cloned()
                    .ok_or_else(ApiError::identity_unverified)?;
                (id, conn)
            }
        };
        match conn.status {
            ConnectionStatus::Active => Ok(id),
            // the pairing-status endpoint answers for pending and finished (denied) pairings
            _ if allow_pending => Ok(id),
            ConnectionStatus::Paused => Err(ApiError::new(ErrorCode::ConnectionPaused)),
            _ => Err(ApiError::identity_unverified()),
        }
    }

    fn route(
        &self,
        method: &Method,
        uri: &Uri,
        pq: &str,
        headers: &HeaderMap,
        body: &[u8],
    ) -> Result<(StatusCode, Value), ApiError> {
        let path = uri.path();
        let segs: Vec<&str> = path.trim_start_matches('/').split('/').collect();
        let record = |principal: Option<&ConnectionId>| {
            self.lock().seen.push(SeenRequest {
                method: method.to_string(),
                path_and_query: pq.to_owned(),
                principal: principal.map(|p| p.as_str().to_owned()),
            });
        };
        match (method.as_str(), segs.as_slice()) {
            ("GET", ["v1", "health"]) => {
                record(None);
                ok(&HealthResponse {
                    status: "ok".into(),
                    version: "mock".into(),
                    executor_online: true,
                    protection_level: ProtectionLevel::Compatible,
                })
            }
            ("POST", ["v1", "connections", "pair"]) => {
                record(None);
                let req: PairConnectionRequest = parse(body)?;
                let pk = b64u::decode_array::<32>(&req.public_key).map_err(|_| {
                    ApiError::invalid_request("公钥无效", "invalid public key")
                })?;
                let cid = ConnectionId::generate();
                let pid = PairingId::generate();
                let code = format!("{:06}", aipass_crypto::rng::random_below(1_000_000).unwrap_or(0));
                let mut s = self.lock();
                s.conns.insert(
                    cid.as_str().to_owned(),
                    Conn {
                        public_key: pk,
                        status: ConnectionStatus::Pending,
                    },
                );
                s.pairings
                    .insert(pid.as_str().to_owned(), (cid.clone(), PairStatus::Pending));
                Ok((
                    StatusCode::CREATED,
                    to_value(&PairConnectionResponse {
                        pairing_request_id: pid,
                        connection_id: cid,
                        pairing_code: code,
                        expires_at: aipass_types::time::add_secs(&aipass_types::time::now(), 600),
                    })?,
                ))
            }
            ("GET", ["v1", "connections", "pair", id]) => {
                let who = self.authenticate(method, pq, headers, body, true)?;
                record(Some(&who));
                let s = self.lock();
                let (cid, st) = s.pairings.get(*id).cloned().ok_or_else(ApiError::not_found)?;
                if cid != who {
                    return Err(ApiError::not_found());
                }
                ok(&PairStatusResponse {
                    status: st,
                    connection_id: cid,
                })
            }
            ("GET", ["v1", "resources"]) => {
                let who = self.authenticate(method, pq, headers, body, false)?;
                record(Some(&who));
                let mut project = None;
                let mut service = None;
                for (k, v) in url::form_urlencoded::parse(uri.query().unwrap_or("").as_bytes()) {
                    match k.as_ref() {
                        "project_id" => project = Some(v.into_owned()),
                        "service" => service = Some(v.into_owned()),
                        _ => {}
                    }
                }
                let resources = self
                    .lock()
                    .resources
                    .iter()
                    .filter(|r| project.as_deref().is_none_or(|p| r.project_id.as_str() == p))
                    .filter(|r| service.as_deref().is_none_or(|sv| r.service == sv))
                    .cloned()
                    .collect();
                ok(&ResourcesResponse { resources })
            }
            ("POST", ["v1", "operations"]) => {
                let who = self.authenticate(method, pq, headers, body, false)?;
                record(Some(&who));
                let req: OperationRequest = parse(body)?;
                req.validate()?;
                let digest = aipass_types::exec::parameters_digest(&req.operation, &req.parameters)?;
                let mut s = self.lock();
                let idem_key = (who.as_str().to_owned(), req.idempotency_key.clone());
                if let Some(existing) = s.idem.get(&idem_key).cloned() {
                    let op = s.ops.get(&existing).cloned().ok_or_else(ApiError::internal)?;
                    if op.digest != digest || op.request.resource_id != req.resource_id {
                        return Err(ApiError::new(ErrorCode::IdempotencyConflict));
                    }
                    return respond_op(&op.response);
                }
                let res = s
                    .resources
                    .iter()
                    .find(|r| r.resource_id == req.resource_id)
                    .cloned()
                    .ok_or_else(ApiError::not_found)?;
                if !res.operations.iter().any(|o| o.name == req.operation) {
                    return Err(ApiError::scope_denied());
                }
                let op_id = OperationId::generate();
                let has_grant = s.grants.values().any(|g| {
                    g.owner == who && g.resource_id == req.resource_id && g.status == GrantStatus::Active
                });
                let response = if has_grant {
                    succeeded(op_id.clone(), &s.result_data)
                } else {
                    let apr = ApprovalRequestId::generate();
                    s.approvals.insert(
                        apr.as_str().to_owned(),
                        Approval {
                            owner: who.clone(),
                            resource_id: req.resource_id.clone(),
                            status: ApprovalStatus::Pending,
                            grant_id: None,
                            operation_id: Some(op_id.clone()),
                        },
                    );
                    OperationResponse::approval_required(op_id.clone(), apr, 120)
                };
                s.idem.insert(idem_key, op_id.as_str().to_owned());
                s.ops.insert(
                    op_id.as_str().to_owned(),
                    Op {
                        owner: who,
                        request: req,
                        digest,
                        response: response.clone(),
                    },
                );
                respond_op(&response)
            }
            ("GET", ["v1", "operations", id]) => {
                let who = self.authenticate(method, pq, headers, body, false)?;
                record(Some(&who));
                let s = self.lock();
                let op = s.ops.get(*id).filter(|o| o.owner == who).ok_or_else(ApiError::not_found)?;
                respond_op(&op.response)
            }
            ("POST", ["v1", "operations", id, "cancel"]) => {
                let who = self.authenticate(method, pq, headers, body, false)?;
                record(Some(&who));
                let mut s = self.lock();
                let op = s
                    .ops
                    .get_mut(*id)
                    .filter(|o| o.owner == who)
                    .ok_or_else(ApiError::not_found)?;
                let cancelled = !op.response.status.is_terminal();
                if cancelled {
                    op.response.status = OperationStatus::Cancelled;
                    op.response.approval_request_id = None;
                    op.response.expires_in_seconds = None;
                    op.response.message = None;
                }
                ok(&CancelResponse {
                    operation_id: op.response.operation_id.clone(),
                    status: op.response.status,
                    cancelled,
                    side_effects: SideEffects::None,
                    message: if cancelled { "已取消".into() } else { "操作已结束，无法取消".into() },
                })
            }
            ("POST", ["v1", "access", "requests"]) => {
                let who = self.authenticate(method, pq, headers, body, false)?;
                record(Some(&who));
                let req: AccessRequest = parse(body)?;
                let mut s = self.lock();
                if !s.resources.iter().any(|r| r.resource_id == req.resource_id) {
                    return Err(ApiError::not_found());
                }
                let apr = ApprovalRequestId::generate();
                s.approvals.insert(
                    apr.as_str().to_owned(),
                    Approval {
                        owner: who,
                        resource_id: req.resource_id,
                        status: ApprovalStatus::Pending,
                        grant_id: None,
                        operation_id: None,
                    },
                );
                Ok((
                    StatusCode::ACCEPTED,
                    to_value(&AccessRequestResponse {
                        approval_request_id: apr,
                        status: ApprovalStatus::Pending,
                        grant_id: None,
                    })?,
                ))
            }
            ("GET", ["v1", "access", "requests", id]) => {
                let who = self.authenticate(method, pq, headers, body, false)?;
                record(Some(&who));
                let s = self.lock();
                let a = s.approvals.get(*id).filter(|a| a.owner == who).ok_or_else(ApiError::not_found)?;
                ok(&AccessRequestResponse {
                    approval_request_id: ApprovalRequestId::parse(id)?,
                    status: a.status,
                    grant_id: a.grant_id.clone(),
                })
            }
            ("POST", ["v1", "access", "grants", id, "release"]) => {
                let who = self.authenticate(method, pq, headers, body, false)?;
                record(Some(&who));
                let mut s = self.lock();
                let g = s
                    .grants
                    .get_mut(*id)
                    .filter(|g| g.owner == who)
                    .ok_or_else(ApiError::not_found)?;
                g.status = GrantStatus::Released;
                ok(&ReleaseResponse {
                    grant_id: GrantId::parse(id)?,
                    status: GrantStatus::Released,
                })
            }
            _ => {
                record(None);
                Err(ApiError::not_found())
            }
        }
    }
}

fn succeeded(op_id: OperationId, data: &Value) -> OperationResponse {
    OperationResponse {
        status: OperationStatus::Succeeded,
        operation_id: op_id,
        approval_request_id: None,
        expires_in_seconds: None,
        message: None,
        result: Some(OperationResult {
            rows: data.as_array().map(|a| a.len() as u64),
            data: data.clone(),
            truncated: false,
            restricted: false,
            restricted_fields: vec![],
        }),
        error: None,
    }
}

fn respond_op(r: &OperationResponse) -> Result<(StatusCode, Value), ApiError> {
    let status = StatusCode::from_u16(r.http_status()).unwrap_or(StatusCode::OK);
    Ok((status, to_value(r)?))
}

fn parse<T: serde::de::DeserializeOwned>(body: &[u8]) -> Result<T, ApiError> {
    serde_json::from_slice(body)
        .map_err(|_| ApiError::invalid_request("请求体无效", "invalid request body"))
}

fn to_value<T: serde::Serialize>(v: &T) -> Result<Value, ApiError> {
    serde_json::to_value(v).map_err(|_| ApiError::internal())
}

fn ok<T: serde::Serialize>(v: &T) -> Result<(StatusCode, Value), ApiError> {
    Ok((StatusCode::OK, to_value(v)?))
}
