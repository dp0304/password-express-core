// SPDX-License-Identifier: Apache-2.0
//! axum HTTP API (CONTRACTS §6.3, prefix `/v1`, JSON).
//!
//! Auth classes: **C** = AppConnection (`AIPass-Sig kid=conn_…` or `Bearer aipc_…`);
//! **D** = trusted device (`AIPass-Sig kid=dev_…`, active owner/member); **A** = local
//! admin (UDS peer on a socket served with [`UdsOptions::admin_peers`], or
//! `Bearer <admin.token>`); **P** = public (rate-limited per peer).
//!
//! Every response carries `X-Request-Id`; errors use the §1.5 envelope with zh-CN
//! messages, English when `Accept-Language` starts with `en`. Request bodies are buffered
//! (bounded) so the signature covers the exact bytes; bodies, tokens and results are
//! never logged.

mod handlers;
mod serve;

use std::net::SocketAddr;
use std::sync::Arc;

use aipass_types::error::{ApiError, ErrorCode, Lang};
use aipass_types::ids::{DeviceId, RequestId};
use aipass_types::signing::Authorization;
use axum::Router;
use axum::body::Body;
use axum::extract::{ConnectInfo, OriginalUri, Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::Broker;
use crate::principal::{Actor, ConnectionPrincipal, VerifiedPrincipal};

pub use serve::{UdsOptions, UdsPeer, bind_uds, serve_tcp, serve_uds, serve_uds_listener};

/// Header carrying the per-request id.
pub const REQUEST_ID_HEADER: &str = "x-request-id";

/// Router state.
#[derive(Clone)]
pub struct BrokerState {
    /// The broker.
    pub broker: Arc<Broker>,
}

impl BrokerState {
    /// Wrap a broker.
    pub fn new(broker: Arc<Broker>) -> Self {
        Self { broker }
    }
}

impl std::fmt::Debug for BrokerState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BrokerState").finish_non_exhaustive()
    }
}

/// Authenticated caller of one request.
#[derive(Debug, Clone)]
pub(crate) enum Auth {
    None,
    Connection(ConnectionPrincipal),
    Device(DeviceId),
    Admin,
}

/// Marker inserted by [`serve_uds`] when peers of that socket are local admins.
#[derive(Debug, Clone, Copy)]
pub(crate) struct UdsAdminUid(pub u32);

/// Per-request context (inserted by the middleware).
#[derive(Debug, Clone)]
pub(crate) struct ReqCtx {
    pub lang: Lang,
    pub auth: Auth,
    pub admin_peer: bool,
    pub peer: String,
}

impl ReqCtx {
    /// Principal class C.
    pub(crate) fn connection(&self) -> Result<ConnectionPrincipal, ApiError> {
        match &self.auth {
            Auth::Connection(p) => Ok(p.clone()),
            Auth::None => Err(ApiError::identity_unverified()),
            _ => Err(ApiError::new(ErrorCode::Forbidden)),
        }
    }

    /// Principal classes D or A.
    pub(crate) fn trusted(&self) -> Result<Actor, ApiError> {
        match &self.auth {
            Auth::Device(d) => Ok(Actor::Device(d.clone())),
            Auth::Admin => Ok(Actor::Admin),
            _ if self.admin_peer => Ok(Actor::Admin),
            Auth::None => Err(ApiError::identity_unverified()),
            Auth::Connection(_) => Err(ApiError::new(ErrorCode::Forbidden)),
        }
    }

    /// Principal class A only.
    pub(crate) fn admin(&self) -> Result<Actor, ApiError> {
        match &self.auth {
            Auth::Admin => Ok(Actor::Admin),
            _ if self.admin_peer => Ok(Actor::Admin),
            Auth::None => Err(ApiError::identity_unverified()),
            _ => Err(ApiError::new(ErrorCode::Forbidden)),
        }
    }

    /// Principal class D only.
    pub(crate) fn device(&self) -> Result<DeviceId, ApiError> {
        match &self.auth {
            Auth::Device(d) => Ok(d.clone()),
            Auth::None => Err(ApiError::identity_unverified()),
            _ => Err(ApiError::new(ErrorCode::Forbidden)),
        }
    }
}

/// Handler error: rendered by the middleware with the request's language and id.
#[derive(Debug)]
pub(crate) struct HttpError(pub ApiError);

impl From<ApiError> for HttpError {
    fn from(e: ApiError) -> Self {
        Self(e)
    }
}

#[derive(Debug, Clone)]
struct ErrorMarker(ApiError);

impl IntoResponse for HttpError {
    fn into_response(self) -> Response {
        let status = StatusCode::from_u16(self.0.http_status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        let mut resp = status.into_response();
        resp.extensions_mut().insert(ErrorMarker(self.0));
        resp
    }
}

pub(crate) type HResult = Result<Response, HttpError>;

/// Render an error envelope.
pub(crate) fn render_error(e: ApiError, lang: Lang, request_id: &str) -> Response {
    let status = StatusCode::from_u16(e.http_status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let body = e.with_request_id(request_id).to_body(lang);
    let mut resp = (status, axum::Json(body)).into_response();
    if let Ok(v) = HeaderValue::from_str(request_id) {
        resp.headers_mut().insert(REQUEST_ID_HEADER, v);
    }
    resp
}

/// JSON response with an explicit status.
pub(crate) fn json<T: Serialize>(status: u16, v: &T) -> Response {
    let status = StatusCode::from_u16(status).unwrap_or(StatusCode::OK);
    (status, axum::Json(v)).into_response()
}

/// Parse a JSON body without echoing values from it in errors.
pub(crate) fn parse_json<T: DeserializeOwned>(body: &[u8]) -> Result<T, ApiError> {
    if body.is_empty() {
        return Err(ApiError::invalid_request("请求体不能为空", "The request body must not be empty."));
    }
    serde_json::from_slice(body).map_err(|e| {
        let text = e.to_string();
        let mut err = ApiError::invalid_request("请求体不是有效的 JSON 或字段不符合要求", "The request body is not valid JSON or a field is invalid.")
            .with_detail("line", e.line())
            .with_detail("column", e.column());
        if text.starts_with("missing field") || text.starts_with("unknown field") {
            let reason: String = text.split(" at line").next().unwrap_or_default().chars().take(120).collect();
            err = err.with_detail("reason", reason);
        }
        err
    })
}

async fn authenticate(
    broker: &Broker,
    value: &HeaderValue,
    method: &str,
    path_and_query: &str,
    body: &[u8],
) -> Result<Auth, ApiError> {
    let text = value.to_str().map_err(|_| ApiError::identity_unverified())?;
    match Authorization::parse(text).map_err(ApiError::from)? {
        Authorization::Sig(h) => match broker.verify_request_signature(&h, method, path_and_query, body).await? {
            VerifiedPrincipal::Connection(p) => Ok(Auth::Connection(p)),
            VerifiedPrincipal::Device(d) => Ok(Auth::Device(d)),
        },
        Authorization::Bearer(token) => {
            if token.starts_with(aipass_types::signing::token_prefix::CONNECTION) {
                Ok(Auth::Connection(broker.authenticate_connection_token(&token).await?))
            } else if broker.verify_admin_token(&token) {
                Ok(Auth::Admin)
            } else {
                Err(ApiError::identity_unverified())
            }
        }
    }
}

async fn context_mw(State(st): State<BrokerState>, req: Request, next: Next) -> Response {
    let request_id = RequestId::generate().into_string();
    let lang = Lang::from_accept_language(req.headers().get(header::ACCEPT_LANGUAGE).and_then(|v| v.to_str().ok()));
    let (mut parts, body) = req.into_parts();
    let bytes = match axum::body::to_bytes(body, st.broker.config().max_body_bytes).await {
        Ok(b) => b,
        Err(_) => {
            return render_error(
                ApiError::invalid_request("请求体过大或读取失败", "The request body is too large or could not be read."),
                lang,
                &request_id,
            );
        }
    };
    let uri = parts
        .extensions
        .get::<OriginalUri>()
        .map(|u| u.0.clone())
        .unwrap_or_else(|| parts.uri.clone());
    let path_and_query = uri.path_and_query().map(|p| p.as_str().to_owned()).unwrap_or_else(|| "/".into());
    let uds_peer = parts.extensions.get::<ConnectInfo<UdsPeer>>().map(|c| c.0.clone());
    let admin_peer = match (parts.extensions.get::<UdsAdminUid>(), &uds_peer) {
        (Some(admin), Some(peer)) => peer.uid == Some(admin.0),
        _ => false,
    };
    let peer = if uds_peer.is_some() {
        "uds".to_owned()
    } else if let Some(ConnectInfo(addr)) = parts.extensions.get::<ConnectInfo<SocketAddr>>() {
        addr.ip().to_string()
    } else {
        "unknown".to_owned()
    };
    let auth = match parts.headers.get(header::AUTHORIZATION) {
        None => Auth::None,
        Some(v) => match authenticate(&st.broker, v, parts.method.as_str(), &path_and_query, &bytes).await {
            Ok(a) => a,
            Err(e) => return render_error(e, lang, &request_id),
        },
    };
    parts.extensions.insert(ReqCtx {
        lang,
        auth,
        admin_peer,
        peer,
    });
    let req = Request::from_parts(parts, Body::from(bytes));
    let mut resp = next.run(req).await;
    if let Some(ErrorMarker(e)) = resp.extensions_mut().remove::<ErrorMarker>() {
        return render_error(e, lang, &request_id);
    }
    if let Ok(v) = HeaderValue::from_str(&request_id) {
        resp.headers_mut().insert(REQUEST_ID_HEADER, v);
    }
    resp.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp
}

/// The broker router: every CONTRACTS §6.3 endpoint under `/v1` (plus the additive
/// endpoints listed in the README). Merge it into the embedding server's router.
pub fn router(state: BrokerState) -> Router {
    use axum::routing::{get, post, put};
    use handlers as h;
    Router::new()
        // P
        .route("/v1/health", get(h::health))
        .route("/v1/connections/pair", post(h::pair))
        .route("/v1/connections/pair/{id}", get(h::pair_status))
        // C
        .route("/v1/resources", get(h::resources))
        .route("/v1/operations", post(h::operation_request).get(h::operations_list))
        .route("/v1/operations/{id}", get(h::operation_get))
        .route("/v1/operations/{id}/cancel", post(h::operation_cancel))
        .route("/v1/access/requests", post(h::access_request))
        .route("/v1/access/requests/{id}", get(h::access_request_get))
        .route("/v1/access/grants/{id}/release", post(h::grant_release))
        // D, A
        .route("/v1/approvals", get(h::approvals))
        .route("/v1/approvals/{id}", get(h::approval_get))
        .route("/v1/approvals/{id}/decision", post(h::approval_decision))
        .route("/v1/connections", get(h::connections))
        .route("/v1/connections/{id}", get(h::connection_get))
        .route("/v1/connections/{id}/{action}", post(h::connection_action))
        .route("/v1/projects", get(h::projects).post(h::project_create))
        .route("/v1/admin/resources", get(h::admin_resources).post(h::admin_resource_create))
        .route(
            "/v1/admin/resources/{id}",
            get(h::admin_resource_get)
                .patch(h::admin_resource_patch)
                .delete(h::admin_resource_delete),
        )
        .route("/v1/admin/entries/{id}/conflict", put(h::entry_conflict))
        .route("/v1/policies", get(h::policies).post(h::policy_create))
        .route("/v1/policies/{id}/disable", post(h::policy_disable))
        .route("/v1/grants", get(h::grants))
        .route("/v1/grants/{id}", get(h::grant_get))
        .route("/v1/grants/{id}/revoke", post(h::grant_revoke))
        .route("/v1/audit", get(h::audit))
        .route("/v1/audit/verify", get(h::audit_verify))
        .route("/v1/activity/summary", get(h::activity))
        .route("/v1/executors", get(h::executors))
        .route("/v1/state", get(h::state))
        // A
        .route("/v1/admin/devices", get(h::devices).post(h::device_add))
        .route("/v1/admin/devices/{id}/revoke", post(h::device_revoke))
        .route("/v1/admin/connections", post(h::admin_connection_create))
        // D
        .route("/v1/credentials/delegate", post(h::delegate))
        .fallback(h::not_found)
        .layer(axum::middleware::from_fn_with_state(state.clone(), context_mw))
        .layer(tower_http::sensitive_headers::SetSensitiveRequestHeadersLayer::new([
            header::AUTHORIZATION,
        ]))
        .with_state(state)
}
