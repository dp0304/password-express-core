// SPDX-License-Identifier: Apache-2.0
//! [`BrokerClient`] — typed calls for the broker `/v1` API (CONTRACTS §6.3).
//!
//! The same client serves three kinds of principals, chosen by its [`Auth`]:
//! AI connections (**C**: `AIPass-Sig kid=conn_…` or `Bearer aipc_…`), trusted devices
//! (**D**: `AIPass-Sig kid=dev_…`) and the local admin (**A**: UDS peer or the admin bearer
//! token). The broker — not this client — decides what each principal may do.

use std::time::Duration;

use aipass_types::models::{
    AccessRequest, AccessRequestResponse, ActivitySummary, AdminResourcesResponse, AppConnection,
    ApprovalDecision, ApprovalStatus, ApprovalsResponse, ApproveConnectionRequest, AuditResponse,
    AuditVerifyResponse, CancelResponse, ConnectionsResponse, CreateProjectRequest,
    DecisionResponse, DelegateCredentialRequest, ExecutorsResponse, GrantStatus, GrantsResponse,
    HealthResponse, OperationRequest, OperationResponse, OperationsResponse,
    PairConnectionRequest, PairConnectionResponse, PairStatusResponse, PoliciesResponse, Policy,
    Project, ProjectsResponse, ReleaseResponse, Resource, ResourceInput, ResourcePatch,
    ResourcesResponse, RevocationLevel, RevocationReport, RevokeRequest,
};
use aipass_types::{
    ApprovalRequestId, ConnectionId, GrantId, Lang, OperationId, PairingId, PolicyId, ProjectId,
    ResourceId,
};
use http::{HeaderName, HeaderValue, Method};
use serde::Serialize;
use serde::de::DeserializeOwned;
use url::form_urlencoded;

use crate::auth::Auth;
use crate::endpoint::BrokerEndpoint;
use crate::error::{ClientError, decode_error_body};
use crate::transport::{RawResponse, Transport};

/// Default request timeout (operations may run synchronously for a few seconds).
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(60);
/// Default connect timeout.
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Actions on an AI connection (`POST /connections/{id}/{action}`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionAction {
    /// Deny a pending connection.
    Deny,
    /// Pause (`CONNECTION_PAUSED`).
    Pause,
    /// Resume.
    Resume,
    /// Remove.
    Remove,
    /// Revoke every grant of the connection.
    RevokeAll,
}

impl ConnectionAction {
    /// Path segment.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Deny => "deny",
            Self::Pause => "pause",
            Self::Resume => "resume",
            Self::Remove => "remove",
            Self::RevokeAll => "revoke_all",
        }
    }
}

/// Builder for [`BrokerClient`].
#[derive(Debug, Clone)]
pub struct BrokerClientBuilder {
    endpoint: BrokerEndpoint,
    auth: Auth,
    lang: Lang,
    timeout: Duration,
    connect_timeout: Duration,
    user_agent: String,
}

impl BrokerClientBuilder {
    /// Authentication.
    pub fn auth(mut self, auth: Auth) -> Self {
        self.auth = auth;
        self
    }
    /// Message language (`Accept-Language`).
    pub fn lang(mut self, lang: Lang) -> Self {
        self.lang = lang;
        self
    }
    /// Request timeout.
    pub fn timeout(mut self, t: Duration) -> Self {
        self.timeout = t;
        self
    }
    /// Connect timeout (HTTP).
    pub fn connect_timeout(mut self, t: Duration) -> Self {
        self.connect_timeout = t;
        self
    }
    /// `User-Agent`.
    pub fn user_agent(mut self, ua: impl Into<String>) -> Self {
        self.user_agent = ua.into();
        self
    }
    /// Build.
    pub fn build(self) -> Result<BrokerClient, ClientError> {
        let transport = Transport::new(&self.endpoint, &self.user_agent, self.connect_timeout)?;
        Ok(BrokerClient {
            label: self.endpoint.to_string(),
            endpoint: self.endpoint,
            transport,
            auth: self.auth,
            lang: self.lang,
            timeout: self.timeout,
            user_agent: self.user_agent,
        })
    }
}

/// Typed broker API client.
#[derive(Clone)]
pub struct BrokerClient {
    endpoint: BrokerEndpoint,
    label: String,
    transport: Transport,
    auth: Auth,
    lang: Lang,
    timeout: Duration,
    user_agent: String,
}

impl std::fmt::Debug for BrokerClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BrokerClient")
            .field("endpoint", &self.label)
            .field("auth", &self.auth)
            .field("lang", &self.lang)
            .finish()
    }
}

fn q(pairs: &[(&str, Option<String>)]) -> String {
    let mut s = form_urlencoded::Serializer::new(String::new());
    let mut any = false;
    for (k, v) in pairs {
        if let Some(v) = v {
            s.append_pair(k, v);
            any = true;
        }
    }
    if any { format!("?{}", s.finish()) } else { String::new() }
}

impl BrokerClient {
    /// Start a builder.
    pub fn builder(endpoint: BrokerEndpoint) -> BrokerClientBuilder {
        BrokerClientBuilder {
            endpoint,
            auth: Auth::None,
            lang: Lang::ZhCn,
            timeout: DEFAULT_TIMEOUT,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            user_agent: format!("aipass-client/{}", env!("CARGO_PKG_VERSION")),
        }
    }

    /// Client with default settings.
    pub fn new(endpoint: BrokerEndpoint, auth: Auth) -> Result<Self, ClientError> {
        Self::builder(endpoint).auth(auth).build()
    }

    /// Same transport, different authentication.
    pub fn with_auth(&self, auth: Auth) -> Self {
        Self {
            auth,
            ..self.clone()
        }
    }

    /// Endpoint.
    pub fn endpoint(&self) -> &BrokerEndpoint {
        &self.endpoint
    }

    /// Authentication.
    pub fn auth(&self) -> &Auth {
        &self.auth
    }

    /// Language.
    pub fn lang(&self) -> Lang {
        self.lang
    }

    /// `User-Agent`.
    pub fn user_agent(&self) -> &str {
        &self.user_agent
    }

    // ---------------------------------------------------------------------------------
    // raw
    // ---------------------------------------------------------------------------------

    /// Send a request and return the raw response (any status). The body is signed exactly as
    /// sent; `path_and_query` is relative to the endpoint (e.g. `/v1/resources?x=1`).
    pub async fn request_raw(
        &self,
        method: Method,
        path_and_query: &str,
        body: Option<Vec<u8>>,
    ) -> Result<RawResponse, ClientError> {
        let wire = self.transport.wire_path(path_and_query)?;
        let body = body.unwrap_or_default();
        let mut headers: Vec<(HeaderName, HeaderValue)> = vec![
            (
                http::header::ACCEPT,
                HeaderValue::from_static("application/json"),
            ),
            (
                http::header::ACCEPT_LANGUAGE,
                HeaderValue::from_static(match self.lang {
                    Lang::ZhCn => "zh-CN",
                    Lang::En => "en",
                }),
            ),
            (
                http::header::USER_AGENT,
                HeaderValue::from_str(&self.user_agent)
                    .unwrap_or_else(|_| HeaderValue::from_static("aipass-client")),
            ),
        ];
        if !body.is_empty() {
            headers.push((
                http::header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            ));
        }
        if let Some(v) = self.auth.header_value(method.as_str(), &wire, &body) {
            let mut hv = HeaderValue::from_str(&v)
                .map_err(|_| ClientError::Config("credential is not a valid header value".into()))?;
            hv.set_sensitive(true);
            headers.push((http::header::AUTHORIZATION, hv));
        }
        tracing::debug!(method = %method, path = %strip_query(&wire), "broker request");
        let resp = self
            .transport
            .send(&self.label, method, &wire, headers, body, self.timeout)
            .await?;
        tracing::debug!(status = resp.status, "broker response");
        Ok(resp)
    }

    async fn call<T: DeserializeOwned>(
        &self,
        method: Method,
        path_and_query: &str,
        body: Option<Vec<u8>>,
    ) -> Result<T, ClientError> {
        let resp = self.request_raw(method, path_and_query, body).await?;
        if !(200..300).contains(&resp.status) {
            return Err(ClientError::Api(decode_error_body(resp.status, &resp.body)));
        }
        serde_json::from_slice(&resp.body).map_err(|e| {
            ClientError::Protocol(format!(
                "HTTP {} body does not match the contract: {e}",
                resp.status
            ))
        })
    }

    async fn call_no_content(
        &self,
        method: Method,
        path_and_query: &str,
        body: Option<Vec<u8>>,
    ) -> Result<(), ClientError> {
        let resp = self.request_raw(method, path_and_query, body).await?;
        if !(200..300).contains(&resp.status) {
            return Err(ClientError::Api(decode_error_body(resp.status, &resp.body)));
        }
        Ok(())
    }

    fn json<B: Serialize + ?Sized>(body: &B) -> Result<Option<Vec<u8>>, ClientError> {
        serde_json::to_vec(body)
            .map(Some)
            .map_err(|e| ClientError::Config(format!("cannot encode request: {e}")))
    }

    /// GET a path and decode JSON (escape hatch for endpoints without a typed method).
    pub async fn get_json<T: DeserializeOwned>(&self, path_and_query: &str) -> Result<T, ClientError> {
        self.call(Method::GET, path_and_query, None).await
    }

    /// POST JSON and decode JSON (escape hatch).
    pub async fn post_json<B: Serialize + ?Sized, T: DeserializeOwned>(
        &self,
        path_and_query: &str,
        body: &B,
    ) -> Result<T, ClientError> {
        self.call(Method::POST, path_and_query, Self::json(body)?).await
    }

    // ---------------------------------------------------------------------------------
    // P — public
    // ---------------------------------------------------------------------------------

    /// `GET /v1/health`.
    pub async fn health(&self) -> Result<HealthResponse, ClientError> {
        self.call(Method::GET, "/v1/health", None).await
    }

    /// `POST /v1/connections/pair` (public; the new connection key's public half).
    pub async fn pair_connection(
        &self,
        req: &PairConnectionRequest,
    ) -> Result<PairConnectionResponse, ClientError> {
        self.call(Method::POST, "/v1/connections/pair", Self::json(req)?)
            .await
    }

    /// `GET /v1/connections/pair/{id}` — must be signed by the pending connection key.
    pub async fn pair_status(&self, id: &PairingId) -> Result<PairStatusResponse, ClientError> {
        self.call(
            Method::GET,
            &format!("/v1/connections/pair/{}", id.as_str()),
            None,
        )
        .await
    }

    // ---------------------------------------------------------------------------------
    // C — AI connection
    // ---------------------------------------------------------------------------------

    /// `GET /v1/resources?project_id=&service=`.
    pub async fn list_resources(
        &self,
        project_id: Option<&ProjectId>,
        service: Option<&str>,
    ) -> Result<ResourcesResponse, ClientError> {
        let query = q(&[
            ("project_id", project_id.map(|p| p.as_str().to_owned())),
            ("service", service.map(str::to_owned)),
        ]);
        self.call(Method::GET, &format!("/v1/resources{query}"), None)
            .await
    }

    /// `POST /v1/operations`.
    pub async fn request_operation(
        &self,
        req: &OperationRequest,
    ) -> Result<OperationResponse, ClientError> {
        self.call(Method::POST, "/v1/operations", Self::json(req)?).await
    }

    /// `GET /v1/operations/{id}`.
    pub async fn get_operation(&self, id: &OperationId) -> Result<OperationResponse, ClientError> {
        self.call(Method::GET, &format!("/v1/operations/{}", id.as_str()), None)
            .await
    }

    /// `POST /v1/operations/{id}/cancel`.
    pub async fn cancel_operation(&self, id: &OperationId) -> Result<CancelResponse, ClientError> {
        self.call(
            Method::POST,
            &format!("/v1/operations/{}/cancel", id.as_str()),
            None,
        )
        .await
    }

    /// `POST /v1/access/requests`.
    pub async fn request_access(
        &self,
        req: &AccessRequest,
    ) -> Result<AccessRequestResponse, ClientError> {
        self.call(Method::POST, "/v1/access/requests", Self::json(req)?)
            .await
    }

    /// `GET /v1/access/requests/{id}`.
    pub async fn get_access_request(
        &self,
        id: &ApprovalRequestId,
    ) -> Result<AccessRequestResponse, ClientError> {
        self.call(
            Method::GET,
            &format!("/v1/access/requests/{}", id.as_str()),
            None,
        )
        .await
    }

    /// `POST /v1/access/grants/{id}/release`.
    pub async fn release_grant(&self, id: &GrantId) -> Result<ReleaseResponse, ClientError> {
        self.call(
            Method::POST,
            &format!("/v1/access/grants/{}/release", id.as_str()),
            None,
        )
        .await
    }

    // ---------------------------------------------------------------------------------
    // D / A — trusted devices and local admin
    // ---------------------------------------------------------------------------------

    /// `GET /v1/approvals?status=`.
    pub async fn list_approvals(
        &self,
        status: Option<ApprovalStatus>,
    ) -> Result<ApprovalsResponse, ClientError> {
        let query = q(&[("status", status.map(enum_str))]);
        self.call(Method::GET, &format!("/v1/approvals{query}"), None)
            .await
    }

    /// `POST /v1/approvals/{id}/decision` — the decision must carry a valid device signature
    /// (build it with `aipass_types::approval::build_decision`).
    pub async fn post_decision(
        &self,
        decision: &ApprovalDecision,
    ) -> Result<DecisionResponse, ClientError> {
        self.call(
            Method::POST,
            &format!(
                "/v1/approvals/{}/decision",
                decision.approval_request_id.as_str()
            ),
            Self::json(decision)?,
        )
        .await
    }

    /// `GET /v1/connections`.
    pub async fn list_connections(&self) -> Result<ConnectionsResponse, ClientError> {
        self.call(Method::GET, "/v1/connections", None).await
    }

    /// `POST /v1/connections/{id}/approve`.
    pub async fn approve_connection(
        &self,
        id: &ConnectionId,
        req: &ApproveConnectionRequest,
    ) -> Result<AppConnection, ClientError> {
        self.call(
            Method::POST,
            &format!("/v1/connections/{}/approve", id.as_str()),
            Self::json(req)?,
        )
        .await
    }

    /// `POST /v1/connections/{id}/{deny|pause|resume|remove|revoke_all}`. Returns the JSON
    /// body (an `AppConnection` or revocation reports, depending on the action).
    pub async fn connection_action(
        &self,
        id: &ConnectionId,
        action: ConnectionAction,
    ) -> Result<serde_json::Value, ClientError> {
        self.call(
            Method::POST,
            &format!("/v1/connections/{}/{}", id.as_str(), action.as_str()),
            None,
        )
        .await
    }

    /// `GET /v1/projects`.
    pub async fn list_projects(&self) -> Result<ProjectsResponse, ClientError> {
        self.call(Method::GET, "/v1/projects", None).await
    }

    /// `POST /v1/projects`.
    pub async fn create_project(&self, name: &str) -> Result<Project, ClientError> {
        self.call(
            Method::POST,
            "/v1/projects",
            Self::json(&CreateProjectRequest {
                name: name.to_owned(),
            })?,
        )
        .await
    }

    /// `GET /v1/admin/resources`.
    pub async fn admin_list_resources(&self) -> Result<AdminResourcesResponse, ClientError> {
        self.call(Method::GET, "/v1/admin/resources", None).await
    }

    /// `POST /v1/admin/resources`.
    pub async fn admin_create_resource(&self, input: &ResourceInput) -> Result<Resource, ClientError> {
        self.call(Method::POST, "/v1/admin/resources", Self::json(input)?)
            .await
    }

    /// `PATCH /v1/admin/resources/{id}`.
    pub async fn admin_patch_resource(
        &self,
        id: &ResourceId,
        patch: &ResourcePatch,
    ) -> Result<Resource, ClientError> {
        self.call(
            Method::PATCH,
            &format!("/v1/admin/resources/{}", id.as_str()),
            Self::json(patch)?,
        )
        .await
    }

    /// `DELETE /v1/admin/resources/{id}`.
    pub async fn admin_delete_resource(&self, id: &ResourceId) -> Result<(), ClientError> {
        self.call_no_content(
            Method::DELETE,
            &format!("/v1/admin/resources/{}", id.as_str()),
            None,
        )
        .await
    }

    /// `GET /v1/policies`.
    pub async fn list_policies(&self) -> Result<PoliciesResponse, ClientError> {
        self.call(Method::GET, "/v1/policies", None).await
    }

    /// `POST /v1/policies` (a policy signed with `aipass_types::policy::sign_policy`).
    pub async fn create_policy(&self, policy: &Policy) -> Result<Policy, ClientError> {
        self.call(Method::POST, "/v1/policies", Self::json(policy)?).await
    }

    /// `POST /v1/policies/{id}/disable`.
    pub async fn disable_policy(&self, id: &PolicyId) -> Result<serde_json::Value, ClientError> {
        self.call(
            Method::POST,
            &format!("/v1/policies/{}/disable", id.as_str()),
            None,
        )
        .await
    }

    /// `GET /v1/grants?status=`.
    pub async fn list_grants(&self, status: Option<GrantStatus>) -> Result<GrantsResponse, ClientError> {
        let query = q(&[("status", status.map(enum_str))]);
        self.call(Method::GET, &format!("/v1/grants{query}"), None).await
    }

    /// `POST /v1/grants/{id}/revoke`.
    pub async fn revoke_grant(
        &self,
        id: &GrantId,
        level: RevocationLevel,
    ) -> Result<RevocationReport, ClientError> {
        self.call(
            Method::POST,
            &format!("/v1/grants/{}/revoke", id.as_str()),
            Self::json(&RevokeRequest { level })?,
        )
        .await
    }

    /// `GET /v1/operations?limit=` (admin list).
    pub async fn list_operations(&self, limit: Option<u32>) -> Result<OperationsResponse, ClientError> {
        let query = q(&[("limit", limit.map(|l| l.to_string()))]);
        self.call(Method::GET, &format!("/v1/operations{query}"), None)
            .await
    }

    /// `GET /v1/audit?after_seq=&limit=`.
    pub async fn audit(
        &self,
        after_seq: Option<u64>,
        limit: Option<u32>,
    ) -> Result<AuditResponse, ClientError> {
        let query = q(&[
            ("after_seq", after_seq.map(|s| s.to_string())),
            ("limit", limit.map(|l| l.to_string())),
        ]);
        self.call(Method::GET, &format!("/v1/audit{query}"), None).await
    }

    /// `GET /v1/audit/verify`.
    pub async fn audit_verify(&self) -> Result<AuditVerifyResponse, ClientError> {
        self.call(Method::GET, "/v1/audit/verify", None).await
    }

    /// `GET /v1/activity/summary?since=` (RFC 3339).
    pub async fn activity_summary(
        &self,
        since: Option<&aipass_types::Timestamp>,
    ) -> Result<ActivitySummary, ClientError> {
        let query = q(&[("since", since.map(aipass_types::time::format_rfc3339))]);
        self.call(Method::GET, &format!("/v1/activity/summary{query}"), None)
            .await
    }

    /// `GET /v1/executors`.
    pub async fn list_executors(&self) -> Result<ExecutorsResponse, ClientError> {
        self.call(Method::GET, "/v1/executors", None).await
    }

    /// `GET /v1/admin/devices` (A).
    pub async fn admin_list_devices(&self) -> Result<serde_json::Value, ClientError> {
        self.call(Method::GET, "/v1/admin/devices", None).await
    }

    /// `POST /v1/admin/devices` (A) — add a trusted approver device (`DevicePublic` JSON).
    pub async fn admin_add_device(
        &self,
        device: &serde_json::Value,
    ) -> Result<serde_json::Value, ClientError> {
        self.call(Method::POST, "/v1/admin/devices", Self::json(device)?)
            .await
    }

    /// `POST /v1/admin/devices/{id}/revoke` (A).
    pub async fn admin_revoke_device(
        &self,
        device_id: &aipass_types::DeviceId,
    ) -> Result<serde_json::Value, ClientError> {
        self.call(
            Method::POST,
            &format!("/v1/admin/devices/{}/revoke", device_id.as_str()),
            None,
        )
        .await
    }

    /// `POST /v1/credentials/delegate` (D, experimental unattended rules).
    pub async fn delegate_credential(
        &self,
        req: &DelegateCredentialRequest,
    ) -> Result<serde_json::Value, ClientError> {
        self.call(Method::POST, "/v1/credentials/delegate", Self::json(req)?)
            .await
    }
}

fn enum_str<T: Serialize>(v: T) -> String {
    match serde_json::to_value(v) {
        Ok(serde_json::Value::String(s)) => s,
        _ => String::new(),
    }
}

fn strip_query(p: &str) -> &str {
    p.split_once('?').map(|(a, _)| a).unwrap_or(p)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_building() {
        assert_eq!(q(&[("a", None)]), "");
        assert_eq!(
            q(&[("project_id", Some("proj_1".into())), ("service", Some("a b&c".into()))]),
            "?project_id=proj_1&service=a+b%26c"
        );
        assert_eq!(enum_str(ApprovalStatus::Pending), "pending");
        assert_eq!(enum_str(GrantStatus::Active), "active");
    }
}
