// SPDX-License-Identifier: Apache-2.0
//! Remote MCP (`/mcp`) and cloud-tunnel MCP: the in-process `BrokerApi` adapter and the
//! bearer resolver for node-issued `aipc_` connection tokens.
//!
//! The adapter value *is* the caller's identity: it is built only after the broker
//! authenticated the token (or, for tunnel frames, after checking the gateway-asserted
//! connection is an active `remote_gateway` connection).

use std::sync::Arc;

use aipass_broker::{Broker, ConnectionHandle, ConnectionPrincipal};
use aipass_client::BrokerApi;
use aipass_mcp::http::{BearerResolver, Principal};
use aipass_types::error::{ApiError, ErrorCode, Lang};
use aipass_types::ids::{ApprovalRequestId, ConnectionId, GrantId, OperationId, ProjectId};
use aipass_types::models::{
    AccessRequest, AccessRequestResponse, CancelResponse, ConnectionStatus, OperationRequest, OperationResponse, ReleaseResponse,
    ResourcesResponse, Transport,
};
use async_trait::async_trait;

/// `BrokerApi` over an in-process `ConnectionHandle`.
pub struct InProcessBroker {
    handle: ConnectionHandle,
}

impl InProcessBroker {
    /// Adapter for an authenticated connection.
    pub fn new(broker: &Arc<Broker>, principal: ConnectionPrincipal, lang: Lang) -> Self {
        Self { handle: broker.connection_handle(principal, lang) }
    }
}

#[async_trait]
impl BrokerApi for InProcessBroker {
    async fn list_resources(&self, project_id: Option<&ProjectId>, service: Option<&str>) -> Result<ResourcesResponse, ApiError> {
        self.handle.list_resources(project_id, service).await
    }
    async fn request_operation(&self, req: &OperationRequest) -> Result<OperationResponse, ApiError> {
        self.handle.request_operation(req).await
    }
    async fn get_operation(&self, id: &OperationId) -> Result<OperationResponse, ApiError> {
        self.handle.get_operation(id).await
    }
    async fn cancel_operation(&self, id: &OperationId) -> Result<CancelResponse, ApiError> {
        self.handle.cancel_operation(id).await
    }
    async fn request_access(&self, req: &AccessRequest) -> Result<AccessRequestResponse, ApiError> {
        self.handle.request_access(req).await
    }
    async fn get_access_request(&self, id: &ApprovalRequestId) -> Result<AccessRequestResponse, ApiError> {
        self.handle.get_access_request(id).await
    }
    async fn release_grant(&self, id: &GrantId) -> Result<ReleaseResponse, ApiError> {
        self.handle.release_grant(id).await
    }
}

/// Resolves `Authorization: Bearer aipc_…` on `/mcp`.
pub struct NodeBearerResolver {
    broker: Arc<Broker>,
    lang: Lang,
}

impl NodeBearerResolver {
    /// Resolver over `broker`.
    pub fn new(broker: Arc<Broker>, lang: Lang) -> Self {
        Self { broker, lang }
    }
}

#[async_trait]
impl BearerResolver for NodeBearerResolver {
    async fn resolve(&self, token: &str) -> Result<Principal, ApiError> {
        let p = self.broker.authenticate_connection_token(token).await?;
        let key = p.connection_id().as_str().to_string();
        Ok(Principal { key, broker: Arc::new(InProcessBroker::new(&self.broker, p, self.lang)) })
    }
}

/// Principal for a tunnel frame: the cloud gateway asserts `connection_id`; the node
/// accepts it only for an **active `remote_gateway`** connection it approved itself.
pub async fn tunnel_principal(broker: &Arc<Broker>, connection_id: &ConnectionId, lang: Lang) -> Result<Principal, ApiError> {
    let conn = broker.get_connection(connection_id).await.map_err(|_| unverified())?;
    if conn.transport != Transport::RemoteGateway {
        return Err(unverified());
    }
    match conn.status {
        ConnectionStatus::Active => {}
        ConnectionStatus::Paused => return Err(ApiError::new(ErrorCode::ConnectionPaused)),
        _ => return Err(unverified()),
    }
    let p = ConnectionPrincipal::in_process(connection_id.clone());
    Ok(Principal { key: connection_id.as_str().to_string(), broker: Arc::new(InProcessBroker::new(broker, p, lang)) })
}

fn unverified() -> ApiError {
    ApiError::new(ErrorCode::IdentityUnverified)
}
