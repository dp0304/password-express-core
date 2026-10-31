// SPDX-License-Identifier: Apache-2.0
//! [`ConnectionHandle`]: the AI-facing (`C`) broker calls bound to one authenticated
//! connection, with method signatures mirroring `aipass_client::BrokerApi`, so in-process
//! embedders (node tunnel / remote MCP handler, desktop) can implement that trait with a
//! one-line newtype instead of going through HTTP.

use std::sync::Arc;

use aipass_types::error::{ApiError, Lang};
use aipass_types::ids::{ApprovalRequestId, GrantId, OperationId, ProjectId};
use aipass_types::models::{
    AccessRequest, AccessRequestResponse, CancelResponse, OperationRequest, OperationResponse,
    ReleaseResponse, ResourcesResponse,
};

use crate::Broker;
use crate::principal::ConnectionPrincipal;

/// Broker calls on behalf of one connection. Every call re-checks the connection's
/// status, visibility, grants and budgets — holding a handle authorizes nothing by itself.
#[derive(Clone)]
pub struct ConnectionHandle {
    broker: Arc<Broker>,
    principal: ConnectionPrincipal,
    lang: Lang,
}

impl std::fmt::Debug for ConnectionHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnectionHandle")
            .field("connection_id", self.principal.connection_id())
            .field("lang", &self.lang)
            .finish()
    }
}

impl ConnectionHandle {
    /// Bind `principal` (authenticated by the caller) and the message language.
    pub fn new(broker: Arc<Broker>, principal: ConnectionPrincipal, lang: Lang) -> Self {
        Self { broker, principal, lang }
    }

    /// The bound principal.
    pub fn principal(&self) -> &ConnectionPrincipal {
        &self.principal
    }

    /// `GET /v1/resources`.
    pub async fn list_resources(&self, project_id: Option<&ProjectId>, service: Option<&str>) -> Result<ResourcesResponse, ApiError> {
        self.broker.list_resources(&self.principal, project_id, service, self.lang).await
    }

    /// `POST /v1/operations`.
    pub async fn request_operation(&self, req: &OperationRequest) -> Result<OperationResponse, ApiError> {
        self.broker.request_operation(&self.principal, req.clone(), self.lang).await
    }

    /// `GET /v1/operations/{id}`.
    pub async fn get_operation(&self, id: &OperationId) -> Result<OperationResponse, ApiError> {
        self.broker.get_operation(&self.principal, id, self.lang).await
    }

    /// `POST /v1/operations/{id}/cancel`.
    pub async fn cancel_operation(&self, id: &OperationId) -> Result<CancelResponse, ApiError> {
        self.broker.cancel_operation(&self.principal, id, self.lang).await
    }

    /// `POST /v1/access/requests`.
    pub async fn request_access(&self, req: &AccessRequest) -> Result<AccessRequestResponse, ApiError> {
        self.broker.request_access(&self.principal, req.clone()).await
    }

    /// `GET /v1/access/requests/{id}`.
    pub async fn get_access_request(&self, id: &ApprovalRequestId) -> Result<AccessRequestResponse, ApiError> {
        self.broker.get_access_request(&self.principal, id).await
    }

    /// `POST /v1/access/grants/{id}/release`.
    pub async fn release_grant(&self, id: &GrantId) -> Result<ReleaseResponse, ApiError> {
        self.broker.release_grant(&self.principal, id).await
    }
}

impl Broker {
    /// A [`ConnectionHandle`] for `principal`.
    pub fn connection_handle(self: &Arc<Self>, principal: ConnectionPrincipal, lang: Lang) -> ConnectionHandle {
        ConnectionHandle::new(self.clone(), principal, lang)
    }
}
