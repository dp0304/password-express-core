// SPDX-License-Identifier: Apache-2.0
//! [`BrokerApi`] — the AI-facing broker operations (CONTRACTS §6.3 "C" endpoints), as a trait.
//!
//! The MCP bridge (`aipass-mcp`) is written against this trait. [`crate::BrokerClient`]
//! implements it over HTTP/UDS for a paired connection; `aipass-node` and the desktop app
//! implement it in-process over `aipass-broker`, bound to one authenticated connection
//! (a `BrokerApi` value *is* the identity of the caller — the trait has no way to name
//! another connection, so IDs passed in arguments are never capabilities).

use std::sync::Arc;

use aipass_types::models::{
    AccessRequest, AccessRequestResponse, CancelResponse, OperationRequest, OperationResponse,
    ReleaseResponse, ResourcesResponse,
};
use aipass_types::{ApiError, ApprovalRequestId, GrantId, OperationId, ProjectId};
use async_trait::async_trait;

use crate::client::BrokerClient;

/// AI-facing broker operations for one authenticated connection.
#[async_trait]
pub trait BrokerApi: Send + Sync {
    /// `GET /v1/resources` — resources this connection may discover.
    async fn list_resources(
        &self,
        project_id: Option<&ProjectId>,
        service: Option<&str>,
    ) -> Result<ResourcesResponse, ApiError>;

    /// `POST /v1/operations` — returns a result, or `approval_required` (never blocks waiting
    /// for a phone).
    async fn request_operation(&self, req: &OperationRequest) -> Result<OperationResponse, ApiError>;

    /// `GET /v1/operations/{id}` — only this connection's operations (`NOT_FOUND` otherwise).
    async fn get_operation(&self, id: &OperationId) -> Result<OperationResponse, ApiError>;

    /// `POST /v1/operations/{id}/cancel`.
    async fn cancel_operation(&self, id: &OperationId) -> Result<CancelResponse, ApiError>;

    /// `POST /v1/access/requests`.
    async fn request_access(&self, req: &AccessRequest) -> Result<AccessRequestResponse, ApiError>;

    /// `GET /v1/access/requests/{id}`.
    async fn get_access_request(
        &self,
        id: &ApprovalRequestId,
    ) -> Result<AccessRequestResponse, ApiError>;

    /// `POST /v1/access/grants/{id}/release`.
    async fn release_grant(&self, id: &GrantId) -> Result<ReleaseResponse, ApiError>;
}

#[async_trait]
impl BrokerApi for BrokerClient {
    async fn list_resources(
        &self,
        project_id: Option<&ProjectId>,
        service: Option<&str>,
    ) -> Result<ResourcesResponse, ApiError> {
        Ok(BrokerClient::list_resources(self, project_id, service).await?)
    }

    async fn request_operation(&self, req: &OperationRequest) -> Result<OperationResponse, ApiError> {
        Ok(BrokerClient::request_operation(self, req).await?)
    }

    async fn get_operation(&self, id: &OperationId) -> Result<OperationResponse, ApiError> {
        Ok(BrokerClient::get_operation(self, id).await?)
    }

    async fn cancel_operation(&self, id: &OperationId) -> Result<CancelResponse, ApiError> {
        Ok(BrokerClient::cancel_operation(self, id).await?)
    }

    async fn request_access(&self, req: &AccessRequest) -> Result<AccessRequestResponse, ApiError> {
        Ok(BrokerClient::request_access(self, req).await?)
    }

    async fn get_access_request(
        &self,
        id: &ApprovalRequestId,
    ) -> Result<AccessRequestResponse, ApiError> {
        Ok(BrokerClient::get_access_request(self, id).await?)
    }

    async fn release_grant(&self, id: &GrantId) -> Result<ReleaseResponse, ApiError> {
        Ok(BrokerClient::release_grant(self, id).await?)
    }
}

#[async_trait]
impl<T: BrokerApi + ?Sized> BrokerApi for Arc<T> {
    async fn list_resources(
        &self,
        project_id: Option<&ProjectId>,
        service: Option<&str>,
    ) -> Result<ResourcesResponse, ApiError> {
        (**self).list_resources(project_id, service).await
    }
    async fn request_operation(&self, req: &OperationRequest) -> Result<OperationResponse, ApiError> {
        (**self).request_operation(req).await
    }
    async fn get_operation(&self, id: &OperationId) -> Result<OperationResponse, ApiError> {
        (**self).get_operation(id).await
    }
    async fn cancel_operation(&self, id: &OperationId) -> Result<CancelResponse, ApiError> {
        (**self).cancel_operation(id).await
    }
    async fn request_access(&self, req: &AccessRequest) -> Result<AccessRequestResponse, ApiError> {
        (**self).request_access(req).await
    }
    async fn get_access_request(
        &self,
        id: &ApprovalRequestId,
    ) -> Result<AccessRequestResponse, ApiError> {
        (**self).get_access_request(id).await
    }
    async fn release_grant(&self, id: &GrantId) -> Result<ReleaseResponse, ApiError> {
        (**self).release_grant(id).await
    }
}

/// A [`BrokerApi`] that rejects every call with one fixed error — used by the MCP bridge
/// when it starts without a usable connection key, so the AI host gets an actionable tool
/// error ("run `aipass-mcp pair`") instead of a crashed server.
#[derive(Debug, Clone)]
pub struct UnavailableBroker {
    error: ApiError,
}

impl UnavailableBroker {
    /// Reject with `error`.
    pub fn new(error: ApiError) -> Self {
        Self { error }
    }
}

#[async_trait]
impl BrokerApi for UnavailableBroker {
    async fn list_resources(
        &self,
        _: Option<&ProjectId>,
        _: Option<&str>,
    ) -> Result<ResourcesResponse, ApiError> {
        Err(self.error.clone())
    }
    async fn request_operation(&self, _: &OperationRequest) -> Result<OperationResponse, ApiError> {
        Err(self.error.clone())
    }
    async fn get_operation(&self, _: &OperationId) -> Result<OperationResponse, ApiError> {
        Err(self.error.clone())
    }
    async fn cancel_operation(&self, _: &OperationId) -> Result<CancelResponse, ApiError> {
        Err(self.error.clone())
    }
    async fn request_access(&self, _: &AccessRequest) -> Result<AccessRequestResponse, ApiError> {
        Err(self.error.clone())
    }
    async fn get_access_request(
        &self,
        _: &ApprovalRequestId,
    ) -> Result<AccessRequestResponse, ApiError> {
        Err(self.error.clone())
    }
    async fn release_grant(&self, _: &GrantId) -> Result<ReleaseResponse, ApiError> {
        Err(self.error.clone())
    }
}
