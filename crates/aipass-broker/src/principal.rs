// SPDX-License-Identifier: Apache-2.0
//! Authenticated principals.
//!
//! A [`ConnectionPrincipal`] says *which* AppConnection is calling — it is produced by
//! signature or token verification (HTTP layer) or asserted by an in-process caller that
//! authenticated the connection some other way (e.g. the node's tunnel handler). It is
//! **not** an authorization: the broker re-checks the connection's status, project
//! visibility, grants and budgets on every call. IDs are never capabilities.

use aipass_types::ids::{ConnectionId, DeviceId};

/// How a connection was authenticated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthVia {
    /// `AIPass-Sig kid=conn_…` verified against the connection's public key.
    Signature,
    /// `Bearer aipc_…` connection token (hash matched).
    ConnectionToken,
    /// Asserted by trusted in-process code.
    InProcess,
}

/// An authenticated AppConnection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionPrincipal {
    connection_id: ConnectionId,
    via: AuthVia,
}

impl ConnectionPrincipal {
    pub(crate) fn verified(connection_id: ConnectionId, via: AuthVia) -> Self {
        Self { connection_id, via }
    }

    /// For trusted in-process callers that authenticated the connection by other means
    /// (MCP handler inside the node bound to a tunnel frame's `connection_id`, desktop UI
    /// tests). The broker still enforces connection status and every grant check.
    pub fn in_process(connection_id: ConnectionId) -> Self {
        Self {
            connection_id,
            via: AuthVia::InProcess,
        }
    }

    /// The connection.
    pub fn connection_id(&self) -> &ConnectionId {
        &self.connection_id
    }

    /// Authentication method.
    pub fn via(&self) -> AuthVia {
        self.via
    }
}

/// Who performed a management action (recorded in audit, `approved_by`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Actor {
    /// A trusted owner/member device (`AIPass-Sig kid=dev_…` or a device-signed relay message).
    Device(DeviceId),
    /// Local administrator (UDS peer or admin token).
    Admin,
    /// The broker itself (sweeper, startup recovery).
    System,
}

impl Actor {
    /// Audit actor string.
    pub fn audit_name(&self) -> String {
        match self {
            Self::Device(d) => d.as_str().to_owned(),
            Self::Admin => "admin".to_owned(),
            Self::System => "system".to_owned(),
        }
    }

    /// Device id, if any.
    pub fn device(&self) -> Option<&DeviceId> {
        match self {
            Self::Device(d) => Some(d),
            _ => None,
        }
    }
}

/// Result of verifying an `AIPass-Sig` request signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifiedPrincipal {
    /// An AppConnection (any non-removed status; endpoints check the status).
    Connection(ConnectionPrincipal),
    /// An active trusted owner/member device.
    Device(DeviceId),
}
