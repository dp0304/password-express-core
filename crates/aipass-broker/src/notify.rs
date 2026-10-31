// SPDX-License-Identifier: Apache-2.0
//! Hooks the embedding process plugs into the broker.
//!
//! * [`ApprovalNotifier`] — in-process listeners (desktop UI, CLI watch). Called
//!   synchronously; must not block (forward to a channel). [`crate::Broker::subscribe`]
//!   offers the same events as a `tokio::sync::broadcast` stream.
//! * [`DeviceOutbox`] — delivers sealed [`RelayEnvelope`]s to trusted devices' relay
//!   mailboxes. The broker builds and seals the envelopes itself (with its
//!   [`RelayIdentity`]); the outbox only transports them (node: `RelayClient` POST).
//! * [`CredentialSource`] — an in-process trusted client (desktop with an unlocked vault)
//!   that can supply credential material for a grant whose approval carried no sealed
//!   envelope (e.g. approved on the same desktop), and optionally install experimental
//!   delegated credentials.
//!
//! None of these hooks ever receive credentials from the broker; notifications carry only
//! what the approval screen shows (§5.3) and push hints carry nothing (§11.4).

use std::fmt;
use std::sync::Arc;

use aipass_crypto::{DeviceIdentity, SealedBox};
use aipass_types::error::{ApiError, ErrorCode};
use aipass_types::exec::{CredentialMaterial, DelegationAad};
use aipass_types::ids::{ApprovalRequestId, ConnectionId, GrantId, MailboxId, OperationId};
use aipass_types::models::{
    AppConnection, ApprovalRequest, ApprovalStatus, Grant, GrantStatus, OperationStatus, Resource,
    RevocationReport,
};
use aipass_types::relay::RelayEnvelope;
use async_trait::async_trait;
use serde::Serialize;

/// An event for in-process listeners. Contains no secrets and no operation results.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum BrokerEvent {
    /// A new approval request is waiting (render per §5.3).
    ApprovalRequested {
        /// The request.
        request: Box<ApprovalRequest>,
    },
    /// An approval request left the pending state.
    ApprovalResolved {
        /// Request.
        approval_request_id: ApprovalRequestId,
        /// New status.
        status: ApprovalStatus,
    },
    /// An AI host asked to be connected; show the pairing code next to the request.
    ConnectionPairingRequested {
        /// The pending connection.
        connection: Box<AppConnection>,
        /// Code the AI host displays.
        pairing_code: String,
    },
    /// A connection changed (approved, paused, resumed, removed, projects edited).
    ConnectionUpdated {
        /// New state.
        connection: Box<AppConnection>,
    },
    /// An operation changed state.
    OperationUpdated {
        /// Operation.
        operation_id: OperationId,
        /// Connection.
        connection_id: ConnectionId,
        /// New status.
        status: OperationStatus,
    },
    /// A grant changed state.
    GrantUpdated {
        /// Grant.
        grant_id: GrantId,
        /// New status.
        status: GrantStatus,
    },
    /// A revocation finished (levels may still be pending — show them honestly).
    Revoked {
        /// The report.
        report: RevocationReport,
    },
}

/// In-process listener. Must return quickly and never block.
pub trait ApprovalNotifier: Send + Sync {
    /// Called for every broker event.
    fn notify(&self, event: &BrokerEvent);
}

/// Transport for sealed envelopes to device mailboxes (`POST /v1/relay/{mailbox}`).
#[async_trait]
pub trait DeviceOutbox: Send + Sync {
    /// Deliver one envelope (already sealed to `envelope.to`). Failures are logged by the
    /// broker; a missing push or delivery never implies approval.
    async fn deliver(&self, envelope: RelayEnvelope) -> Result<(), ApiError>;
}

/// The broker's own relay identity: its mailbox (normally the node's `exe_…` id) and the
/// keys used to sign outgoing and open incoming envelopes.
#[derive(Clone)]
pub struct RelayIdentity {
    /// Mailbox / principal id of the broker.
    pub mailbox: MailboxId,
    /// Signing + KEM keys. Never leaves the process.
    pub identity: Arc<DeviceIdentity>,
}

impl fmt::Debug for RelayIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RelayIdentity")
            .field("mailbox", &self.mailbox)
            .field("identity", &"[REDACTED]")
            .finish()
    }
}

/// In-process credential supplier (desktop trusted client).
#[async_trait]
pub trait CredentialSource: Send + Sync {
    /// Material for a newly approved/auto-approved grant whose credential was not delivered
    /// in a sealed envelope. `Ok(None)` = unavailable (e.g. vault locked) — operations then
    /// fail with `SECRET_UNAVAILABLE` instead of waiting.
    async fn material_for_grant(
        &self,
        grant: &Grant,
        resource: &Resource,
    ) -> Result<Option<CredentialMaterial>, ApiError>;

    /// Whether [`CredentialSource::install_delegated`] is implemented (experimental V1.1).
    fn supports_delegation(&self) -> bool {
        false
    }

    /// Experimental unattended delegation: install an envelope sealed with
    /// [`DelegationAad`] for a grant created from that policy.
    async fn install_delegated(
        &self,
        grant_id: &GrantId,
        envelope: &SealedBox,
        aad: &DelegationAad,
    ) -> Result<(), ApiError> {
        let _ = (grant_id, envelope, aad);
        Err(ApiError::new(ErrorCode::NotSupported))
    }
}
