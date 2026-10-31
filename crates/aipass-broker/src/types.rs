// SPDX-License-Identifier: Apache-2.0
//! Broker-specific request/response shapes that are not in `aipass-types` (additive to
//! CONTRACTS §6.3; documented in the README).

use aipass_types::ids::{ConnectionId, EntryId};
use aipass_types::models::{AllowedProjects, AppConnection, HostType, RevocationReport, Transport};
use aipass_types::time::{Timestamp, rfc3339, rfc3339_option};
use aipass_types::vault::{DevicePublic, MemberStatus};
use serde::{Deserialize, Serialize};

/// A device in the broker's trusted approver set (`GET /v1/admin/devices`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustedDevice {
    /// Public identity (`device_id, name, platform, role, sign_pk, kem_pk`).
    #[serde(flatten)]
    pub device: DevicePublic,
    /// `active` | `revoked`.
    pub status: MemberStatus,
    /// When added.
    #[serde(with = "rfc3339")]
    pub added_at: Timestamp,
    /// Who added it (`dev_…`, `admin`, `system`).
    pub added_by: String,
    /// When revoked.
    #[serde(default, skip_serializing_if = "Option::is_none", with = "rfc3339_option")]
    pub revoked_at: Option<Timestamp>,
}

impl TrustedDevice {
    /// Active owner/member — may approve and act as principal `D`.
    pub fn is_active_approver(&self) -> bool {
        self.status == MemberStatus::Active && self.device.role.is_trusted_approver()
    }
}

/// `GET /v1/admin/devices`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DevicesResponse {
    /// Devices.
    pub devices: Vec<TrustedDevice>,
}

/// Input of [`crate::Broker::begin_pairing`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairingInput {
    /// Host type label.
    pub host_type: HostType,
    /// Self-declared display name (label only).
    pub display_name: String,
    /// Transport.
    pub transport: Transport,
    /// Ed25519 connection key (b64u). `None` for connections that authenticate by other
    /// means (cloud tunnel, bearer token issued after approval).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
}

/// `POST /v1/admin/connections` body (admin-provisioned connection, additive).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NewConnection {
    /// Host type label.
    pub host_type: HostType,
    /// Display name.
    pub display_name: String,
    /// Transport.
    pub transport: Transport,
    /// Visible projects.
    pub allowed_projects: AllowedProjects,
    /// Optional Ed25519 key; when absent a bearer `aipc_` token is issued.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
}

/// `POST /v1/admin/connections` response. The token is shown exactly once.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreatedConnection {
    /// The new active connection.
    pub connection: AppConnection,
    /// `aipc_…` bearer token (only when no public key was given).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
}

/// `POST /v1/connections/{id}/token` response (additive). Shown exactly once; the broker
/// stores only its SHA-256 hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenResponse {
    /// Connection.
    pub connection_id: ConnectionId,
    /// `aipc_…` bearer token.
    pub token: String,
}

/// `POST /v1/connections/{id}/revoke_all` response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevokeAllResponse {
    /// Connection after the action.
    pub connection: AppConnection,
    /// One report per revoked grant.
    pub reports: Vec<RevocationReport>,
}

/// `PUT /v1/admin/entries/{entry_id}/conflict` body (additive).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntryConflictRequest {
    /// Whether the vault entry currently has unresolved `conflict_versions`.
    pub conflict: bool,
}

/// `PUT /v1/admin/entries/{entry_id}/conflict` response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntryConflictResponse {
    /// Entry.
    pub entry_id: EntryId,
    /// Flag as stored.
    pub conflict: bool,
    /// Resources referencing the entry.
    pub resources_affected: u64,
}

/// `POST /v1/credentials/delegate` response (experimental).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelegateResponse {
    /// Policy.
    pub policy_id: aipass_types::ids::PolicyId,
    /// Policy version the envelope is bound to.
    pub policy_version: u64,
    /// Always `stored`.
    pub status: String,
}

/// What one sweep pass changed.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct SweepReport {
    /// Pending approvals that expired (never approved).
    pub approvals_expired: u64,
    /// Grants that reached `expires_at`.
    pub grants_expired: u64,
    /// Connection pairings that expired.
    pub pairings_expired: u64,
    /// Operation results purged after the retention period.
    pub results_purged: u64,
}
