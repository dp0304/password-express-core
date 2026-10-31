// SPDX-License-Identifier: Apache-2.0
//! Approval signing for trusted clients (CONTRACTS §6.1, §7) and device control messages
//! (§4).
//!
//! The approving client recomputes the digest from the fields it displayed (through the
//! single implementation in `aipass_types::approval`; §7 **v2**, which binds the waiting
//! operation's `operation_id` / `parameters_digest` and refuses an operation request
//! without them), signs
//! `aipass:v1:approval:<approve|deny>:<digest>` with the device key and — for approvals —
//! HPKE-seals the referenced credential to the executor (`info = aipass/v1/credential`,
//! `aad = JCS({approval_request_id, digest, executor_id})`). Requests outside their window
//! are never approved; entries with unresolved conflicts are refused (`SYNC_CONFLICT`).

use aipass_crypto::DeviceIdentity;
use aipass_types::approval::{build_decision, credential_aad_bytes};
use aipass_types::exec::{CredentialMaterial, seal_credential};
use aipass_types::ids::{ConnectionId, DeviceId, EntryId, GrantId};
use aipass_types::models::{
    AccessSpec, AllowedProjects, ApprovalDecision, ApprovalRequest, ApprovalStatus, Decision,
    RevocationLevel,
};
use aipass_types::relay::{
    ConnectionControl, ConnectionDecision, ControlAction, DeviceSigned, GrantRevoke,
};
use aipass_types::time::Timestamp;
use aipass_types::vault::{EntryKind, EntryPayload};

use crate::error::{Result, VaultError};

/// The vault entry an approval delivers to the executor.
#[derive(Debug, Clone, Copy)]
pub struct CredentialSource<'a> {
    /// Entry.
    pub entry_id: &'a EntryId,
    /// Version being delivered.
    pub version: u64,
    /// Decrypted payload.
    pub payload: &'a EntryPayload,
    /// Whether the entry has unresolved conflicts (automatic use paused).
    pub has_conflict: bool,
}

/// Build the credential material for an executor from an entry.
pub fn credential_material(
    source: &CredentialSource<'_>,
    expires_at: Timestamp,
) -> Result<CredentialMaterial> {
    if source.has_conflict {
        return Err(VaultError::SyncConflict);
    }
    if source.payload.kind == EntryKind::StorageCredential {
        // a storage key is never automatically an AI resource (§10.2)
        return Err(VaultError::Forbidden(
            "storage credentials are never delivered to executors",
        ));
    }
    let secret = source
        .payload
        .secret
        .clone()
        .filter(|s| !s.is_empty())
        .ok_or(VaultError::SecretUnavailable(
            "the entry has no secret to deliver",
        ))?;
    Ok(CredentialMaterial {
        entry_id: source.entry_id.clone(),
        version: source.version,
        kind: source.payload.kind,
        username: source.payload.username.clone(),
        secret,
        database: source.payload.database.clone(),
        expires_at,
    })
}

fn check_window(request: &ApprovalRequest, now: &Timestamp) -> Result<()> {
    if request.status != ApprovalStatus::Pending {
        return Err(VaultError::PreconditionFailed(
            "approval request is no longer pending",
        ));
    }
    if *now >= request.expires_at {
        // never approve after the window (no auto-approval on timeout either)
        return Err(VaultError::Expired("approval window has passed"));
    }
    Ok(())
}

/// Approve `request` on this trusted device. `narrowed` (optional) must be ⊆ requested.
/// `credential` is the entry referenced by the resource; it is sealed to
/// `executor_kem_pk` (the executor's KEM key, resolved from a trusted source such as the
/// executor's vault member record). `credential = None` approves without delivering a
/// credential (e.g. the desktop installs it in-process with `install_plain_credential`).
pub fn approve_request(
    identity: &DeviceIdentity,
    device_id: &DeviceId,
    request: &ApprovalRequest,
    narrowed: Option<AccessSpec>,
    credential: Option<(&CredentialSource<'_>, &[u8; 32])>,
    now: &Timestamp,
) -> Result<ApprovalDecision> {
    check_window(request, now)?;
    // check the conflict before signing anything
    if let Some((src, _)) = &credential
        && src.has_conflict
    {
        return Err(VaultError::SyncConflict);
    }
    let mut decision = build_decision(
        identity,
        device_id,
        request,
        Decision::Approve,
        narrowed,
        now,
    )?;
    if let Some((src, exe_kem_pk)) = credential {
        let material = credential_material(src, decision.expires_at)?;
        let aad = credential_aad_bytes(
            &request.approval_request_id,
            &decision.digest,
            &request.executor.executor_id,
        )?;
        decision.credential_envelope = Some(seal_credential(exe_kem_pk, &aad, &material)?);
    }
    Ok(decision)
}

/// Deny `request` (signed; digest over the requested access and the request expiry).
pub fn deny_request(
    identity: &DeviceIdentity,
    device_id: &DeviceId,
    request: &ApprovalRequest,
    now: &Timestamp,
) -> Result<ApprovalDecision> {
    if request.status != ApprovalStatus::Pending {
        return Err(VaultError::PreconditionFailed(
            "approval request is no longer pending",
        ));
    }
    Ok(build_decision(
        identity,
        device_id,
        request,
        Decision::Deny,
        None,
        now,
    )?)
}

/// Signed `connection.decision`.
pub fn sign_connection_decision(
    identity: &DeviceIdentity,
    connection_id: &ConnectionId,
    decision: Decision,
    allowed_projects: AllowedProjects,
    now: &Timestamp,
) -> Result<ConnectionDecision> {
    let mut m = ConnectionDecision {
        connection_id: connection_id.clone(),
        decision,
        allowed_projects,
        signed_at: aipass_types::time::truncate(*now),
        signature: String::new(),
    };
    m.sign_control(identity)?;
    Ok(m)
}

/// Signed `grant.revoke`.
pub fn sign_grant_revoke(
    identity: &DeviceIdentity,
    grant_id: &GrantId,
    level: RevocationLevel,
    now: &Timestamp,
) -> Result<GrantRevoke> {
    let mut m = GrantRevoke {
        grant_id: grant_id.clone(),
        level,
        signed_at: aipass_types::time::truncate(*now),
        signature: String::new(),
    };
    m.sign_control(identity)?;
    Ok(m)
}

/// Signed `connection.control`.
pub fn sign_connection_control(
    identity: &DeviceIdentity,
    connection_id: &ConnectionId,
    action: ControlAction,
    now: &Timestamp,
) -> Result<ConnectionControl> {
    let mut m = ConnectionControl {
        connection_id: connection_id.clone(),
        action,
        signed_at: aipass_types::time::truncate(*now),
        signature: String::new(),
    };
    m.sign_control(identity)?;
    Ok(m)
}
