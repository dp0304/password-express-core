// SPDX-License-Identifier: Apache-2.0
//! Approval digest and signatures (CONTRACTS §7) — the **single** implementation used by
//! broker, CLI, desktop and FFI.
//!
//! ```text
//! digest = b64u(SHA-256(JCS({
//!   "v":2, "approval_request_id", "connection_id", "resource_id", "executor_id",
//!   "operations": sorted unique, "scope": normalized GrantScope (sorted arrays/maps),
//!   "limits": Limits (all four integers), "mode", "expires_at", "recipients": sorted connection ids,
//!   "operation_id": op_… | null, "parameters_digest": b64u | null   // both null for kind=access
//! })))
//! signature = Ed25519(device, "aipass:v1:approval:<approve|deny>:<digest>")
//! ```
//!
//! The approving client recomputes the digest **from the fields it displayed**; the broker
//! recomputes it from its stored request and the decision, so any change to resource,
//! view, fields, operation, executor, recipients — or, for `kind:"operation"`, to the
//! waiting operation or its normalized parameters — invalidates the approval (A05).
//! Version 1 digests (without the operation binding) are no longer accepted.
//!
//! [`request_digest`] is a separate, display-level hash of the whole request a client
//! rendered; clients pass it back when the user decides so a request replaced between
//! "shown" and "approved" is refused (`INTEGRITY_FAILED`).

use std::collections::{BTreeMap, BTreeSet};

use aipass_crypto::{Ed25519Signer, b64u};
use serde::Serialize;

use crate::SignatureError;
use crate::canonical::{CanonicalError, jcs_sha256_b64u, to_jcs_bytes};
use crate::error::{ApiError, ErrorCode};
use crate::ids::{ApprovalRequestId, ConnectionId, DeviceId, ExecutorId, OperationId, ResourceId};
use crate::models::{
    AccessSpec, ApprovalDecision, ApprovalKind, ApprovalMode, ApprovalRequest, ApprovalStatus,
    Decision, GithubScope, GrantScope, HttpApiScope, Limits, PostgresScope,
};
use crate::time::{Timestamp, format_rfc3339};

/// Digest format version (2: adds `operation_id` / `parameters_digest`).
pub const DIGEST_VERSION: u32 = 2;
/// Grace added to `requested.duration_seconds` when bounding `expires_at`.
pub const EXPIRY_GRACE_SECS: i64 = 60;
/// Default task grant TTL.
pub const DEFAULT_TASK_TTL_SECS: u64 = 900;
/// Maximum task grant TTL (24 h).
pub const MAX_TASK_TTL_SECS: u64 = 86_400;
/// Approval window for operation-triggered requests.
pub const OPERATION_APPROVAL_TTL_SECS: u64 = 120;
/// Approval window for explicit access requests.
pub const ACCESS_APPROVAL_TTL_SECS: u64 = 600;

fn sorted_unique(items: &[String]) -> Vec<String> {
    items
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

/// Sorted, de-duplicated operation names.
pub fn normalize_operations(ops: &[String]) -> Vec<String> {
    sorted_unique(ops)
}

/// Canonical form of a scope: every array sorted and de-duplicated, GitHub repos
/// lower-cased (GitHub names are case-insensitive), empty connector sections dropped.
pub fn normalize_scope(scope: &GrantScope) -> GrantScope {
    let postgres = scope.postgres.as_ref().and_then(|p| {
        let views: BTreeMap<String, Vec<String>> = p
            .views
            .iter()
            .map(|(v, f)| (v.clone(), sorted_unique(f)))
            .collect();
        (!views.is_empty()).then_some(PostgresScope { views })
    });
    let github = scope.github.as_ref().and_then(|g| {
        let repos: Vec<String> = g
            .repos
            .iter()
            .map(|r| r.to_ascii_lowercase())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        (!repos.is_empty()).then_some(GithubScope { repos })
    });
    let http_api = scope.http_api.as_ref().and_then(|h| {
        let operations = sorted_unique(&h.operations);
        (!operations.is_empty()).then_some(HttpApiScope { operations })
    });
    GrantScope {
        operations: sorted_unique(&scope.operations),
        postgres,
        github,
        http_api,
    }
}

/// Inputs of the approval digest.
#[derive(Debug, Clone)]
pub struct DigestInput<'a> {
    /// Request.
    pub approval_request_id: &'a ApprovalRequestId,
    /// Connection.
    pub connection_id: &'a ConnectionId,
    /// Resource.
    pub resource_id: &'a ResourceId,
    /// Executor.
    pub executor_id: &'a ExecutorId,
    /// Operations (normalized inside).
    pub operations: &'a [String],
    /// Scope (normalized inside).
    pub scope: &'a GrantScope,
    /// Limits.
    pub limits: &'a Limits,
    /// Mode.
    pub mode: ApprovalMode,
    /// Grant expiry.
    pub expires_at: &'a Timestamp,
    /// Result recipients (sorted inside).
    pub recipients: &'a [ConnectionId],
    /// Waiting operation (`kind:"operation"`); `None` (JSON `null`) for access requests.
    pub operation_id: Option<&'a OperationId>,
    /// `parameters_digest` of the waiting operation's normalized parameters
    /// ([`crate::exec::parameters_digest`]); `None` (JSON `null`) for access requests.
    pub parameters_digest: Option<&'a str>,
}

#[derive(Serialize)]
struct DigestDoc<'a> {
    v: u32,
    approval_request_id: &'a str,
    connection_id: &'a str,
    resource_id: &'a str,
    executor_id: &'a str,
    operations: Vec<String>,
    scope: GrantScope,
    limits: &'a Limits,
    mode: ApprovalMode,
    expires_at: String,
    recipients: Vec<String>,
    // Serialized as `null` when absent (never skipped): the key set is fixed for v2.
    operation_id: Option<&'a str>,
    parameters_digest: Option<&'a str>,
}

/// The canonical JSON document that is hashed (exposed for test vectors / debugging).
pub fn digest_document(input: &DigestInput<'_>) -> Result<Vec<u8>, CanonicalError> {
    to_jcs_bytes(&doc(input))
}

fn doc<'a>(input: &'a DigestInput<'a>) -> DigestDoc<'a> {
    let recipients: Vec<String> = input
        .recipients
        .iter()
        .map(|c| c.as_str().to_owned())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    DigestDoc {
        v: DIGEST_VERSION,
        approval_request_id: input.approval_request_id.as_str(),
        connection_id: input.connection_id.as_str(),
        resource_id: input.resource_id.as_str(),
        executor_id: input.executor_id.as_str(),
        operations: normalize_operations(input.operations),
        scope: normalize_scope(input.scope),
        limits: input.limits,
        mode: input.mode,
        expires_at: format_rfc3339(input.expires_at),
        recipients,
        operation_id: input.operation_id.map(OperationId::as_str),
        parameters_digest: input.parameters_digest,
    }
}

/// Compute the approval digest (b64u SHA-256 of the JCS document).
pub fn compute_digest(input: &DigestInput<'_>) -> Result<String, CanonicalError> {
    jcs_sha256_b64u(&doc(input))
}

/// The operation binding that enters the digest: `(operation_id, parameters_digest)` for
/// `kind:"operation"`, `(None, None)` for `kind:"access"` (whatever the request carries).
pub fn operation_binding(request: &ApprovalRequest) -> (Option<&OperationId>, Option<&str>) {
    match request.kind {
        ApprovalKind::Operation => (
            request.operation_id.as_ref(),
            request.parameters_digest.as_deref(),
        ),
        ApprovalKind::Access => (None, None),
    }
}

/// An operation-triggered request must name its operation and parameters, an access
/// request neither (`INTEGRITY_FAILED` otherwise) — a signature never covers an unbound
/// operation approval.
pub fn check_operation_binding(request: &ApprovalRequest) -> Result<(), ApiError> {
    let ok = match request.kind {
        ApprovalKind::Operation => {
            request.operation_id.is_some()
                && request
                    .parameters_digest
                    .as_deref()
                    .is_some_and(|d| !d.is_empty())
        }
        ApprovalKind::Access => {
            request.operation_id.is_none() && request.parameters_digest.is_none()
        }
    };
    if ok {
        Ok(())
    } else {
        Err(ApiError::integrity_failed().with_detail("reason", "operation binding"))
    }
}

/// Display-level digest of a whole approval request:
/// `b64u(SHA-256(JCS(request minus "status")))`. Every rendered field (summary, excluded
/// fields, names, scope, limits, executor, recipients, operation binding) is covered, so a
/// client can prove the request it is about to sign is the one it showed. Unknown fields
/// from newer brokers are dropped by deserialization and therefore not covered — they are
/// not displayed either.
pub fn request_digest(request: &ApprovalRequest) -> Result<String, CanonicalError> {
    let v = serde_json::to_value(request).map_err(|e| CanonicalError::Serialize(e.to_string()))?;
    let bytes = crate::canonical::value_jcs_without_field(&v, "status")?;
    Ok(b64u::encode(aipass_crypto::sha256(&bytes)))
}

/// Digest of `request` bound to the effective access (`approved` for approve, `requested`
/// for deny), the grant expiry and (for `kind:"operation"`) the waiting operation.
pub fn digest_for(
    request: &ApprovalRequest,
    effective: &AccessSpec,
    expires_at: &Timestamp,
) -> Result<String, CanonicalError> {
    let recipients: Vec<ConnectionId> = request
        .recipients
        .iter()
        .map(|r| r.connection_id.clone())
        .collect();
    let (operation_id, parameters_digest) = operation_binding(request);
    compute_digest(&DigestInput {
        approval_request_id: &request.approval_request_id,
        connection_id: &request.connection.connection_id,
        resource_id: &request.resource.resource_id,
        executor_id: &request.executor.executor_id,
        operations: &effective.operations,
        scope: &effective.scope,
        limits: &effective.limits,
        mode: effective.mode,
        expires_at,
        recipients: &recipients,
        operation_id,
        parameters_digest,
    })
}

/// `aipass:v1:approval:<approve|deny>:<digest>`.
pub fn signing_message(decision: Decision, digest: &str) -> String {
    format!("aipass:v1:approval:{}:{digest}", decision.as_str())
}

/// Sign a decision digest; returns the b64u signature.
pub fn sign_decision(signer: &dyn Ed25519Signer, decision: Decision, digest: &str) -> String {
    b64u::encode(signer.sign(signing_message(decision, digest).as_bytes()))
}

/// Verify the signature on a decision against the signer's public key.
pub fn verify_decision_signature(
    decision: &ApprovalDecision,
    signer_pk: &[u8; 32],
) -> Result<(), SignatureError> {
    let sig =
        b64u::decode_array::<64>(&decision.signature).map_err(|_| SignatureError::Malformed)?;
    let msg = signing_message(decision.decision, &decision.digest);
    aipass_crypto::identity::verify(signer_pk, msg.as_bytes(), &sig)
        .map_err(|_| SignatureError::Invalid)
}

/// `a ⊆ b` for grant scopes (compared in normalized form).
pub fn scope_is_subset(a: &GrantScope, b: &GrantScope) -> bool {
    let a = normalize_scope(a);
    let b = normalize_scope(b);
    let ops_b: BTreeSet<&String> = b.operations.iter().collect();
    if !a.operations.iter().all(|o| ops_b.contains(o)) {
        return false;
    }
    match (&a.postgres, &b.postgres) {
        (None, _) => {}
        (Some(_), None) => return false,
        (Some(pa), Some(pb)) => {
            for (view, fields) in &pa.views {
                let Some(allowed) = pb.views.get(view) else {
                    return false;
                };
                let allowed: BTreeSet<&String> = allowed.iter().collect();
                if !fields.iter().all(|f| allowed.contains(f)) {
                    return false;
                }
            }
        }
    }
    match (&a.github, &b.github) {
        (None, _) => {}
        (Some(_), None) => return false,
        (Some(ga), Some(gb)) => {
            let allowed: BTreeSet<&String> = gb.repos.iter().collect();
            if !ga.repos.iter().all(|r| allowed.contains(r)) {
                return false;
            }
        }
    }
    match (&a.http_api, &b.http_api) {
        (None, _) => {}
        (Some(_), None) => return false,
        (Some(ha), Some(hb)) => {
            let allowed: BTreeSet<&String> = hb.operations.iter().collect();
            if !ha.operations.iter().all(|o| allowed.contains(o)) {
                return false;
            }
        }
    }
    true
}

/// `approved ⊆ requested`: operations, scope, every limit, duration and mode breadth
/// (once < task < rule) may only shrink.
pub fn approved_is_subset(approved: &AccessSpec, requested: &AccessSpec) -> bool {
    let req_ops: BTreeSet<&String> = requested.operations.iter().collect();
    approved.operations.iter().all(|o| req_ops.contains(o))
        && scope_is_subset(&approved.scope, &requested.scope)
        && approved.limits.within(&requested.limits)
        && approved.duration_seconds <= requested.duration_seconds
        && approved.mode.rank() <= requested.mode.rank()
}

/// Latest acceptable grant expiry: `now + requested.duration_seconds + 60`.
pub fn max_expires_at(now: &Timestamp, requested_duration_seconds: u64) -> Timestamp {
    let d = i64::try_from(requested_duration_seconds).unwrap_or(i64::MAX / 2);
    crate::time::add_secs(now, d.saturating_add(EXPIRY_GRACE_SECS))
}

/// Build and sign a decision on a trusted device. For `approve`, `narrowed` (if given) must
/// be ⊆ `request.requested`; the grant expiry is `now + duration_seconds`. For `deny`, the
/// digest covers the requested access and `expires_at` is the request's own expiry.
///
/// The credential envelope (approve only) is attached separately with
/// [`crate::exec::seal_credential`] using [`crate::exec::CredentialAad`].
pub fn build_decision(
    signer: &dyn Ed25519Signer,
    signer_device_id: &DeviceId,
    request: &ApprovalRequest,
    decision: Decision,
    narrowed: Option<AccessSpec>,
    now: &Timestamp,
) -> Result<ApprovalDecision, ApiError> {
    check_operation_binding(request)?;
    let (approved, effective, expires_at) = match decision {
        Decision::Approve => {
            let spec = narrowed.unwrap_or_else(|| request.requested.clone());
            if !approved_is_subset(&spec, &request.requested) {
                return Err(ApiError::scope_denied()
                    .with_detail("reason", "approved access is not a subset of the request"));
            }
            let secs = i64::try_from(spec.duration_seconds)
                .map_err(|_| ApiError::invalid_request("期限无效", "invalid duration"))?;
            let exp = crate::time::add_secs(now, secs);
            (Some(spec.clone()), spec, exp)
        }
        Decision::Deny => (None, request.requested.clone(), request.expires_at),
    };
    let digest = digest_for(request, &effective, &expires_at)?;
    let signature = sign_decision(signer, decision, &digest);
    Ok(ApprovalDecision {
        approval_request_id: request.approval_request_id.clone(),
        decision,
        approved,
        expires_at,
        digest,
        signer_device_id: signer_device_id.clone(),
        signed_at: crate::time::truncate(*now),
        signature,
        credential_envelope: None,
    })
}

/// Broker-side verification of a decision against the stored request (everything except
/// "signer is an active trusted owner/member device", which needs the member set — resolve
/// `signer_pk` from it first). Checks: request id match, request still pending and inside
/// its window (never approve after expiry), recomputed digest, signature,
/// `approved ⊆ requested`, `expires_at ≤ now + requested.duration_seconds + 60`.
pub fn verify_decision(
    decision: &ApprovalDecision,
    request: &ApprovalRequest,
    signer_pk: &[u8; 32],
    now: &Timestamp,
) -> Result<(), ApiError> {
    if decision.approval_request_id != request.approval_request_id {
        return Err(ApiError::invalid_request(
            "审批请求不匹配",
            "approval request mismatch",
        ));
    }
    if request.status != ApprovalStatus::Pending {
        return Err(match request.status {
            ApprovalStatus::Expired => ApiError::new(ErrorCode::ApprovalExpired),
            _ => ApiError::invalid_request(
                "该审批请求已处理",
                "approval request is no longer pending",
            ),
        });
    }
    if *now > request.expires_at {
        return Err(ApiError::new(ErrorCode::ApprovalExpired));
    }
    check_operation_binding(request)?;
    let effective = match (decision.decision, &decision.approved) {
        (Decision::Approve, Some(a)) => a.clone(),
        (Decision::Approve, None) => {
            return Err(ApiError::invalid_request(
                "批准缺少 approved 字段",
                "approve decision without approved scope",
            ));
        }
        (Decision::Deny, _) => request.requested.clone(),
    };
    let expected = digest_for(request, &effective, &decision.expires_at)?;
    if !aipass_crypto::ct_eq(expected.as_bytes(), decision.digest.as_bytes()) {
        return Err(ApiError::integrity_failed().with_detail("reason", "digest mismatch"));
    }
    verify_decision_signature(decision, signer_pk).map_err(|_| ApiError::identity_unverified())?;
    if decision.decision == Decision::Approve {
        if !approved_is_subset(&effective, &request.requested) {
            return Err(ApiError::scope_denied());
        }
        if decision.expires_at > max_expires_at(now, request.requested.duration_seconds) {
            return Err(ApiError::invalid_request(
                "授权期限超过请求范围",
                "expires_at exceeds the requested duration",
            ));
        }
        if decision.expires_at <= *now {
            return Err(ApiError::new(ErrorCode::ApprovalExpired));
        }
    }
    Ok(())
}

/// Canonical AAD of a credential envelope: `JCS({approval_request_id, digest, executor_id})`.
pub fn credential_aad_bytes(
    approval_request_id: &ApprovalRequestId,
    digest: &str,
    executor_id: &ExecutorId,
) -> Result<Vec<u8>, CanonicalError> {
    crate::exec::CredentialAad {
        approval_request_id: approval_request_id.clone(),
        digest: digest.to_owned(),
        executor_id: executor_id.clone(),
    }
    .to_bytes()
}
