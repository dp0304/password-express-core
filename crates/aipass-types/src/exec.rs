// SPDX-License-Identifier: Apache-2.0
//! The `ExecutorBackend` trait and execution types (CONTRACTS §8).
//!
//! The broker executes exclusively through [`ExecutorBackend`], so it never depends on
//! connector crates. Credentials live only in executor memory (zeroized), keyed by grant,
//! and are dropped on expiry / revoke / `end_sessions`.

use core::fmt;

use aipass_crypto::{KemKeypair, SealedBox, SecretString};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio_util::sync::CancellationToken;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::canonical::{CanonicalError, jcs_sha256_b64u, to_jcs_bytes};
use crate::error::ApiError;
use crate::ids::{ApprovalRequestId, EntryId, ExecutorId, GrantId, OperationId, PolicyId};
use crate::models::{
    Connector, ExecutorInfo, GrantScope, Limits, Resource, SideEffectClass, SideEffects,
};
use crate::time::{Timestamp, rfc3339};
use crate::vault::{DatabaseInfo, EntryKind};

pub use crate::models::LevelReport;

/// Release stage of an operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Stage {
    /// Generally available in V1.
    #[serde(rename = "v1")]
    V1,
    /// V1.1 — experimental, off by default (UI: 实验性).
    #[serde(rename = "v1.1")]
    V1_1,
}

/// Static description of a connector operation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OperationSpec {
    /// Name, e.g. `postgres.query_view`.
    pub name: String,
    /// Connector.
    pub connector: Connector,
    /// zh-CN description.
    pub description_zh: String,
    /// English description.
    pub description_en: String,
    /// Side-effect class.
    pub side_effect: SideEffectClass,
    /// Whether automatic retry after an uncertain outcome is safe.
    pub retry_safe: bool,
    /// JSON Schema of the parameters.
    pub parameters_schema: Value,
    /// Stage.
    pub stage: Stage,
}

/// A validated, normalized request.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NormalizedRequest {
    /// Operation.
    pub operation: String,
    /// Normalized parameters.
    pub params: Value,
    /// Minimal scope a grant must cover for this request.
    pub required_scope: GrantScope,
    /// Digest of the normalized parameters ([`parameters_digest`]).
    pub parameters_digest: String,
}

/// Everything the executor needs to run one operation.
#[derive(Debug, Clone)]
pub struct ExecutionRequest {
    /// Operation.
    pub operation_id: OperationId,
    /// Grant whose installed credential is used.
    pub grant_id: GrantId,
    /// Resource (config without secrets).
    pub resource: Resource,
    /// Normalized request.
    pub normalized: NormalizedRequest,
    /// Remaining budget (rows/requests/bytes) — the executor must cap output to it.
    pub remaining: Limits,
    /// Cancellation (operations.cancel / revoke end_sessions).
    pub cancel: CancellationToken,
}

/// Executor result before the broker wraps it into an `OperationResult`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExecutionOutcome {
    /// Output-filtered data.
    pub data: Value,
    /// Rows returned.
    pub rows: Option<u64>,
    /// Serialized size of `data`.
    pub bytes: u64,
    /// Truncated by limits.
    pub truncated: bool,
    /// Fields redacted by the output filter.
    pub restricted_fields: Vec<String>,
    /// Side effects.
    pub side_effects: SideEffects,
}

/// Plaintext of a credential envelope (`info=aipass/v1/credential`). Zeroized on drop;
/// `Debug` never shows `username` or `secret`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct CredentialMaterial {
    /// Entry.
    #[zeroize(skip)]
    pub entry_id: EntryId,
    /// Entry version.
    #[zeroize(skip)]
    pub version: u64,
    /// Kind.
    #[zeroize(skip)]
    pub kind: EntryKind,
    /// Username.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// Secret.
    pub secret: SecretString,
    /// Database info.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[zeroize(skip)]
    pub database: Option<DatabaseInfo>,
    /// Must be dropped after this time.
    #[serde(with = "rfc3339")]
    #[zeroize(skip)]
    pub expires_at: Timestamp,
}

impl fmt::Debug for CredentialMaterial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CredentialMaterial")
            .field("entry_id", &self.entry_id)
            .field("version", &self.version)
            .field("kind", &self.kind)
            .field("username", &self.username.as_ref().map(|_| "[REDACTED]"))
            .field("secret", &"[REDACTED]")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// AAD of a credential envelope: `JCS({approval_request_id, digest, executor_id})`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialAad {
    /// Approval request.
    pub approval_request_id: ApprovalRequestId,
    /// Approval digest.
    pub digest: String,
    /// Executor.
    pub executor_id: ExecutorId,
}

impl CredentialAad {
    /// Canonical bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, CanonicalError> {
        to_jcs_bytes(self)
    }
}

/// Additive extension for experimental unattended delegation (`/credentials/delegate`):
/// AAD `JCS({policy_id, policy_digest, executor_id})`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelegationAad {
    /// Policy.
    pub policy_id: PolicyId,
    /// [`crate::policy::policy_digest`].
    pub policy_digest: String,
    /// Executor.
    pub executor_id: ExecutorId,
}

impl DelegationAad {
    /// Canonical bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, CanonicalError> {
        to_jcs_bytes(self)
    }
}

/// Seal credential material to an executor's KEM key (approving device side).
pub fn seal_credential(
    executor_kem_pk: &[u8; 32],
    aad: &[u8],
    material: &CredentialMaterial,
) -> Result<SealedBox, ApiError> {
    let pt =
        zeroize::Zeroizing::new(serde_json::to_vec(material).map_err(|_| ApiError::internal())?);
    aipass_crypto::hpke::seal(executor_kem_pk, aipass_crypto::info::CREDENTIAL, aad, &pt)
        .map_err(ApiError::from)
}

/// Open a credential envelope inside the executor. Failures are `INTEGRITY_FAILED`
/// (never echoing any content).
pub fn open_credential(
    executor: &KemKeypair,
    aad: &[u8],
    sealed: &SealedBox,
) -> Result<CredentialMaterial, ApiError> {
    let pt = aipass_crypto::hpke::open(executor, aipass_crypto::info::CREDENTIAL, aad, sealed)?;
    serde_json::from_slice(pt.expose()).map_err(|_| ApiError::integrity_failed())
}

/// `b64u(SHA-256(JCS({operation, params})))` — digest of normalized parameters, used for
/// idempotency comparison.
pub fn parameters_digest(operation: &str, params: &Value) -> Result<String, CanonicalError> {
    #[derive(Serialize)]
    struct D<'a> {
        operation: &'a str,
        params: &'a Value,
    }
    jcs_sha256_b64u(&D { operation, params })
}

/// The executor interface used by the broker (CONTRACTS §8).
#[async_trait]
pub trait ExecutorBackend: Send + Sync {
    /// Identity, protection level and capabilities.
    fn info(&self) -> ExecutorInfo;
    /// Operation specs offered for a connector name (`postgres`, `github`, `http_api`).
    fn operation_specs(&self, connector: &str) -> Vec<OperationSpec>;
    /// Schema validation + allowlist → `INVALID_REQUEST` / `SCOPE_DENIED`.
    fn normalize(
        &self,
        resource: &Resource,
        operation: &str,
        params: &Value,
    ) -> Result<NormalizedRequest, ApiError>;
    /// Whether `scope` and the remaining `limits` cover `req`.
    fn scope_covers(&self, scope: &GrantScope, limits: &Limits, req: &NormalizedRequest) -> bool;
    /// Install a sealed credential for a grant.
    async fn install_credential(
        &self,
        grant_id: &str,
        envelope: &SealedBox,
        aad: &CredentialAad,
    ) -> Result<(), ApiError>;
    /// Install a plaintext credential — **in-process trusted client only** (desktop).
    async fn install_plain_credential(
        &self,
        grant_id: &str,
        material: CredentialMaterial,
    ) -> Result<(), ApiError>;
    /// Drop the credential of a grant (zeroized).
    async fn drop_credential(&self, grant_id: &str);
    /// Execute an authorized operation.
    async fn execute(&self, req: ExecutionRequest) -> Result<ExecutionOutcome, ApiError>;
    /// Cancel a running operation; true if it was running and is now cancelled.
    async fn cancel(&self, operation_id: &str) -> bool;
    /// Revocation level 2: cancel running operations, close sessions, drop credentials.
    async fn end_sessions(&self, grant_id: &str) -> LevelReport;
    /// Revocation level 3: revoke upstream leases/tokens where supported.
    async fn revoke_upstream(&self, grant_id: &str) -> LevelReport;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn material() -> CredentialMaterial {
        CredentialMaterial {
            entry_id: EntryId::generate(),
            version: 3,
            kind: EntryKind::Database,
            username: Some("readonly_user".into()),
            secret: SecretString::from("pg-pass-DO-NOT-LEAK"),
            database: Some(DatabaseInfo {
                engine: "postgres".into(),
                host: "db.internal".into(),
                port: 5432,
                dbname: "lure".into(),
                sslmode: "require".into(),
            }),
            expires_at: crate::time::now(),
        }
    }

    #[test]
    fn credential_envelope_roundtrip() {
        let exe = KemKeypair::generate();
        let aad = CredentialAad {
            approval_request_id: ApprovalRequestId::generate(),
            digest: "d".into(),
            executor_id: ExecutorId::generate(),
        };
        let m = material();
        let sealed = seal_credential(&exe.public_key(), &aad.to_bytes().unwrap(), &m).unwrap();
        let back = open_credential(&exe, &aad.to_bytes().unwrap(), &sealed).unwrap();
        assert_eq!(back, m);
        let other = CredentialAad {
            digest: "e".into(),
            ..aad.clone()
        };
        let err = open_credential(&exe, &other.to_bytes().unwrap(), &sealed).unwrap_err();
        assert_eq!(err.code, crate::error::ErrorCode::IntegrityFailed);
        let dbg = format!("{m:?} {err:?} {err}");
        assert!(!dbg.contains("pg-pass") && !dbg.contains("readonly_user"));
    }

    #[test]
    fn parameters_digest_is_order_independent() {
        let a = parameters_digest(
            "postgres.query_view",
            &serde_json::json!({"view":"v","fields":["a"]}),
        )
        .unwrap();
        let b = parameters_digest(
            "postgres.query_view",
            &serde_json::json!({"fields":["a"],"view":"v"}),
        )
        .unwrap();
        assert_eq!(a, b);
        let c = parameters_digest(
            "postgres.query_view",
            &serde_json::json!({"fields":["a","b"],"view":"v"}),
        )
        .unwrap();
        assert_ne!(a, c);
        assert!(parameters_digest("x", &serde_json::json!({"f": 1.5})).is_err());
    }

    #[test]
    fn stage_strings() {
        assert_eq!(serde_json::to_value(Stage::V1_1).unwrap(), "v1.1");
    }
}
