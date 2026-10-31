// SPDX-License-Identifier: Apache-2.0
//! Public data shapes of the [`crate::VaultClient`] facade (mirrors CONTRACTS §12 so the
//! FFI, desktop and CLI can map them 1:1). Nothing here exposes key material; secret values
//! appear only in explicitly named fields of reveal / fill / kit results, all of which
//! redact themselves in `Debug`.

use aipass_crypto::SecretString;
use aipass_storage::StorageKind;
use aipass_types::Localized;
use aipass_types::ids::{DeviceId, EntryId, ProjectId, VaultId};
use aipass_types::time::{Timestamp, rfc3339, rfc3339_option};
use aipass_types::vault::{
    Checkpoint, DatabaseInfo, EntryKind, EntrySource, Lifecycle, MemberRole, MemberStatus,
    PasswordRules, Platform,
};
use aipass_vault::matching::MatchKind;
use serde::{Deserialize, Serialize};

/// `CoreStatus` (§12).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoreStatus {
    /// Vault on this device.
    pub vault_id: Option<VaultId>,
    /// Whether keys are in memory.
    pub unlocked: bool,
    /// This device.
    pub device_id: Option<DeviceId>,
    /// This device's name.
    pub device_name: Option<String>,
    /// Primary storage kind.
    pub storage_kind: Option<StorageKind>,
    /// Last successful sync.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "rfc3339_option"
    )]
    pub last_sync_at: Option<Timestamp>,
    /// Outbox size.
    pub pending_changes: u32,
    /// Entries with unresolved conflicts — `None` (unknown) while the vault is locked:
    /// conflicts are only known from the decrypted items, so a locked vault never claims 0.
    pub conflicts: Option<u32>,
    /// Recovery key verified by the user.
    pub recovery_verified: bool,
    /// A rollback was detected; writes are stopped.
    pub rollback_detected: bool,
    /// This device was revoked.
    pub revoked: bool,
    /// Current key epoch (when unlocked).
    pub key_epoch: Option<u32>,
    /// Last sync error code (non-sensitive).
    pub last_error: Option<String>,
    /// This device's Ed25519 public signing key (b64u, public), e.g. for the cloud's
    /// `POST /v1/devices {sign_pk}`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_sign_pk: Option<String>,
    /// This device's X25519 public KEM key (b64u, public).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_kem_pk: Option<String>,
}

/// List row (no secrets).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ItemSummary {
    /// Entry.
    pub entry_id: EntryId,
    /// Kind.
    pub kind: EntryKind,
    /// Title.
    pub title: String,
    /// Username.
    pub username: Option<String>,
    /// First URL.
    pub primary_url: Option<String>,
    /// Project.
    pub project_id: Option<ProjectId>,
    /// Lifecycle (已导入 · 已验证 · 需要处理 …).
    pub lifecycle: Lifecycle,
    /// Unresolved sync conflict (automatic use paused).
    pub has_conflict: bool,
    /// Local change not yet synced.
    pub pending_sync: bool,
    /// Tags.
    pub tags: Vec<String>,
    /// Updated.
    #[serde(with = "rfc3339")]
    pub updated_at: Timestamp,
}

/// A custom field as shown in the UI (sensitive values masked).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldView {
    /// Name.
    pub name: String,
    /// Value — only for non-sensitive fields.
    pub value: Option<String>,
    /// Secret-bearing.
    pub sensitive: bool,
}

/// Detail view with secrets masked (`get_item`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ItemDetail {
    /// Summary.
    #[serde(flatten)]
    pub summary: ItemSummary,
    /// All URLs.
    pub urls: Vec<String>,
    /// Notes.
    pub notes: Option<String>,
    /// Whether a secret is stored.
    pub has_secret: bool,
    /// Mask (`••••••••`) when a secret is stored.
    pub secret_masked: Option<String>,
    /// Whether TOTP is configured.
    pub has_totp: bool,
    /// Custom fields.
    pub fields: Vec<FieldView>,
    /// Database connection info (no password).
    pub database: Option<DatabaseInfo>,
    /// Site password rules.
    pub password_rules: Option<PasswordRules>,
    /// Source.
    pub source: EntrySource,
    /// Created.
    #[serde(with = "rfc3339")]
    pub created_at: Timestamp,
    /// Committed version (`None` until first sync).
    pub version: Option<u64>,
    /// Conflict versions.
    pub conflict_versions: Vec<u64>,
}

/// Which secret to reveal (`reveal_secret`, native re-authentication first; never for AI).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "field", content = "name")]
pub enum SecretField {
    /// Password / key / token.
    Secret,
    /// TOTP seed (base32).
    TotpSecret,
    /// A custom field by name.
    Field(String),
}

impl SecretField {
    /// Parse `"secret"`, `"totp"` or `"field:<name>"`.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "secret" | "password" => Some(Self::Secret),
            "totp" | "totp_secret" => Some(Self::TotpSecret),
            other => other
                .strip_prefix("field:")
                .map(|n| Self::Field(n.to_owned())),
        }
    }
}

/// Custom field input; `value: None` keeps the current value of the field with this name.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldInput {
    /// Name.
    pub name: String,
    /// New value or `None` to keep.
    pub value: Option<SecretString>,
    /// Secret-bearing.
    pub sensitive: bool,
}

impl core::fmt::Debug for FieldInput {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FieldInput")
            .field("sensitive", &self.sensitive)
            .finish_non_exhaustive()
    }
}

/// Create / update input (`save_item`). Secret-bearing values default to "keep" so a UI
/// that only ever saw masked values can update other fields.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ItemInput {
    /// Existing entry to update, or `None` to create.
    pub entry_id: Option<EntryId>,
    /// Kind.
    pub kind: EntryKind,
    /// Title.
    pub title: String,
    /// Username.
    pub username: Option<String>,
    /// New secret (`None` = keep / none).
    pub secret: Option<SecretString>,
    /// Remove the stored secret.
    #[serde(default)]
    pub clear_secret: bool,
    /// URLs.
    #[serde(default)]
    pub urls: Vec<String>,
    /// Notes.
    pub notes: Option<String>,
    /// TOTP as `otpauth://` URI or base32 seed (`None` = keep / none).
    pub totp: Option<SecretString>,
    /// Remove TOTP.
    #[serde(default)]
    pub clear_totp: bool,
    /// Custom fields (replaces the list; `value: None` keeps a field's value).
    #[serde(default)]
    pub fields: Vec<FieldInput>,
    /// Database info.
    pub database: Option<DatabaseInfo>,
    /// Project.
    pub project_id: Option<ProjectId>,
    /// Tags.
    #[serde(default)]
    pub tags: Vec<String>,
    /// Lifecycle (`None` = keep; new entries default to `verified` for manual entries).
    pub lifecycle: Option<Lifecycle>,
    /// Site password rules.
    pub password_rules: Option<PasswordRules>,
    /// Source (`None` = keep / manual).
    pub source: Option<EntrySource>,
}

impl core::fmt::Debug for ItemInput {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ItemInput")
            .field("entry_id", &self.entry_id)
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

impl ItemInput {
    /// A new entry of `kind` titled `title`.
    pub fn new(kind: EntryKind, title: impl Into<String>) -> Self {
        Self {
            entry_id: None,
            kind,
            title: title.into(),
            username: None,
            secret: None,
            clear_secret: false,
            urls: Vec::new(),
            notes: None,
            totp: None,
            clear_totp: false,
            fields: Vec::new(),
            database: None,
            project_id: None,
            tags: Vec::new(),
            lifecycle: None,
            password_rules: None,
            source: None,
        }
    }
}

/// Sync status (§12 `SyncReportFfi.status`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncStatus {
    /// Synced.
    Ok,
    /// Storage unreachable; changes stay in the outbox.
    Offline,
    /// Synced, but entries have unresolved conflicts.
    Conflict,
    /// Storage rolled back / replaced; writes stopped.
    RollbackDetected,
    /// Other error.
    Error,
}

/// Result of `sync()`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SyncReport {
    /// Status.
    pub status: SyncStatus,
    /// Remote entry changes pulled.
    pub pulled: u32,
    /// Local changes pushed.
    pub pushed: u32,
    /// Entries with unresolved conflicts after the sync.
    pub conflicts: u32,
    /// Local edits refused because the entry was deleted elsewhere (kept for restore).
    pub rejected: Vec<EntryId>,
    /// Local deletes skipped because the entry was edited elsewhere.
    pub delete_skipped: Vec<EntryId>,
    /// Error code (when `status` is not ok/conflict).
    pub error_code: Option<String>,
    /// Localized explanation.
    pub message: Option<Localized>,
}

/// One version of a conflicted entry (no secrets; `secret_differs` compares with current).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConflictVersion {
    /// Version.
    pub version: u64,
    /// Whether this is the current version.
    pub is_current: bool,
    /// Author device.
    pub author_device_id: DeviceId,
    /// Author name.
    pub author_name: Option<String>,
    /// Written at.
    #[serde(with = "rfc3339")]
    pub created_at: Timestamp,
    /// Username of this version.
    pub username: Option<String>,
    /// Whether the secret differs from the current version.
    pub secret_differs: bool,
}

/// An unresolved conflict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConflictInfo {
    /// Entry.
    pub entry_id: EntryId,
    /// Title.
    pub title: String,
    /// Current version.
    pub current_version: u64,
    /// Conflict versions.
    pub conflict_versions: Vec<u64>,
    /// Details of every version.
    pub versions: Vec<ConflictVersion>,
}

/// A device of the vault.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceInfo {
    /// Device.
    pub device_id: DeviceId,
    /// Name.
    pub name: String,
    /// Platform.
    pub platform: Platform,
    /// Role.
    pub role: MemberRole,
    /// Status.
    pub status: MemberStatus,
    /// This device.
    pub is_this_device: bool,
    /// The recovery-key member (not a physical device).
    pub is_recovery_key: bool,
    /// Who signed the current record.
    pub added_by: DeviceId,
    /// Record time.
    #[serde(with = "rfc3339")]
    pub updated_at: Timestamp,
    /// Key epoch of the record.
    pub key_epoch: u32,
    /// Ed25519 public signing key of the device (b64u, public).
    pub sign_pk: String,
    /// X25519 public KEM key of the device (b64u, public).
    pub kem_pk: String,
}

/// A credential to rotate after a revocation (§3.2, §10.4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RotationTask {
    /// Entry.
    pub entry_id: EntryId,
    /// Title.
    pub title: String,
    /// Kind.
    pub kind: EntryKind,
    /// Why.
    pub reason: Localized,
}

/// Result of `revoke_device`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevokeResult {
    /// Revoked device.
    pub device_id: DeviceId,
    /// New key epoch (unchanged for executors).
    pub key_epoch: u32,
    /// Long-term credentials the revoked device could read.
    pub rotation_tasks: Vec<RotationTask>,
    /// Honest note: data the device already had cannot be remotely erased.
    pub note: Localized,
}

/// Result of `create_vault`. `Debug` is redacted.
#[derive(Clone)]
pub struct CreateVaultResult {
    /// Vault.
    pub vault_id: VaultId,
    /// This device.
    pub device_id: DeviceId,
    /// Formatted recovery key (`AIPR-…`) — show once, never upload.
    pub recovery_key: SecretString,
    /// Recovery kit text (contains the recovery key).
    pub recovery_kit_text: SecretString,
}

impl core::fmt::Debug for CreateVaultResult {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CreateVaultResult")
            .field("vault_id", &self.vault_id)
            .field("device_id", &self.device_id)
            .finish_non_exhaustive()
    }
}

/// Result of `migrate_storage` (§10.2).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MigrationReport {
    /// Objects copied.
    pub objects_copied: u64,
    /// Objects that were already present and identical.
    pub objects_already_present: u64,
    /// Checkpoint verified on the target before switching.
    pub verified_checkpoint: Checkpoint,
    /// Entries decrypted from the target during verification.
    pub entries_verified: u64,
    /// The old copy was left untouched (the user removes it later).
    pub old_storage_kept: bool,
    /// Capability verdict of the target.
    pub target_report: aipass_storage::CapabilityReport,
}

/// Autofill candidate (no secrets).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AutofillCandidate {
    /// Entry.
    pub entry_id: EntryId,
    /// Title.
    pub title: String,
    /// Username.
    pub username: Option<String>,
    /// Match kind (same-site only after an explicit click).
    pub match_kind: MatchKind,
}

/// Username + password for a manual fill. `Debug` is redacted.
#[derive(Clone)]
pub struct AutofillCredential {
    /// Username.
    pub username: Option<String>,
    /// Password.
    pub password: SecretString,
    /// Current TOTP code, if configured.
    pub totp: Option<SecretString>,
}

impl core::fmt::Debug for AutofillCredential {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("AutofillCredential([REDACTED])")
    }
}

/// Identity registered with the OS credential provider (iOS / Android).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialIdentity {
    /// Entry.
    pub entry_id: EntryId,
    /// Service identifier (host).
    pub service_identifier: String,
    /// Username.
    pub username: Option<String>,
}

/// Result of saving a credential captured by the browser extension.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SaveStatus {
    /// New entry.
    Saved,
    /// Existing entry updated.
    Updated,
    /// Ambiguous; the user must confirm in the app.
    NeedsConfirmation,
}

/// A known executor (approval envelopes are sealed to its KEM key).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KnownExecutor {
    /// Name.
    pub name: String,
    /// Ed25519 key.
    #[serde(with = "aipass_crypto::b64u::array")]
    pub sign_pk: [u8; 32],
    /// X25519 KEM key.
    #[serde(with = "aipass_crypto::b64u::array")]
    pub kem_pk: [u8; 32],
}
