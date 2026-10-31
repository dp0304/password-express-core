// SPDX-License-Identifier: Apache-2.0
//! Records crossing the FFI boundary and their conversions.
//!
//! Conventions: identifiers are prefixed strings (`ent_…`, `dev_…`); enum-like values are
//! the snake_case strings of the JSON contract (`"login"`, `"sync_capable"`, …);
//! timestamps are Unix seconds (`i64`). Secret-bearing inputs are wrapped into
//! `SecretString` immediately; no output record carries a secret except
//! [`AutofillCredentialFfi`] and the recovery key of [`CreateVaultResultFfi`].

use std::collections::BTreeMap;

use aipass_crypto::SecretString;
use aipass_storage::{StorageKind, StorageProfile};
use aipass_types::ids::{EntryId, ProjectId};
use aipass_types::models::{
    AccessSpec, ApprovalRequest, GithubScope, GrantScope, HttpApiScope, Limits, PostgresScope,
    RevocationReport,
};
use aipass_types::time::Timestamp;
use aipass_types::vault::{DatabaseInfo, PasswordRules};
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::error::{CoreError, CoreResult, pick};

// ---------------------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------------------

/// snake_case JSON name of a serde enum.
pub(crate) fn enum_str<T: Serialize>(v: &T) -> String {
    serde_json::to_value(v)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_default()
}

/// Parse a snake_case JSON enum name.
pub(crate) fn parse_enum<T: DeserializeOwned>(s: &str, what: &str) -> CoreResult<T> {
    serde_json::from_value(serde_json::Value::String(s.to_owned())).map_err(|_| {
        CoreError::invalid(&format!("无效的 {what}：{s}"), &format!("invalid {what}: {s}"))
    })
}

pub(crate) fn ts(t: &Timestamp) -> i64 {
    t.timestamp()
}

pub(crate) fn parse_id<T: std::str::FromStr>(s: &str, what: &str) -> CoreResult<T> {
    s.parse::<T>().map_err(|_| {
        CoreError::invalid(&format!("无效的 {what}"), &format!("invalid {what}"))
    })
}

pub(crate) fn secret(s: String) -> SecretString {
    SecretString::new(s)
}

// ---------------------------------------------------------------------------------------
// status / vault
// ---------------------------------------------------------------------------------------

/// `status()` result.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct CoreStatus {
    pub vault_id: Option<String>,
    pub unlocked: bool,
    pub device_id: Option<String>,
    pub device_name: Option<String>,
    pub storage_kind: Option<String>,
    pub last_sync_at: Option<i64>,
    pub pending_changes: u32,
    pub conflicts: u32,
    pub recovery_verified: bool,
    pub rollback_detected: bool,
    pub revoked: bool,
    pub key_epoch: Option<u32>,
    pub relay_configured: bool,
    pub license: Option<LicenseStatusFfi>,
    /// This device's Ed25519 public signing key (b64u; public). Send it as `sign_pk` in
    /// the cloud's `POST /v1/devices`.
    pub device_sign_pk: Option<String>,
    /// This device's X25519 public KEM key (b64u; public).
    pub device_kem_pk: Option<String>,
}

impl CoreStatus {
    pub(crate) fn from_core(
        s: aipass_sync::CoreStatus,
        relay_configured: bool,
        license: Option<LicenseStatusFfi>,
    ) -> Self {
        Self {
            vault_id: s.vault_id.map(|v| v.to_string()),
            unlocked: s.unlocked,
            device_id: s.device_id.map(|v| v.to_string()),
            device_name: s.device_name,
            storage_kind: s.storage_kind.map(|k| enum_str(&k)),
            last_sync_at: s.last_sync_at.as_ref().map(ts),
            pending_changes: s.pending_changes,
            // the FFI record keeps its u32 (bindings unchanged): unknown while locked → 0
            conflicts: s.conflicts.unwrap_or(0),
            recovery_verified: s.recovery_verified,
            rollback_detected: s.rollback_detected,
            revoked: s.revoked,
            key_epoch: s.key_epoch,
            relay_configured,
            license,
            device_sign_pk: s.device_sign_pk,
            device_kem_pk: s.device_kem_pk,
        }
    }
}

/// Result of `create_vault` / `replace_recovery_key`. `recovery_key` and
/// `recovery_kit_text` are shown once for the user to save; never store them natively.
#[derive(Clone, uniffi::Record)]
pub struct CreateVaultResultFfi {
    pub vault_id: String,
    pub device_id: String,
    pub recovery_key: String,
    pub recovery_kit_text: String,
}

impl std::fmt::Debug for CreateVaultResultFfi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CreateVaultResultFfi")
            .field("vault_id", &self.vault_id)
            .field("device_id", &self.device_id)
            .finish_non_exhaustive()
    }
}

impl From<aipass_sync::CreateVaultResult> for CreateVaultResultFfi {
    fn from(r: aipass_sync::CreateVaultResult) -> Self {
        Self {
            vault_id: r.vault_id.to_string(),
            device_id: r.device_id.to_string(),
            recovery_key: r.recovery_key.expose().to_owned(),
            recovery_kit_text: r.recovery_kit_text.expose().to_owned(),
        }
    }
}

/// Storage profile (`kind`: `local` | `official` | `s3` | `webdav` | `selfhost`).
/// Secrets (S3 secret key, WebDAV password, enroll token) are passed separately.
#[derive(Debug, Clone, PartialEq, Eq, Default, uniffi::Record)]
pub struct StorageProfileFfi {
    pub kind: String,
    pub endpoint: Option<String>,
    pub region: Option<String>,
    pub bucket: Option<String>,
    pub prefix: Option<String>,
    pub path_style: Option<bool>,
    pub base_url: Option<String>,
    pub username: Option<String>,
    pub path: Option<String>,
}

impl StorageProfileFfi {
    pub(crate) fn to_profile(&self) -> CoreResult<StorageProfile> {
        let kind: StorageKind = parse_enum(&self.kind, "storage kind")?;
        let mut p = StorageProfile::new(kind);
        p.endpoint = self.endpoint.clone();
        p.region = self.region.clone();
        p.bucket = self.bucket.clone();
        p.prefix = self.prefix.clone();
        p.path_style = self.path_style;
        p.base_url = self.base_url.clone();
        p.username = self.username.clone();
        p.path = self.path.clone();
        Ok(p)
    }
}

/// Storage capability test (§10.2). `verdict`: `sync_capable` | `backup_only`.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct CapabilityReportFfi {
    pub read: bool,
    pub write: bool,
    pub list: bool,
    pub conditional_create: bool,
    pub conditional_update: bool,
    pub delete: bool,
    pub roundtrip: bool,
    pub verdict: String,
    pub details: Vec<String>,
}

impl From<aipass_storage::CapabilityReport> for CapabilityReportFfi {
    fn from(r: aipass_storage::CapabilityReport) -> Self {
        Self {
            read: r.read,
            write: r.write,
            list: r.list,
            conditional_create: r.conditional_create,
            conditional_update: r.conditional_update,
            delete: r.delete,
            roundtrip: r.roundtrip,
            verdict: enum_str(&r.verdict),
            details: r.details,
        }
    }
}

/// Storage migration result.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct MigrationReportFfi {
    pub objects_copied: u64,
    pub objects_already_present: u64,
    pub entries_verified: u64,
    pub old_storage_kept: bool,
    pub verified_seq: u64,
    pub target: CapabilityReportFfi,
}

impl From<aipass_sync::MigrationReport> for MigrationReportFfi {
    fn from(r: aipass_sync::MigrationReport) -> Self {
        Self {
            objects_copied: r.objects_copied,
            objects_already_present: r.objects_already_present,
            entries_verified: r.entries_verified,
            old_storage_kept: r.old_storage_kept,
            verified_seq: r.verified_checkpoint.seq,
            target: r.target_report.into(),
        }
    }
}

// ---------------------------------------------------------------------------------------
// items
// ---------------------------------------------------------------------------------------

/// List row (never contains secrets).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ItemSummary {
    pub entry_id: String,
    pub kind: String,
    pub title: String,
    pub username: Option<String>,
    pub primary_url: Option<String>,
    pub project_id: Option<String>,
    pub lifecycle: String,
    pub has_conflict: bool,
    pub pending_sync: bool,
    pub tags: Vec<String>,
    pub updated_at: i64,
}

impl From<aipass_sync::ItemSummary> for ItemSummary {
    fn from(s: aipass_sync::ItemSummary) -> Self {
        Self {
            entry_id: s.entry_id.to_string(),
            kind: enum_str(&s.kind),
            title: s.title,
            username: s.username,
            primary_url: s.primary_url,
            project_id: s.project_id.map(|p| p.to_string()),
            lifecycle: enum_str(&s.lifecycle),
            has_conflict: s.has_conflict,
            pending_sync: s.pending_sync,
            tags: s.tags,
            updated_at: ts(&s.updated_at),
        }
    }
}

/// Custom field view; `value` is `None` for sensitive fields (use `reveal_secret`).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FieldViewFfi {
    pub name: String,
    pub value: Option<String>,
    pub sensitive: bool,
}

/// Database connection info (no password).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct DatabaseInfoFfi {
    pub engine: String,
    pub host: String,
    pub port: u16,
    pub dbname: String,
    pub sslmode: String,
}

impl From<DatabaseInfo> for DatabaseInfoFfi {
    fn from(d: DatabaseInfo) -> Self {
        Self {
            engine: d.engine,
            host: d.host,
            port: d.port,
            dbname: d.dbname,
            sslmode: d.sslmode,
        }
    }
}

impl From<DatabaseInfoFfi> for DatabaseInfo {
    fn from(d: DatabaseInfoFfi) -> Self {
        Self {
            engine: d.engine,
            host: d.host,
            port: d.port,
            dbname: d.dbname,
            sslmode: d.sslmode,
        }
    }
}

/// Password generator rules (§2.6). `PasswordRulesFfi::default()` on the Rust side and
/// `default_password_rules()` for native callers give the contract defaults.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct PasswordRulesFfi {
    pub length: u32,
    pub lower: bool,
    pub upper: bool,
    pub digits: bool,
    pub symbols: bool,
    pub symbol_set: String,
    pub exclude_ambiguous: bool,
    pub require_each_class: bool,
}

impl Default for PasswordRulesFfi {
    fn default() -> Self {
        PasswordRules::default().into()
    }
}

impl From<PasswordRules> for PasswordRulesFfi {
    fn from(r: PasswordRules) -> Self {
        Self {
            length: r.length,
            lower: r.lower,
            upper: r.upper,
            digits: r.digits,
            symbols: r.symbols,
            symbol_set: r.symbol_set,
            exclude_ambiguous: r.exclude_ambiguous,
            require_each_class: r.require_each_class,
        }
    }
}

impl From<PasswordRulesFfi> for PasswordRules {
    fn from(r: PasswordRulesFfi) -> Self {
        Self {
            length: r.length,
            lower: r.lower,
            upper: r.upper,
            digits: r.digits,
            symbols: r.symbols,
            symbol_set: r.symbol_set,
            exclude_ambiguous: r.exclude_ambiguous,
            require_each_class: r.require_each_class,
        }
    }
}

/// Item detail with secrets masked.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ItemDetail {
    pub summary: ItemSummary,
    pub urls: Vec<String>,
    pub notes: Option<String>,
    pub has_secret: bool,
    pub secret_masked: Option<String>,
    pub has_totp: bool,
    pub fields: Vec<FieldViewFfi>,
    pub database: Option<DatabaseInfoFfi>,
    pub password_rules: Option<PasswordRulesFfi>,
    /// `manual` | `generated` | `import:<format>`.
    pub source: String,
    pub created_at: i64,
    pub version: Option<u64>,
    pub conflict_versions: Vec<u64>,
}

impl From<aipass_sync::ItemDetail> for ItemDetail {
    fn from(d: aipass_sync::ItemDetail) -> Self {
        let source = match serde_json::to_value(&d.source) {
            Ok(serde_json::Value::String(s)) => s,
            Ok(serde_json::Value::Object(m)) => m
                .iter()
                .next()
                .map(|(k, v)| format!("{k}:{}", v.as_str().unwrap_or_default()))
                .unwrap_or_default(),
            _ => String::new(),
        };
        Self {
            summary: d.summary.into(),
            urls: d.urls,
            notes: d.notes,
            has_secret: d.has_secret,
            secret_masked: d.secret_masked,
            has_totp: d.has_totp,
            fields: d
                .fields
                .into_iter()
                .map(|f| FieldViewFfi {
                    name: f.name,
                    value: f.value,
                    sensitive: f.sensitive,
                })
                .collect(),
            database: d.database.map(Into::into),
            password_rules: d.password_rules.map(Into::into),
            source,
            created_at: ts(&d.created_at),
            version: d.version,
            conflict_versions: d.conflict_versions,
        }
    }
}

/// Custom field input; `value = None` keeps the stored value of an existing field.
#[derive(Clone, PartialEq, Eq, uniffi::Record)]
pub struct FieldInputFfi {
    pub name: String,
    pub value: Option<String>,
    pub sensitive: bool,
}

impl std::fmt::Debug for FieldInputFfi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FieldInputFfi")
            .field("name", &self.name)
            .field("sensitive", &self.sensitive)
            .finish_non_exhaustive()
    }
}

/// Create (`entry_id = None`) or update an item. `secret` / `totp = None` keep the stored
/// value; `clear_secret` / `clear_totp` remove it. `totp` accepts a Base32 secret or an
/// `otpauth://` URI.
#[derive(Clone, PartialEq, Eq, uniffi::Record)]
pub struct ItemInputFfi {
    pub entry_id: Option<String>,
    pub kind: String,
    pub title: String,
    pub username: Option<String>,
    pub secret: Option<String>,
    pub clear_secret: bool,
    pub urls: Vec<String>,
    pub notes: Option<String>,
    pub totp: Option<String>,
    pub clear_totp: bool,
    pub fields: Vec<FieldInputFfi>,
    pub database: Option<DatabaseInfoFfi>,
    pub project_id: Option<String>,
    pub tags: Vec<String>,
    pub lifecycle: Option<String>,
    pub password_rules: Option<PasswordRulesFfi>,
}

impl std::fmt::Debug for ItemInputFfi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ItemInputFfi")
            .field("entry_id", &self.entry_id)
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

impl ItemInputFfi {
    pub(crate) fn into_input(self) -> CoreResult<aipass_sync::ItemInput> {
        let mut i = aipass_sync::ItemInput::new(parse_enum(&self.kind, "kind")?, self.title);
        i.entry_id = match self.entry_id {
            Some(e) => Some(parse_id::<EntryId>(&e, "entry_id")?),
            None => None,
        };
        i.username = self.username;
        i.secret = self.secret.map(secret);
        i.clear_secret = self.clear_secret;
        i.urls = self.urls;
        i.notes = self.notes;
        i.totp = self.totp.map(secret);
        i.clear_totp = self.clear_totp;
        i.fields = self
            .fields
            .into_iter()
            .map(|f| aipass_sync::FieldInput {
                name: f.name,
                value: f.value.map(secret),
                sensitive: f.sensitive,
            })
            .collect();
        i.database = self.database.map(Into::into);
        i.project_id = match self.project_id {
            Some(p) => Some(parse_id::<ProjectId>(&p, "project_id")?),
            None => None,
        };
        i.tags = self.tags;
        i.lifecycle = match self.lifecycle {
            Some(l) => Some(parse_enum(&l, "lifecycle")?),
            None => None,
        };
        i.password_rules = self.password_rules.map(Into::into);
        Ok(i)
    }
}

/// Current TOTP code.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct TotpCode {
    pub code: String,
    pub remaining_seconds: u32,
    pub period: u32,
}

/// CSV duplicate (reported for merging, not imported).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct DuplicateFfi {
    pub existing_entry_id: String,
    pub title: String,
    pub username: Option<String>,
    pub url: Option<String>,
    pub row: u64,
}

/// Skipped / warned CSV row.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SkippedRowFfi {
    pub row: u64,
    pub reason: String,
}

/// Import result.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ImportReportFfi {
    pub imported: u32,
    pub duplicates: Vec<DuplicateFfi>,
    pub skipped: Vec<SkippedRowFfi>,
    pub warnings: Vec<SkippedRowFfi>,
}

impl From<aipass_vault::import::ImportReport> for ImportReportFfi {
    fn from(r: aipass_vault::import::ImportReport) -> Self {
        let rows = |v: Vec<aipass_vault::import::SkippedRow>| {
            v.into_iter()
                .map(|s| SkippedRowFfi {
                    row: s.row,
                    reason: s.reason,
                })
                .collect()
        };
        Self {
            imported: r.imported,
            duplicates: r
                .duplicates
                .into_iter()
                .map(|d| DuplicateFfi {
                    existing_entry_id: d.existing_entry_id.to_string(),
                    title: d.title,
                    username: d.username,
                    url: d.url,
                    row: d.row,
                })
                .collect(),
            skipped: rows(r.skipped),
            warnings: rows(r.warnings),
        }
    }
}

// ---------------------------------------------------------------------------------------
// sync / conflicts / devices
// ---------------------------------------------------------------------------------------

/// `status`: `ok` | `offline` | `conflict` | `rollback_detected` | `error`.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SyncReportFfi {
    pub status: String,
    pub pulled: u32,
    pub pushed: u32,
    pub conflicts: u32,
    pub rejected: Vec<String>,
    pub delete_skipped: Vec<String>,
    pub error_code: Option<String>,
    pub message: Option<String>,
}

impl From<aipass_sync::SyncReport> for SyncReportFfi {
    fn from(r: aipass_sync::SyncReport) -> Self {
        Self {
            status: enum_str(&r.status),
            pulled: r.pulled,
            pushed: r.pushed,
            conflicts: r.conflicts,
            rejected: r.rejected.iter().map(ToString::to_string).collect(),
            delete_skipped: r.delete_skipped.iter().map(ToString::to_string).collect(),
            error_code: r.error_code,
            message: r.message.as_ref().map(pick),
        }
    }
}

/// One version of a conflicted entry.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ConflictVersionFfi {
    pub version: u64,
    pub is_current: bool,
    pub author_device_id: String,
    pub author_name: Option<String>,
    pub created_at: i64,
    pub username: Option<String>,
    pub secret_differs: bool,
}

/// A conflicted entry; resolve on a trusted device with `resolve_conflict`.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ConflictInfoFfi {
    pub entry_id: String,
    pub title: String,
    pub current_version: u64,
    pub conflict_versions: Vec<u64>,
    pub versions: Vec<ConflictVersionFfi>,
}

impl From<aipass_sync::ConflictInfo> for ConflictInfoFfi {
    fn from(c: aipass_sync::ConflictInfo) -> Self {
        Self {
            entry_id: c.entry_id.to_string(),
            title: c.title,
            current_version: c.current_version,
            conflict_versions: c.conflict_versions,
            versions: c
                .versions
                .into_iter()
                .map(|v| ConflictVersionFfi {
                    version: v.version,
                    is_current: v.is_current,
                    author_device_id: v.author_device_id.to_string(),
                    author_name: v.author_name,
                    created_at: ts(&v.created_at),
                    username: v.username,
                    secret_differs: v.secret_differs,
                })
                .collect(),
        }
    }
}

/// Vault member device.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct DeviceFfi {
    pub device_id: String,
    pub name: String,
    pub platform: String,
    pub role: String,
    pub status: String,
    pub is_this_device: bool,
    pub is_recovery_key: bool,
    pub added_by: String,
    pub updated_at: i64,
    pub key_epoch: u32,
    /// Ed25519 public signing key (b64u; public).
    pub sign_pk: String,
    /// X25519 public KEM key (b64u; public).
    pub kem_pk: String,
}

impl From<aipass_sync::DeviceInfo> for DeviceFfi {
    fn from(d: aipass_sync::DeviceInfo) -> Self {
        Self {
            device_id: d.device_id.to_string(),
            name: d.name,
            platform: enum_str(&d.platform),
            role: enum_str(&d.role),
            status: enum_str(&d.status),
            is_this_device: d.is_this_device,
            is_recovery_key: d.is_recovery_key,
            added_by: d.added_by.to_string(),
            updated_at: ts(&d.updated_at),
            key_epoch: d.key_epoch,
            sign_pk: d.sign_pk,
            kem_pk: d.kem_pk,
        }
    }
}

/// Suggested credential rotation after a device revocation.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct RotationTaskFfi {
    pub entry_id: String,
    pub title: String,
    pub kind: String,
    pub reason: String,
}

impl From<aipass_sync::RotationTask> for RotationTaskFfi {
    fn from(t: aipass_sync::RotationTask) -> Self {
        Self {
            entry_id: t.entry_id.to_string(),
            title: t.title,
            kind: enum_str(&t.kind),
            reason: pick(&t.reason),
        }
    }
}

/// Device revocation result (key epoch rotated; old copies may still exist — see `note`).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct RevokeResultFfi {
    pub device_id: String,
    pub key_epoch: u32,
    pub rotation_tasks: Vec<RotationTaskFfi>,
    pub note: String,
}

impl From<aipass_sync::RevokeResult> for RevokeResultFfi {
    fn from(r: aipass_sync::RevokeResult) -> Self {
        Self {
            device_id: r.device_id.to_string(),
            key_epoch: r.key_epoch,
            rotation_tasks: r.rotation_tasks.into_iter().map(Into::into).collect(),
            note: pick(&r.note),
        }
    }
}

// ---------------------------------------------------------------------------------------
// autofill
// ---------------------------------------------------------------------------------------

/// `match_kind`: `exact_origin` | `same_site`.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct AutofillCandidate {
    pub entry_id: String,
    pub title: String,
    pub username: Option<String>,
    pub match_kind: String,
}

/// Credential for an AutoFill extension. Only call after native user presence.
#[derive(Clone, uniffi::Record)]
pub struct AutofillCredentialFfi {
    pub username: Option<String>,
    pub password: String,
    pub totp: Option<String>,
}

impl std::fmt::Debug for AutofillCredentialFfi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AutofillCredentialFfi([REDACTED])")
    }
}

/// Identity for `ASCredentialIdentityStore` / Android Autofill datasets (no secret).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct CredentialIdentity {
    pub entry_id: String,
    pub service_identifier: String,
    pub username: Option<String>,
}

/// Result of saving a credential captured by AutoFill. `status`: `saved` | `updated` |
/// `needs_confirmation`.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SaveResultFfi {
    pub status: String,
    pub entry_id: Option<String>,
}

// ---------------------------------------------------------------------------------------
// approvals (§6.1 / §7)
// ---------------------------------------------------------------------------------------

/// Budget limits (all four integers).
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Record)]
pub struct LimitsFfi {
    pub max_rows_per_operation: u64,
    pub max_rows_per_grant: u64,
    pub max_requests_per_grant: u64,
    pub max_result_bytes: u64,
}

impl From<Limits> for LimitsFfi {
    fn from(l: Limits) -> Self {
        Self {
            max_rows_per_operation: l.max_rows_per_operation,
            max_rows_per_grant: l.max_rows_per_grant,
            max_requests_per_grant: l.max_requests_per_grant,
            max_result_bytes: l.max_result_bytes,
        }
    }
}

impl From<LimitsFfi> for Limits {
    fn from(l: LimitsFfi) -> Self {
        Self {
            max_rows_per_operation: l.max_rows_per_operation,
            max_rows_per_grant: l.max_rows_per_grant,
            max_requests_per_grant: l.max_requests_per_grant,
            max_result_bytes: l.max_result_bytes,
        }
    }
}

/// Fields of one PostgreSQL view.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ViewFieldsFfi {
    pub view: String,
    pub fields: Vec<String>,
}

/// Resource scope. Empty connector lists mean "no scope for that connector".
#[derive(Debug, Clone, PartialEq, Eq, Default, uniffi::Record)]
pub struct GrantScopeFfi {
    pub operations: Vec<String>,
    pub postgres_views: Vec<ViewFieldsFfi>,
    pub github_repos: Vec<String>,
    pub http_operations: Vec<String>,
}

impl From<GrantScope> for GrantScopeFfi {
    fn from(s: GrantScope) -> Self {
        Self {
            operations: s.operations,
            postgres_views: s
                .postgres
                .map(|p| {
                    p.views
                        .into_iter()
                        .map(|(view, fields)| ViewFieldsFfi { view, fields })
                        .collect()
                })
                .unwrap_or_default(),
            github_repos: s.github.map(|g| g.repos).unwrap_or_default(),
            http_operations: s.http_api.map(|h| h.operations).unwrap_or_default(),
        }
    }
}

impl From<GrantScopeFfi> for GrantScope {
    fn from(s: GrantScopeFfi) -> Self {
        GrantScope {
            operations: s.operations,
            postgres: if s.postgres_views.is_empty() {
                None
            } else {
                Some(PostgresScope {
                    views: s
                        .postgres_views
                        .into_iter()
                        .map(|v| (v.view, v.fields))
                        .collect::<BTreeMap<_, _>>(),
                })
            },
            github: if s.github_repos.is_empty() {
                None
            } else {
                Some(GithubScope {
                    repos: s.github_repos,
                })
            },
            http_api: if s.http_operations.is_empty() {
                None
            } else {
                Some(HttpApiScope {
                    operations: s.http_operations,
                })
            },
        }
    }
}

/// Requested or approved access (`mode`: `once` | `task` | `policy` …, per §6.1).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct AccessSpecFfi {
    pub operations: Vec<String>,
    pub scope: GrantScopeFfi,
    pub limits: LimitsFfi,
    pub duration_seconds: u64,
    pub mode: String,
}

impl From<AccessSpec> for AccessSpecFfi {
    fn from(a: AccessSpec) -> Self {
        Self {
            operations: a.operations,
            scope: a.scope.into(),
            limits: a.limits.into(),
            duration_seconds: a.duration_seconds,
            mode: enum_str(&a.mode),
        }
    }
}

/// The narrowed scope the user approves (must be a subset of the request). Same shape as
/// [`AccessSpecFfi`].
pub type ApprovedScopeFfi = AccessSpecFfi;

impl AccessSpecFfi {
    pub(crate) fn to_spec(&self) -> CoreResult<AccessSpec> {
        Ok(AccessSpec {
            operations: self.operations.clone(),
            scope: self.scope.clone().into(),
            limits: self.limits.into(),
            duration_seconds: self.duration_seconds,
            mode: parse_enum(&self.mode, "mode")?,
        })
    }
}

/// Fields excluded from one view ("不含客户邮箱").
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ExcludedFieldsFfi {
    pub view: String,
    pub fields: Vec<String>,
}

/// Connection that receives results.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct RecipientFfi {
    pub connection_id: String,
    pub display_name: String,
}

/// An approval request, decrypted from this device's relay mailbox. Show every field the
/// digest covers; `approve` recomputes the digest from exactly these values.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ApprovalRequestFfi {
    pub approval_request_id: String,
    /// `operation` | `access`.
    pub kind: String,
    pub connection_id: String,
    /// Self-declared by the AI tool unless `connection_verified`.
    pub connection_name: String,
    pub connection_verified: bool,
    pub host_type: String,
    pub resource_id: String,
    pub resource_alias: String,
    pub service: String,
    pub environment: String,
    pub summary: String,
    pub requested: AccessSpecFfi,
    pub excluded_fields: Vec<ExcludedFieldsFfi>,
    pub executor_id: String,
    pub executor_name: String,
    pub protection_level: String,
    pub recipients: Vec<RecipientFfi>,
    pub status: String,
    pub created_at: i64,
    pub expires_at: i64,
    pub operation_id: Option<String>,
    /// Broker / executor that sent the request (decision goes back to it).
    pub sender_executor_id: String,
    /// Whether a vault entry is bound to this resource (needed to deliver a credential).
    pub credential_bound: bool,
    /// `parameters_digest` of the waiting operation (`kind:"operation"`), part of the
    /// signed §7 v2 digest.
    pub parameters_digest: Option<String>,
    /// Display-level digest of exactly this request (`aipass_types::approval::request_digest`).
    /// Keep the value of the request **shown on screen** and pass it to `approve`,
    /// `approve_with_entry` or `deny`; they refuse with `INTEGRITY_FAILED` when the stored
    /// request no longer hashes to it.
    pub request_digest: String,
    /// A second copy of this request id with *different* content arrived over the relay.
    /// The first copy is kept (and is what is shown and signed), but approving is refused
    /// (`INTEGRITY_FAILED`) — show a warning; denying stays possible.
    pub conflict: bool,
}

impl ApprovalRequestFfi {
    pub(crate) fn from_request(
        r: &ApprovalRequest,
        sender: &str,
        bound: bool,
        request_digest: String,
        conflict: bool,
    ) -> Self {
        Self {
            approval_request_id: r.approval_request_id.to_string(),
            kind: enum_str(&r.kind),
            connection_id: r.connection.connection_id.to_string(),
            connection_name: r.connection.display_name.clone(),
            connection_verified: r.connection.verified,
            host_type: enum_str(&r.connection.host_type),
            resource_id: r.resource.resource_id.to_string(),
            resource_alias: r.resource.alias.clone(),
            service: r.resource.service.clone(),
            environment: enum_str(&r.resource.environment),
            summary: pick(&r.summary),
            requested: r.requested.clone().into(),
            excluded_fields: r
                .excluded_fields
                .iter()
                .map(|(view, fields)| ExcludedFieldsFfi {
                    view: view.clone(),
                    fields: fields.clone(),
                })
                .collect(),
            executor_id: r.executor.executor_id.to_string(),
            executor_name: r.executor.name.clone(),
            protection_level: enum_str(&r.executor.protection_level),
            recipients: r
                .recipients
                .iter()
                .map(|x| RecipientFfi {
                    connection_id: x.connection_id.to_string(),
                    display_name: x.display_name.clone(),
                })
                .collect(),
            status: enum_str(&r.status),
            created_at: ts(&r.created_at),
            expires_at: ts(&r.expires_at),
            operation_id: r.operation_id.as_ref().map(ToString::to_string),
            sender_executor_id: sender.to_owned(),
            credential_bound: bound,
            parameters_digest: r.parameters_digest.clone(),
            request_digest,
            conflict,
        }
    }
}

/// Result of `approve` / `deny`.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct DecisionResultFfi {
    pub approval_request_id: String,
    /// `approve` | `deny`.
    pub decision: String,
    pub digest: String,
    pub expires_at: i64,
    pub credential_sealed: bool,
    /// Relay message id of the posted `approval.decision`.
    pub message_id: String,
}

/// AI connection waiting for confirmation (`connection.pair_request`).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ConnectionRequestFfi {
    pub connection_id: String,
    pub display_name: String,
    pub host_type: String,
    pub transport: String,
    /// Short code also shown by the AI tool / CLI; the user compares both.
    pub pairing_code: String,
    pub created_at: i64,
    pub sender_executor_id: String,
}

/// Connection in a broker snapshot.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ConnectionFfi {
    pub connection_id: String,
    pub display_name: String,
    pub host_type: String,
    pub status: String,
    /// `["*"]` = all projects.
    pub allowed_projects: Vec<String>,
    pub created_at: i64,
    pub last_seen_at: Option<i64>,
}

/// Grant in a broker snapshot.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct GrantFfi {
    pub grant_id: String,
    pub connection_id: String,
    pub resource_id: String,
    pub executor_id: String,
    pub scope: GrantScopeFfi,
    pub limits: LimitsFfi,
    pub mode: String,
    pub status: String,
    pub requests_used: u64,
    pub rows_used: u64,
    pub bytes_used: u64,
    pub created_at: i64,
    pub expires_at: i64,
    pub revoked_at: Option<i64>,
}

/// Executor in a broker snapshot.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ExecutorFfi {
    pub executor_id: String,
    pub name: String,
    pub protection_level: String,
    pub online: bool,
    pub last_heartbeat_at: Option<i64>,
}

/// Recent operation in a broker snapshot.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct OperationFfi {
    pub operation_id: String,
    pub connection_id: String,
    pub resource_id: String,
    pub operation: String,
    pub status: String,
    pub created_at: i64,
    pub updated_at: i64,
}

/// `state.snapshot` from the broker. `activity_summary_json` is the §6.3
/// `ActivitySummary` object as JSON text.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SnapshotFfi {
    pub executor_id: String,
    pub received_at: i64,
    pub connections: Vec<ConnectionFfi>,
    pub grants: Vec<GrantFfi>,
    pub executors: Vec<ExecutorFfi>,
    pub pending_approvals: Vec<ApprovalRequestFfi>,
    pub recent_operations: Vec<OperationFfi>,
    pub activity_summary_json: String,
}

impl SnapshotFfi {
    pub(crate) fn from_snapshot(
        s: &aipass_types::relay::StateSnapshot,
        sender: &str,
        received_at: i64,
    ) -> Self {
        Self {
            executor_id: sender.to_owned(),
            received_at,
            connections: s
                .connections
                .iter()
                .map(|c| ConnectionFfi {
                    connection_id: c.connection_id.to_string(),
                    display_name: c.display_name.clone(),
                    host_type: enum_str(&c.host_type),
                    status: enum_str(&c.status),
                    allowed_projects: allowed_projects_strings(&c.allowed_projects),
                    created_at: ts(&c.created_at),
                    last_seen_at: c.last_seen_at.as_ref().map(ts),
                })
                .collect(),
            grants: s
                .grants
                .iter()
                .map(|g| GrantFfi {
                    grant_id: g.grant_id.to_string(),
                    connection_id: g.connection_id.to_string(),
                    resource_id: g.resource_id.to_string(),
                    executor_id: g.executor_id.to_string(),
                    scope: g.scope.clone().into(),
                    limits: g.limits.into(),
                    mode: enum_str(&g.mode),
                    status: enum_str(&g.status),
                    requests_used: g.usage.requests,
                    rows_used: g.usage.rows,
                    bytes_used: g.usage.bytes,
                    created_at: ts(&g.created_at),
                    expires_at: ts(&g.expires_at),
                    revoked_at: g.revoked_at.as_ref().map(ts),
                })
                .collect(),
            executors: s
                .executors
                .iter()
                .map(|e| ExecutorFfi {
                    executor_id: e.executor_id.to_string(),
                    name: e.name.clone(),
                    protection_level: enum_str(&e.protection_level),
                    online: e.online,
                    last_heartbeat_at: e.last_heartbeat_at.as_ref().map(ts),
                })
                .collect(),
            pending_approvals: s
                .pending_approvals
                .iter()
                // `request_digest` of the snapshot copy: approving with it only works when
                // the stored (first) copy is identical; conflicts are reported by
                // `pending_approvals()`.
                .filter_map(|r| {
                    let d = aipass_types::approval::request_digest(r).ok()?;
                    Some(ApprovalRequestFfi::from_request(r, sender, false, d, false))
                })
                .collect(),
            recent_operations: s
                .recent_operations
                .iter()
                .map(|o| OperationFfi {
                    operation_id: o.operation_id.to_string(),
                    connection_id: o.connection_id.to_string(),
                    resource_id: o.resource_id.to_string(),
                    operation: o.operation.clone(),
                    status: o.status.as_str().to_owned(),
                    created_at: ts(&o.created_at),
                    updated_at: ts(&o.updated_at),
                })
                .collect(),
            activity_summary_json: serde_json::to_string(&s.activity_summary)
                .unwrap_or_else(|_| "{}".to_owned()),
        }
    }
}

pub(crate) fn allowed_projects_strings(a: &aipass_types::models::AllowedProjects) -> Vec<String> {
    match a {
        aipass_types::models::AllowedProjects::All => vec!["*".to_owned()],
        aipass_types::models::AllowedProjects::Only(set) => {
            set.iter().map(ToString::to_string).collect()
        }
    }
}

/// One revocation level (`status`: `done` | `not_applicable` | `pending` | `failed`).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct LevelReportFfi {
    pub status: String,
    pub detail: Option<String>,
}

/// Revocation report (§8.4). `confirmed = false` means the broker has not answered yet;
/// the UI must then say "已发送，等待执行设备确认" and never "已撤销".
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct RevocationReportFfi {
    pub grant_id: String,
    pub confirmed: bool,
    pub stop_access: LevelReportFfi,
    pub end_sessions: LevelReportFfi,
    pub revoke_upstream: LevelReportFfi,
    pub fully_revoked: bool,
    pub summary: String,
    pub completed_at: Option<i64>,
}

impl RevocationReportFfi {
    pub(crate) fn from_report(r: &RevocationReport) -> Self {
        let l = |x: &aipass_types::models::LevelReport| LevelReportFfi {
            status: enum_str(&x.status),
            detail: x.detail.clone(),
        };
        Self {
            grant_id: r.grant_id.to_string(),
            confirmed: true,
            stop_access: l(&r.stop_access),
            end_sessions: l(&r.end_sessions),
            revoke_upstream: l(&r.revoke_upstream),
            fully_revoked: r.fully_revoked(),
            summary: pick(&r.summary_label()),
            completed_at: r.completed_at.as_ref().map(ts),
        }
    }

    pub(crate) fn unconfirmed(grant_id: &str) -> Self {
        let pending = || LevelReportFfi {
            status: "pending".to_owned(),
            detail: None,
        };
        Self {
            grant_id: grant_id.to_owned(),
            confirmed: false,
            stop_access: pending(),
            end_sessions: pending(),
            revoke_upstream: pending(),
            fully_revoked: false,
            summary: pick(&aipass_types::Localized::new(
                "撤销指令已发送，等待执行设备确认",
                "Revocation sent; waiting for the executor to confirm",
            )),
            completed_at: None,
        }
    }
}

// ---------------------------------------------------------------------------------------
// license (§13)
// ---------------------------------------------------------------------------------------

/// Offline license check. An invalid license only disables premium features; unlock,
/// export, recovery and revocation never depend on it.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct LicenseStatusFfi {
    pub valid: bool,
    pub plan_id: Option<String>,
    pub features: Vec<String>,
    pub expires_at: Option<i64>,
    pub grace_until: Option<i64>,
    pub in_grace_period: bool,
    /// `bad_format` | `bad_signature` | `expired` | `wrong_device` | `unsupported_version`.
    pub reason: Option<String>,
    /// True when checked against the built-in development key (not a production build).
    pub dev_key: bool,
}

/// Pairing session progress (`stage`: `waiting_for_peer` | `confirm_code` | `completed` |
/// `cancelled`).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct PairingProgressFfi {
    pub stage: String,
    pub sas: Option<String>,
    pub peer_name: Option<String>,
    pub peer_role: Option<String>,
    /// Device enrolled (trusted side) or this device (new side) after completion.
    pub device: Option<DeviceFfi>,
}
