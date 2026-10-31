// SPDX-License-Identifier: Apache-2.0
//! Vault storage objects (CONTRACTS §2.3) — the on-storage JSON format shared by the vault
//! core, sync engine, sync server, CLI and FFI.
//!
//! Signed objects ([`VaultHeader`], [`MemberRecord`], [`Manifest`]) are signed over
//! `JCS(object minus "signature")` with Ed25519 ([`SignedObject`]). The cryptography that
//! produces `wrapped_vmk`, `wrapped_dek` and `ciphertext` lives in `aipass-vault`; the AAD
//! strings it must use are defined once in [`aad`], storage keys in [`keys`].

use core::fmt;
use std::collections::BTreeMap;

use aipass_crypto::{Ed25519Signer, SealedBox, SecretString, b64u};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::Zeroize;

use crate::SignatureError;
use crate::canonical::{CanonicalError, jcs_without_field};
use crate::ids::{DeviceId, EntryId, ProjectId, VaultId};
use crate::time::{Timestamp, rfc3339};

/// Current object format version.
pub const FORMAT_V1: u32 = 1;

// ======================================================================================
// Enums
// ======================================================================================

/// Device platform.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Platform {
    /// iPhone / iPad.
    Ios,
    /// Android.
    Android,
    /// macOS desktop.
    Macos,
    /// Windows desktop.
    Windows,
    /// Linux desktop.
    Linux,
    /// Reference CLI.
    Cli,
    /// Self-host node / executor.
    Node,
}

/// Vault member role.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemberRole {
    /// Full control incl. revocation and GC.
    Owner,
    /// Trusted device (can approve, author manifests).
    Member,
    /// Executor — never receives the VMK, never authors manifests, read-only on sync.
    Executor,
}

impl MemberRole {
    /// Owners and members may author manifests and approve.
    pub fn is_trusted_approver(&self) -> bool {
        matches!(self, Self::Owner | Self::Member)
    }
}

/// Member status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemberStatus {
    /// Active.
    Active,
    /// Revoked.
    Revoked,
}

/// Recovery wrap kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryKind {
    /// 32-byte recovery secret (`AIPR-…` key) → HKDF KEK.
    RecoveryKey,
    /// Optional master password → Argon2id KEK.
    MasterPassword,
}

impl RecoveryKind {
    /// Wire name.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::RecoveryKey => "recovery_key",
            Self::MasterPassword => "master_password",
        }
    }
}

/// KDF descriptor of a [`RecoveryWrap`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "alg")]
pub enum KdfSpec {
    /// `KEK = HKDF(ikm=secret, salt=vault_id bytes, info="aipass/v1/recovery-kek")`.
    #[serde(rename = "hkdf-sha256")]
    HkdfSha256,
    /// Argon2id with explicit parameters.
    #[serde(rename = "argon2id")]
    Argon2id {
        /// Memory KiB.
        m: u32,
        /// Iterations.
        t: u32,
        /// Lanes.
        p: u32,
        /// Salt (b64u, 16 bytes).
        #[serde(with = "aipass_crypto::b64u::bytes")]
        salt: Vec<u8>,
    },
}

// ======================================================================================
// Signed objects
// ======================================================================================

/// Objects signed over `JCS(self minus "signature")`.
pub trait SignedObject: Serialize {
    /// The b64u signature field.
    fn signature(&self) -> &str;
    /// Mutable access to the signature field.
    fn signature_mut(&mut self) -> &mut String;

    /// Bytes covered by the signature.
    fn signing_bytes(&self) -> Result<Vec<u8>, CanonicalError> {
        jcs_without_field(self, "signature")
    }

    /// Sign in place.
    fn sign_with(&mut self, signer: &dyn Ed25519Signer) -> Result<(), CanonicalError>
    where
        Self: Sized,
    {
        let bytes = self.signing_bytes()?;
        *self.signature_mut() = b64u::encode(signer.sign(&bytes));
        Ok(())
    }

    /// Verify against an Ed25519 public key.
    fn verify_signature(&self, sign_pk: &[u8; 32]) -> Result<(), SignatureError> {
        let bytes = self.signing_bytes()?;
        let sig =
            b64u::decode_array::<64>(self.signature()).map_err(|_| SignatureError::Malformed)?;
        aipass_crypto::identity::verify(sign_pk, &bytes, &sig).map_err(|_| SignatureError::Invalid)
    }
}

macro_rules! impl_signed {
    ($t:ty) => {
        impl SignedObject for $t {
            fn signature(&self) -> &str {
                &self.signature
            }
            fn signature_mut(&mut self) -> &mut String {
                &mut self.signature
            }
        }
    };
}

/// `vault.json` — immutable, signed by the genesis device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultHeader {
    /// Always 1.
    pub format: u32,
    /// Vault.
    pub vault_id: VaultId,
    /// Created.
    #[serde(with = "rfc3339")]
    pub created_at: Timestamp,
    /// Genesis device (its MemberRecord rev 1 is self-signed).
    pub genesis_device_id: DeviceId,
    /// b64u Ed25519 signature.
    pub signature: String,
}
impl_signed!(VaultHeader);

/// `members/<device_id>/<rev>.json` — immutable; a new rev per change. Signed by `added_by`
/// (an active owner/member); the genesis record is self-signed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberRecord {
    /// Always 1.
    pub format: u32,
    /// Vault.
    pub vault_id: VaultId,
    /// Device.
    pub device_id: DeviceId,
    /// Revision (1-based).
    pub rev: u64,
    /// Device name.
    pub name: String,
    /// Platform.
    pub platform: Platform,
    /// Role.
    pub role: MemberRole,
    /// Ed25519 public key.
    #[serde(with = "aipass_crypto::b64u::array")]
    pub sign_pk: [u8; 32],
    /// X25519 KEM public key.
    #[serde(with = "aipass_crypto::b64u::array")]
    pub kem_pk: [u8; 32],
    /// Status.
    pub status: MemberStatus,
    /// Key epoch the wrap belongs to.
    pub key_epoch: u32,
    /// VMK sealed to this device (`null` for executors and revoked devices).
    pub wrapped_vmk: Option<SealedBox>,
    /// Signer.
    pub added_by: DeviceId,
    /// Created.
    #[serde(with = "rfc3339")]
    pub created_at: Timestamp,
    /// b64u Ed25519 signature.
    pub signature: String,
}
impl_signed!(MemberRecord);

impl MemberRecord {
    /// Public device description.
    pub fn device_public(&self) -> DevicePublic {
        DevicePublic {
            device_id: self.device_id.clone(),
            name: self.name.clone(),
            platform: self.platform,
            role: self.role,
            sign_pk: self.sign_pk,
            kem_pk: self.kem_pk,
        }
    }
}

/// Manifest entry descriptor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestEntry {
    /// Current version.
    pub version: u64,
    /// b64u SHA-256 of the entry version object file bytes.
    pub hash: String,
    /// Conflicting versions awaiting resolution (non-empty → automatic use paused).
    #[serde(default)]
    pub conflict_versions: Vec<u64>,
}

/// Tombstone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tombstone {
    /// Deleted version; writes with `version ≤` this are rejected.
    pub version: u64,
    /// When.
    #[serde(with = "rfc3339")]
    pub deleted_at: Timestamp,
}

/// Manifest member descriptor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestMember {
    /// Current member record rev.
    pub rev: u64,
    /// b64u SHA-256 of the member record file bytes.
    pub hash: String,
    /// Status.
    pub status: MemberStatus,
    /// Role.
    pub role: MemberRole,
}

/// `manifests/<seq:012>.json` — create-only write = commit point.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    /// Always 1.
    pub format: u32,
    /// Vault.
    pub vault_id: VaultId,
    /// Sequence (1-based).
    pub seq: u64,
    /// b64u SHA-256 of the previous manifest file bytes (`""` for seq 1).
    pub prev_hash: String,
    /// Current key epoch.
    pub key_epoch: u32,
    /// Live entries.
    pub entries: BTreeMap<EntryId, ManifestEntry>,
    /// Deleted entries.
    pub tombstones: BTreeMap<EntryId, Tombstone>,
    /// Members.
    pub members: BTreeMap<DeviceId, ManifestMember>,
    /// Author — an active owner/member in the previous manifest (seq 1: genesis).
    pub author_device_id: DeviceId,
    /// Created.
    #[serde(with = "rfc3339")]
    pub created_at: Timestamp,
    /// b64u Ed25519 signature.
    pub signature: String,
}
impl_signed!(Manifest);

impl Manifest {
    /// Whether `entry` has unresolved conflicts (automatic use must be refused: `SYNC_CONFLICT`).
    pub fn has_conflict(&self, entry: &EntryId) -> bool {
        self.entries
            .get(entry)
            .is_some_and(|e| !e.conflict_versions.is_empty())
    }

    /// Active owner/member devices of this manifest.
    pub fn active_approvers(&self) -> impl Iterator<Item = &DeviceId> {
        self.members
            .iter()
            .filter(|(_, m)| m.status == MemberStatus::Active && m.role.is_trusted_approver())
            .map(|(id, _)| id)
    }
}

/// `recovery/<key_epoch>-<kind>.json`. `aad = aipass:v1:recovery:{vault_id}:{key_epoch}:{kind}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryWrap {
    /// Always 1.
    pub format: u32,
    /// Vault.
    pub vault_id: VaultId,
    /// Key epoch of the wrapped VMK.
    pub key_epoch: u32,
    /// Kind.
    pub kind: RecoveryKind,
    /// KDF that produced the KEK.
    pub kdf: KdfSpec,
    /// XChaCha20 nonce.
    #[serde(with = "aipass_crypto::b64u::array")]
    pub nonce: [u8; 24],
    /// VMK wrapped under the KEK.
    #[serde(with = "aipass_crypto::b64u::bytes")]
    pub wrapped_vmk: Vec<u8>,
}

/// One previous-epoch VMK inside a [`KeyringRecord`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyringItem {
    /// The older epoch.
    pub key_epoch: u32,
    /// XChaCha20 nonce.
    #[serde(with = "aipass_crypto::b64u::array")]
    pub nonce: [u8; 24],
    /// VMK[key_epoch] wrapped under the record's (newer) VMK.
    #[serde(with = "aipass_crypto::b64u::bytes")]
    pub wrapped_vmk: Vec<u8>,
}

/// `keyring/<key_epoch>.json` — previous epochs' VMKs encrypted under VMK[key_epoch],
/// `aad = aipass:v1:keyring:{vault_id}:{key_epoch}`. (Shape defined here; CONTRACTS §2.3
/// specifies only key, content and AAD.)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyringRecord {
    /// Always 1.
    pub format: u32,
    /// Vault.
    pub vault_id: VaultId,
    /// Epoch whose VMK encrypts the items.
    pub key_epoch: u32,
    /// Older VMKs.
    pub previous: Vec<KeyringItem>,
    /// Author.
    pub author_device_id: DeviceId,
    /// Created.
    #[serde(with = "rfc3339")]
    pub created_at: Timestamp,
}

/// `entries/<entry_id>/<version>.json` — immutable encrypted entry version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntryVersion {
    /// Always 1.
    pub format: u32,
    /// Vault.
    pub vault_id: VaultId,
    /// Entry.
    pub entry_id: EntryId,
    /// Version (1-based).
    pub version: u64,
    /// VMK epoch used to wrap the DEK.
    pub key_epoch: u32,
    /// Nonce of `wrapped_dek`.
    #[serde(with = "aipass_crypto::b64u::array")]
    pub dek_nonce: [u8; 24],
    /// DEK wrapped under VMK[key_epoch] (`aad::dek`).
    #[serde(with = "aipass_crypto::b64u::bytes")]
    pub wrapped_dek: Vec<u8>,
    /// Nonce of `ciphertext`.
    #[serde(with = "aipass_crypto::b64u::array")]
    pub nonce: [u8; 24],
    /// JCS(EntryPayload) encrypted under the DEK (`aad::entry`).
    #[serde(with = "aipass_crypto::b64u::bytes")]
    pub ciphertext: Vec<u8>,
    /// Author device.
    pub author_device_id: DeviceId,
    /// Created.
    #[serde(with = "rfc3339")]
    pub created_at: Timestamp,
}

/// Public description of a device (pairing, approver sets, relay).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DevicePublic {
    /// Device.
    pub device_id: DeviceId,
    /// Name.
    pub name: String,
    /// Platform.
    pub platform: Platform,
    /// Role.
    pub role: MemberRole,
    /// Ed25519 public key.
    #[serde(with = "aipass_crypto::b64u::array")]
    pub sign_pk: [u8; 32],
    /// X25519 KEM public key.
    #[serde(with = "aipass_crypto::b64u::array")]
    pub kem_pk: [u8; 32],
}

/// A device's checkpoint of the newest verified manifest.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Checkpoint {
    /// Vault.
    pub vault_id: VaultId,
    /// Manifest sequence.
    pub seq: u64,
    /// b64u SHA-256 of that manifest's file bytes.
    pub hash: String,
}

/// b64u SHA-256 of an object's file bytes (manifest `hash` / `prev_hash`).
pub fn object_hash(bytes: &[u8]) -> String {
    aipass_crypto::sha256_b64u(bytes)
}

// ======================================================================================
// Entry payload (plaintext only inside ciphertext)
// ======================================================================================

/// Entry kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryKind {
    /// Website login.
    Login,
    /// API key.
    ApiKey,
    /// Database credential.
    Database,
    /// OAuth token.
    OauthToken,
    /// SSH key.
    SshKey,
    /// Secure note.
    SecureNote,
    /// Storage backend credential (never automatically an AI resource, §10.2).
    StorageCredential,
}

/// Entry lifecycle (UI: 已导入 · 已验证 · 需要处理 · 待注册 · 已停用).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Lifecycle {
    /// Imported, not verified.
    #[default]
    Imported,
    /// Verified working.
    Verified,
    /// Needs attention.
    NeedsAttention,
    /// Pending registration (experimental accounts.create).
    PendingRegistration,
    /// Retired.
    Retired,
}

/// Where an entry came from: `manual`, `generated` or `import:<format>`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub enum EntrySource {
    /// Typed by the user.
    #[default]
    Manual,
    /// Created with the password generator.
    Generated,
    /// Imported from a CSV format (`chrome`, `firefox`, …).
    Import(String),
}

impl EntrySource {
    /// Wire string.
    pub fn as_string(&self) -> String {
        match self {
            Self::Manual => "manual".into(),
            Self::Generated => "generated".into(),
            Self::Import(f) => format!("import:{f}"),
        }
    }
}

impl Serialize for EntrySource {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.as_string())
    }
}

impl<'de> Deserialize<'de> for EntrySource {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        match s.as_str() {
            "manual" => Ok(Self::Manual),
            "generated" => Ok(Self::Generated),
            other => match other.strip_prefix("import:") {
                Some(f)
                    if !f.is_empty()
                        && f.bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-') =>
                {
                    Ok(Self::Import(f.to_owned()))
                }
                _ => Err(serde::de::Error::custom("invalid entry source")),
            },
        }
    }
}

/// TOTP hash algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub enum TotpAlgorithm {
    /// HMAC-SHA1 (default).
    #[default]
    #[serde(rename = "SHA1")]
    Sha1,
    /// HMAC-SHA256.
    #[serde(rename = "SHA256")]
    Sha256,
    /// HMAC-SHA512.
    #[serde(rename = "SHA512")]
    Sha512,
}

/// TOTP configuration (secret-bearing).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TotpConfig {
    /// Base32 seed.
    pub secret: SecretString,
    /// Algorithm.
    #[serde(default)]
    pub algorithm: TotpAlgorithm,
    /// 6 or 8.
    #[serde(default = "default_digits")]
    pub digits: u32,
    /// Period seconds.
    #[serde(default = "default_period")]
    pub period: u32,
}

fn default_digits() -> u32 {
    6
}
fn default_period() -> u32 {
    30
}

impl fmt::Debug for TotpConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TotpConfig")
            .field("secret", &"[REDACTED]")
            .field("algorithm", &self.algorithm)
            .field("digits", &self.digits)
            .field("period", &self.period)
            .finish()
    }
}

/// Custom field. Values are always held in a zeroizing [`SecretString`]; `sensitive`
/// marks them secret-bearing (masked in UI, never auto-shown).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustomField {
    /// Name.
    pub name: String,
    /// Value.
    pub value: SecretString,
    /// Secret-bearing.
    #[serde(default = "default_true")]
    pub sensitive: bool,
}

fn default_true() -> bool {
    true
}

impl fmt::Debug for CustomField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CustomField")
            .field("name", &"[REDACTED]")
            .field("value", &"[REDACTED]")
            .field("sensitive", &self.sensitive)
            .finish()
    }
}

/// Database connection info (no password; that is `secret`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DatabaseInfo {
    /// Engine (`postgres`).
    pub engine: String,
    /// Host.
    pub host: String,
    /// Port.
    pub port: u16,
    /// Database name.
    pub dbname: String,
    /// `disable` | `prefer` | `require` | `verify-full`.
    pub sslmode: String,
}

/// Password generator rules (CONTRACTS §2.6). The generator itself lives in `aipass-vault`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasswordRules {
    /// 8..=128, default 20.
    #[serde(default = "default_len")]
    pub length: u32,
    /// Lower-case letters.
    #[serde(default = "default_true")]
    pub lower: bool,
    /// Upper-case letters.
    #[serde(default = "default_true")]
    pub upper: bool,
    /// Digits.
    #[serde(default = "default_true")]
    pub digits: bool,
    /// Symbols.
    #[serde(default = "default_true")]
    pub symbols: bool,
    /// Symbol alphabet.
    #[serde(default = "default_symbols")]
    pub symbol_set: String,
    /// Exclude `Il1O0o`.
    #[serde(default)]
    pub exclude_ambiguous: bool,
    /// At least one character of every enabled class.
    #[serde(default = "default_true")]
    pub require_each_class: bool,
}

fn default_len() -> u32 {
    20
}
fn default_symbols() -> String {
    PasswordRules::DEFAULT_SYMBOLS.to_owned()
}

impl PasswordRules {
    /// Default symbol set.
    pub const DEFAULT_SYMBOLS: &'static str = "!@#$%^&*()-_=+[]{};:,.?";
    /// Ambiguous characters removed by `exclude_ambiguous`.
    pub const AMBIGUOUS: &'static str = "Il1O0o";
    /// Minimum length.
    pub const MIN_LEN: u32 = 8;
    /// Maximum length.
    pub const MAX_LEN: u32 = 128;

    /// Validate ranges and that at least one class is enabled.
    pub fn validate(&self) -> Result<(), &'static str> {
        if !(Self::MIN_LEN..=Self::MAX_LEN).contains(&self.length) {
            return Err("length must be between 8 and 128");
        }
        let sym = self.symbols && !self.symbol_set.is_empty();
        if !(self.lower || self.upper || self.digits || sym) {
            return Err("at least one character class must be enabled");
        }
        if self.symbols && !self.symbol_set.is_ascii() {
            return Err("symbol_set must be ASCII");
        }
        Ok(())
    }
}

impl Default for PasswordRules {
    fn default() -> Self {
        Self {
            length: 20,
            lower: true,
            upper: true,
            digits: true,
            symbols: true,
            symbol_set: Self::DEFAULT_SYMBOLS.to_owned(),
            exclude_ambiguous: false,
            require_each_class: true,
        }
    }
}

/// Decrypted entry content. Exists in plaintext only inside trusted components; titles,
/// usernames, URLs and notes are encrypted by default (§10.3).
///
/// `Debug` prints only kind and lifecycle. Secret-bearing fields (`secret`, `totp`,
/// `fields[sensitive]`) are zeroizing types; [`Zeroize`] clears the rest on demand.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntryPayload {
    /// Kind.
    pub kind: EntryKind,
    /// Title.
    #[serde(default)]
    pub title: String,
    /// Username / login.
    #[serde(default)]
    pub username: Option<String>,
    /// Password / key / token (secret-bearing).
    #[serde(default)]
    pub secret: Option<SecretString>,
    /// URLs (first is primary).
    #[serde(default)]
    pub urls: Vec<String>,
    /// Notes.
    #[serde(default)]
    pub notes: Option<String>,
    /// TOTP (secret-bearing).
    #[serde(default)]
    pub totp: Option<TotpConfig>,
    /// Custom fields.
    #[serde(default)]
    pub fields: Vec<CustomField>,
    /// Database connection info.
    #[serde(default)]
    pub database: Option<DatabaseInfo>,
    /// Project.
    #[serde(default)]
    pub project_id: Option<ProjectId>,
    /// Tags.
    #[serde(default)]
    pub tags: Vec<String>,
    /// Lifecycle.
    #[serde(default)]
    pub lifecycle: Lifecycle,
    /// Source.
    #[serde(default)]
    pub source: EntrySource,
    /// Site password rules.
    #[serde(default)]
    pub password_rules: Option<PasswordRules>,
    /// Created.
    #[serde(with = "rfc3339")]
    pub created_at: Timestamp,
    /// Updated.
    #[serde(with = "rfc3339")]
    pub updated_at: Timestamp,
}

impl EntryPayload {
    /// A new empty payload of `kind` created now.
    pub fn new(kind: EntryKind, title: impl Into<String>) -> Self {
        let now = crate::time::now();
        Self {
            kind,
            title: title.into(),
            username: None,
            secret: None,
            urls: Vec::new(),
            notes: None,
            totp: None,
            fields: Vec::new(),
            database: None,
            project_id: None,
            tags: Vec::new(),
            lifecycle: Lifecycle::Imported,
            source: EntrySource::Manual,
            password_rules: None,
            created_at: now,
            updated_at: now,
        }
    }

    /// Canonical plaintext bytes to encrypt (`JCS(EntryPayload)`).
    pub fn to_plaintext(&self) -> Result<zeroize::Zeroizing<Vec<u8>>, CanonicalError> {
        crate::canonical::to_jcs_bytes(self).map(zeroize::Zeroizing::new)
    }

    /// Parse decrypted plaintext.
    pub fn from_plaintext(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(bytes)
    }

    /// Whether the entry carries any secret-bearing value.
    pub fn has_secret_material(&self) -> bool {
        self.secret.is_some() || self.totp.is_some() || self.fields.iter().any(|f| f.sensitive)
    }
}

impl fmt::Debug for EntryPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EntryPayload")
            .field("kind", &self.kind)
            .field("lifecycle", &self.lifecycle)
            .field("content", &"[REDACTED]")
            .finish()
    }
}

impl Zeroize for EntryPayload {
    fn zeroize(&mut self) {
        self.title.zeroize();
        if let Some(u) = self.username.as_mut() {
            u.zeroize();
        }
        self.secret.zeroize();
        for u in &mut self.urls {
            u.zeroize();
        }
        if let Some(n) = self.notes.as_mut() {
            n.zeroize();
        }
        if let Some(t) = self.totp.as_mut() {
            t.secret.zeroize();
        }
        for fld in &mut self.fields {
            fld.name.zeroize();
            fld.value.zeroize();
        }
        for t in &mut self.tags {
            t.zeroize();
        }
    }
}

// ======================================================================================
// Storage keys and AAD strings
// ======================================================================================

/// Object keys relative to the vault root (CONTRACTS §2.3).
pub mod keys {
    use super::RecoveryKind;
    use crate::ids::{DeviceId, EntryId};

    /// `vault.json`.
    pub const VAULT_HEADER: &str = "vault.json";
    /// `HEAD` — untrusted hint.
    pub const HEAD: &str = "HEAD";
    /// Prefix of member records.
    pub const MEMBERS_PREFIX: &str = "members/";
    /// Prefix of recovery wraps.
    pub const RECOVERY_PREFIX: &str = "recovery/";
    /// Prefix of keyring records.
    pub const KEYRING_PREFIX: &str = "keyring/";
    /// Prefix of entry versions.
    pub const ENTRIES_PREFIX: &str = "entries/";
    /// Prefix of manifests.
    pub const MANIFESTS_PREFIX: &str = "manifests/";
    /// Prefixes whose objects are immutable (overwrite → 412 regardless of headers).
    pub const IMMUTABLE_PREFIXES: &[&str] = &[
        ENTRIES_PREFIX,
        MANIFESTS_PREFIX,
        MEMBERS_PREFIX,
        RECOVERY_PREFIX,
        KEYRING_PREFIX,
    ];
    /// Maximum key length accepted.
    pub const MAX_KEY_LEN: usize = 512;

    /// `members/<device_id>/<rev>.json`.
    pub fn member(device_id: &DeviceId, rev: u64) -> String {
        format!("members/{device_id}/{rev}.json")
    }
    /// `recovery/<key_epoch>-<kind>.json`.
    pub fn recovery(key_epoch: u32, kind: RecoveryKind) -> String {
        format!("recovery/{key_epoch}-{}.json", kind.as_str())
    }
    /// `keyring/<key_epoch>.json`.
    pub fn keyring(key_epoch: u32) -> String {
        format!("keyring/{key_epoch}.json")
    }
    /// `entries/<entry_id>/<version>.json`.
    pub fn entry(entry_id: &EntryId, version: u64) -> String {
        format!("entries/{entry_id}/{version}.json")
    }
    /// `manifests/<seq zero-padded to 12>.json`.
    pub fn manifest(seq: u64) -> String {
        format!("manifests/{seq:012}.json")
    }
    /// Parse a manifest key back into its sequence number.
    pub fn parse_manifest(key: &str) -> Option<u64> {
        let n = key.strip_prefix(MANIFESTS_PREFIX)?.strip_suffix(".json")?;
        if n.len() != 12 || !n.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        n.parse().ok()
    }
    /// Parse `entries/<entry_id>/<version>.json`.
    pub fn parse_entry(key: &str) -> Option<(EntryId, u64)> {
        let rest = key.strip_prefix(ENTRIES_PREFIX)?.strip_suffix(".json")?;
        let (id, v) = rest.split_once('/')?;
        if v.is_empty() || !v.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        Some((EntryId::parse(id).ok()?, v.parse().ok()?))
    }
    /// Parse `members/<device_id>/<rev>.json`.
    pub fn parse_member(key: &str) -> Option<(DeviceId, u64)> {
        let rest = key.strip_prefix(MEMBERS_PREFIX)?.strip_suffix(".json")?;
        let (id, v) = rest.split_once('/')?;
        if v.is_empty() || !v.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        Some((DeviceId::parse(id).ok()?, v.parse().ok()?))
    }
    /// Whether `key` is immutable once written (`vault.json` and the immutable prefixes).
    pub fn is_immutable(key: &str) -> bool {
        key == VAULT_HEADER || IMMUTABLE_PREFIXES.iter().any(|p| key.starts_with(p))
    }
    /// Safe object key: non-empty, ≤ 512 bytes, `[A-Za-z0-9._-]` segments separated by `/`,
    /// no empty, `.` or `..` segments, no leading `/`. Backends must reject anything else
    /// (prevents path traversal in directory-backed stores).
    pub fn is_valid(key: &str) -> bool {
        !key.is_empty()
            && key.len() <= MAX_KEY_LEN
            && key.split('/').all(|seg| {
                !seg.is_empty()
                    && seg != "."
                    && seg != ".."
                    && seg
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
            })
    }
}

/// Associated-data strings binding ciphertexts to their context (CONTRACTS §2.2–§2.3).
pub mod aad {
    use super::RecoveryKind;
    use crate::ids::{DeviceId, EntryId, VaultId};

    /// VMK sealed to a device: `aipass:v1:vmk:{vault_id}:{device_id}:{key_epoch}`.
    pub fn vmk_wrap(vault_id: &VaultId, device_id: &DeviceId, key_epoch: u32) -> String {
        format!("aipass:v1:vmk:{vault_id}:{device_id}:{key_epoch}")
    }
    /// Recovery wrap: `aipass:v1:recovery:{vault_id}:{key_epoch}:{kind}`.
    pub fn recovery(vault_id: &VaultId, key_epoch: u32, kind: RecoveryKind) -> String {
        format!(
            "aipass:v1:recovery:{vault_id}:{key_epoch}:{}",
            kind.as_str()
        )
    }
    /// Keyring: `aipass:v1:keyring:{vault_id}:{key_epoch}`.
    pub fn keyring(vault_id: &VaultId, key_epoch: u32) -> String {
        format!("aipass:v1:keyring:{vault_id}:{key_epoch}")
    }
    /// Wrapped DEK: `aipass:v1:dek:{vault_id}:{entry_id}:{version}:{key_epoch}`.
    pub fn dek(vault_id: &VaultId, entry_id: &EntryId, version: u64, key_epoch: u32) -> String {
        format!("aipass:v1:dek:{vault_id}:{entry_id}:{version}:{key_epoch}")
    }
    /// Entry ciphertext: `aipass:v1:entry:{vault_id}:{entry_id}:{version}:1` (format 1).
    pub fn entry(vault_id: &VaultId, entry_id: &EntryId, version: u64) -> String {
        format!("aipass:v1:entry:{vault_id}:{entry_id}:{version}:1")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aipass_crypto::DeviceIdentity;

    fn vid() -> VaultId {
        VaultId::parse("vlt_01jbz3k6w8a7m2q4t5v9x0y1z0").unwrap()
    }

    #[test]
    fn signed_header_and_tamper() {
        let id = DeviceIdentity::generate();
        let mut h = VaultHeader {
            format: FORMAT_V1,
            vault_id: vid(),
            created_at: crate::time::now(),
            genesis_device_id: DeviceId::generate(),
            signature: String::new(),
        };
        h.sign_with(&id).unwrap();
        h.verify_signature(&id.public().sign_pk).unwrap();
        let json = serde_json::to_string(&h).unwrap();
        let back: VaultHeader = serde_json::from_str(&json).unwrap();
        back.verify_signature(&id.public().sign_pk).unwrap();
        let mut t = back.clone();
        t.genesis_device_id = DeviceId::generate();
        assert_eq!(
            t.verify_signature(&id.public().sign_pk),
            Err(SignatureError::Invalid)
        );
        assert!(
            back.verify_signature(&DeviceIdentity::generate().public().sign_pk)
                .is_err()
        );
    }

    #[test]
    fn member_record_null_wrap_and_manifest() {
        let id = DeviceIdentity::generate();
        let dev = DeviceId::generate();
        let mut m = MemberRecord {
            format: 1,
            vault_id: vid(),
            device_id: dev.clone(),
            rev: 1,
            name: "Node".into(),
            platform: Platform::Node,
            role: MemberRole::Executor,
            sign_pk: id.public().sign_pk,
            kem_pk: id.public().kem_pk,
            status: MemberStatus::Active,
            key_epoch: 1,
            wrapped_vmk: None,
            added_by: dev.clone(),
            created_at: crate::time::now(),
            signature: String::new(),
        };
        m.sign_with(&id).unwrap();
        let v = serde_json::to_value(&m).unwrap();
        assert!(v["wrapped_vmk"].is_null());
        assert_eq!(v["platform"], "node");
        m.verify_signature(&id.public().sign_pk).unwrap();
        assert_eq!(m.device_public().role, MemberRole::Executor);

        let e = EntryId::generate();
        let mut man = Manifest {
            format: 1,
            vault_id: vid(),
            seq: 1,
            prev_hash: String::new(),
            key_epoch: 1,
            entries: BTreeMap::from([(
                e.clone(),
                ManifestEntry {
                    version: 1,
                    hash: "h".into(),
                    conflict_versions: vec![2],
                },
            )]),
            tombstones: BTreeMap::new(),
            members: BTreeMap::from([(
                dev.clone(),
                ManifestMember {
                    rev: 1,
                    hash: "x".into(),
                    status: MemberStatus::Active,
                    role: MemberRole::Owner,
                },
            )]),
            author_device_id: dev.clone(),
            created_at: crate::time::now(),
            signature: String::new(),
        };
        man.sign_with(&id).unwrap();
        man.verify_signature(&id.public().sign_pk).unwrap();
        assert!(man.has_conflict(&e));
        assert_eq!(man.active_approvers().count(), 1);
        assert!(
            !man.signing_bytes()
                .unwrap()
                .windows(9)
                .any(|w| w == b"signature")
        );
    }

    #[test]
    fn keys_and_aad() {
        let e = EntryId::parse("ent_01jbz3k6w8a7m2q4t5v9x0y1z5").unwrap();
        assert_eq!(keys::manifest(7), "manifests/000000000007.json");
        assert_eq!(keys::parse_manifest("manifests/000000000007.json"), Some(7));
        assert_eq!(keys::parse_manifest("manifests/7.json"), None);
        assert_eq!(
            keys::entry(&e, 3),
            "entries/ent_01jbz3k6w8a7m2q4t5v9x0y1z5/3.json"
        );
        assert_eq!(keys::parse_entry(&keys::entry(&e, 3)), Some((e.clone(), 3)));
        assert_eq!(
            keys::recovery(2, RecoveryKind::MasterPassword),
            "recovery/2-master_password.json"
        );
        assert!(keys::is_immutable("manifests/000000000001.json"));
        assert!(keys::is_immutable("vault.json"));
        assert!(!keys::is_immutable("HEAD"));
        assert!(keys::is_valid("entries/ent_x/1.json"));
        for bad in [
            "", "/abs", "a//b", "../x", "a/./b", "a/..", "a\\b", "a b", "é",
        ] {
            assert!(!keys::is_valid(bad), "{bad}");
        }
        assert_eq!(
            aad::dek(&vid(), &e, 1, 1),
            "aipass:v1:dek:vlt_01jbz3k6w8a7m2q4t5v9x0y1z0:ent_01jbz3k6w8a7m2q4t5v9x0y1z5:1:1"
        );
        assert_eq!(
            aad::entry(&vid(), &e, 1),
            "aipass:v1:entry:vlt_01jbz3k6w8a7m2q4t5v9x0y1z0:ent_01jbz3k6w8a7m2q4t5v9x0y1z5:1:1"
        );
        assert_eq!(
            aad::recovery(&vid(), 1, RecoveryKind::RecoveryKey),
            "aipass:v1:recovery:vlt_01jbz3k6w8a7m2q4t5v9x0y1z0:1:recovery_key"
        );
    }

    #[test]
    fn payload_redaction_and_roundtrip() {
        let mut p = EntryPayload::new(EntryKind::Login, "Bank of Secrets");
        p.username = Some("alice@example.com".into());
        p.secret = Some(SecretString::from("hunter2-pw"));
        p.totp = Some(TotpConfig {
            secret: "JBSWY3DPEHPK3PXP".into(),
            algorithm: TotpAlgorithm::Sha1,
            digits: 6,
            period: 30,
        });
        p.fields.push(CustomField {
            name: "pin".into(),
            value: "4321".into(),
            sensitive: true,
        });
        p.source = EntrySource::Import("chrome".into());
        let dbg = format!("{p:?} {:?} {:?}", p.totp, p.fields);
        for leak in ["hunter2", "alice", "Bank of", "JBSWY3", "4321", "pin"] {
            assert!(!dbg.contains(leak), "leaked {leak} in {dbg}");
        }
        assert!(p.has_secret_material());
        let pt = p.to_plaintext().unwrap();
        let back = EntryPayload::from_plaintext(&pt).unwrap();
        assert_eq!(back, p);
        let v: serde_json::Value = serde_json::from_slice(&pt).unwrap();
        assert_eq!(v["source"], "import:chrome");
        assert_eq!(v["totp"]["algorithm"], "SHA1");
        assert_eq!(v["kind"], "login");
        assert!(v["notes"].is_null());
        assert!(serde_json::from_value::<EntrySource>(serde_json::json!("import:")).is_err());
        let mut z = back.clone();
        z.zeroize();
        assert!(z.title.is_empty() && z.secret.as_ref().is_none_or(|s| s.is_empty()));
    }

    #[test]
    fn kdf_spec_and_rules() {
        let k = serde_json::to_value(KdfSpec::HkdfSha256).unwrap();
        assert_eq!(k, serde_json::json!({"alg":"hkdf-sha256"}));
        let a: KdfSpec = serde_json::from_value(serde_json::json!({"alg":"argon2id","m":65536,"t":3,"p":1,"salt":"AAAAAAAAAAAAAAAAAAAAAA"})).unwrap();
        assert!(matches!(a, KdfSpec::Argon2id { m: 65536, .. }));
        let r: PasswordRules = serde_json::from_str("{}").unwrap();
        assert_eq!(r, PasswordRules::default());
        r.validate().unwrap();
        assert!(
            PasswordRules {
                length: 7,
                ..Default::default()
            }
            .validate()
            .is_err()
        );
        assert!(
            PasswordRules {
                lower: false,
                upper: false,
                digits: false,
                symbols: false,
                ..Default::default()
            }
            .validate()
            .is_err()
        );
    }
}
