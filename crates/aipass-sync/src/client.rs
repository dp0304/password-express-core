// SPDX-License-Identifier: Apache-2.0
//! [`VaultClient`] — the high-level facade used by the CLI, the desktop app and the FFI
//! (CONTRACTS §12). A UI never touches the VMK: it creates / unlocks / locks the vault,
//! lists summaries, reveals one secret after its own re-authentication, saves items, syncs
//! and resolves conflicts.
//!
//! Local data directory layout (one vault per directory):
//!
//! ```text
//! <data_dir>/device.json   public device description (no secrets)
//! <data_dir>/state.json    vault id, storage profile (non-secret), checkpoint, flags
//! <data_dir>/outbox.json   encrypted pending changes (local key in the secret store)
//! <data_dir>/cache/…       verified ciphertext objects (same keys as storage)
//! ```
//!
//! Secret-store keys: `aipass.device.<device_id>` (64-byte identity, user presence),
//! `aipass.local.<vault_id>` (outbox key), `aipass.storage.<vault_id>` (storage access
//! secret), `aipass.recovery-pending.<vault_id>` (recovery key until the user verified it).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};

use aipass_crypto::{Argon2Params, DeviceIdentity, Key32, SecretString};
use aipass_storage::{
    MemoryStore, Object, ObjectMeta, ObjectStore, PutCondition, PutOutcome, StorageDescription,
    StorageError, StorageProfile,
};
use aipass_types::Localized;
use aipass_types::ids::{DeviceId, EntryId, ExecutorId, ResourceId, VaultId};
use aipass_types::time::{Timestamp, rfc3339, rfc3339_option};
use aipass_types::vault::{
    Checkpoint, CustomField, EntryPayload, EntrySource, Lifecycle, MemberRecord, MemberRole,
    Platform, VaultHeader,
};
use aipass_vault::manifest::VaultView;
use aipass_vault::{Result, SecretStore, UnlockedVault, VaultError};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::cache::FileStore;
use crate::engine::{PullStats, SyncEngine};
use crate::models::*;
use crate::outbox::{self, ChangeOp, Outbox, PendingChange};
use crate::planners::OutboxPlanner;

/// Days after which a device must re-verify its membership before pushing (§3.2).
pub const OFFLINE_LIMIT_DAYS: i64 = 90;
/// Mask shown instead of secrets.
pub const SECRET_MASK: &str = "••••••••";

/// Client configuration.
#[derive(Debug, Clone)]
pub struct ClientConfig {
    /// Data directory (one vault).
    pub data_dir: PathBuf,
    /// This device's platform.
    pub platform: Platform,
    /// App version (diagnostics only).
    pub app_version: String,
    /// Argon2id parameters for master-password wraps and encrypted exports
    /// (default: the contract parameters m=64 MiB, t=3, p=1).
    pub argon2: Argon2Params,
    /// Push automatically after each local change (default true).
    pub auto_sync: bool,
}

impl ClientConfig {
    /// Defaults for `data_dir`.
    pub fn new(
        data_dir: impl Into<PathBuf>,
        platform: Platform,
        app_version: impl Into<String>,
    ) -> Self {
        Self {
            data_dir: data_dir.into(),
            platform,
            app_version: app_version.into(),
            argon2: Argon2Params::CONTRACT_V1,
            auto_sync: true,
        }
    }
}

/// Who opens a store (HTTP sync stores sign requests with this identity).
#[derive(Clone)]
pub struct StoreContext {
    /// Vault.
    pub vault_id: VaultId,
    /// Signing device (a vault member; during key recovery the recovery member).
    pub device_id: Option<DeviceId>,
    /// Its identity.
    pub identity: Option<DeviceIdentity>,
}

impl core::fmt::Debug for StoreContext {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StoreContext")
            .field("vault_id", &self.vault_id)
            .field("device_id", &self.device_id)
            .finish_non_exhaustive()
    }
}

/// Builds storage backends from profiles. CLI / desktop / FFI implement it with the
/// `aipass-storage` backends (LocalDir, S3, HttpSync, WebDAV); [`MemoryStoreFactory`]
/// serves tests. `open` must not perform network I/O (unlock works offline).
#[async_trait]
pub trait StoreFactory: Send + Sync {
    /// A store scoped to the vault root of `ctx.vault_id`.
    async fn open(
        &self,
        profile: &StorageProfile,
        secret: Option<&SecretString>,
        ctx: &StoreContext,
    ) -> Result<Arc<dyn ObjectStore>>;

    /// Backend-specific vault creation (e.g. `POST /v1/vaults` for HTTP sync). Default: none.
    async fn provision(
        &self,
        _profile: &StorageProfile,
        _secret: Option<&SecretString>,
        _ctx: &StoreContext,
        _header: &VaultHeader,
        _genesis: &MemberRecord,
    ) -> Result<()> {
        Ok(())
    }
}

/// In-memory stores keyed by profile location (tests; several clients can share one).
#[derive(Default)]
pub struct MemoryStoreFactory {
    stores: Mutex<BTreeMap<String, Arc<MemoryStore>>>,
}

impl MemoryStoreFactory {
    /// New factory.
    pub fn new() -> Self {
        Self::default()
    }

    fn key(profile: &StorageProfile, vault: &VaultId) -> String {
        format!(
            "{:?}|{}|{}|{}|{}|{}|{vault}",
            profile.kind,
            profile.endpoint.as_deref().unwrap_or(""),
            profile.bucket.as_deref().unwrap_or(""),
            profile.prefix.as_deref().unwrap_or(""),
            profile.path.as_deref().unwrap_or(""),
            profile.base_url.as_deref().unwrap_or("")
        )
    }

    /// The store behind `profile` for `vault` (created on demand) — lets tests tamper.
    pub fn store(&self, profile: &StorageProfile, vault: &VaultId) -> Arc<MemoryStore> {
        let mut m = self.stores.lock().unwrap_or_else(|e| e.into_inner());
        m.entry(Self::key(profile, vault))
            .or_insert_with(|| Arc::new(MemoryStore::new()))
            .clone()
    }
}

#[async_trait]
impl StoreFactory for MemoryStoreFactory {
    async fn open(
        &self,
        profile: &StorageProfile,
        _secret: Option<&SecretString>,
        ctx: &StoreContext,
    ) -> Result<Arc<dyn ObjectStore>> {
        Ok(self.store(profile, &ctx.vault_id))
    }
}

/// A store that is always unreachable (used when a factory cannot build the remote; reads
/// then come from the local cache only).
struct UnavailableStore;

#[async_trait]
impl ObjectStore for UnavailableStore {
    async fn get(&self, _key: &str) -> std::result::Result<Option<Object>, StorageError> {
        Err(StorageError::Network(
            "storage not configured or unreachable".into(),
        ))
    }
    async fn put(
        &self,
        _key: &str,
        _bytes: Vec<u8>,
        _cond: PutCondition,
    ) -> std::result::Result<PutOutcome, StorageError> {
        Err(StorageError::Network(
            "storage not configured or unreachable".into(),
        ))
    }
    async fn delete(&self, _key: &str) -> std::result::Result<(), StorageError> {
        Err(StorageError::Network(
            "storage not configured or unreachable".into(),
        ))
    }
    async fn list(
        &self,
        _p: &str,
        _a: Option<&str>,
        _l: usize,
    ) -> std::result::Result<Vec<ObjectMeta>, StorageError> {
        Err(StorageError::Network(
            "storage not configured or unreachable".into(),
        ))
    }
    fn describe(&self) -> StorageDescription {
        StorageDescription {
            kind: "unavailable".into(),
            endpoint: None,
            detail: None,
        }
    }
}

// ---------------------------------------------------------------------------------------
// files
// ---------------------------------------------------------------------------------------

/// `device.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceFile {
    /// Always 1.
    pub format: u32,
    /// Device id.
    pub device_id: DeviceId,
    /// Name.
    pub name: String,
    /// Platform.
    pub platform: Platform,
    /// Role in the vault.
    pub role: MemberRole,
    /// Ed25519 public key.
    #[serde(with = "aipass_crypto::b64u::array")]
    pub sign_pk: [u8; 32],
    /// X25519 public key.
    #[serde(with = "aipass_crypto::b64u::array")]
    pub kem_pk: [u8; 32],
    /// Created.
    #[serde(with = "rfc3339")]
    pub created_at: Timestamp,
    /// App version that created the file.
    pub app_version: String,
}

/// A credential flagged for rotation after a revocation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredRotationTask {
    /// Entry.
    pub entry_id: EntryId,
    /// Version current at revocation time.
    pub version: u64,
    /// Revoked device.
    pub revoked_device: DeviceId,
}

/// `state.json` (no secrets).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StateFile {
    /// Always 1.
    pub format: u32,
    /// Vault.
    pub vault_id: VaultId,
    /// Primary storage (non-secret).
    pub storage: StorageProfile,
    /// Newest verified manifest.
    pub checkpoint: Option<Checkpoint>,
    /// Last successful sync.
    #[serde(default, with = "rfc3339_option")]
    pub last_sync_at: Option<Timestamp>,
    /// Last time this device verified its own membership against storage.
    #[serde(default, with = "rfc3339_option")]
    pub membership_verified_at: Option<Timestamp>,
    /// When the user verified the recovery key.
    #[serde(default, with = "rfc3339_option")]
    pub recovery_verified_at: Option<Timestamp>,
    /// Rollback detected (writes stopped).
    #[serde(default)]
    pub rollback_detected: bool,
    /// This device was revoked.
    #[serde(default)]
    pub revoked: bool,
    /// Relay base URL.
    #[serde(default)]
    pub relay_base_url: Option<String>,
    /// Last sync error code.
    #[serde(default)]
    pub last_error: Option<String>,
    /// resource → credential entry (approvals).
    #[serde(default)]
    pub resource_bindings: BTreeMap<ResourceId, EntryId>,
    /// Executors that are not vault members (e.g. desktop-embedded).
    #[serde(default)]
    pub known_executors: BTreeMap<ExecutorId, KnownExecutor>,
    /// Immutable objects to write on the next sync (e.g. a recovery wrap).
    #[serde(default)]
    pub pending_objects: BTreeMap<String, String>,
    /// Open rotation tasks.
    #[serde(default)]
    pub rotation_tasks: Vec<StoredRotationTask>,
    /// Long-term credentials this device sealed to executors on approval (executor →
    /// entry → highest delivered version). An executor is not trusted to forget them, so
    /// revoking it turns them into rotation tasks (design doc §9.4, §10.4).
    #[serde(default)]
    pub executor_deliveries: BTreeMap<ExecutorId, BTreeMap<EntryId, u64>>,
    /// Created.
    #[serde(with = "rfc3339")]
    pub created_at: Timestamp,
}

pub(crate) struct CachedItem {
    pub version: u64,
    pub key_epoch: u32,
    pub payload: EntryPayload,
    pub conflict_versions: Vec<u64>,
}

pub(crate) struct Session {
    pub vault: UnlockedVault,
    pub items: BTreeMap<EntryId, CachedItem>,
    pub outbox: Outbox,
    pub local_key: Key32,
}

#[derive(Default)]
pub(crate) struct Inner {
    pub device: Option<DeviceFile>,
    pub state: Option<StateFile>,
    pub view: Option<VaultView>,
    pub session: Option<Session>,
}

/// An entry as seen by the UI: committed payload overlaid with pending outbox changes.
pub(crate) struct Effective {
    pub payload: EntryPayload,
    pub version: Option<u64>,
    pub conflict_versions: Vec<u64>,
    pub pending: bool,
}

pub(crate) fn device_secret_key(d: &DeviceId) -> String {
    format!("aipass.device.{d}")
}
pub(crate) fn local_key_name(v: &VaultId) -> String {
    format!("aipass.local.{v}")
}
pub(crate) fn storage_secret_key(v: &VaultId) -> String {
    format!("aipass.storage.{v}")
}
pub(crate) fn recovery_pending_key(v: &VaultId) -> String {
    format!("aipass.recovery-pending.{v}")
}

/// The vault facade. `Send + Sync`; network operations are serialized internally.
pub struct VaultClient {
    pub(crate) cfg: ClientConfig,
    pub(crate) secrets: Arc<dyn SecretStore>,
    pub(crate) factory: Arc<dyn StoreFactory>,
    pub(crate) inner: Mutex<Inner>,
    pub(crate) op: tokio::sync::Mutex<()>,
}

impl core::fmt::Debug for VaultClient {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VaultClient")
            .field("data_dir", &self.cfg.data_dir)
            .finish_non_exhaustive()
    }
}

impl VaultClient {
    /// Open the client on `cfg.data_dir` (loads `device.json` / `state.json` if present).
    pub fn open(
        cfg: ClientConfig,
        secrets: Arc<dyn SecretStore>,
        factory: Arc<dyn StoreFactory>,
    ) -> Result<Self> {
        aipass_vault::fsutil::create_private_dir(&cfg.data_dir)?;
        let device: Option<DeviceFile> = read_json(&cfg.data_dir.join("device.json"))?;
        let state: Option<StateFile> = read_json(&cfg.data_dir.join("state.json"))?;
        Ok(Self {
            cfg,
            secrets,
            factory,
            inner: Mutex::new(Inner {
                device,
                state,
                view: None,
                session: None,
            }),
            op: tokio::sync::Mutex::new(()),
        })
    }

    pub(crate) fn lock_inner(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Data directory.
    pub fn data_dir(&self) -> &Path {
        &self.cfg.data_dir
    }

    /// Whether this device has (or had) a vault.
    pub fn has_vault(&self) -> bool {
        let g = self.lock_inner();
        g.device.is_some() && g.state.is_some()
    }

    /// Whether the vault is unlocked.
    pub fn is_unlocked(&self) -> bool {
        self.lock_inner().session.is_some()
    }

    /// Vault id.
    pub fn vault_id(&self) -> Option<VaultId> {
        self.lock_inner().state.as_ref().map(|s| s.vault_id.clone())
    }

    /// This device's id.
    pub fn device_id(&self) -> Option<DeviceId> {
        self.lock_inner()
            .device
            .as_ref()
            .map(|d| d.device_id.clone())
    }

    /// `CoreStatus`.
    pub fn status(&self) -> CoreStatus {
        let g = self.lock_inner();
        let st = g.state.as_ref();
        // only an unlocked session knows the conflicts; a locked vault (a fresh process, or
        // a view left over from before `lock()`) reports unknown rather than a stale/false 0
        let conflicts = g.session.as_ref().map(|s| {
            s.items
                .values()
                .filter(|i| !i.conflict_versions.is_empty())
                .count() as u32
        });
        CoreStatus {
            vault_id: st.map(|s| s.vault_id.clone()),
            unlocked: g.session.is_some(),
            device_id: g.device.as_ref().map(|d| d.device_id.clone()),
            device_name: g.device.as_ref().map(|d| d.name.clone()),
            storage_kind: st.map(|s| s.storage.kind),
            last_sync_at: st.and_then(|s| s.last_sync_at),
            pending_changes: g.session.as_ref().map_or(0, |s| s.outbox.len() as u32),
            conflicts,
            recovery_verified: st.is_some_and(|s| s.recovery_verified_at.is_some()),
            rollback_detected: st.is_some_and(|s| s.rollback_detected),
            revoked: st.is_some_and(|s| s.revoked),
            key_epoch: g.session.as_ref().map(|s| s.vault.key_epoch()),
            last_error: st.and_then(|s| s.last_error.clone()),
            device_sign_pk: g
                .device
                .as_ref()
                .map(|d| aipass_crypto::b64u::encode(d.sign_pk)),
            device_kem_pk: g
                .device
                .as_ref()
                .map(|d| aipass_crypto::b64u::encode(d.kem_pk)),
        }
    }

    // ---------------------------------------------------------------------------------
    // persistence helpers
    // ---------------------------------------------------------------------------------

    pub(crate) fn save_state(&self, state: &StateFile) -> Result<()> {
        write_json(&self.cfg.data_dir.join("state.json"), state)
    }

    pub(crate) fn save_device(&self, device: &DeviceFile) -> Result<()> {
        write_json(&self.cfg.data_dir.join("device.json"), device)
    }

    pub(crate) fn outbox_path(&self) -> PathBuf {
        self.cfg.data_dir.join("outbox.json")
    }

    pub(crate) fn cache_store(&self) -> Arc<dyn ObjectStore> {
        Arc::new(FileStore::new(self.cfg.data_dir.join("cache")))
    }

    pub(crate) fn storage_secret(&self, vault: &VaultId) -> Result<Option<SecretString>> {
        Ok(match self.secrets.get(&storage_secret_key(vault))? {
            Some(b) => Some(
                b.into_secret_string()
                    .map_err(|_| VaultError::SecretStore("storage secret is not UTF-8"))?,
            ),
            None => None,
        })
    }

    pub(crate) fn identity(&self, device: &DeviceFile) -> Result<DeviceIdentity> {
        let b = self
            .secrets
            .get(&device_secret_key(&device.device_id))?
            .ok_or(VaultError::SecretUnavailable(
                "device key not found in the secret store",
            ))?;
        let id = DeviceIdentity::from_secret_bytes(b.expose())
            .map_err(|_| VaultError::Integrity("device key in the secret store is invalid"))?;
        if id.public().sign_pk != device.sign_pk || id.public().kem_pk != device.kem_pk {
            return Err(VaultError::Integrity(
                "device key does not match device.json",
            ));
        }
        Ok(id)
    }

    /// Engine for the current state (remote may be unavailable).
    pub(crate) async fn engine_for(&self, state: &StateFile, ctx: StoreContext) -> SyncEngine {
        let secret = self.storage_secret(&state.vault_id).ok().flatten();
        let remote = match self
            .factory
            .open(&state.storage, secret.as_ref(), &ctx)
            .await
        {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(error = %e, "storage backend could not be opened; using local cache only");
                Arc::new(UnavailableStore)
            }
        };
        SyncEngine::new(remote, self.cache_store(), state.vault_id.clone())
    }

    pub(crate) fn snapshot(&self) -> Result<(DeviceFile, StateFile)> {
        let g = self.lock_inner();
        let d = g.device.clone().ok_or(VaultError::NoVault)?;
        let s = g.state.clone().ok_or(VaultError::NoVault)?;
        Ok((d, s))
    }

    pub(crate) fn unlocked_snapshot(
        &self,
    ) -> Result<(DeviceFile, StateFile, UnlockedVault, VaultView)> {
        let g = self.lock_inner();
        let d = g.device.clone().ok_or(VaultError::NoVault)?;
        let s = g.state.clone().ok_or(VaultError::NoVault)?;
        if s.revoked {
            return Err(VaultError::Revoked);
        }
        let sess = g.session.as_ref().ok_or(VaultError::Locked)?;
        let v = g.view.clone().ok_or(VaultError::Locked)?;
        Ok((d, s, sess.vault.clone(), v))
    }

    pub(crate) fn ctx_for(
        device: &DeviceFile,
        vault: &UnlockedVault,
        vault_id: &VaultId,
    ) -> StoreContext {
        StoreContext {
            vault_id: vault_id.clone(),
            device_id: Some(device.device_id.clone()),
            identity: Some(vault.identity().clone()),
        }
    }

    // ---------------------------------------------------------------------------------
    // create / unlock / lock
    // ---------------------------------------------------------------------------------

    /// Create a new vault on `storage` (genesis device = this device, owner). Returns the
    /// recovery key and kit text once; the key is kept in the secret store only until the
    /// user verifies it ([`VaultClient::verify_recovery_key`]).
    pub async fn create_vault(
        &self,
        device_name: &str,
        storage: StorageProfile,
        storage_secret: Option<SecretString>,
        master_password: Option<SecretString>,
    ) -> Result<CreateVaultResult> {
        let _op = self.op.lock().await;
        if self.has_vault() {
            return Err(VaultError::AlreadyExists);
        }
        let genesis = aipass_vault::vault::create_genesis(aipass_vault::GenesisParams {
            device_name,
            platform: self.cfg.platform,
            master_password: master_password.as_ref(),
            argon2: self.cfg.argon2,
            now: aipass_types::time::now(),
        })?;
        let vault_id = genesis.vault_id.clone();
        let device_id = genesis.device_id.clone();
        let identity = genesis.unlocked.identity().clone();
        let ctx = StoreContext {
            vault_id: vault_id.clone(),
            device_id: Some(device_id.clone()),
            identity: Some(identity.clone()),
        };
        let remote = self
            .factory
            .open(&storage, storage_secret.as_ref(), &ctx)
            .await?;
        self.factory
            .provision(
                &storage,
                storage_secret.as_ref(),
                &ctx,
                &genesis.header,
                &genesis.genesis_member.record,
            )
            .await?;

        // secrets first, so a successful storage write is never left without its keys
        self.secrets.set(
            &device_secret_key(&device_id),
            identity.to_secret_bytes().expose(),
            true,
        )?;
        let local_key = Key32::generate()?;
        self.secrets
            .set(&local_key_name(&vault_id), local_key.expose(), false)?;
        if let Some(s) = &storage_secret {
            self.secrets
                .set(&storage_secret_key(&vault_id), s.expose().as_bytes(), false)?;
        }
        let formatted = genesis.recovery_key.format();
        self.secrets.set(
            &recovery_pending_key(&vault_id),
            formatted.expose().as_bytes(),
            true,
        )?;

        let engine = SyncEngine::new(remote, self.cache_store(), vault_id.clone());
        if let Err(e) = engine
            .write_genesis(&genesis.objects, &genesis.manifest)
            .await
        {
            let _ = self.secrets.delete(&device_secret_key(&device_id));
            let _ = self.secrets.delete(&local_key_name(&vault_id));
            let _ = self.secrets.delete(&storage_secret_key(&vault_id));
            let _ = self.secrets.delete(&recovery_pending_key(&vault_id));
            return Err(e);
        }
        let now = aipass_types::time::now();
        let pubk = identity.public();
        let device = DeviceFile {
            format: 1,
            device_id: device_id.clone(),
            name: device_name.trim().to_owned(),
            platform: self.cfg.platform,
            role: MemberRole::Owner,
            sign_pk: pubk.sign_pk,
            kem_pk: pubk.kem_pk,
            created_at: now,
            app_version: self.cfg.app_version.clone(),
        };
        let state = StateFile {
            format: 1,
            vault_id: vault_id.clone(),
            storage: storage.clone(),
            checkpoint: genesis.view.checkpoint(),
            last_sync_at: Some(now),
            membership_verified_at: Some(now),
            recovery_verified_at: None,
            rollback_detected: false,
            revoked: false,
            relay_base_url: None,
            last_error: None,
            resource_bindings: BTreeMap::new(),
            known_executors: BTreeMap::new(),
            pending_objects: BTreeMap::new(),
            rotation_tasks: Vec::new(),
            executor_deliveries: BTreeMap::new(),
            created_at: now,
        };
        self.save_device(&device)?;
        self.save_state(&state)?;
        outbox::save(
            &self.outbox_path(),
            &local_key,
            &vault_id,
            &device_id,
            &Outbox::default(),
        )?;
        let kit = aipass_vault::recovery::recovery_kit_text(&aipass_vault::recovery::RecoveryKit {
            vault_id: &vault_id,
            recovery_key: Some(&formatted),
            created_at: &now,
            storage: &storage,
            storage_secret: None,
        });
        {
            let mut g = self.lock_inner();
            g.device = Some(device);
            g.state = Some(state);
            g.view = Some(genesis.view);
            g.session = Some(Session {
                vault: genesis.unlocked,
                items: BTreeMap::new(),
                outbox: Outbox::default(),
                local_key,
            });
        }
        Ok(CreateVaultResult {
            vault_id,
            device_id,
            recovery_key: formatted,
            recovery_kit_text: SecretString::new(kit),
        })
    }

    /// Unlock with the device key from the secret store (the native layer performs
    /// biometric / passcode verification first). Works offline from the local cache.
    pub async fn unlock(&self) -> Result<()> {
        let _op = self.op.lock().await;
        if self.is_unlocked() {
            return Ok(());
        }
        let (device, state) = self.snapshot()?;
        if state.revoked {
            return Err(VaultError::Revoked);
        }
        let identity = self.identity(&device)?;
        let cp = state
            .checkpoint
            .clone()
            .ok_or(VaultError::Integrity("no checkpoint on this device"))?;
        let ctx = StoreContext {
            vault_id: state.vault_id.clone(),
            device_id: Some(device.device_id.clone()),
            identity: Some(identity.clone()),
        };
        let engine = self.engine_for(&state, ctx).await;
        let view = engine.cached_view(&cp).await?;
        let vault = engine
            .open_vault(&view, &device.device_id, identity)
            .await?;
        let local_key = match self.secrets.get(&local_key_name(&state.vault_id))? {
            Some(k) => k
                .to_key32()
                .ok_or(VaultError::Integrity("local key invalid"))?,
            None => {
                let k = Key32::generate()?;
                self.secrets
                    .set(&local_key_name(&state.vault_id), k.expose(), false)?;
                k
            }
        };
        let outbox = outbox::load(
            &self.outbox_path(),
            &local_key,
            &state.vault_id,
            &device.device_id,
        )?;
        let items = decrypt_all(&engine, &view, &vault, &BTreeMap::new()).await?;
        let mut g = self.lock_inner();
        g.view = Some(view);
        g.session = Some(Session {
            vault,
            items,
            outbox,
            local_key,
        });
        Ok(())
    }

    /// Lock: drop keys and decrypted payloads from memory (zeroized).
    pub fn lock(&self) {
        let mut g = self.lock_inner();
        g.session = None;
    }

    // ---------------------------------------------------------------------------------
    // items
    // ---------------------------------------------------------------------------------

    pub(crate) fn effective(sess: &Session) -> BTreeMap<EntryId, Effective> {
        let mut out: BTreeMap<EntryId, Effective> = sess
            .items
            .iter()
            .map(|(id, c)| {
                (
                    id.clone(),
                    Effective {
                        payload: c.payload.clone(),
                        version: Some(c.version),
                        conflict_versions: c.conflict_versions.clone(),
                        pending: false,
                    },
                )
            })
            .collect();
        for ch in &sess.outbox.changes {
            match &ch.op {
                ChangeOp::Upsert { payload } | ChangeOp::Restore { payload } => {
                    let (version, conflicts) = out
                        .get(&ch.entry_id)
                        .map(|e| (e.version, e.conflict_versions.clone()))
                        .unwrap_or((None, Vec::new()));
                    out.insert(
                        ch.entry_id.clone(),
                        Effective {
                            payload: payload.clone(),
                            version,
                            conflict_versions: conflicts,
                            pending: true,
                        },
                    );
                }
                ChangeOp::Delete => {
                    out.remove(&ch.entry_id);
                }
            }
        }
        out
    }

    pub(crate) fn with_session<T>(
        &self,
        f: impl FnOnce(&Session, &StateFile) -> Result<T>,
    ) -> Result<T> {
        let g = self.lock_inner();
        let st = g.state.as_ref().ok_or(VaultError::NoVault)?;
        if st.revoked {
            return Err(VaultError::Revoked);
        }
        let s = g.session.as_ref().ok_or(VaultError::Locked)?;
        f(s, st)
    }

    /// Summaries (no secrets), filtered by a case-insensitive query over title / username /
    /// URLs / tags and optionally by project.
    pub fn list_items(
        &self,
        query: Option<&str>,
        project_id: Option<&aipass_types::ids::ProjectId>,
    ) -> Result<Vec<ItemSummary>> {
        self.with_session(|s, _| {
            let q = query
                .map(|q| q.trim().to_lowercase())
                .filter(|q| !q.is_empty());
            let mut out: Vec<ItemSummary> = Self::effective(s)
                .iter()
                .filter(|(_, e)| {
                    project_id.is_none_or(|p| e.payload.project_id.as_ref() == Some(p))
                })
                .filter(|(_, e)| {
                    q.as_ref().is_none_or(|q| {
                        let p = &e.payload;
                        p.title.to_lowercase().contains(q)
                            || p.username
                                .as_deref()
                                .is_some_and(|u| u.to_lowercase().contains(q))
                            || p.urls.iter().any(|u| u.to_lowercase().contains(q))
                            || p.tags.iter().any(|t| t.to_lowercase().contains(q))
                    })
                })
                .map(|(id, e)| summary(id, e))
                .collect();
            out.sort_by(|a, b| {
                a.title
                    .to_lowercase()
                    .cmp(&b.title.to_lowercase())
                    .then(a.entry_id.cmp(&b.entry_id))
            });
            Ok(out)
        })
    }

    /// Detail with secrets masked.
    pub fn get_item(&self, entry_id: &EntryId) -> Result<ItemDetail> {
        self.with_session(|s, _| {
            let eff = Self::effective(s);
            let e = eff.get(entry_id).ok_or(VaultError::NotFound("entry"))?;
            let p = &e.payload;
            Ok(ItemDetail {
                summary: summary(entry_id, e),
                urls: p.urls.clone(),
                notes: p.notes.clone(),
                has_secret: p.secret.as_ref().is_some_and(|s| !s.is_empty()),
                secret_masked: p
                    .secret
                    .as_ref()
                    .filter(|s| !s.is_empty())
                    .map(|_| SECRET_MASK.to_owned()),
                has_totp: p.totp.is_some(),
                fields: p
                    .fields
                    .iter()
                    .map(|f| FieldView {
                        name: f.name.clone(),
                        value: (!f.sensitive).then(|| f.value.expose().to_owned()),
                        sensitive: f.sensitive,
                    })
                    .collect(),
                database: p.database.clone(),
                password_rules: p.password_rules.clone(),
                source: p.source.clone(),
                created_at: p.created_at,
                version: e.version,
                conflict_versions: e.conflict_versions.clone(),
            })
        })
    }

    /// Reveal one secret for the human user (the native layer re-authenticates first).
    /// Never exposed to AI principals.
    pub fn reveal_secret(&self, entry_id: &EntryId, field: &SecretField) -> Result<SecretString> {
        self.with_session(|s, _| {
            let eff = Self::effective(s);
            let p = &eff
                .get(entry_id)
                .ok_or(VaultError::NotFound("entry"))?
                .payload;
            match field {
                SecretField::Secret => p.secret.clone().ok_or(VaultError::NotFound("secret")),
                SecretField::TotpSecret => p
                    .totp
                    .as_ref()
                    .map(|t| t.secret.clone())
                    .ok_or(VaultError::NotFound("totp")),
                SecretField::Field(name) => p
                    .fields
                    .iter()
                    .find(|f| &f.name == name)
                    .map(|f| f.value.clone())
                    .ok_or(VaultError::NotFound("field")),
            }
        })
    }

    /// Current TOTP code of an entry.
    pub fn totp_now(&self, entry_id: &EntryId) -> Result<aipass_vault::totp::TotpCode> {
        self.with_session(|s, _| {
            let eff = Self::effective(s);
            let p = &eff
                .get(entry_id)
                .ok_or(VaultError::NotFound("entry"))?
                .payload;
            let cfg = p.totp.as_ref().ok_or(VaultError::NotFound("totp"))?;
            aipass_vault::totp::totp_now(cfg)
        })
    }

    /// Generate a password (CSPRNG; models never generate passwords).
    pub fn generate_password(
        &self,
        rules: &aipass_types::vault::PasswordRules,
    ) -> Result<SecretString> {
        aipass_vault::generator::generate_password(rules)
    }

    fn build_payload(
        input: ItemInput,
        existing: Option<&EntryPayload>,
        now: Timestamp,
    ) -> Result<EntryPayload> {
        let title = input.title.trim().to_owned();
        if title.is_empty() {
            return Err(VaultError::Invalid(Localized::new(
                "标题不能为空",
                "The title must not be empty.",
            )));
        }
        if title.chars().count() > 512 {
            return Err(VaultError::InvalidInput("title too long"));
        }
        let mut p = existing.cloned().unwrap_or_else(|| {
            let mut p = EntryPayload::new(input.kind, title.clone());
            p.lifecycle = Lifecycle::Verified;
            p.created_at = now;
            p
        });
        p.kind = input.kind;
        p.title = title;
        p.username = input
            .username
            .map(|u| u.trim().to_owned())
            .filter(|u| !u.is_empty());
        if input.clear_secret {
            p.secret = None;
        } else if let Some(s) = input.secret {
            p.secret = Some(s);
        }
        if input.clear_totp {
            p.totp = None;
        } else if let Some(t) = input.totp {
            p.totp = Some(aipass_vault::totp::parse_totp_input(t.expose())?);
        }
        let mut urls = Vec::new();
        for u in input.urls {
            let t = u.trim();
            if t.is_empty() {
                continue;
            }
            if aipass_vault::matching::parse_site(t).is_none() {
                return Err(VaultError::Invalid(Localized::new(
                    "网址格式不正确",
                    "A URL is not valid.",
                )));
            }
            urls.push(if t.contains("://") {
                t.to_owned()
            } else {
                format!("https://{t}")
            });
        }
        p.urls = urls;
        p.notes = input.notes.filter(|n| !n.is_empty());
        let old_fields = std::mem::take(&mut p.fields);
        for f in input.fields {
            let name = f.name.trim().to_owned();
            if name.is_empty() {
                continue;
            }
            let value = match f.value {
                Some(v) => v,
                None => old_fields
                    .iter()
                    .find(|o| o.name == name)
                    .map(|o| o.value.clone())
                    .ok_or(VaultError::InvalidInput("field value missing"))?,
            };
            p.fields.push(CustomField {
                name,
                value,
                sensitive: f.sensitive,
            });
        }
        p.database = input.database;
        p.project_id = input.project_id;
        p.tags = input
            .tags
            .into_iter()
            .map(|t| t.trim().to_owned())
            .filter(|t| !t.is_empty())
            .collect();
        if let Some(l) = input.lifecycle {
            p.lifecycle = l;
        }
        p.password_rules = input.password_rules;
        if let Some(src) = input.source {
            p.source = src;
        } else if existing.is_none() {
            p.source = EntrySource::Manual;
        }
        p.updated_at = now;
        Ok(p)
    }

    pub(crate) fn queue_change(&self, entry_id: EntryId, op: ChangeOp) -> Result<()> {
        let mut g = self.lock_inner();
        let device_id = g
            .device
            .as_ref()
            .ok_or(VaultError::NoVault)?
            .device_id
            .clone();
        let vault_id = g
            .state
            .as_ref()
            .ok_or(VaultError::NoVault)?
            .vault_id
            .clone();
        let sess = g.session.as_mut().ok_or(VaultError::Locked)?;
        let base_version = sess.items.get(&entry_id).map(|c| c.version);
        let mut next = sess.outbox.clone();
        next.push(PendingChange {
            entry_id,
            base_version,
            op,
            created_at: aipass_types::time::now(),
        });
        outbox::save(
            &self.outbox_path(),
            &sess.local_key,
            &vault_id,
            &device_id,
            &next,
        )?;
        sess.outbox = next;
        Ok(())
    }

    /// Create or update an item. The change is stored encrypted in the outbox first and
    /// pushed immediately when `auto_sync` is on and storage is reachable.
    pub async fn save_item(&self, input: ItemInput) -> Result<EntryId> {
        let now = aipass_types::time::now();
        let (entry_id, payload, secret_changed) = {
            let g = self.lock_inner();
            let st = g.state.as_ref().ok_or(VaultError::NoVault)?;
            if st.revoked {
                return Err(VaultError::Revoked);
            }
            let s = g.session.as_ref().ok_or(VaultError::Locked)?;
            let eff = Self::effective(s);
            let (id, existing) = match &input.entry_id {
                Some(id) => (
                    id.clone(),
                    Some(
                        eff.get(id)
                            .ok_or(VaultError::NotFound("entry"))?
                            .payload
                            .clone(),
                    ),
                ),
                None => (EntryId::generate(), None),
            };
            let new_secret = input.secret.clone();
            let clear = input.clear_secret;
            let p = Self::build_payload(input, existing.as_ref(), now)?;
            let changed = clear
                || new_secret
                    .is_some_and(|n| existing.as_ref().and_then(|e| e.secret.as_ref()) != Some(&n));
            (id, p, changed)
        };
        self.queue_change(entry_id.clone(), ChangeOp::Upsert { payload })?;
        if secret_changed {
            self.complete_rotation_task(&entry_id)?;
        }
        if self.cfg.auto_sync {
            let _ = self.sync().await;
        }
        Ok(entry_id)
    }

    /// Delete an item (tombstone on the next push).
    pub async fn delete_item(&self, entry_id: &EntryId) -> Result<()> {
        self.with_session(|s, _| {
            Self::effective(s)
                .get(entry_id)
                .map(|_| ())
                .ok_or(VaultError::NotFound("entry"))
        })?;
        self.queue_change(entry_id.clone(), ChangeOp::Delete)?;
        if self.cfg.auto_sync {
            let _ = self.sync().await;
        }
        Ok(())
    }

    /// Edits refused because the entry was deleted on another device.
    pub fn rejected_changes(&self) -> Result<Vec<EntryId>> {
        self.with_session(|s, _| {
            Ok(s.outbox
                .rejected
                .iter()
                .map(|r| r.entry_id.clone())
                .collect())
        })
    }

    /// Explicitly restore a rejected edit as a new version above the tombstone.
    pub async fn restore_rejected(&self, entry_id: &EntryId) -> Result<()> {
        let payload = {
            let mut g = self.lock_inner();
            let sess = g.session.as_mut().ok_or(VaultError::Locked)?;
            let i = sess
                .outbox
                .rejected
                .iter()
                .position(|r| &r.entry_id == entry_id)
                .ok_or(VaultError::NotFound("rejected change"))?;
            match &sess.outbox.rejected[i].op {
                ChangeOp::Upsert { payload } | ChangeOp::Restore { payload } => payload.clone(),
                ChangeOp::Delete => return Err(VaultError::InvalidInput("nothing to restore")),
            }
        };
        {
            let mut g = self.lock_inner();
            if let Some(sess) = g.session.as_mut() {
                sess.outbox.rejected.retain(|r| &r.entry_id != entry_id);
            }
        }
        self.queue_change(entry_id.clone(), ChangeOp::Restore { payload })?;
        if self.cfg.auto_sync {
            let _ = self.sync().await;
        }
        Ok(())
    }

    /// Discard a rejected edit.
    pub fn discard_rejected(&self, entry_id: &EntryId) -> Result<()> {
        let mut g = self.lock_inner();
        let device_id = g
            .device
            .as_ref()
            .ok_or(VaultError::NoVault)?
            .device_id
            .clone();
        let vault_id = g
            .state
            .as_ref()
            .ok_or(VaultError::NoVault)?
            .vault_id
            .clone();
        let sess = g.session.as_mut().ok_or(VaultError::Locked)?;
        let mut next = sess.outbox.clone();
        next.rejected.retain(|r| &r.entry_id != entry_id);
        outbox::save(
            &self.outbox_path(),
            &sess.local_key,
            &vault_id,
            &device_id,
            &next,
        )?;
        sess.outbox = next;
        Ok(())
    }

    // ---------------------------------------------------------------------------------
    // sync
    // ---------------------------------------------------------------------------------

    /// Pull, verify, push the outbox (rebase + merge), and refresh the local view. Never
    /// returns an error for operational failures — the report carries the status.
    pub async fn sync(&self) -> Result<SyncReport> {
        let _op = self.op.lock().await;
        if !self.is_unlocked() {
            return Err(if self.has_vault() {
                VaultError::Locked
            } else {
                VaultError::NoVault
            });
        }
        self.sync_locked().await
    }

    pub(crate) async fn sync_locked(&self) -> Result<SyncReport> {
        let (device, state) = self.snapshot()?;
        if state.revoked {
            return Err(VaultError::Revoked);
        }
        let result = self.sync_inner(&device, &state).await;
        let mut st = self.snapshot()?.1;
        match result {
            Ok(mut report) => {
                st.last_error = None;
                st.rollback_detected = false;
                self.save_state(&st)?;
                self.lock_inner().state = Some(st);
                if report.conflicts > 0 && report.status == SyncStatus::Ok {
                    report.status = SyncStatus::Conflict;
                }
                Ok(report)
            }
            Err(VaultError::Revoked) => {
                self.handle_revoked()?;
                Err(VaultError::Revoked)
            }
            Err(e) => {
                let status = match &e {
                    VaultError::Rollback(_) => {
                        st.rollback_detected = true;
                        SyncStatus::RollbackDetected
                    }
                    e if e.is_offline() => SyncStatus::Offline,
                    _ => SyncStatus::Error,
                };
                st.last_error = Some(e.code().as_str().to_owned());
                self.save_state(&st)?;
                self.lock_inner().state = Some(st);
                tracing::warn!(error = %e, "sync failed");
                let conflicts = self.status().conflicts.unwrap_or(0);
                Ok(SyncReport {
                    status,
                    pulled: 0,
                    pushed: 0,
                    conflicts,
                    rejected: Vec::new(),
                    delete_skipped: Vec::new(),
                    error_code: Some(e.code().as_str().to_owned()),
                    message: Some(e.localized()),
                })
            }
        }
    }

    async fn sync_inner(&self, device: &DeviceFile, state: &StateFile) -> Result<SyncReport> {
        let (view, vault, outbox) = {
            let g = self.lock_inner();
            let sess = g.session.as_ref();
            (
                g.view.clone(),
                sess.map(|s| s.vault.clone()),
                sess.map(|s| s.outbox.clone()),
            )
        };
        let identity = match &vault {
            Some(v) => v.identity().clone(),
            None => return Err(VaultError::Locked),
        };
        let ctx = StoreContext {
            vault_id: state.vault_id.clone(),
            device_id: Some(device.device_id.clone()),
            identity: Some(identity),
        };
        let engine = self.engine_for(state, ctx).await;
        let start = match view {
            Some(v) => v,
            None => {
                let cp = state
                    .checkpoint
                    .clone()
                    .ok_or(VaultError::Integrity("no checkpoint"))?;
                engine.cached_view(&cp).await?
            }
        };
        let now = aipass_types::time::now();
        let stale = state
            .membership_verified_at
            .or(state.last_sync_at)
            .is_none_or(|t| (now - t).num_days() > OFFLINE_LIMIT_DAYS);
        if stale {
            // long offline: re-verify the pinned header and our own membership before
            // anything is pushed (design doc §10.4)
            engine.recheck_header().await?;
        }

        let mut report = SyncReport {
            status: SyncStatus::Ok,
            pulled: 0,
            pushed: 0,
            conflicts: 0,
            rejected: Vec::new(),
            delete_skipped: Vec::new(),
            error_code: None,
            message: None,
        };
        let (new_view, pulled, vault_after, applied) = match (vault, outbox) {
            (Some(mut vault), Some(outbox)) if !outbox.is_empty() => {
                // verify membership on a fresh pull before pushing anything
                let (pre, pre_stats) = engine.pull(&start).await?;
                if pre.is_revoked(&device.device_id) {
                    return Err(VaultError::Revoked);
                }
                if !pre.is_active_approver(&device.device_id) {
                    return Err(VaultError::Forbidden(
                        "this device may not write to the vault",
                    ));
                }
                let mut planner = OutboxPlanner::new(outbox.changes.clone());
                let out = engine.commit(&pre, &mut vault, &mut planner).await?;
                let mut pulled = pre_stats;
                merge_stats(&mut pulled, out.pulled);
                (
                    out.view,
                    pulled,
                    Some(vault),
                    Some((outbox, planner.report)),
                )
            }
            (vault, _) => {
                let (v, st) = engine.pull(&start).await?;
                let vault = match vault {
                    Some(mut vlt) => {
                        if v.is_revoked(&device.device_id) {
                            return Err(VaultError::Revoked);
                        }
                        engine.refresh_keys(&v, &mut vlt).await?;
                        Some(vlt)
                    }
                    None => None,
                };
                (v, st, vault, None)
            }
        };
        if new_view.is_revoked(&device.device_id) {
            return Err(VaultError::Revoked);
        }
        report.pulled = pulled.changed_entries.len() as u32;

        // write queued standalone objects (e.g. a recovery wrap for the current epoch)
        let mut st = self.snapshot()?.1;
        let mut written = Vec::new();
        for (k, b64) in &st.pending_objects {
            if let Ok(bytes) = aipass_crypto::b64u::decode(b64) {
                match engine.put_create_only(k, bytes).await {
                    Ok(_) => written.push(k.clone()),
                    Err(e) if e.is_offline() => {}
                    Err(e) => {
                        tracing::warn!(error = %e, key = %k, "pending object could not be written");
                        written.push(k.clone());
                    }
                }
            }
        }
        for k in written {
            st.pending_objects.remove(&k);
        }
        st.checkpoint = new_view.checkpoint();
        st.last_sync_at = Some(now);
        st.membership_verified_at = Some(now);
        self.save_state(&st)?;

        // refresh the decrypted cache and the outbox
        let mut g_items = None;
        if let Some(vault) = &vault_after {
            let existing = {
                let g = self.lock_inner();
                g.session
                    .as_ref()
                    .map(|s| {
                        s.items
                            .iter()
                            .map(|(k, v)| (k.clone(), (v.version, v.key_epoch)))
                            .collect::<BTreeMap<_, _>>()
                    })
                    .unwrap_or_default()
            };
            g_items = Some(decrypt_all_reuse(&engine, &new_view, vault, &existing, self).await?);
        }
        let mut g = self.lock_inner();
        g.state = Some(st);
        g.view = Some(new_view.clone());
        if let (Some(sess), Some(vault)) = (g.session.as_mut(), vault_after) {
            sess.vault = vault;
            if let Some(items) = g_items {
                let mut merged: BTreeMap<EntryId, CachedItem> = BTreeMap::new();
                let mut old = std::mem::take(&mut sess.items);
                for (id, upd) in items {
                    match upd {
                        Some(ci) => {
                            merged.insert(id, ci);
                        }
                        None => {
                            if let Some(mut keep) = old.remove(&id) {
                                if let Some(me) = new_view.manifest.entries.get(&id) {
                                    keep.conflict_versions = me.conflict_versions.clone();
                                }
                                merged.insert(id, keep);
                            }
                        }
                    }
                }
                sess.items = merged;
            }
            if let Some((sent, applied)) = applied {
                let mut next = sess.outbox.clone();
                // drop the changes that were part of this push (newer local edits stay)
                next.changes.retain(|c| !sent.changes.contains(c));
                for (eid, tv) in &applied.rejected {
                    if let Some(c) = sent.changes.iter().find(|c| &c.entry_id == eid) {
                        next.rejected.retain(|r| &r.entry_id != eid);
                        next.rejected.push(crate::outbox::RejectedChange {
                            entry_id: eid.clone(),
                            op: c.op.clone(),
                            tombstone_version: *tv,
                            rejected_at: now,
                        });
                    }
                }
                outbox::save(
                    &self.outbox_path(),
                    &sess.local_key,
                    &state.vault_id,
                    &device.device_id,
                    &next,
                )?;
                sess.outbox = next;
                report.pushed = (applied.applied.len()) as u32;
                report.rejected = applied.rejected.iter().map(|(e, _)| e.clone()).collect();
                report.delete_skipped = applied.delete_skipped.clone();
            }
        }
        report.conflicts = new_view.conflicted_entries().len() as u32;
        Ok(report)
    }

    /// The device learned it was revoked: drop keys, local caches and secrets (best
    /// effort — data the device already had cannot be guaranteed erased).
    pub(crate) fn handle_revoked(&self) -> Result<()> {
        let mut g = self.lock_inner();
        g.session = None;
        g.view = None;
        if let Some(st) = g.state.as_mut() {
            st.revoked = true;
            st.checkpoint = None;
            let st2 = st.clone();
            write_json(&self.cfg.data_dir.join("state.json"), &st2)?;
            let _ = self.secrets.delete(&local_key_name(&st2.vault_id));
            let _ = self.secrets.delete(&storage_secret_key(&st2.vault_id));
            let _ = self.secrets.delete(&recovery_pending_key(&st2.vault_id));
        }
        if let Some(d) = g.device.as_ref() {
            let _ = self.secrets.delete(&device_secret_key(&d.device_id));
        }
        let _ = std::fs::remove_dir_all(self.cfg.data_dir.join("cache"));
        let _ = std::fs::remove_file(self.outbox_path());
        Ok(())
    }

    pub(crate) fn complete_rotation_task(&self, entry_id: &EntryId) -> Result<()> {
        let mut g = self.lock_inner();
        if let Some(st) = g.state.as_mut()
            && st.rotation_tasks.iter().any(|t| &t.entry_id == entry_id)
        {
            st.rotation_tasks.retain(|t| &t.entry_id != entry_id);
            let s = st.clone();
            drop(g);
            self.save_state(&s)?;
        }
        Ok(())
    }
}

fn merge_stats(a: &mut PullStats, b: PullStats) {
    a.manifests += b.manifests;
    a.changed_entries.extend(b.changed_entries);
    a.members_changed |= b.members_changed;
    a.epoch_changed |= b.epoch_changed;
}

fn summary(id: &EntryId, e: &Effective) -> ItemSummary {
    let p = &e.payload;
    ItemSummary {
        entry_id: id.clone(),
        kind: p.kind,
        title: p.title.clone(),
        username: p.username.clone(),
        primary_url: p.urls.first().cloned(),
        project_id: p.project_id.clone(),
        lifecycle: p.lifecycle,
        has_conflict: !e.conflict_versions.is_empty(),
        pending_sync: e.pending,
        tags: p.tags.clone(),
        updated_at: p.updated_at,
    }
}

/// Decrypt every current entry of `view`.
pub(crate) async fn decrypt_all(
    engine: &SyncEngine,
    view: &VaultView,
    vault: &UnlockedVault,
    _existing: &BTreeMap<EntryId, (u64, u32)>,
) -> Result<BTreeMap<EntryId, CachedItem>> {
    let mut out = BTreeMap::new();
    for (id, me) in &view.manifest.entries {
        let ev = engine.entry_object(view, id, me.version).await?;
        let payload = vault.decrypt_entry(id, me.version, &ev)?;
        out.insert(
            id.clone(),
            CachedItem {
                version: me.version,
                key_epoch: ev.key_epoch,
                payload,
                conflict_versions: me.conflict_versions.clone(),
            },
        );
    }
    Ok(out)
}

/// Decrypt only entries whose version changed; `None` = keep the cached payload.
async fn decrypt_all_reuse(
    engine: &SyncEngine,
    view: &VaultView,
    vault: &UnlockedVault,
    existing: &BTreeMap<EntryId, (u64, u32)>,
    _client: &VaultClient,
) -> Result<BTreeMap<EntryId, Option<CachedItem>>> {
    let mut out = BTreeMap::new();
    for (id, me) in &view.manifest.entries {
        if existing.get(id).is_some_and(|(v, _)| *v == me.version) {
            out.insert(id.clone(), None);
            continue;
        }
        let ev = engine.entry_object(view, id, me.version).await?;
        let payload = vault.decrypt_entry(id, me.version, &ev)?;
        out.insert(
            id.clone(),
            Some(CachedItem {
                version: me.version,
                key_epoch: ev.key_epoch,
                payload,
                conflict_versions: me.conflict_versions.clone(),
            }),
        );
    }
    Ok(out)
}

pub(crate) fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<Option<T>> {
    match aipass_vault::fsutil::read_optional(path)? {
        Some(b) => Ok(Some(serde_json::from_slice(&b).map_err(|_| {
            VaultError::Integrity("local state file is not valid")
        })?)),
        None => Ok(None),
    }
}

pub(crate) fn write_json<T: Serialize>(path: &Path, v: &T) -> Result<()> {
    let b = serde_json::to_vec_pretty(v).map_err(|_| VaultError::Internal("encode"))?;
    aipass_vault::fsutil::write_private_atomic(path, &b)
}
