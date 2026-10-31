// SPDX-License-Identifier: Apache-2.0
//! `AppCore`: the Rust side of the desktop app. It owns the vault client, the lockable
//! secret store, the embedded node and every sensitive operation. Tauri commands are thin
//! wrappers around these methods (see `commands.rs`), which keeps the logic testable
//! without a WebView.
//!
//! WebView rule: nothing returned from here contains a secret value, except
//! [`AppCore::reveal_secret`] (requires a fresh re-authentication) and the one-time
//! recovery key of [`AppCore::create_vault`]. Copies go straight from Rust to the OS
//! clipboard; generated passwords stay in Rust behind short-lived handles.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use aipass_crypto::{DeviceIdentity, SecretString, password::Argon2Params};
use aipass_storage::{CapabilityReport, StorageKind, StorageProfile};
use aipass_sync::{
    ClientConfig, ConflictInfo, CoreStatus, DeviceFile, DeviceInfo, FieldInput, ItemDetail,
    ItemInput, ItemSummary, KnownExecutor, MigrationReport, RevokeResult, SecretField,
    StandardStoreFactory, StoreFactory, SyncReport, VaultClient,
};
use aipass_types::ids::{DeviceId, EntryId, ExecutorId, ProjectId};
use aipass_types::vault::{DatabaseInfo, DevicePublic, EntryKind, MemberStatus, PasswordRules, Platform};
use aipass_vault::import::{CsvFormat, ImportReport};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::task::JoinHandle;
use zeroize::Zeroizing;

use crate::clipboard::ClipboardGuard;
use crate::error::{UiError, UiResult};
use crate::node::EmbeddedNode;
use crate::paths::AppPaths;
use crate::secrets::LockableSecretStore;
use crate::settings::Settings;

/// Re-authentication stays valid this long.
pub const REAUTH_WINDOW: Duration = Duration::from_secs(60);
/// Consecutive wrong presence confirmations (approval decisions) before the app locks itself.
pub const PRESENCE_MAX_FAILURES: u32 = 5;
/// Generated-password handles expire after this long.
pub const GENERATED_TTL: Duration = Duration::from_secs(600);
/// Background sync interval while unlocked.
pub const SYNC_INTERVAL: Duration = Duration::from_secs(60);
/// Keep the embedded broker's approvers in step with the verified vault member chain: a
/// device that was revoked (or is no longer an owner / member) on *any* trusted device
/// stops being able to approve here — its decisions are refused and the grants it approved
/// are revoked by the broker. Returns how many approvers were revoked.
pub async fn reconcile_approvers(vault: &VaultClient, broker: &aipass_broker::Broker) -> UiResult<usize> {
    let members = vault.devices()?;
    let mut revoked = 0;
    for d in broker.list_devices().await?.devices {
        if d.status != MemberStatus::Active {
            continue;
        }
        let Some(m) = members.iter().find(|m| m.device_id == d.device.device_id) else {
            continue;
        };
        if m.status == MemberStatus::Revoked || !m.role.is_trusted_approver() {
            broker.revoke_device(&aipass_broker::Actor::System, &d.device.device_id).await?;
            revoked += 1;
        }
    }
    Ok(revoked)
}

/// Secret-store key of the embedded executor identity.
pub fn executor_secret_key(exe: &ExecutorId) -> String {
    format!("aipass.desktop.executor.{exe}")
}
/// Secret-store key of the cloud session token.
pub const CLOUD_SESSION_KEY: &str = "aipass.desktop.cloud-session";

/// Events emitted to the UI (metadata only).
pub trait EventSink: Send + Sync {
    /// Emit `event` with a JSON payload that contains no secret values.
    fn emit(&self, event: &str, payload: Value);
}

/// Sink that drops events (tests, headless).
#[derive(Debug, Default)]
pub struct NullSink;
impl EventSink for NullSink {
    fn emit(&self, _event: &str, _payload: Value) {}
}

/// Construction options.
pub struct CoreOptions {
    /// Data root.
    pub paths: AppPaths,
    /// Platform reported to the vault.
    pub platform: Platform,
    /// App version.
    pub app_version: String,
    /// Argon2id parameters for the local secret store and vault (tests use the fast set).
    pub argon2: Argon2Params,
    /// Serve the broker on `<home>/run/broker.sock`.
    pub serve_broker_socket: bool,
    /// Storage factory (tests may inject a memory factory).
    pub store_factory: Option<Arc<dyn StoreFactory>>,
    /// Event sink.
    pub sink: Arc<dyn EventSink>,
}

/// Overall state for the UI.
#[derive(Debug, Clone, Serialize)]
pub struct AppStatus {
    /// A vault exists on this device.
    pub has_vault: bool,
    /// Unlocked.
    pub unlocked: bool,
    /// Vault status (no secrets).
    pub core: CoreStatus,
    /// Embedded node running.
    pub node_running: bool,
    /// Embedded executor id.
    pub executor_id: Option<ExecutorId>,
    /// Onboarding finished.
    pub onboarding_done: bool,
    /// UI language.
    pub lang: String,
    /// App version.
    pub version: String,
    /// Data root (for diagnostics).
    pub home: String,
    /// Cloud account e-mail when signed in.
    pub cloud_email: Option<String>,
    /// Relay configured for phone approvals.
    pub relay_url: Option<String>,
}

/// Storage selection from the UI. Secrets are only ever sent *into* Rust.
#[derive(Clone, Deserialize)]
pub struct StorageInput {
    /// local | official | s3 | selfhost (webdav is experimental and not offered here).
    pub kind: StorageKind,
    /// Local folder (kind local); default `<home>/storage`.
    #[serde(default)]
    pub path: Option<String>,
    /// S3 endpoint URL.
    #[serde(default)]
    pub endpoint: Option<String>,
    /// S3 region.
    #[serde(default)]
    pub region: Option<String>,
    /// S3 bucket.
    #[serde(default)]
    pub bucket: Option<String>,
    /// S3 key prefix.
    #[serde(default)]
    pub prefix: Option<String>,
    /// S3 path-style addressing.
    #[serde(default)]
    pub path_style: Option<bool>,
    /// S3 access key id.
    #[serde(default)]
    pub access_key_id: Option<String>,
    /// S3 secret key, or a self-host enrolment token.
    #[serde(default)]
    pub secret: Option<SecretString>,
    /// Self-hosted node base URL (kind selfhost).
    #[serde(default)]
    pub base_url: Option<String>,
}

impl std::fmt::Debug for StorageInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StorageInput").field("kind", &self.kind).finish_non_exhaustive()
    }
}

/// Vault creation input.
#[derive(Deserialize)]
pub struct CreateVaultInput {
    /// Device display name.
    pub device_name: String,
    /// Local unlock password (protects the device key on this computer).
    pub unlock_password: SecretString,
    /// Storage.
    pub storage: StorageInput,
    /// Optional vault master password (an extra unlock path; never required).
    #[serde(default)]
    pub master_password: Option<SecretString>,
}

/// Result of vault creation. `recovery_key` is shown exactly once in onboarding.
#[derive(Serialize)]
pub struct CreateVaultOutput {
    /// Vault.
    pub vault_id: String,
    /// Device.
    pub device_id: String,
    /// `AIPR-…` recovery key — the only time it is returned.
    pub recovery_key: String,
}

/// Item editor input.
#[derive(Deserialize)]
pub struct ItemForm {
    /// Existing entry to update.
    #[serde(default)]
    pub entry_id: Option<EntryId>,
    /// Kind.
    pub kind: EntryKind,
    /// Title.
    pub title: String,
    /// Username.
    #[serde(default)]
    pub username: Option<String>,
    /// New secret typed by the user (`None` keeps the current one).
    #[serde(default)]
    pub secret: Option<SecretString>,
    /// Handle of a password generated in Rust (takes precedence over `secret`).
    #[serde(default)]
    pub secret_ref: Option<String>,
    /// Remove the secret.
    #[serde(default)]
    pub clear_secret: bool,
    /// Website URLs.
    #[serde(default)]
    pub urls: Vec<String>,
    /// Notes.
    #[serde(default)]
    pub notes: Option<String>,
    /// New TOTP seed or otpauth:// URI (`None` keeps).
    #[serde(default)]
    pub totp: Option<SecretString>,
    /// Remove TOTP.
    #[serde(default)]
    pub clear_totp: bool,
    /// Project.
    #[serde(default)]
    pub project_id: Option<ProjectId>,
    /// Tags.
    #[serde(default)]
    pub tags: Vec<String>,
    /// Database connection info (non-secret).
    #[serde(default)]
    pub database: Option<DatabaseInfo>,
    /// Password rules remembered for this site.
    #[serde(default)]
    pub password_rules: Option<PasswordRules>,
}

/// A generated password as the UI sees it.
#[derive(Debug, Clone, Serialize)]
pub struct GeneratedPassword {
    /// Opaque handle (`gen_…`) for save / copy.
    pub handle: String,
    /// Length in characters.
    pub length: usize,
    /// Masked preview.
    pub masked: String,
}

/// TOTP code view.
#[derive(Debug, Clone, Serialize)]
pub struct TotpView {
    /// Current code (short-lived; shown like any authenticator app).
    pub code: String,
    /// Seconds left.
    pub remaining_seconds: u32,
    /// Period.
    pub period: u32,
}

struct GeneratedSlot {
    secret: SecretString,
    created: Instant,
}

/// Mutable runtime state.
#[derive(Default)]
struct Runtime {
    reauth_until: Option<Instant>,
    /// Consecutive failed presence confirmations (see [`AppCore::confirm_presence`]).
    presence_failures: u32,
    generated: HashMap<String, GeneratedSlot>,
    sync_task: Option<JoinHandle<()>>,
    cloud_session: Option<SecretString>,
    last_activity: Option<Instant>,
    relay: Option<(tokio_util::sync::CancellationToken, JoinHandle<()>)>,
}

/// The desktop core.
pub struct AppCore {
    pub(crate) paths: AppPaths,
    pub(crate) app_version: String,
    pub(crate) serve_broker_socket: bool,
    pub(crate) settings: Mutex<Settings>,
    pub(crate) secrets: Arc<LockableSecretStore>,
    pub(crate) vault: Arc<VaultClient>,
    pub(crate) node: tokio::sync::Mutex<Option<Arc<EmbeddedNode>>>,
    pub(crate) sink: Arc<dyn EventSink>,
    runtime: Mutex<Runtime>,
    pub(crate) clipboard: ClipboardGuard,
    pub(crate) host_plans: Mutex<HashMap<String, crate::core_ai::PendingPlan>>,
    pub(crate) pairing: tokio::sync::Mutex<crate::core_pair::PairingState>,
    pub(crate) nm_limiter: crate::nm_server::RateLimiter,
    pub(crate) tunnel: tokio::sync::Mutex<Option<crate::tunnel::RunningTunnel>>,
}

impl std::fmt::Debug for AppCore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppCore").field("home", &self.paths.home).finish_non_exhaustive()
    }
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

impl AppCore {
    /// Open the core on `opts.paths` (does not unlock anything).
    pub fn open(opts: CoreOptions) -> UiResult<Arc<Self>> {
        crate::paths::ensure_private_dir(opts.paths.home())?;
        crate::paths::ensure_private_dir(&opts.paths.vault_dir())?;
        let settings = Settings::load(&opts.paths.settings_file())?;
        let secrets = Arc::new(LockableSecretStore::new(opts.paths.secrets_file(), opts.argon2));
        let mut cfg = ClientConfig::new(opts.paths.vault_dir(), opts.platform, opts.app_version.clone());
        cfg.argon2 = opts.argon2;
        let factory: Arc<dyn StoreFactory> = opts
            .store_factory
            .unwrap_or_else(|| Arc::new(StandardStoreFactory { allow_http: false }));
        let store: Arc<dyn aipass_vault::SecretStore> = secrets.clone();
        let vault = Arc::new(VaultClient::open(cfg, store, factory)?);
        Ok(Arc::new(Self {
            paths: opts.paths,
            app_version: opts.app_version,
            serve_broker_socket: opts.serve_broker_socket,
            settings: Mutex::new(settings),
            secrets,
            vault,
            node: tokio::sync::Mutex::new(None),
            sink: opts.sink,
            runtime: Mutex::new(Runtime::default()),
            clipboard: ClipboardGuard::default(),
            host_plans: Mutex::new(HashMap::new()),
            pairing: tokio::sync::Mutex::new(crate::core_pair::PairingState::default()),
            nm_limiter: crate::nm_server::RateLimiter::default(),
            tunnel: tokio::sync::Mutex::new(None),
        }))
    }

    /// Paths.
    pub fn paths(&self) -> &AppPaths {
        &self.paths
    }

    /// The vault client (for in-crate helpers and tests).
    pub fn vault(&self) -> &Arc<VaultClient> {
        &self.vault
    }

    /// Settings snapshot.
    pub fn settings(&self) -> Settings {
        lock(&self.settings).clone()
    }

    /// Update settings after validation.
    pub fn update_settings(&self, new: Settings) -> UiResult<Settings> {
        new.validate()?;
        let mut g = lock(&self.settings);
        // Fields managed by the app itself are not user-editable.
        let mut merged = new;
        merged.executor_id = g.executor_id.clone();
        merged.license_token = g.license_token.clone();
        merged.license_public_key = g.license_public_key.clone();
        merged.cloud_email = g.cloud_email.clone();
        merged.save(&self.paths.settings_file())?;
        *g = merged.clone();
        Ok(merged)
    }

    pub(crate) fn mutate_settings(&self, f: impl FnOnce(&mut Settings)) -> UiResult<()> {
        let mut g = lock(&self.settings);
        f(&mut g);
        g.save(&self.paths.settings_file())
    }

    /// Status for the UI.
    pub async fn status(&self) -> AppStatus {
        let node = self.node.lock().await.clone();
        let s = self.settings();
        AppStatus {
            has_vault: self.vault.has_vault(),
            unlocked: self.is_unlocked(),
            core: self.vault.status(),
            node_running: node.is_some(),
            executor_id: node.map(|n| n.executor_id.clone()).or(s.executor_id.clone()),
            onboarding_done: s.onboarding_done,
            lang: s.lang,
            version: self.app_version.clone(),
            home: self.paths.home.display().to_string(),
            cloud_email: s.cloud_email,
            relay_url: s.relay_url,
        }
    }

    /// Vault and secret store both open.
    pub fn is_unlocked(&self) -> bool {
        self.secrets.is_open() && self.vault.is_unlocked()
    }

    pub(crate) fn require_unlocked(&self) -> UiResult<()> {
        if self.is_unlocked() {
            self.touch();
            Ok(())
        } else {
            Err(UiError::locked())
        }
    }

    /// Record user activity (auto-lock timer).
    pub fn touch(&self) {
        lock(&self.runtime).last_activity = Some(Instant::now());
    }

    /// Lock when idle longer than the configured auto-lock time. Returns true if it locked.
    pub async fn auto_lock_tick(&self) -> bool {
        let secs = self.settings().auto_lock_secs;
        if secs == 0 || !self.is_unlocked() {
            return false;
        }
        let idle = lock(&self.runtime).last_activity.map(|t| t.elapsed()).unwrap_or_default();
        if idle >= Duration::from_secs(secs) {
            self.lock_app().await;
            return true;
        }
        false
    }

    // ------------------------------------------------------------------------------
    // lifecycle
    // ------------------------------------------------------------------------------

    /// Build a storage profile + secret from UI input.
    pub(crate) fn storage_profile(&self, input: &StorageInput) -> UiResult<(StorageProfile, Option<SecretString>)> {
        let mut p = StorageProfile::new(input.kind);
        let mut secret = input.secret.clone();
        match input.kind {
            StorageKind::Local => {
                let path = input
                    .path
                    .as_deref()
                    .filter(|s| !s.trim().is_empty())
                    .map(PathBuf::from)
                    .unwrap_or_else(|| self.paths.default_local_storage());
                if !path.is_absolute() {
                    return Err(UiError::invalid("本地文件夹必须是绝对路径", "The local folder must be an absolute path"));
                }
                p.path = Some(path.display().to_string());
                secret = None;
            }
            StorageKind::S3 => {
                let endpoint = input.endpoint.clone().filter(|s| !s.is_empty()).ok_or_else(|| {
                    UiError::invalid("请填写 S3 端点地址", "Enter the S3 endpoint URL")
                })?;
                let u = url::Url::parse(&endpoint).map_err(|_| UiError::invalid("S3 端点地址无效", "Invalid S3 endpoint URL"))?;
                if u.scheme() != "https" {
                    return Err(UiError::invalid("S3 端点必须使用 https", "The S3 endpoint must use https"));
                }
                p.endpoint = Some(endpoint);
                p.region = input.region.clone().filter(|s| !s.is_empty());
                p.bucket = Some(input.bucket.clone().filter(|s| !s.is_empty()).ok_or_else(|| {
                    UiError::invalid("请填写存储桶名称", "Enter the bucket name")
                })?);
                p.prefix = input.prefix.clone().filter(|s| !s.is_empty());
                p.path_style = input.path_style;
                p.username = Some(input.access_key_id.clone().filter(|s| !s.is_empty()).ok_or_else(|| {
                    UiError::invalid("请填写 Access Key ID", "Enter the access key id")
                })?);
                if secret.as_ref().is_none_or(|s| s.expose().is_empty()) {
                    return Err(UiError::invalid("请填写 Secret Access Key", "Enter the secret access key"));
                }
            }
            StorageKind::Official => {
                p.base_url = Some(self.settings().cloud_url);
                secret = lock(&self.runtime).cloud_session.clone();
                if secret.is_none() {
                    return Err(UiError::new(
                        "UNAUTHENTICATED",
                        "官方同步需要先登录 AI 通行证账户（设置 → 云账户）。",
                        "Official sync needs an AI Pass account sign-in first (Settings → Cloud account).",
                    ));
                }
            }
            StorageKind::Selfhost => {
                let base = input.base_url.clone().filter(|s| !s.is_empty()).ok_or_else(|| {
                    UiError::invalid("请填写自托管节点地址", "Enter the self-hosted node URL")
                })?;
                let u = url::Url::parse(&base).map_err(|_| UiError::invalid("节点地址无效", "Invalid node URL"))?;
                if u.scheme() != "https" {
                    return Err(UiError::invalid("自托管节点必须使用 https", "The self-hosted node must use https"));
                }
                p.base_url = Some(base);
            }
            StorageKind::Webdav => {
                return Err(UiError::new(
                    "NOT_SUPPORTED",
                    "WebDAV 为实验性功能，桌面 App 暂不提供。",
                    "WebDAV is experimental and not offered in the desktop app.",
                ));
            }
        }
        Ok((p, secret))
    }

    /// Run the storage capability test (CONTRACTS §3.1) before using a location.
    pub async fn test_storage(&self, input: StorageInput) -> UiResult<CapabilityReport> {
        let (p, s) = self.storage_profile(&input)?;
        if p.kind == StorageKind::Local
            && let Some(path) = &p.path
        {
            crate::paths::ensure_private_dir(std::path::Path::new(path))?;
        }
        Ok(self.vault.test_storage(&p, s.as_ref()).await?)
    }

    /// Create the vault, the local secret store and start the node.
    pub async fn create_vault(&self, input: CreateVaultInput) -> UiResult<CreateVaultOutput> {
        if self.vault.has_vault() {
            return Err(UiError::new("CONFLICT", "此设备上已有账号库。", "A vault already exists on this device."));
        }
        let name = input.device_name.trim();
        if name.is_empty() || name.chars().count() > 64 {
            return Err(UiError::invalid("设备名称需为 1–64 个字符", "Device name must be 1–64 characters"));
        }
        let (profile, storage_secret) = self.storage_profile(&input.storage)?;
        if profile.kind == StorageKind::Local
            && let Some(path) = &profile.path
        {
            crate::paths::ensure_private_dir(std::path::Path::new(path))?;
        }
        if !self.secrets.exists() {
            self.secrets.create(&input.unlock_password)?;
        } else {
            self.secrets.open(&input.unlock_password)?;
        }
        let cloud = lock(&self.runtime).cloud_session.clone();
        if let Some(tok) = &cloud {
            aipass_vault::SecretStore::set(&*self.secrets, CLOUD_SESSION_KEY, tok.expose().as_bytes(), false)?;
        }
        let res = self
            .vault
            .create_vault(name, profile, storage_secret, input.master_password)
            .await?;
        if !self.vault.is_unlocked() {
            self.vault.unlock().await?;
        }
        self.after_unlock().await?;
        Ok(CreateVaultOutput {
            vault_id: res.vault_id.to_string(),
            device_id: res.device_id.to_string(),
            recovery_key: res.recovery_key.expose().to_owned(),
        })
    }

    /// Unlock with the local unlock password.
    pub async fn unlock(&self, password: SecretString) -> UiResult<()> {
        if !self.vault.has_vault() {
            return Err(UiError::new("NO_VAULT", "此设备上还没有账号库。", "There is no vault on this device yet."));
        }
        self.secrets.open(&password).map_err(|e| match e {
            aipass_vault::VaultError::Invalid(_) => UiError::new(
                "UNAUTHENTICATED",
                "解锁密码不正确。",
                "The unlock password is incorrect.",
            ),
            other => other.into(),
        })?;
        if let Err(e) = self.vault.unlock().await {
            self.secrets.close();
            return Err(e.into());
        }
        self.after_unlock().await
    }

    pub(crate) async fn after_unlock(&self) -> UiResult<()> {
        self.touch();
        if let Ok(Some(tok)) = aipass_vault::SecretStore::get(&*self.secrets, CLOUD_SESSION_KEY)
            && let Ok(s) = String::from_utf8(tok.expose().to_vec())
        {
            lock(&self.runtime).cloud_session = Some(SecretString::new(s));
        }
        self.ensure_node().await?;
        if let Err(e) = self.enroll_embedded_executor().await {
            tracing::warn!(code = %e.code, "embedded executor not enrolled as vault member");
        }
        if let Err(e) = self.restart_relay().await {
            tracing::warn!(code = %e.code, "relay not started");
        }
        let broker = self.node.lock().await.as_ref().map(|n| n.broker.clone());
        if let Some(b) = &broker
            && let Err(e) = reconcile_approvers(&self.vault, b).await
        {
            tracing::warn!(code = %e.code, "approver reconciliation failed");
        }
        self.start_sync_loop(broker);
        self.sink.emit("app-status", json!({"unlocked": true}));
        Ok(())
    }

    /// Lock: close the vault session and the secret store. The embedded node keeps running
    /// (AI requests then wait for approval; approving needs an unlock).
    pub async fn lock_app(&self) {
        self.vault.lock();
        self.secrets.close();
        let mut rt = lock(&self.runtime);
        rt.reauth_until = None;
        rt.generated.clear();
        rt.cloud_session = None;
        if let Some(h) = rt.sync_task.take() {
            h.abort();
        }
        drop(rt);
        self.sink.emit("app-status", json!({"unlocked": false}));
    }

    /// Re-authenticate for sensitive actions (reveal / export) with the unlock password.
    pub fn reauth(&self, password: SecretString) -> UiResult<()> {
        self.require_unlocked()?;
        if !self.secrets.verify_password(&password) {
            return Err(UiError::new("UNAUTHENTICATED", "密码不正确。", "Incorrect password."));
        }
        lock(&self.runtime).reauth_until = Some(Instant::now() + REAUTH_WINDOW);
        Ok(())
    }

    /// Fresh user presence for ONE approval decision (§7.5 / §11.3, review CLI-01).
    ///
    /// Approving an AI request or a bridge connection must not be reachable by a single
    /// click on a WebView button: an agent that can drive the desktop (accessibility
    /// scripting, computer use) could otherwise approve its own request while the vault is
    /// unlocked. Every approve therefore carries the unlock password, verified here for that
    /// one call. The re-auth window used for reveal/export deliberately does NOT count: a
    /// recent reveal must not leave approvals open for a minute. Missing password →
    /// `REAUTH_REQUIRED`; wrong password → `UNAUTHENTICATED`, and after
    /// [`PRESENCE_MAX_FAILURES`] consecutive misses the app locks (guessing through the UI).
    pub(crate) async fn confirm_presence(&self, password: Option<&SecretString>) -> UiResult<()> {
        self.require_unlocked()?;
        let Some(pw) = password.filter(|p| !p.expose().is_empty()) else {
            return Err(UiError::reauth_required());
        };
        if self.secrets.verify_password(pw) {
            lock(&self.runtime).presence_failures = 0;
            return Ok(());
        }
        let failures = {
            let mut rt = lock(&self.runtime);
            rt.presence_failures = rt.presence_failures.saturating_add(1);
            rt.presence_failures
        };
        if failures >= PRESENCE_MAX_FAILURES {
            tracing::warn!(failures, "too many failed approval confirmations; locking");
            lock(&self.runtime).presence_failures = 0;
            self.lock_app().await;
            return Err(UiError::locked());
        }
        Err(UiError::new("UNAUTHENTICATED", "密码不正确。", "Incorrect password."))
    }

    pub(crate) fn require_reauth(&self) -> UiResult<()> {
        self.require_unlocked()?;
        let ok = lock(&self.runtime).reauth_until.is_some_and(|t| Instant::now() < t);
        if ok { Ok(()) } else { Err(UiError::reauth_required()) }
    }

    fn start_sync_loop(&self, broker: Option<Arc<aipass_broker::Broker>>) {
        let vault = self.vault.clone();
        let sink = self.sink.clone();
        let h = tokio::spawn(async move {
            loop {
                if vault.is_unlocked()
                    && let Ok(r) = vault.sync().await
                {
                    sink.emit("sync", json!({"status": r.status, "pulled": r.pulled, "pushed": r.pushed, "conflicts": r.conflicts}));
                    if let Some(b) = &broker
                        && let Err(e) = reconcile_approvers(&vault, b).await
                    {
                        tracing::warn!(code = %e.code, "approver reconciliation failed");
                    }
                }
                tokio::time::sleep(SYNC_INTERVAL).await;
            }
        });
        let mut rt = lock(&self.runtime);
        if let Some(old) = rt.sync_task.replace(h) {
            old.abort();
        }
    }

    /// This desktop's device record as a broker approver.
    pub(crate) fn device_public(&self) -> UiResult<DevicePublic> {
        let bytes = std::fs::read(self.paths.vault_dir().join("device.json"))?;
        let d: DeviceFile = serde_json::from_slice(&bytes).map_err(|_| UiError::internal("device.json"))?;
        Ok(DevicePublic {
            device_id: d.device_id,
            name: d.name,
            platform: d.platform,
            role: d.role,
            sign_pk: d.sign_pk,
            kem_pk: d.kem_pk,
        })
    }

    /// Start the embedded node if it is not running (needs the secret store open).
    pub async fn ensure_node(&self) -> UiResult<Arc<EmbeddedNode>> {
        let mut g = self.node.lock().await;
        if let Some(n) = g.as_ref() {
            return Ok(n.clone());
        }
        let exe = match self.settings().executor_id {
            Some(e) => e,
            None => {
                let e = ExecutorId::generate();
                let e2 = e.clone();
                self.mutate_settings(|s| s.executor_id = Some(e2))?;
                e
            }
        };
        let key = executor_secret_key(&exe);
        let identity = match aipass_vault::SecretStore::get(&*self.secrets, &key)? {
            Some(b) => DeviceIdentity::from_secret_bytes(b.expose()).map_err(|_| UiError::internal("executor identity"))?,
            None => {
                let id = DeviceIdentity::generate();
                aipass_vault::SecretStore::set(&*self.secrets, &key, id.to_secret_bytes().expose(), false)?;
                id
            }
        };
        let public = identity.public();
        if self.vault.executor_keys(&exe).is_err() {
            self.vault.register_executor(
                &exe,
                KnownExecutor { name: crate::node::EXECUTOR_NAME.into(), sign_pk: public.sign_pk, kem_pk: public.kem_pk },
            )?;
        }
        let params = crate::node::NodeParams {
            node_dir: self.paths.node_dir(),
            broker_socket: self.serve_broker_socket.then(|| self.paths.broker_socket()),
            executor_id: exe,
            executor_identity: identity,
            trusted_device: self.device_public()?,
            notifier: Arc::new(crate::core_ai::UiNotifier { sink: self.sink.clone() }),
            credential_source: Some(Arc::new(crate::core_ai::VaultCredentialSource { vault: self.vault.clone() })),
            version: self.app_version.clone(),
        };
        let node = Arc::new(EmbeddedNode::start(params).await?);
        *g = Some(node.clone());
        Ok(node)
    }

    /// (Re)start the relay outbox + mailbox consumer for phone approvals when a relay URL is
    /// configured. Returns whether a relay is now running.
    pub async fn restart_relay(&self) -> UiResult<bool> {
        let old = lock(&self.runtime).relay.take();
        if let Some((t, h)) = old {
            t.cancel();
            h.abort();
        }
        let Some(url) = self.settings().relay_url.filter(|u| !u.is_empty()) else {
            return Ok(false);
        };
        let n = self.node().await?;
        let exe = n.executor_id.clone();
        let bytes = aipass_vault::SecretStore::get(&*self.secrets, &executor_secret_key(&exe))?
            .ok_or_else(|| UiError::internal("executor identity"))?;
        let id = Arc::new(DeviceIdentity::from_secret_bytes(bytes.expose()).map_err(|_| UiError::internal("executor identity"))?);
        let u = url::Url::parse(&url).map_err(|_| UiError::invalid("中继地址无效", "Invalid relay URL"))?;
        let signer: aipass_storage::http::DeviceSigner = id.clone();
        let client = Arc::new(
            aipass_storage::RelayClient::new(
                u,
                aipass_storage::relay_client::RelayAuth::Signed { kid: aipass_types::ids::PrincipalId::Executor(exe.clone()), signer },
            )
            .map_err(|e| UiError::from(aipass_types::ApiError::from(e)))?,
        );
        let mailbox = aipass_types::ids::MailboxId::Executor(exe);
        n.broker.set_relay(
            aipass_broker::RelayIdentity { mailbox: mailbox.clone(), identity: id },
            Arc::new(crate::relay::RelayOutbox { client: client.clone() }),
        );
        let token = tokio_util::sync::CancellationToken::new();
        let h = crate::relay::spawn_consumer(n.broker.clone(), client, mailbox, token.clone());
        lock(&self.runtime).relay = Some((token, h));
        Ok(true)
    }

    /// The running node.
    pub async fn node(&self) -> UiResult<Arc<EmbeddedNode>> {
        self.node.lock().await.clone().ok_or_else(UiError::node_not_running)
    }

    /// Shut everything down (app exit).
    pub async fn shutdown(&self) {
        if let Some(t) = self.tunnel.lock().await.take() {
            t.stop().await;
        }
        self.lock_app().await;
        if let Some(n) = self.node.lock().await.take() {
            n.stop().await;
        }
    }

    /// Cloud session token currently in memory.
    pub(crate) fn cloud_session(&self) -> Option<SecretString> {
        lock(&self.runtime).cloud_session.clone()
    }

    pub(crate) fn set_cloud_session(&self, token: Option<SecretString>) -> UiResult<()> {
        match &token {
            Some(t) if self.secrets.is_open() => {
                aipass_vault::SecretStore::set(&*self.secrets, CLOUD_SESSION_KEY, t.expose().as_bytes(), false)?;
            }
            None if self.secrets.is_open() => {
                aipass_vault::SecretStore::delete(&*self.secrets, CLOUD_SESSION_KEY)?;
            }
            _ => {}
        }
        lock(&self.runtime).cloud_session = token;
        Ok(())
    }

    // ------------------------------------------------------------------------------
    // recovery
    // ------------------------------------------------------------------------------

    /// Verify the recovery key the user typed back (mandatory onboarding step).
    pub fn verify_recovery_key(&self, key: &str) -> UiResult<bool> {
        self.require_unlocked()?;
        if key.len() > 256 {
            return Ok(false);
        }
        Ok(self.vault.verify_recovery_key(key)?)
    }

    /// Write the recovery kit text to `path` (0600). Contains the recovery key only while
    /// it is pending verification on this device.
    pub fn save_recovery_kit_to(&self, path: &std::path::Path) -> UiResult<()> {
        self.require_unlocked()?;
        let text = self.vault.recovery_kit_text(false)?;
        crate::paths::write_private(path, text.expose().as_bytes())?;
        Ok(())
    }

    /// Replace the recovery key (after re-authentication). Returns the new key once.
    pub async fn replace_recovery_key(&self) -> UiResult<String> {
        self.require_reauth()?;
        let r = self.vault.replace_recovery_key().await?;
        Ok(r.recovery_key.expose().to_owned())
    }

    // ------------------------------------------------------------------------------
    // items
    // ------------------------------------------------------------------------------

    /// List items (metadata only).
    pub fn list_items(&self, query: Option<String>, project: Option<ProjectId>) -> UiResult<Vec<ItemSummary>> {
        self.require_unlocked()?;
        let q = query.filter(|s| !s.trim().is_empty());
        if q.as_ref().is_some_and(|s| s.len() > 200) {
            return Err(UiError::invalid("搜索词过长", "Search text too long"));
        }
        Ok(self.vault.list_items(q.as_deref(), project.as_ref())?)
    }

    /// Item detail (secrets masked).
    pub fn get_item(&self, id: &EntryId) -> UiResult<ItemDetail> {
        self.require_unlocked()?;
        Ok(self.vault.get_item(id)?)
    }

    /// Create / update an item.
    pub async fn save_item(&self, form: ItemForm) -> UiResult<EntryId> {
        self.require_unlocked()?;
        let title = form.title.trim().to_owned();
        if title.is_empty() || title.chars().count() > 200 {
            return Err(UiError::invalid("名称需为 1–200 个字符", "Title must be 1–200 characters"));
        }
        if form.urls.len() > 20 || form.urls.iter().any(|u| u.len() > 2048) {
            return Err(UiError::invalid("网址过多或过长", "Too many or too long URLs"));
        }
        if form.notes.as_ref().is_some_and(|n| n.len() > 20_000) {
            return Err(UiError::invalid("备注过长", "Notes too long"));
        }
        let secret = match &form.secret_ref {
            Some(h) => Some(self.take_generated(h)?),
            None => form.secret.clone().filter(|s| !s.expose().is_empty()),
        };
        // Keep existing custom fields untouched (value None = keep).
        let (fields, lifecycle, source) = match &form.entry_id {
            Some(id) => {
                let d = self.vault.get_item(id)?;
                let f = d
                    .fields
                    .iter()
                    .map(|f| FieldInput { name: f.name.clone(), value: None, sensitive: f.sensitive })
                    .collect();
                (f, Some(d.summary.lifecycle), Some(d.source))
            }
            None => (Vec::new(), None, None),
        };
        let input = ItemInput {
            entry_id: form.entry_id,
            kind: form.kind,
            title,
            username: form.username.filter(|s| !s.is_empty()),
            secret,
            clear_secret: form.clear_secret,
            urls: form.urls.into_iter().map(|u| u.trim().to_owned()).filter(|u| !u.is_empty()).collect(),
            notes: form.notes,
            totp: form.totp.filter(|s| !s.expose().is_empty()),
            clear_totp: form.clear_totp,
            fields,
            database: form.database,
            project_id: form.project_id,
            tags: form.tags,
            lifecycle,
            password_rules: form.password_rules,
            source,
        };
        Ok(self.vault.save_item(input).await?)
    }

    /// Delete (tombstone) an item.
    pub async fn delete_item(&self, id: &EntryId) -> UiResult<()> {
        self.require_unlocked()?;
        Ok(self.vault.delete_item(id).await?)
    }

    /// Reveal a raw secret to the WebView — only after a fresh re-authentication.
    pub fn reveal_secret(&self, id: &EntryId, field: &str) -> UiResult<SecretString> {
        self.require_reauth()?;
        let f = SecretField::parse(field).ok_or_else(|| UiError::invalid("未知字段", "Unknown field"))?;
        Ok(self.vault.reveal_secret(id, &f)?)
    }

    /// Copy a secret straight to the OS clipboard (cleared after the configured delay).
    pub fn copy_secret(&self, id: &EntryId, field: &str) -> UiResult<u64> {
        self.require_unlocked()?;
        let secret = if field == "totp_code" {
            self.vault.totp_now(id)?.code
        } else if field == "username" {
            let d = self.vault.get_item(id)?;
            SecretString::new(d.summary.username.unwrap_or_default())
        } else {
            let f = SecretField::parse(field).ok_or_else(|| UiError::invalid("未知字段", "Unknown field"))?;
            self.vault.reveal_secret(id, &f)?
        };
        let secs = self.settings().clipboard_clear_secs;
        self.clipboard.copy(secret, Duration::from_secs(secs), self.sink.clone())?;
        Ok(secs)
    }

    /// Current TOTP code.
    pub fn totp_now(&self, id: &EntryId) -> UiResult<TotpView> {
        self.require_unlocked()?;
        let c = self.vault.totp_now(id)?;
        Ok(TotpView { code: c.code.expose().to_owned(), remaining_seconds: c.remaining_seconds, period: c.period })
    }

    /// Generate a password in Rust and return only a handle + masked preview.
    pub fn generate_password(&self, rules: PasswordRules) -> UiResult<GeneratedPassword> {
        self.require_unlocked()?;
        let secret = self.vault.generate_password(&rules)?;
        Ok(self.store_generated(secret))
    }

    pub(crate) fn store_generated(&self, secret: SecretString) -> GeneratedPassword {
        let handle = format!("gen_{}", hex::encode(aipass_crypto::rng::random_array::<16>()));
        let length = secret.expose().chars().count();
        let mut rt = lock(&self.runtime);
        rt.generated.retain(|_, s| s.created.elapsed() < GENERATED_TTL);
        rt.generated.insert(handle.clone(), GeneratedSlot { secret, created: Instant::now() });
        GeneratedPassword { handle, length, masked: "•".repeat(length.min(24)) }
    }

    fn take_generated(&self, handle: &str) -> UiResult<SecretString> {
        let mut rt = lock(&self.runtime);
        match rt.generated.remove(handle) {
            Some(s) if s.created.elapsed() < GENERATED_TTL => Ok(s.secret),
            _ => Err(UiError::invalid("生成的密码已过期，请重新生成", "The generated password expired; generate again")),
        }
    }

    /// Copy a generated password to the clipboard.
    pub fn copy_generated(&self, handle: &str) -> UiResult<u64> {
        self.require_unlocked()?;
        let secret = {
            let rt = lock(&self.runtime);
            rt.generated
                .get(handle)
                .filter(|s| s.created.elapsed() < GENERATED_TTL)
                .map(|s| s.secret.clone())
                .ok_or_else(|| UiError::invalid("生成的密码已过期", "The generated password expired"))?
        };
        let secs = self.settings().clipboard_clear_secs;
        self.clipboard.copy(secret, Duration::from_secs(secs), self.sink.clone())?;
        Ok(secs)
    }

    // ------------------------------------------------------------------------------
    // import / export
    // ------------------------------------------------------------------------------

    /// Import a CSV file (read in Rust; the WebView never sees its content).
    pub async fn import_csv_file(&self, format: &str, path: &std::path::Path) -> UiResult<ImportReport> {
        self.require_unlocked()?;
        let fmt = CsvFormat::parse(format).ok_or_else(|| UiError::invalid("不支持的格式", "Unsupported format"))?;
        let meta = std::fs::metadata(path)?;
        if meta.len() > 20 * 1024 * 1024 {
            return Err(UiError::invalid("文件过大（上限 20 MB）", "File too large (20 MB limit)"));
        }
        let bytes = Zeroizing::new(std::fs::read(path)?);
        Ok(self.vault.import_csv(fmt, &bytes).await?)
    }

    /// Export an encrypted `.aipassx` to `path` (re-authentication required).
    pub fn export_encrypted_to(&self, path: &std::path::Path, password: &SecretString) -> UiResult<()> {
        self.require_reauth()?;
        if password.expose().chars().count() < 10 {
            return Err(UiError::invalid("导出密码至少 10 个字符", "The export password needs at least 10 characters"));
        }
        let bytes = self.vault.export_encrypted(password)?;
        crate::paths::write_private(path, &bytes)?;
        Ok(())
    }

    /// Export plaintext CSV to `path` (re-authentication required; UI shows the warning).
    pub fn export_csv_to(&self, path: &std::path::Path) -> UiResult<()> {
        self.require_reauth()?;
        let bytes = self.vault.export_csv()?;
        crate::paths::write_private(path, &bytes)?;
        Ok(())
    }

    /// Import an `.aipassx` file.
    pub async fn import_encrypted_file(&self, path: &std::path::Path, password: &SecretString) -> UiResult<ImportReport> {
        self.require_unlocked()?;
        let bytes = std::fs::read(path)?;
        Ok(self.vault.import_encrypted(&bytes, password).await?)
    }

    // ------------------------------------------------------------------------------
    // sync, conflicts, devices, storage
    // ------------------------------------------------------------------------------

    /// Sync now.
    pub async fn sync_now(&self) -> UiResult<SyncReport> {
        self.require_unlocked()?;
        Ok(self.vault.sync().await?)
    }

    /// Unresolved conflicts.
    pub async fn conflicts(&self) -> UiResult<Vec<ConflictInfo>> {
        self.require_unlocked()?;
        Ok(self.vault.conflicts().await?)
    }

    /// Resolve a conflict by keeping one version. Also clears the broker's pause flag.
    pub async fn resolve_conflict(&self, id: &EntryId, keep_version: u64) -> UiResult<()> {
        self.require_unlocked()?;
        self.vault.resolve_conflict(id, keep_version).await?;
        if let Ok(n) = self.node().await {
            let _ = n.broker.set_entry_conflict(&aipass_broker::Actor::System, id, false).await;
        }
        Ok(())
    }

    /// Vault members.
    pub fn devices(&self) -> UiResult<Vec<DeviceInfo>> {
        self.require_unlocked()?;
        Ok(self.vault.devices()?)
    }

    /// Revoke a vault device (rotates keys) and its broker approver role.
    pub async fn revoke_device(&self, id: &DeviceId) -> UiResult<RevokeResult> {
        self.require_reauth()?;
        let r = self.vault.revoke_device(id).await?;
        if let Ok(n) = self.node().await {
            let _ = n.broker.revoke_device(&aipass_broker::Actor::System, id).await;
        }
        Ok(r)
    }

    /// Move the vault to another storage location (target verified first; old copy kept).
    pub async fn migrate_storage(&self, input: StorageInput) -> UiResult<MigrationReport> {
        self.require_reauth()?;
        let (p, s) = self.storage_profile(&input)?;
        if p.kind == StorageKind::Local
            && let Some(path) = &p.path
        {
            crate::paths::ensure_private_dir(std::path::Path::new(path))?;
        }
        Ok(self.vault.migrate_storage(p, s).await?)
    }
}
