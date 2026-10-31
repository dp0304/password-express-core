// SPDX-License-Identifier: Apache-2.0
//! `AipassCore` — the object native apps hold (CONTRACTS §12).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use aipass_crypto::b64u;
use aipass_sync::{ClientConfig, SecretField, StandardStoreFactory, StoreFactory, VaultClient};
use aipass_types::ErrorCode;
use aipass_types::ids::{
    ApprovalRequestId, ConnectionId, DeviceId, EntryId, ExecutorId, GrantId, MailboxId, MessageId,
    PrincipalId, ProjectId, ResourceId, VaultId,
};
use aipass_types::models::{
    AllowedProjects, ApprovalRequest, Decision, RevocationLevel, RevocationReport,
};
use aipass_types::relay::{
    ConnectionPairRequest, ControlAction, RelayMessage, StateRequest, StateSnapshot,
};
use aipass_types::vault::{MemberRole, MemberStatus, Platform};
use aipass_vault::RelayTransport;
use aipass_vault::import::CsvFormat;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::error::{CoreError, CoreResult, set_lang};
use crate::license;
use crate::relay::{LocalRelay, RelaySetting};
use crate::secret_store::{NativeSecretStore, SecretStore};
use crate::types::*;

const FFI_STATE_FILE: &str = "ffi-state.json";
/// How long `snapshot` / `revoke_grant` wait for the broker's reply.
const REPLY_WAIT_SECS: u64 = 20;
const MAX_INBOX_PAGES: usize = 20;

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct PendingApproval {
    pub request: ApprovalRequest,
    pub sender: ExecutorId,
    /// Another copy with the same id but different content was received; the first copy
    /// is kept and approving is refused.
    #[serde(default)]
    pub conflict: bool,
}

/// Display-level digest of a stored request (`aipass_types::approval::request_digest`).
pub(crate) fn request_digest(r: &ApprovalRequest) -> CoreResult<String> {
    aipass_types::approval::request_digest(r).map_err(|_| CoreError::code(ErrorCode::Internal))
}

/// Store a relayed approval request (`approval.request` or a snapshot row). Only the
/// executor named in the request may send it (its decision is sealed back to that
/// sender); an existing pending copy is never replaced — a copy with different content
/// marks the request as conflicting instead. Returns false when the message was ignored.
fn absorb_approval(
    approvals: &mut BTreeMap<String, PendingApproval>,
    sender: &ExecutorId,
    request: ApprovalRequest,
) -> bool {
    if request.expires_at <= aipass_types::time::now() {
        return false;
    }
    if request.executor.executor_id != *sender {
        tracing::warn!("ignoring an approval request relayed by an executor it does not name");
        return false;
    }
    let id = request.approval_request_id.to_string();
    match approvals.get_mut(&id) {
        Some(existing) => {
            let same = match (request_digest(&existing.request), request_digest(&request)) {
                (Ok(a), Ok(b)) => aipass_crypto::ct_eq(a.as_bytes(), b.as_bytes()),
                _ => false,
            };
            if !same && !existing.conflict {
                tracing::warn!("approval request received again with different content; keeping the first copy");
                existing.conflict = true;
            }
            false
        }
        None => {
            approvals.insert(
                id,
                PendingApproval {
                    request,
                    sender: sender.clone(),
                    conflict: false,
                },
            );
            true
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct PendingConnection {
    pub request: ConnectionPairRequest,
    pub sender: ExecutorId,
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct StoredSnapshot {
    pub sender: ExecutorId,
    pub received_at: i64,
    pub snapshot: StateSnapshot,
    /// Increases with every snapshot absorbed, so `snapshot()` can tell a reply to its own
    /// request from one received earlier in the same second.
    #[serde(default)]
    pub seq: u64,
}

/// FFI-layer state (no secrets): relay URL, inbox cursor, decrypted approval requests
/// (metadata only), latest snapshot and revocation reports, license token.
#[derive(Default, Clone, Serialize, Deserialize)]
pub(crate) struct FfiState {
    #[serde(default)]
    pub relay_url: Option<String>,
    #[serde(default)]
    pub inbox_cursor: Option<MessageId>,
    #[serde(default)]
    pub approvals: BTreeMap<String, PendingApproval>,
    #[serde(default)]
    pub connections: BTreeMap<String, PendingConnection>,
    #[serde(default)]
    pub snapshot: Option<StoredSnapshot>,
    #[serde(default)]
    pub revoke_reports: BTreeMap<String, RevocationReport>,
    #[serde(default)]
    pub last_broker: Option<ExecutorId>,
    #[serde(default)]
    pub bindings: BTreeMap<String, String>,
    #[serde(default)]
    pub license_token: Option<String>,
    #[serde(default)]
    pub license_public_key: Option<String>,
}

pub(crate) struct Shared {
    pub data_dir: PathBuf,
    pub cfg: ClientConfig,
    pub client: RwLock<Arc<VaultClient>>,
    pub secrets: Arc<NativeSecretStore>,
    pub factory: Arc<dyn StoreFactory>,
    pub relay: Mutex<RelaySetting>,
    pub state: Mutex<FfiState>,
}

impl Shared {
    pub(crate) fn client(&self) -> Arc<VaultClient> {
        match self.client.read() {
            Ok(g) => g.clone(),
            Err(p) => p.into_inner().clone(),
        }
    }

    pub(crate) fn relay(&self) -> RelaySetting {
        self.relay.lock().map(|g| g.clone()).unwrap_or_default()
    }

    pub(crate) fn set_relay(&self, r: RelaySetting) {
        if let Ok(mut g) = self.relay.lock() {
            *g = r;
        }
    }

    fn state(&self) -> FfiState {
        self.state.lock().map(|g| g.clone()).unwrap_or_default()
    }

    pub(crate) fn update_state<T>(&self, f: impl FnOnce(&mut FfiState) -> T) -> CoreResult<T> {
        let mut g = self
            .state
            .lock()
            .map_err(|_| CoreError::code(ErrorCode::Internal))?;
        let out = f(&mut g);
        write_state(&self.data_dir, &g)?;
        Ok(out)
    }

    pub(crate) fn device_id(&self) -> CoreResult<DeviceId> {
        self.client()
            .device_id()
            .ok_or_else(|| aipass_vault::VaultError::NoVault.into())
    }

    /// Transport for this device's own mailbox.
    pub(crate) fn own_transport(&self) -> CoreResult<Arc<dyn RelayTransport>> {
        let dev = self.device_id()?;
        let identity = self.secrets.device_identity(dev.as_str());
        self.relay().own(PrincipalId::Device(dev), identity)
    }
}

fn read_state(dir: &Path) -> FfiState {
    std::fs::read(dir.join(FFI_STATE_FILE))
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

fn write_state(dir: &Path, st: &FfiState) -> CoreResult<()> {
    let bytes = serde_json::to_vec_pretty(st).map_err(|_| CoreError::code(ErrorCode::Internal))?;
    let tmp = dir.join(format!("{FFI_STATE_FILE}.tmp"));
    std::fs::write(&tmp, bytes)
        .and_then(|()| std::fs::rename(&tmp, dir.join(FFI_STATE_FILE)))
        .map_err(|e| CoreError::from(aipass_vault::VaultError::Io(e.kind().to_string())))
}

fn parse_relay_url(url: &str) -> CoreResult<url::Url> {
    let u = url::Url::parse(url.trim())
        .map_err(|_| CoreError::invalid("中继地址无效", "invalid relay URL"))?;
    let loopback = matches!(u.host_str(), Some("127.0.0.1") | Some("localhost") | Some("[::1]"));
    if u.scheme() == "https" || (u.scheme() == "http" && loopback) {
        Ok(u)
    } else {
        Err(CoreError::invalid(
            "中继地址必须使用 https（本机调试可用 http://127.0.0.1）",
            "relay URL must use https (http only for loopback development)",
        ))
    }
}

/// Main entry point for iOS / Android. All methods are thread-safe.
#[derive(uniffi::Object)]
pub struct AipassCore {
    pub(crate) shared: Arc<Shared>,
}

impl AipassCore {
    /// Rust constructor with an explicit storage factory (tests use
    /// `aipass_sync::MemoryStoreFactory`).
    pub fn with_factory(
        data_dir: String,
        secret_store: Arc<dyn SecretStore>,
        platform: String,
        app_version: String,
        factory: Arc<dyn StoreFactory>,
    ) -> CoreResult<Arc<Self>> {
        let platform: Platform = parse_enum(&platform, "platform")?;
        let dir = PathBuf::from(&data_dir);
        std::fs::create_dir_all(&dir)
            .map_err(|e| CoreError::from(aipass_vault::VaultError::Io(e.kind().to_string())))?;
        let cfg = ClientConfig::new(dir.clone(), platform, app_version);
        let secrets = Arc::new(NativeSecretStore::new(secret_store));
        let client = VaultClient::open(cfg.clone(), secrets.clone(), factory.clone())?;
        let state = read_state(&dir);
        let relay = match state.relay_url.as_deref().map(parse_relay_url) {
            Some(Ok(u)) => RelaySetting::Http(u),
            _ => RelaySetting::None,
        };
        Ok(Arc::new(Self {
            shared: Arc::new(Shared {
                data_dir: dir,
                cfg,
                client: RwLock::new(Arc::new(client)),
                secrets,
                factory,
                relay: Mutex::new(relay),
                state: Mutex::new(state),
            }),
        }))
    }

    fn client(&self) -> Arc<VaultClient> {
        self.shared.client()
    }

    fn license_key(&self) -> Option<([u8; 32], bool)> {
        match self.shared.state().license_public_key {
            Some(k) => b64u::decode_array::<32>(&k).ok().map(|k| (k, false)),
            None => license::builtin_key(),
        }
    }

    fn current_license(&self) -> Option<LicenseStatusFfi> {
        let tok = self.shared.state().license_token?;
        let dev = self.client().device_id().map(|d| d.to_string());
        Some(license::verify(
            &tok,
            self.license_key(),
            dev.as_deref(),
            aipass_types::time::unix_now(),
        ))
    }

    fn pending(&self, id: &str) -> CoreResult<PendingApproval> {
        let st = self.shared.state();
        let p = st
            .approvals
            .get(id)
            .cloned()
            .ok_or_else(|| CoreError::new(ErrorCode::NotFound, "找不到该访问请求", "approval request not found"))?;
        if p.request.expires_at <= aipass_types::time::now() {
            self.shared.update_state(|s| s.approvals.remove(id))?;
            return Err(CoreError::new(
                ErrorCode::ApprovalExpired,
                "该请求已过期，未授予任何权限",
                "this request expired; nothing was granted",
            ));
        }
        Ok(p)
    }

    fn binding(&self, resource: &ResourceId) -> Option<EntryId> {
        self.shared
            .state()
            .bindings
            .get(resource.as_str())
            .and_then(|e| e.parse().ok())
    }

    /// Process one inbox message; returns whether it was a reply of interest.
    fn absorb(&self, sender: ExecutorId, msg: RelayMessage) -> CoreResult<()> {
        let now = aipass_types::time::unix_now();
        self.shared.update_state(|s| {
            s.last_broker = Some(sender.clone());
            match msg {
                RelayMessage::ApprovalRequest(r) => {
                    absorb_approval(&mut s.approvals, &sender, *r);
                }
                RelayMessage::ApprovalCancelled(c) => {
                    // only the broker that sent the request may withdraw it (otherwise a
                    // cancel + re-send could swap the content behind the user's back)
                    let id = c.approval_request_id.as_str();
                    if s.approvals.get(id).is_some_and(|p| p.sender == sender) {
                        s.approvals.remove(id);
                    }
                }
                RelayMessage::ConnectionPairRequest(r) => {
                    // first copy wins: a later copy (another sender, or a different pairing
                    // code / name) must not swap what the user compares and approves
                    let id = r.connection.connection_id.to_string();
                    match s.connections.get(&id) {
                        Some(existing) => {
                            if existing.sender != sender || existing.request != *r {
                                tracing::warn!(
                                    "connection pair request received again with a different sender or content; keeping the first copy"
                                );
                            }
                        }
                        None => {
                            s.connections.insert(
                                id,
                                PendingConnection {
                                    request: *r,
                                    sender,
                                },
                            );
                        }
                    }
                }
                RelayMessage::StateSnapshot(snap) => {
                    for a in &snap.pending_approvals {
                        absorb_approval(&mut s.approvals, &sender, a.clone());
                    }
                    let seq = s.snapshot.as_ref().map_or(0, |p| p.seq) + 1;
                    s.snapshot = Some(StoredSnapshot {
                        sender,
                        received_at: now,
                        snapshot: *snap,
                        seq,
                    });
                }
                RelayMessage::RevokeReport(r) => {
                    s.revoke_reports.insert(r.grant_id.to_string(), r);
                }
                _ => {}
            }
        })
    }

    /// Pull every new message from this device's mailbox (optionally long-polling).
    async fn drain_inbox(&self, wait_secs: u64) -> CoreResult<u32> {
        let c = self.client();
        let transport = self.shared.own_transport()?;
        let me = MailboxId::Device(self.shared.device_id()?);
        let mut cursor = self.shared.state().inbox_cursor;
        let mut n = 0u32;
        let mut wait = wait_secs;
        for _ in 0..MAX_INBOX_PAGES {
            let (msgs, next) = c.fetch_inbox(&*transport, cursor.as_ref(), wait).await?;
            wait = 0;
            let fetched_any = next != cursor;
            for (mid, exe, msg) in msgs {
                self.absorb(exe, msg)?;
                // best effort acknowledgement; the cursor already prevents re-delivery
                let _ = transport.delete(&me, &mid, None).await;
                n += 1;
            }
            cursor = next;
            self.shared.update_state(|s| s.inbox_cursor = cursor.clone())?;
            if !fetched_any {
                break;
            }
        }
        Ok(n)
    }

    /// Resolve the broker / executor to talk to.
    fn target_executor(&self, hint: Option<&str>) -> CoreResult<ExecutorId> {
        if let Some(h) = hint {
            return parse_id::<ExecutorId>(h, "executor_id");
        }
        if let Some(b) = self.shared.state().last_broker {
            return Ok(b);
        }
        let execs: Vec<ExecutorId> = self
            .client()
            .devices()?
            .into_iter()
            .filter(|d| d.role == MemberRole::Executor && d.status == MemberStatus::Active)
            .map(|d| aipass_sync::executor_principal(&d.device_id))
            .collect();
        match execs.as_slice() {
            [one] => Ok(one.clone()),
            [] => Err(CoreError::new(
                ErrorCode::NotFound,
                "尚未配对执行设备",
                "no executor is paired",
            )),
            _ => Err(CoreError::invalid(
                "有多个执行设备，请指定 executor_id",
                "several executors are paired; pass executor_id",
            )),
        }
    }

    async fn send(&self, exe: &ExecutorId, msg: RelayMessage) -> CoreResult<MessageId> {
        let transport = self.shared.own_transport()?;
        Ok(self
            .client()
            .send_to_executor(&*transport, exe, &msg)
            .await?)
    }

    /// The stored request must still be exactly the one the user saw (`displayed` =
    /// `ApprovalRequestFfi.request_digest`), and a conflicting request is never approved.
    fn check_displayed(p: &PendingApproval, displayed: &str, deny: bool) -> CoreResult<()> {
        let stored = request_digest(&p.request)?;
        if !aipass_crypto::ct_eq(stored.as_bytes(), displayed.trim().as_bytes()) {
            return Err(CoreError::new(
                ErrorCode::IntegrityFailed,
                "该请求的内容与屏幕上显示的不一致，请重新查看后再决定",
                "this request no longer matches what was displayed; review it again",
            ));
        }
        if p.conflict && !deny {
            return Err(CoreError::new(
                ErrorCode::IntegrityFailed,
                "收到了内容不同的同一请求，已阻止批准；可以拒绝，或在执行设备上核对",
                "this request arrived twice with different content; approving is blocked (you can still deny)",
            ));
        }
        Ok(())
    }

    async fn decide(
        &self,
        id: &str,
        displayed_digest: &str,
        narrowed: Option<AccessSpecFfi>,
        entry: Option<EntryId>,
        deny: bool,
    ) -> CoreResult<DecisionResultFfi> {
        let p = self.pending(id)?;
        Self::check_displayed(&p, displayed_digest, deny)?;
        let c = self.client();
        let decision = if deny {
            c.deny(&p.request)?
        } else {
            let narrowed = narrowed.map(|n| n.to_spec()).transpose()?;
            let entry = entry.or_else(|| self.binding(&p.request.resource.resource_id));
            let Some(e) = entry else {
                return Err(CoreError::new(
                    ErrorCode::NotFound,
                    "此资源尚未关联保险库中的凭证，请先选择要使用的条目",
                    "this resource is not linked to a vault entry; choose the entry first",
                ));
            };
            c.approve_with_entry(&p.request, narrowed, Some(&e)).await?
        };
        let message_id = self
            .send(
                &p.sender,
                RelayMessage::ApprovalDecision(Box::new(decision.clone())),
            )
            .await?;
        self.shared.update_state(|s| s.approvals.remove(id))?;
        Ok(DecisionResultFfi {
            approval_request_id: decision.approval_request_id.to_string(),
            decision: enum_str(&decision.decision),
            digest: decision.digest.clone(),
            expires_at: ts(&decision.expires_at),
            credential_sealed: decision.credential_envelope.is_some(),
            message_id: message_id.to_string(),
        })
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl AipassCore {
    /// Open (or prepare) the core in `data_dir` (app-private directory). `platform`:
    /// `ios` | `android` | `macos` | …. Uses the standard storage backends (local, s3,
    /// webdav, official, selfhost).
    #[uniffi::constructor]
    pub fn new(
        data_dir: String,
        secret_store: Arc<dyn SecretStore>,
        platform: String,
        app_version: String,
    ) -> CoreResult<Arc<Self>> {
        Self::with_factory(
            data_dir,
            secret_store,
            platform,
            app_version,
            Arc::new(StandardStoreFactory { allow_http: false }),
        )
    }

    /// UI language for error and status messages: `zh-CN` (default) or `en`.
    pub fn set_locale(&self, locale: String) {
        set_lang(locale.to_ascii_lowercase().starts_with("en"));
    }

    /// Whether a vault exists on this device.
    pub fn has_vault(&self) -> bool {
        self.client().has_vault()
    }

    /// Current status (no secrets).
    pub fn status(&self) -> CoreStatus {
        CoreStatus::from_core(
            self.client().status(),
            self.shared.relay().is_configured(),
            self.current_license(),
        )
    }

    /// Create a new vault. Show `recovery_key` / `recovery_kit_text` once and ask the user
    /// to save them; the core never stores the recovery key after verification.
    pub async fn create_vault(
        &self,
        device_name: String,
        storage: StorageProfileFfi,
        storage_secret: Option<String>,
    ) -> CoreResult<CreateVaultResultFfi> {
        let profile = storage.to_profile()?;
        let r = self
            .client()
            .create_vault(&device_name, profile, storage_secret.map(secret), None)
            .await?;
        Ok(r.into())
    }

    /// Unlock. The native side performs biometrics / passcode first (the device key is
    /// read from the `SecretStore` with user presence). Works offline.
    pub async fn unlock(&self) -> CoreResult<()> {
        Ok(self.client().unlock().await?)
    }

    /// Lock and wipe decrypted state from memory.
    pub fn lock(&self) {
        self.client().lock();
        self.shared.secrets.forget();
    }

    /// Whether the vault is unlocked.
    pub fn is_unlocked(&self) -> bool {
        self.client().is_unlocked()
    }

    // ---- items ---------------------------------------------------------------------

    /// List items (no secrets). `query` matches title / username / URL.
    pub fn list_items(
        &self,
        query: Option<String>,
        project_id: Option<String>,
    ) -> CoreResult<Vec<ItemSummary>> {
        let project = project_id
            .map(|p| parse_id::<ProjectId>(&p, "project_id"))
            .transpose()?;
        Ok(self
            .client()
            .list_items(query.as_deref(), project.as_ref())?
            .into_iter()
            .map(Into::into)
            .collect())
    }

    /// Item detail with secrets masked.
    pub fn get_item(&self, entry_id: String) -> CoreResult<ItemDetail> {
        let id = parse_id::<EntryId>(&entry_id, "entry_id")?;
        Ok(self.client().get_item(&id)?.into())
    }

    /// Reveal one secret (`field`: `secret` | `totp` | `field:<name>`). **The native side
    /// must re-authenticate the user (biometrics / passcode) right before calling.** Never
    /// expose the result to AI tools, logs or analytics.
    pub fn reveal_secret(&self, entry_id: String, field: String) -> CoreResult<String> {
        let id = parse_id::<EntryId>(&entry_id, "entry_id")?;
        let f = SecretField::parse(&field)
            .ok_or_else(|| CoreError::invalid("无效的字段", "invalid field"))?;
        Ok(self.client().reveal_secret(&id, &f)?.expose().to_owned())
    }

    /// Create or update an item; returns its entry id.
    pub async fn save_item(&self, item: ItemInputFfi) -> CoreResult<String> {
        let input = item.into_input()?;
        Ok(self.client().save_item(input).await?.to_string())
    }

    /// Delete an item (tombstone).
    pub async fn delete_item(&self, entry_id: String) -> CoreResult<()> {
        let id = parse_id::<EntryId>(&entry_id, "entry_id")?;
        Ok(self.client().delete_item(&id).await?)
    }

    /// Generate a password with the given rules (CSPRNG).
    pub fn generate_password(&self, rules: PasswordRulesFfi) -> CoreResult<String> {
        let rules: aipass_types::vault::PasswordRules = rules.into();
        Ok(self.client().generate_password(&rules)?.expose().to_owned())
    }

    /// Current TOTP code for an item.
    pub fn totp_now(&self, entry_id: String) -> CoreResult<TotpCode> {
        let id = parse_id::<EntryId>(&entry_id, "entry_id")?;
        let t = self.client().totp_now(&id)?;
        Ok(TotpCode {
            code: t.code.expose().to_owned(),
            remaining_seconds: t.remaining_seconds,
            period: t.period,
        })
    }

    // ---- import / export -----------------------------------------------------------

    /// Import a CSV export (`format`: `chrome` | `firefox` | `safari` | `bitwarden` |
    /// `1password` | `lastpass` | `generic`). Remind the user to delete the CSV file.
    pub async fn import_csv(&self, format: String, mut bytes: Vec<u8>) -> CoreResult<ImportReportFfi> {
        let fmt = CsvFormat::parse(&format)
            .ok_or_else(|| CoreError::invalid("不支持的 CSV 格式", "unsupported CSV format"));
        let r = match fmt {
            Ok(f) => self.client().import_csv(f, &bytes).await,
            Err(e) => {
                bytes.zeroize();
                return Err(e);
            }
        };
        bytes.zeroize();
        Ok(r?.into())
    }

    /// Encrypted `.aipassx` export protected by `password` (Argon2id).
    pub fn export_encrypted(&self, password: String) -> CoreResult<Vec<u8>> {
        let pw = secret(password);
        Ok(self.client().export_encrypted(&pw)?)
    }

    /// Import an `.aipassx` file.
    pub async fn import_encrypted(&self, bytes: Vec<u8>, password: String) -> CoreResult<ImportReportFfi> {
        let pw = secret(password);
        Ok(self.client().import_encrypted(&bytes, &pw).await?.into())
    }

    // ---- sync ----------------------------------------------------------------------

    /// Pull + push. Network problems are reported as `status = "offline"`, not errors.
    pub async fn sync(&self) -> CoreResult<SyncReportFfi> {
        Ok(self.client().sync().await?.into())
    }

    /// Entries with conflicting versions (paused for autofill / approvals).
    pub async fn conflicts(&self) -> CoreResult<Vec<ConflictInfoFfi>> {
        Ok(self
            .client()
            .conflicts()
            .await?
            .into_iter()
            .map(Into::into)
            .collect())
    }

    /// Keep `keep_version` of a conflicted entry.
    pub async fn resolve_conflict(&self, entry_id: String, keep_version: u64) -> CoreResult<()> {
        let id = parse_id::<EntryId>(&entry_id, "entry_id")?;
        Ok(self.client().resolve_conflict(&id, keep_version).await?)
    }

    // ---- recovery ------------------------------------------------------------------

    /// Check a typed recovery key against the vault (marks the kit as verified).
    pub fn verify_recovery_key(&self, key: String) -> CoreResult<bool> {
        let k = secret(key);
        Ok(self.client().verify_recovery_key(k.expose())?)
    }

    /// Recovery kit text (contains the recovery key only while it is not yet verified).
    pub fn recovery_kit_text(&self) -> CoreResult<String> {
        Ok(self.client().recovery_kit_text(false)?.expose().to_owned())
    }

    /// Replace the recovery key (the old one stops working for new key epochs).
    pub async fn replace_recovery_key(&self) -> CoreResult<CreateVaultResultFfi> {
        Ok(self.client().replace_recovery_key().await?.into())
    }

    /// Set or change the optional master password.
    pub async fn set_master_password(&self, password: String) -> CoreResult<()> {
        let pw = secret(password);
        Ok(self.client().set_master_password(&pw).await?)
    }

    /// Restore a vault on this (fresh) device with the recovery key.
    pub async fn recover_with_key(
        &self,
        vault_id: String,
        storage: StorageProfileFfi,
        storage_secret: Option<String>,
        recovery_key: String,
        device_name: String,
    ) -> CoreResult<()> {
        let vid = parse_id::<VaultId>(&vault_id, "vault_id")?;
        let key = secret(recovery_key);
        let profile = storage.to_profile()?;
        let client = VaultClient::recover_with_key(
            self.shared.cfg.clone(),
            self.shared.secrets.clone(),
            self.shared.factory.clone(),
            &vid,
            profile,
            storage_secret.map(secret),
            key.expose(),
            &device_name,
        )
        .await?;
        if let Ok(mut g) = self.shared.client.write() {
            *g = Arc::new(client);
        }
        Ok(())
    }

    // ---- devices -------------------------------------------------------------------

    /// Vault members (devices, executors, recovery identity).
    pub fn devices(&self) -> CoreResult<Vec<DeviceFfi>> {
        Ok(self
            .client()
            .devices()?
            .into_iter()
            .map(Into::into)
            .collect())
    }

    /// Revoke a device and rotate the vault key epoch.
    pub async fn revoke_device(&self, device_id: String) -> CoreResult<RevokeResultFfi> {
        let id = parse_id::<DeviceId>(&device_id, "device_id")?;
        Ok(self.client().revoke_device(&id).await?.into())
    }

    /// Outstanding credential rotation suggestions.
    pub fn rotation_tasks(&self) -> CoreResult<Vec<RotationTaskFfi>> {
        Ok(self
            .client()
            .rotation_tasks()?
            .into_iter()
            .map(Into::into)
            .collect())
    }

    /// Dismiss a rotation suggestion.
    pub fn dismiss_rotation_task(&self, entry_id: String) -> CoreResult<()> {
        let id = parse_id::<EntryId>(&entry_id, "entry_id")?;
        Ok(self.client().dismiss_rotation_task(&id)?)
    }

    // ---- storage -------------------------------------------------------------------

    /// Run the storage capability test on a candidate profile.
    pub async fn test_storage(
        &self,
        profile: StorageProfileFfi,
        secret_value: Option<String>,
    ) -> CoreResult<CapabilityReportFfi> {
        let p = profile.to_profile()?;
        let s = secret_value.map(secret);
        Ok(self.client().test_storage(&p, s.as_ref()).await?.into())
    }

    /// Migrate to another storage (target must be `sync_capable`; old copy is kept).
    pub async fn migrate_storage(
        &self,
        profile: StorageProfileFfi,
        secret_value: Option<String>,
    ) -> CoreResult<MigrationReportFfi> {
        let p = profile.to_profile()?;
        Ok(self
            .client()
            .migrate_storage(p, secret_value.map(secret))
            .await?
            .into())
    }

    // ---- autofill ------------------------------------------------------------------

    /// Matching logins for a service identifier (URL or domain).
    pub fn autofill_candidates(&self, service_identifier: String) -> CoreResult<Vec<AutofillCandidate>> {
        Ok(self
            .client()
            .autofill_candidates(&service_identifier)?
            .into_iter()
            .map(|c| AutofillCandidate {
                entry_id: c.entry_id.to_string(),
                title: c.title,
                username: c.username,
                match_kind: enum_str(&c.match_kind),
            })
            .collect())
    }

    /// Credential to fill. **Requires native user presence first.** Fails with
    /// `SYNC_CONFLICT` while the entry has conflicting versions.
    pub fn autofill_credential(&self, entry_id: String) -> CoreResult<AutofillCredentialFfi> {
        let id = parse_id::<EntryId>(&entry_id, "entry_id")?;
        let c = self.client().autofill_credential(&id)?;
        Ok(AutofillCredentialFfi {
            username: c.username.clone(),
            password: c.password.expose().to_owned(),
            totp: c.totp.as_ref().map(|t| t.expose().to_owned()),
        })
    }

    /// Identities for the OS credential identity store (no secrets).
    pub fn all_credential_identities(&self) -> CoreResult<Vec<CredentialIdentity>> {
        Ok(self
            .client()
            .all_credential_identities()?
            .into_iter()
            .map(|c| CredentialIdentity {
                entry_id: c.entry_id.to_string(),
                service_identifier: c.service_identifier,
                username: c.username,
            })
            .collect())
    }

    /// Save a credential captured by AutoFill / a save prompt (`form_kind`: `login` |
    /// `signup` | `change_password`).
    pub async fn save_from_autofill(
        &self,
        origin: String,
        username: Option<String>,
        password: String,
        form_kind: String,
    ) -> CoreResult<SaveResultFfi> {
        let (status, id) = self
            .client()
            .save_from_browser(&origin, username.as_deref(), secret(password), &form_kind)
            .await?;
        Ok(SaveResultFfi {
            status: enum_str(&status),
            entry_id: id.map(|e| e.to_string()),
        })
    }

    // ---- pairing -------------------------------------------------------------------

    /// New device: create a pairing offer (QR / link) through the configured relay.
    pub async fn pairing_offer(&self, device_name: String) -> CoreResult<Arc<crate::pairing::PairingSession>> {
        crate::pairing::PairingSession::offer(self.shared.clone(), &device_name)
    }

    /// Trusted device: scan a pairing link and send `pairing.hello`.
    pub async fn pairing_scan(&self, qr_payload: String) -> CoreResult<Arc<crate::pairing::PairingSession>> {
        crate::pairing::PairingSession::scan(self.shared.clone(), &qr_payload).await
    }

    // ---- relay, approvals & control ------------------------------------------------

    /// Use the HTTPS relay at `base_url` (e.g. `https://cloud.aipass.example` or the
    /// node's URL). Persisted.
    pub fn set_relay(&self, base_url: String) -> CoreResult<()> {
        let u = parse_relay_url(&base_url)?;
        self.shared
            .update_state(|s| s.relay_url = Some(u.as_str().to_owned()))?;
        self.shared.set_relay(RelaySetting::Http(u));
        Ok(())
    }

    /// Use an in-process relay (tests / single-process demos). Not persisted.
    pub fn set_local_relay(&self, relay: Arc<LocalRelay>) {
        self.shared.set_relay(RelaySetting::Local(relay.inner.clone()));
    }

    /// Link a broker resource (`res_…`) to the vault entry whose credential is delivered
    /// (sealed to the executor) when the user approves access to it.
    pub fn bind_resource(&self, resource_id: String, entry_id: String) -> CoreResult<()> {
        let r = parse_id::<ResourceId>(&resource_id, "resource_id")?;
        let e = parse_id::<EntryId>(&entry_id, "entry_id")?;
        self.client().bind_resource(&r, &e)?;
        self.shared
            .update_state(|s| s.bindings.insert(r.to_string(), e.to_string()))?;
        Ok(())
    }

    /// Fetch and decrypt this device's relay inbox; returns pending (unexpired) approval
    /// requests. Messages whose sender cannot be verified are dropped.
    pub async fn fetch_inbox(&self) -> CoreResult<Vec<ApprovalRequestFfi>> {
        self.drain_inbox(0).await?;
        Ok(self.pending_approvals())
    }

    /// Pending approval requests already fetched (no network).
    pub fn pending_approvals(&self) -> Vec<ApprovalRequestFfi> {
        let now = aipass_types::time::now();
        let mut v: Vec<ApprovalRequestFfi> = self
            .shared
            .state()
            .approvals
            .values()
            .filter(|p| p.request.expires_at > now)
            .filter_map(|p| {
                Some(ApprovalRequestFfi::from_request(
                    &p.request,
                    p.sender.as_str(),
                    self.binding(&p.request.resource.resource_id).is_some(),
                    request_digest(&p.request).ok()?,
                    p.conflict,
                ))
            })
            .collect();
        v.sort_by_key(|a| a.created_at);
        v
    }

    /// AI connections waiting for confirmation (from `connection.pair_request`).
    pub fn pending_connections(&self) -> Vec<ConnectionRequestFfi> {
        self.shared
            .state()
            .connections
            .values()
            .map(|p| ConnectionRequestFfi {
                connection_id: p.request.connection.connection_id.to_string(),
                display_name: p.request.connection.display_name.clone(),
                host_type: enum_str(&p.request.connection.host_type),
                transport: enum_str(&p.request.connection.transport),
                pairing_code: p.request.pairing_code.clone(),
                created_at: ts(&p.request.connection.created_at),
                sender_executor_id: p.sender.to_string(),
            })
            .collect()
    }

    /// Approve (optionally narrowed). `request_digest` is the
    /// `ApprovalRequestFfi.request_digest` of the request **displayed** to the user; the
    /// call refuses with `INTEGRITY_FAILED` if the stored request no longer hashes to it
    /// or arrived twice with different content. Then recomputes the §7 digest from that
    /// request, signs it, seals the bound credential to the executor and posts
    /// `approval.decision`.
    pub async fn approve(
        &self,
        approval_request_id: String,
        request_digest: String,
        narrowed: Option<AccessSpecFfi>,
    ) -> CoreResult<DecisionResultFfi> {
        self.decide(&approval_request_id, &request_digest, narrowed, None, false)
            .await
    }

    /// Approve using `entry_id`'s credential (also binds the resource to it). Same
    /// `request_digest` rule as [`Self::approve`]; nothing is bound when it fails.
    pub async fn approve_with_entry(
        &self,
        approval_request_id: String,
        request_digest: String,
        narrowed: Option<AccessSpecFfi>,
        entry_id: String,
    ) -> CoreResult<DecisionResultFfi> {
        let e = parse_id::<EntryId>(&entry_id, "entry_id")?;
        let p = self.pending(&approval_request_id)?;
        Self::check_displayed(&p, &request_digest, false)?;
        self.bind_resource(p.request.resource.resource_id.to_string(), e.to_string())?;
        self.decide(&approval_request_id, &request_digest, narrowed, Some(e), false)
            .await
    }

    /// Deny (signed) and notify the broker. `request_digest` as for [`Self::approve`]
    /// (a conflicting request may still be denied).
    pub async fn deny(
        &self,
        approval_request_id: String,
        request_digest: String,
    ) -> CoreResult<DecisionResultFfi> {
        self.decide(&approval_request_id, &request_digest, None, None, true)
            .await
    }

    /// Ask the broker for `state.snapshot` and wait up to 20 s for it.
    pub async fn snapshot(&self, executor_id: Option<String>) -> CoreResult<SnapshotFfi> {
        let exe = self.target_executor(executor_id.as_deref())?;
        // only a snapshot absorbed after this request counts (a timestamp comparison would
        // accept an older snapshot received within the same second)
        let before = self.shared.state().snapshot.map_or(0, |s| s.seq);
        self.send(&exe, RelayMessage::StateRequest(StateRequest::default()))
            .await?;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(REPLY_WAIT_SECS);
        loop {
            if let Some(s) = self.shared.state().snapshot
                && s.sender == exe
                && s.seq > before
            {
                return Ok(SnapshotFfi::from_snapshot(&s.snapshot, s.sender.as_str(), s.received_at));
            }
            let left = deadline.saturating_duration_since(tokio::time::Instant::now());
            if left.is_zero() {
                return Err(CoreError::new(
                    ErrorCode::ExecutorOffline,
                    "执行设备未响应，显示的是上次同步的状态",
                    "the executor did not answer",
                ));
            }
            self.drain_inbox(left.as_secs().clamp(1, 25)).await?;
        }
    }

    /// Last snapshot received (no network), if any.
    pub fn last_snapshot(&self) -> Option<SnapshotFfi> {
        self.shared
            .state()
            .snapshot
            .map(|s| SnapshotFfi::from_snapshot(&s.snapshot, s.sender.as_str(), s.received_at))
    }

    /// Revoke a grant (`level`: `stop_access` | `end_sessions` | `revoke_upstream`) and
    /// wait up to 20 s for the broker's report. `confirmed = false` if it did not answer.
    pub async fn revoke_grant(&self, grant_id: String, level: String) -> CoreResult<RevocationReportFfi> {
        let gid = parse_id::<GrantId>(&grant_id, "grant_id")?;
        let lvl: RevocationLevel = parse_enum(&level, "level")?;
        let hint = self.shared.state().snapshot.and_then(|s| {
            s.snapshot
                .grants
                .iter()
                .find(|g| g.grant_id == gid)
                .map(|_| s.sender.clone())
        });
        let exe = match hint {
            Some(h) => h,
            None => self.target_executor(None)?,
        };
        let msg = self.client().sign_grant_revoke(&gid, lvl)?;
        self.shared
            .update_state(|s| s.revoke_reports.remove(gid.as_str()))?;
        self.send(&exe, RelayMessage::GrantRevoke(msg)).await?;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(REPLY_WAIT_SECS);
        loop {
            if let Some(r) = self.shared.state().revoke_reports.get(gid.as_str()) {
                return Ok(RevocationReportFfi::from_report(r));
            }
            let left = deadline.saturating_duration_since(tokio::time::Instant::now());
            if left.is_zero() {
                return Ok(RevocationReportFfi::unconfirmed(gid.as_str()));
            }
            self.drain_inbox(left.as_secs().clamp(1, 25)).await?;
        }
    }

    /// Pause / resume / remove a connection or revoke all its grants
    /// (`action`: `pause` | `resume` | `remove` | `revoke_all`).
    pub async fn control_connection(&self, connection_id: String, action: String) -> CoreResult<()> {
        let cid = parse_id::<ConnectionId>(&connection_id, "connection_id")?;
        let a: ControlAction = parse_enum(&action, "action")?;
        let exe = self.connection_executor(&cid)?;
        let msg = self.client().sign_connection_control(&cid, a)?;
        self.send(&exe, RelayMessage::ConnectionControl(msg)).await?;
        Ok(())
    }

    /// Approve an AI connection after the user compared the pairing code.
    /// `allowed_projects`: `["*"]` for all, or `proj_…` ids.
    pub async fn approve_connection(&self, connection_id: String, allowed_projects: Vec<String>) -> CoreResult<()> {
        self.connection_decision(connection_id, Decision::Approve, allowed_projects)
            .await
    }

    /// Reject an AI connection.
    pub async fn deny_connection(&self, connection_id: String) -> CoreResult<()> {
        self.connection_decision(connection_id, Decision::Deny, Vec::new())
            .await
    }

    // ---- license -------------------------------------------------------------------

    /// Override the license verifying key (b64u Ed25519 public key from
    /// `GET /v1/licenses/public-key`, pinned at build time in production apps).
    pub fn set_license_public_key(&self, public_key_b64u: String) -> CoreResult<()> {
        b64u::decode_array::<32>(public_key_b64u.trim())
            .map_err(|_| CoreError::invalid("公钥格式无效", "invalid public key"))?;
        self.shared
            .update_state(|s| s.license_public_key = Some(public_key_b64u.trim().to_owned()))
    }

    /// Verify a license token offline and remember it for `status().license`. A failure
    /// only disables premium features.
    pub fn verify_license(&self, token: String) -> LicenseStatusFfi {
        let dev = self.client().device_id().map(|d| d.to_string());
        let s = license::verify(
            &token,
            self.license_key(),
            dev.as_deref(),
            aipass_types::time::unix_now(),
        );
        if s.valid {
            let _ = self
                .shared
                .update_state(|st| st.license_token = Some(token.trim().to_owned()));
        }
        s
    }
}

impl AipassCore {
    fn connection_executor(&self, cid: &ConnectionId) -> CoreResult<ExecutorId> {
        let st = self.shared.state();
        if let Some(p) = st.connections.get(cid.as_str()) {
            return Ok(p.sender.clone());
        }
        if let Some(s) = &st.snapshot
            && s.snapshot.connections.iter().any(|c| &c.connection_id == cid)
        {
            return Ok(s.sender.clone());
        }
        self.target_executor(None)
    }

    async fn connection_decision(
        &self,
        connection_id: String,
        decision: Decision,
        allowed_projects: Vec<String>,
    ) -> CoreResult<()> {
        let cid = parse_id::<ConnectionId>(&connection_id, "connection_id")?;
        let allowed = if allowed_projects.iter().any(|p| p == "*") {
            AllowedProjects::All
        } else {
            AllowedProjects::Only(
                allowed_projects
                    .iter()
                    .map(|p| parse_id::<ProjectId>(p, "project_id"))
                    .collect::<CoreResult<_>>()?,
            )
        };
        let exe = self.connection_executor(&cid)?;
        let msg = self
            .client()
            .sign_connection_decision(&cid, decision, allowed)?;
        self.send(&exe, RelayMessage::ConnectionDecision(msg)).await?;
        self.shared
            .update_state(|s| s.connections.remove(cid.as_str()))?;
        Ok(())
    }

    /// Approval request ids currently pending (Rust tests).
    pub fn pending_ids(&self) -> Vec<ApprovalRequestId> {
        self.shared
            .state()
            .approvals
            .values()
            .map(|p| p.request.approval_request_id.clone())
            .collect()
    }

    /// Data directory.
    pub fn data_dir(&self) -> &Path {
        &self.shared.data_dir
    }
}

/// Default password rules (§2.6).
#[uniffi::export]
pub fn default_password_rules() -> PasswordRulesFfi {
    PasswordRulesFfi::default()
}

/// Version of the Rust core.
#[uniffi::export]
pub fn core_version() -> String {
    env!("CARGO_PKG_VERSION").to_owned()
}
