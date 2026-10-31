// SPDX-License-Identifier: Apache-2.0
//! The [`Broker`]: identity, policy, grants, approvals, the operation state machine,
//! budgets, revocation and audit. Every public method re-checks authorization from the
//! database state; nothing is trusted because a caller "has an ID".

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use aipass_crypto::SecretString;
use aipass_types::Timestamp;
use aipass_types::error::{ApiError, ErrorCode};
use aipass_types::exec::ExecutorBackend;
use aipass_types::ids::{ConnectionId, DeviceId, ExecutorId, GrantId, MailboxId, OperationId};
use aipass_types::relay::{RelayMessage, seal_envelope};
use serde_json::json;
use tokio::sync::{Semaphore, broadcast, watch};
use tokio_util::sync::CancellationToken;

use crate::audit::{self, Audit};
use crate::clock::{Clock, SystemClock};
use crate::config::{ADMIN_TOKEN_PREFIX, BrokerConfig};
use crate::db::Db;
use crate::error::OpenError;
use crate::notify::{ApprovalNotifier, BrokerEvent, CredentialSource, DeviceOutbox, RelayIdentity};
use crate::ratelimit::RateLimiter;
use crate::store;

mod activity;
mod approvals;
mod connections;
mod devices;
mod grants;
mod operations;
mod policies;
mod resources;
mod sweep;

pub use sweep::BackgroundTask;

pub(crate) const DENIAL_THROTTLE_SECS_PUB: i64 = operations::DENIAL_THROTTLE_SECS;
pub(crate) const MAX_PENDING_PUB: u64 = operations::MAX_PENDING_APPROVALS_PER_CONNECTION;

/// The Access Broker. Create with [`Broker::open`]; share as `Arc<Broker>`.
pub struct Broker {
    pub(crate) cfg: BrokerConfig,
    pub(crate) db: Db,
    pub(crate) clock: Arc<dyn Clock>,
    pub(crate) executors: RwLock<HashMap<ExecutorId, Arc<ExecutorSlot>>>,
    pub(crate) inflight: Mutex<HashMap<OperationId, Arc<Inflight>>>,
    pub(crate) notifiers: RwLock<Vec<Arc<dyn ApprovalNotifier>>>,
    pub(crate) events: broadcast::Sender<BrokerEvent>,
    pub(crate) relay: RwLock<Option<RelayLink>>,
    pub(crate) credentials: RwLock<Option<Arc<dyn CredentialSource>>>,
    pub(crate) admin_token_hash: RwLock<Option<String>>,
    pub(crate) public_limiter: RateLimiter,
}

impl std::fmt::Debug for Broker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Broker")
            .field("db", &self.db)
            .field("experimental", &self.cfg.experimental)
            .finish_non_exhaustive()
    }
}

#[derive(Clone)]
pub(crate) struct RelayLink {
    pub identity: RelayIdentity,
    pub outbox: Arc<dyn DeviceOutbox>,
}

/// A registered executor.
pub(crate) struct ExecutorSlot {
    pub backend: Arc<dyn ExecutorBackend>,
    pub control_ok: AtomicBool,
    pub permits: Arc<Semaphore>,
}

impl ExecutorSlot {
    /// `Err(EXECUTOR_OFFLINE | CONTROL_CHANNEL_LOST)` unless the executor can take work.
    pub(crate) fn ready(&self) -> Result<(), ApiError> {
        if !self.backend.info().online {
            return Err(ApiError::new(ErrorCode::ExecutorOffline));
        }
        if !self.control_ok.load(Ordering::SeqCst) {
            return Err(ApiError::new(ErrorCode::ControlChannelLost));
        }
        Ok(())
    }

    pub(crate) fn is_online(&self) -> bool {
        self.backend.info().online && self.control_ok.load(Ordering::SeqCst)
    }
}

/// An operation that is authorized (queued) or running.
pub(crate) struct Inflight {
    pub connection_id: ConnectionId,
    pub grant_id: GrantId,
    pub executor_id: ExecutorId,
    pub token: CancellationToken,
    /// Set once `ExecutorBackend::execute` has been called.
    pub started: AtomicBool,
    /// Why it was cancelled (`None` = cancelled by its own connection).
    pub reason: Mutex<Option<ErrorCode>>,
    pub done: watch::Sender<bool>,
}

impl Inflight {
    pub(crate) fn cancel_with(&self, reason: Option<ErrorCode>) {
        if let Ok(mut r) = self.reason.lock()
            && r.is_none() {
                *r = reason;
            }
        self.token.cancel();
    }

    pub(crate) fn cancel_reason(&self) -> Option<ErrorCode> {
        self.reason.lock().ok().and_then(|r| *r)
    }

    pub(crate) async fn wait_done(&self, timeout: std::time::Duration) -> bool {
        let mut rx = self.done.subscribe();
        tokio::time::timeout(timeout, rx.wait_for(|d| *d))
            .await
            .is_ok_and(|r| r.is_ok())
    }
}

impl Broker {
    /// Open (or create) a broker with the system clock.
    pub fn open(cfg: BrokerConfig) -> Result<Arc<Self>, OpenError> {
        Self::open_with_clock(cfg, Arc::new(SystemClock))
    }

    /// Open with an explicit clock (tests use [`crate::ManualClock`]).
    pub fn open_with_clock(cfg: BrokerConfig, clock: Arc<dyn Clock>) -> Result<Arc<Self>, OpenError> {
        if let Some(dir) = &cfg.data_dir {
            create_private_dir(dir)?;
        }
        let db = Db::open(cfg.db_path().as_deref())?;
        let admin_token_hash = match cfg.admin_token_path() {
            Some(p) => Some(load_or_create_admin_token(&p)?),
            None => None,
        };
        let now = clock.now();
        db.call_sync(|c| sweep::recover_after_restart(c, &now))?;
        let (events, _) = broadcast::channel(256);
        let broker = Arc::new(Self {
            public_limiter: RateLimiter::new(cfg.public_rate_per_minute),
            cfg,
            db,
            clock,
            executors: RwLock::new(HashMap::new()),
            inflight: Mutex::new(HashMap::new()),
            notifiers: RwLock::new(Vec::new()),
            events,
            relay: RwLock::new(None),
            credentials: RwLock::new(None),
            admin_token_hash: RwLock::new(admin_token_hash),
        });
        Ok(broker)
    }

    /// Configuration in effect.
    pub fn config(&self) -> &BrokerConfig {
        &self.cfg
    }

    /// Path of `broker.db` (None when in-memory).
    pub fn db_path(&self) -> Option<&Path> {
        self.db.path()
    }

    /// Path of the admin token file (None when in-memory).
    pub fn admin_token_path(&self) -> Option<PathBuf> {
        self.cfg.admin_token_path()
    }

    /// Current time from the broker clock.
    pub fn now(&self) -> Timestamp {
        self.clock.now()
    }

    // ---------------------------------------------------------------- hooks

    /// Register (or replace) an executor. Resources reference it by `executor_id`.
    pub async fn register_executor(&self, backend: Arc<dyn ExecutorBackend>) -> Result<ExecutorId, ApiError> {
        let info = backend.info();
        let id = info.executor_id.clone();
        let slot = Arc::new(ExecutorSlot {
            backend,
            control_ok: AtomicBool::new(true),
            permits: Arc::new(Semaphore::new(self.cfg.executor_concurrency.max(1))),
        });
        if let Ok(mut map) = self.executors.write() {
            map.insert(id.clone(), slot);
        }
        let now = self.now();
        self.db
            .call(move |c| {
                let tx = c.transaction()?;
                store::save_executor_info(&tx, &info, &now)?;
                audit::append(
                    &tx,
                    now,
                    Audit::new("system", "executor.registered").detail(json!({
                        "executor_id": info.executor_id.as_str(),
                        "protection_level": crate::db::enum_str(&info.protection_level),
                        "capabilities": info.capabilities.iter().map(|c| c.as_str()).collect::<Vec<_>>(),
                    })),
                )?;
                tx.commit()?;
                Ok(())
            })
            .await?;
        Ok(id)
    }

    /// Report the executor's control channel (the path revocations arrive on). While
    /// lost, new operations are denied with `CONTROL_CHANNEL_LOST`
    /// (`on_control_channel_lost: deny_new_operations`).
    pub async fn set_control_channel(&self, executor: &ExecutorId, connected: bool) -> Result<(), ApiError> {
        let slot = self.executor_slot(executor).ok_or_else(ApiError::not_found)?;
        let before = slot.control_ok.swap(connected, Ordering::SeqCst);
        if before != connected {
            let now = self.now();
            let id = executor.clone();
            self.db
                .call(move |c| {
                    audit::append(
                        c,
                        now,
                        Audit::new("system", "executor.control_channel")
                            .outcome(if connected { "ok" } else { "lost" })
                            .detail(json!({ "executor_id": id.as_str(), "connected": connected })),
                    )?;
                    Ok(())
                })
                .await?;
        }
        Ok(())
    }

    /// Connect the relay: the broker's identity (mailbox + keys) and the transport used
    /// to deliver sealed envelopes to trusted devices.
    pub fn set_relay(&self, identity: RelayIdentity, outbox: Arc<dyn DeviceOutbox>) {
        if let Ok(mut r) = self.relay.write() {
            *r = Some(RelayLink { identity, outbox });
        }
    }

    /// Add an in-process listener.
    pub fn add_notifier(&self, n: Arc<dyn ApprovalNotifier>) {
        if let Ok(mut v) = self.notifiers.write() {
            v.push(n);
        }
    }

    /// Subscribe to broker events.
    pub fn subscribe(&self) -> broadcast::Receiver<BrokerEvent> {
        self.events.subscribe()
    }

    /// Set the in-process credential source (desktop trusted client).
    pub fn set_credential_source(&self, s: Arc<dyn CredentialSource>) {
        if let Ok(mut c) = self.credentials.write() {
            *c = Some(s);
        }
    }

    /// Whether `token` is the local admin token (constant-time on hashes).
    pub fn verify_admin_token(&self, token: &str) -> bool {
        let Ok(guard) = self.admin_token_hash.read() else {
            return false;
        };
        match guard.as_deref() {
            Some(h) => {
                let got = aipass_types::signing::token_hash(token);
                aipass_crypto::ct_eq(got.as_bytes(), h.as_bytes())
            }
            None => false,
        }
    }

    /// Replace the admin token (rewrites `<data>/admin.token` when persistent) and return
    /// it once. The broker keeps only its hash.
    pub fn rotate_admin_token(&self) -> Result<SecretString, ApiError> {
        let token = aipass_crypto::rng::random_token(ADMIN_TOKEN_PREFIX, 32).map_err(|_| ApiError::internal())?;
        if let Some(p) = self.cfg.admin_token_path() {
            write_private_file(&p, token.expose().as_bytes()).map_err(|e| {
                tracing::error!(error = %e, "could not write admin token file");
                ApiError::internal()
            })?;
        }
        if let Ok(mut h) = self.admin_token_hash.write() {
            *h = Some(aipass_types::signing::token_hash(token.expose()));
        }
        Ok(token)
    }

    // ---------------------------------------------------------------- internals

    pub(crate) fn executor_slot(&self, id: &ExecutorId) -> Option<Arc<ExecutorSlot>> {
        self.executors.read().ok().and_then(|m| m.get(id).cloned())
    }

    pub(crate) fn executor_slots(&self) -> Vec<Arc<ExecutorSlot>> {
        self.executors
            .read()
            .map(|m| m.values().cloned().collect())
            .unwrap_or_default()
    }

    pub(crate) fn credential_source(&self) -> Option<Arc<dyn CredentialSource>> {
        self.credentials.read().ok().and_then(|c| c.clone())
    }

    pub(crate) fn relay_link(&self) -> Option<RelayLink> {
        self.relay.read().ok().and_then(|r| r.clone())
    }

    pub(crate) fn emit(&self, ev: BrokerEvent) {
        if let Ok(list) = self.notifiers.read() {
            for n in list.iter() {
                n.notify(&ev);
            }
        }
        let _ = self.events.send(ev);
    }

    pub(crate) fn inflight_for_grant(&self, grant: &GrantId) -> Vec<(OperationId, Arc<Inflight>)> {
        self.inflight
            .lock()
            .map(|m| {
                m.iter()
                    .filter(|(_, f)| &f.grant_id == grant)
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect()
            })
            .unwrap_or_default()
    }

    pub(crate) fn inflight_for_connection(&self, conn: &ConnectionId) -> Vec<(OperationId, Arc<Inflight>)> {
        self.inflight
            .lock()
            .map(|m| {
                m.iter()
                    .filter(|(_, f)| &f.connection_id == conn)
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect()
            })
            .unwrap_or_default()
    }

    pub(crate) fn inflight_get(&self, op: &OperationId) -> Option<Arc<Inflight>> {
        self.inflight.lock().ok().and_then(|m| m.get(op).cloned())
    }

    /// Seal `msg` to every active approver device (except `except`) and hand the envelopes
    /// to the outbox in background tasks. Never blocks the caller on delivery.
    pub(crate) async fn notify_devices(&self, msg: RelayMessage, except: Option<DeviceId>) {
        let Some(link) = self.relay_link() else {
            return;
        };
        let devices = match self.db.call(|c| store::active_approvers(c)).await {
            Ok(d) => d,
            Err(e) => {
                tracing::warn!(code = %e.code, "could not load approver devices");
                return;
            }
        };
        let now = self.now();
        for d in devices {
            if except.as_ref() == Some(&d.device.device_id) {
                continue;
            }
            match seal_envelope(
                &*link.identity.identity,
                link.identity.mailbox.clone(),
                MailboxId::Device(d.device.device_id.clone()),
                &d.device.kem_pk,
                &msg,
                now,
            ) {
                Ok(env) => {
                    let outbox = link.outbox.clone();
                    tokio::spawn(async move {
                        if let Err(e) = outbox.deliver(env).await {
                            tracing::warn!(code = %e.code, "relay delivery failed");
                        }
                    });
                }
                Err(e) => tracing::warn!(error = %e, kind = msg.message_type().as_str(), "could not seal relay message"),
            }
        }
    }

    /// Append an audit event in its own transaction (for events without a state change).
    pub(crate) async fn audit(&self, a: Audit) {
        let now = self.now();
        if let Err(e) = self.db.call(move |c| audit::append(c, now, a).map(|_| ())).await {
            tracing::error!(code = %e.code, "audit append failed");
        }
    }
}

#[cfg(unix)]
fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    if !dir.exists() {
        std::fs::DirBuilder::new().recursive(true).mode(0o700).create(dir)?;
    } else {
        let meta = std::fs::metadata(dir)?;
        if meta.permissions().mode() & 0o077 != 0 {
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)
}

#[cfg(unix)]
fn write_private_file(p: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let tmp = p.with_extension("tmp");
    let _ = std::fs::remove_file(&tmp);
    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, p)
}

#[cfg(not(unix))]
fn write_private_file(p: &Path, bytes: &[u8]) -> std::io::Result<()> {
    std::fs::write(p, bytes)
}

fn load_or_create_admin_token(p: &Path) -> Result<String, OpenError> {
    if p.exists() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let meta = std::fs::metadata(p)?;
            if meta.permissions().mode() & 0o077 != 0 {
                std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o600))?;
            }
        }
        let text = zeroize::Zeroizing::new(std::fs::read_to_string(p)?);
        let t = text.trim();
        if t.len() >= 16 {
            return Ok(aipass_types::signing::token_hash(t));
        }
    }
    let token = aipass_crypto::rng::random_token(ADMIN_TOKEN_PREFIX, 32)
        .map_err(|_| OpenError::Database("OS random number generator failed".into()))?;
    write_private_file(p, token.expose().as_bytes())?;
    Ok(aipass_types::signing::token_hash(token.expose()))
}
