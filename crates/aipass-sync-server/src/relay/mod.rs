// SPDX-License-Identifier: Apache-2.0
//! E2E relay mailbox (CONTRACTS §4, design doc §4.3).
//!
//! | method | path | auth |
//! | --- | --- | --- |
//! | POST | `/v1/relay/{mailbox}` | sender `AIPass-Sig` (dev_/exe_ sharing a vault with the mailbox owner) or `X-AIPass-Pairing-Secret` for `pair_…` → 202 `{message_id}` |
//! | GET | `/v1/relay/{mailbox}?after=&wait=0..25` | owner `AIPass-Sig` (kid = mailbox) or pairing secret; long-poll → `{messages}` |
//! | DELETE | `/v1/relay/{mailbox}/{message_id}` | owner / pairing secret → 204 |
//!
//! **What the relay can see.** Payloads are HPKE-sealed to the recipient; the relay has no
//! key to open them. It does see the envelope header — `from`, `to`, `type` (e.g.
//! `approval.request`), `created_at` — plus sizes, timing and the sender's network
//! address. It uses `type` only to decide whether to emit a push hint. This metadata
//! exposure is inherent to store-and-forward and is documented to users (§4.3).
//!
//! Limits: envelope ≤ 64 KiB, ≤ 500 live messages per mailbox, TTL 24 h (pairing
//! mailboxes 10 min from first use), long-poll ≤ 25 s, sender signature on the envelope
//! verified server-side (a member cannot spoof `from`). Pairing mailboxes bind the
//! SHA-256 of the 16-byte secret on first use (the new device starts polling right after
//! showing its QR code); later requests must present the same secret.

pub mod directory;
pub mod push;
pub mod sqlite;
pub mod store;

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use aipass_crypto::b64u;
use aipass_types::ids::{MailboxId, MessageId, PairingId, PrincipalId};
use aipass_types::pairing::PAIRING_SECRET_HEADER;
use aipass_types::relay::{
    MAX_ENVELOPE_BYTES, MAX_MESSAGES_PER_MAILBOX, MAX_WAIT_SECS, MESSAGE_TTL_SECS, MailboxMessage,
    MailboxResponse, PAIRING_MAILBOX_TTL_SECS, PostMessageResponse, PushHint, RELAY_VERSION,
    RelayEnvelope,
};
use aipass_types::signing::NonceCache;
use aipass_types::{ApiError, ErrorCode, Lang, Timestamp};
use axum::Router;
use axum::extract::rejection::PathRejection;
use axum::extract::{Path, Query, Request, State};
use axum::http::request::Parts;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get};
use serde::Deserialize;
use tokio::sync::Notify;

pub use directory::{ChainDirectory, RelayDirectory, StaticDirectory, SyncDirectory};
pub use push::{
    LogPushNotifier, NoopPushNotifier, PushNotifier, WEBHOOK_SIGNATURE_HEADER, WebhookPushNotifier,
};
pub use sqlite::SqliteRelayStore;
pub use store::{GcStats, InsertOutcome, MemoryRelayStore, MessageIdGen, PairingCheck, RelayStore};

use crate::auth::{self, rate_limited};
use crate::clock::{Clock, SystemClock};
use crate::error::{HttpError, invalid, lang_of, too_large, unverified};
use crate::ratelimit::{RateLimitConfig, RateLimiter};

/// Relay settings.
#[derive(Debug, Clone)]
pub struct RelayConfig {
    /// Message TTL (default 24 h).
    pub message_ttl_secs: i64,
    /// Pairing mailbox TTL from first use (default 10 min).
    pub pairing_ttl_secs: i64,
    /// Live messages per mailbox (default 500).
    pub max_messages_per_mailbox: usize,
    /// Long-poll cap (default 25 s).
    pub max_wait_secs: u64,
    /// Messages per GET response (default 100; clients page with `after`).
    pub fetch_limit: usize,
    /// Concurrent long-polls per mailbox; extra requests return immediately.
    pub max_waiters_per_mailbox: usize,
    /// Envelopes may be created at most this far in the future.
    pub max_future_skew_secs: i64,
    /// Per authenticated principal (or pairing mailbox).
    pub principal_rate: RateLimitConfig,
    /// Per client address (only with connect info).
    pub address_rate: RateLimitConfig,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            message_ttl_secs: MESSAGE_TTL_SECS,
            pairing_ttl_secs: PAIRING_MAILBOX_TTL_SECS,
            max_messages_per_mailbox: MAX_MESSAGES_PER_MAILBOX,
            max_wait_secs: MAX_WAIT_SECS,
            fetch_limit: 100,
            max_waiters_per_mailbox: 4,
            max_future_skew_secs: 300,
            principal_rate: RateLimitConfig::new(20.0, 100.0),
            address_rate: RateLimitConfig::new(50.0, 200.0),
        }
    }
}

#[derive(Debug, Default)]
struct Waiters {
    notify: Notify,
    waiting: AtomicUsize,
}

struct RelayInner {
    store: Arc<dyn RelayStore>,
    directory: Arc<dyn RelayDirectory>,
    push: Arc<dyn PushNotifier>,
    clock: Arc<dyn Clock>,
    nonces: Arc<NonceCache>,
    cfg: RelayConfig,
    limiter: RateLimiter,
    address_limiter: RateLimiter,
    hub: Mutex<HashMap<String, Arc<Waiters>>>,
}

/// Shared state of the relay router (cheap to clone).
#[derive(Clone)]
pub struct RelayState {
    inner: Arc<RelayInner>,
}

impl core::fmt::Debug for RelayState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RelayState").finish_non_exhaustive()
    }
}

/// Builder for [`RelayState`].
pub struct RelayStateBuilder {
    store: Arc<dyn RelayStore>,
    directory: Arc<dyn RelayDirectory>,
    push: Arc<dyn PushNotifier>,
    clock: Arc<dyn Clock>,
    nonces: Arc<NonceCache>,
    cfg: RelayConfig,
}

impl RelayStateBuilder {
    /// Push notifier (default: none).
    pub fn push(mut self, p: Arc<dyn PushNotifier>) -> Self {
        self.push = p;
        self
    }
    /// Clock (default: system).
    pub fn clock(mut self, c: Arc<dyn Clock>) -> Self {
        self.clock = c;
        self
    }
    /// Shared replay cache.
    pub fn nonce_cache(mut self, n: Arc<NonceCache>) -> Self {
        self.nonces = n;
        self
    }
    /// Settings.
    pub fn config(mut self, cfg: RelayConfig) -> Self {
        self.cfg = cfg;
        self
    }
    /// Build.
    pub fn build(self) -> RelayState {
        RelayState {
            inner: Arc::new(RelayInner {
                limiter: RateLimiter::new(self.cfg.principal_rate),
                address_limiter: RateLimiter::new(self.cfg.address_rate),
                store: self.store,
                directory: self.directory,
                push: self.push,
                clock: self.clock,
                nonces: self.nonces,
                cfg: self.cfg,
                hub: Mutex::new(HashMap::new()),
            }),
        }
    }
}

/// Who is accessing a mailbox.
enum Access {
    Principal,
    Pairing { expires_at: Timestamp },
}

struct WaitGuard(Arc<Waiters>);

impl Drop for WaitGuard {
    fn drop(&mut self) {
        self.0.waiting.fetch_sub(1, Ordering::SeqCst);
    }
}

#[derive(Debug, Deserialize)]
struct FetchParams {
    #[serde(default)]
    after: Option<String>,
    #[serde(default)]
    wait: Option<String>,
}

impl RelayState {
    /// Start building.
    pub fn builder(
        store: Arc<dyn RelayStore>,
        directory: Arc<dyn RelayDirectory>,
    ) -> RelayStateBuilder {
        RelayStateBuilder {
            store,
            directory,
            push: Arc::new(NoopPushNotifier),
            clock: Arc::new(SystemClock),
            nonces: Arc::new(NonceCache::default()),
            cfg: RelayConfig::default(),
        }
    }

    /// State with defaults.
    pub fn new(store: Arc<dyn RelayStore>, directory: Arc<dyn RelayDirectory>) -> Self {
        Self::builder(store, directory).build()
    }

    fn waiters(&self, mailbox: &MailboxId) -> Arc<Waiters> {
        self.inner
            .hub
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .entry(mailbox.as_str().to_owned())
            .or_default()
            .clone()
    }

    /// One garbage-collection pass (expired messages, pairing mailboxes, idle waiters and
    /// rate-limit buckets).
    pub async fn gc_once(&self) -> Result<GcStats, ApiError> {
        let stats = self.inner.store.gc(self.inner.clock.now()).await?;
        self.inner
            .hub
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .retain(|_, w| Arc::strong_count(w) > 1 || w.waiting.load(Ordering::SeqCst) > 0);
        self.inner.limiter.prune();
        self.inner.address_limiter.prune();
        Ok(stats)
    }

    fn pairing_secret_hash(parts: &Parts) -> Result<Option<[u8; 32]>, ApiError> {
        let Some(v) = parts.headers.get(PAIRING_SECRET_HEADER) else {
            return Ok(None);
        };
        let s = v
            .to_str()
            .map_err(|_| unverified("malformed_pairing_secret"))?;
        let raw = zeroize::Zeroizing::new(
            b64u::decode_array::<16>(s.trim())
                .map_err(|_| unverified("malformed_pairing_secret"))?,
        );
        Ok(Some(aipass_crypto::sha256(raw.as_slice())))
    }

    /// Authenticate as the owner of `mailbox` (or holder of the pairing secret).
    async fn owner_access(
        &self,
        mailbox: &MailboxId,
        parts: &Parts,
        body: &[u8],
    ) -> Result<Access, ApiError> {
        if let Some(addr) = auth::client_key(parts)
            && !self.inner.address_limiter.check(&addr)
        {
            return Err(rate_limited());
        }
        let now = self.inner.clock.now();
        match mailbox {
            MailboxId::Pairing(pid) => self.pairing_access(pid, parts, now).await,
            _ => {
                let req = auth::parse_sig(parts)?;
                if req.principal.as_str() != mailbox.as_str() {
                    return Err(unverified("not_mailbox_owner"));
                }
                self.verify_principal(&req, parts, body).await?;
                Ok(Access::Principal)
            }
        }
    }

    async fn pairing_access(
        &self,
        pid: &PairingId,
        parts: &Parts,
        now: Timestamp,
    ) -> Result<Access, ApiError> {
        let hash = Self::pairing_secret_hash(parts)?
            .ok_or_else(|| unverified("missing_pairing_secret"))?;
        if !self.inner.limiter.check(pid.as_str()) {
            return Err(rate_limited());
        }
        let exp = aipass_types::time::add_secs(&now, self.inner.cfg.pairing_ttl_secs);
        match self
            .inner
            .store
            .pairing_secret(pid, &hash, exp, now)
            .await?
        {
            PairingCheck::Registered { expires_at } | PairingCheck::Matched { expires_at } => {
                Ok(Access::Pairing { expires_at })
            }
            PairingCheck::Mismatch => Err(unverified("pairing_secret_mismatch")),
        }
    }

    async fn verify_principal(
        &self,
        req: &auth::SignedRequest,
        parts: &Parts,
        body: &[u8],
    ) -> Result<PrincipalId, ApiError> {
        let now = self.inner.clock.unix();
        auth::check_skew(&req.header, now)?;
        let pk = self
            .inner
            .directory
            .principal_key(&req.principal)
            .await?
            .ok_or_else(|| unverified(auth::UNVERIFIED_PRINCIPAL))?;
        auth::verify(
            req,
            &pk,
            parts.method.as_str(),
            &auth::path_and_query(parts),
            body,
            now,
            &self.inner.nonces,
        )?;
        if !self.inner.limiter.check(req.principal.as_str()) {
            return Err(rate_limited());
        }
        Ok(req.principal.clone())
    }

    async fn fetch_wait(
        &self,
        mailbox: &MailboxId,
        after: Option<&MessageId>,
        wait: u64,
    ) -> Result<Vec<MailboxMessage>, ApiError> {
        let limit = self.inner.cfg.fetch_limit;
        let first = self
            .inner
            .store
            .fetch(mailbox, after, self.inner.clock.now(), limit)
            .await?;
        if !first.is_empty() || wait == 0 {
            return Ok(first);
        }
        let w = self.waiters(mailbox);
        if w.waiting.fetch_add(1, Ordering::SeqCst) >= self.inner.cfg.max_waiters_per_mailbox {
            w.waiting.fetch_sub(1, Ordering::SeqCst);
            return Ok(first);
        }
        let _guard = WaitGuard(w.clone());
        let deadline = tokio::time::Instant::now() + Duration::from_secs(wait);
        loop {
            let notified = w.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let msgs = self
                .inner
                .store
                .fetch(mailbox, after, self.inner.clock.now(), limit)
                .await?;
            if !msgs.is_empty() {
                return Ok(msgs);
            }
            tokio::select! {
                _ = &mut notified => {}
                _ = tokio::time::sleep_until(deadline) => return Ok(Vec::new()),
            }
        }
    }
}

// ======================================================================================
// Handlers
// ======================================================================================

type HResult = Result<Response, HttpError>;

fn parse_mailbox(s: &str, lang: Lang) -> Result<MailboxId, HttpError> {
    MailboxId::parse(s).map_err(|_| HttpError::new(invalid("invalid_mailbox"), lang))
}

fn as_principal(m: &MailboxId) -> Option<PrincipalId> {
    PrincipalId::parse(m.as_str()).ok()
}

async fn post_message(
    State(s): State<RelayState>,
    path: Result<Path<String>, PathRejection>,
    req: Request,
) -> HResult {
    let (parts, body) = req.into_parts();
    let lang = lang_of(&parts.headers);
    let Path(mailbox) = path.map_err(|_| HttpError::new(invalid("invalid_path"), lang))?;
    let e = |err: ApiError| HttpError::new(err, lang);
    let mailbox = parse_mailbox(&mailbox, lang)?;
    if let Some(addr) = auth::client_key(&parts)
        && !s.inner.address_limiter.check(&addr)
    {
        return Err(e(rate_limited()));
    }
    let limit = MAX_ENVELOPE_BYTES + 8 * 1024;
    let bytes = axum::body::to_bytes(body, limit)
        .await
        .map_err(|_| e(too_large(MAX_ENVELOPE_BYTES)))?;
    let env: RelayEnvelope =
        serde_json::from_slice(&bytes).map_err(|_| e(invalid("invalid_envelope")))?;
    if env.v != RELAY_VERSION {
        return Err(e(invalid("unsupported_version")));
    }
    if env.to != mailbox {
        return Err(e(invalid("recipient_mismatch")));
    }
    env.check_size()
        .map_err(|_| e(too_large(MAX_ENVELOPE_BYTES)))?;
    let now = s.inner.clock.now();
    let cfg = &s.inner.cfg;
    if env.created_at > aipass_types::time::add_secs(&now, cfg.max_future_skew_secs) {
        return Err(e(invalid("envelope_from_future")));
    }
    if env.created_at <= aipass_types::time::add_secs(&now, -cfg.message_ttl_secs) {
        return Err(e(invalid("envelope_expired")));
    }
    let mut expires_at = aipass_types::time::add_secs(&now, cfg.message_ttl_secs);
    match &mailbox {
        MailboxId::Pairing(pid) => {
            if let Access::Pairing { expires_at: mexp } =
                s.pairing_access(pid, &parts, now).await.map_err(e)?
            {
                expires_at = expires_at.min(mexp);
            }
        }
        _ => {
            let req = auth::parse_sig(&parts).map_err(e)?;
            let sender = s.verify_principal(&req, &parts, &bytes).await.map_err(e)?;
            if env.from.as_str() != sender.as_str() {
                return Err(e(
                    ApiError::new(ErrorCode::Forbidden).with_detail("reason", "sender_mismatch")
                ));
            }
            let pk = s
                .inner
                .directory
                .principal_key(&sender)
                .await
                .map_err(e)?
                .ok_or_else(|| e(unverified(auth::UNVERIFIED_PRINCIPAL)))?;
            env.verify(&pk).map_err(|_| {
                e(ApiError::new(ErrorCode::IntegrityFailed)
                    .with_detail("reason", "envelope_signature_invalid"))
            })?;
            let recipient = as_principal(&mailbox).ok_or_else(|| e(invalid("invalid_mailbox")))?;
            s.inner
                .directory
                .authorize_send(&sender, &recipient)
                .await
                .map_err(e)?;
        }
    }
    let outcome = s
        .inner
        .store
        .insert(
            &mailbox,
            &env,
            now,
            expires_at,
            cfg.max_messages_per_mailbox,
        )
        .await
        .map_err(e)?;
    let message_id = match outcome {
        InsertOutcome::Inserted(id) => id,
        InsertOutcome::MailboxFull => {
            return Err(e(ApiError::new(ErrorCode::RateLimited)
                .with_message(
                    "收件箱已满，请稍后再试",
                    "The mailbox is full; try again later.",
                )
                .with_detail("reason", "mailbox_full")));
        }
    };
    if let Some(w) = s
        .inner
        .hub
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .get(mailbox.as_str())
    {
        w.notify.notify_waiters();
    }
    if matches!(mailbox, MailboxId::Device(_)) && env.message_type.triggers_push() {
        let push = s.inner.push.clone();
        let hint = PushHint {
            mailbox: mailbox.clone(),
            message_id: message_id.clone(),
        };
        tokio::spawn(async move { push.notify(hint).await });
    }
    let mut resp = (
        StatusCode::ACCEPTED,
        axum::Json(PostMessageResponse { message_id }),
    )
        .into_response();
    resp.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(resp)
}

async fn get_messages(
    State(s): State<RelayState>,
    path: Result<Path<String>, PathRejection>,
    query: Result<Query<FetchParams>, axum::extract::rejection::QueryRejection>,
    req: Request,
) -> HResult {
    let (parts, body) = req.into_parts();
    let lang = lang_of(&parts.headers);
    let Path(mailbox) = path.map_err(|_| HttpError::new(invalid("invalid_path"), lang))?;
    let e = |err: ApiError| HttpError::new(err, lang);
    let mailbox = parse_mailbox(&mailbox, lang)?;
    let Query(q) = query.map_err(|_| e(invalid("invalid_query")))?;
    let body = axum::body::to_bytes(body, 1024)
        .await
        .map_err(|_| e(too_large(1024)))?;
    let after = match q.after.as_deref().filter(|a| !a.is_empty()) {
        Some(a) => Some(MessageId::parse(a).map_err(|_| e(invalid("invalid_after")))?),
        None => None,
    };
    let wait = match q.wait.as_deref().filter(|w| !w.is_empty()) {
        Some(w) => w
            .parse::<u64>()
            .map_err(|_| e(invalid("invalid_wait")))?
            .min(s.inner.cfg.max_wait_secs),
        None => 0,
    };
    s.owner_access(&mailbox, &parts, &body).await.map_err(e)?;
    let messages = s
        .fetch_wait(&mailbox, after.as_ref(), wait)
        .await
        .map_err(e)?;
    let mut resp = axum::Json(MailboxResponse { messages }).into_response();
    resp.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(resp)
}

async fn delete_message(
    State(s): State<RelayState>,
    path: Result<Path<(String, String)>, PathRejection>,
    req: Request,
) -> HResult {
    let (parts, body) = req.into_parts();
    let lang = lang_of(&parts.headers);
    let Path((mailbox, message_id)) =
        path.map_err(|_| HttpError::new(invalid("invalid_path"), lang))?;
    let e = |err: ApiError| HttpError::new(err, lang);
    let mailbox = parse_mailbox(&mailbox, lang)?;
    let message_id = MessageId::parse(&message_id).map_err(|_| e(invalid("invalid_message_id")))?;
    let body = axum::body::to_bytes(body, 1024)
        .await
        .map_err(|_| e(too_large(1024)))?;
    s.owner_access(&mailbox, &parts, &body).await.map_err(e)?;
    s.inner
        .store
        .delete(&mailbox, &message_id)
        .await
        .map_err(e)?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// The relay router (`/v1/relay…`). Merge it into the embedding application's router.
pub fn relay_router(state: RelayState) -> Router {
    Router::new()
        .route("/v1/relay/{mailbox}", get(get_messages).post(post_message))
        .route("/v1/relay/{mailbox}/{message_id}", delete(delete_message))
        .with_state(state)
}

/// Run [`RelayState::gc_once`] every `every` until the returned handle is aborted.
pub fn spawn_relay_gc(state: RelayState, every: Duration) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(every);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            match state.gc_once().await {
                Ok(st) if st.messages > 0 || st.pairings > 0 => {
                    tracing::debug!(messages = st.messages, pairings = st.pairings, "relay gc");
                }
                Ok(_) => {}
                Err(_) => tracing::warn!("relay gc failed"),
            }
        }
    })
}
