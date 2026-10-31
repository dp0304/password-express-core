// SPDX-License-Identifier: Apache-2.0
//! HTTP sync API (CONTRACTS §3.3) over any [`ObjectStore`] blob backend.
//!
//! Blob layout: vault objects at `vaults/<vault_id>/<key>`; a server-maintained index of
//! memberships at `index/devices/<device_id>/<vault_id>` (empty objects, used by the relay
//! directory). The server only ever stores ciphertext and signed metadata; it never holds
//! a vault key.
//!
//! | method | path | who |
//! | --- | --- | --- |
//! | POST | `/v1/vaults` | `Bearer` (enroll token / cloud session) via [`VaultAdmission`] |
//! | GET | `/v1/vaults/{vault_id}` | any active member |
//! | GET | `/v1/vaults/{vault_id}/objects/{*key}` | any active member (incl. executors) |
//! | PUT | `/v1/vaults/{vault_id}/objects/{*key}` | active owner / member |
//! | GET | `/v1/vaults/{vault_id}/objects?prefix=&start_after=&limit=` | any active member |
//! | DELETE | `/v1/vaults/{vault_id}/objects/{*key}` | owner (immutable keys); owner/member (mutable keys) |
//!
//! Enforcement: `AIPass-Sig` with `kid` = `dev_…` / `exe_…` resolved from signed member
//! records (signature-checked chains, see `src/sync/members.rs`) bound to the device's
//! server-wide key and combined with the verified manifest chain (`src/sync/view.rs`);
//! ±300 s skew; nonce replay cache; per-principal rate limit;
//! 4 MiB object limit; immutable prefixes (`entries/ manifests/ members/ recovery/ keyring/`
//! and `vault.json`) can only be created, never overwritten (412 regardless of headers);
//! uploaded member records, manifests, entry versions, recovery wraps and keyring records
//! are validated against their keys (and member records / manifests against signatures)
//! before they are stored. `vault.json` and `members/` are never deletable (deleting a
//! revocation record would resurrect a device).

pub mod admission;
pub(crate) mod members;
pub mod quota;
pub(crate) mod view;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use aipass_storage::http::{
    ListObjectsResponse, MAX_CREATE_VAULT_BYTES, MAX_LIST_LIMIT, MAX_OBJECT_BYTES,
    PutObjectResponse, VaultInfo,
};
use aipass_storage::{
    ObjectStore, PrefixedStore, PutCondition, PutOutcome, list_all, validate_key, validate_prefix,
};
use aipass_types::ids::{DeviceId, PrincipalId, VaultId};
use aipass_types::signing::NonceCache;
use aipass_types::vault::{
    EntryVersion, KeyringRecord, Manifest, MemberRecord, MemberRole, MemberStatus, RecoveryWrap,
    SignedObject, VaultHeader, keys,
};
use aipass_types::{ApiError, ErrorCode, Lang};
use axum::Router;
use axum::body::Body;
use axum::extract::rejection::PathRejection;
use axum::extract::{Path, Query, Request, State};
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use serde::Deserialize;
use serde_json::value::RawValue;

pub use admission::{
    Admission, AdmissionRequest, DenyAllAdmission, ENROLL_TOKEN_PREFIX, EnrollTokenAdmission,
    VaultAdmission,
};
pub use quota::{QuotaPolicy, StaticQuota, VaultUsage, WriteDelta};

use crate::auth::{self, rate_limited};
use crate::clock::{Clock, SystemClock};
use crate::error::{HttpError, invalid, lang_of, storage, too_large, unverified};
use crate::ratelimit::{RateLimitConfig, RateLimiter};
use members::integrity;

/// Blob prefix of vault namespaces.
pub const VAULTS_PREFIX: &str = "vaults/";
/// Blob prefix of the membership index.
pub const INDEX_PREFIX: &str = "index/devices/";
/// Blob prefix of the server-wide device-key bindings (`index/keys/<device_id>` = hex
/// Ed25519 key; first binding wins, CONTRACTS §1.1 "IDs are not capabilities").
pub const KEY_INDEX_PREFIX: &str = "index/keys/";
pub use view::VIEW_INDEX_PREFIX;
/// Maximum size of the mutable `HEAD` hint.
pub const MAX_HEAD_BYTES: usize = 64;

/// Sync server settings.
#[derive(Debug, Clone)]
pub struct SyncConfig {
    /// Maximum object size (default 4 MiB, CONTRACTS §3.3).
    pub max_object_bytes: usize,
    /// Maximum `limit` per listing (default 1000).
    pub max_list_limit: usize,
    /// How long resolved memberships are cached (local writes invalidate immediately;
    /// changes made through *another* server instance become visible after this).
    pub member_cache_ttl: Duration,
    /// Per authenticated principal.
    pub principal_rate: RateLimitConfig,
    /// Per client address before authentication (only when the server runs with
    /// `into_make_service_with_connect_info::<SocketAddr>()`).
    pub address_rate: RateLimitConfig,
}

impl Default for SyncConfig {
    fn default() -> Self {
        Self {
            max_object_bytes: MAX_OBJECT_BYTES,
            max_list_limit: MAX_LIST_LIMIT,
            member_cache_ttl: Duration::from_secs(10),
            principal_rate: RateLimitConfig::new(50.0, 200.0),
            address_rate: RateLimitConfig::new(100.0, 400.0),
        }
    }
}

/// A resolved vault member.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedMember {
    /// Device id of the member record.
    pub device_id: DeviceId,
    /// Latest revision.
    pub rev: u64,
    /// Role.
    pub role: MemberRole,
    /// Status.
    pub status: MemberStatus,
    /// Ed25519 key.
    pub sign_pk: [u8; 32],
    /// X25519 key.
    pub kem_pk: [u8; 32],
}

impl ResolvedMember {
    fn from_record(r: &MemberRecord) -> Self {
        Self {
            device_id: r.device_id.clone(),
            rev: r.rev,
            role: r.role,
            status: r.status,
            sign_pk: r.sign_pk,
            kem_pk: r.kem_pk,
        }
    }

    /// Active.
    pub fn is_active(&self) -> bool {
        self.status == MemberStatus::Active
    }

    /// Active owner or member (may write).
    pub fn can_write(&self) -> bool {
        self.is_active() && self.role.is_trusted_approver()
    }
}

/// The member-record device id behind a principal: `dev_X` → `dev_X`; `exe_U` → `dev_U`
/// (an executor that signs as `exe_U` must be enrolled as member `dev_U` with role
/// `executor`); `conn_` → none.
pub fn member_device_for(principal: &PrincipalId) -> Option<DeviceId> {
    match principal {
        PrincipalId::Device(d) => Some(d.clone()),
        PrincipalId::Executor(e) => {
            let (_, ulid) = aipass_types::ids::split(e.as_str())?;
            DeviceId::parse(&format!("dev_{ulid}")).ok()
        }
        PrincipalId::Connection(_) => None,
    }
}

type MemberCache = HashMap<(VaultId, DeviceId), (Instant, Option<ResolvedMember>)>;

struct SyncInner {
    blobs: Arc<dyn ObjectStore>,
    admission: Arc<dyn VaultAdmission>,
    quota: Arc<dyn QuotaPolicy>,
    clock: Arc<dyn Clock>,
    nonces: Arc<NonceCache>,
    cfg: SyncConfig,
    principal_limiter: RateLimiter,
    address_limiter: RateLimiter,
    member_cache: Mutex<MemberCache>,
    header_cache: Mutex<HashMap<VaultId, VaultHeader>>,
    views: Mutex<HashMap<VaultId, (Instant, Arc<aipass_vault::VaultView>)>>,
    usage: tokio::sync::Mutex<HashMap<VaultId, VaultUsage>>,
    /// Per-vault lock around a write's quota check + reservation, so the policy is asked
    /// once per write (a cross-replica policy reserves in its database on every call).
    quota_locks: Mutex<HashMap<VaultId, Arc<tokio::sync::Mutex<()>>>>,
}

/// Shared state of the sync router (cheap to clone).
#[derive(Clone)]
pub struct SyncState {
    inner: Arc<SyncInner>,
}

impl core::fmt::Debug for SyncState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SyncState")
            .field("blobs", &self.inner.blobs.describe())
            .finish_non_exhaustive()
    }
}

/// Builder for [`SyncState`].
pub struct SyncStateBuilder {
    blobs: Arc<dyn ObjectStore>,
    admission: Arc<dyn VaultAdmission>,
    quota: Arc<dyn QuotaPolicy>,
    clock: Arc<dyn Clock>,
    nonces: Arc<NonceCache>,
    cfg: SyncConfig,
}

impl SyncStateBuilder {
    /// Quota policy (default: unlimited).
    pub fn quota(mut self, q: Arc<dyn QuotaPolicy>) -> Self {
        self.quota = q;
        self
    }
    /// Clock (default: system).
    pub fn clock(mut self, c: Arc<dyn Clock>) -> Self {
        self.clock = c;
        self
    }
    /// Shared replay cache (share one between the sync and relay routers).
    pub fn nonce_cache(mut self, n: Arc<NonceCache>) -> Self {
        self.nonces = n;
        self
    }
    /// Settings.
    pub fn config(mut self, cfg: SyncConfig) -> Self {
        self.cfg = cfg;
        self
    }
    /// Build.
    pub fn build(self) -> SyncState {
        SyncState {
            inner: Arc::new(SyncInner {
                principal_limiter: RateLimiter::new(self.cfg.principal_rate),
                address_limiter: RateLimiter::new(self.cfg.address_rate),
                blobs: self.blobs,
                admission: self.admission,
                quota: self.quota,
                clock: self.clock,
                nonces: self.nonces,
                cfg: self.cfg,
                member_cache: Mutex::new(HashMap::new()),
                header_cache: Mutex::new(HashMap::new()),
                views: Mutex::new(HashMap::new()),
                usage: tokio::sync::Mutex::new(HashMap::new()),
                quota_locks: Mutex::new(HashMap::new()),
            }),
        }
    }
}

#[derive(Deserialize)]
struct CreateVaultBody<'a> {
    #[serde(borrow)]
    vault_header: &'a RawValue,
    #[serde(borrow)]
    genesis_member: &'a RawValue,
}

#[derive(Debug, Deserialize)]
struct ListParams {
    #[serde(default)]
    prefix: Option<String>,
    #[serde(default)]
    start_after: Option<String>,
    #[serde(default)]
    limit: Option<usize>,
}

/// An authenticated sync request.
struct Authed {
    principal: PrincipalId,
    member: ResolvedMember,
}

fn forbidden(reason: &'static str) -> ApiError {
    ApiError::new(ErrorCode::Forbidden).with_detail("reason", reason)
}

fn precondition_failed() -> ApiError {
    ApiError::new(ErrorCode::PreconditionFailed)
}

fn not_found() -> ApiError {
    ApiError::new(ErrorCode::NotFound)
}

async fn read_body(body: Body, limit: usize) -> Result<Vec<u8>, ApiError> {
    match axum::body::to_bytes(body, limit).await {
        Ok(b) => Ok(b.to_vec()),
        Err(_) => Err(too_large(limit)),
    }
}

fn etag_header(etag: &str) -> Option<HeaderValue> {
    HeaderValue::from_str(&format!("\"{etag}\"")).ok()
}

fn parse_if_match(v: &str) -> Option<String> {
    let v = v.trim();
    if v == "*" {
        return None;
    }
    let v = v.strip_prefix("W/").unwrap_or(v);
    let inner = v.strip_prefix('"')?.strip_suffix('"')?;
    (!inner.is_empty() && !inner.contains('"')).then(|| inner.to_owned())
}

/// Client-requested condition.
enum Requested {
    None,
    IfAbsent,
    IfMatch(String),
}

fn requested_condition(h: &HeaderMap) -> Result<Requested, ApiError> {
    let inm = h
        .get(header::IF_NONE_MATCH)
        .map(|v| v.to_str().unwrap_or("\u{0}"));
    let im = h
        .get(header::IF_MATCH)
        .map(|v| v.to_str().unwrap_or("\u{0}"));
    match (inm, im) {
        (Some(_), Some(_)) => Err(invalid("conflicting_conditions")),
        (Some(v), None) if v.trim() == "*" => Ok(Requested::IfAbsent),
        (Some(_), None) => Err(invalid("unsupported_if_none_match")),
        (None, Some(v)) => parse_if_match(v)
            .map(Requested::IfMatch)
            .ok_or_else(|| invalid("invalid_if_match")),
        (None, None) => Ok(Requested::None),
    }
}

impl SyncState {
    /// Start building a state over `blobs` with an admission policy.
    pub fn builder(
        blobs: Arc<dyn ObjectStore>,
        admission: Arc<dyn VaultAdmission>,
    ) -> SyncStateBuilder {
        SyncStateBuilder {
            blobs,
            admission,
            quota: Arc::new(StaticQuota::unlimited()),
            clock: Arc::new(SystemClock),
            nonces: Arc::new(NonceCache::default()),
            cfg: SyncConfig::default(),
        }
    }

    /// State with defaults.
    pub fn new(blobs: Arc<dyn ObjectStore>, admission: Arc<dyn VaultAdmission>) -> Self {
        Self::builder(blobs, admission).build()
    }

    /// The replay cache (to share with the relay router).
    pub fn nonce_cache(&self) -> Arc<NonceCache> {
        self.inner.nonces.clone()
    }

    /// The clock.
    pub fn clock(&self) -> Arc<dyn Clock> {
        self.inner.clock.clone()
    }

    /// The vault's namespace as a store of its own.
    pub fn vault_store(&self, vault_id: &VaultId) -> Result<PrefixedStore, ApiError> {
        PrefixedStore::new(
            self.inner.blobs.clone(),
            &format!("{VAULTS_PREFIX}{vault_id}"),
        )
        .map_err(storage)
    }

    /// Verified `vault.json` (signature by the self-signed genesis record), cached.
    pub async fn vault_header(&self, vault_id: &VaultId) -> Result<Option<VaultHeader>, ApiError> {
        if let Some(h) = self
            .inner
            .header_cache
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(vault_id)
        {
            return Ok(Some(h.clone()));
        }
        let ns = self.vault_store(vault_id)?;
        let Some(obj) = ns.get(keys::VAULT_HEADER).await.map_err(storage)? else {
            return Ok(None);
        };
        let header: VaultHeader =
            serde_json::from_slice(&obj.bytes).map_err(|_| integrity("vault_header_malformed"))?;
        if header.format != 1 || header.vault_id != *vault_id {
            return Err(integrity("vault_header_mismatch"));
        }
        let ctx = members::Ctx::new(&ns, vault_id, &header.genesis_device_id);
        let genesis_key = keys::member(&header.genesis_device_id, 1);
        let gobj = ns
            .get(&genesis_key)
            .await
            .map_err(storage)?
            .ok_or_else(|| integrity("genesis_member_missing"))?;
        let grec = members::parse_record(&gobj.bytes, vault_id, &header.genesis_device_id, 1)?;
        members::verify_record(&ctx, &grec, 0, false).await?;
        header
            .verify_signature(&grec.sign_pk)
            .map_err(|_| integrity("vault_header_signature_invalid"))?;
        let mut cache = self
            .inner
            .header_cache
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        if cache.len() > 100_000 {
            cache.clear();
        }
        cache.insert(vault_id.clone(), header.clone());
        Ok(Some(header))
    }

    /// Resolve `principal` (dev_/exe_) to its latest verified member record in `vault_id`.
    /// `Ok(None)` for unknown principals, missing vaults, or records failing verification.
    pub async fn resolve_member(
        &self,
        vault_id: &VaultId,
        principal: &PrincipalId,
    ) -> Result<Option<ResolvedMember>, ApiError> {
        let Some(dev) = member_device_for(principal) else {
            return Ok(None);
        };
        let key = (vault_id.clone(), dev.clone());
        let ttl = self.inner.cfg.member_cache_ttl;
        if let Some((at, v)) = self
            .inner
            .member_cache
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&key)
            && at.elapsed() < ttl
        {
            return Ok(filter_executor(principal, v.clone()));
        }
        let resolved = match self.vault_header(vault_id).await {
            Ok(Some(header)) => match self.resolve_effective(vault_id, &header, &dev).await {
                Ok(r) => r,
                Err(e) if e.code == ErrorCode::IntegrityFailed => {
                    tracing::warn!(vault = %vault_id, device = %dev, "member record failed verification; access denied");
                    None
                }
                Err(e) => return Err(e),
            },
            Ok(None) => None,
            Err(e) if e.code == ErrorCode::IntegrityFailed => {
                tracing::warn!(vault = %vault_id, "vault header failed verification; access denied");
                None
            }
            Err(e) => return Err(e),
        };
        let mut cache = self
            .inner
            .member_cache
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        if cache.len() > 200_000 {
            cache.clear();
        }
        cache.insert(key, (Instant::now(), resolved.clone()));
        Ok(filter_executor(principal, resolved))
    }

    /// Latest verified record of `dev`, bound to the server-wide key of its device id and
    /// combined with the verified manifest chain (see `view.rs`).
    async fn resolve_effective(
        &self,
        vault_id: &VaultId,
        header: &VaultHeader,
        dev: &DeviceId,
    ) -> Result<Option<ResolvedMember>, ApiError> {
        let ns = self.vault_store(vault_id)?;
        let ctx = members::Ctx::new(&ns, vault_id, &header.genesis_device_id);
        let Some(rec) = members::resolve(&ctx, dev.clone(), None, 0).await? else {
            return Ok(None);
        };
        if let Some(bound) = self.bound_key(dev).await?
            && bound != rec.sign_pk
        {
            tracing::warn!(vault = %vault_id, device = %dev, "member record key differs from the device's bound key; access denied");
            return Ok(None);
        }
        let Some(view) = self.manifest_view(vault_id, false).await? else {
            return Ok(None);
        };
        Ok(view::effective(&ctx, &view, rec, 0)
            .await?
            .as_ref()
            .map(ResolvedMember::from_record))
    }

    /// The Ed25519 key `dev` is bound to on this server (`None` before its first record).
    pub async fn bound_key(&self, dev: &DeviceId) -> Result<Option<[u8; 32]>, ApiError> {
        let Some(obj) = self
            .inner
            .blobs
            .get(&format!("{KEY_INDEX_PREFIX}{dev}"))
            .await
            .map_err(storage)?
        else {
            return Ok(None);
        };
        let mut k = [0u8; 32];
        hex::decode_to_slice(obj.bytes.trim_ascii(), &mut k)
            .map_err(|_| integrity("device_key_binding_malformed"))?;
        Ok(Some(k))
    }

    /// Bind `dev` to `sign_pk` server-wide (first binding wins); a record carrying another
    /// key for an already bound device id is refused, whichever vault it is uploaded to.
    async fn bind_key(&self, dev: &DeviceId, sign_pk: &[u8; 32]) -> Result<(), ApiError> {
        let mismatch = || integrity("device_key_mismatch");
        if let Some(k) = self.bound_key(dev).await? {
            return if k == *sign_pk {
                Ok(())
            } else {
                Err(mismatch())
            };
        }
        match self
            .inner
            .blobs
            .put(
                &format!("{KEY_INDEX_PREFIX}{dev}"),
                hex::encode(sign_pk).into_bytes(),
                PutCondition::IfAbsent,
            )
            .await
            .map_err(storage)?
        {
            PutOutcome::Written { .. } => Ok(()),
            PutOutcome::PreconditionFailed => match self.bound_key(dev).await? {
                Some(k) if k == *sign_pk => Ok(()),
                _ => Err(mismatch()),
            },
        }
    }

    /// Reserve a write's usage delta atomically with the quota check (released with
    /// [`SyncState::adjust_usage`] on failure), so concurrent writes cannot overshoot.
    async fn reserve_usage(
        &self,
        vault_id: &VaultId,
        principal: &PrincipalId,
        delta: &WriteDelta,
        objects: i64,
        bytes: i64,
    ) -> Result<(), ApiError> {
        // writes to one vault check + reserve one at a time on this replica: the policy is
        // then asked once per write (no retry while another write's reservation lands),
        // and only a concurrent release/delete can still force a re-check below
        let lock = self
            .inner
            .quota_locks
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .entry(vault_id.clone())
            .or_default()
            .clone();
        let _serial = lock.lock().await;
        for _ in 0..64 {
            let usage = self.usage(vault_id).await?;
            self.inner
                .quota
                .check_write(vault_id, principal, &usage, delta)
                .await?;
            let mut map = self.inner.usage.lock().await;
            if let Some(u) = map.get_mut(vault_id)
                && *u == usage
            {
                u.object_count = (u.object_count as i64 + objects).max(0) as u64;
                u.bytes_used = (u.bytes_used as i64 + bytes).max(0) as u64;
                return Ok(());
            }
            // changed by a concurrent write since the check: check again
        }
        Err(rate_limited())
    }

    fn invalidate_vault(&self, vault_id: &VaultId) {
        self.inner
            .member_cache
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .retain(|(v, _), _| v != vault_id);
    }

    /// Vaults in which `device` has (or had) a member record, from the server's index.
    pub async fn vaults_of(&self, device: &DeviceId) -> Result<Vec<VaultId>, ApiError> {
        let prefix = format!("{INDEX_PREFIX}{device}/");
        let metas = list_all(self.inner.blobs.as_ref(), &prefix)
            .await
            .map_err(storage)?;
        Ok(metas
            .iter()
            .filter_map(|m| m.key.strip_prefix(&prefix))
            .filter_map(|v| VaultId::parse(v).ok())
            .collect())
    }

    async fn index_member(&self, device: &DeviceId, vault_id: &VaultId) -> Result<(), ApiError> {
        self.inner
            .blobs
            .put(
                &format!("{INDEX_PREFIX}{device}/{vault_id}"),
                Vec::new(),
                PutCondition::None,
            )
            .await
            .map_err(storage)?;
        Ok(())
    }

    /// Rebuild the membership index by scanning every vault (after migrating blobs).
    /// Device-key bindings are restored for devices whose records all carry the same key;
    /// conflicting devices stay unbound (and fail closed on the relay). Returns the number
    /// of index entries written.
    pub async fn rebuild_member_index(&self) -> Result<usize, ApiError> {
        let metas = list_all(self.inner.blobs.as_ref(), VAULTS_PREFIX)
            .await
            .map_err(storage)?;
        let mut n = 0;
        let mut seen: HashMap<DeviceId, std::collections::BTreeSet<[u8; 32]>> = HashMap::new();
        for m in metas {
            let Some(rest) = m.key.strip_prefix(VAULTS_PREFIX) else {
                continue;
            };
            let Some((vid, key)) = rest.split_once('/') else {
                continue;
            };
            let (Ok(vid), Some((dev, rev))) = (VaultId::parse(vid), keys::parse_member(key)) else {
                continue;
            };
            self.index_member(&dev, &vid).await?;
            n += 1;
            if let Some(obj) = self.inner.blobs.get(&m.key).await.map_err(storage)?
                && let Ok(rec) = members::parse_record(&obj.bytes, &vid, &dev, rev)
            {
                seen.entry(dev).or_default().insert(rec.sign_pk);
            }
        }
        for (dev, keys) in seen {
            match keys.len() {
                1 => {
                    if let Some(k) = keys.first()
                        && self.bind_key(&dev, k).await.is_err()
                    {
                        tracing::warn!(device = %dev, "device already bound to another key");
                    }
                }
                _ => {
                    tracing::warn!(device = %dev, "device has records with different keys; left unbound")
                }
            }
        }
        Ok(n)
    }

    /// Current usage (computed lazily from a listing, then maintained incrementally).
    pub async fn usage(&self, vault_id: &VaultId) -> Result<VaultUsage, ApiError> {
        if let Some(u) = self.inner.usage.lock().await.get(vault_id) {
            return Ok(*u);
        }
        let ns = self.vault_store(vault_id)?;
        let all = list_all(&ns, "").await.map_err(storage)?;
        let u = VaultUsage {
            object_count: all.len() as u64,
            bytes_used: all.iter().map(|m| m.size).sum(),
        };
        Ok(*self
            .inner
            .usage
            .lock()
            .await
            .entry(vault_id.clone())
            .or_insert(u))
    }

    async fn adjust_usage(&self, vault_id: &VaultId, objects: i64, bytes: i64) {
        let snapshot = {
            let mut map = self.inner.usage.lock().await;
            let Some(u) = map.get_mut(vault_id) else {
                return;
            };
            u.object_count = (u.object_count as i64 + objects).max(0) as u64;
            u.bytes_used = (u.bytes_used as i64 + bytes).max(0) as u64;
            *u
        };
        self.inner.quota.usage_changed(vault_id, &snapshot).await;
    }

    async fn authenticate(
        &self,
        vault_id: &VaultId,
        parts: &Parts,
        body: &[u8],
    ) -> Result<Authed, ApiError> {
        if let Some(addr) = auth::client_key(parts)
            && !self.inner.address_limiter.check(&addr)
        {
            return Err(rate_limited());
        }
        let req = auth::parse_sig(parts)?;
        let now = self.inner.clock.unix();
        auth::check_skew(&req.header, now)?;
        let member = self
            .resolve_member(vault_id, &req.principal)
            .await?
            .filter(ResolvedMember::is_active)
            .ok_or_else(|| unverified(auth::UNVERIFIED_PRINCIPAL))?;
        auth::verify(
            &req,
            &member.sign_pk,
            parts.method.as_str(),
            &auth::path_and_query(parts),
            body,
            now,
            &self.inner.nonces,
        )?;
        if !self.inner.principal_limiter.check(req.principal.as_str()) {
            return Err(rate_limited());
        }
        Ok(Authed {
            principal: req.principal,
            member,
        })
    }

    /// Validate an object before it is stored (see module docs). For a manifest, returns
    /// the verified view it leads to (installed once the write succeeds).
    async fn validate_object(
        &self,
        vault_id: &VaultId,
        ns: &PrefixedStore,
        key: &str,
        bytes: &[u8],
    ) -> Result<Option<aipass_vault::VaultView>, ApiError> {
        let header = self.vault_header(vault_id).await?.ok_or_else(not_found)?;
        if key.starts_with(keys::MEMBERS_PREFIX) {
            let (dev, rev) = keys::parse_member(key).ok_or_else(|| invalid("invalid_key"))?;
            let rec = members::parse_record(bytes, vault_id, &dev, rev)?;
            let ctx = members::Ctx::new(ns, vault_id, &header.genesis_device_id);
            members::verify_record(&ctx, &rec, 0, true).await?;
            self.bind_key(&dev, &rec.sign_pk).await?;
            return Ok(None);
        }
        if key.starts_with(keys::MANIFESTS_PREFIX) {
            let seq = keys::parse_manifest(key).ok_or_else(|| invalid("invalid_key"))?;
            let m: Manifest =
                serde_json::from_slice(bytes).map_err(|_| invalid("manifest_malformed"))?;
            if m.format != 1 || m.vault_id != *vault_id || m.seq != seq || seq == 0 {
                return Err(invalid("manifest_mismatch"));
            }
            // the same transition rules as every client (author must be an active
            // owner/member of the previous manifest, prev_hash, member rules, …)
            let view = self
                .manifest_view(vault_id, true)
                .await?
                .ok_or_else(not_found)?;
            if seq <= view.seq() {
                return Err(precondition_failed().with_detail("reason", "immutable"));
            }
            if seq != view.seq() + 1 {
                return Err(integrity("manifest_sequence_gap"));
            }
            return view::verify_next(ns, &view, bytes.to_vec(), seq)
                .await
                .map(Some);
        }
        if key.starts_with(keys::ENTRIES_PREFIX) {
            let (eid, ver) = keys::parse_entry(key).ok_or_else(|| invalid("invalid_key"))?;
            let e: EntryVersion =
                serde_json::from_slice(bytes).map_err(|_| invalid("entry_malformed"))?;
            if e.format != 1
                || e.vault_id != *vault_id
                || e.entry_id != eid
                || e.version != ver
                || ver == 0
            {
                return Err(invalid("entry_mismatch"));
            }
            return Ok(None);
        }
        if key.starts_with(keys::RECOVERY_PREFIX) {
            let r: RecoveryWrap =
                serde_json::from_slice(bytes).map_err(|_| invalid("recovery_malformed"))?;
            if r.format != 1
                || r.vault_id != *vault_id
                || keys::recovery(r.key_epoch, r.kind) != key
            {
                return Err(invalid("recovery_mismatch"));
            }
            return Ok(None);
        }
        if key.starts_with(keys::KEYRING_PREFIX) {
            let k: KeyringRecord =
                serde_json::from_slice(bytes).map_err(|_| invalid("keyring_malformed"))?;
            if k.format != 1 || k.vault_id != *vault_id || keys::keyring(k.key_epoch) != key {
                return Err(invalid("keyring_mismatch"));
            }
            return Ok(None);
        }
        if key == keys::HEAD && bytes.len() > MAX_HEAD_BYTES {
            return Err(too_large(MAX_HEAD_BYTES));
        }
        Ok(None)
    }
}

fn filter_executor(principal: &PrincipalId, m: Option<ResolvedMember>) -> Option<ResolvedMember> {
    match principal {
        PrincipalId::Executor(_) => m.filter(|m| m.role == MemberRole::Executor),
        // an executor record answers only to its `exe_` kid (one valid kid per record)
        _ => m.filter(|m| m.role != MemberRole::Executor),
    }
}

// ======================================================================================
// Handlers
// ======================================================================================

type HResult = Result<Response, HttpError>;

fn parse_vault(s: &str, lang: Lang) -> Result<VaultId, HttpError> {
    VaultId::parse(s).map_err(|_| HttpError::new(invalid("invalid_vault_id"), lang))
}

async fn create_vault(State(s): State<SyncState>, req: Request) -> HResult {
    let (parts, body) = req.into_parts();
    let lang = lang_of(&parts.headers);
    let e = |err: ApiError| HttpError::new(err, lang);
    if let Some(addr) = auth::client_key(&parts)
        && !s.inner.address_limiter.check(&addr)
    {
        return Err(e(rate_limited()));
    }
    let bytes = read_body(body, MAX_CREATE_VAULT_BYTES).await.map_err(e)?;
    let bearer: Option<String> = match parts.headers.get(header::AUTHORIZATION) {
        Some(v) => {
            let v = v
                .to_str()
                .map_err(|_| e(unverified("malformed_authorization")))?;
            match aipass_types::signing::Authorization::parse(v) {
                Ok(aipass_types::signing::Authorization::Bearer(t)) => Some(t),
                _ => return Err(e(unverified("bearer_required"))),
            }
        }
        None => None,
    };
    let body: CreateVaultBody =
        serde_json::from_slice(&bytes).map_err(|_| e(invalid("invalid_body")))?;
    let header_bytes = body.vault_header.get().as_bytes().to_vec();
    let member_bytes = body.genesis_member.get().as_bytes().to_vec();
    let header: VaultHeader =
        serde_json::from_slice(&header_bytes).map_err(|_| e(invalid("vault_header_malformed")))?;
    let member: MemberRecord = serde_json::from_slice(&member_bytes)
        .map_err(|_| e(invalid("genesis_member_malformed")))?;
    if header.format != 1
        || member.format != 1
        || member.vault_id != header.vault_id
        || member.device_id != header.genesis_device_id
        || member.added_by != member.device_id
        || member.rev != 1
        || member.role != MemberRole::Owner
        || member.status != MemberStatus::Active
        || member.key_epoch == 0
    {
        return Err(e(invalid("genesis_mismatch")));
    }
    member
        .verify_signature(&member.sign_pk)
        .map_err(|_| e(integrity("genesis_member_signature_invalid")))?;
    header
        .verify_signature(&member.sign_pk)
        .map_err(|_| e(integrity("vault_header_signature_invalid")))?;
    let vault_id = header.vault_id.clone();
    let admission = s
        .inner
        .admission
        .admit(
            bearer.as_deref(),
            &AdmissionRequest {
                vault_id: vault_id.clone(),
                genesis_device_id: member.device_id.clone(),
                genesis_sign_pk: member.sign_pk,
            },
        )
        .await
        .map_err(e)?;
    let result = async {
        s.bind_key(&member.device_id, &member.sign_pk).await?;
        let ns = s.vault_store(&vault_id)?;
        let member_key = keys::member(&member.device_id, 1);
        // vault.json is the commit point; a retry with identical bytes completes creation
        match ns
            .put(
                keys::VAULT_HEADER,
                header_bytes.clone(),
                PutCondition::IfAbsent,
            )
            .await
            .map_err(storage)?
        {
            PutOutcome::Written { .. } => {}
            PutOutcome::PreconditionFailed => {
                let existing = ns.get(keys::VAULT_HEADER).await.map_err(storage)?;
                if existing.map(|o| o.bytes) != Some(header_bytes.clone()) {
                    return Err(precondition_failed().with_detail("reason", "vault_exists"));
                }
            }
        }
        match ns
            .put(&member_key, member_bytes.clone(), PutCondition::IfAbsent)
            .await
            .map_err(storage)?
        {
            PutOutcome::Written { .. } => {}
            PutOutcome::PreconditionFailed => {
                let existing = ns.get(&member_key).await.map_err(storage)?;
                if existing.map(|o| o.bytes) != Some(member_bytes.clone()) {
                    return Err(precondition_failed().with_detail("reason", "vault_exists"));
                }
            }
        }
        s.index_member(&member.device_id, &vault_id).await?;
        s.invalidate_vault(&vault_id);
        s.inner.usage.lock().await.remove(&vault_id);
        Ok(())
    }
    .await;
    if let Err(err) = result {
        s.inner.admission.abort(&admission).await;
        return Err(e(err));
    }
    s.inner
        .admission
        .commit(&admission, &vault_id)
        .await
        .map_err(e)?;
    tracing::info!(vault = %vault_id, "vault created");
    let info = vault_info_of(&s, &vault_id).await.map_err(e)?;
    Ok((StatusCode::CREATED, axum::Json(info)).into_response())
}

async fn vault_info_of(s: &SyncState, vault_id: &VaultId) -> Result<VaultInfo, ApiError> {
    let header = s.vault_header(vault_id).await?.ok_or_else(not_found)?;
    let usage = s.usage(vault_id).await?;
    Ok(VaultInfo {
        vault_id: vault_id.clone(),
        created_at: header.created_at,
        object_count: usage.object_count,
        bytes_used: usage.bytes_used,
        quota_bytes: s.inner.quota.quota_bytes(vault_id).await?,
    })
}

async fn vault_info(
    State(s): State<SyncState>,
    path: Result<Path<String>, PathRejection>,
    req: Request,
) -> HResult {
    let (parts, body) = req.into_parts();
    let lang = lang_of(&parts.headers);
    let Path(vault) = path.map_err(|_| HttpError::new(invalid("invalid_path"), lang))?;
    let e = |err: ApiError| HttpError::new(err, lang);
    let vault_id = parse_vault(&vault, lang)?;
    let body = read_body(body, 1024).await.map_err(e)?;
    s.authenticate(&vault_id, &parts, &body).await.map_err(e)?;
    let info = vault_info_of(&s, &vault_id).await.map_err(e)?;
    Ok(no_store(axum::Json(info).into_response()))
}

fn no_store(mut r: Response) -> Response {
    r.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    r
}

async fn get_object(
    State(s): State<SyncState>,
    path: Result<Path<(String, String)>, PathRejection>,
    req: Request,
) -> HResult {
    let (parts, body) = req.into_parts();
    let lang = lang_of(&parts.headers);
    let Path((vault, key)) = path.map_err(|_| HttpError::new(invalid("invalid_path"), lang))?;
    let e = |err: ApiError| HttpError::new(err, lang);
    let vault_id = parse_vault(&vault, lang)?;
    validate_key(&key).map_err(|_| e(invalid("invalid_key")))?;
    let body = read_body(body, 1024).await.map_err(e)?;
    s.authenticate(&vault_id, &parts, &body).await.map_err(e)?;
    let ns = s.vault_store(&vault_id).map_err(e)?;
    let obj = ns
        .get(&key)
        .await
        .map_err(|x| e(storage(x)))?
        .ok_or_else(|| e(not_found()))?;
    let mut resp = Response::new(Body::from(obj.bytes));
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    if let Some(v) = etag_header(&obj.etag) {
        h.insert(header::ETAG, v);
    }
    Ok(no_store(resp))
}

async fn put_object(
    State(s): State<SyncState>,
    path: Result<Path<(String, String)>, PathRejection>,
    req: Request,
) -> HResult {
    let (parts, body) = req.into_parts();
    let lang = lang_of(&parts.headers);
    let Path((vault, key)) = path.map_err(|_| HttpError::new(invalid("invalid_path"), lang))?;
    let e = |err: ApiError| HttpError::new(err, lang);
    let vault_id = parse_vault(&vault, lang)?;
    validate_key(&key).map_err(|_| e(invalid("invalid_key")))?;
    let max = s.inner.cfg.max_object_bytes;
    let bytes = read_body(body, max).await.map_err(e)?;
    let authed = s.authenticate(&vault_id, &parts, &bytes).await.map_err(e)?;
    if !authed.member.can_write() {
        return Err(e(forbidden("read_only_principal")));
    }
    let requested = requested_condition(&parts.headers).map_err(e)?;
    let ns = s.vault_store(&vault_id).map_err(e)?;
    let immutable = keys::is_immutable(&key);
    let cond = if immutable {
        match requested {
            // an If-Match on an immutable key can only mean an overwrite
            Requested::IfMatch(_) => {
                return Err(e(precondition_failed().with_detail("reason", "immutable")));
            }
            Requested::None | Requested::IfAbsent => PutCondition::IfAbsent,
        }
    } else {
        match requested {
            Requested::None => PutCondition::None,
            Requested::IfAbsent => PutCondition::IfAbsent,
            Requested::IfMatch(t) => PutCondition::IfMatch(t),
        }
    };
    // previous object (mutable keys only: immutable keys are create-only)
    let previous = if immutable {
        None
    } else {
        ns.get(&key).await.map_err(|x| e(storage(x)))?
    };
    if immutable && ns.get(&key).await.map_err(|x| e(storage(x)))?.is_some() {
        return Err(e(precondition_failed().with_detail("reason", "immutable")));
    }
    let next_view = s
        .validate_object(&vault_id, &ns, &key, &bytes)
        .await
        .map_err(e)?;
    let delta = WriteDelta {
        added_bytes: bytes.len() as u64,
        removed_bytes: previous.as_ref().map(|o| o.bytes.len() as u64).unwrap_or(0),
        new_object: previous.is_none(),
    };
    let len = bytes.len() as i64;
    let (objects, bytes_delta) = match &previous {
        Some(p) => (0, len - p.bytes.len() as i64),
        None => (1, len),
    };
    s.reserve_usage(&vault_id, &authed.principal, &delta, objects, bytes_delta)
        .await
        .map_err(e)?;
    let outcome = match ns.put(&key, bytes, cond).await {
        Ok(o) => o,
        Err(x) => {
            s.adjust_usage(&vault_id, -objects, -bytes_delta).await;
            return Err(e(storage(x)));
        }
    };
    let etag = match outcome {
        PutOutcome::Written { etag } => etag,
        PutOutcome::PreconditionFailed => {
            s.adjust_usage(&vault_id, -objects, -bytes_delta).await;
            return Err(e(precondition_failed().with_detail(
                "reason",
                if immutable {
                    "immutable"
                } else {
                    "condition_failed"
                },
            )));
        }
    };
    if key.starts_with(keys::MEMBERS_PREFIX) {
        if let Some((dev, _)) = keys::parse_member(&key) {
            s.index_member(&dev, &vault_id).await.map_err(e)?;
        }
        s.invalidate_vault(&vault_id);
    }
    if let Some(v) = next_view {
        s.install_view(&vault_id, Arc::new(v), true).await;
        s.invalidate_vault(&vault_id);
    }
    // the delta was reserved before the write; report the new usage
    s.adjust_usage(&vault_id, 0, 0).await;
    let status = if previous.is_some() {
        StatusCode::OK
    } else {
        StatusCode::CREATED
    };
    let mut resp = (status, axum::Json(PutObjectResponse { etag: etag.clone() })).into_response();
    if let Some(v) = etag_header(&etag) {
        resp.headers_mut().insert(header::ETAG, v);
    }
    Ok(no_store(resp))
}

async fn delete_object(
    State(s): State<SyncState>,
    path: Result<Path<(String, String)>, PathRejection>,
    req: Request,
) -> HResult {
    let (parts, body) = req.into_parts();
    let lang = lang_of(&parts.headers);
    let Path((vault, key)) = path.map_err(|_| HttpError::new(invalid("invalid_path"), lang))?;
    let e = |err: ApiError| HttpError::new(err, lang);
    let vault_id = parse_vault(&vault, lang)?;
    validate_key(&key).map_err(|_| e(invalid("invalid_key")))?;
    let body = read_body(body, 1024).await.map_err(e)?;
    let authed = s.authenticate(&vault_id, &parts, &body).await.map_err(e)?;
    if key == keys::VAULT_HEADER || key.starts_with(keys::MEMBERS_PREFIX) {
        return Err(e(forbidden("undeletable")));
    }
    let immutable = keys::is_immutable(&key);
    let allowed = if immutable {
        authed.member.is_active() && authed.member.role == MemberRole::Owner
    } else {
        authed.member.can_write()
    };
    if !allowed {
        return Err(e(forbidden("owner_required")));
    }
    let ns = s.vault_store(&vault_id).map_err(e)?;
    let previous = ns.get(&key).await.map_err(|x| e(storage(x)))?;
    ns.delete(&key).await.map_err(|x| e(storage(x)))?;
    if key.starts_with(keys::MANIFESTS_PREFIX) {
        s.forget_view(&vault_id).await;
        s.invalidate_vault(&vault_id);
    }
    if let Some(p) = previous {
        s.adjust_usage(&vault_id, -1, -(p.bytes.len() as i64)).await;
    }
    Ok(no_store(StatusCode::NO_CONTENT.into_response()))
}

async fn list_objects(
    State(s): State<SyncState>,
    path: Result<Path<String>, PathRejection>,
    query: Result<Query<ListParams>, axum::extract::rejection::QueryRejection>,
    req: Request,
) -> HResult {
    let (parts, body) = req.into_parts();
    let lang = lang_of(&parts.headers);
    let Path(vault) = path.map_err(|_| HttpError::new(invalid("invalid_path"), lang))?;
    let e = |err: ApiError| HttpError::new(err, lang);
    let vault_id = parse_vault(&vault, lang)?;
    let Query(q) = query.map_err(|_| e(invalid("invalid_query")))?;
    let body = read_body(body, 1024).await.map_err(e)?;
    s.authenticate(&vault_id, &parts, &body).await.map_err(e)?;
    let prefix = q.prefix.unwrap_or_default();
    validate_prefix(&prefix).map_err(|_| e(invalid("invalid_prefix")))?;
    if let Some(a) = &q.start_after {
        validate_prefix(a).map_err(|_| e(invalid("invalid_start_after")))?;
    }
    let max = s.inner.cfg.max_list_limit;
    let limit = q.limit.unwrap_or(max);
    if limit == 0 || limit > max {
        return Err(e(invalid("invalid_limit")));
    }
    let ns = s.vault_store(&vault_id).map_err(e)?;
    let mut page = ns
        .list(&prefix, q.start_after.as_deref(), limit + 1)
        .await
        .map_err(|x| e(storage(x)))?;
    let truncated = page.len() > limit;
    page.truncate(limit);
    Ok(no_store(
        axum::Json(ListObjectsResponse {
            objects: page,
            truncated,
        })
        .into_response(),
    ))
}

/// The sync API router (`/v1/vaults…`). Merge it into the embedding application's router.
pub fn sync_router(state: SyncState) -> Router {
    Router::new()
        .route("/v1/vaults", post(create_vault))
        .route("/v1/vaults/{vault_id}", get(vault_info))
        .route("/v1/vaults/{vault_id}/objects", get(list_objects))
        .route(
            "/v1/vaults/{vault_id}/objects/{*key}",
            get(get_object).put(put_object).delete(delete_object),
        )
        .with_state(state)
}
