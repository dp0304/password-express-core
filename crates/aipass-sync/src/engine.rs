// SPDX-License-Identifier: Apache-2.0
//! The sync engine (CONTRACTS §3.2, design doc §10.3–§10.6).
//!
//! * **Pull** — check that the checkpoint manifest is still on storage with the same hash
//!   (otherwise `ROLLBACK_DETECTED`, refuse to write); list `manifests/` after the
//!   checkpoint (plus a direct probe for listing lag); verify each manifest in order with
//!   [`verify_transition`] (signature chain, `prev_hash`, author membership, member and
//!   tombstone rules); fetch and verify changed member records and entry versions; store
//!   verified objects in the local cache.
//! * **Commit / push** — on top of the freshly pulled view, a [`CommitPlanner`] stages
//!   entry versions / member records into a [`ManifestDraft`]; the engine self-verifies the
//!   manifest, writes every object create-only (`IfAbsent`), then writes
//!   `manifests/<seq+1>` create-only — the commit point. `PreconditionFailed` → pull,
//!   re-plan (rebase / 3-way merge), retry, bounded by [`MAX_COMMIT_ATTEMPTS`].
//!
//! Storage is never trusted: ETags only serve concurrency control; integrity comes from
//! signatures, hashes and AEAD.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use aipass_storage::{LIST_PAGE, ObjectStore, PutCondition, PutOutcome};
use aipass_types::ids::{DeviceId, EntryId, VaultId};
use aipass_types::time::Timestamp;
use aipass_types::vault::{
    Checkpoint, EntryPayload, EntryVersion, Manifest, MemberRecord, SignedObject, VaultHeader,
    keys, object_hash,
};
use aipass_vault::manifest::{
    ManifestCandidate, ManifestDraft, VaultView, changed_entries, introduced_conflicts,
    required_member_records, staged_member_records, verify_entry_object, verify_header,
    verify_introduced_version, verify_other_version, verify_transition,
};
use aipass_vault::{Result, UnlockedVault, VaultError};
use async_trait::async_trait;

/// Maximum commit attempts (each attempt = pull + re-plan + create-only writes).
pub const MAX_COMMIT_ATTEMPTS: usize = 8;
/// Maximum orphan-collision retries within one commit.
pub const MAX_COLLISION_RETRIES: usize = 16;
/// Probe limit for manifests beyond the listing (listing lag).
pub const MAX_PROBE: usize = 64;

/// What a pull changed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PullStats {
    /// Manifests verified and applied.
    pub manifests: u64,
    /// Entries whose current version changed (or that were deleted).
    pub changed_entries: BTreeSet<EntryId>,
    /// Member records changed.
    pub members_changed: bool,
    /// The key epoch advanced.
    pub epoch_changed: bool,
}

impl PullStats {
    fn absorb(&mut self, other: PullStats) {
        self.manifests += other.manifests;
        self.changed_entries.extend(other.changed_entries);
        self.members_changed |= other.members_changed;
        self.epoch_changed |= other.epoch_changed;
    }
}

/// Result of a commit.
#[derive(Debug, Clone)]
pub struct CommitOutcome {
    /// Newest verified view (including our manifest when `committed`).
    pub view: VaultView,
    /// Whether a manifest was written (`false` when the planner changed nothing).
    pub committed: bool,
    /// Remote changes pulled along the way.
    pub pulled: PullStats,
    /// Attempts used.
    pub attempts: usize,
}

/// Context handed to a [`CommitPlanner`].
pub struct PlanContext<'a> {
    /// Engine (for reading entry versions).
    pub engine: &'a SyncEngine,
    /// The view the draft is based on.
    pub view: &'a VaultView,
    /// The unlocked vault (keys of the current epoch).
    pub vault: &'a UnlockedVault,
    /// Commit time.
    pub now: Timestamp,
}

impl PlanContext<'_> {
    /// Decrypted payload of `version` of `entry`.
    pub async fn payload(&self, entry: &EntryId, version: u64) -> Result<EntryPayload> {
        let ev = self.engine.entry_object(self.view, entry, version).await?;
        self.vault.decrypt_entry(entry, version, &ev)
    }
}

/// Stages changes on top of a freshly pulled view. `plan` may run several times (once per
/// attempt) and must rebuild everything from the given view each time.
#[async_trait]
pub trait CommitPlanner: Send {
    /// Stage changes into `draft`.
    async fn plan(&mut self, ctx: &PlanContext<'_>, draft: &mut ManifestDraft) -> Result<()>;
}

/// Client sync engine over a remote store and a local verified-object cache.
pub struct SyncEngine {
    remote: Arc<dyn ObjectStore>,
    cache: Arc<dyn ObjectStore>,
    vault_id: VaultId,
}

impl core::fmt::Debug for SyncEngine {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SyncEngine")
            .field("vault_id", &self.vault_id)
            .field("remote", &self.remote.describe())
            .finish_non_exhaustive()
    }
}

impl SyncEngine {
    /// Engine for `vault_id`.
    pub fn new(
        remote: Arc<dyn ObjectStore>,
        cache: Arc<dyn ObjectStore>,
        vault_id: VaultId,
    ) -> Self {
        Self {
            remote,
            cache,
            vault_id,
        }
    }

    /// Remote store.
    pub fn remote(&self) -> &Arc<dyn ObjectStore> {
        &self.remote
    }

    /// Local cache.
    pub fn cache(&self) -> &Arc<dyn ObjectStore> {
        &self.cache
    }

    /// Vault id.
    pub fn vault_id(&self) -> &VaultId {
        &self.vault_id
    }

    async fn remote_get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        Ok(self.remote.get(key).await?.map(|o| o.bytes))
    }

    async fn cache_get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        Ok(self.cache.get(key).await?.map(|o| o.bytes))
    }

    async fn cache_put(&self, key: &str, bytes: &[u8]) -> Result<()> {
        self.cache
            .put(key, bytes.to_vec(), PutCondition::None)
            .await?;
        Ok(())
    }

    /// Immutable object: cache first, then remote. `verify` runs on whichever copy is used;
    /// a cached copy that fails verification is dropped and refetched, and a remote copy is
    /// cached only after it verified (never cache unverified storage content).
    async fn verified<T>(
        &self,
        key: &str,
        verify: impl Fn(&[u8]) -> Result<T>,
    ) -> Result<Option<(T, Vec<u8>)>> {
        if let Some(b) = self.cache_get(key).await? {
            match verify(&b) {
                Ok(t) => return Ok(Some((t, b))),
                Err(e) => {
                    tracing::warn!(error = %e, "cached object failed verification; refetching");
                    self.cache.delete(key).await?;
                }
            }
        }
        let Some(b) = self.remote_get(key).await? else {
            return Ok(None);
        };
        let t = verify(&b)?;
        self.cache_put(key, &b).await?;
        Ok(Some((t, b)))
    }

    /// Verify `vault.json` + genesis member (pinned in the local cache after first use).
    pub async fn genesis_view(&self) -> Result<VaultView> {
        if let Ok(v) = self.genesis_view_cached().await {
            return Ok(v);
        }
        let hb = self
            .remote_get(keys::VAULT_HEADER)
            .await?
            .ok_or(VaultError::NotFound("vault.json"))?;
        let header: VaultHeader = serde_json::from_slice(&hb)
            .map_err(|_| VaultError::Integrity("vault.json is not valid"))?;
        let gk = keys::member(&header.genesis_device_id, 1);
        let gb = self
            .remote_get(&gk)
            .await?
            .ok_or(VaultError::Integrity("genesis member record missing"))?;
        let view = verify_header(&hb, &gb, Some(&self.vault_id))?;
        self.cache_put(keys::VAULT_HEADER, &hb).await?;
        self.cache_put(&gk, &gb).await?;
        Ok(view)
    }

    /// Re-check the pinned header against storage (detects a replaced `vault.json`).
    pub async fn recheck_header(&self) -> Result<()> {
        let cached = self.cache_get(keys::VAULT_HEADER).await?;
        let remote = self.remote_get(keys::VAULT_HEADER).await?;
        match (cached, remote) {
            (Some(c), Some(r)) if c == r => Ok(()),
            (Some(_), Some(_)) => Err(VaultError::Integrity(
                "vault.json on storage differs from the pinned copy",
            )),
            (Some(_), None) => Err(VaultError::Rollback("vault.json missing from storage")),
            (None, _) => self.genesis_view().await.map(|_| ()),
        }
    }

    /// Rebuild the verified view at `checkpoint` from the local cache (offline unlock).
    pub async fn cached_view(&self, checkpoint: &Checkpoint) -> Result<VaultView> {
        if checkpoint.vault_id != self.vault_id {
            return Err(VaultError::Integrity("checkpoint belongs to another vault"));
        }
        let g = self.genesis_view_cached().await?;
        let mk = keys::manifest(checkpoint.seq);
        let mb = self
            .cache_get(&mk)
            .await?
            .ok_or(VaultError::Integrity("cached manifest missing"))?;
        if object_hash(&mb) != checkpoint.hash {
            return Err(VaultError::Integrity(
                "cached manifest does not match the checkpoint",
            ));
        }
        let m: Manifest = serde_json::from_slice(&mb)
            .map_err(|_| VaultError::Integrity("cached manifest invalid"))?;
        let mut members = BTreeMap::new();
        for (id, mm) in &m.members {
            let b = self
                .cache_get(&keys::member(id, mm.rev))
                .await?
                .ok_or(VaultError::Integrity("cached member record missing"))?;
            if object_hash(&b) != mm.hash {
                return Err(VaultError::Integrity("cached member record hash mismatch"));
            }
            let r: MemberRecord = serde_json::from_slice(&b)
                .map_err(|_| VaultError::Integrity("cached member record invalid"))?;
            members.insert(id.clone(), r);
        }
        let author = members
            .get(&m.author_device_id)
            .ok_or(VaultError::Integrity("manifest author unknown"))?;
        m.verify_signature(&author.sign_pk)
            .map_err(|_| VaultError::Integrity("cached manifest signature invalid"))?;
        Ok(VaultView {
            header: g.header,
            manifest: m,
            manifest_hash: checkpoint.hash.clone(),
            members,
        })
    }

    async fn genesis_view_cached(&self) -> Result<VaultView> {
        let hb = self
            .cache_get(keys::VAULT_HEADER)
            .await?
            .ok_or(VaultError::NotFound("cached vault.json"))?;
        let header: VaultHeader = serde_json::from_slice(&hb)
            .map_err(|_| VaultError::Integrity("vault.json is not valid"))?;
        let gb = self
            .cache_get(&keys::member(&header.genesis_device_id, 1))
            .await?
            .ok_or(VaultError::Integrity("cached genesis member missing"))?;
        verify_header(&hb, &gb, Some(&self.vault_id))
    }

    /// Pull and verify every manifest after `start`. Never writes to the remote.
    pub async fn pull(&self, start: &VaultView) -> Result<(VaultView, PullStats)> {
        if start.vault_id() != &self.vault_id {
            return Err(VaultError::Integrity("view belongs to another vault"));
        }
        if let Some(cp) = start.checkpoint() {
            match self.remote_get(&keys::manifest(cp.seq)).await? {
                None => {
                    return Err(VaultError::Rollback(
                        "the newest known manifest is missing from storage",
                    ));
                }
                Some(b) if object_hash(&b) != cp.hash => {
                    return Err(VaultError::Rollback(
                        "the manifest at the known checkpoint was replaced",
                    ));
                }
                Some(_) => {}
            }
        }
        let mut seqs: Vec<u64> = Vec::new();
        let mut after: Option<String> = (start.seq() > 0).then(|| keys::manifest(start.seq()));
        loop {
            let page = self
                .remote
                .list(keys::MANIFESTS_PREFIX, after.as_deref(), LIST_PAGE)
                .await?;
            let n = page.len();
            if let (Some(prev), Some(first)) = (after.as_deref(), page.first())
                && first.key.as_str() <= prev
            {
                return Err(VaultError::Storage(aipass_storage::StorageError::Backend {
                    status: None,
                    message: "listing did not advance".into(),
                }));
            }
            for m in &page {
                if let Some(s) = keys::parse_manifest(&m.key)
                    && s > start.seq()
                {
                    seqs.push(s);
                }
            }
            after = page.last().map(|m| m.key.clone());
            if n < LIST_PAGE {
                break;
            }
        }
        seqs.sort_unstable();
        seqs.dedup();
        let mut view = start.clone();
        let mut stats = PullStats::default();
        for s in seqs {
            if s != view.seq() + 1 {
                return Err(VaultError::Integrity("manifest sequence gap on storage"));
            }
            let b = self
                .remote_get(&keys::manifest(s))
                .await?
                .ok_or(VaultError::Integrity("listed manifest could not be read"))?;
            let (next, st) = self.apply(&view, b, s).await?;
            view = next;
            stats.absorb(st);
        }
        // listing lag: probe directly for newer manifests
        for _ in 0..MAX_PROBE {
            let s = view.seq() + 1;
            let Some(b) = self.remote_get(&keys::manifest(s)).await? else {
                break;
            };
            let (next, st) = self.apply(&view, b, s).await?;
            view = next;
            stats.absorb(st);
        }
        Ok((view, stats))
    }

    async fn apply(
        &self,
        prev: &VaultView,
        bytes: Vec<u8>,
        seq: u64,
    ) -> Result<(VaultView, PullStats)> {
        let cand = ManifestCandidate::parse(bytes, seq)?;
        let mut records = BTreeMap::new();
        for (id, rev) in required_member_records(prev, &cand.manifest) {
            let k = keys::member(&id, rev);
            let b = self
                .remote_get(&k)
                .await?
                .ok_or(VaultError::Integrity("member record missing from storage"))?;
            records.insert((id, rev), b);
        }
        let next = verify_transition(prev, &cand, &records)?;
        let mut stats = PullStats {
            manifests: 1,
            ..Default::default()
        };
        let mut fetched: Vec<(String, Vec<u8>)> = Vec::new();
        for (id, me) in changed_entries(prev, &next) {
            let k = keys::entry(&id, me.version);
            let cached = self
                .cache_get(&k)
                .await?
                .filter(|b| verify_entry_object(&next, &id, b, true).is_ok());
            let b = match cached {
                Some(b) => b,
                None => {
                    let b = self
                        .remote_get(&k)
                        .await?
                        .ok_or(VaultError::Integrity("entry version missing from storage"))?;
                    verify_entry_object(&next, &id, &b, true)?;
                    b
                }
            };
            fetched.push((k, b));
            stats.changed_entries.insert(id);
        }
        // conflict versions are not hash-listed: verify and pin them right away (CVS-04)
        for (id, v) in introduced_conflicts(prev, &next) {
            let k = keys::entry(&id, v);
            let cached = self
                .cache_get(&k)
                .await?
                .filter(|b| verify_introduced_version(&next, &id, v, b).is_ok());
            let b = match cached {
                Some(b) => b,
                None => {
                    let b = self
                        .remote_get(&k)
                        .await?
                        .ok_or(VaultError::Integrity("entry version missing from storage"))?;
                    verify_introduced_version(&next, &id, v, &b)?;
                    b
                }
            };
            fetched.push((k, b));
        }
        for id in prev.manifest.entries.keys() {
            if next.manifest.tombstones.contains_key(id) {
                stats.changed_entries.insert(id.clone());
            }
        }
        for (id, e) in &next.manifest.entries {
            if prev
                .manifest
                .entries
                .get(id)
                .is_some_and(|p| p.conflict_versions != e.conflict_versions)
            {
                stats.changed_entries.insert(id.clone());
            }
        }
        if next.manifest.key_epoch > prev.manifest.key_epoch {
            // the keyring is fetched (and structurally checked) on demand by keyring_bytes
            stats.epoch_changed = true;
        }
        stats.members_changed = !records.is_empty();
        // cache only after everything verified
        for ((id, rev), b) in &records {
            self.cache_put(&keys::member(id, *rev), b).await?;
        }
        for (k, b) in &fetched {
            self.cache_put(k, b).await?;
        }
        self.cache_put(&cand.key(), &cand.bytes).await?;
        Ok((next, stats))
    }

    /// Entry version object (cache first), verified against `view`.
    pub async fn entry_object(
        &self,
        view: &VaultView,
        entry: &EntryId,
        version: u64,
    ) -> Result<EntryVersion> {
        let k = keys::entry(entry, version);
        let current = view
            .manifest
            .entries
            .get(entry)
            .is_some_and(|e| e.version == version);
        let got = self
            .verified(&k, |b| {
                if current {
                    verify_entry_object(view, entry, b, false)
                } else {
                    verify_other_version(view, entry, version, b)
                }
            })
            .await?;
        got.map(|(ev, _)| ev)
            .ok_or(VaultError::NotFound("entry version"))
    }

    /// `keyring/<epoch>.json` bytes (cache first; structurally checked — the AEAD is
    /// checked by the caller with the VMK).
    pub async fn keyring_bytes(&self, epoch: u32) -> Result<Option<Vec<u8>>> {
        if epoch <= 1 {
            return Ok(None);
        }
        let vault = self.vault_id.clone();
        let got = self
            .verified(&keys::keyring(epoch), |b| {
                let r: aipass_types::vault::KeyringRecord = serde_json::from_slice(b)
                    .map_err(|_| VaultError::Integrity("keyring record is not valid"))?;
                if r.vault_id != vault || r.key_epoch != epoch {
                    return Err(VaultError::Integrity("keyring record does not match"));
                }
                Ok(())
            })
            .await?;
        Ok(got.map(|(_, b)| b))
    }

    /// Any immutable JSON object (cache first, structurally checked as JSON).
    pub async fn object(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let got = self
            .verified(key, |b| {
                serde_json::from_slice::<serde_json::Value>(b)
                    .map(|_| ())
                    .map_err(|_| VaultError::Integrity("object is not valid JSON"))
            })
            .await?;
        Ok(got.map(|(_, b)| b))
    }

    /// Write a standalone immutable object create-only (e.g. a recovery wrap). Returns
    /// `false` when an object already exists under that key.
    pub async fn put_create_only(&self, key: &str, bytes: Vec<u8>) -> Result<bool> {
        match self
            .remote
            .put(key, bytes.clone(), PutCondition::IfAbsent)
            .await?
        {
            PutOutcome::Written { .. } => {
                self.cache_put(key, &bytes).await?;
                Ok(true)
            }
            PutOutcome::PreconditionFailed => Ok(false),
        }
    }

    /// Write the objects of a brand-new vault (genesis) and its first manifest.
    ///
    /// Idempotent per object: when a key already exists (e.g. `vault.json` and the genesis
    /// member record stored by `POST /v1/vaults`, or an interrupted earlier attempt), the
    /// stored object is accepted only if its bytes are **identical** to ours; any other
    /// content means another vault (or a tampered one) is already there →
    /// [`VaultError::AlreadyExists`]. The manifest is written last (the commit point).
    pub async fn write_genesis(
        &self,
        objects: &[(String, Vec<u8>)],
        manifest: &ManifestCandidate,
    ) -> Result<()> {
        for (k, b) in objects {
            self.put_genesis_object(k, b).await?;
        }
        self.put_genesis_object(&manifest.key(), &manifest.bytes)
            .await?;
        for (k, b) in objects {
            self.cache_put(k, b).await?;
        }
        self.cache_put(&manifest.key(), &manifest.bytes).await?;
        self.update_head(manifest.manifest.seq).await;
        Ok(())
    }

    /// Create-only write that tolerates an existing byte-identical object.
    async fn put_genesis_object(&self, key: &str, bytes: &[u8]) -> Result<()> {
        match self
            .remote
            .put(key, bytes.to_vec(), PutCondition::IfAbsent)
            .await?
        {
            PutOutcome::Written { .. } => Ok(()),
            PutOutcome::PreconditionFailed => match self.remote.get(key).await? {
                Some(existing) if existing.bytes == bytes => Ok(()),
                _ => Err(VaultError::AlreadyExists),
            },
        }
    }

    async fn update_head(&self, seq: u64) {
        // HEAD is an untrusted hint; failures are harmless
        if let Err(e) = self
            .remote
            .put(keys::HEAD, seq.to_string().into_bytes(), PutCondition::None)
            .await
        {
            tracing::debug!(error = %e, "HEAD update failed");
        }
    }

    /// Learn new epochs for `vault` from `view` (own member record + keyring); refuses a
    /// revoked or non-member device.
    pub async fn refresh_keys(&self, view: &VaultView, vault: &mut UnlockedVault) -> Result<()> {
        let rec = view.member(vault.device_id()).ok_or(VaultError::Forbidden(
            "this device is not a member of the vault",
        ))?;
        if view.is_revoked(vault.device_id()) {
            return Err(VaultError::Revoked);
        }
        if rec.key_epoch > vault.key_epoch() || !vault.epochs().contains(&rec.key_epoch) {
            let kb = self.keyring_bytes(rec.key_epoch).await?;
            if let Err(e) = vault.refresh_from_view(view, kb.as_deref()) {
                // a cached keyring that does not open: drop it and try the stored copy once
                let kk = keys::keyring(rec.key_epoch);
                self.cache.delete(&kk).await?;
                let Some(fresh) = self.remote_get(&kk).await? else {
                    return Err(e);
                };
                vault.refresh_from_view(view, Some(&fresh))?;
                self.cache_put(&kk, &fresh).await?;
            }
        }
        Ok(())
    }

    /// Open the vault for `device` from `view` (own wrap + keyring), retrying once with the
    /// stored keyring if the cached copy does not open.
    pub async fn open_vault(
        &self,
        view: &VaultView,
        device: &DeviceId,
        identity: aipass_crypto::DeviceIdentity,
    ) -> Result<UnlockedVault> {
        let epoch = view.member(device).map(|m| m.key_epoch).unwrap_or(1);
        let kb = self.keyring_bytes(epoch).await?;
        match UnlockedVault::open(view, device.clone(), identity.clone(), kb.as_deref()) {
            Ok(v) => Ok(v),
            Err(e) if epoch > 1 => {
                let kk = keys::keyring(epoch);
                self.cache.delete(&kk).await?;
                let Some(fresh) = self.remote_get(&kk).await.ok().flatten() else {
                    return Err(e);
                };
                let v = UnlockedVault::open(view, device.clone(), identity, Some(&fresh))?;
                self.cache_put(&kk, &fresh).await?;
                Ok(v)
            }
            Err(e) => Err(e),
        }
    }

    /// Pull, plan, write create-only, retry on races (see the module docs).
    pub async fn commit(
        &self,
        start: &VaultView,
        vault: &mut UnlockedVault,
        planner: &mut dyn CommitPlanner,
    ) -> Result<CommitOutcome> {
        let mut view = start.clone();
        let mut pulled = PullStats::default();
        let mut taken: BTreeSet<String> = BTreeSet::new();
        let mut collisions = 0usize;
        let mut attempt = 0usize;
        while attempt < MAX_COMMIT_ATTEMPTS {
            attempt += 1;
            let (v, st) = self.pull(&view).await?;
            view = v;
            pulled.absorb(st);
            if !view.is_active_approver(vault.device_id()) {
                return Err(if view.is_revoked(vault.device_id()) {
                    VaultError::Revoked
                } else {
                    VaultError::Forbidden("only active owners or members can write to the vault")
                });
            }
            self.refresh_keys(&view, vault).await?;
            if vault.key_epoch() != view.manifest.key_epoch {
                return Err(VaultError::SecretUnavailable(
                    "the current vault key is not available on this device",
                ));
            }
            let now = aipass_types::time::now();
            let mut draft = ManifestDraft::from_view(&view).with_taken(&taken);
            {
                let ctx = PlanContext {
                    engine: self,
                    view: &view,
                    vault,
                    now,
                };
                planner.plan(&ctx, &mut draft).await?;
            }
            if draft.is_unchanged() {
                return Ok(CommitOutcome {
                    view,
                    committed: false,
                    pulled,
                    attempts: attempt,
                });
            }
            let author: DeviceId = vault.device_id().clone();
            let (cand, objects) = draft.finish(vault.identity(), &author, &now)?;
            // never publish a manifest other devices would reject
            let recs = staged_member_records(&view, &cand, &objects);
            let next = verify_transition(&view, &cand, &recs)?;

            let mut collided = false;
            for (k, b) in &objects {
                match self
                    .remote
                    .put(k, b.clone(), PutCondition::IfAbsent)
                    .await?
                {
                    PutOutcome::Written { .. } => {}
                    PutOutcome::PreconditionFailed => match self.remote_get(k).await? {
                        Some(existing) if existing == *b => {}
                        _ => {
                            taken.insert(k.clone());
                            collided = true;
                        }
                    },
                }
            }
            if collided {
                collisions += 1;
                if collisions > MAX_COLLISION_RETRIES {
                    return Err(VaultError::PreconditionFailed(
                        "could not allocate object names on storage",
                    ));
                }
                attempt -= 1; // orphan collisions do not count as races
                continue;
            }
            match self
                .remote
                .put(&cand.key(), cand.bytes.clone(), PutCondition::IfAbsent)
                .await?
            {
                PutOutcome::Written { .. } => {
                    for (k, b) in &objects {
                        self.cache_put(k, b).await?;
                    }
                    self.cache_put(&cand.key(), &cand.bytes).await?;
                    self.update_head(cand.manifest.seq).await;
                    return Ok(CommitOutcome {
                        view: next,
                        committed: true,
                        pulled,
                        attempts: attempt,
                    });
                }
                PutOutcome::PreconditionFailed => {
                    tracing::debug!(seq = cand.manifest.seq, "manifest race lost; rebasing");
                    continue;
                }
            }
        }
        Err(VaultError::PreconditionFailed(
            "too many concurrent changes; try again",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aipass_crypto::Argon2Params;
    use aipass_storage::MemoryStore;
    use aipass_types::vault::Platform;

    fn genesis() -> aipass_vault::vault::Genesis {
        aipass_vault::vault::create_genesis(aipass_vault::GenesisParams {
            device_name: "test",
            platform: Platform::Cli,
            master_password: None,
            argon2: Argon2Params::INSECURE_FAST_FOR_TESTS_ONLY,
            now: aipass_types::time::now(),
        })
        .unwrap()
    }

    fn engine(remote: Arc<MemoryStore>, vault: &VaultId) -> SyncEngine {
        SyncEngine::new(remote, Arc::new(MemoryStore::new()), vault.clone())
    }

    #[tokio::test]
    async fn genesis_accepts_identical_preprovisioned_objects() {
        let g = genesis();
        let remote = Arc::new(MemoryStore::new());
        // what `POST /v1/vaults` stores before the client writes its genesis
        let pre: Vec<_> = g
            .objects
            .iter()
            .filter(|(k, _)| k == keys::VAULT_HEADER || *k == keys::member(&g.device_id, 1))
            .collect();
        assert_eq!(pre.len(), 2);
        for (k, b) in pre {
            remote
                .put(k, b.clone(), PutCondition::IfAbsent)
                .await
                .unwrap();
        }
        let e = engine(remote.clone(), &g.vault_id);
        e.write_genesis(&g.objects, &g.manifest).await.unwrap();
        for (k, b) in &g.objects {
            assert_eq!(&remote.get(k).await.unwrap().unwrap().bytes, b);
        }
        assert_eq!(
            remote.get(&g.manifest.key()).await.unwrap().unwrap().bytes,
            g.manifest.bytes
        );
        // a full retry of the same genesis is idempotent too
        e.write_genesis(&g.objects, &g.manifest).await.unwrap();
    }

    #[tokio::test]
    async fn genesis_refuses_different_existing_objects() {
        let g = genesis();
        let other = genesis();
        // another vault's header under the same key
        let remote = Arc::new(MemoryStore::new());
        remote
            .put(
                keys::VAULT_HEADER,
                other
                    .objects
                    .iter()
                    .find(|(k, _)| k == keys::VAULT_HEADER)
                    .unwrap()
                    .1
                    .clone(),
                PutCondition::IfAbsent,
            )
            .await
            .unwrap();
        let e = engine(remote.clone(), &g.vault_id);
        assert!(matches!(
            e.write_genesis(&g.objects, &g.manifest).await,
            Err(VaultError::AlreadyExists)
        ));
        assert!(
            remote.get(&g.manifest.key()).await.unwrap().is_none(),
            "no commit point"
        );

        // identical objects but a different first manifest already committed
        let remote = Arc::new(MemoryStore::new());
        remote
            .put(
                &g.manifest.key(),
                other.manifest.bytes.clone(),
                PutCondition::IfAbsent,
            )
            .await
            .unwrap();
        let e = engine(remote, &g.vault_id);
        assert!(matches!(
            e.write_genesis(&g.objects, &g.manifest).await,
            Err(VaultError::AlreadyExists)
        ));
    }
}
