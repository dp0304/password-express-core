// SPDX-License-Identifier: Apache-2.0
//! Server-side tracking of the **verified manifest chain** and the membership derived from
//! it (design doc §10.3–§10.4, acceptance A12).
//!
//! Signed member records alone only prove that *some* trusted device vouched for a device;
//! clients, however, only ever see (and owners only ever revoke) the devices listed in the
//! manifest. The server therefore:
//!
//! * walks `manifests/<seq>` with the clients' own pure transition check
//!   ([`aipass_vault::manifest::verify_transition`]) and keeps the latest verified view
//!   (cached in memory, checkpointed at `index/views/<vault_id>` so a restart does not
//!   re-verify the whole chain);
//! * accepts an uploaded manifest only when it is a valid transition from that view (its
//!   author must be an active owner/member *of the previous manifest*), so a device that
//!   was never listed cannot wedge every client's sync with an unacceptable manifest;
//! * treats a device as a member only when the latest view lists it (revoked there →
//!   denied), **or** — for the short window of an in-flight commit (records are written
//!   before the manifest that lists them) — when its record is vouched for by a device that
//!   is itself an effective active owner/member *now*. Revoking the voucher therefore
//!   revokes every unlisted device it introduced ("sock puppets").

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Instant;

use aipass_storage::{ObjectStore, PrefixedStore, PutCondition};
use aipass_types::ids::VaultId;
use aipass_types::vault::{MemberRecord, MemberRole, MemberStatus, keys, object_hash};
use aipass_types::{ApiError, ErrorCode};
use aipass_vault::manifest::{
    ManifestCandidate, VaultView, required_member_records, verify_header, verify_transition,
};
use futures::future::BoxFuture;
use serde::{Deserialize, Serialize};

use super::SyncState;
use super::members::{self, integrity};
use crate::error::storage;

/// Blob prefix of the server's manifest checkpoints.
pub const VIEW_INDEX_PREFIX: &str = "index/views/";

/// How many unlisted vouchers are followed before failing closed.
const MAX_VOUCH_DEPTH: usize = 8;

#[derive(Serialize, Deserialize)]
struct ViewCheckpoint {
    seq: u64,
    hash: String,
}

fn vault_err(e: aipass_vault::VaultError) -> ApiError {
    match e {
        aipass_vault::VaultError::Integrity(r) | aipass_vault::VaultError::Unsupported(r) => {
            integrity(r)
        }
        _ => integrity("manifest_invalid"),
    }
}

/// Privilege order used to combine the manifest's and the latest record's role.
fn rank(r: MemberRole) -> u8 {
    match r {
        MemberRole::Owner => 2,
        MemberRole::Member => 1,
        MemberRole::Executor => 0,
    }
}

impl SyncState {
    /// Latest verified manifest view of `vault_id` (`None` when the vault does not exist).
    /// `refresh` ignores the cache TTL and looks for newer manifests now.
    pub(crate) async fn manifest_view(
        &self,
        vault_id: &VaultId,
        refresh: bool,
    ) -> Result<Option<Arc<VaultView>>, ApiError> {
        let ttl = self.inner.cfg.member_cache_ttl;
        let cached = self
            .inner
            .views
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(vault_id)
            .cloned();
        if let Some((at, v)) = &cached
            && !refresh
            && at.elapsed() < ttl
        {
            return Ok(Some(v.clone()));
        }
        let ns = self.vault_store(vault_id)?;
        let start = match cached {
            Some((_, v)) => (*v).clone(),
            None => match self.checkpoint_view(vault_id, &ns).await? {
                Some(v) => v,
                None => match self.genesis_view(vault_id, &ns).await? {
                    Some(v) => v,
                    None => return Ok(None),
                },
            },
        };
        let start_seq = start.seq();
        let view = self.advance(&ns, start).await?;
        let advanced = view.seq() > start_seq;
        let view = Arc::new(view);
        self.install_view(vault_id, view.clone(), advanced).await;
        Ok(Some(view))
    }

    /// Cache `view` (unless a newer one is already cached) and checkpoint it.
    pub(crate) async fn install_view(
        &self,
        vault_id: &VaultId,
        view: Arc<VaultView>,
        checkpoint: bool,
    ) {
        {
            let mut map = self.inner.views.lock().unwrap_or_else(|p| p.into_inner());
            if map.len() > 100_000 {
                map.clear();
            }
            let keep = map
                .get(vault_id)
                .is_some_and(|(_, old)| old.seq() > view.seq());
            if !keep {
                map.insert(vault_id.clone(), (Instant::now(), view.clone()));
            }
        }
        if checkpoint && view.seq() > 0 {
            let cp = ViewCheckpoint {
                seq: view.seq(),
                hash: view.manifest_hash.clone(),
            };
            let Ok(bytes) = serde_json::to_vec(&cp) else {
                return;
            };
            if let Err(e) = self
                .inner
                .blobs
                .put(
                    &format!("{VIEW_INDEX_PREFIX}{vault_id}"),
                    bytes,
                    PutCondition::None,
                )
                .await
            {
                tracing::warn!(vault = %vault_id, error = %e, "could not checkpoint manifest view");
            }
        }
    }

    /// Forget the tracked view (e.g. after an owner deleted a manifest object).
    pub(crate) async fn forget_view(&self, vault_id: &VaultId) {
        self.inner
            .views
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(vault_id);
        if let Err(e) = self
            .inner
            .blobs
            .delete(&format!("{VIEW_INDEX_PREFIX}{vault_id}"))
            .await
        {
            tracing::warn!(vault = %vault_id, error = %e, "could not drop manifest checkpoint");
        }
    }

    async fn genesis_view(
        &self,
        vault_id: &VaultId,
        ns: &PrefixedStore,
    ) -> Result<Option<VaultView>, ApiError> {
        let Some(h) = ns.get(keys::VAULT_HEADER).await.map_err(storage)? else {
            return Ok(None);
        };
        let header = self
            .vault_header(vault_id)
            .await?
            .ok_or_else(|| ApiError::new(ErrorCode::NotFound))?;
        let g = ns
            .get(&keys::member(&header.genesis_device_id, 1))
            .await
            .map_err(storage)?
            .ok_or_else(|| integrity("genesis_member_missing"))?;
        verify_header(&h.bytes, &g.bytes, Some(vault_id))
            .map(Some)
            .map_err(vault_err)
    }

    /// View rebuilt from the server's own checkpoint (`None` when missing or stale).
    async fn checkpoint_view(
        &self,
        vault_id: &VaultId,
        ns: &PrefixedStore,
    ) -> Result<Option<VaultView>, ApiError> {
        let Some(obj) = self
            .inner
            .blobs
            .get(&format!("{VIEW_INDEX_PREFIX}{vault_id}"))
            .await
            .map_err(storage)?
        else {
            return Ok(None);
        };
        let Ok(cp) = serde_json::from_slice::<ViewCheckpoint>(&obj.bytes) else {
            return Ok(None);
        };
        let Some(header) = self.vault_header(vault_id).await? else {
            return Ok(None);
        };
        let Some(m) = ns.get(&keys::manifest(cp.seq)).await.map_err(storage)? else {
            return Ok(None);
        };
        if object_hash(&m.bytes) != cp.hash {
            return Ok(None);
        }
        let Ok(cand) = ManifestCandidate::parse(m.bytes, cp.seq) else {
            return Ok(None);
        };
        let mut recs = BTreeMap::new();
        for (dev, mm) in &cand.manifest.members {
            let Some(o) = ns.get(&keys::member(dev, mm.rev)).await.map_err(storage)? else {
                return Ok(None);
            };
            if object_hash(&o.bytes) != mm.hash {
                return Ok(None);
            }
            let Ok(rec) = members::parse_record(&o.bytes, vault_id, dev, mm.rev) else {
                return Ok(None);
            };
            recs.insert(dev.clone(), rec);
        }
        Ok(Some(VaultView {
            header,
            manifest: cand.manifest,
            manifest_hash: cand.hash,
            members: recs,
        }))
    }

    /// Follow `manifests/<seq+1>` while they verify; stops at the first one that does not
    /// (clients reject it as well).
    async fn advance(
        &self,
        ns: &PrefixedStore,
        mut view: VaultView,
    ) -> Result<VaultView, ApiError> {
        loop {
            let seq = view.seq() + 1;
            let Some(obj) = ns.get(&keys::manifest(seq)).await.map_err(storage)? else {
                return Ok(view);
            };
            match verify_next(ns, &view, obj.bytes, seq).await {
                Ok(next) => view = next,
                Err(e) if e.code == ErrorCode::IntegrityFailed => {
                    tracing::warn!(vault = %view.vault_id(), seq, "stored manifest failed verification; view stops before it");
                    return Ok(view);
                }
                Err(e) => return Err(e),
            }
        }
    }
}

/// Verify `bytes` as `manifests/<seq>` on top of `view` (member records read from `ns`).
pub(crate) async fn verify_next(
    ns: &dyn ObjectStore,
    view: &VaultView,
    bytes: Vec<u8>,
    seq: u64,
) -> Result<VaultView, ApiError> {
    let cand = ManifestCandidate::parse(bytes, seq).map_err(vault_err)?;
    let mut recs = BTreeMap::new();
    for (dev, rev) in required_member_records(view, &cand.manifest) {
        if let Some(o) = ns.get(&keys::member(&dev, rev)).await.map_err(storage)? {
            recs.insert((dev, rev), o.bytes);
        }
    }
    verify_transition(view, &cand, &recs).map_err(vault_err)
}

/// Effective membership of `rec` (the device's latest verified record) given the view.
/// `None` = not a member.
pub(crate) fn effective<'a>(
    ctx: &'a members::Ctx<'a>,
    view: &'a VaultView,
    rec: MemberRecord,
    depth: usize,
) -> BoxFuture<'a, Result<Option<MemberRecord>, ApiError>> {
    Box::pin(async move {
        if let Some(listed) = view.manifest.members.get(&rec.device_id) {
            let Some(listed_rec) = view.members.get(&rec.device_id) else {
                return Ok(None);
            };
            if listed.status == MemberStatus::Revoked
                || rec.rev < listed.rev
                || listed_rec.sign_pk != rec.sign_pk
            {
                return Ok(None);
            }
            // a pending (not yet committed) revision can only reduce privileges
            let mut out = rec;
            if rank(listed.role) < rank(out.role) {
                out.role = listed.role;
            }
            return Ok(Some(out));
        }
        // unlisted: only while its voucher is an effective active owner/member now
        if depth >= MAX_VOUCH_DEPTH {
            return Ok(None);
        }
        let Some(voucher) = members::voucher(ctx, &rec, depth).await? else {
            return Ok(None);
        };
        let Some(vrec) = members::resolve(ctx, voucher, None, depth).await? else {
            return Ok(None);
        };
        let Some(v) = effective(ctx, view, vrec, depth + 1).await? else {
            return Ok(None);
        };
        if v.status != MemberStatus::Active || !v.role.is_trusted_approver() {
            return Ok(None);
        }
        Ok(Some(rec))
    })
}
