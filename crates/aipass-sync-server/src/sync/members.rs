// SPDX-License-Identifier: Apache-2.0
//! Member resolution from `members/<device_id>/<rev>.json` with signature checks — the
//! server's only source of truth for "is this kid an active member of this vault"
//! (CONTRACTS §2.3, §3.3).
//!
//! Rules (applied when a record is uploaded **and** every time it is used):
//! * the record parses, `format == 1`, `vault_id` / `device_id` / `rev` match its key;
//! * **genesis** (`members/<genesis>/1.json`): self-signed, role `owner`, status `active`,
//!   and the device is `vault.json`'s `genesis_device_id`;
//! * **self-signed later revision**: the device's previous revision must be an *active*
//!   owner/member with the same keys, a member cannot promote itself to owner, and only
//!   an owner may change its own role or status;
//! * **signed by another device** (`added_by`): the signer's latest verified record must
//!   have role owner/member (an owner for `owner` records), and the signature must verify
//!   with that record's `sign_pk`. Historical signatures of since-revoked signers stay
//!   valid (records are immutable and were checked on upload) — **on upload** the signer
//!   must be active. When a stored record's signer was later re-signed by a device that
//!   this record vouches for (key rotation after a revocation), the signer is resolved at
//!   its newest revision outside that loop (`resolve_signer`); uploads never do this;
//! * **transitions** (mirroring the client's `verify_transition`): keys never change; a
//!   revoked device is never reinstated; a change of role or status, and any new revision
//!   of an owner's record, needs an owner signer; a device's first record is active.
//! * The **latest** revision decides status and role. If the latest revision fails
//!   verification the device is treated as unknown (fail closed — a damaged revocation
//!   record never resurrects an older active revision).
//!
//! These rules only make individual records trustworthy. Whether a device is a member
//! at all is decided together with the verified manifest chain (`super::view`).

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

use aipass_storage::{ObjectStore, list_all};
use aipass_types::ids::{DeviceId, VaultId};
use aipass_types::vault::{MemberRecord, MemberRole, MemberStatus, SignedObject, keys};
use aipass_types::{ApiError, ErrorCode};
use futures::future::BoxFuture;

use crate::error::storage;

/// Maximum signer-chain depth followed.
const MAX_DEPTH: usize = 32;

/// Integrity failure with a short reason.
pub(crate) fn integrity(reason: &'static str) -> ApiError {
    ApiError::new(ErrorCode::IntegrityFailed).with_detail("reason", reason)
}

type MemoKey = (DeviceId, u64);

/// Resolution context for one vault and one request.
pub(crate) struct Ctx<'a> {
    pub store: &'a dyn ObjectStore,
    pub vault_id: &'a VaultId,
    pub genesis: &'a DeviceId,
    memo: Mutex<HashMap<MemoKey, Option<MemberRecord>>>,
    revs: Mutex<HashMap<DeviceId, Vec<u64>>>,
    in_progress: Mutex<HashSet<MemoKey>>,
}

impl<'a> Ctx<'a> {
    pub fn new(store: &'a dyn ObjectStore, vault_id: &'a VaultId, genesis: &'a DeviceId) -> Self {
        Self {
            store,
            vault_id,
            genesis,
            memo: Mutex::new(HashMap::new()),
            revs: Mutex::new(HashMap::new()),
            in_progress: Mutex::new(HashSet::new()),
        }
    }

    async fn revs_of(&self, dev: &DeviceId) -> Result<Vec<u64>, ApiError> {
        if let Some(r) = self.revs.lock().unwrap_or_else(|p| p.into_inner()).get(dev) {
            return Ok(r.clone());
        }
        let r = list_revs(self.store, dev).await?;
        self.revs
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(dev.clone(), r.clone());
        Ok(r)
    }
}

/// Revisions present for `dev`, ascending.
pub(crate) async fn list_revs(
    store: &dyn ObjectStore,
    dev: &DeviceId,
) -> Result<Vec<u64>, ApiError> {
    let metas = list_all(store, &format!("{}{dev}/", keys::MEMBERS_PREFIX))
        .await
        .map_err(storage)?;
    let mut revs: Vec<u64> = metas
        .iter()
        .filter_map(|m| keys::parse_member(&m.key))
        .filter(|(d, _)| d == dev)
        .map(|(_, r)| r)
        .collect();
    revs.sort_unstable();
    revs.dedup();
    Ok(revs)
}

/// Parse a member record and check it against its key and vault.
pub(crate) fn parse_record(
    bytes: &[u8],
    vault_id: &VaultId,
    dev: &DeviceId,
    rev: u64,
) -> Result<MemberRecord, ApiError> {
    let rec: MemberRecord =
        serde_json::from_slice(bytes).map_err(|_| integrity("member_record_malformed"))?;
    if rec.format != 1
        || rec.vault_id != *vault_id
        || rec.device_id != *dev
        || rec.rev != rev
        || rev == 0
    {
        return Err(integrity("member_record_mismatch"));
    }
    Ok(rec)
}

async fn load(ctx: &Ctx<'_>, dev: &DeviceId, rev: u64) -> Result<Option<MemberRecord>, ApiError> {
    let Some(obj) = ctx
        .store
        .get(&keys::member(dev, rev))
        .await
        .map_err(storage)?
    else {
        return Ok(None);
    };
    parse_record(&obj.bytes, ctx.vault_id, dev, rev).map(Some)
}

/// Latest verified record of `dev` with `rev < below` (any rev when `None`). Every older
/// revision is verified first (bottom-up, memoised), so each revision's transition check
/// only recurses one level and long revision histories stay within [`MAX_DEPTH`].
pub(crate) fn resolve<'a>(
    ctx: &'a Ctx<'a>,
    dev: DeviceId,
    below: Option<u64>,
    depth: usize,
) -> BoxFuture<'a, Result<Option<MemberRecord>, ApiError>> {
    Box::pin(async move {
        let revs = ctx.revs_of(&dev).await?;
        let Some(target) = revs
            .iter()
            .rev()
            .find(|r| below.is_none_or(|b| **r < b))
            .copied()
        else {
            return Ok(None);
        };
        for r in revs.iter().copied().filter(|r| *r < target) {
            verify_rev(ctx, &dev, r, depth).await?;
        }
        verify_rev(ctx, &dev, target, depth).await
    })
}

/// Load and verify one revision (memoised; cycles and over-deep chains fail closed).
fn verify_rev<'a>(
    ctx: &'a Ctx<'a>,
    dev: &'a DeviceId,
    rev: u64,
    depth: usize,
) -> BoxFuture<'a, Result<Option<MemberRecord>, ApiError>> {
    Box::pin(async move {
        let key = (dev.clone(), rev);
        if let Some(hit) = ctx.memo.lock().unwrap_or_else(|p| p.into_inner()).get(&key) {
            return Ok(hit.clone());
        }
        if depth > MAX_DEPTH {
            return Err(integrity("member_chain_too_deep"));
        }
        if !ctx
            .in_progress
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(key.clone())
        {
            return Err(integrity("member_chain_cycle"));
        }
        let result = async {
            let Some(rec) = load(ctx, dev, rev).await? else {
                return Ok(None);
            };
            verify_record(ctx, &rec, depth + 1, false).await?;
            Ok(Some(rec))
        }
        .await;
        ctx.in_progress
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&key);
        if let Ok(v) = &result {
            ctx.memo
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .insert(key, v.clone());
        }
        result
    })
}

/// Verify one record's signature chain and transition (see module docs). `upload` adds
/// the checks that only make sense when the record is being stored now (signer active).
pub(crate) fn verify_record<'a>(
    ctx: &'a Ctx<'a>,
    rec: &'a MemberRecord,
    depth: usize,
    upload: bool,
) -> BoxFuture<'a, Result<(), ApiError>> {
    Box::pin(async move {
        if rec.format != 1 || rec.vault_id != *ctx.vault_id || rec.rev == 0 {
            return Err(integrity("member_record_mismatch"));
        }
        let prev = if rec.rev > 1 {
            resolve(ctx, rec.device_id.clone(), Some(rec.rev), depth).await?
        } else {
            None
        };
        let signer_pk: [u8; 32] = if rec.added_by == rec.device_id {
            if rec.rev == 1 {
                if rec.device_id != *ctx.genesis
                    || rec.role != MemberRole::Owner
                    || rec.status != MemberStatus::Active
                {
                    return Err(integrity("self_signed_non_genesis"));
                }
                rec.sign_pk
            } else {
                let prev = prev
                    .as_ref()
                    .ok_or_else(|| integrity("self_signed_without_previous"))?;
                if prev.status != MemberStatus::Active || !prev.role.is_trusted_approver() {
                    return Err(integrity("self_signed_by_inactive"));
                }
                check_transition(prev, rec, prev.role)?;
                if rec.role == MemberRole::Owner && prev.role != MemberRole::Owner {
                    return Err(integrity("self_promotion"));
                }
                prev.sign_pk
            }
        } else {
            let signer = resolve_signer(ctx, &rec.added_by, depth, upload)
                .await?
                .ok_or_else(|| integrity("unknown_signer"))?;
            if !signer.role.is_trusted_approver() {
                return Err(integrity("signer_not_trusted"));
            }
            if upload && signer.status != MemberStatus::Active {
                return Err(integrity("signer_not_active"));
            }
            if rec.role == MemberRole::Owner && signer.role != MemberRole::Owner {
                return Err(integrity("owner_requires_owner_signer"));
            }
            match &prev {
                Some(prev) => check_transition(prev, rec, signer.role)?,
                None if rec.status != MemberStatus::Active => {
                    return Err(integrity("new_member_not_active"));
                }
                None => {}
            }
            signer.sign_pk
        };
        rec.verify_signature(&signer_pk)
            .map_err(|_| integrity("member_signature_invalid"))
    })
}

/// True for the fail-closed cycle error of [`verify_rev`].
fn is_cycle(e: &ApiError) -> bool {
    e.details.get("reason").and_then(|v| v.as_str()) == Some("member_chain_cycle")
}

/// The signer's latest verified record.
///
/// For a **stored** record (not an upload), a signer whose latest revision loops back
/// through the record being verified — an owner re-signed the record of a device in its
/// own voucher chain, which every key-epoch rotation after a revocation does for all
/// remaining members — is resolved at its newest earlier revision that verifies on its
/// own. That is sound because keys never change between revisions and historic
/// signatures stay valid (records are immutable and their signer was checked on upload);
/// whether the device is still a member is decided separately by its own latest revision
/// and the manifest view. If no earlier revision exists the cycle error propagates, so the
/// fallback happens at the outermost point of the loop. Uploads never fall back: the
/// signer of a record stored now must verify at its latest revision.
fn resolve_signer<'a>(
    ctx: &'a Ctx<'a>,
    signer: &'a DeviceId,
    depth: usize,
    upload: bool,
) -> BoxFuture<'a, Result<Option<MemberRecord>, ApiError>> {
    Box::pin(async move {
        let err = match resolve(ctx, signer.clone(), None, depth).await {
            Err(e) if !upload && is_cycle(&e) => e,
            other => return other,
        };
        let revs = ctx.revs_of(signer).await?;
        for below in revs.iter().rev().copied() {
            match resolve(ctx, signer.clone(), Some(below), depth).await {
                Ok(Some(rec)) => return Ok(Some(rec)),
                Ok(None) => break,
                Err(e) if is_cycle(&e) => continue,
                Err(e) => return Err(e),
            }
        }
        Err(err)
    })
}

/// Rules for a new revision `rec` on top of `prev`, signed by a device with `signer_role`.
fn check_transition(
    prev: &MemberRecord,
    rec: &MemberRecord,
    signer_role: MemberRole,
) -> Result<(), ApiError> {
    if prev.sign_pk != rec.sign_pk || prev.kem_pk != rec.kem_pk {
        return Err(integrity("member_key_change"));
    }
    if prev.status == MemberStatus::Revoked && rec.status == MemberStatus::Active {
        return Err(integrity("member_reinstated"));
    }
    let changes_standing = prev.role != rec.role || prev.status != rec.status;
    if (changes_standing || prev.role == MemberRole::Owner) && signer_role != MemberRole::Owner {
        return Err(integrity("owner_required"));
    }
    Ok(())
}

/// The device that vouched for `rec`'s device: the signer of its latest revision that is
/// not self-signed (`None` for the self-signed genesis chain).
pub(crate) async fn voucher(
    ctx: &Ctx<'_>,
    rec: &MemberRecord,
    depth: usize,
) -> Result<Option<DeviceId>, ApiError> {
    let mut cur = rec.clone();
    for _ in 0..=MAX_DEPTH {
        if cur.added_by != cur.device_id {
            return Ok(Some(cur.added_by));
        }
        if cur.rev <= 1 {
            return Ok(None);
        }
        match resolve(ctx, cur.device_id.clone(), Some(cur.rev), depth).await? {
            Some(prev) => cur = prev,
            None => return Ok(None),
        }
    }
    Err(integrity("member_chain_too_deep"))
}
