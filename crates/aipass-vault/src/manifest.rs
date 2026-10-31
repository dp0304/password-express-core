// SPDX-License-Identifier: Apache-2.0
//! Signed manifests, the verified vault view and the manifest chain rules
//! (CONTRACTS §2.3, §3.2; design doc §10.3–§10.4).
//!
//! A [`VaultView`] is the state of the vault as of one **verified** manifest: the header,
//! the manifest itself (with its file hash = the checkpoint hash) and the member record at
//! the revision listed for every member. Views only ever advance through
//! [`verify_transition`], which enforces:
//!
//! * `seq` is exactly previous + 1 and `prev_hash` is the previous file hash (`""` for 1);
//! * the author is an **active owner/member of the previous manifest** (seq 1: genesis) and
//!   the Ed25519 signature over `JCS(manifest − signature)` verifies;
//! * members are never dropped; every changed member record matches its listed hash, is
//!   signed by an active owner/member of the previous manifest, keeps its keys and platform,
//!   and a revoked device can never become active again; role/status changes and adding
//!   owners need an owner; revoking an owner/member requires a `key_epoch` bump, and a bump
//!   (owners only) must re-seal the new VMK to every remaining owner/member; executors and
//!   revoked devices carry no VMK; at least one active owner remains;
//! * entries never disappear without a tombstone, versions never go backwards, a tombstone
//!   is permanent unless the entry is restored with a version greater than the tombstone.
//!
//! Entry version objects are checked against the view with [`verify_entry_object`]
//! (hash, location, key epoch, author).

use std::collections::{BTreeMap, BTreeSet};

use aipass_crypto::DeviceIdentity;
use aipass_types::ids::{DeviceId, EntryId, VaultId};
use aipass_types::time::Timestamp;
use aipass_types::vault::{
    Checkpoint, EntryVersion, FORMAT_V1, Manifest, ManifestEntry, ManifestMember, MemberRecord,
    MemberRole, MemberStatus, SignedObject, Tombstone, VaultHeader, keys, object_hash,
};

use crate::encoding::object_bytes;
use crate::entry::{SealedEntry, parse_entry_object};
use crate::error::{Result, VaultError, parse_json};
use crate::member::SignedMember;

/// The verified state of a vault as of one manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultView {
    /// Verified `vault.json`.
    pub header: VaultHeader,
    /// Verified manifest (`seq == 0` is the pseudo-manifest "genesis only, nothing committed").
    pub manifest: Manifest,
    /// File hash of the manifest (`""` for the pseudo-manifest).
    pub manifest_hash: String,
    /// Member record at the listed revision for every member.
    pub members: BTreeMap<DeviceId, MemberRecord>,
}

impl VaultView {
    /// Vault id.
    pub fn vault_id(&self) -> &VaultId {
        &self.header.vault_id
    }

    /// Manifest sequence (0 = nothing committed yet).
    pub fn seq(&self) -> u64 {
        self.manifest.seq
    }

    /// Checkpoint of this view (`None` for the pseudo-manifest).
    pub fn checkpoint(&self) -> Option<Checkpoint> {
        (self.manifest.seq > 0).then(|| Checkpoint {
            vault_id: self.header.vault_id.clone(),
            seq: self.manifest.seq,
            hash: self.manifest_hash.clone(),
        })
    }

    /// Member record of `device`.
    pub fn member(&self, device: &DeviceId) -> Option<&MemberRecord> {
        self.members.get(device)
    }

    /// Whether `device` is an active member with role owner or member.
    pub fn is_active_approver(&self, device: &DeviceId) -> bool {
        self.manifest
            .members
            .get(device)
            .is_some_and(|m| m.status == MemberStatus::Active && m.role.is_trusted_approver())
    }

    /// Whether `device` is an active owner.
    pub fn is_active_owner(&self, device: &DeviceId) -> bool {
        self.manifest
            .members
            .get(device)
            .is_some_and(|m| m.status == MemberStatus::Active && m.role == MemberRole::Owner)
    }

    /// Whether `device` is listed as revoked.
    pub fn is_revoked(&self, device: &DeviceId) -> bool {
        self.manifest
            .members
            .get(device)
            .is_some_and(|m| m.status == MemberStatus::Revoked)
    }

    /// Pseudo-view before the first manifest: only the (verified) genesis member exists.
    pub fn genesis(header: VaultHeader, genesis: MemberRecord) -> Result<Self> {
        let signed = SignedMember::from_record(genesis.clone())?;
        let manifest = Manifest {
            format: FORMAT_V1,
            vault_id: header.vault_id.clone(),
            seq: 0,
            prev_hash: String::new(),
            key_epoch: genesis.key_epoch,
            entries: BTreeMap::new(),
            tombstones: BTreeMap::new(),
            members: BTreeMap::from([(
                genesis.device_id.clone(),
                ManifestMember {
                    rev: genesis.rev,
                    hash: signed.hash,
                    status: genesis.status,
                    role: genesis.role,
                },
            )]),
            author_device_id: genesis.device_id.clone(),
            created_at: header.created_at,
            signature: String::new(),
        };
        Ok(Self {
            header,
            manifest,
            manifest_hash: String::new(),
            members: BTreeMap::from([(genesis.device_id.clone(), genesis)]),
        })
    }

    /// Entries with unresolved conflicts.
    pub fn conflicted_entries(&self) -> Vec<EntryId> {
        self.manifest
            .entries
            .iter()
            .filter(|(_, e)| !e.conflict_versions.is_empty())
            .map(|(id, _)| id.clone())
            .collect()
    }
}

/// Verify `vault.json` and the genesis member record (`members/<genesis>/1.json`).
pub fn verify_header(
    header_bytes: &[u8],
    genesis_member_bytes: &[u8],
    expected_vault: Option<&VaultId>,
) -> Result<VaultView> {
    let header: VaultHeader = parse_json(header_bytes, "vault.json is not valid")?;
    if header.format != FORMAT_V1 {
        return Err(VaultError::Unsupported("vault format"));
    }
    if expected_vault.is_some_and(|v| v != &header.vault_id) {
        return Err(VaultError::Integrity("vault.json belongs to another vault"));
    }
    let genesis: MemberRecord =
        parse_json(genesis_member_bytes, "genesis member record is not valid")?;
    if genesis.format != FORMAT_V1
        || genesis.vault_id != header.vault_id
        || genesis.device_id != header.genesis_device_id
        || genesis.rev != 1
        || genesis.added_by != genesis.device_id
        || genesis.role != MemberRole::Owner
        || genesis.status != MemberStatus::Active
    {
        return Err(VaultError::Integrity(
            "genesis member record is inconsistent",
        ));
    }
    genesis
        .verify_signature(&genesis.sign_pk)
        .map_err(|_| VaultError::Integrity("genesis member record signature invalid"))?;
    header
        .verify_signature(&genesis.sign_pk)
        .map_err(|_| VaultError::Integrity("vault.json signature invalid"))?;
    VaultView::genesis(header, genesis)
}

/// A parsed manifest with its exact bytes and hash.
#[derive(Debug, Clone)]
pub struct ManifestCandidate {
    /// Parsed manifest.
    pub manifest: Manifest,
    /// Exact file bytes.
    pub bytes: Vec<u8>,
    /// `b64u(SHA-256(bytes))`.
    pub hash: String,
}

impl ManifestCandidate {
    /// Parse manifest bytes fetched from `manifests/<expected_seq>.json`.
    pub fn parse(bytes: Vec<u8>, expected_seq: u64) -> Result<Self> {
        let manifest: Manifest = parse_json(&bytes, "manifest is not valid")?;
        if manifest.seq != expected_seq {
            return Err(VaultError::Integrity(
                "manifest sequence does not match its key",
            ));
        }
        let hash = object_hash(&bytes);
        Ok(Self {
            manifest,
            bytes,
            hash,
        })
    }

    /// Storage key.
    pub fn key(&self) -> String {
        keys::manifest(self.manifest.seq)
    }
}

/// Member record revisions that must be fetched to verify `next` after `prev`.
pub fn required_member_records(prev: &VaultView, next: &Manifest) -> Vec<(DeviceId, u64)> {
    next.members
        .iter()
        .filter(|(id, m)| {
            prev.manifest
                .members
                .get(*id)
                .is_none_or(|old| old.rev != m.rev)
        })
        .map(|(id, m)| (id.clone(), m.rev))
        .collect()
}

/// Entries whose current version is new or changed between two views.
pub fn changed_entries(prev: &VaultView, next: &VaultView) -> Vec<(EntryId, ManifestEntry)> {
    next.manifest
        .entries
        .iter()
        .filter(|(id, e)| {
            prev.manifest
                .entries
                .get(*id)
                .is_none_or(|old| old.version != e.version || old.hash != e.hash)
        })
        .map(|(id, e)| (id.clone(), e.clone()))
        .collect()
}

fn integrity(reason: &'static str) -> VaultError {
    VaultError::Integrity(reason)
}

/// Verify the transition `prev → candidate` (see the module docs for every rule).
/// `member_records` must contain the bytes of every record listed by
/// [`required_member_records`].
pub fn verify_transition(
    prev: &VaultView,
    cand: &ManifestCandidate,
    member_records: &BTreeMap<(DeviceId, u64), Vec<u8>>,
) -> Result<VaultView> {
    let n = &cand.manifest;
    let p = &prev.manifest;
    if n.format != FORMAT_V1 {
        return Err(VaultError::Unsupported("manifest format"));
    }
    if n.vault_id != prev.header.vault_id {
        return Err(integrity("manifest belongs to another vault"));
    }
    if n.seq != p.seq + 1 {
        return Err(integrity("manifest sequence gap"));
    }
    if n.prev_hash != prev.manifest_hash {
        return Err(integrity(
            "manifest prev_hash does not match the previous manifest",
        ));
    }

    // ---- author ---------------------------------------------------------------------
    if !prev.is_active_approver(&n.author_device_id) {
        return Err(integrity(
            "manifest author is not an active owner or member of the previous manifest",
        ));
    }
    let author = prev
        .members
        .get(&n.author_device_id)
        .ok_or(integrity("manifest author record missing"))?;
    n.verify_signature(&author.sign_pk)
        .map_err(|_| integrity("manifest signature invalid"))?;

    // ---- key epoch --------------------------------------------------------------------
    if n.key_epoch < p.key_epoch {
        return Err(integrity("manifest key epoch went backwards"));
    }
    let epoch_bumped = n.key_epoch > p.key_epoch;
    if epoch_bumped && author.role != MemberRole::Owner {
        return Err(integrity("only owners may rotate the vault key"));
    }

    // ---- members ----------------------------------------------------------------------
    for id in p.members.keys() {
        if !n.members.contains_key(id) {
            return Err(integrity("member dropped from manifest"));
        }
    }
    let mut members = prev.members.clone();
    for (id, nm) in &n.members {
        let old_meta = p.members.get(id);
        if let Some(om) = old_meta {
            if om.rev == nm.rev {
                if om.hash != nm.hash || om.status != nm.status || om.role != nm.role {
                    return Err(integrity("member entry changed without a new revision"));
                }
                continue;
            }
            if nm.rev < om.rev {
                return Err(integrity("member revision went backwards"));
            }
        }
        let bytes = member_records
            .get(&(id.clone(), nm.rev))
            .ok_or(integrity("member record missing from storage"))?;
        if object_hash(bytes) != nm.hash {
            return Err(integrity("member record hash mismatch"));
        }
        let record: MemberRecord = parse_json(bytes, "member record is not valid")?;
        if record.format != FORMAT_V1
            || record.vault_id != n.vault_id
            || &record.device_id != id
            || record.rev != nm.rev
            || record.status != nm.status
            || record.role != nm.role
        {
            return Err(integrity("member record does not match the manifest"));
        }
        if !prev.is_active_approver(&record.added_by) {
            return Err(integrity(
                "member record signer is not an active owner or member",
            ));
        }
        let signer = prev
            .members
            .get(&record.added_by)
            .ok_or(integrity("member record signer missing"))?;
        record
            .verify_signature(&signer.sign_pk)
            .map_err(|_| integrity("member record signature invalid"))?;
        let signer_is_owner = signer.role == MemberRole::Owner;

        if let Some(old) = prev.members.get(id) {
            if old.sign_pk != record.sign_pk
                || old.kem_pk != record.kem_pk
                || old.platform != record.platform
            {
                return Err(integrity("member keys cannot change"));
            }
            if old.status == MemberStatus::Revoked && record.status == MemberStatus::Active {
                return Err(integrity("a revoked device cannot be reinstated"));
            }
            if (old.role != record.role || old.status != record.status) && !signer_is_owner {
                return Err(integrity("only owners may change roles or revoke devices"));
            }
            if old.status == MemberStatus::Active
                && record.status == MemberStatus::Revoked
                && old.role.is_trusted_approver()
                && !epoch_bumped
            {
                return Err(integrity("revoking a trusted device requires key rotation"));
            }
        } else {
            if record.status != MemberStatus::Active {
                return Err(integrity("new members must be active"));
            }
            if record.role == MemberRole::Owner && !signer_is_owner {
                return Err(integrity("only owners may add owners"));
            }
        }
        match (record.role, record.status) {
            (MemberRole::Executor, _) | (_, MemberStatus::Revoked) => {
                if record.wrapped_vmk.is_some() {
                    return Err(integrity(
                        "executors and revoked devices carry no vault key",
                    ));
                }
            }
            _ => {
                if record.wrapped_vmk.is_none() || record.key_epoch > n.key_epoch {
                    return Err(integrity(
                        "member vault key wrap missing or from the future",
                    ));
                }
            }
        }
        members.insert(id.clone(), record);
    }
    if epoch_bumped {
        for (id, m) in &n.members {
            if m.status == MemberStatus::Active
                && m.role.is_trusted_approver()
                && members.get(id).is_none_or(|r| r.key_epoch != n.key_epoch)
            {
                return Err(integrity(
                    "key rotation did not re-seal the vault key to every member",
                ));
            }
        }
    }
    if !n
        .members
        .values()
        .any(|m| m.status == MemberStatus::Active && m.role == MemberRole::Owner)
    {
        return Err(integrity("no active owner left"));
    }

    // ---- entries & tombstones -------------------------------------------------------------
    for (eid, pe) in &p.entries {
        if let Some(ne) = n.entries.get(eid) {
            if ne.version < pe.version || (ne.version == pe.version && ne.hash != pe.hash) {
                return Err(integrity(
                    "entry version went backwards or changed in place",
                ));
            }
        } else if let Some(t) = n.tombstones.get(eid) {
            let max_seen = pe
                .conflict_versions
                .iter()
                .copied()
                .chain([pe.version])
                .max()
                .unwrap_or(pe.version);
            if t.version < max_seen {
                return Err(integrity("tombstone is older than the deleted entry"));
            }
        } else {
            return Err(integrity("entry dropped without a tombstone"));
        }
    }
    for (eid, pt) in &p.tombstones {
        match (n.tombstones.get(eid), n.entries.get(eid)) {
            (Some(nt), None) => {
                if nt != pt {
                    return Err(integrity("tombstone changed"));
                }
            }
            (None, Some(ne)) => {
                if ne.version <= pt.version {
                    return Err(integrity(
                        "deleted entry resurrected without an explicit newer version",
                    ));
                }
            }
            (Some(_), Some(_)) => return Err(integrity("entry is both live and deleted")),
            (None, None) => return Err(integrity("tombstone dropped")),
        }
    }
    for (eid, ne) in &n.entries {
        if n.tombstones.contains_key(eid) {
            return Err(integrity("entry is both live and deleted"));
        }
        if ne.version == 0 {
            return Err(integrity("entry version 0"));
        }
        let set: BTreeSet<u64> = ne.conflict_versions.iter().copied().collect();
        if set.len() != ne.conflict_versions.len() || set.contains(&ne.version) || set.contains(&0)
        {
            return Err(integrity("invalid conflict versions"));
        }
    }

    Ok(VaultView {
        header: prev.header.clone(),
        manifest: n.clone(),
        manifest_hash: cand.hash.clone(),
        members,
    })
}

/// Verify the object of the **current** version of `entry_id` in `view`. `introduced`
/// marks a version that first appeared in this view's manifest: it must use the
/// manifest's key epoch (after a rotation, revoked devices cannot read new versions).
pub fn verify_entry_object(
    view: &VaultView,
    entry_id: &EntryId,
    bytes: &[u8],
    introduced: bool,
) -> Result<EntryVersion> {
    let me = view
        .manifest
        .entries
        .get(entry_id)
        .ok_or(VaultError::NotFound("entry"))?;
    if object_hash(bytes) != me.hash {
        return Err(integrity("entry version hash does not match the manifest"));
    }
    let ev = parse_entry_object(bytes, view.vault_id(), entry_id, me.version)?;
    check_entry_meta(view, &ev)?;
    if introduced && ev.key_epoch != view.manifest.key_epoch {
        return Err(integrity("new entry version uses an outdated vault key"));
    }
    Ok(ev)
}

/// Verify a conflict / historical version object (not hash-listed in the manifest; its
/// integrity comes from the AEAD bound to vault, entry and version).
pub fn verify_other_version(
    view: &VaultView,
    entry_id: &EntryId,
    version: u64,
    bytes: &[u8],
) -> Result<EntryVersion> {
    let ev = parse_entry_object(bytes, view.vault_id(), entry_id, version)?;
    check_entry_meta(view, &ev)?;
    Ok(ev)
}

/// Conflict versions that first appear in `next` (not listed for the entry in `prev`).
/// Planners only ever add *freshly sealed* versions to a conflict list, so such a version
/// was encrypted by the committing device under `next`'s key epoch.
pub fn introduced_conflicts(prev: &VaultView, next: &VaultView) -> Vec<(EntryId, u64)> {
    next.manifest
        .entries
        .iter()
        .flat_map(|(id, e)| {
            let old = prev.manifest.entries.get(id);
            e.conflict_versions
                .iter()
                .copied()
                .filter(move |v| {
                    old.is_none_or(|o| o.version != *v && !o.conflict_versions.contains(v))
                })
                .map(move |v| (id.clone(), v))
        })
        .collect()
}

/// Verify a conflict version introduced by `view`'s manifest: like a new current version
/// it must use the manifest's key epoch, so a device revoked by an earlier rotation cannot
/// forge it with the old keys it kept. Clients verify and cache it as soon as the manifest
/// is applied, so later storage tampering cannot swap it either (conflict versions are
/// not hash-listed in the manifest).
pub fn verify_introduced_version(
    view: &VaultView,
    entry_id: &EntryId,
    version: u64,
    bytes: &[u8],
) -> Result<EntryVersion> {
    let ev = verify_other_version(view, entry_id, version, bytes)?;
    if ev.key_epoch != view.manifest.key_epoch {
        return Err(integrity("new conflict version uses an outdated vault key"));
    }
    Ok(ev)
}

fn check_entry_meta(view: &VaultView, ev: &EntryVersion) -> Result<()> {
    if ev.key_epoch == 0 || ev.key_epoch > view.manifest.key_epoch {
        return Err(integrity("entry version key epoch out of range"));
    }
    match view.members.get(&ev.author_device_id) {
        Some(m) if m.role.is_trusted_approver() => Ok(()),
        _ => Err(integrity("entry version author is not an owner or member")),
    }
}

/// Objects staged by a draft: `(storage key, exact bytes)`, written create-only before the
/// manifest.
pub type StagedObjects = Vec<(String, Vec<u8>)>;

/// Builder for the next manifest on top of a verified view.
#[derive(Debug, Clone)]
pub struct ManifestDraft {
    base: Manifest,
    base_hash: String,
    /// Entries of the next manifest.
    pub entries: BTreeMap<EntryId, ManifestEntry>,
    /// Tombstones of the next manifest.
    pub tombstones: BTreeMap<EntryId, Tombstone>,
    /// Members of the next manifest.
    pub members: BTreeMap<DeviceId, ManifestMember>,
    /// Key epoch of the next manifest.
    pub key_epoch: u32,
    objects: Vec<(String, Vec<u8>)>,
    allocated: BTreeMap<EntryId, u64>,
    taken: BTreeSet<String>,
}

impl ManifestDraft {
    /// Start from `view` (the next manifest is `view.seq + 1`).
    pub fn from_view(view: &VaultView) -> Self {
        Self {
            base: view.manifest.clone(),
            base_hash: view.manifest_hash.clone(),
            entries: view.manifest.entries.clone(),
            tombstones: view.manifest.tombstones.clone(),
            members: view.manifest.members.clone(),
            key_epoch: view.manifest.key_epoch,
            objects: Vec::new(),
            allocated: BTreeMap::new(),
            taken: BTreeSet::new(),
        }
    }

    /// Mark storage keys known to exist already (orphans of failed commits) so that
    /// [`ManifestDraft::next_version`] skips them.
    pub fn with_taken(mut self, taken: &BTreeSet<String>) -> Self {
        self.taken.extend(taken.iter().cloned());
        self
    }

    /// Sequence the draft will have.
    pub fn seq(&self) -> u64 {
        self.base.seq + 1
    }

    /// Allocate the next unused version number for `entry`: greater than the current
    /// version, every conflict version, the tombstone version and anything allocated in
    /// this draft, skipping keys known to be taken.
    pub fn next_version(&mut self, entry: &EntryId) -> u64 {
        let mut v = [
            self.entries.get(entry).map(|e| {
                e.conflict_versions
                    .iter()
                    .copied()
                    .chain([e.version])
                    .max()
                    .unwrap_or(e.version)
            }),
            self.base.entries.get(entry).map(|e| {
                e.conflict_versions
                    .iter()
                    .copied()
                    .chain([e.version])
                    .max()
                    .unwrap_or(e.version)
            }),
            self.tombstones.get(entry).map(|t| t.version),
            self.base.tombstones.get(entry).map(|t| t.version),
            self.allocated.get(entry).copied(),
        ]
        .into_iter()
        .flatten()
        .max()
        .unwrap_or(0)
            + 1;
        while self.taken.contains(&keys::entry(entry, v)) {
            v += 1;
        }
        self.allocated.insert(entry.clone(), v);
        v
    }

    /// Next member record revision for `device` after `current_rev`, skipping revisions
    /// whose objects are known to exist (orphans of failed commits).
    pub fn next_member_rev(&self, device: &DeviceId, current_rev: u64) -> u64 {
        let mut rev = current_rev + 1;
        while self.taken.contains(&keys::member(device, rev)) {
            rev += 1;
        }
        rev
    }

    /// Next key epoch for a rotation (greater than the current one, skipping epochs whose
    /// keyring object is known to exist).
    pub fn next_epoch(&self) -> u32 {
        let mut e = self.key_epoch.max(self.base.key_epoch) + 1;
        while self.taken.contains(&keys::keyring(e)) {
            e += 1;
        }
        e
    }

    /// Stage an object to be written (create-only) before the manifest.
    pub fn add_object(&mut self, key: String, bytes: Vec<u8>) {
        self.objects.push((key, bytes));
    }

    /// Stage `sealed` as the current version of its entry with the given conflict versions
    /// (restores a tombstoned entry when the version is newer than the tombstone).
    pub fn set_current(&mut self, sealed: &SealedEntry, conflict_versions: Vec<u64>) {
        let id = sealed.version.entry_id.clone();
        self.tombstones.remove(&id);
        self.entries.insert(
            id,
            ManifestEntry {
                version: sealed.version.version,
                hash: sealed.hash.clone(),
                conflict_versions,
            },
        );
        self.objects.push((sealed.key(), sealed.bytes.clone()));
    }

    /// Stage an additional (conflict) version object without making it current.
    pub fn add_version_object(&mut self, sealed: &SealedEntry) {
        self.objects.push((sealed.key(), sealed.bytes.clone()));
    }

    /// Replace only the conflict list of an entry.
    pub fn set_conflicts(&mut self, entry: &EntryId, conflict_versions: Vec<u64>) -> Result<()> {
        let e = self
            .entries
            .get_mut(entry)
            .ok_or(VaultError::NotFound("entry"))?;
        e.conflict_versions = conflict_versions;
        Ok(())
    }

    /// Delete an entry (tombstone at its highest version).
    pub fn tombstone(&mut self, entry: &EntryId, deleted_at: &Timestamp) -> Result<()> {
        let e = self
            .entries
            .remove(entry)
            .ok_or(VaultError::NotFound("entry"))?;
        let version = e
            .conflict_versions
            .iter()
            .copied()
            .chain([e.version])
            .max()
            .unwrap_or(e.version);
        self.tombstones.insert(
            entry.clone(),
            Tombstone {
                version,
                deleted_at: aipass_types::time::truncate(*deleted_at),
            },
        );
        Ok(())
    }

    /// Stage a member record revision.
    pub fn put_member(&mut self, m: &SignedMember) {
        self.members.insert(
            m.record.device_id.clone(),
            ManifestMember {
                rev: m.record.rev,
                hash: m.hash.clone(),
                status: m.record.status,
                role: m.record.role,
            },
        );
        self.objects.push((m.key(), m.bytes.clone()));
    }

    /// Whether the draft changes nothing.
    pub fn is_unchanged(&self) -> bool {
        self.objects.is_empty()
            && self.entries == self.base.entries
            && self.tombstones == self.base.tombstones
            && self.members == self.base.members
            && self.key_epoch == self.base.key_epoch
    }

    /// Objects staged so far.
    pub fn objects(&self) -> &[(String, Vec<u8>)] {
        &self.objects
    }

    /// Sign the next manifest. Returns the candidate and the objects to write first.
    pub fn finish(
        self,
        signer: &DeviceIdentity,
        author: &DeviceId,
        now: &Timestamp,
    ) -> Result<(ManifestCandidate, StagedObjects)> {
        let mut m = Manifest {
            format: FORMAT_V1,
            vault_id: self.base.vault_id.clone(),
            seq: self.base.seq + 1,
            prev_hash: self.base_hash.clone(),
            key_epoch: self.key_epoch,
            entries: self.entries,
            tombstones: self.tombstones,
            members: self.members,
            author_device_id: author.clone(),
            created_at: aipass_types::time::truncate(*now),
            signature: String::new(),
        };
        m.sign_with(signer)?;
        let bytes = object_bytes(&m)?;
        let hash = object_hash(&bytes);
        Ok((
            ManifestCandidate {
                manifest: m,
                bytes,
                hash,
            },
            self.objects,
        ))
    }
}

/// Collect member record bytes for a candidate from staged objects (used to self-verify a
/// manifest before committing it).
pub fn staged_member_records(
    prev: &VaultView,
    cand: &ManifestCandidate,
    staged: &[(String, Vec<u8>)],
) -> BTreeMap<(DeviceId, u64), Vec<u8>> {
    let wanted: BTreeSet<(DeviceId, u64)> = required_member_records(prev, &cand.manifest)
        .into_iter()
        .collect();
    staged
        .iter()
        .filter_map(|(k, b)| {
            let id = keys::parse_member(k)?;
            wanted.contains(&id).then(|| (id, b.clone()))
        })
        .collect()
}
