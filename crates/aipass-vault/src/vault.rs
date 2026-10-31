// SPDX-License-Identifier: Apache-2.0
//! Vault creation (genesis), the unlocked vault and member operations.
//!
//! [`UnlockedVault`] holds the device identity and the VMKs in memory. It is the only type
//! that can encrypt or decrypt entries; it never hands the VMK to callers, so user
//! interfaces work with payloads and summaries only.

use core::fmt;
use std::collections::BTreeMap;

use aipass_crypto::{Argon2Params, DeviceIdentity, Key32, SecretString};
use aipass_types::ids::{DeviceId, EntryId, VaultId};
use aipass_types::time::Timestamp;
use aipass_types::vault::{
    DevicePublic, EntryPayload, EntryVersion, FORMAT_V1, KdfSpec, KeyringRecord, MemberRole,
    MemberStatus, Platform, RecoveryKind, RecoveryWrap, SignedObject, VaultHeader, keys,
};

use crate::encoding::object_bytes;
use crate::entry::{SealedEntry, decrypt_entry, encrypt_entry};
use crate::error::{Result, VaultError, parse_json};
use crate::keys::{
    VaultKeys, build_keyring, master_password_kdf, master_password_kek, open_keyring,
    open_recovery, open_vmk, seal_vmk, wrap_recovery,
};
use crate::manifest::{
    ManifestCandidate, ManifestDraft, VaultView, staged_member_records, verify_transition,
};
use crate::member::{
    MemberParams, RECOVERY_MEMBER_NAME, SignedMember, build_member, device_public,
    is_recovery_member, recovery_device_id, validate_device_name,
};
use crate::recovery::RecoveryKey;

/// An unlocked vault on one device: device identity + VMKs (by epoch). Cloning copies the
/// in-memory secrets (all zeroized on drop).
#[derive(Clone)]
pub struct UnlockedVault {
    vault_id: VaultId,
    device_id: DeviceId,
    identity: DeviceIdentity,
    keys: VaultKeys,
}

impl fmt::Debug for UnlockedVault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UnlockedVault")
            .field("vault_id", &self.vault_id)
            .field("device_id", &self.device_id)
            .field("keys", &self.keys)
            .finish_non_exhaustive()
    }
}

impl UnlockedVault {
    /// Vault.
    pub fn vault_id(&self) -> &VaultId {
        &self.vault_id
    }

    /// This device.
    pub fn device_id(&self) -> &DeviceId {
        &self.device_id
    }

    /// This device's signing / KEM identity (for manifests, member records, approvals).
    pub fn identity(&self) -> &DeviceIdentity {
        &self.identity
    }

    /// Current key epoch held.
    pub fn key_epoch(&self) -> u32 {
        self.keys.current_epoch()
    }

    /// Key epochs held.
    pub fn epochs(&self) -> Vec<u32> {
        self.keys.epochs()
    }

    /// Open the vault on this device from a verified view: the device's own member record
    /// must be active with a VMK wrap; older epochs come from `keyring/<epoch>.json`
    /// (`keyring_bytes`, required when the wrap epoch is > 1).
    pub fn open(
        view: &VaultView,
        device_id: DeviceId,
        identity: DeviceIdentity,
        keyring_bytes: Option<&[u8]>,
    ) -> Result<Self> {
        let rec = view.member(&device_id).ok_or(VaultError::Forbidden(
            "this device is not a member of the vault",
        ))?;
        if rec.status == MemberStatus::Revoked {
            return Err(VaultError::Revoked);
        }
        if !rec.role.is_trusted_approver() {
            return Err(VaultError::Forbidden("executors never hold the vault key"));
        }
        if rec.sign_pk != identity.public().sign_pk || rec.kem_pk != identity.public().kem_pk {
            return Err(VaultError::Integrity(
                "member record keys do not match this device",
            ));
        }
        let sealed = rec
            .wrapped_vmk
            .as_ref()
            .ok_or(VaultError::Integrity("member record has no vault key wrap"))?;
        let vmk = open_vmk(
            identity.kem_keypair(),
            view.vault_id(),
            &device_id,
            rec.key_epoch,
            sealed,
        )?;
        Self::from_vmk(view, device_id, identity, rec.key_epoch, vmk, keyring_bytes)
    }

    fn from_vmk(
        view: &VaultView,
        device_id: DeviceId,
        identity: DeviceIdentity,
        epoch: u32,
        vmk: Key32,
        keyring_bytes: Option<&[u8]>,
    ) -> Result<Self> {
        let mut keys = VaultKeys::new(view.vault_id().clone(), epoch, vmk);
        if epoch > 1 {
            let bytes = keyring_bytes.ok_or(VaultError::NotFound("keyring record"))?;
            let rec: KeyringRecord = parse_json(bytes, "keyring record is not valid")?;
            let prev = open_keyring(&rec, keys.current_vmk(), view.vault_id(), epoch)?;
            for (e, k) in prev {
                keys.insert(e, k);
            }
        }
        Ok(Self {
            vault_id: view.vault_id().clone(),
            device_id,
            identity,
            keys,
        })
    }

    /// Encrypt `payload` as `version` of `entry_id` (current epoch, fresh DEK).
    pub fn encrypt_entry(
        &self,
        entry_id: &EntryId,
        version: u64,
        payload: &EntryPayload,
        now: &Timestamp,
    ) -> Result<SealedEntry> {
        encrypt_entry(&self.keys, entry_id, version, payload, &self.device_id, now)
    }

    /// Decrypt an entry version found at `entries/<entry_id>/<version>.json`.
    pub fn decrypt_entry(
        &self,
        entry_id: &EntryId,
        version: u64,
        ev: &EntryVersion,
    ) -> Result<EntryPayload> {
        decrypt_entry(&self.keys, entry_id, version, ev)
    }

    /// Seal the current VMK to a device (HPKE, contract AAD).
    pub fn seal_current_vmk(
        &self,
        device_id: &DeviceId,
        kem_pk: &[u8; 32],
    ) -> Result<aipass_crypto::SealedBox> {
        seal_vmk(
            self.keys.current_vmk(),
            &self.vault_id,
            device_id,
            self.keys.current_epoch(),
            kem_pk,
        )
    }

    /// Install a key epoch committed by a rotation (see [`stage_revocation`]).
    pub fn install_epoch(&mut self, pending: PendingEpoch) {
        self.keys.insert(pending.epoch, pending.vmk);
    }

    /// Learn newer epochs after a pull: open this device's newest member record wrap and
    /// the keyring of that epoch.
    pub fn refresh_from_view(
        &mut self,
        view: &VaultView,
        keyring_bytes: Option<&[u8]>,
    ) -> Result<()> {
        let rec = view.member(&self.device_id).ok_or(VaultError::Forbidden(
            "this device is not a member of the vault",
        ))?;
        if rec.status == MemberStatus::Revoked {
            return Err(VaultError::Revoked);
        }
        if self.keys.has_epoch(rec.key_epoch) && rec.key_epoch <= self.keys.current_epoch() {
            return Ok(());
        }
        let sealed = rec
            .wrapped_vmk
            .as_ref()
            .ok_or(VaultError::Integrity("member record has no vault key wrap"))?;
        let vmk = open_vmk(
            self.identity.kem_keypair(),
            &self.vault_id,
            &self.device_id,
            rec.key_epoch,
            sealed,
        )?;
        let epoch = rec.key_epoch;
        if epoch > 1
            && let Some(bytes) = keyring_bytes
        {
            let kr: KeyringRecord = parse_json(bytes, "keyring record is not valid")?;
            for (e, k) in open_keyring(&kr, &vmk, &self.vault_id, epoch)? {
                self.keys.insert(e, k);
            }
        }
        self.keys.insert(epoch, vmk);
        Ok(())
    }

    /// Write (create) a master-password wrap of the **current** VMK.
    pub fn master_password_wrap(
        &self,
        password: &SecretString,
        params: Argon2Params,
    ) -> Result<(String, Vec<u8>)> {
        if password.expose().chars().count() < 8 {
            return Err(VaultError::Invalid(aipass_types::Localized::new(
                "主密码至少需要 8 个字符",
                "The master password must be at least 8 characters.",
            )));
        }
        let spec = master_password_kdf(params)?;
        let kek = master_password_kek(password.expose().as_bytes(), &spec)?;
        let w = wrap_recovery(
            self.keys.current_vmk(),
            &self.vault_id,
            self.keys.current_epoch(),
            RecoveryKind::MasterPassword,
            spec,
            &kek,
        )?;
        Ok((keys::recovery(w.key_epoch, w.kind), object_bytes(&w)?))
    }

    /// Recovery-key wrap of the **current** VMK (written when the user re-enters the key,
    /// e.g. during recovery verification after a rotation).
    pub fn recovery_key_wrap(&self, key: &RecoveryKey) -> Result<(String, Vec<u8>)> {
        let w = wrap_recovery(
            self.keys.current_vmk(),
            &self.vault_id,
            self.keys.current_epoch(),
            RecoveryKind::RecoveryKey,
            KdfSpec::HkdfSha256,
            &key.kek(&self.vault_id),
        )?;
        Ok((keys::recovery(w.key_epoch, w.kind), object_bytes(&w)?))
    }

    /// Keyring record for the current epoch (all older VMKs under the current VMK).
    pub fn keyring_record(&self, now: &Timestamp) -> Result<KeyringRecord> {
        build_keyring(
            &self.vault_id,
            self.keys.current_epoch(),
            self.keys.current_vmk(),
            self.keys.all(),
            &self.device_id,
            now,
        )
    }
}

/// A freshly generated VMK for a new epoch, staged by a rotation and installed only after
/// the manifest that introduces it has been committed.
pub struct PendingEpoch {
    /// Epoch.
    pub epoch: u32,
    vmk: Key32,
}

impl fmt::Debug for PendingEpoch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PendingEpoch")
            .field("epoch", &self.epoch)
            .finish_non_exhaustive()
    }
}

/// Parameters of a new vault.
#[derive(Debug, Clone)]
pub struct GenesisParams<'a> {
    /// Name of the creating device.
    pub device_name: &'a str,
    /// Platform of the creating device.
    pub platform: Platform,
    /// Optional master password (additional recovery wrap, Argon2id).
    pub master_password: Option<&'a SecretString>,
    /// Argon2id parameters for the master-password wrap.
    pub argon2: Argon2Params,
    /// Creation time.
    pub now: Timestamp,
}

/// Everything produced when a vault is created.
pub struct Genesis {
    /// The new vault id.
    pub vault_id: VaultId,
    /// The creating device id.
    pub device_id: DeviceId,
    /// The recovery key (show once in the kit; never uploaded).
    pub recovery_key: RecoveryKey,
    /// Signed header.
    pub header: VaultHeader,
    /// Genesis member record.
    pub genesis_member: SignedMember,
    /// Objects to write create-only, in order, before the first manifest.
    pub objects: Vec<(String, Vec<u8>)>,
    /// First manifest (seq 1).
    pub manifest: ManifestCandidate,
    /// Verified view after the first manifest.
    pub view: VaultView,
    /// The unlocked vault on the creating device.
    pub unlocked: UnlockedVault,
}

impl fmt::Debug for Genesis {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Genesis")
            .field("vault_id", &self.vault_id)
            .field("device_id", &self.device_id)
            .finish_non_exhaustive()
    }
}

/// Create a new vault: device identity, VMK epoch 1, signed header, self-signed genesis
/// member, recovery member + recovery-key wrap, optional master-password wrap and the
/// first manifest. Nothing is written; the caller stores `objects` then `manifest`.
pub fn create_genesis(p: GenesisParams<'_>) -> Result<Genesis> {
    validate_device_name(p.device_name)?;
    let vault_id = VaultId::generate();
    let device_id = DeviceId::generate();
    let identity = DeviceIdentity::generate();
    let keys = VaultKeys::generate(vault_id.clone())?;
    let now = aipass_types::time::truncate(p.now);

    let me = device_public(
        &device_id,
        &identity,
        p.device_name.trim(),
        p.platform,
        MemberRole::Owner,
    );
    let genesis_member = build_member(
        &identity,
        MemberParams {
            vault_id: &vault_id,
            device: &me,
            rev: 1,
            status: MemberStatus::Active,
            key_epoch: 1,
            wrapped_vmk: Some(seal_vmk(
                keys.current_vmk(),
                &vault_id,
                &device_id,
                1,
                &me.kem_pk,
            )?),
            added_by: &device_id,
            now: &now,
        },
    )?;
    let mut header = VaultHeader {
        format: FORMAT_V1,
        vault_id: vault_id.clone(),
        created_at: now,
        genesis_device_id: device_id.clone(),
        signature: String::new(),
    };
    header.sign_with(&identity)?;
    let header_bytes = object_bytes(&header)?;

    // recovery member + recovery-key wrap
    let recovery_key = RecoveryKey::generate()?;
    let rid = recovery_key.identity(&vault_id);
    let rdev_id = recovery_device_id(&rid.public().sign_pk);
    let rdev = device_public(
        &rdev_id,
        &rid,
        RECOVERY_MEMBER_NAME,
        Platform::Cli,
        MemberRole::Owner,
    );
    let recovery_member = build_member(
        &identity,
        MemberParams {
            vault_id: &vault_id,
            device: &rdev,
            rev: 1,
            status: MemberStatus::Active,
            key_epoch: 1,
            wrapped_vmk: Some(seal_vmk(
                keys.current_vmk(),
                &vault_id,
                &rdev_id,
                1,
                &rdev.kem_pk,
            )?),
            added_by: &device_id,
            now: &now,
        },
    )?;
    let rwrap = wrap_recovery(
        keys.current_vmk(),
        &vault_id,
        1,
        RecoveryKind::RecoveryKey,
        KdfSpec::HkdfSha256,
        &recovery_key.kek(&vault_id),
    )?;

    let genesis_view = VaultView::genesis(header.clone(), genesis_member.record.clone())?;
    let unlocked = UnlockedVault {
        vault_id: vault_id.clone(),
        device_id: device_id.clone(),
        identity,
        keys,
    };

    let mut objects = vec![
        (keys::VAULT_HEADER.to_owned(), header_bytes),
        (genesis_member.key(), genesis_member.bytes.clone()),
        (
            keys::recovery(1, RecoveryKind::RecoveryKey),
            object_bytes(&rwrap)?,
        ),
    ];
    if let Some(pw) = p.master_password {
        objects.push(unlocked.master_password_wrap(pw, p.argon2)?);
    }

    let mut draft = ManifestDraft::from_view(&genesis_view);
    draft.put_member(&recovery_member);
    let (manifest, staged) = draft.finish(unlocked.identity(), &device_id, &now)?;
    let members = staged_member_records(&genesis_view, &manifest, &staged);
    let view = verify_transition(&genesis_view, &manifest, &members)?;
    objects.extend(staged);

    Ok(Genesis {
        vault_id,
        device_id,
        recovery_key,
        header,
        genesis_member,
        objects,
        manifest,
        view,
        unlocked,
    })
}

/// Stage a new member (owner/member get the current VMK sealed; executors get none).
/// The caller must be an active owner/member; adding an owner requires an owner.
pub fn stage_add_member(
    vault: &UnlockedVault,
    view: &VaultView,
    draft: &mut ManifestDraft,
    device: &DevicePublic,
    now: &Timestamp,
) -> Result<SignedMember> {
    validate_device_name(&device.name)?;
    aipass_crypto::identity::validate_ed25519_public_key(&device.sign_pk)
        .map_err(|_| VaultError::InvalidInput("device signing key is invalid"))?;
    if !view.is_active_approver(vault.device_id()) {
        return Err(VaultError::Forbidden(
            "only active owners or members can add devices",
        ));
    }
    if device.role == MemberRole::Owner && !view.is_active_owner(vault.device_id()) {
        return Err(VaultError::Forbidden("only owners can add owners"));
    }
    if view.manifest.members.contains_key(&device.device_id)
        || draft.members.contains_key(&device.device_id)
    {
        return Err(VaultError::AlreadyExists);
    }
    if draft.key_epoch != vault.key_epoch() {
        return Err(VaultError::PreconditionFailed(
            "vault key epoch changed; sync first",
        ));
    }
    let wrapped = match device.role {
        MemberRole::Executor => None,
        _ => Some(vault.seal_current_vmk(&device.device_id, &device.kem_pk)?),
    };
    let m = build_member(
        vault.identity(),
        MemberParams {
            vault_id: vault.vault_id(),
            device,
            rev: 1,
            status: MemberStatus::Active,
            key_epoch: vault.key_epoch(),
            wrapped_vmk: wrapped,
            added_by: vault.device_id(),
            now,
        },
    )?;
    draft.put_member(&m);
    Ok(m)
}

/// Stage the revocation of `target` (owners only): a revoked member record, a new VMK epoch
/// sealed to every remaining active owner/member (including the recovery member), and the
/// keyring of the new epoch. Revoking an executor needs no rotation (it never held the
/// VMK). Returns the pending epoch to install after the commit succeeds.
pub fn stage_revocation(
    vault: &UnlockedVault,
    view: &VaultView,
    draft: &mut ManifestDraft,
    target: &DeviceId,
    now: &Timestamp,
) -> Result<Option<PendingEpoch>> {
    if !view.is_active_owner(vault.device_id()) {
        return Err(VaultError::Forbidden("only owners can revoke devices"));
    }
    let rec = view.member(target).ok_or(VaultError::NotFound("device"))?;
    if rec.status == MemberStatus::Revoked {
        return Err(VaultError::PreconditionFailed("device already revoked"));
    }
    if target == vault.device_id() {
        return Err(VaultError::Forbidden(
            "use another owner device to revoke this device",
        ));
    }
    let remaining_owners = view
        .manifest
        .members
        .iter()
        .filter(|(id, m)| {
            *id != target && m.status == MemberStatus::Active && m.role == MemberRole::Owner
        })
        .count();
    if remaining_owners == 0 {
        return Err(VaultError::Forbidden("the last owner cannot be revoked"));
    }
    let needs_rotation = rec.role.is_trusted_approver();
    let new_epoch = if needs_rotation {
        draft.next_epoch()
    } else {
        view.manifest.key_epoch
    };
    let revoked = build_member(
        vault.identity(),
        MemberParams {
            vault_id: vault.vault_id(),
            device: &rec.device_public(),
            rev: draft.next_member_rev(target, rec.rev),
            status: MemberStatus::Revoked,
            key_epoch: new_epoch,
            wrapped_vmk: None,
            added_by: vault.device_id(),
            now,
        },
    )?;
    draft.put_member(&revoked);
    if !needs_rotation {
        return Ok(None);
    }
    stage_rotation_inner(vault, view, draft, Some(target), new_epoch, now).map(Some)
}

/// Stage a key rotation without revoking anyone (owners only): a new VMK epoch sealed to
/// every active owner/member and the keyring of the new epoch. Used e.g. to change the
/// master password (recovery wraps are immutable per epoch).
pub fn stage_rotation(
    vault: &UnlockedVault,
    view: &VaultView,
    draft: &mut ManifestDraft,
    now: &Timestamp,
) -> Result<PendingEpoch> {
    if !view.is_active_owner(vault.device_id()) {
        return Err(VaultError::Forbidden(
            "only owners can rotate the vault key",
        ));
    }
    let new_epoch = draft.next_epoch();
    stage_rotation_inner(vault, view, draft, None, new_epoch, now)
}

fn stage_rotation_inner(
    vault: &UnlockedVault,
    view: &VaultView,
    draft: &mut ManifestDraft,
    exclude: Option<&DeviceId>,
    new_epoch: u32,
    now: &Timestamp,
) -> Result<PendingEpoch> {
    let vmk = Key32::generate()?;
    for (id, m) in &view.manifest.members {
        if Some(id) == exclude || m.status != MemberStatus::Active || !m.role.is_trusted_approver()
        {
            continue;
        }
        let r = view
            .member(id)
            .ok_or(VaultError::Internal("member record missing"))?;
        let sealed = seal_vmk(&vmk, vault.vault_id(), id, new_epoch, &r.kem_pk)?;
        let resealed = build_member(
            vault.identity(),
            MemberParams {
                vault_id: vault.vault_id(),
                device: &r.device_public(),
                rev: draft.next_member_rev(id, r.rev),
                status: MemberStatus::Active,
                key_epoch: new_epoch,
                wrapped_vmk: Some(sealed),
                added_by: vault.device_id(),
                now,
            },
        )?;
        draft.put_member(&resealed);
    }
    let mut all: BTreeMap<u32, Key32> = vault.keys.all().clone();
    all.insert(new_epoch, vmk.clone());
    let kr = build_keyring(
        vault.vault_id(),
        new_epoch,
        &vmk,
        &all,
        vault.device_id(),
        now,
    )?;
    draft.add_object(keys::keyring(new_epoch), object_bytes(&kr)?);
    draft.key_epoch = new_epoch;
    Ok(PendingEpoch {
        epoch: new_epoch,
        vmk,
    })
}

impl PendingEpoch {
    /// Master-password wrap of this (not yet installed) epoch's VMK.
    pub fn master_password_wrap(
        &self,
        vault_id: &VaultId,
        password: &SecretString,
        params: Argon2Params,
    ) -> Result<(String, Vec<u8>)> {
        let spec = master_password_kdf(params)?;
        let kek = master_password_kek(password.expose().as_bytes(), &spec)?;
        let w = wrap_recovery(
            &self.vmk,
            vault_id,
            self.epoch,
            RecoveryKind::MasterPassword,
            spec,
            &kek,
        )?;
        Ok((keys::recovery(w.key_epoch, w.kind), object_bytes(&w)?))
    }
}

/// Recover the vault with the recovery key: returns the recovery member's identity and an
/// unlocked vault **acting as the recovery member** (used only to enrol a new device and
/// revoke lost ones). `recovery_wrap_bytes` (optional) is `recovery/<epoch>-recovery_key.json`
/// for the current epoch — used as a fallback when the recovery member wrap is unusable.
pub fn open_with_recovery_key(
    view: &VaultView,
    key: &RecoveryKey,
    keyring_bytes: Option<&[u8]>,
    recovery_wrap_bytes: Option<&[u8]>,
) -> Result<UnlockedVault> {
    let rid = key.identity(view.vault_id());
    let rdev = recovery_device_id(&rid.public().sign_pk);
    let rec = view.member(&rdev).ok_or_else(|| {
        VaultError::Invalid(aipass_types::Localized::new(
            "恢复密钥与此账号库不匹配",
            "This recovery key does not belong to this vault.",
        ))
    })?;
    if !is_recovery_member(rec) || rec.sign_pk != rid.public().sign_pk {
        return Err(VaultError::Integrity(
            "recovery member record is inconsistent",
        ));
    }
    if rec.status == MemberStatus::Revoked {
        return Err(VaultError::Invalid(aipass_types::Localized::new(
            "这个恢复密钥已被替换或撤销，请使用最新的恢复包",
            "This recovery key was replaced or revoked; use your newest recovery kit.",
        )));
    }
    match UnlockedVault::open(view, rdev.clone(), rid, keyring_bytes) {
        Ok(v) => Ok(v),
        Err(e) => {
            let Some(bytes) = recovery_wrap_bytes else {
                return Err(e);
            };
            let w: RecoveryWrap = parse_json(bytes, "recovery wrap is not valid")?;
            if w.kind != RecoveryKind::RecoveryKey || w.key_epoch != rec.key_epoch {
                return Err(e);
            }
            let vmk = open_recovery(&w, &key.kek(view.vault_id()), view.vault_id())?;
            UnlockedVault::from_vmk(
                view,
                rdev,
                key.identity(view.vault_id()),
                w.key_epoch,
                vmk,
                keyring_bytes,
            )
        }
    }
}

/// Open the vault with a master password wrap (`recovery/<epoch>-master_password.json` of
/// the newest epoch that has one) and act as `device` — used only by tooling that has the
/// device identity but lost its local secret store; normal unlock uses the device wrap.
pub fn vmk_from_master_password(
    view: &VaultView,
    wrap_bytes: &[u8],
    password: &SecretString,
) -> Result<(u32, Key32)> {
    let w: RecoveryWrap = parse_json(wrap_bytes, "recovery wrap is not valid")?;
    if w.kind != RecoveryKind::MasterPassword {
        return Err(VaultError::InvalidInput("not a master password wrap"));
    }
    let kek = master_password_kek(password.expose().as_bytes(), &w.kdf)?;
    let vmk = open_recovery(&w, &kek, view.vault_id()).map_err(|_| {
        VaultError::Invalid(aipass_types::Localized::new(
            "主密码不正确",
            "The master password is incorrect.",
        ))
    })?;
    Ok((w.key_epoch, vmk))
}

/// The recovery member of a view, if any.
pub fn recovery_member(view: &VaultView) -> Option<&aipass_types::vault::MemberRecord> {
    view.members
        .values()
        .find(|m| is_recovery_member(m) && m.status == MemberStatus::Active)
}

/// Verify a typed recovery key against the view without touching storage.
pub fn recovery_key_matches(view: &VaultView, key: &RecoveryKey) -> bool {
    let rid = key.identity(view.vault_id());
    let id = recovery_device_id(&rid.public().sign_pk);
    view.member(&id).is_some_and(|m| {
        m.status == MemberStatus::Active && aipass_crypto::ct_eq(&m.sign_pk, &rid.public().sign_pk)
    })
}

/// Stage replacing the recovery key: revoke the current recovery member (with key rotation)
/// and enrol a recovery member for `new_key`. Owners only.
pub fn stage_replace_recovery_key(
    vault: &UnlockedVault,
    view: &VaultView,
    draft: &mut ManifestDraft,
    new_key: &RecoveryKey,
    now: &Timestamp,
) -> Result<Option<PendingEpoch>> {
    let old = recovery_member(view).map(|m| m.device_id.clone());
    let pending = match &old {
        Some(id) => stage_revocation(vault, view, draft, id, now)?,
        None => None,
    };
    let rid = new_key.identity(vault.vault_id());
    let rdev_id = recovery_device_id(&rid.public().sign_pk);
    let rdev = device_public(
        &rdev_id,
        &rid,
        RECOVERY_MEMBER_NAME,
        Platform::Cli,
        MemberRole::Owner,
    );
    let (epoch, sealed, wrap) = match &pending {
        Some(p) => (
            p.epoch,
            seal_vmk(&p.vmk, vault.vault_id(), &rdev_id, p.epoch, &rdev.kem_pk)?,
            wrap_recovery(
                &p.vmk,
                vault.vault_id(),
                p.epoch,
                RecoveryKind::RecoveryKey,
                KdfSpec::HkdfSha256,
                &new_key.kek(vault.vault_id()),
            )?,
        ),
        None => (
            vault.key_epoch(),
            vault.seal_current_vmk(&rdev_id, &rdev.kem_pk)?,
            wrap_recovery(
                vault.keys.current_vmk(),
                vault.vault_id(),
                vault.key_epoch(),
                RecoveryKind::RecoveryKey,
                KdfSpec::HkdfSha256,
                &new_key.kek(vault.vault_id()),
            )?,
        ),
    };
    if view.manifest.members.contains_key(&rdev_id) {
        return Err(VaultError::AlreadyExists);
    }
    let m = build_member(
        vault.identity(),
        MemberParams {
            vault_id: vault.vault_id(),
            device: &rdev,
            rev: 1,
            status: MemberStatus::Active,
            key_epoch: epoch,
            wrapped_vmk: Some(sealed),
            added_by: vault.device_id(),
            now,
        },
    )?;
    draft.put_member(&m);
    // A fresh recovery key wrap for the (possibly new) epoch; the key name is unique per
    // epoch, so when there is no rotation an older wrap for this epoch may already exist —
    // the caller writes it create-only and tolerates "already exists".
    if pending.is_some() {
        draft.add_object(
            keys::recovery(wrap.key_epoch, wrap.kind),
            object_bytes(&wrap)?,
        );
    }
    Ok(pending)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn genesis() -> Genesis {
        create_genesis(GenesisParams {
            device_name: "Laptop",
            platform: Platform::Macos,
            master_password: Some(&SecretString::from("correct horse battery")),
            argon2: Argon2Params::INSECURE_FAST_FOR_TESTS_ONLY,
            now: aipass_types::time::now(),
        })
        .unwrap()
    }

    #[test]
    fn genesis_view_is_consistent() {
        let g = genesis();
        assert_eq!(g.view.seq(), 1);
        assert!(g.view.is_active_owner(&g.device_id));
        let rm = recovery_member(&g.view).unwrap();
        assert!(is_recovery_member(rm));
        assert!(recovery_key_matches(&g.view, &g.recovery_key));
        assert!(!recovery_key_matches(
            &g.view,
            &RecoveryKey::generate().unwrap()
        ));
        // header + genesis verify from bytes
        let hb = &g.objects[0].1;
        let v0 =
            crate::manifest::verify_header(hb, &g.genesis_member.bytes, Some(&g.vault_id)).unwrap();
        assert_eq!(v0.seq(), 0);
        // the recovery key opens the vault as the recovery member
        let rv = open_with_recovery_key(&g.view, &g.recovery_key, None, None).unwrap();
        assert_eq!(rv.key_epoch(), 1);
        // master password wrap opens the same VMK
        let (k, b) = g
            .objects
            .iter()
            .find(|(k, _)| k.ends_with("master_password.json"))
            .unwrap();
        assert_eq!(k, "recovery/1-master_password.json");
        let (_, vmk) =
            vmk_from_master_password(&g.view, b, &SecretString::from("correct horse battery"))
                .unwrap();
        assert_eq!(&vmk, g.unlocked.keys.current_vmk());
        assert!(
            vmk_from_master_password(&g.view, b, &SecretString::from("wrong password!")).is_err()
        );
    }

    #[test]
    fn revocation_rotates_and_reseals() {
        let g = genesis();
        let mut view = g.view.clone();
        // add a member
        let other = DeviceIdentity::generate();
        let oid = DeviceId::generate();
        let od = device_public(&oid, &other, "Phone", Platform::Ios, MemberRole::Member);
        let now = aipass_types::time::now();
        let mut d = ManifestDraft::from_view(&view);
        stage_add_member(&g.unlocked, &view, &mut d, &od, &now).unwrap();
        let (c, staged) = d.finish(g.unlocked.identity(), &g.device_id, &now).unwrap();
        view = verify_transition(&view, &c, &staged_member_records(&view, &c, &staged)).unwrap();
        let phone = UnlockedVault::open(
            &view,
            oid.clone(),
            DeviceIdentity::from_secret_bytes(other.to_secret_bytes().expose()).unwrap(),
            None,
        )
        .unwrap();
        assert_eq!(phone.key_epoch(), 1);

        // revoke it
        let mut d = ManifestDraft::from_view(&view);
        let pending = stage_revocation(&g.unlocked, &view, &mut d, &oid, &now)
            .unwrap()
            .unwrap();
        assert_eq!(pending.epoch, 2);
        let (c, staged) = d.finish(g.unlocked.identity(), &g.device_id, &now).unwrap();
        let v2 = verify_transition(&view, &c, &staged_member_records(&view, &c, &staged)).unwrap();
        assert!(v2.is_revoked(&oid));
        assert_eq!(v2.manifest.key_epoch, 2);
        let mut laptop = g.unlocked;
        laptop.install_epoch(pending);
        assert_eq!(laptop.key_epoch(), 2);
        // revoked device cannot open the new view
        assert!(matches!(
            UnlockedVault::open(&v2, oid, other, None),
            Err(VaultError::Revoked)
        ));
        // recovery member got the new key too
        let kr = staged
            .iter()
            .find(|(k, _)| k == "keyring/2.json")
            .unwrap()
            .1
            .clone();
        let rv = open_with_recovery_key(&v2, &g.recovery_key, Some(&kr), None).unwrap();
        assert_eq!(rv.epochs(), vec![1, 2]);
    }
}
