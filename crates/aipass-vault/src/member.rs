// SPDX-License-Identifier: Apache-2.0
//! Member records (CONTRACTS §2.3) and identity conventions.
//!
//! * A `MemberRecord` is immutable; every change is a new `rev`, signed by `added_by`
//!   (an active owner/member — the genesis record rev 1 is self-signed).
//! * Owners/members get the VMK HPKE-sealed to their KEM key; executors get `null`.
//! * **Executor ids.** Vault member records are keyed by `dev_` ids; an executor node's
//!   broker/relay principal is its `exe_` id. The two share the same ULID part
//!   (`exe_X` ⇔ `dev_X`), see [`executor_member_id`] / [`member_executor_id`].
//! * **Recovery member.** At vault creation the genesis device enrols a *recovery identity*
//!   derived from the recovery secret (see [`recovery_identity`]) as an `owner` member. Its
//!   device id is a deterministic function of its public key ([`recovery_device_id`]), so
//!   every client can recognise it ([`is_recovery_member`]). Because new VMKs are sealed to
//!   it like to any other member, recovery keeps working after key rotation without any
//!   device ever storing the recovery secret.

use aipass_crypto::{DeviceIdentity, SealedBox, kdf};
use aipass_types::ids::{DeviceId, ExecutorId, VaultId};
use aipass_types::time::Timestamp;
use aipass_types::vault::{
    DevicePublic, FORMAT_V1, MemberRecord, MemberRole, MemberStatus, Platform, SignedObject,
};

use crate::encoding::{object_bytes, ulid_text};
use crate::error::{Result, VaultError};

/// HKDF info: Ed25519 seed of the recovery identity.
pub const INFO_RECOVERY_SIGN: &[u8] = b"aipass/v1/recovery-sign";
/// HKDF info: X25519 secret of the recovery identity.
pub const INFO_RECOVERY_KEM: &[u8] = b"aipass/v1/recovery-kem";
/// Domain separator of the recovery member's deterministic device id.
pub const RECOVERY_DEVICE_ID_DOMAIN: &[u8] = b"aipass/v1/recovery-device-id";
/// Display name of the recovery member (zh / en).
pub const RECOVERY_MEMBER_NAME: &str = "恢复密钥 / Recovery key";

/// The recovery identity derived from the 32-byte recovery secret:
/// `seed = HKDF(ikm = secret, salt = vault_id, info = "aipass/v1/recovery-sign")`,
/// `kem  = HKDF(ikm = secret, salt = vault_id, info = "aipass/v1/recovery-kem")`.
pub fn recovery_identity(secret: &[u8; 32], vault_id: &VaultId) -> DeviceIdentity {
    let salt = vault_id.as_str().as_bytes();
    let seed = kdf::derive_key32(salt, secret, INFO_RECOVERY_SIGN);
    let kem = kdf::derive_key32(salt, secret, INFO_RECOVERY_KEM);
    DeviceIdentity::from_parts(seed.expose(), kem.expose())
}

/// Deterministic device id of a recovery member:
/// `dev_` + ULID text of the first 16 bytes of `SHA-256(domain ‖ sign_pk)`.
pub fn recovery_device_id(sign_pk: &[u8; 32]) -> DeviceId {
    let h = aipass_crypto::hash::sha256_concat(&[RECOVERY_DEVICE_ID_DOMAIN, sign_pk]);
    let mut b = [0u8; 16];
    b.copy_from_slice(&h[..16]);
    let id = format!("dev_{}", ulid_text(u128::from_be_bytes(b)));
    // ulid_text always yields a valid 26-character Crockford string
    DeviceId::parse(&id).unwrap_or_else(|_| DeviceId::generate())
}

/// Whether a member record is the vault's recovery member.
pub fn is_recovery_member(record: &MemberRecord) -> bool {
    record.role == MemberRole::Owner && record.device_id == recovery_device_id(&record.sign_pk)
}

/// Whether a public device description is a recovery member.
pub fn is_recovery_device(device: &DevicePublic) -> bool {
    device.role == MemberRole::Owner && device.device_id == recovery_device_id(&device.sign_pk)
}

/// The vault member id (`dev_X`) of executor `exe_X`.
pub fn executor_member_id(executor: &ExecutorId) -> DeviceId {
    let ulid = &executor.as_str()[ExecutorId::PREFIX.len() + 1..];
    DeviceId::parse(&format!("dev_{ulid}")).unwrap_or_else(|_| DeviceId::generate())
}

/// The executor principal (`exe_X`) of vault member `dev_X`.
pub fn member_executor_id(device: &DeviceId) -> ExecutorId {
    let ulid = &device.as_str()[DeviceId::PREFIX.len() + 1..];
    ExecutorId::parse(&format!("exe_{ulid}")).unwrap_or_else(|_| ExecutorId::generate())
}

/// A member record with its exact bytes and hash.
#[derive(Debug, Clone)]
pub struct SignedMember {
    /// Record.
    pub record: MemberRecord,
    /// Exact stored bytes (JCS).
    pub bytes: Vec<u8>,
    /// `b64u(SHA-256(bytes))`.
    pub hash: String,
}

impl SignedMember {
    /// Storage key `members/<device_id>/<rev>.json`.
    pub fn key(&self) -> String {
        aipass_types::vault::keys::member(&self.record.device_id, self.record.rev)
    }

    /// Wrap an existing record (e.g. fetched from storage) — recomputes bytes and hash.
    pub fn from_record(record: MemberRecord) -> Result<Self> {
        let bytes = object_bytes(&record)?;
        let hash = aipass_types::vault::object_hash(&bytes);
        Ok(Self {
            record,
            bytes,
            hash,
        })
    }
}

/// Parameters of a new member record revision.
#[derive(Debug, Clone)]
pub struct MemberParams<'a> {
    /// Vault.
    pub vault_id: &'a VaultId,
    /// The device described.
    pub device: &'a DevicePublic,
    /// Revision (1 for a new member).
    pub rev: u64,
    /// Status.
    pub status: MemberStatus,
    /// Key epoch of `wrapped_vmk`.
    pub key_epoch: u32,
    /// VMK sealed to the device (`None` for executors and revoked devices).
    pub wrapped_vmk: Option<SealedBox>,
    /// Signing device id (`added_by`).
    pub added_by: &'a DeviceId,
    /// Timestamp.
    pub now: &'a Timestamp,
}

/// Build and sign a member record with `signer` (the identity of `added_by`).
pub fn build_member(signer: &DeviceIdentity, p: MemberParams<'_>) -> Result<SignedMember> {
    if p.rev == 0 {
        return Err(VaultError::InvalidInput("member revisions start at 1"));
    }
    if p.device.role == MemberRole::Executor && p.wrapped_vmk.is_some() {
        return Err(VaultError::InvalidInput(
            "executors never receive the vault key",
        ));
    }
    if p.status == MemberStatus::Revoked && p.wrapped_vmk.is_some() {
        return Err(VaultError::InvalidInput(
            "revoked members carry no vault key",
        ));
    }
    let mut record = MemberRecord {
        format: FORMAT_V1,
        vault_id: p.vault_id.clone(),
        device_id: p.device.device_id.clone(),
        rev: p.rev,
        name: p.device.name.clone(),
        platform: p.device.platform,
        role: p.device.role,
        sign_pk: p.device.sign_pk,
        kem_pk: p.device.kem_pk,
        status: p.status,
        key_epoch: p.key_epoch,
        wrapped_vmk: p.wrapped_vmk,
        added_by: p.added_by.clone(),
        created_at: aipass_types::time::truncate(*p.now),
        signature: String::new(),
    };
    record.sign_with(signer)?;
    SignedMember::from_record(record)
}

/// Public description of a local identity.
pub fn device_public(
    device_id: &DeviceId,
    identity: &DeviceIdentity,
    name: &str,
    platform: Platform,
    role: MemberRole,
) -> DevicePublic {
    let p = identity.public();
    DevicePublic {
        device_id: device_id.clone(),
        name: name.to_owned(),
        platform,
        role,
        sign_pk: p.sign_pk,
        kem_pk: p.kem_pk,
    }
}

/// Validate a device display name (non-empty, ≤ 64 chars, no control characters).
pub fn validate_device_name(name: &str) -> Result<()> {
    let n = name.trim();
    if n.is_empty()
        || n.chars().count() > aipass_types::pairing::MAX_NAME_CHARS
        || n.chars().any(char::is_control)
    {
        return Err(VaultError::Invalid(aipass_types::Localized::new(
            "设备名称不能为空、不能超过 64 个字符，且不能包含控制字符",
            "The device name must be 1–64 characters without control characters.",
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovery_identity_is_deterministic_and_vault_bound() {
        let v = VaultId::generate();
        let a = recovery_identity(&[1; 32], &v);
        let b = recovery_identity(&[1; 32], &v);
        assert_eq!(a.public(), b.public());
        assert_ne!(a.public(), recovery_identity(&[2; 32], &v).public());
        assert_ne!(
            a.public(),
            recovery_identity(&[1; 32], &VaultId::generate()).public()
        );
        let id = recovery_device_id(&a.public().sign_pk);
        assert_eq!(id, recovery_device_id(&b.public().sign_pk));
        let dp = device_public(
            &id,
            &a,
            RECOVERY_MEMBER_NAME,
            Platform::Cli,
            MemberRole::Owner,
        );
        assert!(is_recovery_device(&dp));
        let other = device_public(
            &DeviceId::generate(),
            &a,
            "x",
            Platform::Cli,
            MemberRole::Owner,
        );
        assert!(!is_recovery_device(&other));
    }

    #[test]
    fn executor_mapping() {
        let e = ExecutorId::generate();
        let d = executor_member_id(&e);
        assert_eq!(&d.as_str()[4..], &e.as_str()[4..]);
        assert_eq!(member_executor_id(&d), e);
    }

    #[test]
    fn member_rules() {
        let id = DeviceIdentity::generate();
        let dev = DeviceId::generate();
        let v = VaultId::generate();
        let now = aipass_types::time::now();
        let exe = device_public(&dev, &id, "node", Platform::Node, MemberRole::Executor);
        let sealed = crate::keys::seal_vmk(
            &aipass_crypto::Key32::generate().unwrap(),
            &v,
            &dev,
            1,
            &exe.kem_pk,
        )
        .unwrap();
        let bad = build_member(
            &id,
            MemberParams {
                vault_id: &v,
                device: &exe,
                rev: 1,
                status: MemberStatus::Active,
                key_epoch: 1,
                wrapped_vmk: Some(sealed),
                added_by: &dev,
                now: &now,
            },
        );
        assert!(bad.is_err());
        let ok = build_member(
            &id,
            MemberParams {
                vault_id: &v,
                device: &exe,
                rev: 1,
                status: MemberStatus::Active,
                key_epoch: 1,
                wrapped_vmk: None,
                added_by: &dev,
                now: &now,
            },
        )
        .unwrap();
        ok.record.verify_signature(&id.public().sign_pk).unwrap();
        assert_eq!(ok.key(), format!("members/{dev}/1.json"));
        assert!(validate_device_name("").is_err());
        assert!(validate_device_name("我的 iPhone").is_ok());
    }
}
