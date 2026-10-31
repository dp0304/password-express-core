// SPDX-License-Identifier: Apache-2.0
//! Key hierarchy (CONTRACTS §2.2, design doc §9.4).
//!
//! * **VMK** — 32 random bytes per `key_epoch` (u32, starts at 1, incremented on member
//!   revocation / rotation). Held only inside [`VaultKeys`], never exposed to UIs.
//! * **DEK** — 32 random bytes per entry *version* ([`crate::entry`]).
//! * VMK sealed per owner/member device with HPKE (`info = aipass/v1/vmk-wrap`,
//!   `aad = aipass:v1:vmk:{vault_id}:{device_id}:{key_epoch}`). Executors never get it.
//! * Recovery KEK = `HKDF-SHA256(ikm = secret, salt = UTF-8 bytes of vault_id,
//!   info = "aipass/v1/recovery-kek")`; master-password KEK = Argon2id. Both wrap the VMK
//!   with XChaCha20-Poly1305 into a [`RecoveryWrap`].
//! * Keyring `keyring/<e>.json` — every previous epoch's VMK encrypted under VMK[e]
//!   (`aad = aipass:v1:keyring:{vault_id}:{e}`), so a device that only holds the newest VMK
//!   can still read older entry versions.

use core::fmt;
use std::collections::BTreeMap;

use aipass_crypto::{Argon2Params, KemKeypair, Key32, SealedBox, aead, hpke, info, kdf};
use aipass_types::ids::{DeviceId, VaultId};
use aipass_types::time::Timestamp;
use aipass_types::vault::{
    FORMAT_V1, KdfSpec, KeyringItem, KeyringRecord, RecoveryKind, RecoveryWrap, aad,
};

use crate::error::{Result, VaultError};

/// The VMKs of a vault, by key epoch. Debug output is redacted; there is deliberately no
/// accessor that hands a VMK to callers outside this crate.
#[derive(Clone)]
pub struct VaultKeys {
    vault_id: VaultId,
    current_epoch: u32,
    vmks: BTreeMap<u32, Key32>,
}

impl fmt::Debug for VaultKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VaultKeys")
            .field("vault_id", &self.vault_id)
            .field("current_epoch", &self.current_epoch)
            .field("epochs", &self.vmks.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl VaultKeys {
    /// Start a key set with the VMK of `epoch` as the current key.
    pub(crate) fn new(vault_id: VaultId, epoch: u32, vmk: Key32) -> Self {
        let mut vmks = BTreeMap::new();
        vmks.insert(epoch, vmk);
        Self {
            vault_id,
            current_epoch: epoch,
            vmks,
        }
    }

    /// Generate a brand-new epoch-1 key set (vault creation).
    pub(crate) fn generate(vault_id: VaultId) -> Result<Self> {
        Ok(Self::new(vault_id, 1, Key32::generate()?))
    }

    /// Vault the keys belong to.
    pub fn vault_id(&self) -> &VaultId {
        &self.vault_id
    }

    /// Newest epoch held.
    pub fn current_epoch(&self) -> u32 {
        self.current_epoch
    }

    /// Epochs held.
    pub fn epochs(&self) -> Vec<u32> {
        self.vmks.keys().copied().collect()
    }

    /// Whether the VMK of `epoch` is held.
    pub fn has_epoch(&self, epoch: u32) -> bool {
        self.vmks.contains_key(&epoch)
    }

    pub(crate) fn vmk(&self, epoch: u32) -> Result<&Key32> {
        self.vmks.get(&epoch).ok_or(VaultError::SecretUnavailable(
            "vault key for this epoch is not available",
        ))
    }

    pub(crate) fn current_vmk(&self) -> &Key32 {
        // invariant: the current epoch is always present
        &self.vmks[&self.current_epoch]
    }

    /// Add a VMK; the newest epoch becomes current.
    pub(crate) fn insert(&mut self, epoch: u32, vmk: Key32) {
        self.vmks.insert(epoch, vmk);
        if epoch > self.current_epoch {
            self.current_epoch = epoch;
        }
    }

    pub(crate) fn all(&self) -> &BTreeMap<u32, Key32> {
        &self.vmks
    }
}

/// HPKE-seal `vmk` (epoch `epoch`) to a member device's X25519 key.
pub fn seal_vmk(
    vmk: &Key32,
    vault_id: &VaultId,
    device_id: &DeviceId,
    epoch: u32,
    recipient_kem_pk: &[u8; 32],
) -> Result<SealedBox> {
    let aad = aad::vmk_wrap(vault_id, device_id, epoch);
    Ok(hpke::seal(
        recipient_kem_pk,
        info::VMK_WRAP,
        aad.as_bytes(),
        vmk.expose(),
    )?)
}

/// Open a VMK sealed with [`seal_vmk`].
pub fn open_vmk(
    kem: &KemKeypair,
    vault_id: &VaultId,
    device_id: &DeviceId,
    epoch: u32,
    sealed: &SealedBox,
) -> Result<Key32> {
    let aad = aad::vmk_wrap(vault_id, device_id, epoch);
    let pt = hpke::open(kem, info::VMK_WRAP, aad.as_bytes(), sealed)
        .map_err(|_| VaultError::Integrity("vault key wrap could not be opened"))?;
    pt.to_key32()
        .ok_or(VaultError::Integrity("vault key wrap has the wrong length"))
}

/// `KEK = HKDF(ikm = recovery secret, salt = vault_id bytes, info = "aipass/v1/recovery-kek")`.
pub fn recovery_kek(secret: &[u8; 32], vault_id: &VaultId) -> Key32 {
    kdf::derive_key32(vault_id.as_str().as_bytes(), secret, info::RECOVERY_KEK)
}

/// A fresh Argon2id KDF descriptor for a master-password wrap.
pub fn master_password_kdf(params: Argon2Params) -> Result<KdfSpec> {
    let salt = aipass_crypto::rng::try_random_array::<{ aipass_crypto::password::SALT_LEN }>()?;
    Ok(KdfSpec::Argon2id {
        m: params.m,
        t: params.t,
        p: params.p,
        salt: salt.to_vec(),
    })
}

/// Derive the KEK of a master-password wrap.
pub fn master_password_kek(password: &[u8], kdf_spec: &KdfSpec) -> Result<Key32> {
    match kdf_spec {
        KdfSpec::Argon2id { m, t, p, salt } => {
            if salt.len() < aipass_crypto::password::SALT_LEN {
                return Err(VaultError::Integrity("master password salt too short"));
            }
            Ok(aipass_crypto::password::argon2id(
                password,
                salt,
                Argon2Params {
                    m: *m,
                    t: *t,
                    p: *p,
                },
            )?)
        }
        KdfSpec::HkdfSha256 => Err(VaultError::Integrity(
            "master password wrap must use argon2id",
        )),
    }
}

/// Wrap `vmk` under `kek` into a [`RecoveryWrap`] (random nonce).
pub fn wrap_recovery(
    vmk: &Key32,
    vault_id: &VaultId,
    epoch: u32,
    kind: RecoveryKind,
    kdf_spec: KdfSpec,
    kek: &Key32,
) -> Result<RecoveryWrap> {
    let nonce = aipass_crypto::rng::try_random_array::<{ aead::NONCE_LEN }>()?;
    wrap_recovery_with_nonce(vmk, vault_id, epoch, kind, kdf_spec, kek, &nonce)
}

/// [`wrap_recovery`] with an explicit nonce (test vectors only; production uses random).
#[doc(hidden)]
pub fn wrap_recovery_with_nonce(
    vmk: &Key32,
    vault_id: &VaultId,
    epoch: u32,
    kind: RecoveryKind,
    kdf_spec: KdfSpec,
    kek: &Key32,
    nonce: &[u8; 24],
) -> Result<RecoveryWrap> {
    let ad = aad::recovery(vault_id, epoch, kind);
    let wrapped = aead::seal_with_nonce(kek, nonce, ad.as_bytes(), vmk.expose())?;
    Ok(RecoveryWrap {
        format: FORMAT_V1,
        vault_id: vault_id.clone(),
        key_epoch: epoch,
        kind,
        kdf: kdf_spec,
        nonce: *nonce,
        wrapped_vmk: wrapped,
    })
}

/// Open a [`RecoveryWrap`] with its KEK. `expected_vault` binds the wrap to the vault being
/// recovered (the AAD is computed from it, not from the object).
pub fn open_recovery(wrap: &RecoveryWrap, kek: &Key32, expected_vault: &VaultId) -> Result<Key32> {
    if wrap.format != FORMAT_V1 || &wrap.vault_id != expected_vault {
        return Err(VaultError::Integrity(
            "recovery wrap does not belong to this vault",
        ));
    }
    let ad = aad::recovery(expected_vault, wrap.key_epoch, wrap.kind);
    aead::unwrap_key(kek, &wrap.nonce, ad.as_bytes(), &wrap.wrapped_vmk)
        .map_err(|_| VaultError::Integrity("recovery material does not open this vault"))
}

/// Build `keyring/<epoch>.json`: every VMK in `previous` (epochs < `epoch`) encrypted under
/// `vmk` (the VMK of `epoch`).
pub fn build_keyring(
    vault_id: &VaultId,
    epoch: u32,
    vmk: &Key32,
    previous: &BTreeMap<u32, Key32>,
    author: &DeviceId,
    now: &Timestamp,
) -> Result<KeyringRecord> {
    let ad = aad::keyring(vault_id, epoch);
    let mut items = Vec::new();
    for (e, k) in previous.range(..epoch) {
        let (nonce, wrapped) = aead::wrap_key(vmk, ad.as_bytes(), k)?;
        items.push(KeyringItem {
            key_epoch: *e,
            nonce,
            wrapped_vmk: wrapped,
        });
    }
    Ok(KeyringRecord {
        format: FORMAT_V1,
        vault_id: vault_id.clone(),
        key_epoch: epoch,
        previous: items,
        author_device_id: author.clone(),
        created_at: aipass_types::time::truncate(*now),
    })
}

/// Open a keyring record with the VMK of its epoch.
pub fn open_keyring(
    record: &KeyringRecord,
    vmk: &Key32,
    expected_vault: &VaultId,
    expected_epoch: u32,
) -> Result<BTreeMap<u32, Key32>> {
    if record.format != FORMAT_V1
        || &record.vault_id != expected_vault
        || record.key_epoch != expected_epoch
    {
        return Err(VaultError::Integrity("keyring record does not match"));
    }
    let ad = aad::keyring(expected_vault, expected_epoch);
    let mut out = BTreeMap::new();
    for item in &record.previous {
        if item.key_epoch >= expected_epoch {
            return Err(VaultError::Integrity("keyring item epoch out of range"));
        }
        let k = aead::unwrap_key(vmk, &item.nonce, ad.as_bytes(), &item.wrapped_vmk)
            .map_err(|_| VaultError::Integrity("keyring item could not be opened"))?;
        out.insert(item.key_epoch, k);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vmk_wrap_binds_device_and_epoch() {
        let vault = VaultId::generate();
        let dev = DeviceId::generate();
        let kem = KemKeypair::generate();
        let vmk = Key32::generate().unwrap();
        let sealed = seal_vmk(&vmk, &vault, &dev, 1, &kem.public_key()).unwrap();
        assert_eq!(open_vmk(&kem, &vault, &dev, 1, &sealed).unwrap(), vmk);
        assert!(open_vmk(&kem, &vault, &dev, 2, &sealed).is_err());
        assert!(open_vmk(&kem, &vault, &DeviceId::generate(), 1, &sealed).is_err());
        assert!(open_vmk(&KemKeypair::generate(), &vault, &dev, 1, &sealed).is_err());
    }

    #[test]
    fn recovery_and_keyring() {
        let vault = VaultId::generate();
        let vmk = Key32::generate().unwrap();
        let kek = recovery_kek(&[5u8; 32], &vault);
        let w = wrap_recovery(
            &vmk,
            &vault,
            1,
            RecoveryKind::RecoveryKey,
            KdfSpec::HkdfSha256,
            &kek,
        )
        .unwrap();
        assert_eq!(open_recovery(&w, &kek, &vault).unwrap(), vmk);
        assert!(open_recovery(&w, &recovery_kek(&[6u8; 32], &vault), &vault).is_err());
        assert!(open_recovery(&w, &kek, &VaultId::generate()).is_err());
        let mut relabeled = w.clone();
        relabeled.kind = RecoveryKind::MasterPassword;
        assert!(open_recovery(&relabeled, &kek, &vault).is_err());

        let spec = master_password_kdf(Argon2Params::INSECURE_FAST_FOR_TESTS_ONLY).unwrap();
        let k1 = master_password_kek(b"pw", &spec).unwrap();
        assert_eq!(k1, master_password_kek(b"pw", &spec).unwrap());
        assert_ne!(k1, master_password_kek(b"pw2", &spec).unwrap());

        let mut prev = BTreeMap::new();
        prev.insert(1, vmk.clone());
        let v2 = Key32::generate().unwrap();
        let dev = DeviceId::generate();
        let now = aipass_types::time::now();
        let kr = build_keyring(&vault, 2, &v2, &prev, &dev, &now).unwrap();
        let opened = open_keyring(&kr, &v2, &vault, 2).unwrap();
        assert_eq!(opened[&1], vmk);
        assert!(open_keyring(&kr, &vmk, &vault, 2).is_err());
        assert!(open_keyring(&kr, &v2, &vault, 3).is_err());
        let dbg = format!("{:?}", VaultKeys::new(vault.clone(), 1, vmk));
        assert!(dbg.contains("epochs") && !dbg.contains("Key32("));
    }
}
