// SPDX-License-Identifier: Apache-2.0
//! Entry versions (CONTRACTS §2.3):
//!
//! ```text
//! wrapped_dek = XChaCha20Poly1305(VMK[key_epoch], dek_nonce, DEK,
//!               aad = "aipass:v1:dek:{vault_id}:{entry_id}:{version}:{key_epoch}")
//! ciphertext  = XChaCha20Poly1305(DEK, nonce, JCS(EntryPayload),
//!               aad = "aipass:v1:entry:{vault_id}:{entry_id}:{version}:1")
//! ```
//!
//! A fresh random DEK is generated for every version. Decryption computes both AADs from
//! the **expected** location (the storage key / manifest), never from the object's own
//! fields, so moving a ciphertext to another entry id or version fails authentication.

use aipass_crypto::{Key32, aead};
use aipass_types::ids::{DeviceId, EntryId, VaultId};
use aipass_types::time::Timestamp;
use aipass_types::vault::{EntryPayload, EntryVersion, FORMAT_V1, aad};

use crate::encoding::object_bytes;
use crate::error::{Result, VaultError, parse_json};
use crate::keys::VaultKeys;

/// An encrypted entry version together with its exact file bytes and hash.
#[derive(Debug, Clone)]
pub struct SealedEntry {
    /// Parsed object.
    pub version: EntryVersion,
    /// Exact bytes to store (JCS).
    pub bytes: Vec<u8>,
    /// `b64u(SHA-256(bytes))` — the manifest `hash`.
    pub hash: String,
}

impl SealedEntry {
    /// Storage key `entries/<entry_id>/<version>.json`.
    pub fn key(&self) -> String {
        aipass_types::vault::keys::entry(&self.version.entry_id, self.version.version)
    }
}

/// Encrypt `payload` as version `version` of `entry_id` under the **current** VMK.
pub fn encrypt_entry(
    keys: &VaultKeys,
    entry_id: &EntryId,
    version: u64,
    payload: &EntryPayload,
    author: &DeviceId,
    now: &Timestamp,
) -> Result<SealedEntry> {
    let dek = Key32::generate()?;
    let dek_nonce = aipass_crypto::rng::try_random_array::<{ aead::NONCE_LEN }>()?;
    let nonce = aipass_crypto::rng::try_random_array::<{ aead::NONCE_LEN }>()?;
    encrypt_entry_with(
        keys.vault_id(),
        keys.current_epoch(),
        keys.current_vmk(),
        entry_id,
        version,
        payload,
        author,
        now,
        &dek,
        &dek_nonce,
        &nonce,
    )
}

/// Fully explicit variant of [`encrypt_entry`] (fixed DEK and nonces) — used by the test
/// vectors. Production code must use [`encrypt_entry`], which draws all randomness from the
/// OS CSPRNG.
#[doc(hidden)]
#[allow(clippy::too_many_arguments)]
pub fn encrypt_entry_with(
    vault_id: &VaultId,
    key_epoch: u32,
    vmk: &Key32,
    entry_id: &EntryId,
    version: u64,
    payload: &EntryPayload,
    author: &DeviceId,
    now: &Timestamp,
    dek: &Key32,
    dek_nonce: &[u8; 24],
    nonce: &[u8; 24],
) -> Result<SealedEntry> {
    if version == 0 {
        return Err(VaultError::InvalidInput("entry versions start at 1"));
    }
    let dek_aad = aad::dek(vault_id, entry_id, version, key_epoch);
    let wrapped_dek = aead::seal_with_nonce(vmk, dek_nonce, dek_aad.as_bytes(), dek.expose())?;
    let plaintext = payload.to_plaintext()?;
    let entry_aad = aad::entry(vault_id, entry_id, version);
    let ciphertext = aead::seal_with_nonce(dek, nonce, entry_aad.as_bytes(), &plaintext)?;
    let ev = EntryVersion {
        format: FORMAT_V1,
        vault_id: vault_id.clone(),
        entry_id: entry_id.clone(),
        version,
        key_epoch,
        dek_nonce: *dek_nonce,
        wrapped_dek,
        nonce: *nonce,
        ciphertext,
        author_device_id: author.clone(),
        created_at: aipass_types::time::truncate(*now),
    };
    let bytes = object_bytes(&ev)?;
    let hash = aipass_types::vault::object_hash(&bytes);
    Ok(SealedEntry {
        version: ev,
        bytes,
        hash,
    })
}

/// Parse an entry version object and check that it is the object expected at
/// `entries/<entry_id>/<version>.json` of `vault_id`.
pub fn parse_entry_object(
    bytes: &[u8],
    vault_id: &VaultId,
    entry_id: &EntryId,
    version: u64,
) -> Result<EntryVersion> {
    let ev: EntryVersion = parse_json(bytes, "entry version is not valid JSON")?;
    if ev.format != FORMAT_V1 {
        return Err(VaultError::Unsupported("entry version format"));
    }
    if &ev.vault_id != vault_id || &ev.entry_id != entry_id || ev.version != version {
        return Err(VaultError::Integrity(
            "entry version object does not match its location",
        ));
    }
    Ok(ev)
}

/// Decrypt an entry version found at `entries/<entry_id>/<version>.json`. The AADs are
/// computed from the expected location; any mismatch (moved ciphertext, swapped DEK, wrong
/// epoch, tampering) fails with an integrity error.
pub fn decrypt_entry(
    keys: &VaultKeys,
    entry_id: &EntryId,
    version: u64,
    ev: &EntryVersion,
) -> Result<EntryPayload> {
    let vault_id = keys.vault_id();
    let vmk = keys.vmk(ev.key_epoch)?;
    let dek_aad = aad::dek(vault_id, entry_id, version, ev.key_epoch);
    let dek = aead::unwrap_key(vmk, &ev.dek_nonce, dek_aad.as_bytes(), &ev.wrapped_dek)
        .map_err(|_| VaultError::Integrity("entry key could not be unwrapped"))?;
    let entry_aad = aad::entry(vault_id, entry_id, version);
    let pt = aead::open(&dek, &ev.nonce, entry_aad.as_bytes(), &ev.ciphertext)
        .map_err(|_| VaultError::Integrity("entry ciphertext failed authentication"))?;
    EntryPayload::from_plaintext(pt.expose())
        .map_err(|_| VaultError::Integrity("entry payload is not valid JSON"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use aipass_crypto::SecretString;
    use aipass_types::vault::EntryKind;

    fn keys() -> VaultKeys {
        VaultKeys::generate(VaultId::generate()).unwrap()
    }

    #[test]
    fn roundtrip_and_aad_binding() {
        let k = keys();
        let e = EntryId::generate();
        let dev = DeviceId::generate();
        let mut p = EntryPayload::new(EntryKind::Login, "Example");
        p.secret = Some(SecretString::from("pw-123"));
        let now = aipass_types::time::now();
        let s = encrypt_entry(&k, &e, 1, &p, &dev, &now).unwrap();
        let ev = parse_entry_object(&s.bytes, k.vault_id(), &e, 1).unwrap();
        assert_eq!(decrypt_entry(&k, &e, 1, &ev).unwrap(), p);
        // moved to another entry id / version: AAD mismatch
        let other = EntryId::generate();
        assert!(decrypt_entry(&k, &other, 1, &ev).is_err());
        assert!(decrypt_entry(&k, &e, 2, &ev).is_err());
        // location check
        assert!(parse_entry_object(&s.bytes, k.vault_id(), &other, 1).is_err());
        // DEK swapped from another version
        let s2 = encrypt_entry(&k, &e, 2, &p, &dev, &now).unwrap();
        let mut franken = ev.clone();
        franken.wrapped_dek = s2.version.wrapped_dek.clone();
        franken.dek_nonce = s2.version.dek_nonce;
        assert!(decrypt_entry(&k, &e, 1, &franken).is_err());
        // different vault keys
        assert!(decrypt_entry(&keys(), &e, 1, &ev).is_err());
        // plaintext never appears in the stored bytes
        assert!(!String::from_utf8_lossy(&s.bytes).contains("pw-123"));
        assert!(!String::from_utf8_lossy(&s.bytes).contains("Example"));
        assert_eq!(s.key(), format!("entries/{e}/1.json"));
    }
}
