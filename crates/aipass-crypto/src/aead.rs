// SPDX-License-Identifier: Apache-2.0
//! XChaCha20-Poly1305 AEAD with 24-byte random nonces (CONTRACTS §2.1, design doc §9.4).
//!
//! Every call binds caller-supplied associated data (AAD). The vault formats put vault ID,
//! entry ID, version, key epoch and format version into the AAD (see
//! `aipass_types::vault::aad`), so ciphertexts cannot be swapped between contexts.

use chacha20poly1305::aead::{Aead as _, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::{CryptoError, Result};
use crate::secret::{Key32, SecretBytes};

/// Key length (32 bytes).
pub const KEY_LEN: usize = 32;
/// XChaCha20 nonce length (24 bytes).
pub const NONCE_LEN: usize = 24;
/// Poly1305 tag length (16 bytes), appended to the ciphertext.
pub const TAG_LEN: usize = 16;

fn cipher(key: &Key32) -> XChaCha20Poly1305 {
    XChaCha20Poly1305::new(&chacha20poly1305::Key::from(*key.expose()))
}

/// Encrypt with an explicit nonce. Prefer [`seal`], which draws the nonce from the CSPRNG;
/// this variant exists for known-answer tests and deterministic re-encryption checks.
/// Returns `ciphertext ‖ tag`.
pub fn seal_with_nonce(
    key: &Key32,
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    cipher(key)
        .encrypt(
            &XNonce::from(*nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| CryptoError::Encrypt)
}

/// Encrypt `plaintext` under `key` with a fresh random 24-byte nonce.
/// Returns `(nonce, ciphertext ‖ tag)`.
pub fn seal(key: &Key32, aad: &[u8], plaintext: &[u8]) -> Result<([u8; NONCE_LEN], Vec<u8>)> {
    let nonce = crate::rng::try_random_array::<NONCE_LEN>()?;
    let ct = seal_with_nonce(key, &nonce, aad, plaintext)?;
    Ok((nonce, ct))
}

/// Decrypt and authenticate. Any mismatch of key, nonce, AAD or ciphertext yields
/// [`CryptoError::Decrypt`]; the plaintext is returned in a zeroizing buffer.
pub fn open(
    key: &Key32,
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<SecretBytes> {
    if ciphertext.len() < TAG_LEN {
        return Err(CryptoError::Decrypt);
    }
    let pt = cipher(key)
        .decrypt(
            &XNonce::from(*nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| CryptoError::Decrypt)?;
    Ok(SecretBytes::new(pt))
}

/// Wrap a 32-byte key under another key (VMK under KEK, DEK under VMK).
pub fn wrap_key(kek: &Key32, aad: &[u8], key: &Key32) -> Result<([u8; NONCE_LEN], Vec<u8>)> {
    seal(kek, aad, key.expose())
}

/// Unwrap a 32-byte key wrapped with [`wrap_key`].
pub fn unwrap_key(
    kek: &Key32,
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    wrapped: &[u8],
) -> Result<Key32> {
    let pt = open(kek, nonce, aad, wrapped)?;
    let bytes = Zeroizing::new(pt.expose().to_vec());
    Key32::from_slice(&bytes).map_err(|_| CryptoError::Decrypt)
}

/// A self-describing XChaCha20-Poly1305 box for JSON messages:
/// `{"nonce": b64u(24 bytes), "ct": b64u(ciphertext ‖ tag)}`.
///
/// Used where a contract says `sealed: XChaCha20(K, {...})`, e.g. the pairing messages of
/// CONTRACTS §5. The AAD is never stored in the box; both sides derive it from context.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AeadBox {
    /// 24-byte nonce.
    #[serde(with = "crate::b64u::array")]
    pub nonce: [u8; NONCE_LEN],
    /// Ciphertext with appended 16-byte tag.
    #[serde(with = "crate::b64u::bytes")]
    pub ct: Vec<u8>,
}

impl core::fmt::Debug for AeadBox {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AeadBox")
            .field("ct_len", &self.ct.len())
            .finish_non_exhaustive()
    }
}

impl AeadBox {
    /// Encrypt into a box with a random nonce.
    pub fn seal(key: &Key32, aad: &[u8], plaintext: &[u8]) -> Result<Self> {
        let (nonce, ct) = seal(key, aad, plaintext)?;
        Ok(Self { nonce, ct })
    }

    /// Decrypt the box.
    pub fn open(&self, key: &Key32, aad: &[u8]) -> Result<SecretBytes> {
        open(key, &self.nonce, aad, &self.ct)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_tamper() {
        let key = Key32::generate().unwrap();
        let (nonce, ct) = seal(&key, b"aad-1", b"hello vault").unwrap();
        assert_eq!(ct.len(), b"hello vault".len() + TAG_LEN);
        assert_eq!(
            open(&key, &nonce, b"aad-1", &ct).unwrap().expose(),
            b"hello vault"
        );
        // wrong AAD
        assert_eq!(open(&key, &nonce, b"aad-2", &ct), Err(CryptoError::Decrypt));
        // flipped bit
        let mut bad = ct.clone();
        bad[0] ^= 1;
        assert_eq!(
            open(&key, &nonce, b"aad-1", &bad),
            Err(CryptoError::Decrypt)
        );
        // wrong nonce
        let mut n2 = nonce;
        n2[23] ^= 0x80;
        assert_eq!(open(&key, &n2, b"aad-1", &ct), Err(CryptoError::Decrypt));
        // wrong key
        let other = Key32::generate().unwrap();
        assert_eq!(
            open(&other, &nonce, b"aad-1", &ct),
            Err(CryptoError::Decrypt)
        );
        // truncated
        assert_eq!(
            open(&key, &nonce, b"aad-1", &ct[..10]),
            Err(CryptoError::Decrypt)
        );
    }

    #[test]
    fn nonces_are_random() {
        let key = Key32::generate().unwrap();
        let (n1, c1) = seal(&key, b"", b"same").unwrap();
        let (n2, c2) = seal(&key, b"", b"same").unwrap();
        assert_ne!(n1, n2);
        assert_ne!(c1, c2);
    }

    #[test]
    fn key_wrap_and_box() {
        let kek = Key32::generate().unwrap();
        let dek = Key32::generate().unwrap();
        let (n, w) = wrap_key(&kek, b"ctx", &dek).unwrap();
        assert_eq!(unwrap_key(&kek, &n, b"ctx", &w).unwrap(), dek);
        assert!(unwrap_key(&kek, &n, b"other", &w).is_err());

        let b = AeadBox::seal(&kek, b"pair", b"{\"x\":1}").unwrap();
        let json = serde_json::to_string(&b).unwrap();
        let back: AeadBox = serde_json::from_str(&json).unwrap();
        assert_eq!(back.open(&kek, b"pair").unwrap().expose(), b"{\"x\":1}");
        assert!(!format!("{b:?}").contains(&crate::b64u::encode(&b.ct)));
    }
}
