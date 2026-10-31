// SPDX-License-Identifier: Apache-2.0
//! HKDF-SHA256 (RFC 5869) helpers.
//!
//! Info strings are namespaced `aipass/v1/<purpose>`; see [`crate::info`].

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::error::{CryptoError, Result};
use crate::secret::{Key32, SecretBytes};

/// Maximum HKDF-SHA256 output length (255 × 32).
pub const MAX_OUTPUT_LEN: usize = 255 * 32;

/// HKDF-Extract(salt, ikm) → PRK (32 bytes). An empty salt means "HashLen zeros" per RFC 5869.
pub fn extract(salt: &[u8], ikm: &[u8]) -> Key32 {
    let (prk, _) = Hkdf::<Sha256>::extract(Some(salt), ikm);
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&prk);
    Key32::from_bytes(*out)
}

/// HKDF-Expand(prk, info, len).
pub fn expand(prk: &[u8], info: &[u8], len: usize) -> Result<SecretBytes> {
    if len == 0 || len > MAX_OUTPUT_LEN {
        return Err(CryptoError::Kdf);
    }
    let hk = Hkdf::<Sha256>::from_prk(prk).map_err(|_| CryptoError::Kdf)?;
    let mut okm = vec![0u8; len];
    hk.expand(info, &mut okm).map_err(|_| CryptoError::Kdf)?;
    Ok(SecretBytes::new(okm))
}

/// Full HKDF-SHA256(salt, ikm, info) with `len` output bytes.
pub fn hkdf_sha256(salt: &[u8], ikm: &[u8], info: &[u8], len: usize) -> Result<SecretBytes> {
    if len == 0 || len > MAX_OUTPUT_LEN {
        return Err(CryptoError::Kdf);
    }
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut okm = vec![0u8; len];
    hk.expand(info, &mut okm).map_err(|_| CryptoError::Kdf)?;
    Ok(SecretBytes::new(okm))
}

/// HKDF-SHA256 producing a 32-byte key (the common case: KEKs, pairing key).
pub fn derive_key32(salt: &[u8], ikm: &[u8], info: &[u8]) -> Key32 {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut okm = Zeroizing::new([0u8; 32]);
    // 32 ≤ 255·HashLen, so expand cannot fail.
    if hk.expand(info, okm.as_mut()).is_err() {
        unreachable!("32-byte HKDF-SHA256 output is always valid");
    }
    Key32::from_bytes(*okm)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_bad_lengths() {
        assert!(hkdf_sha256(b"s", b"k", b"i", 0).is_err());
        assert!(hkdf_sha256(b"s", b"k", b"i", MAX_OUTPUT_LEN + 1).is_err());
        assert!(expand(&[0u8; 8], b"", 32).is_err()); // PRK shorter than HashLen
        assert_eq!(
            hkdf_sha256(b"s", b"k", b"i", MAX_OUTPUT_LEN).unwrap().len(),
            MAX_OUTPUT_LEN
        );
    }

    #[test]
    fn derive_key32_matches_generic() {
        let a = derive_key32(b"salt", b"ikm", b"aipass/v1/test");
        let b = hkdf_sha256(b"salt", b"ikm", b"aipass/v1/test", 32).unwrap();
        assert_eq!(a.expose().as_slice(), b.expose());
        let prk = extract(b"salt", b"ikm");
        assert_eq!(expand(prk.expose(), b"aipass/v1/test", 32).unwrap(), b);
    }
}
