// SPDX-License-Identifier: Apache-2.0
//! SHA-256 and HMAC-SHA256 helpers (CONTRACTS §1.2: "Hash = SHA-256").

use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};

/// SHA-256 of `data`.
pub fn sha256(data: impl AsRef<[u8]>) -> [u8; 32] {
    Sha256::digest(data.as_ref()).into()
}

/// SHA-256 over the concatenation of several parts (no separators — callers must use
/// unambiguous encodings).
pub fn sha256_concat(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// b64u(SHA-256(data)) — the hash form used throughout the wire formats.
pub fn sha256_b64u(data: impl AsRef<[u8]>) -> String {
    crate::b64u::encode(sha256(data))
}

/// HMAC-SHA256(key, msg).
pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    // HMAC accepts keys of any length; `new_from_slice` cannot fail for Hmac<Sha256>.
    let mut mac = match <Hmac<Sha256> as KeyInit>::new_from_slice(key) {
        Ok(m) => m,
        Err(_) => unreachable!("HMAC-SHA256 accepts any key length"),
    };
    mac.update(msg);
    mac.finalize().into_bytes().into()
}

/// Verify an HMAC-SHA256 tag in constant time.
pub fn hmac_sha256_verify(key: &[u8], msg: &[u8], tag: &[u8]) -> bool {
    crate::secret::ct_eq(&hmac_sha256(key, msg), tag)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_known_answers() {
        assert_eq!(
            hex::encode(sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex::encode(sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            sha256_b64u(b""),
            "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU"
        );
        assert_eq!(sha256_concat(&[b"a", b"bc"]), sha256(b"abc"));
    }

    #[test]
    fn hmac_rfc4231_case_2() {
        // RFC 4231 test case 2
        let tag = hmac_sha256(b"Jefe", b"what do ya want for nothing?");
        assert_eq!(
            hex::encode(tag),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
        assert!(hmac_sha256_verify(
            b"Jefe",
            b"what do ya want for nothing?",
            &tag
        ));
        assert!(!hmac_sha256_verify(
            b"Jefe",
            b"what do ya want for nothing!",
            &tag
        ));
    }
}
