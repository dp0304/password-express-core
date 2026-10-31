// SPDX-License-Identifier: Apache-2.0
//! Encoding helpers: canonical object bytes and Crockford base32.

use aipass_types::canonical::to_jcs_bytes;
use serde::Serialize;

use crate::error::Result;

/// Bytes of a stored JSON object. All objects AI Pass writes are JCS (RFC 8785) so every
/// implementation produces identical bytes — and therefore identical manifest hashes — for
/// the same object. Readers hash the bytes exactly as fetched.
pub fn object_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    Ok(to_jcs_bytes(value)?)
}

/// Upper-case Crockford base32 alphabet (no I, L, O, U).
pub const CROCKFORD_UPPER: &str = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const CROCKFORD_LOWER: &[u8; 32] = b"0123456789abcdefghjkmnpqrstvwxyz";

fn crockford() -> &'static data_encoding::Encoding {
    static ENC: std::sync::OnceLock<data_encoding::Encoding> = std::sync::OnceLock::new();
    ENC.get_or_init(|| {
        let mut spec = data_encoding::Specification::new();
        spec.symbols.push_str(CROCKFORD_UPPER);
        spec.check_trailing_bits = true;
        // Crockford decoding rules: case-insensitive, O→0, I/L→1.
        spec.translate.from.push_str("abcdefghjkmnpqrstvwxyzoOiIlL");
        spec.translate.to.push_str("ABCDEFGHJKMNPQRSTVWXYZ001111");
        // The specification is a constant; `encoding()` only fails for invalid specs.
        spec.encoding()
            .expect("static Crockford base32 specification is valid")
    })
}

/// Encode bytes as upper-case Crockford base32 without padding (trailing bits are zero).
pub fn crockford_encode(bytes: &[u8]) -> String {
    crockford().encode(bytes)
}

/// Decode Crockford base32 (case-insensitive, O→0, I/L→1). Rejects non-zero trailing bits.
pub fn crockford_decode(text: &str) -> Option<Vec<u8>> {
    crockford().decode(text.as_bytes()).ok()
}

/// Encode a 128-bit value as the 26-character lower-case ULID text used in AI Pass ids.
pub fn ulid_text(value: u128) -> String {
    let mut out = [0u8; 26];
    let mut v = value;
    for i in (0..26).rev() {
        out[i] = CROCKFORD_LOWER[(v & 0x1f) as usize];
        v >>= 5;
    }
    out.iter().map(|b| *b as char).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crockford_roundtrip_and_aliases() {
        let data: Vec<u8> = (0u8..34).collect();
        let s = crockford_encode(&data);
        assert_eq!(s.len(), 55);
        assert!(s.chars().all(|c| CROCKFORD_UPPER.contains(c)));
        assert_eq!(crockford_decode(&s).unwrap(), data);
        assert_eq!(crockford_decode(&s.to_lowercase()).unwrap(), data);
        let aliased = s.replace('0', "O").replace('1', "l");
        assert_eq!(crockford_decode(&aliased).unwrap(), data);
        assert!(crockford_decode("U").is_none());
    }

    #[test]
    fn ulid_text_is_valid_id() {
        let t = ulid_text(u128::MAX);
        assert_eq!(t.len(), 26);
        assert!(aipass_types::ids::DeviceId::parse(&format!("dev_{t}")).is_ok());
        assert_eq!(ulid_text(0), "0".repeat(26));
    }
}
