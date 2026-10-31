// SPDX-License-Identifier: Apache-2.0
//! base64url **without padding** ("b64u", CONTRACTS §1.2).
//!
//! Decoding is strict: padding characters, the standard (`+/`) alphabet and non-canonical
//! trailing bits are all rejected, so every byte string has exactly one textual form.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use crate::error::{CryptoError, Result};

/// Encode bytes as base64url without padding.
pub fn encode(bytes: impl AsRef<[u8]>) -> String {
    URL_SAFE_NO_PAD.encode(bytes.as_ref())
}

/// Decode base64url without padding.
pub fn decode(text: &str) -> Result<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(text.as_bytes())
        .map_err(|_| CryptoError::InvalidEncoding)
}

/// Decode base64url into a fixed-size array, checking the length.
pub fn decode_array<const N: usize>(text: &str) -> Result<[u8; N]> {
    let bytes = decode(text)?;
    let actual = bytes.len();
    bytes.try_into().map_err(|_| CryptoError::InvalidLength {
        expected: N,
        actual,
    })
}

/// serde helper: `Vec<u8>` <-> b64u string. Use with `#[serde(with = "aipass_crypto::b64u::bytes")]`.
pub mod bytes {
    use serde::{Deserialize, Deserializer, Serializer, de::Error as _};

    /// Serialize bytes as b64u.
    pub fn serialize<S: Serializer>(value: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&super::encode(value))
    }

    /// Deserialize bytes from b64u.
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let text = String::deserialize(d)?;
        super::decode(&text).map_err(D::Error::custom)
    }
}

/// serde helper: `[u8; N]` <-> b64u string. Use with `#[serde(with = "aipass_crypto::b64u::array")]`.
pub mod array {
    use serde::{Deserialize, Deserializer, Serializer, de::Error as _};

    /// Serialize a byte array as b64u.
    pub fn serialize<S: Serializer, const N: usize>(
        value: &[u8; N],
        s: S,
    ) -> Result<S::Ok, S::Error> {
        s.serialize_str(&super::encode(value))
    }

    /// Deserialize a byte array from b64u, checking its length.
    pub fn deserialize<'de, D: Deserializer<'de>, const N: usize>(
        d: D,
    ) -> Result<[u8; N], D::Error> {
        let text = String::deserialize(d)?;
        super::decode_array::<N>(&text).map_err(D::Error::custom)
    }
}

/// serde helper: `Option<Vec<u8>>` <-> b64u string or `null`.
pub mod option_bytes {
    use serde::{Deserialize, Deserializer, Serializer, de::Error as _};

    /// Serialize optional bytes as b64u or null.
    pub fn serialize<S: Serializer>(value: &Option<Vec<u8>>, s: S) -> Result<S::Ok, S::Error> {
        match value {
            Some(v) => s.serialize_str(&super::encode(v)),
            None => s.serialize_none(),
        }
    }

    /// Deserialize optional bytes from b64u or null.
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Vec<u8>>, D::Error> {
        let text = Option::<String>::deserialize(d)?;
        text.map(|t| super::decode(&t).map_err(D::Error::custom))
            .transpose()
    }
}

/// serde helper: `Option<[u8; N]>` <-> b64u string or `null`.
pub mod option_array {
    use serde::{Deserialize, Deserializer, Serializer, de::Error as _};

    /// Serialize an optional byte array as b64u or null.
    pub fn serialize<S: Serializer, const N: usize>(
        value: &Option<[u8; N]>,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        match value {
            Some(v) => s.serialize_str(&super::encode(v)),
            None => s.serialize_none(),
        }
    }

    /// Deserialize an optional byte array from b64u or null.
    pub fn deserialize<'de, D: Deserializer<'de>, const N: usize>(
        d: D,
    ) -> Result<Option<[u8; N]>, D::Error> {
        let text = Option::<String>::deserialize(d)?;
        text.map(|t| super::decode_array::<N>(&t).map_err(D::Error::custom))
            .transpose()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_strictness() {
        let data = [0xfbu8, 0xff, 0x00, 0x10];
        let text = encode(data);
        assert_eq!(text, "-_8AEA");
        assert_eq!(decode(&text).unwrap(), data);
        // padding rejected
        assert!(decode("-_8AEA==").is_err());
        // standard alphabet rejected
        assert!(decode("+/8AEA").is_err());
        // non-canonical trailing bits rejected ("AB" would decode 0x00 with leftover bits)
        assert!(decode("AB").is_err());
        assert_eq!(decode("").unwrap(), Vec::<u8>::new());
        assert_eq!(decode_array::<4>(&text).unwrap(), [0xfb, 0xff, 0x00, 0x10]);
        assert_eq!(
            decode_array::<3>(&text),
            Err(CryptoError::InvalidLength {
                expected: 3,
                actual: 4
            })
        );
    }
}
