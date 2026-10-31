// SPDX-License-Identifier: Apache-2.0
//! Zeroizing secret wrappers whose `Debug` / `Display` never reveal contents.
//!
//! * [`SecretBytes`] — variable-length secret bytes (plaintexts, wrapped material).
//! * [`SecretString`] — passwords, API keys, tokens, TOTP seeds.
//! * [`Key32`] — fixed 32-byte symmetric keys (VMK, DEK, KEKs, pairing keys).
//!
//! All three zeroize their memory on drop, compare in constant time and print
//! `[REDACTED]` from `Debug`. `SecretString` and `SecretBytes` implement serde so they can
//! be placed inside payloads that are **about to be encrypted** (e.g. `EntryPayload`,
//! `CredentialMaterial`); never serialize them into logs, API responses or telemetry.

use core::fmt;

use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

const REDACTED: &str = "[REDACTED]";

/// Constant-time equality of two byte strings (length is not secret).
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && bool::from(a.ct_eq(b))
}

// ---------------------------------------------------------------------------------------
// SecretBytes
// ---------------------------------------------------------------------------------------

/// Variable-length secret bytes. Zeroized on drop, redacted in `Debug`.
#[derive(Clone, Default, Zeroize, ZeroizeOnDrop)]
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    /// Wrap bytes (takes ownership; the caller's buffer is moved, not copied).
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Copy from a slice.
    pub fn from_slice(bytes: &[u8]) -> Self {
        Self(bytes.to_vec())
    }

    /// Borrow the secret bytes. Keep the borrow as short as possible.
    pub fn expose(&self) -> &[u8] {
        &self.0
    }

    /// Length in bytes (not secret).
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// True when empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Interpret as UTF-8 and convert into a [`SecretString`] without leaving copies behind.
    pub fn into_secret_string(mut self) -> Result<SecretString, Self> {
        let bytes = core::mem::take(&mut self.0);
        match String::from_utf8(bytes) {
            Ok(s) => Ok(SecretString(s)),
            Err(e) => Err(SecretBytes(e.into_bytes())),
        }
    }

    /// Try to view as a fixed 32-byte key.
    pub fn to_key32(&self) -> Option<Key32> {
        let arr: [u8; 32] = self.0.as_slice().try_into().ok()?;
        Some(Key32::from_bytes(arr))
    }
}

impl From<Vec<u8>> for SecretBytes {
    fn from(v: Vec<u8>) -> Self {
        Self(v)
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED)
    }
}

impl PartialEq for SecretBytes {
    fn eq(&self, other: &Self) -> bool {
        ct_eq(&self.0, &other.0)
    }
}
impl Eq for SecretBytes {}

impl serde::Serialize for SecretBytes {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&crate::b64u::encode(&self.0))
    }
}

impl<'de> serde::Deserialize<'de> for SecretBytes {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let text = zeroize::Zeroizing::new(String::deserialize(d)?);
        crate::b64u::decode(&text)
            .map(SecretBytes)
            .map_err(serde::de::Error::custom)
    }
}

// ---------------------------------------------------------------------------------------
// SecretString
// ---------------------------------------------------------------------------------------

/// A secret UTF-8 string (password, API key, token, TOTP seed). Zeroized on drop,
/// redacted in `Debug` and `Display`.
#[derive(Clone, Default, Zeroize, ZeroizeOnDrop)]
pub struct SecretString(String);

impl SecretString {
    /// Wrap a string (moves it).
    pub fn new(s: String) -> Self {
        Self(s)
    }

    /// Borrow the secret text. Keep the borrow as short as possible.
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// Length in bytes (not secret).
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// True when empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl From<String> for SecretString {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for SecretString {
    fn from(s: &str) -> Self {
        Self(s.to_owned())
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED)
    }
}

impl fmt::Display for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED)
    }
}

impl PartialEq for SecretString {
    fn eq(&self, other: &Self) -> bool {
        ct_eq(self.0.as_bytes(), other.0.as_bytes())
    }
}
impl Eq for SecretString {}

impl serde::Serialize for SecretString {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0)
    }
}

impl<'de> serde::Deserialize<'de> for SecretString {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        String::deserialize(d).map(SecretString)
    }
}

// ---------------------------------------------------------------------------------------
// Key32
// ---------------------------------------------------------------------------------------

/// A 32-byte symmetric key. Zeroized on drop, redacted in `Debug`, no serde (keys are only
/// ever stored wrapped/encrypted; use [`Key32::expose`] + an explicit wrap).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Key32([u8; 32]);

impl Key32 {
    /// Key length in bytes.
    pub const LEN: usize = 32;

    /// Wrap raw key bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Copy from a slice, checking the length.
    pub fn from_slice(bytes: &[u8]) -> crate::Result<Self> {
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| crate::CryptoError::InvalidLength {
                expected: 32,
                actual: bytes.len(),
            })?;
        Ok(Self(arr))
    }

    /// Generate a fresh random key from the OS CSPRNG.
    pub fn generate() -> crate::Result<Self> {
        crate::rng::random_key32()
    }

    /// Borrow the raw key bytes.
    pub fn expose(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for Key32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED)
    }
}

impl PartialEq for Key32 {
    fn eq(&self, other: &Self) -> bool {
        ct_eq(&self.0, &other.0)
    }
}
impl Eq for Key32 {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_is_redacted() {
        let s = SecretString::from("hunter2-very-secret");
        let b = SecretBytes::from_slice(b"\x01\x02secret-bytes");
        let k = Key32::from_bytes([7u8; 32]);
        for out in [
            format!("{s:?}"),
            format!("{s}"),
            format!("{b:?}"),
            format!("{k:?}"),
            format!("{:?}", Some(&s)),
            format!("{:#?}", vec![s.clone()]),
        ] {
            assert!(out.contains("[REDACTED]"), "{out}");
            assert!(!out.contains("hunter2"));
            assert!(!out.contains("secret-bytes"));
            assert!(!out.contains('7'));
        }
    }

    #[test]
    fn equality_and_serde() {
        let a = SecretString::from("abc");
        assert_eq!(a, SecretString::from("abc"));
        assert_ne!(a, SecretString::from("abd"));
        let json = serde_json::to_string(&a).unwrap();
        assert_eq!(json, "\"abc\"");
        let b: SecretBytes = serde_json::from_str("\"AQID\"").unwrap();
        assert_eq!(b.expose(), &[1, 2, 3]);
        assert_eq!(serde_json::to_string(&b).unwrap(), "\"AQID\"");
        assert!(ct_eq(b"x", b"x"));
        assert!(!ct_eq(b"x", b"xy"));
    }

    #[test]
    fn into_secret_string() {
        let b = SecretBytes::from_slice("päss".as_bytes());
        assert_eq!(b.into_secret_string().unwrap().expose(), "päss");
        let bad = SecretBytes::from_slice(&[0xff, 0xfe]);
        assert!(bad.into_secret_string().is_err());
    }
}
