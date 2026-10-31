// SPDX-License-Identifier: Apache-2.0
//! Error type for all cryptographic operations.
//!
//! Error values never carry key material, plaintext, nonces of secret data or any other
//! secret — only the *kind* of failure and, where useful, public lengths.

use thiserror::Error;

/// Errors returned by `aipass-crypto`.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum CryptoError {
    /// Input had the wrong length (lengths are public information).
    #[error("invalid length: expected {expected} bytes, got {actual}")]
    InvalidLength {
        /// Expected length in bytes.
        expected: usize,
        /// Actual length in bytes.
        actual: usize,
    },
    /// Input was not valid base64url (no padding).
    #[error("invalid base64url encoding")]
    InvalidEncoding,
    /// A public or secret key was malformed or weak.
    #[error("invalid key")]
    InvalidKey,
    /// AEAD authentication failed (wrong key, nonce, AAD or tampered ciphertext).
    #[error("authenticated decryption failed")]
    Decrypt,
    /// AEAD encryption failed (input too large).
    #[error("encryption failed")]
    Encrypt,
    /// An Ed25519 signature failed to verify or was malformed.
    #[error("signature verification failed")]
    BadSignature,
    /// HPKE setup, seal or open failed.
    #[error("HPKE operation failed")]
    Hpke,
    /// HKDF was asked for an invalid output length or given an invalid PRK.
    #[error("key derivation failed")]
    Kdf,
    /// Argon2id parameters or inputs were rejected.
    #[error("password key derivation failed: {0}")]
    PasswordKdf(&'static str),
    /// The operating-system CSPRNG failed.
    #[error("operating system random number generator failed")]
    Rng,
}

/// Convenience result alias.
pub type Result<T> = core::result::Result<T, CryptoError>;
