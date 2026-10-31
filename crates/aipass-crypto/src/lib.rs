// SPDX-License-Identifier: Apache-2.0
//! # aipass-crypto — cryptographic primitives for AI Pass
//!
//! A thin, opinionated layer over mature, widely used libraries (CONTRACTS §2.1, design doc
//! §9.4 — *no home-made algorithms*):
//!
//! | need | module | library |
//! | --- | --- | --- |
//! | AEAD | [`aead`] — XChaCha20-Poly1305, 24-byte random nonce, mandatory AAD | `chacha20poly1305` |
//! | sealing to a public key | [`hpke`] — RFC 9180 base mode, X25519 / HKDF-SHA256 / ChaCha20-Poly1305, [`hpke::SealedBox`] | `hpke` |
//! | signatures | [`identity`] — Ed25519 (strict verification) | `ed25519-dalek` |
//! | key agreement / KEM keys | [`identity::KemKeypair`] — X25519 | `x25519-dalek` |
//! | device identity | [`identity::DeviceIdentity`] = Ed25519 + X25519 | |
//! | KDF | [`kdf`] — HKDF-SHA256 | `hkdf` |
//! | password KDF | [`password`] — Argon2id m=64 MiB t=3 p=1 | `argon2` |
//! | hashing | [`hash`] — SHA-256, HMAC-SHA256 | `sha2`, `hmac` |
//! | randomness | [`rng`] — OS CSPRNG only | `getrandom` |
//! | encoding | [`b64u`] — base64url without padding | `base64` |
//! | secrets in memory | [`secret`] — [`SecretBytes`], [`SecretString`], [`Key32`] | `zeroize`, `subtle` |
//!
//! Security properties every caller can rely on:
//! * secret types zeroize on drop and print `[REDACTED]` from `Debug`;
//! * [`CryptoError`] never contains key material or plaintext;
//! * all randomness comes from the operating-system CSPRNG.
//!
//! Status: not yet independently audited.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod aead;
pub mod b64u;
pub mod error;
pub mod hash;
pub mod hpke;
pub mod identity;
pub mod kdf;
pub mod password;
pub mod rng;
pub mod secret;

pub use aead::AeadBox;
pub use error::{CryptoError, Result};
pub use hash::{sha256, sha256_b64u};
pub use hpke::SealedBox;
pub use identity::{DeviceIdentity, Ed25519Keypair, Ed25519Signer, IdentityPublic, KemKeypair};
pub use password::{Argon2Params, Argon2idDescriptor};
pub use secret::{Key32, SecretBytes, SecretString, ct_eq};

/// Namespaced HPKE `info` / HKDF `info` strings (CONTRACTS §2.2, §4, §5, §6.1).
pub mod info {
    /// HPKE: VMK sealed to a member device.
    pub const VMK_WRAP: &[u8] = b"aipass/v1/vmk-wrap";
    /// HPKE: credential envelope sealed to an executor.
    pub const CREDENTIAL: &[u8] = b"aipass/v1/credential";
    /// HPKE: relay envelope sealed to the recipient device/executor.
    pub const RELAY: &[u8] = b"aipass/v1/relay";
    /// HKDF: recovery-key KEK (`salt = vault_id bytes`).
    pub const RECOVERY_KEK: &[u8] = b"aipass/v1/recovery-kek";
    /// HKDF: pairing channel key K.
    pub const PAIRING_KEY: &[u8] = b"aipass/v1/pairing-key";
    /// HKDF: pairing short authentication string.
    pub const PAIRING_SAS: &[u8] = b"aipass/v1/pairing-sas";
}
