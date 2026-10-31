// SPDX-License-Identifier: Apache-2.0
//! Argon2id password key derivation (CONTRACTS §2.1: m=65536 KiB, t=3, p=1, 16-byte salt,
//! 32-byte output).
//!
//! Only the optional vault **master password** and encrypted exports use this. Subscription
//! passwords, email logins and passkey IDs never derive vault keys (design doc §9.4).

use argon2::{Algorithm, Argon2, Params, Version};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::{CryptoError, Result};
use crate::secret::Key32;

/// Salt length used by AI Pass (16 bytes).
pub const SALT_LEN: usize = 16;

/// Argon2id cost parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Argon2Params {
    /// Memory cost in KiB.
    pub m: u32,
    /// Iterations.
    pub t: u32,
    /// Parallelism (lanes).
    pub p: u32,
}

impl Argon2Params {
    /// The binding contract parameters for all persisted data: m = 64 MiB, t = 3, p = 1.
    pub const CONTRACT_V1: Argon2Params = Argon2Params {
        m: 65_536,
        t: 3,
        p: 1,
    };

    /// **Tests only.** Cheap parameters so test suites run fast. Never use for real data;
    /// [`Argon2Params::is_production_strength`] returns `false` for these.
    pub const INSECURE_FAST_FOR_TESTS_ONLY: Argon2Params = Argon2Params { m: 256, t: 1, p: 1 };

    /// Upper bounds accepted when *reading* parameters from untrusted files, so a malicious
    /// file cannot make a client allocate unbounded memory (4 GiB / 64 iterations / 16 lanes).
    pub const MAX_ACCEPTED: Argon2Params = Argon2Params {
        m: 4 * 1024 * 1024,
        t: 64,
        p: 16,
    };

    /// True when every cost is at least the contract parameters.
    pub fn is_production_strength(&self) -> bool {
        self.m >= Self::CONTRACT_V1.m
            && self.t >= Self::CONTRACT_V1.t
            && self.p >= Self::CONTRACT_V1.p
    }

    /// True when the parameters are within [`Argon2Params::MAX_ACCEPTED`].
    pub fn is_within_limits(&self) -> bool {
        self.m <= Self::MAX_ACCEPTED.m
            && self.t <= Self::MAX_ACCEPTED.t
            && self.p <= Self::MAX_ACCEPTED.p
    }
}

/// Serialized KDF descriptor `{alg:"argon2id", m, t, p, salt}` used by encrypted exports
/// (CONTRACTS §2.5) and master-password recovery wraps.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Argon2idDescriptor {
    /// Always `"argon2id"`.
    pub alg: Argon2Alg,
    /// Memory cost (KiB).
    pub m: u32,
    /// Iterations.
    pub t: u32,
    /// Parallelism.
    pub p: u32,
    /// 16-byte random salt, b64u.
    #[serde(with = "crate::b64u::bytes")]
    pub salt: Vec<u8>,
}

/// Marker enum serializing as the string `"argon2id"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Argon2Alg {
    /// Argon2id v1.3.
    #[serde(rename = "argon2id")]
    Argon2id,
}

impl Argon2idDescriptor {
    /// New descriptor with a fresh random salt.
    pub fn generate(params: Argon2Params) -> Result<Self> {
        let salt = crate::rng::try_random_array::<SALT_LEN>()?;
        Ok(Self {
            alg: Argon2Alg::Argon2id,
            m: params.m,
            t: params.t,
            p: params.p,
            salt: salt.to_vec(),
        })
    }

    /// Cost parameters of this descriptor.
    pub fn params(&self) -> Argon2Params {
        Argon2Params {
            m: self.m,
            t: self.t,
            p: self.p,
        }
    }

    /// Derive the 32-byte key for `password`. Rejects parameters outside
    /// [`Argon2Params::MAX_ACCEPTED`] and salts shorter than 16 bytes.
    pub fn derive(&self, password: &[u8]) -> Result<Key32> {
        if self.salt.len() < SALT_LEN {
            return Err(CryptoError::PasswordKdf("salt too short"));
        }
        argon2id(password, &self.salt, self.params())
    }
}

/// Argon2id(password, salt) → 32-byte key with the given parameters.
pub fn argon2id(password: &[u8], salt: &[u8], params: Argon2Params) -> Result<Key32> {
    argon2id_with_secret(password, salt, params, None, &[])
}

/// Full Argon2id with optional secret value `K` and associated data `X` (RFC 9106 §3.1).
/// AI Pass formats use neither; this exists for completeness and the RFC 9106 KAT.
pub fn argon2id_with_secret(
    password: &[u8],
    salt: &[u8],
    params: Argon2Params,
    secret: Option<&[u8]>,
    associated_data: &[u8],
) -> Result<Key32> {
    if !params.is_within_limits() {
        return Err(CryptoError::PasswordKdf(
            "parameters exceed accepted limits",
        ));
    }
    let mut builder = argon2::ParamsBuilder::new();
    builder
        .m_cost(params.m)
        .t_cost(params.t)
        .p_cost(params.p)
        .output_len(32);
    if !associated_data.is_empty() {
        let ad = argon2::AssociatedData::new(associated_data)
            .map_err(|_| CryptoError::PasswordKdf("associated data too long"))?;
        builder.data(ad);
    }
    let p: Params = builder
        .build()
        .map_err(|_| CryptoError::PasswordKdf("invalid parameters"))?;
    let ctx = match secret {
        Some(k) => Argon2::new_with_secret(k, Algorithm::Argon2id, Version::V0x13, p)
            .map_err(|_| CryptoError::PasswordKdf("secret too long"))?,
        None => Argon2::new(Algorithm::Argon2id, Version::V0x13, p),
    };
    let mut out = Zeroizing::new([0u8; 32]);
    ctx.hash_password_into(password, salt, out.as_mut())
        .map_err(|_| CryptoError::PasswordKdf("argon2 rejected input"))?;
    Ok(Key32::from_bytes(*out))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_and_salted() {
        let p = Argon2Params::INSECURE_FAST_FOR_TESTS_ONLY;
        assert!(!p.is_production_strength());
        assert!(Argon2Params::CONTRACT_V1.is_production_strength());
        let a = argon2id(b"correct horse", &[1u8; 16], p).unwrap();
        let b = argon2id(b"correct horse", &[1u8; 16], p).unwrap();
        let c = argon2id(b"correct horse", &[2u8; 16], p).unwrap();
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn descriptor_roundtrip() {
        let d = Argon2idDescriptor::generate(Argon2Params::INSECURE_FAST_FOR_TESTS_ONLY).unwrap();
        let json = serde_json::to_value(&d).unwrap();
        assert_eq!(json["alg"], "argon2id");
        assert_eq!(json["m"], 256);
        let back: Argon2idDescriptor = serde_json::from_value(json).unwrap();
        assert_eq!(back.derive(b"pw").unwrap(), d.derive(b"pw").unwrap());
        let short = Argon2idDescriptor {
            salt: vec![0; 8],
            ..d.clone()
        };
        assert!(short.derive(b"pw").is_err());
        let huge = Argon2idDescriptor { m: u32::MAX, ..d };
        assert!(huge.derive(b"pw").is_err());
    }
}
