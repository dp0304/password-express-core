// SPDX-License-Identifier: Apache-2.0
//! Operating-system CSPRNG helpers (CONTRACTS §2.1: "OS CSPRNG only").
//!
//! Every random value in AI Pass — keys, nonces, salts, request nonces, tokens, IDs,
//! generated passwords — comes from [`getrandom`] (the OS CSPRNG) through this module.
//! There is deliberately no seedable or user-space PRNG here.

use rand_core::UnwrapErr;
use zeroize::Zeroizing;

use crate::error::{CryptoError, Result};
use crate::secret::{Key32, SecretBytes};

/// Fill `dest` from the OS CSPRNG.
pub fn fill_random(dest: &mut [u8]) -> Result<()> {
    getrandom::fill(dest).map_err(|_| CryptoError::Rng)
}

/// Return `N` bytes from the OS CSPRNG.
///
/// # Panics
/// Panics if the operating system RNG fails. This mirrors the behaviour of every mainstream
/// CSPRNG interface: continuing without entropy would be unsafe. Use [`try_random_array`]
/// where a recoverable error is preferred.
pub fn random_array<const N: usize>() -> [u8; N] {
    match try_random_array::<N>() {
        Ok(bytes) => bytes,
        Err(_) => panic!("operating system CSPRNG unavailable"),
    }
}

/// Return `N` bytes from the OS CSPRNG, or an error if the OS RNG fails.
pub fn try_random_array<const N: usize>() -> Result<[u8; N]> {
    let mut out = [0u8; N];
    fill_random(&mut out)?;
    Ok(out)
}

/// Return `len` random bytes as a zeroizing [`SecretBytes`].
pub fn random_secret(len: usize) -> Result<SecretBytes> {
    let mut buf = Zeroizing::new(vec![0u8; len]);
    fill_random(&mut buf)?;
    Ok(SecretBytes::new(buf.to_vec()))
}

/// Return a fresh random 32-byte key (VMK, DEK, recovery secret, …).
pub fn random_key32() -> Result<Key32> {
    let mut bytes = Zeroizing::new([0u8; 32]);
    fill_random(bytes.as_mut())?;
    Ok(Key32::from_bytes(*bytes))
}

/// Uniform random integer in `0..bound` using rejection sampling (no modulo bias).
///
/// Returns an error if `bound == 0` or the OS RNG fails.
pub fn random_below(bound: u32) -> Result<u32> {
    if bound == 0 {
        return Err(CryptoError::InvalidLength {
            expected: 1,
            actual: 0,
        });
    }
    // Largest multiple of `bound` that fits in u32 range [0, 2^32).
    let zone = u32::MAX - (u32::MAX % bound);
    loop {
        let mut b = [0u8; 4];
        fill_random(&mut b)?;
        let v = u32::from_le_bytes(b);
        if v < zone {
            return Ok(v % bound);
        }
    }
}

/// Random token: `prefix` followed by b64u of `n_bytes` random bytes
/// (e.g. `random_token("aipc_", 32)` for node-issued connection tokens).
pub fn random_token(prefix: &str, n_bytes: usize) -> Result<crate::secret::SecretString> {
    let bytes = random_secret(n_bytes)?;
    let mut s = String::with_capacity(prefix.len() + n_bytes.div_ceil(3) * 4);
    s.push_str(prefix);
    s.push_str(&crate::b64u::encode(bytes.expose()));
    Ok(crate::secret::SecretString::new(s))
}

/// A [`rand_core::CryptoRng`] backed by the OS CSPRNG, for APIs (dalek, hpke) that take an RNG.
///
/// Panics if the OS RNG fails (see [`random_array`]).
pub fn os_rng() -> UnwrapErr<getrandom::SysRng> {
    UnwrapErr(getrandom::SysRng)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_values_differ_and_have_length() {
        let a: [u8; 32] = random_array();
        let b: [u8; 32] = random_array();
        assert_ne!(a, b);
        assert_eq!(random_secret(17).unwrap().len(), 17);
    }

    #[test]
    fn random_below_is_in_range_and_covers() {
        let mut seen = [false; 7];
        for _ in 0..2000 {
            let v = random_below(7).unwrap();
            assert!(v < 7);
            seen[v as usize] = true;
        }
        assert!(seen.iter().all(|s| *s));
        assert!(random_below(0).is_err());
        assert_eq!(random_below(1).unwrap(), 0);
    }

    #[test]
    fn token_format() {
        let t = random_token("aipc_", 32).unwrap();
        assert!(t.expose().starts_with("aipc_"));
        assert_eq!(t.expose().len(), 5 + 43);
    }
}
