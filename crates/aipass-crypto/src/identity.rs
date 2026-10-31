// SPDX-License-Identifier: Apache-2.0
//! Ed25519 signing keys, X25519 KEM keys and the combined [`DeviceIdentity`]
//! (CONTRACTS §2.1: "Device identity = Ed25519 signing keypair + X25519 KEM keypair").
//!
//! Verification uses `verify_strict` (rejects small-order keys and malleable signatures).

use core::fmt;

use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey as XPublic, StaticSecret};
use zeroize::Zeroizing;

use crate::error::{CryptoError, Result};
use crate::secret::{Key32, SecretBytes};

/// Ed25519 / X25519 public key length.
pub const PUBLIC_KEY_LEN: usize = 32;
/// Ed25519 signature length.
pub const SIGNATURE_LEN: usize = 64;

/// Anything that can produce Ed25519 signatures (request signing, approvals, manifests…).
pub trait Ed25519Signer {
    /// The 32-byte Ed25519 public key.
    fn public_key(&self) -> [u8; PUBLIC_KEY_LEN];
    /// Sign `msg` (pure Ed25519, RFC 8032).
    fn sign(&self, msg: &[u8]) -> [u8; SIGNATURE_LEN];
}

// ---------------------------------------------------------------------------------------
// Ed25519
// ---------------------------------------------------------------------------------------

/// An Ed25519 signing keypair (connection keys, executor/node keys, device signing keys).
#[derive(Clone)]
pub struct Ed25519Keypair {
    sk: SigningKey,
}

impl Ed25519Keypair {
    /// Generate from the OS CSPRNG.
    pub fn generate() -> Self {
        Self {
            sk: SigningKey::generate(&mut crate::rng::os_rng()),
        }
    }

    /// Construct from the 32-byte RFC 8032 private seed.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self {
            sk: SigningKey::from_bytes(seed),
        }
    }

    /// Construct from a seed slice (must be 32 bytes).
    pub fn from_seed_slice(seed: &[u8]) -> Result<Self> {
        let arr: Zeroizing<[u8; 32]> =
            Zeroizing::new(seed.try_into().map_err(|_| CryptoError::InvalidLength {
                expected: 32,
                actual: seed.len(),
            })?);
        Ok(Self::from_seed(&arr))
    }

    /// Copy of the private seed (zeroizing). Store it only in a platform secret store.
    pub fn seed(&self) -> Key32 {
        Key32::from_bytes(self.sk.to_bytes())
    }

    /// The public key bytes.
    pub fn public_key(&self) -> [u8; PUBLIC_KEY_LEN] {
        self.sk.verifying_key().to_bytes()
    }

    /// The public key as b64u.
    pub fn public_key_b64u(&self) -> String {
        crate::b64u::encode(self.public_key())
    }

    /// Sign a message.
    pub fn sign(&self, msg: &[u8]) -> [u8; SIGNATURE_LEN] {
        self.sk.sign(msg).to_bytes()
    }

    /// Sign a message and return the b64u signature.
    pub fn sign_b64u(&self, msg: &[u8]) -> String {
        crate::b64u::encode(self.sign(msg))
    }
}

impl Ed25519Signer for Ed25519Keypair {
    fn public_key(&self) -> [u8; PUBLIC_KEY_LEN] {
        Ed25519Keypair::public_key(self)
    }
    fn sign(&self, msg: &[u8]) -> [u8; SIGNATURE_LEN] {
        Ed25519Keypair::sign(self, msg)
    }
}

impl fmt::Debug for Ed25519Keypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ed25519Keypair")
            .field("public_key", &self.public_key_b64u())
            .field("secret", &"[REDACTED]")
            .finish()
    }
}

/// Verify an Ed25519 signature with strict (non-malleable) rules.
pub fn verify(
    public_key: &[u8; PUBLIC_KEY_LEN],
    msg: &[u8],
    signature: &[u8; SIGNATURE_LEN],
) -> Result<()> {
    let vk = VerifyingKey::from_bytes(public_key).map_err(|_| CryptoError::InvalidKey)?;
    if vk.is_weak() {
        return Err(CryptoError::InvalidKey);
    }
    let sig = Signature::from_bytes(signature);
    vk.verify_strict(msg, &sig)
        .map_err(|_| CryptoError::BadSignature)
}

/// Verify with b64u-encoded public key and signature.
pub fn verify_b64u(public_key_b64u: &str, msg: &[u8], signature_b64u: &str) -> Result<()> {
    let pk = crate::b64u::decode_array::<PUBLIC_KEY_LEN>(public_key_b64u)
        .map_err(|_| CryptoError::InvalidKey)?;
    let sig = crate::b64u::decode_array::<SIGNATURE_LEN>(signature_b64u)
        .map_err(|_| CryptoError::BadSignature)?;
    verify(&pk, msg, &sig)
}

/// Check that `public_key` is a valid, non-weak Ed25519 point.
pub fn validate_ed25519_public_key(public_key: &[u8; PUBLIC_KEY_LEN]) -> Result<()> {
    let vk = VerifyingKey::from_bytes(public_key).map_err(|_| CryptoError::InvalidKey)?;
    if vk.is_weak() {
        Err(CryptoError::InvalidKey)
    } else {
        Ok(())
    }
}

// ---------------------------------------------------------------------------------------
// X25519 (KEM keys and pairing ephemerals)
// ---------------------------------------------------------------------------------------

/// An X25519 keypair: device KEM key (HPKE recipient) or a pairing ephemeral key.
#[derive(Clone)]
pub struct KemKeypair {
    sk: StaticSecret,
    pk: [u8; PUBLIC_KEY_LEN],
}

impl KemKeypair {
    /// Generate from the OS CSPRNG.
    pub fn generate() -> Self {
        let sk = StaticSecret::random_from_rng(&mut crate::rng::os_rng());
        let pk = XPublic::from(&sk).to_bytes();
        Self { sk, pk }
    }

    /// Construct from 32 secret bytes (RFC 7748 scalar; clamping happens at use).
    pub fn from_secret_bytes(secret: &[u8; 32]) -> Self {
        let sk = StaticSecret::from(*secret);
        let pk = XPublic::from(&sk).to_bytes();
        Self { sk, pk }
    }

    /// Copy of the secret bytes (zeroizing).
    pub fn secret_bytes(&self) -> Key32 {
        Key32::from_bytes(self.sk.to_bytes())
    }

    /// The public key bytes.
    pub fn public_key(&self) -> [u8; PUBLIC_KEY_LEN] {
        self.pk
    }

    /// The public key as b64u.
    pub fn public_key_b64u(&self) -> String {
        crate::b64u::encode(self.pk)
    }

    /// X25519 Diffie–Hellman. Rejects low-order peer keys (all-zero shared secret).
    pub fn diffie_hellman(&self, peer_public: &[u8; PUBLIC_KEY_LEN]) -> Result<Key32> {
        let shared = self.sk.diffie_hellman(&XPublic::from(*peer_public));
        if !shared.was_contributory() {
            return Err(CryptoError::InvalidKey);
        }
        Ok(Key32::from_bytes(shared.to_bytes()))
    }

    /// Open an HPKE [`crate::hpke::SealedBox`] addressed to this key.
    pub fn open(
        &self,
        info: &[u8],
        aad: &[u8],
        sealed: &crate::hpke::SealedBox,
    ) -> Result<SecretBytes> {
        crate::hpke::open(self, info, aad, sealed)
    }
}

impl fmt::Debug for KemKeypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KemKeypair")
            .field("public_key", &self.public_key_b64u())
            .field("secret", &"[REDACTED]")
            .finish()
    }
}

// ---------------------------------------------------------------------------------------
// DeviceIdentity
// ---------------------------------------------------------------------------------------

/// Public half of a device identity: `{sign_pk, kem_pk}` (both b64u in JSON).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct IdentityPublic {
    /// Ed25519 public key.
    #[serde(with = "crate::b64u::array")]
    pub sign_pk: [u8; PUBLIC_KEY_LEN],
    /// X25519 KEM public key (HPKE recipient key).
    #[serde(with = "crate::b64u::array")]
    pub kem_pk: [u8; PUBLIC_KEY_LEN],
}

impl IdentityPublic {
    /// Verify a signature made by this identity.
    pub fn verify(&self, msg: &[u8], signature: &[u8; SIGNATURE_LEN]) -> Result<()> {
        verify(&self.sign_pk, msg, signature)
    }

    /// `sign_pk` as b64u.
    pub fn sign_pk_b64u(&self) -> String {
        crate::b64u::encode(self.sign_pk)
    }

    /// `kem_pk` as b64u.
    pub fn kem_pk_b64u(&self) -> String {
        crate::b64u::encode(self.kem_pk)
    }
}

/// Length of [`DeviceIdentity::to_secret_bytes`] output: Ed25519 seed ‖ X25519 secret.
pub const DEVICE_SECRET_LEN: usize = 64;

/// A device's long-term identity: Ed25519 signing keypair + X25519 KEM keypair.
#[derive(Clone)]
pub struct DeviceIdentity {
    signing: Ed25519Keypair,
    kem: KemKeypair,
}

impl DeviceIdentity {
    /// Generate a fresh identity from the OS CSPRNG.
    pub fn generate() -> Self {
        Self {
            signing: Ed25519Keypair::generate(),
            kem: KemKeypair::generate(),
        }
    }

    /// Reconstruct from the two 32-byte secrets.
    pub fn from_parts(sign_seed: &[u8; 32], kem_secret: &[u8; 32]) -> Self {
        Self {
            signing: Ed25519Keypair::from_seed(sign_seed),
            kem: KemKeypair::from_secret_bytes(kem_secret),
        }
    }

    /// Reconstruct from the 64-byte export produced by [`DeviceIdentity::to_secret_bytes`].
    pub fn from_secret_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != DEVICE_SECRET_LEN {
            return Err(CryptoError::InvalidLength {
                expected: DEVICE_SECRET_LEN,
                actual: bytes.len(),
            });
        }
        let mut seed = Zeroizing::new([0u8; 32]);
        let mut kem = Zeroizing::new([0u8; 32]);
        seed.copy_from_slice(&bytes[..32]);
        kem.copy_from_slice(&bytes[32..]);
        Ok(Self::from_parts(&seed, &kem))
    }

    /// Export both secrets (`seed ‖ kem_secret`, 64 bytes, zeroizing) for the platform
    /// secret store (Keychain / Keystore / OS keyring). Never log or upload this.
    pub fn to_secret_bytes(&self) -> SecretBytes {
        let mut out = Vec::with_capacity(DEVICE_SECRET_LEN);
        out.extend_from_slice(self.signing.seed().expose());
        out.extend_from_slice(self.kem.secret_bytes().expose());
        SecretBytes::new(out)
    }

    /// Public half.
    pub fn public(&self) -> IdentityPublic {
        IdentityPublic {
            sign_pk: self.signing.public_key(),
            kem_pk: self.kem.public_key(),
        }
    }

    /// Sign a message with the device signing key.
    pub fn sign(&self, msg: &[u8]) -> [u8; SIGNATURE_LEN] {
        self.signing.sign(msg)
    }

    /// Sign and return b64u.
    pub fn sign_b64u(&self, msg: &[u8]) -> String {
        self.signing.sign_b64u(msg)
    }

    /// The signing keypair.
    pub fn signing_keypair(&self) -> &Ed25519Keypair {
        &self.signing
    }

    /// The KEM keypair.
    pub fn kem_keypair(&self) -> &KemKeypair {
        &self.kem
    }

    /// Open an HPKE box addressed to this device.
    pub fn open(
        &self,
        info: &[u8],
        aad: &[u8],
        sealed: &crate::hpke::SealedBox,
    ) -> Result<SecretBytes> {
        self.kem.open(info, aad, sealed)
    }
}

impl Ed25519Signer for DeviceIdentity {
    fn public_key(&self) -> [u8; PUBLIC_KEY_LEN] {
        self.signing.public_key()
    }
    fn sign(&self, msg: &[u8]) -> [u8; SIGNATURE_LEN] {
        self.signing.sign(msg)
    }
}

impl fmt::Debug for DeviceIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let p = self.public();
        f.debug_struct("DeviceIdentity")
            .field("sign_pk", &p.sign_pk_b64u())
            .field("kem_pk", &p.kem_pk_b64u())
            .field("secrets", &"[REDACTED]")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_and_tamper() {
        let kp = Ed25519Keypair::generate();
        let sig = kp.sign(b"msg");
        verify(&kp.public_key(), b"msg", &sig).unwrap();
        assert_eq!(
            verify(&kp.public_key(), b"msg2", &sig),
            Err(CryptoError::BadSignature)
        );
        let mut bad = sig;
        bad[10] ^= 1;
        assert!(verify(&kp.public_key(), b"msg", &bad).is_err());
        verify_b64u(&kp.public_key_b64u(), b"msg", &kp.sign_b64u(b"msg")).unwrap();
        assert!(verify_b64u("not-base64!", b"msg", &kp.sign_b64u(b"msg")).is_err());
        // identity point (small order) is rejected as a public key
        let mut ident = [0u8; 32];
        ident[0] = 1;
        assert!(validate_ed25519_public_key(&ident).is_err());
    }

    #[test]
    fn device_identity_roundtrip() {
        let id = DeviceIdentity::generate();
        let exported = id.to_secret_bytes();
        assert_eq!(exported.len(), DEVICE_SECRET_LEN);
        let back = DeviceIdentity::from_secret_bytes(exported.expose()).unwrap();
        assert_eq!(back.public(), id.public());
        let sig = back.sign(b"x");
        id.public().verify(b"x", &sig).unwrap();
        assert!(DeviceIdentity::from_secret_bytes(&[0u8; 63]).is_err());

        let dbg = format!("{id:?}");
        assert!(dbg.contains("[REDACTED]"));
        assert!(!dbg.contains(&crate::b64u::encode(id.signing_keypair().seed().expose())));

        let json = serde_json::to_value(id.public()).unwrap();
        assert_eq!(json["sign_pk"], id.public().sign_pk_b64u());
        let p: IdentityPublic = serde_json::from_value(json).unwrap();
        assert_eq!(p, id.public());
    }

    #[test]
    fn x25519_agreement() {
        let a = KemKeypair::generate();
        let b = KemKeypair::generate();
        assert_eq!(
            a.diffie_hellman(&b.public_key()).unwrap(),
            b.diffie_hellman(&a.public_key()).unwrap()
        );
        // low-order point → rejected
        assert_eq!(a.diffie_hellman(&[0u8; 32]), Err(CryptoError::InvalidKey));
        let again = KemKeypair::from_secret_bytes(a.secret_bytes().expose());
        assert_eq!(again.public_key(), a.public_key());
    }

    #[test]
    fn rfc7748_x25519_vector() {
        // RFC 7748 §6.1 Alice/Bob
        let a_sk: [u8; 32] =
            hex::decode("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
                .unwrap()
                .try_into()
                .unwrap();
        let b_sk: [u8; 32] =
            hex::decode("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
                .unwrap()
                .try_into()
                .unwrap();
        let a = KemKeypair::from_secret_bytes(&a_sk);
        let b = KemKeypair::from_secret_bytes(&b_sk);
        assert_eq!(
            hex::encode(a.public_key()),
            "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
        );
        assert_eq!(
            hex::encode(b.public_key()),
            "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
        );
        assert_eq!(
            hex::encode(a.diffie_hellman(&b.public_key()).unwrap().expose()),
            "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
        );
    }
}
