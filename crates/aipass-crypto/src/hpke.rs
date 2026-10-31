// SPDX-License-Identifier: Apache-2.0
//! HPKE (RFC 9180) **base mode**, suite DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 /
//! ChaCha20-Poly1305, via the widely used `hpke` crate (CONTRACTS §2.1).
//!
//! Used to seal: the VMK to each member device (`info = aipass/v1/vmk-wrap`), credential
//! envelopes to an executor (`aipass/v1/credential`) and relay messages
//! (`aipass/v1/relay`). See [`crate::info`] for the namespaced info strings.

use ::hpke::aead::ChaCha20Poly1305;
use ::hpke::kdf::HkdfSha256;
use ::hpke::kem::X25519HkdfSha256;
use ::hpke::{Deserializable, Kem as _, OpModeR, OpModeS, Serializable};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::{CryptoError, Result};
use crate::identity::{KemKeypair, PUBLIC_KEY_LEN};
use crate::secret::SecretBytes;

type Kem = X25519HkdfSha256;
type Kdf = HkdfSha256;
type Aead = ChaCha20Poly1305;

/// Length of the encapsulated key (`enc`) for DHKEM(X25519): 32 bytes.
pub const ENC_LEN: usize = 32;
/// AEAD tag length appended to `ct`.
pub const TAG_LEN: usize = 16;

/// An HPKE ciphertext: `{"enc": b64u, "ct": b64u}` (CONTRACTS §2.1).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedBox {
    /// Encapsulated ephemeral public key (32 bytes for X25519).
    #[serde(with = "crate::b64u::bytes")]
    pub enc: Vec<u8>,
    /// AEAD ciphertext ‖ tag.
    #[serde(with = "crate::b64u::bytes")]
    pub ct: Vec<u8>,
}

impl core::fmt::Debug for SealedBox {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SealedBox")
            .field("enc", &crate::b64u::encode(&self.enc))
            .field("ct_len", &self.ct.len())
            .finish()
    }
}

impl SealedBox {
    /// Build from b64u strings.
    pub fn from_b64u(enc: &str, ct: &str) -> Result<Self> {
        Ok(Self {
            enc: crate::b64u::decode(enc)?,
            ct: crate::b64u::decode(ct)?,
        })
    }
}

/// Seal `plaintext` to `recipient_kem_pk` with the given `info` and `aad`.
pub fn seal(
    recipient_kem_pk: &[u8; PUBLIC_KEY_LEN],
    info: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<SealedBox> {
    seal_with_rng(
        recipient_kem_pk,
        info,
        aad,
        plaintext,
        &mut crate::rng::os_rng(),
    )
}

/// Seal with a caller-provided RNG. Crate-private: only used to replay RFC 9180 known-answer
/// vectors in tests; production code always uses the OS CSPRNG through [`seal`].
pub(crate) fn seal_with_rng(
    recipient_kem_pk: &[u8; PUBLIC_KEY_LEN],
    info: &[u8],
    aad: &[u8],
    plaintext: &[u8],
    rng: &mut impl rand_core::CryptoRng,
) -> Result<SealedBox> {
    let pk = <Kem as ::hpke::Kem>::PublicKey::from_bytes(recipient_kem_pk)
        .map_err(|_| CryptoError::InvalidKey)?;
    let (enc, ct) = ::hpke::single_shot_seal_with_rng::<Aead, Kdf, Kem>(
        &OpModeS::Base,
        &pk,
        info,
        plaintext,
        aad,
        rng,
    )
    .map_err(|_| CryptoError::Hpke)?;
    Ok(SealedBox {
        enc: enc.to_bytes().to_vec(),
        ct,
    })
}

/// Open a [`SealedBox`] with the recipient's KEM keypair. Any failure (wrong key, info, AAD,
/// tampered `enc`/`ct`) yields an error; plaintext is returned zeroizing.
pub fn open(
    recipient: &KemKeypair,
    info: &[u8],
    aad: &[u8],
    sealed: &SealedBox,
) -> Result<SecretBytes> {
    if sealed.enc.len() != ENC_LEN {
        return Err(CryptoError::InvalidLength {
            expected: ENC_LEN,
            actual: sealed.enc.len(),
        });
    }
    if sealed.ct.len() < TAG_LEN {
        return Err(CryptoError::Hpke);
    }
    let sk_bytes = Zeroizing::new(*recipient.secret_bytes().expose());
    let sk = <Kem as ::hpke::Kem>::PrivateKey::from_bytes(sk_bytes.as_ref())
        .map_err(|_| CryptoError::InvalidKey)?;
    let enc = <Kem as ::hpke::Kem>::EncappedKey::from_bytes(&sealed.enc)
        .map_err(|_| CryptoError::Hpke)?;
    let pt = ::hpke::single_shot_open::<Aead, Kdf, Kem>(
        &OpModeR::Base,
        &sk,
        &enc,
        info,
        &sealed.ct,
        aad,
    )
    .map_err(|_| CryptoError::Hpke)?;
    Ok(SecretBytes::new(pt))
}

/// RFC 9180 `DeriveKeyPair(ikm)` for DHKEM(X25519, HKDF-SHA256). Deterministic; used for
/// known-answer tests. Returns `(secret, public)`.
pub fn derive_keypair(ikm: &[u8]) -> (crate::secret::Key32, [u8; PUBLIC_KEY_LEN]) {
    let (sk, pk) = Kem::derive_keypair(ikm);
    let mut sk_arr = Zeroizing::new([0u8; 32]);
    sk.write_exact(sk_arr.as_mut());
    let mut pk_arr = [0u8; 32];
    pk_arr.copy_from_slice(pk.to_bytes().as_slice());
    (crate::secret::Key32::from_bytes(*sk_arr), pk_arr)
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::convert::Infallible;

    /// Deterministic "RNG" that replays fixed bytes — test-only, to reproduce RFC 9180 KATs.
    struct ReplayRng(Vec<u8>, usize);
    impl rand_core::TryRng for ReplayRng {
        type Error = Infallible;
        fn try_next_u32(&mut self) -> core::result::Result<u32, Infallible> {
            let mut b = [0u8; 4];
            self.try_fill_bytes(&mut b)?;
            Ok(u32::from_le_bytes(b))
        }
        fn try_next_u64(&mut self) -> core::result::Result<u64, Infallible> {
            let mut b = [0u8; 8];
            self.try_fill_bytes(&mut b)?;
            Ok(u64::from_le_bytes(b))
        }
        fn try_fill_bytes(&mut self, dst: &mut [u8]) -> core::result::Result<(), Infallible> {
            for d in dst.iter_mut() {
                *d = self.0[self.1 % self.0.len()];
                self.1 += 1;
            }
            Ok(())
        }
    }
    impl rand_core::TryCryptoRng for ReplayRng {}

    fn h(s: &str) -> Vec<u8> {
        hex::decode(s).unwrap()
    }

    /// RFC 9180 Appendix A.2.1 (mode base, X25519/HKDF-SHA256/ChaCha20Poly1305),
    /// encryption sequence number 0 (single-shot seal = first message of a context).
    #[test]
    fn rfc9180_a21_known_answer() {
        let info = h("4f6465206f6e2061204772656369616e2055726e");
        let ikm_e = h("909a9b35d3dc4713a5e72a4da274b55d3d3821a37e5d099e74a647db583a904b");
        let ikm_r = h("1ac01f181fdf9f352797655161c58b75c656a6cc2716dcb66372da835542e1df");
        // RFC values; the `hpke` crate serializes X25519 secrets in clamped form
        // (RFC 7748 decodeScalar25519), so compare clamped scalars.
        let sk_rm: [u8; 32] = h("8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb")
            .try_into()
            .unwrap();
        let sk_em: [u8; 32] = h("f4ec9b33b792c372c1d2c2063507b684ef925b8c75a42dbcbf57d63ccd381600")
            .try_into()
            .unwrap();
        let clamp = |mut k: [u8; 32]| {
            k[0] &= 248;
            k[31] &= 127;
            k[31] |= 64;
            k
        };
        let (sk_r, pk_r) = derive_keypair(&ikm_r);
        assert_eq!(*sk_r.expose(), clamp(sk_rm));
        assert_eq!(
            hex::encode(pk_r),
            "4310ee97d88cc1f088a5576c77ab0cf5c3ac797f3d95139c6c84b5429c59662a"
        );
        let (sk_e, pk_e) = derive_keypair(&ikm_e);
        assert_eq!(*sk_e.expose(), clamp(sk_em));
        assert_eq!(
            hex::encode(pk_e),
            "1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a"
        );

        let pt = h("4265617574792069732074727574682c20747275746820626561757479");
        let aad = h("436f756e742d30");
        let mut rng = ReplayRng(ikm_e.clone(), 0);
        let sealed = seal_with_rng(&pk_r, &info, &aad, &pt, &mut rng).unwrap();
        assert_eq!(
            hex::encode(&sealed.enc),
            "1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a"
        );
        assert_eq!(
            hex::encode(&sealed.ct),
            "1c5250d8034ec2b784ba2cfd69dbdb8af406cfe3ff938e131f0def8c8b60b4db21993c62ce81883d2dd1b51a28"
        );

        // Our KemKeypair (x25519-dalek StaticSecret) must interoperate with the HPKE key.
        // Use the RFC's unclamped skRm to show both encodings interoperate.
        let recipient = KemKeypair::from_secret_bytes(&sk_rm);
        assert_eq!(recipient.public_key(), pk_r);
        let recipient_clamped = KemKeypair::from_secret_bytes(sk_r.expose());
        assert_eq!(
            open(&recipient_clamped, &info, &aad, &sealed)
                .unwrap()
                .expose(),
            pt.as_slice()
        );
        assert_eq!(
            open(&recipient, &info, &aad, &sealed).unwrap().expose(),
            pt.as_slice()
        );
    }

    /// The same vector, read from `test-vectors/hpke-rfc9180-a2.json`, must match too.
    #[test]
    fn rfc9180_vector_file() {
        let text = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../test-vectors/hpke-rfc9180-a2.json"
        ));
        let v: serde_json::Value = serde_json::from_str(text).unwrap();
        let g = |k: &str| h(v[k].as_str().unwrap());
        let (_, pk_r) = derive_keypair(&g("ikmR"));
        assert_eq!(pk_r.to_vec(), g("pkRm"));
        let sk_rm: [u8; 32] = g("skRm").try_into().unwrap();
        let recipient = KemKeypair::from_secret_bytes(&sk_rm);
        for e in v["encryptions"].as_array().unwrap() {
            let eh = |k: &str| h(e[k].as_str().unwrap());
            let mut rng = ReplayRng(g("ikmE"), 0);
            let sealed = seal_with_rng(&pk_r, &g("info"), &eh("aad"), &eh("pt"), &mut rng).unwrap();
            assert_eq!(sealed.enc, g("enc"));
            assert_eq!(sealed.ct, eh("ct"));
            assert_eq!(
                open(&recipient, &g("info"), &eh("aad"), &sealed)
                    .unwrap()
                    .expose(),
                eh("pt").as_slice()
            );
        }
    }

    #[test]
    fn roundtrip_and_tamper() {
        let r = KemKeypair::generate();
        let info = crate::info::CREDENTIAL;
        let s = seal(&r.public_key(), info, b"aad", b"secret material").unwrap();
        assert_eq!(s.enc.len(), ENC_LEN);
        assert_eq!(
            open(&r, info, b"aad", &s).unwrap().expose(),
            b"secret material"
        );

        // wrong aad / info / recipient
        assert!(open(&r, info, b"aad2", &s).is_err());
        assert!(open(&r, crate::info::RELAY, b"aad", &s).is_err());
        assert!(open(&KemKeypair::generate(), info, b"aad", &s).is_err());
        // tampered ct / enc
        let mut t = s.clone();
        t.ct[3] ^= 0x40;
        assert!(open(&r, info, b"aad", &t).is_err());
        let mut t = s.clone();
        t.enc[0] ^= 0x01;
        assert!(open(&r, info, b"aad", &t).is_err());
        let mut t = s.clone();
        t.enc.pop();
        assert!(open(&r, info, b"aad", &t).is_err());
        let mut t = s.clone();
        t.ct.truncate(5);
        assert!(open(&r, info, b"aad", &t).is_err());

        // two seals of the same message differ (fresh ephemeral)
        let s2 = seal(&r.public_key(), info, b"aad", b"secret material").unwrap();
        assert_ne!(s.enc, s2.enc);

        // serde shape
        let json = serde_json::to_value(&s).unwrap();
        assert!(json["enc"].is_string() && json["ct"].is_string());
        let back: SealedBox = serde_json::from_value(json).unwrap();
        assert_eq!(back, s);
        assert!(!format!("{s:?}").contains(&crate::b64u::encode(&s.ct)));
    }

    #[test]
    fn seal_to_low_order_point_fails() {
        assert!(seal(&[0u8; 32], b"i", b"", b"x").is_err());
    }
}
