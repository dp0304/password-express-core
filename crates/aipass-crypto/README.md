<!-- SPDX-License-Identifier: Apache-2.0 -->
# aipass-crypto

Cryptographic primitives for AI Pass (CONTRACTS §2.1, design doc §9.4). A thin layer over
mature cryptographic libraries.

| need | API | library |
| --- | --- | --- |
| AEAD | `aead::{seal, open, seal_with_nonce, wrap_key, unwrap_key}`, `AeadBox {nonce, ct}` — XChaCha20-Poly1305, random 24-byte nonce, mandatory AAD | `chacha20poly1305` 0.11 |
| seal to a public key | `hpke::{seal, open}`, `SealedBox {enc, ct}` (b64u) — RFC 9180 base, X25519/HKDF-SHA256/ChaCha20-Poly1305 | `hpke` 0.15 |
| signatures | `Ed25519Keypair`, `identity::{verify, verify_b64u}` (strict) | `ed25519-dalek` 3 |
| KEM / ECDH | `KemKeypair` (X25519; DH rejects low-order points) | `x25519-dalek` 3 |
| device identity | `DeviceIdentity` (Ed25519 + X25519; `to_secret_bytes` / `from_secret_bytes` 64 bytes), `IdentityPublic {sign_pk, kem_pk}` | |
| KDF | `kdf::{hkdf_sha256, derive_key32, extract, expand}` | `hkdf` 0.13 |
| password KDF | `password::argon2id`, `Argon2Params::CONTRACT_V1` (m=65536, t=3, p=1), `Argon2Params::INSECURE_FAST_FOR_TESTS_ONLY`, `Argon2idDescriptor {alg, m, t, p, salt}` | `argon2` 0.6 |
| hashing | `sha256`, `sha256_b64u`, `hash::{sha256_concat, hmac_sha256, hmac_sha256_verify}` | `sha2`, `hmac` |
| randomness | `rng::{fill_random, random_array, try_random_array, random_secret, random_key32, random_below, random_token, os_rng}` — OS CSPRNG only | `getrandom` 0.4 |
| encoding | `b64u::{encode, decode, decode_array}` + serde helpers `b64u::{bytes, array, option_bytes, option_array}` | `base64` |
| secrets | `SecretBytes`, `SecretString`, `Key32`, `ct_eq` — zeroize on drop, `Debug` = `[REDACTED]`, constant-time `==` | `zeroize`, `subtle` |
| info strings | `info::{VMK_WRAP, CREDENTIAL, RELAY, RECOVERY_KEK, PAIRING_KEY, PAIRING_SAS}` | |

## Build / test

```bash
cd open-source
cargo test -p aipass-crypto
AIPASS_REGEN_VECTORS=1 cargo test -p aipass-crypto   # rewrite test-vectors/xchacha.json
```

Known-answer tests (`tests/kat.rs`, `src/hpke.rs`, `src/identity.rs`, `src/hash.rs`):
draft-irtf-cfrg-xchacha-03 §A.3.1, RFC 8439 §2.8.2, RFC 8032 TEST 1–3, RFC 5869 A.1–A.3,
RFC 9106 §5.3 (Argon2id), RFC 7748 §6.1 (X25519), RFC 4231 case 2 (HMAC), RFC 9180 A.2.1
(HPKE, reproduced byte-for-byte via a crate-private test RNG; also read from
`test-vectors/hpke-rfc9180-a2.json`), plus roundtrip and tamper tests.

The dev profile compiles `argon2`, `blake2`, `chacha20`, `poly1305`, `curve25519-dalek` and
`sha2` at `opt-level = 3` so Argon2id with the real contract parameters stays fast in tests.

## Notes and limitations

- `random_array` and `os_rng` panic if the operating-system RNG fails (as every mainstream
  CSPRNG interface does); use `try_random_array` / `fill_random` for a recoverable error.
- The `hpke` crate stores X25519 secrets in clamped form; `KemKeypair::from_secret_bytes`
  accepts both clamped and unclamped scalars (identical public keys).
- `SecretString` / `SecretBytes` implement serde **only** so they can live inside payloads
  that are about to be encrypted; never serialize them into logs or API responses.
- Memory zeroization is best-effort (the OS may have swapped pages; copies made by callers
  outside these types are not tracked).

## Contract deviations

None. (`AeadBox {nonce, ct}` is the concrete JSON shape for the contract's
`sealed: XChaCha20(K, …)` notation in §5.)
