<!-- SPDX-License-Identifier: Apache-2.0 -->
# HPKE vectors and roundtrip notes

AI Pass seals data to a device or executor public key with **HPKE (RFC 9180) base mode**,
suite **DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / ChaCha20-Poly1305** (`kem_id=0x0020`,
`kdf_id=0x0001`, `aead_id=0x0003`), via the `hpke` Rust crate. Output shape:

```json
{"enc": "<b64u 32-byte encapsulated X25519 key>", "ct": "<b64u ciphertext || 16-byte tag>"}
```

## Why there is no fixed "AI Pass HPKE vector"

Every seal draws a fresh ephemeral key from the OS CSPRNG, so ciphertexts are intentionally
non-deterministic. Correctness is pinned instead by:

1. **RFC 9180 A.2.1 known answer** (`hpke-rfc9180-a2.json`): the test replays `ikmE` through a
   test-only RNG and must reproduce `enc` and `ct` byte-for-byte, then open it with `skRm`
   (both the RFC's unclamped scalar and the clamped form produced by `DeriveKeyPair`).
   The replay RNG is crate-private test code; production code cannot choose ephemerals.
2. **Roundtrip + tamper tests** (`crates/aipass-crypto/src/hpke.rs`): seal → open succeeds;
   any change to `info`, `aad`, recipient key, `enc` (bit flip or truncation) or `ct` fails;
   sealing to the all-zero (low-order) X25519 point fails; two seals of the same plaintext
   differ.

## Info / AAD strings used by AI Pass

| purpose | info | aad |
| --- | --- | --- |
| VMK wrap to a member device | `aipass/v1/vmk-wrap` | `aipass:v1:vmk:{vault_id}:{device_id}:{key_epoch}` |
| credential envelope to an executor | `aipass/v1/credential` | `JCS({approval_request_id, digest, executor_id})` |
| relay envelope | `aipass/v1/relay` | `JCS({v, from, to, type, created_at})` |

Status: not independently audited.
