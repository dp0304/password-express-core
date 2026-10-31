<!-- SPDX-License-Identifier: Apache-2.0 -->
# Vault test vectors

Generated and checked by `crates/aipass-vault/tests/vectors.rs` (fixed seeds;
`AIPASS_REGEN_VECTORS=1 cargo test -p aipass-vault --test vectors` regenerates). Format:
[`docs/spec/vault-format.md`](../../docs/spec/vault-format.md). Binary values are b64u;
`*_jcs` fields are the exact JCS bytes as UTF-8 strings.

| file | content |
| --- | --- |
| `recovery-key.json` | recovery secret 0x40..0x5f → `AIPR-…` text, equivalent parse inputs, recovery KEK, recovery member identity and device id |
| `entry-encryption.json` | VMK / DEK / nonces → AAD strings, payload JCS, `EntryVersion` object JCS, object hash |
| `recovery-wrap.json` | `recovery/1-recovery_key.json` with a fixed nonce |
| `signed-objects.json` | `vault.json`, genesis `MemberRecord` (placeholder `wrapped_vmk`) and a `Manifest` signed with seed 0x60..0x7f; signing bytes, hashes, storage keys |
| `pairing-sas.json` | eN / eO secrets → shared secret, transcript JCS, `th`, `K`, 6-digit SAS |
| `export.json` | `.aipassx` with Argon2id contract parameters, fixed salt / nonce |
| `vmk-wrap-hpke.json` | decrypt-only: VMK HPKE-sealed to the KEM key 0x80..0x9f (HPKE uses a fresh ephemeral key, so this file is generated once and verified by opening) |

Independently cross-checked with Python `cryptography` (HKDF, X25519, Ed25519 over JCS,
Crockford base32), PyNaCl / libsodium (XChaCha20-Poly1305) and argon2-cffi (Argon2id).
