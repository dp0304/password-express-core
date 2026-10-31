<!-- SPDX-License-Identifier: Apache-2.0 -->
# AI Pass test vectors

Every implementation (Rust, TypeScript SDK, Python SDK where applicable) must reproduce these
exactly. Files marked *generated* are written by the Rust tests when missing or when
`AIPASS_REGEN_VECTORS=1` is set, and are compared on every test run.

| file | content | checked by |
| --- | --- | --- |
| `request-signing.json` | CONTRACTS §1.6 `AIPass-Sig` vector (verbatim from the contract) | `crates/aipass-types/tests/vectors.rs` |
| `jcs.json` *(generated)* | RFC 8785 canonicalization cases for the AI Pass subset + rejected inputs (floats, unsafe integers) | `crates/aipass-types/tests/vectors.rs` |
| `approval-digest.json` *(generated)* | §7 **v2** digest: full `ApprovalRequest` (`kind:"operation"`, with `operation_id` + `parameters_digest`) + three `ApprovalDecision`s (approve, narrowed approve, deny) with digest document, digest, signing message and Ed25519 signature from seed `0x20..0x3f`; plus the display-level `request_digest` (JCS of the request minus `status`) | `crates/aipass-types/tests/vectors.rs` |
| `hpke-rfc9180-a2.json` | RFC 9180 A.2.1 known answer for the exact AI Pass HPKE suite | `crates/aipass-crypto/src/hpke.rs` |
| `hpke-roundtrip.md` | why HPKE has no fixed AI Pass vector; roundtrip/tamper coverage; info/AAD table | — |
| `xchacha.json` *(generated)* | XChaCha20-Poly1305: draft-irtf-cfrg-xchacha-03 A.3.1 + an AI Pass DEK wrap with the contract AAD | `crates/aipass-crypto/tests/kat.rs` |

Encodings: binary values are hex in the RFC-derived files and b64u (base64url, no padding)
in AI Pass protocol files, as labelled per field.
