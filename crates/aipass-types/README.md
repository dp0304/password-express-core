<!-- SPDX-License-Identifier: Apache-2.0 -->
# aipass-types

Shared models and protocol rules of AI Pass — the Rust implementation of the binding shapes
in `docs/spec/CONTRACTS.md`. Every digest and signature in Rust (broker, CLI, desktop, FFI)
goes through this crate. **Not yet independently audited.**

| module | contract | key items |
| --- | --- | --- |
| `ids` | §1.1 | `VaultId`, `EntryId`, `DeviceId`, `ExecutorId`, `ConnectionId`, `ResourceId`, `ProjectId`, `PolicyId`, `GrantId`, `ApprovalRequestId`, `OperationId`, `LeaseId`, `EventId`, `MessageId`, `PairingId`, `RequestId`, `UserId`, `OrgId`, `SubscriptionId`, `InvitationId`, `IncidentId`, `OAuthClientId`, `SessionId`; `PrincipalId`, `MailboxId`; `X::generate()`, `X::parse()` |
| `time` | §1.3 | `Timestamp`, `now()`, `unix_now()`, `format_rfc3339`, `parse_rfc3339`, serde `time::rfc3339` / `time::rfc3339_option` |
| `canonical` | §1.4 | `to_jcs_bytes`, `to_jcs_string`, `value_to_jcs`, `canonicalize_json_text`, `jcs_sha256_b64u`, `jcs_without_field`, `value_jcs_without_field` |
| `error` | §1.5 | `ErrorCode` (+ HTTP status, zh-CN/en messages), `ApiError`, `ErrorBody`, `ErrorObject`, `Lang::from_accept_language`, `Localized` |
| `signing` | §1.6 | `SigHeader::{parse, to_header_value}`, `string_to_sign`, `sign_request(_with)`, `verify_request(_with_nonce)`, `NonceCache`, `Authorization`, `token_hash` |
| `vault` | §2.3 | `VaultHeader`, `MemberRecord`, `RecoveryWrap`, `KeyringRecord`, `EntryVersion`, `Manifest`, `EntryPayload`, `DevicePublic`, `Checkpoint`, `PasswordRules`, `SignedObject::{signing_bytes, sign_with, verify_signature}`, `vault::keys::*`, `vault::aad::*` |
| `storage` | §3.1 | `StorageProfile`, `StorageKind`, `StorageVerdict` |
| `relay` | §4 | `RelayEnvelope`, `RelayMessage`, `RelayMessageType`, `seal_envelope`, `open_envelope(_unverified)`, `DeviceSigned` (control signatures), `MailboxMessage`, `PushHint` |
| `pairing` | §5 | `PairingOffer::{to_uri, parse, is_expired}`, `transcript_hash`, `PairingHello/Join/Welcome(+Inner)` |
| `models` | §6.1 / §6.3 | all broker models and HTTP request/response shapes; `OperationStatus::can_transition` |
| `approval` | §7 | `normalize_scope`, `compute_digest` (**v2**: binds `operation_id` + `parameters_digest`, both `null` for `kind:"access"`), `digest_for`, `operation_binding`, `check_operation_binding`, `request_digest` (display-level hash of a whole request, minus `status`), `signing_message`, `approved_is_subset`, `build_decision`, `verify_decision`, `credential_aad_bytes` |
| `policy` | §7 | `policy_digest`, `signing_message`, `sign_policy`, `verify_policy`, `auto_approve_allowed` |
| `exec` | §8 | `ExecutorBackend` (async-trait), `OperationSpec`, `NormalizedRequest`, `ExecutionRequest`, `ExecutionOutcome`, `LevelReport`, `CredentialMaterial`, `CredentialAad`, `seal_credential`, `open_credential`, `parameters_digest` |

## Build / test

```bash
cd open-source
cargo test -p aipass-types
AIPASS_REGEN_VECTORS=1 cargo test -p aipass-types   # rewrite jcs.json / approval-digest.json
```

`tests/vectors.rs` reproduces `test-vectors/request-signing.json` (the CONTRACTS §1.6 vector,
byte-for-byte) and generates + checks `jcs.json` and `approval-digest.json`. The two signing
vectors were additionally cross-checked with Python `cryptography` during development.

## Design notes

- IDs are lowercase-only and strictly validated (prefix, length, Crockford alphabet, 128-bit
  range). IDs are never capabilities.
- Signed objects are signed over `JCS(object minus "signature")` computed from the typed
  struct; unknown fields are not preserved, so a newer writer's extra fields make the
  signature fail closed. `canonical::value_jcs_without_field` is available for verifying raw
  JSON instead.
- `OperationStatus::AwaitingApproval` serializes as `"approval_required"` everywhere (accepts
  `"awaiting_approval"` on input); `state_name()` gives the internal name for databases.
- Credential-bearing types (`EntryPayload`, `TotpConfig`, `CustomField`, `CredentialMaterial`,
  `PairingWelcomeInner`, `PairingOffer`) redact in `Debug`; secret values use zeroizing types.
- `normalize_scope` lower-cases GitHub `owner/name` (GitHub names are case-insensitive) and
  drops empty connector sections; connectors must compare repos case-insensitively.

## Contract deviations

None that change a contract shape. Additive or clarifying choices (recorded for reviewers):

1. `ApprovalRequest.excluded_fields` — optional (omitted when empty) display-only map of
   per-view fields that are *not* requested ("不含客户邮箱", design doc §5.3); not part of the digest.
2. `StorageProfile.path` — optional directory for `kind: "local"`.
3. `ErrorCode` also contains client-local codes `LOCKED` (423), `NO_VAULT` (404),
   `ORIGIN_MISMATCH` (403), `NOT_PAIRED` (401) used by FFI / native messaging (§11, §12).
4. `KeyringRecord {format, vault_id, key_epoch, previous:[{key_epoch, nonce, wrapped_vmk}],
   author_device_id, created_at}` — the contract fixes only key, content and AAD.
5. `exec::DelegationAad {policy_id, policy_digest, executor_id}` for the experimental
   `/credentials/delegate` envelope (the contract defines no AAD for it).
6. Audit hash: `prev_hash_bytes` is the b64u-decoded previous hash (empty for the first event).
7. Connection pairing requests use the `pair_` prefix (`PairingId`) for `pairing_request_id`.
8. `ActivitySummary` counts are integers; `anomalies` is `[{kind, summary:{zh,en}, at,
   connection_id?, resource_id?}]` (the contract leaves the element shape open).
9. Pairing `transcript_hash` uses the literal JCS keys `pairing_id`, `eN`, `eO`, `relay`;
   `pairing.hello` serializes the ephemeral key as `"eO"` exactly as written in §5.
10. **Approval digest v2** (CONTRACTS §7, edited in place): the digest document adds
    `operation_id` and `parameters_digest` (always present; `null` for `kind:"access"`) and
    `"v":2`. `ApprovalRequest.parameters_digest` (optional, additive) carries the waiting
    operation's normalized-parameter digest. `build_decision` / `verify_decision` refuse
    (`INTEGRITY_FAILED`) an operation request without both fields and an access request with
    either; v1 digests never verify.
