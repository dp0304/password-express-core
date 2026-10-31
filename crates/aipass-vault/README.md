<!-- SPDX-License-Identifier: Apache-2.0 -->
# aipass-vault — Vault Core

账号库核心：密钥层级、条目加密、成员记录、签名清单、恢复密钥与恢复包、密码生成器、TOTP、
CSV 导入与导出、设备配对状态机、审批签名。所有密码学原语来自 `aipass-crypto`（成熟库，
无自制算法），所有线上格式来自 `aipass-types`。**尚未经过独立安全审计。**

Vault Core of AI Pass (CONTRACTS §2, §4, §5, §7; design doc §6, §9.4, §9.5, §10). The exact
on-storage format is specified in [`docs/spec/vault-format.md`](../../docs/spec/vault-format.md).

## Modules

| module | contents |
| --- | --- |
| `keys` | `VaultKeys` (VMK per epoch, never exposed), `seal_vmk` / `open_vmk` (HPKE, contract AAD), `recovery_kek`, `wrap_recovery` / `open_recovery`, master-password KEK (Argon2id), `build_keyring` / `open_keyring` |
| `entry` | `encrypt_entry` (fresh DEK per version), `decrypt_entry` (AADs from the expected location), `parse_entry_object`, `SealedEntry` |
| `member` | `build_member` / `SignedMember`, `recovery_identity`, `recovery_device_id`, `is_recovery_member`, `executor_member_id` / `member_executor_id` (`exe_X` ⇔ `dev_X`) |
| `manifest` | `VaultView`, `verify_header`, `verify_transition` (all chain rules), `verify_entry_object`, `ManifestDraft` (version / rev / epoch allocation, staging, signing) |
| `vault` | `create_genesis`, `UnlockedVault`, `stage_add_member`, `stage_revocation` (+ key rotation), `stage_rotation`, `stage_replace_recovery_key`, `open_with_recovery_key`, `recovery_key_matches` |
| `recovery` | `RecoveryKey` (`AIPR-…` format / parse / checksum), `recovery_kit_text` (zh + en) |
| `secret_store` | `SecretStore` trait, `MemorySecretStore`, `FileSecretStore` (Argon2id-encrypted file, 0600), `OsKeyringStore` (feature `os-keyring`) |
| `generator` | `generate_password(PasswordRules)`, `parse_passwordrules` (Apple syntax), `generate_from_spec`, `generate_for_site` |
| `totp` | RFC 6238 / 4226, `parse_otpauth`, `parse_totp_input`, `to_otpauth` |
| `import` / `export` | CSV importers `chrome firefox safari bitwarden 1password lastpass generic` with de-dup + `ImportReport`; `.aipassx` encrypted export / import; CSV export |
| `matching` | `match_entry` (exact origin / same site over https only), `registrable_domain` (PSL) |
| `pairing` | `NewDeviceSession` (new device N), `TrustedSession` (trusted device O), `derive_pairing_secrets` (K + SAS exactly per contract) |
| `relay` | `RelayTransport` trait, `MemoryRelay`, `seal_message` / `open_message`, `RelayTransport` impl for `aipass_storage::RelayClient` |
| `approval` | `approve_request` (digest via `aipass_types::approval`, Ed25519, HPKE credential envelope), `deny_request`, `sign_connection_decision`, `sign_grant_revoke`, `sign_connection_control` |
| `fsutil` | atomic 0600 writes |

## Architecture notes

* **UIs never see the VMK.** `UnlockedVault` keeps the device identity and the VMKs and only
  offers encrypt / decrypt / seal operations. All secret types zeroize on drop and print
  `[REDACTED]`; errors (`VaultError`) carry only static reasons and map to the stable error
  codes of CONTRACTS §1.5 (`From<VaultError> for ApiError`).
* **Location-bound AEAD.** Entry decryption derives both AADs from the storage key, so a
  moved, relabelled or spliced ciphertext fails (see `tests/security.rs`).
* **Manifest chain.** `verify_transition` is the single gate for every remote change: author
  membership, signatures, member-record hashes and signers, immutable device keys, no
  reinstatement of revoked devices, revocation ⇒ key rotation re-sealed to every member,
  tombstones permanent unless explicitly restored with a newer version, new versions under the
  current epoch.
* **Recovery member.** The recovery secret also derives an owner identity enrolled at
  genesis; rotations seal the new VMK to it, so recovery survives revocations although no
  device stores the secret (details in vault-format.md §4.2).
* **Pairing** runs over any `RelayTransport`; the user confirms the 6-digit SAS on the
  trusted device (`TrustedSession::confirm_code` cancels on mismatch). The member record is
  written by the sync layer (`aipass-sync`) only after confirmation.

## Build / test

```bash
cd open-source
cargo build -p aipass-vault
cargo test  -p aipass-vault                       # unit + integration tests
cargo test  -p aipass-vault --features os-keyring # also compiles the OS keychain store
cargo test  -p aipass-vault --features os-keyring -- --ignored   # touches the real keychain
AIPASS_REGEN_VECTORS=1 cargo test -p aipass-vault --test vectors # regenerate test vectors
```

Tests: unit tests in every module; `tests/csv_import.rs` (fixtures for all 7 CSV formats in
`tests/fixtures/`), `tests/security.rs` (AAD swap attacks, malicious manifest transitions,
generator chi-square distribution), `tests/vectors.rs` (writes and checks
`open-source/test-vectors/vault/*.json`; RFC 6238 / 4226 vectors are in `totp.rs`). The
vectors were cross-checked independently with Python `cryptography` (HKDF, X25519, Ed25519
over JCS, Crockford), PyNaCl/libsodium (XChaCha20-Poly1305) and argon2-cffi.

## Limitations

* Not independently audited.
* `require_user_presence` is enforced only by native secret stores (iOS / Android through
  FFI). `FileSecretStore` uses its passphrase as the presence check; `OsKeyringStore` (keyring
  v1 API) cannot request biometrics and is not described as hardware-protected. The OS
  keychain test is `#[ignore]`d (it would write to the developer's real keychain) and was not
  run in this build.
* Keyring items share the contract AAD (`aipass:v1:keyring:{vault}:{epoch}`); relabelling the
  item epochs inside a record is not detected until decryption fails (no confidentiality
  impact).
* CSV exports are written verbatim (no spreadsheet formula neutralisation, to keep passwords
  exact); the UI must show the plaintext warning.
* CSV duplicates (same registrable domain + username) are reported, not imported, so the UI
  can offer a merge.

## Contract deviations

* **Additive — recovery member identity**: owner member derived from the recovery secret
  (HKDF infos `aipass/v1/recovery-sign`, `aipass/v1/recovery-kem`, id domain
  `aipass/v1/recovery-device-id`). Keeps recovery working after key rotation without storing
  the recovery secret, and lets the recovering device authenticate to HTTP sync storage.
  `recovery/<epoch>-recovery_key.json` wraps (contract) are written at creation and whenever the
  user re-enters the key for a newer epoch.
* **Convention where the contract is open**: executor vault member id `dev_X` ⇔ broker
  principal `exe_X` (same ULID part).
* **Defined where the contract is open**: AADs of the pairing K-sealed boxes
  (`aipass:v1:pairing:{hello|join|welcome}:…`, vault-format.md §8), the `.aipassx` AAD
  `aipass:v1:export:aipass-export-1`, the secret-store file format.
* **Clarification**: recovery KEK salt = UTF-8 bytes of the `vault_id` string; every stored
  object is JCS-encoded; a tombstone records the highest version incl. conflict versions;
  manifest verification enforces stricter rules than §2.3 lists (see Architecture notes).
* **Additive**: `ImportReport.warnings` (rows imported with a caveat, e.g. invalid TOTP
  dropped) and `duplicates[].row`.
* **Error mapping**: an expired pairing QR maps to `APPROVAL_EXPIRED` (410) — the closest
  existing code.
