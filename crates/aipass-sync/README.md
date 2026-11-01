<!-- SPDX-License-Identifier: Apache-2.0 -->
# aipass-sync — sync engine and vault facade

客户端同步引擎与 `VaultClient` 门面：拉取并逐条验证签名清单链，检测已知检查点的回滚，
"只能新建"的提交与重放合并，三方合并与冲突暂停自动使用，删除标记，离线 90 天规则，
加密的本地待同步队列，成员撤销与密钥轮换。CLI、桌面端和 FFI 都通过 `VaultClient` 使用账号库，
界面不接触主密钥。

Client sync engine (CONTRACTS §3.2) and the `VaultClient` facade used by the CLI, the
desktop app and the FFI (CONTRACTS §12). Format: [`docs/spec/vault-format.md`](../../docs/spec/vault-format.md).

## Modules

| module | contents |
| --- | --- |
| `engine` | `SyncEngine::{genesis_view, cached_view, pull, commit, entry_object, keyring_bytes, open_vault, refresh_keys, write_genesis, put_create_only, recheck_header}`, `CommitPlanner` trait, `PlanContext`, `PullStats`, `CommitOutcome` |
| `planners` | `OutboxPlanner` (rebase + 3-way merge, tombstone rejection), `AddMemberPlanner`, `RevokePlanner`, `ReplaceRecoveryPlanner`, `ResolvePlanner` |
| `merge` | `merge3(base, local, remote)` — secret-bearing conflicts (destination fields `username`/`urls`/`database` are coupled to the secret), notes concatenation |
| `outbox` | encrypted outbox file, coalescing of offline edits |
| `cache` | `FileStore` — directory `ObjectStore` for the local verified-object cache |
| `client` / `client_ops` | `VaultClient` (see below), `ClientConfig`, `StoreFactory`, `StoreContext`, `MemoryStoreFactory`, `DeviceFile`, `StateFile` |
| `factory` | `StandardStoreFactory` over `aipass_storage::profile::open_store` (local / s3 / webdav / official / selfhost) + `POST /v1/vaults` provisioning |
| `models` | `CoreStatus`, `ItemSummary`, `ItemDetail`, `ItemInput`, `SecretField`, `SyncReport`, `ConflictInfo`, `DeviceInfo`, `RevokeResult`, `RotationTask`, `CreateVaultResult`, `MigrationReport`, `AutofillCandidate`, `AutofillCredential`, `CredentialIdentity`, `SaveStatus`, `KnownExecutor` |

### `VaultClient` (mirrors CONTRACTS §12)

* lifecycle: `open(cfg, secret_store, factory)`, `has_vault`, `status`, `create_vault(name, storage, storage_secret?, master_password?)`, `unlock` (offline from cache), `lock`, `is_unlocked`
* items: `list_items(query?, project?)`, `get_item` (secrets masked), `reveal_secret(id, SecretField)`, `save_item(ItemInput)`, `delete_item`, `generate_password`, `totp_now`, `rejected_changes`, `restore_rejected`, `discard_rejected`
* sync: `sync() -> SyncReport {status ok|offline|conflict|rollback_detected|error, …}`, `conflicts()`, `resolve_conflict(id, keep_version)`
* import / export: `import_csv(CsvFormat, bytes)`, `export_encrypted(password)`, `import_encrypted(bytes, password)`, `export_csv()`
* recovery: `verify_recovery_key`, `recovery_kit_text(include_storage_secret)`, `replace_recovery_key`, `set_master_password`, `VaultClient::recover_with_key(cfg, secrets, factory, vault_id, storage, secret?, key, device_name)`
* devices: `devices`, `revoke_device` (→ rotation tasks: every readable credential for a trusted device; every credential sealed to it on approval for an executor, from `StateFile.executor_deliveries`), `rotation_tasks`, `dismiss_rotation_task`; conflict versions are verified (current key epoch) and pinned in the cache when the manifest introducing them is applied
* storage: `test_storage(profile, secret?)`, `migrate_storage(profile, secret?)`
* autofill / extension: `autofill_candidates`, `autofill_credential` (refuses conflicts), `all_credential_identities`, `save_from_browser`
* approvals & control: `bind_resource`, `register_executor`, `executor_keys`, `approve`, `approve_with_entry`, `deny`, `sign_connection_decision`, `sign_grant_revoke`, `sign_connection_control`, `seal_for_executor`, `send_to_executor`, `open_from_executor`, `fetch_inbox`
* pairing: trusted side `scan_pairing` → `TrustedSession::{wait_for_join, sas, confirm|confirm_code}` → `confirm_pairing[_with_role]`; new side `begin_join` → `NewDeviceSession::{qr_payload, wait_for_hello, wait_for_welcome}` → `complete_join`

## Architecture notes

* Network operations are serialized by an async lock; in-memory state sits behind a
  short-lived mutex, so the synchronous accessors (list, get, reveal, status) never block on
  I/O. `VaultClient` is `Send + Sync`.
* Every local change goes to the encrypted outbox first, then (with `auto_sync`) is pushed.
  Offline → `SyncStatus::Offline`, the change stays queued; unlock and reading work from the
  verified local cache.
* Pull never trusts storage: rollback of a known checkpoint → `ROLLBACK_DETECTED` and no
  writes (flag persisted); tampered objects / forged manifests → `INTEGRITY_FAILED`, the
  last verified state is kept. Only verified objects are cached.
* Revocation (owner only): revoked record + new key epoch sealed to the remaining members and
  the recovery member + keyring. The revoked device, on its next sync, drops keys, caches,
  outbox and secrets (best effort, cannot be guaranteed).
* Pairing confirmed by an owner enrols the new trusted device as an **owner** (so any of the
  user's devices can revoke a lost one); `confirm_pairing_with_role` chooses explicitly.
* Genesis writes are create-only but idempotent per object: when a key already exists (the
  HTTP sync API's `POST /v1/vaults` stores `vault.json` and the genesis member record, or an
  interrupted earlier attempt), it is accepted only if the stored bytes are identical;
  anything else → `AlreadyExists` and no first manifest is written.
* `CoreStatus.device_sign_pk` / `device_kem_pk` and `DeviceInfo.sign_pk` / `kem_pk` expose
  public keys (b64u), e.g. for the cloud's device registration.
* Storage migration (§10.2): sync → capability test (must be `sync_capable`) → copy every
  object create-only → verify the target from scratch reaches the same checkpoint and
  decrypts → switch; the old copy is kept.

## Build / test

```bash
cd open-source
cargo build -p aipass-sync
cargo test  -p aipass-sync
```

Integration tests (in-memory storage via `MemoryStoreFactory` / a toggleable offline wrapper,
in-memory relay):

| file | covers |
| --- | --- |
| `a11_concurrent_edits.rs` | A11: concurrent password edits → conflict, no silent overwrite, autofill / approvals paused, resolution; non-secret merge + notes concatenation; offline outbox (encrypted, survives restart) |
| `a12_tamper_rollback.rs` | A12: tampered entry / member record, forged and altered manifests, known-version rollback (writes stopped, resumes after restore), revoked device return (wiped, cannot open new epoch or author), resurrected tombstone (rejected, forged resurrection rejected, explicit restore) |
| `a13_recovery.rs` | A13: recovery key on a fresh device, wrong / mistyped keys rejected, revoke lost device, recovery after rotation, replacing the recovery key, recovery via a second trusted device; A14: master password + offline unlock / export |
| `pairing_and_approvals.rs` | pairing happy path, substituted QR (MITM) caught by SAS, expired QR, executor pairing (no VMK, no storage secret), approval digest + signature checked with `aipass_types::approval::verify_decision`, credential envelope opened by the executor, narrowing, expiry, control messages, relay inbox |
| `client_ops.rs` | masking / reveal / TOTP, lock / unlock, import / export / autofill / browser save, storage capability test + migration + backup-only refusal, concurrent commits + orphan objects, 90-day re-verification |
| `local_dir_e2e.rs` | real `LocalDirStore` via `StandardStoreFactory` + `FileSecretStore`: create, pair, restart, recover |
| `selfhost_http.rs` | `selfhost` profile against the real `aipass-sync-server` router (in-process): enroll-token `POST /v1/vaults` + idempotent genesis, save / sync / lock / unlock, single-use token refused |

## Limitations

* A brand-new device verifies the full manifest history from `vault.json` (no signed
  snapshot compaction yet) and cannot detect a storage rolled back *as a whole* without an
  independent checkpoint (design doc §10.4; pairing passes and checks the trusted device's
  checkpoint).
* Orphan objects of interrupted commits are skipped but not garbage-collected.
* On unlock the view is rebuilt from the local cache pinned by the checkpoint hash and the
  manifest signature (a local attacker with write access to the data directory is out of
  scope).
* `StandardStoreFactory` is exercised here with `LocalDirStore` and the HTTP sync API
  (in-process `aipass-sync-server`); `tests/e2e/run.sh` runs the selfhost profile, member
  pairing and the `RelayClient` adapter against a real `aipass-node`. S3 and WebDAV are not
  exercised against live services (their backends are tested in `aipass-storage`).
* Rotation tasks complete when the secret is changed on this device or are dismissed by the
  user; rotations done elsewhere are not detected.
* When an approval is requested while the credential entry has an unsynced local edit, the
  client syncs first; if offline it delivers the last committed version.

## Contract deviations

* **Additive API**: `StoreFactory` / `StoreContext` (how the facade builds storage backends
  and authenticates HTTP sync with the device — or, during recovery, the recovery member).
* **Behaviour**: `sync()` requires an unlocked vault (returns `LOCKED`), so a background
  sync never triggers a biometric prompt for the device key.
* **Behaviour**: new trusted devices paired by an owner become owners (QR `t=member`); see
  above.
* **Behaviour**: `recovery_kit_text()` contains the recovery key only while it is pending
  verification on this device; afterwards the kit says to use the saved copy.
* **Behaviour**: changing an existing master password rotates the key epoch (recovery wraps
  are immutable per epoch).
* Outbox format / AAD and the local data-directory layout are defined here (vault-format.md
  §6, §11).
