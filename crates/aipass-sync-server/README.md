<!-- SPDX-License-Identifier: Apache-2.0 -->
# aipass-sync-server

密文同步 API（CONTRACTS §3.3）与端到端中继邮箱（CONTRACTS §4）的可嵌入 axum 路由。
`aipass-node`（自托管）和商业云服务都挂载这两个路由。服务器只保存密文、签名元数据和
已封装的中继信封，从不持有账号库密钥。

Embeddable axum routers for the HTTP sync API (CONTRACTS §3.3) and the E2E relay mailbox
(CONTRACTS §4), used by `aipass-node` and the commercial cloud.

## Usage

```rust
let blobs = Arc::new(aipass_storage::LocalDirStore::open(data_dir.join("blobs"))?);
let sync = sync::SyncState::builder(blobs, Arc::new(sync::EnrollTokenAdmission::new()))
    .quota(Arc::new(sync::StaticQuota { max_bytes_per_vault: Some(1 << 30), max_objects_per_vault: None }))
    .build();
let relay = relay::RelayState::builder(
        Arc::new(relay::SqliteRelayStore::open(data_dir.join("relay.db"))?),
        Arc::new(relay::SyncDirectory::new(sync.clone())),
    )
    .push(Arc::new(relay::NoopPushNotifier))
    .nonce_cache(sync.nonce_cache())          // one replay cache for both routers
    .build();
let gc = relay::spawn_relay_gc(relay.clone(), Duration::from_secs(60)); // abort on shutdown
let app = Router::new().merge(sync_router(sync)).merge(relay_router(relay));
axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await?;
```

Serving with connect info enables the per-address pre-authentication rate limit. The
routers carry full paths (`/v1/vaults…`, `/v1/relay…`); signatures are verified over the
path + query the server receives, so a reverse proxy must not rewrite paths.

## Sync API (CONTRACTS §3.3)

| method | path | who | result |
| --- | --- | --- | --- |
| POST | `/v1/vaults` | `Bearer` checked by `VaultAdmission` | 201 `VaultInfo` |
| GET | `/v1/vaults/{vault_id}` | active member | `{vault_id, created_at, object_count, bytes_used, quota_bytes}` |
| GET | `/v1/vaults/{vault_id}/objects/{*key}` | active member (incl. executors) | bytes, `ETag: "<etag>"`, 404 |
| PUT | `/v1/vaults/{vault_id}/objects/{*key}` | active owner/member | 201 new / 200 replaced, `ETag`, body `{etag}`; 412 |
| GET | `/v1/vaults/{vault_id}/objects?prefix=&start_after=&limit=` | active member | `{objects:[ObjectMeta], truncated}` (limit ≤ 1000) |
| DELETE | `/v1/vaults/{vault_id}/objects/{*key}` | owner (immutable keys) / owner+member (mutable keys) | 204 |

* Blob layout over any `ObjectStore`: `vaults/<vault_id>/<key>`; membership index
  `index/devices/<device_id>/<vault_id>` (rebuild with `SyncState::rebuild_member_index`);
  server-wide device-key bindings `index/keys/<device_id>` (hex Ed25519 key, **first
  binding wins**: a member record or genesis carrying another key for an already bound
  device id is refused with `422`, in whichever vault it is uploaded); verified-manifest
  checkpoints `index/views/<vault_id>`.
* Auth: `AIPass-Sig`, kid `dev_…` or `exe_…` (`conn_…` and bearer tokens are refused),
  ±300 s skew, nonce replay cache (600 s, keyed by the verifying key, so kid aliases share
  one window), per-principal token bucket. Unknown principals,
  wrong keys, revoked members and non-existent vaults all answer the same
  `401 IDENTITY_UNVERIFIED`.
* **Member resolution** (`src/sync/members.rs`): the latest revision of
  `members/<device_id>/` decides; every record is verified up a signature chain to the
  self-signed genesis record named in `vault.json`; owner records must be signed by an
  owner; a member cannot self-promote; a self-signed later revision requires an active
  previous revision; the client transition rules apply to every revision (keys never
  change, a revoked device is never reinstated, role/status changes and any change to an
  owner's record need an owner signer, a first record is active) and on upload the signer
  must be active; older revisions are verified bottom-up; a damaged latest revision makes
  the device unknown (fail closed — a corrupted revocation never resurrects an older
  active record). The record's key must match the device's server-wide binding.
* **Manifest chain** (`src/sync/view.rs`): the server follows `manifests/<seq>` with the
  clients' own `verify_transition` and accepts a new manifest only as a valid transition
  from the latest verified one (author = active owner/member of the previous manifest,
  `prev_hash`, member rules …; otherwise `422`). A device is a member only when the latest
  manifest lists it (listed as revoked → denied; a pending revision can only reduce its
  role) or, during an in-flight commit, while the device that vouched for its record is
  itself an effective active owner/member — revoking a member therefore also cuts off
  every unlisted device it introduced.
  Results are cached for `member_cache_ttl` (10 s); writes through this server invalidate
  the vault immediately.
* **Executors**: role `executor` is read-only and signs only as `exe_<U>` when its member
  record id is `dev_<U>` (same ULID); the `dev_<U>` alias is refused.
* **Quota**: a write's usage delta is reserved atomically with the quota check (released
  if the write fails), so concurrent writes cannot overshoot within one process.
* **Immutability**: `vault.json`, `entries/ manifests/ members/ recovery/ keyring/` are
  create-only — any overwrite (with or without `If-Match`) is `412`. `vault.json` and
  `members/` can never be deleted.
* **Validation before storing**: member records (key ↔ content, signature chain,
  transition rules, key binding), manifests (key ↔ seq, full chain transition), entry versions, recovery
  wraps and keyring records (key ↔ content, vault id). `HEAD` ≤ 64 bytes.
* `POST /v1/vaults` stores the sub-object bytes **verbatim** (via `RawValue`), checks both
  signatures and the genesis shape, writes `vault.json` (commit point) then the genesis
  record, and is idempotent for an identical retry. Existing vault → `412`.
* `VaultAdmission` (pluggable): `EnrollTokenAdmission` (`aipe_…` tokens, stored as
  SHA-256, single/multi-use, optional expiry, refunded when creation fails),
  `DenyAllAdmission`. The cloud plugs session + `official_sync` entitlement
  (`PAYMENT_REQUIRED`) + account quota.
* `QuotaPolicy` (pluggable): `StaticQuota` per-vault bytes / objects → `429 QUOTA_EXCEEDED`.
  Usage is computed lazily from a listing and maintained incrementally (approximate under
  concurrent writes across instances).

## Relay (CONTRACTS §4)

| method | path | auth |
| --- | --- | --- |
| POST | `/v1/relay/{mailbox}` | sender `AIPass-Sig` sharing a vault with the mailbox owner, or `X-AIPass-Pairing-Secret` for `pair_…` → 202 `{message_id}` |
| GET | `/v1/relay/{mailbox}?after=&wait=0..25` | owner (`kid` = mailbox) or pairing secret → `{messages}` (≤ 100 per call; page with `after`) |
| DELETE | `/v1/relay/{mailbox}/{message_id}` | owner or pairing secret → 204 |

* `RelayStore`: `MemoryRelayStore`, `SqliteRelayStore` (rusqlite bundled, WAL, file `0600`,
  schema versioned with `user_version`). Message ids are strictly increasing ULIDs, so
  `after` keeps working after the cursor message was deleted.
* Limits: envelope ≤ 64 KiB, ≤ 500 live messages per mailbox (`429 RATE_LIMITED`,
  `details.reason = "mailbox_full"`), TTL 24 h, pairing mailboxes 10 min from first use,
  long-poll ≤ 25 s (≤ 4 concurrent waiters per mailbox), envelopes older than the TTL or
  more than 300 s in the future are refused. `spawn_relay_gc` removes expired data.
* Sender checks: `envelope.to` = mailbox, `envelope.from` = authenticated kid, envelope
  signature verified server-side with the sender's key (`422 INTEGRITY_FAILED`), sender and
  recipient must share a vault (`403 FORBIDDEN`). AI connections (`conn_…`) cannot use the
  relay.
* `RelayDirectory` (pluggable): `SyncDirectory` (vault memberships of the co-located sync
  server, revocations effective immediately on this server), `StaticDirectory` (explicit
  approver set, e.g. a node whose vault is on the user's own S3), `ChainDirectory`.
* Pairing mailboxes: the SHA-256 of the 16-byte secret is bound on first use (the new
  device starts polling right after showing its QR code) and compared in constant time
  afterwards.
* `PushNotifier` (pluggable) is invoked **only** with `PushHint {mailbox, message_id}`, only
  for `dev_…` mailboxes and only for `approval.request` / `connection.pair_request`:
  `NoopPushNotifier`, `LogPushNotifier`, `WebhookPushNotifier` (HTTPS, HMAC-SHA256 in
  `X-AIPass-Signature: v1=<hex>`). The cloud implements APNs / FCM behind the same trait.

### Metadata the relay can see (honest disclosure)

Payloads are HPKE-sealed to the recipient; the relay cannot open them. It **does** see the
envelope header — `from`, `to`, `type` (for example `approval.request`), `created_at` — and
message sizes, timing and the client's network address. The `type` is read only to decide
whether to send a push hint. The sync server likewise sees object keys, counts, sizes and
access times (keys contain entry ids and version numbers, never titles or usernames).

## Errors

Every error body is the §1.5 envelope
`{"error":{"code","message","details","request_id"}}` with zh-CN messages by default and
English when `Accept-Language` starts with `en`; `request_id` (`req_…`) is also sent as
`X-Request-Id`. Details carry only short machine reasons (`"nonce replay"`,
`"immutable"`, `"too_large"`, …), never bodies or secrets. axum's own `405 Method Not
Allowed` responses keep axum's empty body.

## Build / test

```bash
cd open-source
cargo build -p aipass-sync-server
cargo test  -p aipass-sync-server
```

`tests/sync_api.rs` (HttpSyncStore ↔ sync_router in-process over real TCP): vault creation
with enroll tokens (missing / wrong / reused token, existing vault, idempotent retry, forged
header), capability test → `sync_capable`, 12-writer create-only and compare-and-swap races
(exactly one winner), immutable overwrite refused, strangers / impostors / revoked members
refused, self-promotion and non-owner owner grants refused, executor read-only (both kid
forms), delete permissions, replayed / skewed / wrong-path / tampered-body signatures
refused, quota, size limits, bad input, ETag + `no-store`, index rebuild, tampered member
record fails closed.

`tests/relay_api.rs` (RelayClient ↔ relay_router): long-poll delivery and decryption, push
hook called with exactly `{mailbox, message_id}`, no push for other types / exe mailboxes,
cursor + ack, empty long-poll timeout, authorization rules (other vault, unknown device,
spoofed `from`, tampered envelope, non-owner read, revoked executor), relay replay, TTL
expiry + GC (manual clock), pairing mailbox secret (bind, mismatch, expiry), mailbox cap,
SQLite store end-to-end + persistence + monotonic ids, static directory.

All servers in tests bind `127.0.0.1:0` inside the test runtime and stop with it.

## Limitations

* Single-process state: the replay cache, rate limiters, member cache and long-poll
  wake-ups are in memory. Multi-instance deployments (cloud) need sticky routing for
  long-polls or a shared notifier, and revocations made through another instance take
  effect after `member_cache_ttl`. Nonces are per instance; ±300 s skew bounds replays
  across instances.
* The quota usage counter is approximate under concurrent writes from several instances.
* Relay message ids are monotonic per process (plus the SQLite floor on restart); several
  writers sharing one SQLite file would need a shared generator.
* Not independently security-audited.

## Contract deviations

* Clarification — executor kid: `exe_<U>` resolves to member record `dev_<U>` with role
  `executor` (MemberRecord ids are `DeviceId`s in `aipass-types`).
* Stricter than the contract: uploaded `members/`, `manifests/`, `entries/`, `recovery/`,
  `keyring/` objects are validated (400 / 422) before storage; owner records need an owner
  signer; members cannot self-promote.
* DELETE: immutable keys owner-only as specified; mutable keys (`HEAD`, scratch such as the
  capability test's `_aipass_captest/…`) may also be deleted by members (they can already
  overwrite them); `vault.json` and `members/` are never deletable (deleting a revocation
  would resurrect a device). Success is `204`.
* Additive: PUT returns body `{etag}` besides the `ETag` header; relay DELETE returns `204`;
  relay GET returns at most 100 messages per call.
* Object too large → `400 INVALID_REQUEST` with `details:{reason:"too_large", limit}` (there
  is no 413 code in §1.5).
* Vault already exists → `412 PRECONDITION_FAILED` (`details.reason = "vault_exists"`).
* Mailbox full → `429 RATE_LIMITED` (`details.reason = "mailbox_full"`).
* Pairing mailboxes bind their secret on first use (trust on first use by the new device).
