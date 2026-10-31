# AI 通行证 (AI Pass) — Cross-Component Contracts v1

Status: **binding** contract between every component in this monorepo. It refines
`AI_Credential_Manager_Design_v1.0.md` (the "design doc", cited as §x.y) into concrete
interfaces. If an implementation must deviate, it records the deviation in its component
README under "Contract deviations" and in its final report. Never silently change a shape
another component depends on.

---

## 0. Repository layout & ownership

```
passw/
├── AI_Credential_Manager_Design_v1.0.md   design baseline (do not edit)
├── README.md                              monorepo overview (zh-CN)
├── docs/                                  specs, architecture, threat model, acceptance map
│   └── spec/CONTRACTS.md                  this file
├── open-source/                           Apache-2.0 — 开源核心与后台
│   ├── Cargo.toml                         Rust workspace
│   ├── crates/
│   │   ├── aipass-types/      shared models, IDs, error codes, canonical JSON, request signing, approval digest, ExecutorBackend trait
│   │   ├── aipass-crypto/     AEAD, HPKE seal/open, Ed25519/X25519 identities, HKDF, Argon2id, RNG, zeroize
│   │   ├── aipass-vault/      Vault Core: key hierarchy, entries, members, manifests, recovery, generator, TOTP, import/export, pairing crypto
│   │   ├── aipass-storage/    ObjectStore trait + Memory / LocalDir / S3 / HttpSync / WebDAV backends + capability test
│   │   ├── aipass-sync/       client sync engine: manifests, checkpoints, rollback, tombstones, conflicts, outbox
│   │   ├── aipass-sync-server/ HTTP sync API + relay mailbox (axum Routers, embeddable)
│   │   ├── aipass-broker/     Access Broker: connections, policies, grants, approvals, operations state machine, budgets, revocation, audit, HTTP API
│   │   ├── aipass-executor/   Executor + connectors (postgres, github, http_api), egress guard, output filter
│   │   ├── aipass-client/     Rust HTTP client for the broker API (signing, UDS + TCP)
│   │   ├── aipass-mcp/        MCP bridge (stdio + Streamable HTTP) → binary `aipass-mcp`
│   │   ├── aipass-hostconfig/ AI host config wizard (Codex, Claude Code, Cursor, …)
│   │   ├── aipass-node/       self-host server → binary `aipass-node` (broker+executor+sync+relay+remote MCP)
│   │   ├── aipass-cli/        reference CLI / trusted client → binary `aipass`
│   │   └── aipass-ffi/        uniffi bindings for iOS / Android
│   ├── sdk/typescript/        @aipass/sdk
│   ├── sdk/python/            aipass (PyPI name aipass-sdk)
│   ├── deploy/                docker, systemd, examples (lure-store demo DB)
│   ├── desktop/               Tauri 2 (cross-platform: macOS / Windows / Linux) + React; embeds broker+executor; native-messaging host
│   │                          (own Cargo workspace in desktop/src-tauri, excluded from open-source/Cargo.toml)
│   └── test-vectors/          JSON test vectors (crypto, signing, digest, vault)
├── clients/                               Proprietary — 商业客户端
│   ├── ios/                   SwiftUI app + Credential Provider Extension + AIPassKit Swift package
│   ├── android/               Kotlin / Compose app + AutofillService + CredentialProviderService
│   └── browser-extension/     Chromium MV3 extension (TypeScript)
├── cloud/                                 Proprietary — 付费后台（官方云服务）
│   ├── server/                Rust axum → binary `aipass-cloud`
│   └── console/               React web console (account, billing, devices, connections, team, admin)
└── website/                               产品官网 (Astro, zh-CN + en)
```

Ownership rule: an agent writes only inside the directories it owns. Shared files
(`open-source/Cargo.toml` workspace members / `[workspace.dependencies]`) are created by
the foundation step; later agents may *append* a dependency line to their own crate's
`Cargo.toml` but must not reorganise the workspace.

License header: every source file under `open-source/` (including the desktop app in
`open-source/desktop/`) starts with `// SPDX-License-Identifier: Apache-2.0` (or the language's
comment equivalent). Files under `clients/` and `cloud/` use
`// Proprietary — © AI Pass. All rights reserved.`

---

## 1. Conventions

### 1.1 IDs
`<prefix>_<ulid lowercase>` (26 Crockford base32 chars), e.g. `res_01jbz3k6w8a7m2q4t5v9x0y1z2`.

| prefix | object | prefix | object |
| --- | --- | --- | --- |
| `vlt` | vault | `grt` | grant |
| `ent` | vault entry | `apr` | approval request |
| `dev` | trusted device (phone/desktop/CLI) | `op` | operation |
| `exe` | executor node | `lse` | lease |
| `conn` | app connection (AI host) | `evt` | audit event |
| `res` | resource | `msg` | relay message |
| `proj` | project | `pair` | pairing session |
| `pol` | policy | `usr` `org` `sub` `inv` `inc` `oac` `ses` | cloud objects |

Parsers validate the prefix. IDs are not capabilities: possessing an ID never authorises anything (§12.1).

### 1.2 Encoding
Binary values in JSON are **base64url without padding** ("b64u"). Hash = SHA-256. Raw 32-byte keys are b64u.

### 1.3 Time
RFC 3339 UTC with `Z` (`2026-10-30T12:00:00Z`), second precision in anything signed. Signature headers use unix seconds.

### 1.4 Canonical JSON
RFC 8785 (JCS). Signed or hashed payloads contain only strings, integers (|n| < 2^53), booleans, null, arrays and objects (no floats). Implemented once in `aipass_types::canonical::to_jcs_bytes`. Only Rust code computes digests; mobile goes through FFI, TS/Python never compute approval digests.

### 1.5 Error envelope and codes
Every HTTP error body:
```json
{"error":{"code":"SCOPE_DENIED","message":"超出本次授权范围","details":{},"request_id":"req_01j..."}}
```
`message` is zh-CN by default, English when `Accept-Language` starts with `en`.

| code | HTTP | meaning |
| --- | --- | --- |
| `IDENTITY_UNVERIFIED` | 401 | signature/token invalid, unknown or unpaired principal |
| `UNAUTHENTICATED` | 401 | (cloud) missing/invalid session |
| `FORBIDDEN` | 403 | principal not allowed to call this endpoint |
| `CONNECTION_PAUSED` | 403 | user paused this AI app |
| `APPROVAL_REQUIRED` | 202 | only as SDK exception when caller disabled waiting; API returns it as a status |
| `APPROVAL_DENIED` | 403 | user denied |
| `APPROVAL_EXPIRED` | 410 | approval window passed — never auto-approved |
| `GRANT_EXPIRED` | 403 | |
| `GRANT_REVOKED` | 403 | |
| `BUDGET_EXHAUSTED` | 403 | grant row/request/byte budget used up |
| `SCOPE_DENIED` | 403 | outside policy/grant scope, or capability not offered |
| `EXECUTOR_OFFLINE` | 503 | no online executor ("执行设备离线") |
| `CONTROL_CHANNEL_LOST` | 503 | executor lost its control channel; new operations denied |
| `SECRET_UNAVAILABLE` | 409 | credential not delivered to executor / vault locked |
| `SYNC_CONFLICT` | 409 | entry has unresolved conflict; automatic use paused |
| `PRECONDITION_FAILED` | 412 | conditional write failed |
| `ROLLBACK_DETECTED` | 409 | storage older than known checkpoint |
| `INTEGRITY_FAILED` | 422 | signature / hash / AEAD failure |
| `INTERACTIVE_AUTH_REQUIRED` | 409 | upstream needs re-login / OAuth re-consent (never ask for secrets in chat) |
| `RESULT_RESTRICTED` | 403 | whole result withheld by output policy (partial redaction is a result flag) |
| `UPSTREAM_OUTCOME_UNKNOWN` | 502 | external service may have executed; verify before retrying |
| `UPSTREAM_ERROR` | 502 | |
| `IDEMPOTENCY_CONFLICT` | 409 | same idempotency key, different normalized parameters |
| `RATE_LIMITED` | 429 | includes throttling after a denial |
| `NOT_FOUND` | 404 | also returned for objects owned by another principal (no existence leak) |
| `INVALID_REQUEST` | 400 | |
| `NOT_SUPPORTED` | 501 | |
| `PAYMENT_REQUIRED` | 402 | (cloud) entitlement missing |
| `QUOTA_EXCEEDED` | 429 | (cloud) |
| `INTERNAL` | 500 | |

### 1.6 Request signing (`AIPass-Sig`)
```
Authorization: AIPass-Sig kid=<principal id>, ts=<unix seconds>, nonce=<b64u 16 bytes>, sig=<b64u 64 bytes>
```
String to sign — UTF-8, joined by `\n`, no trailing newline:
```
AIPASS-SIG-V1
<METHOD upper-case>
<path + query exactly as sent>
<ts>
<nonce>
<b64u(SHA-256(raw body bytes))>        (empty body → hash of empty string)
```
Ed25519 over those bytes. Verifier: `|now − ts| ≤ 300 s`; nonce unique per kid for 600 s; kid resolves to an active principal (`conn_` → AppConnection key; `dev_` → active vault member device; `exe_` → node key).

Bearer alternatives: `aipc_<b64u 32B>` (node-issued connection token for remote MCP / SDK), `aipa_…` / `aipr_…` (cloud OAuth access / refresh), `aips_…` (cloud session). Stored only as SHA-256 hashes.

**Test vector** (all implementations — Rust, TypeScript SDK, Python SDK — must reproduce exactly; also stored as `open-source/test-vectors/request-signing.json`):
```json
{
  "seed": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
  "public_key": "A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg",
  "kid": "conn_01jbz3k6w8a7m2q4t5v9x0y1z4",
  "ts": 1793318400,
  "nonce": "qqqqqqqqqqqqqqqqqqqqqg",
  "cases": [
    {
      "method": "POST",
      "path": "/v1/operations",
      "body": "{\"resource_id\":\"res_01jbz3k6w8a7m2q4t5v9x0y1z2\",\"operation\":\"postgres.query_view\",\"parameters\":{\"view\":\"analytics.subscription_daily\",\"fields\":[\"day\",\"plan\",\"subscriptions\"],\"period_days\":30},\"idempotency_key\":\"subscription-summary-request-001\"}",
      "body_sha256": "xR8hGf1lWFHmtsMZF81X1VBrAPQQyuFe2wpLmxcaLjE",
      "string_to_sign": "AIPASS-SIG-V1\nPOST\n/v1/operations\n1793318400\nqqqqqqqqqqqqqqqqqqqqqg\nxR8hGf1lWFHmtsMZF81X1VBrAPQQyuFe2wpLmxcaLjE",
      "signature": "bkY5XhOuTqE-0g0GA_J5SPOZgk67xYrVj77Koc0EBsWGH-APHWHBuGx1MojhxBSiYyV4Cj2Llu1xmAyRITt1Aw"
    },
    {
      "method": "GET",
      "path": "/v1/resources?project_id=proj_01jbz3k6w8a7m2q4t5v9x0y1z3",
      "body": "",
      "body_sha256": "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU",
      "string_to_sign": "AIPASS-SIG-V1\nGET\n/v1/resources?project_id=proj_01jbz3k6w8a7m2q4t5v9x0y1z3\n1793318400\nqqqqqqqqqqqqqqqqqqqqqg\n47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU",
      "signature": "z-FXrTabpsAztih0b7vQ-r9wqLCSnkTZtGHBrGgL9U5aT6Nt4usP6qgRQb_FBzyl_DQ0xrNb0oSuphvOvmOjDg"
    }
  ]
}
```
(`seed` is the 32-byte Ed25519 private seed 0x00..0x1f.)

### 1.7 Ports, paths, binaries, env
| item | value |
| --- | --- |
| `aipass-node` HTTP | `0.0.0.0:7878` (dev `127.0.0.1:7878`) — broker `/v1/*`, sync `/v1/vaults*`, relay `/v1/relay*`, remote MCP `/mcp` |
| local broker (desktop / `aipass node`) | UDS `<AIPASS_HOME>/run/broker.sock` (0600) + optional TCP `127.0.0.1:7878` |
| `aipass-mcp` local HTTP | `127.0.0.1:7879` |
| `aipass-cloud` | `127.0.0.1:8787` |
| console dev | `5173` (Vite proxies `/v1`, `/oauth`, `/.well-known`, `/mcp` → 8787) |
| website dev | `4321` |
| desktop UI dev | `1420` |
| test Postgres | `55432` (executor/e2e), `55433` (cloud tests) — temp clusters via Homebrew `initdb` |

Env vars: `AIPASS_HOME` (default `~/.aipass`), `AIPASS_BROKER_URL` (`unix:///abs/path.sock` or `http(s)://host:port`), `AIPASS_LOG` (tracing filter), `AIPASS_CLOUD_URL` (default `https://cloud.aipass.example`).
Placeholder domains (name/domain not yet verified, design doc header): website `https://aipass.example`, cloud `https://cloud.aipass.example`, console `https://console.aipass.example`.
Binaries: `aipass` (CLI), `aipass-mcp`, `aipass-node`, `aipass-cloud`, `aipass-nm-host` (desktop native-messaging host).

---

## 2. Crypto primitives & vault format

### 2.1 Primitives (`aipass-crypto`) — mature libraries only, no home-made algorithms (§9.4)
- AEAD: **XChaCha20-Poly1305**, 24-byte random nonce (`chacha20poly1305` crate).
- Signatures: **Ed25519** (`ed25519-dalek` 2.x).
- Sealing to a public key: **HPKE RFC 9180 base mode**, suite DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / ChaCha20-Poly1305 (`hpke` crate). `SealedBox { enc: b64u, ct: b64u }`. `info` strings are namespaced `aipass/v1/<purpose>`.
- KDF: HKDF-SHA256. Password KDF: **Argon2id** m=65536 KiB, t=3, p=1, 16-byte salt, 32-byte output.
- RNG: OS CSPRNG only. Secrets wrapped in `zeroize`/`secrecy` types; never `Debug`-printed.
- Device identity = Ed25519 signing keypair + X25519 KEM keypair. `DevicePublic { device_id, name, platform, role, sign_pk, kem_pk }`.

### 2.2 Key hierarchy
- **VMK** (vault master key): 32 random bytes, per `key_epoch` (u32, starts at 1; incremented on member revocation / rotation).
- **DEK**: 32 random bytes per entry *version*.
- VMK is HPKE-sealed separately to each owner/member device (`info=aipass/v1/vmk-wrap`, `aad=aipass:v1:vmk:{vault_id}:{device_id}:{key_epoch}`). Executors never receive the VMK.
- Recovery: 32-byte recovery secret → `KEK = HKDF(ikm=secret, salt=vault_id bytes, info="aipass/v1/recovery-kek")`; optional master password → Argon2id KEK. Each wraps the VMK with XChaCha20-Poly1305. Subscription password / email login / passkey ID never derive vault keys (§9.4).

### 2.3 Storage objects (keys relative to the vault root; JSON UTF-8)
| key | object | mutability |
| --- | --- | --- |
| `vault.json` | `VaultHeader {format:1, vault_id, created_at, genesis_device_id, signature}` (signed by genesis device) | immutable |
| `members/<device_id>/<rev>.json` | `MemberRecord` | immutable (new rev per change) |
| `recovery/<key_epoch>-<kind>.json` | `RecoveryWrap {format, vault_id, key_epoch, kind:"recovery_key"\|"master_password", kdf, nonce, wrapped_vmk}` aad=`aipass:v1:recovery:{vault_id}:{key_epoch}:{kind}` | immutable |
| `keyring/<key_epoch>.json` | previous epochs' VMKs encrypted under VMK[epoch], aad=`aipass:v1:keyring:{vault_id}:{key_epoch}` | immutable |
| `entries/<entry_id>/<version>.json` | `EntryVersion` | immutable |
| `manifests/<seq zero-padded 12>.json` | `Manifest` — **create-only write = commit point** | immutable |
| `HEAD` | text seq number — untrusted hint | mutable |

`MemberRecord {format:1, vault_id, device_id, rev, name, platform:"ios"|"android"|"macos"|"windows"|"linux"|"cli"|"node", role:"owner"|"member"|"executor", sign_pk, kem_pk, status:"active"|"revoked", key_epoch, wrapped_vmk: SealedBox|null, added_by, created_at, signature}` — signed by `added_by` (an active owner/member); genesis record self-signed.

`EntryVersion {format:1, vault_id, entry_id, version, key_epoch, dek_nonce, wrapped_dek, nonce, ciphertext, author_device_id, created_at}`
- `wrapped_dek = XChaCha20Poly1305(VMK[key_epoch], dek_nonce, DEK, aad="aipass:v1:dek:{vault_id}:{entry_id}:{version}:{key_epoch}")`
- `ciphertext = XChaCha20Poly1305(DEK, nonce, JCS(EntryPayload), aad="aipass:v1:entry:{vault_id}:{entry_id}:{version}:1")`

`EntryPayload` (plaintext only inside ciphertext — titles, usernames, URLs, notes are encrypted by default, §10.3):
```json
{"kind":"login|api_key|database|oauth_token|ssh_key|secure_note|storage_credential",
 "title":"", "username":null, "secret":null, "urls":[], "notes":null,
 "totp":{"secret":"BASE32","algorithm":"SHA1|SHA256|SHA512","digits":6,"period":30},
 "fields":[{"name":"","value":"","sensitive":true}],
 "database":{"engine":"postgres","host":"","port":5432,"dbname":"","sslmode":"require"},
 "project_id":null, "tags":[],
 "lifecycle":"imported|verified|needs_attention|pending_registration|retired",
 "source":"manual|generated|import:<format>", "password_rules":null,
 "created_at":"", "updated_at":""}
```
Secret-bearing fields: `secret`, `totp`, `fields[sensitive=true]`.

`Manifest {format:1, vault_id, seq, prev_hash, key_epoch, entries:{entry_id:{version, hash, conflict_versions:[]}}, tombstones:{entry_id:{version, deleted_at}}, members:{device_id:{rev, hash, status, role}}, author_device_id, created_at, signature}`
- `hash` / `prev_hash` = b64u(SHA-256(object file bytes)); `prev_hash=""` for seq 1.
- `signature` = Ed25519(author, JCS(manifest minus `signature`)). Author must be an active owner/member in the previous manifest (seq 1: genesis). Executors never author manifests.
- Each device keeps a **checkpoint** `{vault_id, seq, hash}` of the newest verified manifest.

### 2.4 Recovery key & kit
Recovery key = 32 random bytes ‖ first 2 bytes of SHA-256(those 32) → Crockford base32 → `AIPR-` + groups of 4 joined by `-`. Parsing ignores case/spaces/dashes, maps O→0, I/L→1, verifies checksum.
Recovery kit (generated locally, never uploaded): vault_id, recovery key, created_at, storage profile (kind/endpoint/bucket/prefix/region; access keys only if the user opts in — avoids the circular dependency in §10.5), zh/en instructions. Clients must run a **recovery verification** (user re-enters the key) and track `recovery_verified_at`.

### 2.5 Export
- Encrypted export `.aipassx`: `{format:"aipass-export-1", created_at, kdf:{alg:"argon2id",m,t,p,salt}, nonce, ciphertext}` of JCS `{vault_id, entries:[{entry_id, version, payload}]}`.
- CSV export `title,url,username,password,notes,totp,kind` — requires re-authentication and shows the plaintext-file risk warning (§6.1). Exports are never offered to AI.

### 2.6 Password generator
`PasswordRules {length 8..=128 (default 20), lower, upper, digits, symbols (default true), symbol_set (default "!@#$%^&*()-_=+[]{};:,.?"), exclude_ambiguous (default false; "Il1O0o"), require_each_class (default true)}` + parser for the Apple `passwordrules` attribute syntax (`minlength`, `maxlength`, `required`, `allowed`, `max-consecutive`). Uniform rejection sampling from OS CSPRNG. **Models never generate passwords** (§6.2).

### 2.7 TOTP
RFC 6238 (SHA1/SHA256/SHA512, 6/8 digits, period), `otpauth://` URI parsing.

### 2.8 CSV import
Formats `chrome`, `firefox`, `safari`, `bitwarden`, `1password`, `lastpass`, `generic` (header auto-map). `ImportReport {imported, duplicates:[{existing_entry_id, title, username, url}], skipped:[{row, reason}]}`. Dedup key = (registrable domain of first URL, lower-case username). Imported entries have `lifecycle:"imported"` (not "verified", §6.1). Import runs locally only; clients show the "delete the CSV" guidance without promising secure deletion on SSDs.

---

## 3. Storage & sync

### 3.1 `aipass-storage` trait
```rust
pub struct Object { pub bytes: Vec<u8>, pub etag: String }
pub struct ObjectMeta { pub key: String, pub etag: String, pub size: u64, pub modified_at: Option<DateTime<Utc>> }
pub enum PutCondition { None, IfAbsent, IfMatch(String) }
pub enum PutOutcome { Written { etag: String }, PreconditionFailed }
#[async_trait]
pub trait ObjectStore: Send + Sync {
    async fn get(&self, key: &str) -> Result<Option<Object>, StorageError>;
    async fn put(&self, key: &str, bytes: Vec<u8>, cond: PutCondition) -> Result<PutOutcome, StorageError>;
    async fn delete(&self, key: &str) -> Result<(), StorageError>;
    async fn list(&self, prefix: &str, start_after: Option<&str>, limit: usize) -> Result<Vec<ObjectMeta>, StorageError>; // lexicographic
    fn describe(&self) -> StorageDescription; // kind + endpoint, never secrets
}
pub async fn capability_test(store: &dyn ObjectStore, scratch_prefix: &str) -> CapabilityReport;
// CapabilityReport { read, write, list, conditional_create, conditional_update, delete, roundtrip: bool, verdict: "sync_capable"|"backup_only", details: Vec<String> }
```
Backends: `MemoryStore` (tests), `LocalDirStore` (O_EXCL/hard-link create, etag = b64u sha256), `S3Store` (SigV4, path-style or virtual-host, `If-None-Match: *` / `If-Match`, ListObjectsV2, static or session credentials), `HttpSyncStore` (§3.3, device-signed), `WebDavStore` (V1.1; PROPFIND, conditional PUT; capability test decides). A backend whose conditional writes fail the capability test is **backup only** (§10.1–10.2).

`StorageProfile` (non-secret, persisted): `{kind:"local"|"official"|"s3"|"webdav"|"selfhost", endpoint?, region?, bucket?, prefix?, path_style?, base_url?, username?, credential_ref?, verdict?, tested_at?}`. Storage secrets live in the platform secret store and (copy) in a `storage_credential` vault entry; a storage key is **never** automatically an AI resource (§10.2).

### 3.2 Sync engine (`aipass-sync`)
- Pull: list `manifests/` after checkpoint, verify signature chain, `prev_hash`, author membership; `latest.seq < checkpoint.seq` or hash mismatch at checkpoint seq → `ROLLBACK_DETECTED` (refuse to write).
- Push: write entry versions (`IfAbsent`), then `manifests/<seq+1>` (`IfAbsent`). `PreconditionFailed` → pull, rebase, retry (bounded).
- Conflict: 3-way merge per field against the base version. Secret-bearing field changed on both sides with different values → keep remote as current, append local version to `conflict_versions`; entry auto-use is **paused** (broker, autofill and extension must refuse entries with non-empty `conflict_versions` → `SYNC_CONFLICT`) until a trusted client resolves. Non-secret conflicting fields: remote wins; if both edited `notes`, concatenate with a `--- 冲突副本 / conflict copy ---` marker.
- Tombstones: deletion moves the entry to `tombstones`; writes for a tombstoned entry with `version ≤ tombstone.version` are rejected; restore = explicit new version.
- Offline limit: last successful sync older than 90 days → re-verify own membership before pushing.
- Revocation: owner writes revoked MemberRecord rev, bumps `key_epoch`, seals new VMK to remaining members, writes keyring; future versions use the new epoch; client offers rotation tasks for long-term credentials the revoked device could read (§10.4).
- Outbox persisted locally (encrypted) for offline edits (§10.6).

### 3.3 HTTP Sync API (`aipass-sync-server`, embedded by `aipass-node` and `aipass-cloud`)
Auth: `AIPass-Sig` with `kid=dev_…`/`exe_…` that is an active member of the vault (server reads `members/` records; executors may only read). Max object 4 MiB.

| method | path | notes |
| --- | --- | --- |
| POST | `/v1/vaults` | body `{vault_header, genesis_member}`; `Authorization: Bearer <enroll token (self-host) \| aips_ session (cloud)>`; server verifies both signatures |
| GET | `/v1/vaults/{vault_id}` | `{vault_id, created_at, object_count, bytes_used, quota_bytes}` |
| GET | `/v1/vaults/{vault_id}/objects/{*key}` | bytes, `ETag: "<etag>"`; 404 |
| PUT | `/v1/vaults/{vault_id}/objects/{*key}` | `If-None-Match: *` or `If-Match: "<etag>"`; 201/200 + ETag; 412 `PRECONDITION_FAILED`. Keys under `entries/ manifests/ members/ recovery/ keyring/` are immutable: overwrite → 412 regardless of headers |
| GET | `/v1/vaults/{vault_id}/objects?prefix=&start_after=&limit=` | `{objects:[ObjectMeta], truncated}` |
| DELETE | `/v1/vaults/{vault_id}/objects/{*key}` | owner-role only (GC) |

---

## 4. Relay mailbox (E2E store-and-forward)
Mounted at `/v1/relay` by the same crate. The server only ever sees sealed envelopes (§4.3 design doc).

| method | path | auth |
| --- | --- | --- |
| POST | `/v1/relay/{mailbox}` | sender `AIPass-Sig` (member/executor sharing a vault with the mailbox owner) or `X-AIPass-Pairing-Secret` for `pair_` mailboxes → 202 `{message_id}` |
| GET | `/v1/relay/{mailbox}?after=<message_id>&wait=<0..25>` | owner `AIPass-Sig` (kid = mailbox id) or pairing secret; long-poll → `{messages:[{message_id, received_at, envelope}]}` |
| DELETE | `/v1/relay/{mailbox}/{message_id}` | owner |

Mailbox id = principal id (`dev_…`, `exe_…`) or `pair_…`. TTL 24 h (pairing 10 min); ≤ 500 messages/mailbox; envelope ≤ 64 KiB. On a new message for a `dev_` mailbox whose type is `approval.request` or `connection.pair_request`, the server calls its `PushNotifier` (cloud: APNs/FCM; node: none/webhook) with **only** `{mailbox, message_id}` — never details or secrets (§9.2, §11.4).

`RelayEnvelope {v:1, from, to, type, created_at, sealed: SealedBox, sig}` — `sealed` = HPKE to recipient `kem_pk` (`info=aipass/v1/relay`, `aad=JCS({v,from,to,type,created_at})`); `sig` = Ed25519(sender, JCS(envelope minus sig)).

Inner message types (plaintext after open):
| type | direction | payload |
| --- | --- | --- |
| `approval.request` | broker → device | `ApprovalRequest` (§6.1) |
| `approval.decision` | device → broker | `ApprovalDecision` |
| `approval.cancelled` | broker → device | `{approval_request_id, reason}` |
| `connection.pair_request` | broker → device | `{connection: AppConnection, pairing_code}` |
| `connection.decision` | device → broker | `{connection_id, decision, allowed_projects, signed_at, signature}` |
| `grant.revoke` | device → broker | `{grant_id, level, signed_at, signature}` |
| `connection.control` | device → broker | `{connection_id, action:"pause"\|"resume"\|"remove"\|"revoke_all", signed_at, signature}` |
| `state.request` / `state.snapshot` | device ↔ broker | snapshot = `{connections, grants, executors, pending_approvals, recent_operations, activity_summary}` |
| `revoke.report` | broker → device | `RevocationReport` |
| `pairing.hello` / `pairing.join` / `pairing.welcome` | §5 | |

Device control messages are signed over `aipass:v1:control:<b64u sha256 JCS(payload minus signature)>`.

---

## 5. Device / executor pairing (§9.5)
QR / link shown by the **new** device (desktop, node or second phone):
`aipass://pair?v=1&p=<pairing_id>&s=<b64u 16B secret>&k=<b64u ephemeral X25519 pk>&r=<urlencoded relay base URL>&n=<urlencoded name>&t=<member|executor>&e=<expiry unix>`
1. New device N creates its DeviceIdentity + ephemeral `eN`; QR TTL 10 min.
2. Existing trusted device O scans, creates `eO`; `shared = X25519(eO, eN)`; `th = SHA-256(JCS({pairing_id, eN, eO, relay}))`; `K = HKDF(shared, salt=th, info="aipass/v1/pairing-key")`; **SAS** = 6 digits = `u32_be(HKDF(shared, salt=th, info="aipass/v1/pairing-sas")[0..4]) mod 1_000_000`, zero-padded.
3. O → mailbox `pairing.hello {eO, o_device: DevicePublic, sealed: XChaCha20(K, {vault_id, o_name})}`.
4. N → mailbox `pairing.join {sealed: XChaCha20(K, {device: DevicePublic})}`.
5. Both show the SAS + peer name; the user confirms **on O** (trusted device). Scanning alone never grants access.
6. O writes N's MemberRecord (`wrapped_vmk` sealed to N; `null` for executors) + manifest, then sends `pairing.welcome {sealed: XChaCha20(K, {vault_id, member_rev, checkpoint, storage_profile, storage_secret?, relay_base_url, trusted_devices:[DevicePublic]})}`.
7. N verifies `vault.json` signature, member chain and checkpoint, then syncs. Executors store `trusted_devices` as their approver set.

The QR never carries the VMK or long-term keys.

---

## 6. Access Broker (`aipass-broker`)
`Broker` (SQLite via rusqlite, file `<data>/broker.db`) + `router(state) -> axum::Router`. Executes through `aipass_types::exec::ExecutorBackend` (§8) so it does not depend on connector crates. Embedded by `aipass-node`, the desktop app and `aipass node` (CLI).

### 6.1 Models (serde shapes; Rust types live in `aipass-types`)
- `AppConnection {connection_id, host_type:"codex"|"claude_code"|"cursor"|"chatgpt"|"claude_connector"|"sdk"|"custom", display_name, transport:"stdio"|"http"|"sdk"|"remote_gateway", status:"pending"|"active"|"paused"|"removed", public_key?, allowed_projects:[proj_…]|["*"], created_at, approved_at?, approved_by?, last_seen_at?}` — `display_name`/`clientInfo.name` are labels, never identity (§7.3).
- `Project {project_id, name}`
- `Resource {resource_id, alias, service, connector:"postgres"|"github"|"http_api", project_id, environment:"test"|"production", config:{…no secrets…}, credential_entry_id, executor_id, operations:[name], status:"available"|"needs_login"|"sync_conflict"|"executor_offline"|"disabled", created_at}`
- `GrantScope {operations:[name], postgres?:{views:{"schema.view":[field]}}, github?:{repos:["owner/name"]}, http_api?:{operations:[name]}}`
- `Limits {max_rows_per_operation, max_rows_per_grant, max_requests_per_grant, max_result_bytes}` (integers; defaults 1000 / 5000 / 20 / 262144)
- `Policy {policy_id, version, subject_connection_id, project_id, resource_id, executor_id, allowed_operations, allowed_views, allowed_fields, scope: GrantScope, limits: Limits, grant_ttl_seconds, approval_mode:"once"|"task"|"rule", auto_approve, on_control_channel_lost:"deny_new_operations", output_recipients:[conn_…], status, created_at, signed_by, signature}` — superset of the design doc §8.2 example (flat fields kept for compatibility). `auto_approve` only valid for `rule` + `environment:"test"` + read-only operations.
- `ApprovalRequest {approval_request_id, kind:"operation"|"access", connection:{connection_id, display_name, host_type, verified:true}, resource:{resource_id, alias, service, environment}, summary:{zh, en}, requested:{operations, scope, limits, duration_seconds, mode}, executor:{executor_id, name, protection_level}, recipients:[{connection_id, display_name}], status:"pending"|"approved"|"denied"|"expired"|"cancelled", created_at, expires_at, operation_id?}` — render exactly the fields of design doc §5.3.
- `ApprovalDecision {approval_request_id, decision:"approve"|"deny", approved?:{operations, scope, limits, duration_seconds, mode}, expires_at, digest, signer_device_id, signed_at, signature, credential_envelope?: SealedBox}` — `approved ⊆ requested` (user may narrow); `credential_envelope` = HPKE to executor `kem_pk`, `info=aipass/v1/credential`, `aad=JCS({approval_request_id, digest, executor_id})`, plaintext `CredentialMaterial {entry_id, version, kind, username?, secret, database?, expires_at}`.
- `Grant {grant_id, approval_request_id?, policy_id?, policy_version?, connection_id, resource_id, executor_id, scope, limits, mode, digest, status:"active"|"expired"|"revoked"|"exhausted"|"released", usage:{requests, rows, bytes}, created_at, expires_at, revoked_at?, revocation?: RevocationReport}`
- `Operation {operation_id, connection_id, resource_id, operation, parameters_digest, idempotency_key, status, grant_id?, approval_request_id?, result?: OperationResult, error?, side_effects:"none"|"possible"|"applied", created_at, updated_at}`
- `OperationResult {data, rows?, truncated, restricted, restricted_fields:[name]}`
- `RevocationReport {grant_id, stop_access:{status, detail?}, end_sessions:{status, detail?}, revoke_upstream:{status, detail?}, completed_at?}` — status ∈ `done|pending|failed|not_applicable`. UI says "全部已收回" only when every level is `done`/`not_applicable` (§8.4).
- `Lease {lease_id, grant_id, kind, upstream_ref, expires_at, revoke_status}`
- `AuditEvent {seq, event_id, ts, actor, action, resource_id?, operation_id?, grant_id?, outcome, error_code?, detail:{…no secrets, no result bodies…}, prev_hash, hash}`; `hash = b64u(SHA-256(prev_hash_bytes ‖ JCS(event minus hash)))`.
- `ExecutorInfo {executor_id, name, protection_level:"isolated"|"compatible", capabilities:[connector], online, last_heartbeat_at?, sign_pk, kem_pk}` — UI labels 隔离执行 / 兼容连接 (§9.3). Desktop-embedded executor is always `compatible`; `isolated` only when the node operator attests a separate host/VM.

### 6.2 Operation state machine (§12.3)
`received → policy_checked → (awaiting_approval | authorized | denied)`; `awaiting_approval → authorized | denied | expired | cancelled`; `authorized → running | cancelled | failed`; `running → succeeded | failed | unknown | cancelled`. Terminal: `succeeded failed unknown denied expired cancelled`. The API shows `awaiting_approval` as `"approval_required"`.

Processing rules, re-checked on **every** operation:
1. Authenticate connection; status active (else `IDENTITY_UNVERIFIED` / `CONNECTION_PAUSED`).
2. Idempotency `(connection_id, idempotency_key)`: same `parameters_digest` → return the existing operation; different → `IDEMPOTENCY_CONFLICT`.
3. Resource must be visible to the connection (`allowed_projects`) else `NOT_FOUND`; entry with conflicts → `SYNC_CONFLICT`.
4. `ExecutorBackend::normalize` (schema validation, allowlist) → `INVALID_REQUEST` / `SCOPE_DENIED`.
5. Find an active, unexpired, unrevoked grant for (connection, resource, executor) whose scope covers the normalized request and whose budget remains → authorized. Else a signed `rule` policy with `auto_approve` → create grant, audit `rule.auto_approved`. Else throttled? (same connection+resource+operation denied < 10 min ago, or > 5 pending approvals for the connection) → `RATE_LIMITED`. Else create `ApprovalRequest` (TTL 120 s for operations, 600 s for access requests), notify trusted devices (relay + in-process listeners), return `approval_required`. **Never block waiting for the phone; never approve on timeout.**
6. Run: executor online (else `EXECUTOR_OFFLINE`), control channel ok (else `CONTROL_CHANNEL_LOST`), credential installed (else `SECRET_UNAVAILABLE`). Increment request usage before, row/byte usage after; cumulative limits per grant defeat pagination/concurrency bypass (A08).
7. Output passes the executor's output filter; outcome uncertain after send → `unknown` + `UPSTREAM_OUTCOME_UNKNOWN`; only retry when the connector marks the op `retry_safe`.
- Approvals bind to the digest (§7): any change to resource, view, fields, operation, executor or recipients needs a new approval (A05).
- `once` grants serve one operation; `task` grants serve the same connection+scope until expiry (default TTL 900 s, max 24 h).
- Revocation: `stop_access` (reject new + queued), `end_sessions` (cancel running ops, close connector sessions, drop installed credentials), `revoke_upstream` (lease revoke where supported). Each higher level includes lower ones. In-process target ≤ 5 s (A09).

### 6.3 HTTP API (prefix `/v1`, JSON)
Auth: **C** = AppConnection (`AIPass-Sig kid=conn_…` or `Bearer aipc_…`); **D** = trusted device (`AIPass-Sig kid=dev_…`, active owner/member); **A** = local admin (UDS peer, or `Bearer` token from `<data>/admin.token`, 0600); **P** = public (rate-limited).

| method | path | auth | request → response |
| --- | --- | --- | --- |
| POST | `/connections/pair` | P | `{host_type, display_name, transport, public_key}` → 201 `{pairing_request_id, connection_id, pairing_code, expires_at}` |
| GET | `/connections/pair/{pairing_request_id}` | P + signed by the pending key | → `{status:"pending"\|"approved"\|"denied"\|"expired", connection_id}` |
| GET | `/resources?project_id=&service=` | C | → `{resources:[ResourceView]}` |
| POST | `/operations` | C | `OperationRequest` → `OperationResponse` (200 done / 202 pending) |
| GET | `/operations/{id}` | C own | → `OperationResponse` |
| POST | `/operations/{id}/cancel` | C own | → `CancelResponse` |
| POST | `/access/requests` | C | `AccessRequest` → 202 `{approval_request_id, status, grant_id?}` |
| GET | `/access/requests/{id}` | C own | → same |
| POST | `/access/grants/{id}/release` | C own | → `{grant_id, status:"released"}` |
| GET | `/approvals?status=pending` | D, A | → `{approvals:[ApprovalRequest]}` |
| POST | `/approvals/{id}/decision` | D (A may relay but the decision itself must carry a valid device signature) | `ApprovalDecision` → `{status, grant_id?, operation?: OperationResponse}` |
| GET | `/connections` | D, A | → `{connections:[ConnectionView]}` |
| GET | `/connections/{id}` | D, A | → `ConnectionView` |
| POST | `/connections/{id}/{approve\|deny\|pause\|resume\|remove\|revoke_all}` | D, A | approve body `{allowed_projects}` → `AppConnection` / reports |
| GET/POST | `/projects` | D, A | |
| GET/POST | `/admin/resources`, PATCH/DELETE `/admin/resources/{id}` | D, A | `ResourceInput` (no secrets) |
| GET/POST | `/policies`, POST `/policies/{id}/disable` | D, A | signed policies |
| GET | `/grants?status=` | D, A | → `{grants}` |
| POST | `/grants/{id}/revoke` | D, A | `{level:"stop_access"\|"end_sessions"\|"revoke_upstream"}` → `RevocationReport` |
| GET | `/operations?limit=` | D, A | admin list |
| GET | `/audit?after_seq=&limit=` / `/audit/verify` | D, A | `{events, head_hash}` / `{valid, events_checked, head_hash}` |
| GET | `/activity/summary?since=` | D, A | `{pending_approvals, active_grants, recent_operations, auto_approved_count, anomalies}` |
| GET | `/executors` | D, A | `{executors:[ExecutorInfo]}` |
| GET/POST | `/admin/devices`, POST `/admin/devices/{id}/revoke` | A | trusted approver set |
| POST | `/credentials/delegate` | D | experimental unattended rules: `{policy_id, credential_envelope}` |
| GET | `/health` | P | `{status:"ok", version, executor_online, protection_level}` |

`OperationRequest {resource_id, operation, parameters:{}, idempotency_key (1..128), task_id?}`
`OperationResponse {status, operation_id, approval_request_id?, expires_in_seconds?, message?, result?: OperationResult, error?}` — approval case matches design doc §12.2 exactly (`message: "请在已配对的手机或可信客户端批准本次访问。"`).
`CancelResponse {operation_id, status, cancelled, side_effects, message}`
`AccessRequest {resource_id, operations, scope?, limits?, duration_seconds?, reason?}`
`ResourceView {resource_id, alias, service, project_id, environment, operations:[{name, description, side_effect, parameters_schema}], status, protection_level, executor_status:"online"|"offline"}` — **never** contains config secrets, hosts may be shown only as alias.
`ConnectionView` = `AppConnection` + `{pairing_code?, pairing_expires_at?}` — the two extra fields are present only while the connection is `pending` and its pairing is still open (not decided, not expired), so the approving user can compare the 6-digit code with the one the AI host displays. Returned only to D/A principals; C principals are refused on these endpoints and never receive a pairing code. *(edited in place, see §16.5)*

Not exposed anywhere to AI principals: `get_password`, `export_vault`, `get_cookie`, `get_refresh_token`, keyed `exec`, arbitrary HTTP forwarding (§12.1).

---

## 7. Approval digest & signatures
```
digest = b64u(SHA-256(JCS({
  "v":2, "approval_request_id", "connection_id", "resource_id", "executor_id",
  "operations": sorted unique, "scope": normalized GrantScope (sorted arrays/maps),
  "limits": Limits (all four integers), "mode", "expires_at", "recipients": sorted connection ids,
  "operation_id": <op_…> | null, "parameters_digest": <b64u> | null
})))
signature = Ed25519(device, "aipass:v1:approval:<approve|deny>:<digest>")
```
*(v2, edited in place — see §16.5.)* For `kind:"operation"` both `operation_id` and `parameters_digest` (`ApprovalRequest.parameters_digest` = the waiting operation's `parameters_digest`, §8) are required; for `kind:"access"` both are `null`. Every key is always present. Version 1 digests are not accepted.
Single implementation: `aipass_types::approval::{compute_digest, signing_message}`, used by broker, CLI, desktop and FFI. The approving client recomputes the digest **from the fields it displayed**. Broker verifies: signer is an active trusted owner/member device; recomputed digest (v2) matches; for operation requests, the stored operation still has that `operation_id`, connection, resource, operation and `parameters_digest` and is linked to this request (`INTEGRITY_FAILED` otherwise); `approved ⊆ requested`; `expires_at ≤ now + requested.duration_seconds + 60`.
Display-level request digest (clients, not on the wire): `request_digest = b64u(SHA-256(JCS(ApprovalRequest minus "status")))` (`aipass_types::approval::request_digest`). Trusted clients that render a request keep this value and pass it back when the user decides; a stored request that no longer hashes to it is refused with `INTEGRITY_FAILED` before anything is signed (§12).
Policy signature: `Ed25519(device, "aipass:v1:policy:" + b64u(SHA-256(JCS(policy minus signature))))`.

---

## 8. Executor & connectors (`aipass-executor`)
Trait in `aipass_types::exec` (async-trait):
```rust
pub trait ExecutorBackend: Send + Sync {
    fn info(&self) -> ExecutorInfo;
    fn operation_specs(&self, connector: &str) -> Vec<OperationSpec>;
    fn normalize(&self, resource: &Resource, operation: &str, params: &serde_json::Value) -> Result<NormalizedRequest, ApiError>;
    fn scope_covers(&self, scope: &GrantScope, limits: &Limits, req: &NormalizedRequest) -> bool;
    async fn install_credential(&self, grant_id: &str, envelope: &SealedBox, aad: &CredentialAad) -> Result<(), ApiError>;
    async fn install_plain_credential(&self, grant_id: &str, material: CredentialMaterial) -> Result<(), ApiError>; // in-process trusted client only (desktop)
    async fn drop_credential(&self, grant_id: &str);
    async fn execute(&self, req: ExecutionRequest) -> Result<ExecutionOutcome, ApiError>;
    async fn cancel(&self, operation_id: &str) -> bool;
    async fn end_sessions(&self, grant_id: &str) -> LevelReport;
    async fn revoke_upstream(&self, grant_id: &str) -> LevelReport;
}
// OperationSpec {name, connector, description_zh, description_en, side_effect:"read"|"write"|"irreversible", retry_safe, parameters_schema, stage:"v1"|"v1.1"}
// NormalizedRequest {operation, params, required_scope: GrantScope, parameters_digest}
// ExecutionRequest {operation_id, grant_id, resource: Resource, normalized: NormalizedRequest, remaining: Limits, cancel: CancellationToken}
// ExecutionOutcome {data, rows: Option<u64>, bytes, truncated, restricted_fields, side_effects}
```
Credentials live only in executor memory (zeroized), keyed by grant, dropped on expiry/revoke/end_sessions.

**postgres** — `postgres.query_view` (read, retry_safe). Resource config `{host, port, dbname, sslmode:"disable"|"prefer"|"require"|"verify-full", allowed_views:{"schema.view":{fields:[…], date_field?}}, statement_timeout_ms:5000, max_rows_per_operation:1000, allow_superuser:false, lease_mode:"static"|"temporary_role"}`. Params `{view, fields[], filters?:[{field, op:"eq"|"ne"|"lt"|"lte"|"gt"|"gte"|"in"|"between"|"is_null"|"not_null", value?}], order_by?:[{field, direction}], limit?, period_days?}`. Execution: `BEGIN READ ONLY`, `SET LOCAL statement_timeout`, identifiers only from the allowlist and quoted, values as bound parameters cast from text via `information_schema` column types, `SELECT row_to_json(t) FROM (…) t`, row cap = min(op limit, remaining grant rows). Refuse superuser / `BYPASSRLS` roles unless `allow_superuser`. Never "starts with SELECT" heuristics; never raw SQL from the model (§9.6).

**github** — fixed `api_base` `https://api.github.com` (GHES only via trusted-client config), `allowed_repos`. Ops (read, retry_safe): `github.repo.get {repo}`, `github.contents.get {repo, path, ref?}` (text ≤ 256 KiB), `github.issues.list {repo, state?, labels?, per_page≤100, page}`, `github.pulls.list {…}`, `github.commits.list {repo, sha?, path?, per_page, page}`. Fixed per-op output field allowlists; response headers never returned.

**http_api** — declarative connector: `{base_url (https), auth:{type:"bearer"|"header"|"query"|"basic", name?}, allow_private_network:false, operations:{name:{method, path (template with {param}), query:{param:{type, enum?, max?}}, body_schema?, side_effect, retry_safe, response:{items_path?, allowed_fields:[…]}}}}`. Egress guard (§9.6, A06): https only, host:port pinned, DNS resolved and connection pinned to the vetted IP, deny loopback/private/link-local/CGNAT/multicast/`169.254.169.254`/`fd00:ec2::254` unless `allow_private_network`, redirects not followed (3xx → `UPSTREAM_ERROR`), 10 s timeout, 1 MiB cap, credentials never sent to any other origin, auth headers stripped from errors.

**Output filter** (all connectors): field allowlist; secret detectors (`ghp_`, `github_pat_`, `gho_`, `ghs_`, `sk-`, `sk-ant-`, `AKIA[0-9A-Z]{16}`, `xox[abprs]-`, JWT, PEM private keys, `scheme://user:pass@`, `Bearer …`, plus exact match of the installed credential's username/secret) → `"[REDACTED]"`, field added to `restricted_fields`. Detection is a secondary defence, not the primary boundary (§9.8).

**Experimental (V1.1, cargo feature `experimental`, MCP flag `--experimental`)**: `credentials.rotate` scheme `postgres.password` (candidate from CSPRNG → `ALTER ROLE` → verify login → new credential sealed back to the approving device only); postgres `lease_mode:"temporary_role"` (`CREATE ROLE … VALID UNTIL`, `revoke_upstream` terminates backends and drops the role); `accounts.create` / `browser.start_task` via a `SiteAdapter` trait with a `demo` adapter (HTTP-form flow against a bundled test site; pending record persisted **before** submit; outcomes `created | needs_verification | unknown`; idempotency required). A real controlled-browser driver is out of scope for this build.

---

## 9. MCP bridge (`aipass-mcp`)
- JSON-RPC 2.0 MCP server; protocol versions `2025-11-25`, `2025-06-18`, `2025-03-26`, `2024-11-05` (negotiated). Methods: `initialize`, `notifications/initialized`, `ping`, `tools/list`, `tools/call`; `resources/list` and `prompts/list` return empty lists.
- Transports: **stdio** (newline-delimited JSON on stdout; logs on stderr only) and **Streamable HTTP** (`POST /mcp` JSON responses, `Mcp-Session-Id`, `DELETE /mcp`, `GET /mcp` → 405; local mode validates `Origin`; remote mode requires Bearer and answers 401 with `WWW-Authenticate: Bearer resource_metadata="<url>"`). `aipass-node` serves the same handler at `/mcp`.
- **Tool names use underscores** (Claude / OpenAI tool-name rules reject dots); the design doc's dotted names are documentation aliases:

| tool | input | output (`structuredContent`) |
| --- | --- | --- |
| `resources_list` | `{project_id?, service?}` | `{resources:[ResourceView]}` |
| `operations_request` | `{resource_id, operation, parameters, idempotency_key}` | `OperationResponse` |
| `operations_status` | `{operation_id}` | `OperationResponse` |
| `operations_cancel` | `{operation_id}` | `CancelResponse` |
| `access_request` | `{resource_id, operations, scope?, duration_seconds?, reason?}` | `{approval_request_id, status, grant_id?}` |
| `access_release` | `{grant_id}` | `{grant_id, status}` |
| `accounts_create` / `credentials_rotate` / `browser_start_task` | experimental only | |

- `content` = one text block (JSON + short zh/en hint). Errors → `isError:true` with `{error:{code,message}}`. `approval_required` is **not** an error; the hint tells the model to ask the user to approve on their phone / trusted client and then call `operations_status`, and never to ask for passwords or keys in chat. No MCP elicitation form mode for secrets (§7.5).
- The bridge holds no business secrets — only its connection key `<AIPASS_HOME>/connections/<conn_id>.key` (0600).
- CLI: `aipass-mcp stdio [--broker URL] [--connection ID] [--experimental]`, `aipass-mcp pair --host <host_type> --name <label> [--broker URL]`, `aipass-mcp http --listen 127.0.0.1:7879`, `aipass-mcp doctor`.
- Broker URL resolution: flag > `AIPASS_BROKER_URL` > `<AIPASS_HOME>/broker.json` > `unix://<AIPASS_HOME>/run/broker.sock`.

---

## 10. Host config wizard (`aipass-hostconfig`, §5.2)
| host | file | entry |
| --- | --- | --- |
| `codex` | `~/.codex/config.toml` | `[mcp_servers.aipass] command, args` (edit with `toml_edit`, preserve formatting) |
| `claude_code` | user `~/.claude.json` `mcpServers.aipass`; project `<dir>/.mcp.json` | `{type:"stdio", command, args, env:{}}` — or print `claude mcp add --scope user aipass -- <cmd> <args>` |
| `cursor` | `~/.cursor/mcp.json` `mcpServers.aipass` | `{command, args}` |
| `claude_desktop` | macOS `~/Library/Application Support/Claude/claude_desktop_config.json`, Windows `%APPDATA%\Claude\claude_desktop_config.json` | `{command, args}` |
| `vscode` | `<dir>/.vscode/mcp.json` `servers.aipass` | `{type:"stdio", command, args}` |
| `windsurf` | `~/.codeium/windsurf/mcp_config.json` | `{command, args}` |
| `chatgpt`, `claude_connector` | remote — instructions only (server URL + OAuth) | |

API: `detect() -> Vec<HostStatus {host, installed, version?, config_path, has_aipass_entry, label}>`, `plan(host, scope, entry) -> ConfigPlan {path, before, after, unified_diff}`, `apply(&plan) -> {backup_path}` (backup `<file>.aipass-backup-<yyyymmddHHMMSS>`, atomic write, only our key touched), `remove(host, scope)`. Entry = absolute path of `aipass-mcp` + `["stdio","--connection","conn_…"]`. **No secrets ever written** to host config. `label` ∈ `verified | standard_protocol | needs_partnership | unsupported` (§7.1); the verified-version list is **empty in this build**, so local hosts report `standard_protocol`.

---

## 11. Native messaging (browser extension ↔ desktop)
Host `com.aipass.native`, binary `aipass-nm-host` (installed by the desktop app; manifest per OS, `allowed_origins: ["chrome-extension://<id>/"]`). Chrome framing (u32 LE length + JSON). The host forwards to the desktop app over `<desktop data dir>/run/desktop.sock` authenticated by a per-install token file.

Request `{id, type, …}` → response `{id, ok:true, …}` or `{id, ok:false, error:{code, message}}`:
| type | request | response |
| --- | --- | --- |
| `hello` | `{extension_version}` | `{app_version, locked, ai_mode_available:false}` |
| `status` | | `{locked}` |
| `match` | `{origin, url}` | `{candidates:[{entry_id, title, username, match:"exact_origin"\|"same_site"}]}` (no secrets) |
| `fill` | `{entry_id, origin, frame_origin, user_gesture:true}` | `{username, password, totp?}` |
| `generate` | `{origin, passwordrules?, length?}` | `{password}` |
| `save` | `{origin, url, username, password, form_kind:"login"\|"signup"\|"change_password"}` | `{status:"saved"\|"updated"\|"needs_confirmation", entry_id}` |
| `open_app` / `lock` | | `{}` |
Error codes: `LOCKED`, `NOT_FOUND`, `ORIGIN_MISMATCH`, `RATE_LIMITED`, `NOT_PAIRED`, `SYNC_CONFLICT`.
Matching (§11.3): exact origin preferred; same registrable domain (PSL eTLD+1) only over https and only after an explicit click ("相关站点"); never fill a cross-origin iframe unless its origin matches; never fill on http an entry saved for https; never trust page-declared branding. AI mode stays off until a supported host completes secure binding; the extension never exposes a "show password" control to page scripts.

---

## 12. FFI (`aipass-ffi`, uniffi proc-macros; Swift module `AIPassCore`, Kotlin package `com.aipass.core`)
Callback interface implemented natively:
```
trait SecretStore { get(key) -> Option<bytes>; set(key, value: bytes, require_user_presence: bool); delete(key) }
```
`object AipassCore` (async = uniffi async with tokio):
- `new(data_dir, secret_store, platform, app_version)`; `has_vault()`; `status() -> CoreStatus {vault_id?, unlocked, device_id?, device_name?, storage_kind?, last_sync_at?, pending_changes, conflicts?, recovery_verified, license?}` (`conflicts` is `None` — unknown — while locked; the FFI record keeps `u32` and maps unknown to 0)
- `async create_vault(device_name, storage: StorageProfileFfi, storage_secret?) -> CreateVaultResult {vault_id, recovery_key, recovery_kit_text}`; `async unlock()` (native performs biometric/passcode before); `lock()`; `is_unlocked()`
- items: `list_items(query?, project_id?) -> [ItemSummary {entry_id, kind, title, username?, primary_url?, project_id?, lifecycle, has_conflict, updated_at}]`, `get_item(id) -> ItemDetail` (secrets masked), `reveal_secret(id, field) -> String` (native re-auth first; never for AI), `async save_item(ItemInput) -> entry_id`, `async delete_item(id)`, `generate_password(PasswordRulesFfi)`, `totp_now(id) -> TotpCode {code, remaining_seconds}`
- `async import_csv(format, bytes) -> ImportReportFfi`; `export_encrypted(password) -> bytes`
- sync: `async sync() -> SyncReportFfi {status:"ok"|"offline"|"conflict"|"rollback_detected"|"error", pulled, pushed, conflicts}`; `conflicts()`; `async resolve_conflict(entry_id, keep_version)`
- recovery: `verify_recovery_key(key) -> bool`; `recovery_kit_text()`
- devices: `devices() -> [DeviceFfi]`; `async revoke_device(device_id)`
- storage: `async test_storage(profile, secret?) -> CapabilityReportFfi`; `async migrate_storage(profile, secret?)`
- autofill: `autofill_candidates(service_identifier) -> [AutofillCandidate {entry_id, title, username, match_kind}]`; `autofill_credential(entry_id) -> {username, password}`; `all_credential_identities() -> [CredentialIdentity {entry_id, service_identifier, username}]`
- pairing: `async pairing_offer(device_name) -> PairingOffer {qr_payload}` + `PairingSession`; `async pairing_scan(qr_payload) -> PairingSession`; `PairingSession { sas(), peer_name(), peer_role(), async confirm(), async cancel(), async wait() }`
- approvals & control (via relay): `set_relay(base_url)`; `async fetch_inbox() -> [ApprovalRequestFfi]` (accepts an `approval.request` only when the relay sender equals `request.executor.executor_id`; never replaces a pending request — a copy with different content keeps the first and sets `conflict`; `approval.cancelled` only from the original sender); `async approve(approval_request_id, request_digest, narrowed?: ApprovedScopeFfi) -> DecisionResultFfi` (`request_digest` = `ApprovalRequestFfi.request_digest` of the request **displayed**; refuses with `INTEGRITY_FAILED` when the stored request no longer hashes to it or is in `conflict`; then recomputes the §7 v2 digest, signs, seals credential to executor); `async deny(id, request_digest)` (same check; a conflicting request may be denied); `ApprovalRequestFfi` exposes `request_digest`, `conflict`, `parameters_digest` *(edited in place, see §16.9)*; `async snapshot() -> SnapshotFfi`; `async revoke_grant(grant_id, level) -> RevocationReportFfi`; `async control_connection(connection_id, action)`; `async approve_connection(connection_id, allowed_projects)`
- license: `verify_license(token) -> LicenseStatusFfi {valid, plan_id?, features, expires_at?, reason?}` (offline Ed25519 check against embedded cloud public key; failure only disables premium features — never unlock/export/recovery/revoke, §5.5, §16.2)
- errors: `CoreError { code: String, message: String }` (codes from §1.5 plus `LOCKED`, `NO_VAULT`).

---

## 13. Commercial cloud API (`aipass-cloud`, PostgreSQL via sqlx runtime queries)
Base `https://cloud.aipass.example` (dev `http://127.0.0.1:8787`). Session: `Authorization: Bearer aips_…` (apps) or HttpOnly cookie `aipass_session` (console; state-changing cookie requests require same-origin `Origin`). JSON errors per §1.5.

**Auth** — `POST /v1/auth/register {email, password, locale}` → `{user, session_token}` (Argon2id; verification mail via SMTP or logged in dev); `POST /v1/auth/login`; `POST /v1/auth/logout`; `POST /v1/auth/verify-email {token}`; `POST /v1/auth/password-reset/request|confirm` (resets the **subscription account only** — UI states it cannot decrypt any vault); `GET /v1/me` → `{user_id, email, email_verified, locale, is_staff, created_at}`; `DELETE /v1/me` (schedules deletion of cloud data after export notice). Team SSO (OIDC): `GET /v1/auth/sso/{org_slug}/start`, `GET /v1/auth/sso/callback`. **v1.1 (additive):** `PATCH /v1/me {locale:"zh-CN"|"en"}` → the `GET /v1/me` shape (only `locale` is writable — it selects the language of e-mails and server-rendered pages; unknown fields or locales → `INVALID_REQUEST`); `POST /v1/auth/verify-email/resend` (session, empty body) → `{ok, email_verified, sent}` — sends a new link to the signed-in account's own address only (no e-mail parameter, so no account probing), invalidates earlier unused links, rate-limited per account (`RATE_LIMITED`), sends nothing when already verified.

**Billing** — `GET /v1/plans` → `community` (free, self-host, no account required), `personal_monthly` (499 USD cents / month), `personal_yearly` (3900 / year), `team_monthly` (800 / seat / month); trial 14 days; prices labelled 试运营价格. `GET /v1/subscription` → `{plan_id, status:"none"|"trialing"|"active"|"past_due"|"canceled", current_period_end?, cancel_at_period_end, seats?, grace_until?, entitlements:{official_sync, sync_quota_bytes, relay, push, remote_gateway, team}}`. `POST /v1/billing/checkout {plan_id, seats?}` → `{checkout_url}`; `POST /v1/billing/portal` → `{portal_url}`; `POST /v1/billing/cancel`; `POST /v1/billing/webhooks/stripe` (verify `Stripe-Signature`); `POST /v1/billing/appstore/notifications`, `POST /v1/billing/play/notifications`; `POST /v1/billing/mock/complete {checkout_id}` (only with `BILLING_PROVIDER=mock`). After cancellation: entitlements until period end, then 30-day read-only grace for official sync + export notice. Nothing in the cloud can lock a local vault (§5.5, §13.3).

**Licenses** — `POST /v1/licenses/activate {device_id, platform, app_version}` → `{license_token}` = `b64u(JCS(payload)) + "." + b64u(Ed25519 sig)`, payload `{v:1, sub, plan_id, features:[…], device_id, iat, exp, grace_until}`; `GET /v1/licenses/public-key` → `{kid, public_key}`. Activation never uploads vault material (§3.3).

**Devices (metadata only)** — `GET /v1/devices`; `POST /v1/devices {device_id, name, platform, app_version, sign_pk}`; `PUT /v1/devices/{id}/push {provider:"apns"|"fcm", token, environment}`; `DELETE /v1/devices/{id}` (UI note: does not revoke vault membership — use a trusted device).

**Official ciphertext sync & relay** — mounts `aipass-sync-server` routers at `/v1/vaults*` and `/v1/relay*` with a cloud layer: vault creation needs a session with `official_sync` (else `PAYMENT_REQUIRED`); per-account quota (`QUOTA_EXCEEDED`); relay needs `relay`. Ciphertext blobs on local disk (`AIPASS_CLOUD_BLOB_DIR`) or S3.

**Nodes & tunnel** — `POST /v1/nodes/link-codes` (session) → `{code, expires_at}`; `POST /v1/nodes/link {code, node_id, name, sign_pk, kem_pk, protection_level, version}` (signed `kid=exe_…`) → `{node_id}`; `GET /v1/nodes` → `[{node_id, name, online, last_seen_at, protection_level, version}]`; `DELETE /v1/nodes/{id}`. `GET /v1/tunnel` (WebSocket, node-initiated outbound; first frame `{type:"auth", node_id, ts, nonce, sig}` over `aipass:v1:tunnel:<node_id>:<ts>:<nonce>`). Frames (JSON): `{type:"mcp", id, connection_id, session_id?, body}` ↔ `{type:"mcp_result", id, status, headers?, body}`; `{type:"connection.create", id, connection:{host_type, display_name, oauth_client_id, user_id}}` ↔ `{type:"connection.created", id, connection_id, pairing_code}` then `{type:"connection.status", connection_id, status}`; `{type:"connection.revoke", connection_id}`; `{type:"policy.org", policy}`; `{type:"audit.batch", events:[…metadata only…]}`; `ping`/`pong` every 20 s.

**Remote MCP gateway + OAuth 2.1 (§7.4, [S6])**
- `GET /.well-known/oauth-protected-resource` and `/.well-known/oauth-protected-resource/mcp` → `{resource:"<base>/mcp", authorization_servers:["<base>"], scopes_supported:["aipass.tools"], bearer_methods_supported:["header"]}`
- `GET /.well-known/oauth-authorization-server` → RFC 8414 metadata (S256 only, `authorization_code` + `refresh_token`, `none` + `client_secret_post`, registration & revocation endpoints).
- `POST /oauth/register` (RFC 7591; redirect URIs https or loopback only). `GET/POST /oauth/authorize` — server-rendered zh/en consent page: requires login; shows the client name **marked as self-declared** and the redirect host; user picks an online node + allowed projects; the cloud sends `connection.create` through the tunnel; the page shows the pairing code "请在手机或桌面 App 确认此连接" and completes only after the node reports `active`; node offline → "执行设备离线" page. `POST /oauth/token` (PKCE S256 mandatory, refresh rotation; access `aipa_` 1 h, refresh `aipr_` 30 d; token bound to user, client, node, connection and audience `<base>/mcp`). `POST /oauth/revoke`.
- `POST /mcp` (Streamable HTTP) — validate token (issuer, audience, expiry, user active, `remote_gateway` entitlement) → forward JSON-RPC through the tunnel → return node's response. Node offline → `tools/call` result `isError:true`, code `EXECUTOR_OFFLINE`. `GET /mcp` 405, `DELETE /mcp` ends session. 401 carries `WWW-Authenticate: Bearer resource_metadata="<base>/.well-known/oauth-protected-resource/mcp"`. The gateway **never logs JSON-RPC bodies** (only method, tool name, connection, status, latency) and is described honestly as *not* an E2E-blind relay (§4.3).
- `GET /v1/connections` (remote connections), `DELETE /v1/connections/{id}` (revoke tokens + `connection.revoke` to node).

**Push (`PushNotifier`)** — APNs token auth (ES256 JWT, HTTP/2), FCM HTTP v1 (service-account JWT → OAuth token), `log` provider in dev. Payload only `{"aps":{"alert":{"title":"AI 通行证","body":"有一项访问请求等待处理"}},"mid":"<message_id>"}` (FCM equivalent). Rate-limited per device. Missing push never implies approval (§11.5).

**Teams (P3)** — `POST/GET /v1/orgs`, `GET /v1/orgs/{id}`, `GET /v1/orgs/{id}/members`, `POST /v1/orgs/{id}/invitations {email, role}`, `POST /v1/invitations/{token}/accept`, `PATCH /v1/orgs/{id}/members/{user_id} {role:"owner"|"admin"|"member"}`, `DELETE /v1/orgs/{id}/members/{user_id}` (creates an **offboarding task**: org vaults + resources needing key rotation, tracked to completion), `GET/POST /v1/orgs/{id}/vaults {vault_id, name}`, `GET/PUT /v1/orgs/{id}/policy {require_trusted_approval_for_production, allowed_host_types, max_grant_ttl_seconds, auto_approve_test_reads}` (pushed to linked nodes as `policy.org`), `POST /v1/orgs/{id}/audit/ingest` (node-signed, metadata only), `GET /v1/orgs/{id}/audit`, `GET /v1/orgs/{id}/audit/export?format=csv|jsonl`, `PUT /v1/orgs/{id}/sso {issuer, client_id, client_secret}`, `GET /v1/orgs/{id}/offboarding`. Seats sync to billing quantity. Org admins never gain access to members' personal vaults (§16.5).

**Staff admin** — `GET /v1/admin/metrics` `{users, active_subscriptions, trials, mrr_cents, churn_30d, vaults, storage_bytes, nodes_online}`, `GET /v1/admin/users?q=`, `GET /v1/admin/users/{id}`, `POST /v1/admin/users/{id}/disable|enable`, `GET /v1/admin/subscriptions`, `POST /v1/admin/incidents`, `PATCH /v1/admin/incidents/{id}`. Staff created via `aipass-cloud admin create-staff --email`.

**Status** — `GET /v1/status` (public, CORS `*`) → `{status:"operational"|"degraded"|"outage", components:[{id, name_zh, name_en, status}], incidents:[{id, title, status, started_at, resolved_at?, updates:[{at, body}]}], updated_at}`; components `sync relay push gateway console billing`.

**v1.1 additions (additive, implemented by aipass-cloud)** — `GET /oauth/authorize/wait?p=…` (pairing-code wait page of the consent flow); `POST /v1/orgs/{id}/offboarding/{task_id}/items/{index} {status:"done"|"failed"|"not_applicable"|"pending"}` → the offboarding task (owners/admins; the cloud only tracks the checklist — re-keying and rotation happen on trusted devices); `DELETE /v1/orgs/{id}/vaults/{vault_id}`. Tunnel: `connection.create` may carry `requested_projects:[proj_…]` (advisory; the trusted device decides); the cloud may send `{type:"auth.ok"}` after auth; `mcp` frames may carry `protocol_version` and `http_method` (`POST` default, `DELETE` ends the session); a node that cannot serve a request frame answers `{type:"error", id, error:{code, message}}`. `/mcp` passes the node's HTTP status through (e.g. `404` for an unknown `Mcp-Session-Id` after a node restart — the client re-initialises).

Config env: `AIPASS_CLOUD_DATABASE_URL`, `AIPASS_CLOUD_BASE_URL`, `AIPASS_CLOUD_CONSOLE_ORIGIN`, `AIPASS_CLOUD_LICENSE_SIGNING_KEY` (b64u seed; dev auto-generates), `AIPASS_CLOUD_BLOB_DIR`, `BILLING_PROVIDER=mock|stripe`, `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET`, `STRIPE_PRICE_PERSONAL_MONTHLY|PERSONAL_YEARLY|TEAM_MONTHLY`, `APNS_KEY_ID`, `APNS_TEAM_ID`, `APNS_KEY_P8`, `APNS_TOPIC`, `FCM_SERVICE_ACCOUNT_JSON`, `SMTP_URL`, `SMTP_FROM`.

---

## 14. UX, copy and design tokens
- Name: **AI 通行证** / *AI Pass* (working name). Tagline: 让人少操心每一个密码，让 AI 在授权范围内使用账号。Hero copy: design doc §1.1.
- **Honesty rules (all UIs, website, READMEs)**: never claim "已验证/verified" compatibility in this build (use 标准协议可接入 / *standard protocol*); never "首个/first"; never claim the official remote MCP gateway is E2E-blind; never claim hosted execution keeps credentials invisible to the provider; never promise auto-registration on arbitrary sites, guaranteed rotation, instant revocation or recovery without recovery material; label V1.1 features 实验性 / *experimental*; state that the product is not yet independently audited. Pricing labelled 试运营价格.
- Status vocabulary: 可用 · 需要重新登录 · 同步冲突 · 设备离线 · 执行设备离线 · 待处理 · 已撤销 · 部分撤销失败 · 已导入 · 已验证 · 需要处理.
- Primary actions: 连接 AI · 打开服务 · 停止访问 · 处理异常. "查看原始密码" / "导出" are secondary and require re-authentication.
- Approval screen: field order of §5.3 — requester (verified), resource, operation, data fields (and excluded fields), scope/limits/duration, execution location, result recipients, buttons 允许本次 / 选择较小权限 / 拒绝. No "全部允许" without itemised scope.
- Mobile tabs 首页 · 账号 · 连接 · 我的. Desktop nav 总览 · 账号 · AI 连接 · 执行设备 · 活动 · 设置; first run shows exactly three actions 导入账号 · 连接 AI · 绑定手机.
- Exception pages: all eight of §11.5.
- Tokens: `--ap-ink #0F172A`, `--ap-primary #4F46E5`, `--ap-primary-ink #FFFFFF`, `--ap-accent #0EA5A4`, `--ap-success #16A34A`, `--ap-warning #D97706`, `--ap-danger #DC2626`, `--ap-surface #FFFFFF`, `--ap-surface-2 #F5F7FB`, `--ap-border #E2E8F0`, `--ap-muted #64748B`; dark: surface `#0B1020`, surface-2 `#121A2F`, border `#1E293B`, ink `#E2E8F0`. Radius 10 px; font stack `Inter, "PingFang SC", "Noto Sans SC", system-ui, sans-serif`.
- i18n: zh-CN default and complete; en complete.

---

## 15. Scope tiers for this build
- **V1 — must work and be tested**: everything in design doc §14.2 that can be built here: vault core, local/official/S3 sync, recovery, export, conflict handling, broker + state machine + budgets + revocation + audit, executor with postgres + github + http_api, MCP stdio/HTTP, host wizard, SDKs, self-host node, CLI, cloud (accounts, billing, licenses, devices, sync, relay, push, OAuth + remote MCP gateway, status), console, website, desktop app, browser extension, iOS app + Credential Provider, Android app + Autofill/Credential Provider.
- **V1.1 — implemented as experimental, off by default**: WebDAV backend, `credentials.rotate` (postgres password), temporary DB role leases, unattended rule delegation, `accounts.create` / `browser.start_task` with the demo site adapter.
- **P3 — implemented in cloud/console**: teams, roles, invitations, offboarding tasks, org policy, audit ingest/export, OIDC SSO, staff admin.
- **Excluded by design** (documented, not built): official hosted executor (separate trust boundary, §4.2), SSH connector, arbitrary script/connector marketplace, iCloud/Google Drive sync, real controlled-browser automation of arbitrary sites, bank/payment automation.

Environment notes for implementers: Rust nightly 1.97 (aarch64-apple-darwin only), Node 24 + pnpm 11, Python 3.9 system + `uv`, PostgreSQL 17 (Homebrew `initdb`/`pg_ctl`, no Docker), Swift 6.3 with Command Line Tools only (**no Xcode, no iOS SDK**), **no JDK / Android SDK**. Components that cannot be compiled here must say so plainly in their README and report.

---

## 16. Changes since v1 (consolidated, accepted deviations)

This section collects every contract deviation that the implementing agents reported and that integration and security review accepted. Nothing in §0–§15 above was edited, apart from the §13 entries already marked **v1.1** and the §0 layout / licence lines (v1.1: the desktop app moved from `clients/desktop` to `open-source/desktop` and is Apache-2.0). Where this section and an earlier section disagree, **this section describes the build**. Each component README keeps its own "Contract deviations" list. Kinds: **A** = additive (old readers unaffected); **S** = stricter than v1 (valid v1 traffic may now be refused); **C** = clarification of something v1 left open; **D** = a real deviation from the v1 text.

### 16.1 Workspace & conventions (§0, §1)
- **D** `ed25519-dalek` 3.x (with `x25519-dalek` 3, `hpke` 0.15, `sha2` 0.11, `chacha20poly1305` 0.11), not 2.x. There is one TLS provider for the whole workspace, rustls with aws-lc-rs, so `ring` is not compiled; sqlx uses feature `tls-rustls-aws-lc-rs`. `rusqlite` is pinned to 0.39 so that its `libsqlite3-sys` can link alongside sqlx 0.9.
- **A** Additional error codes. These are client-local and never appear on the broker or cloud wire unless noted:
  - core / native messaging: `LOCKED` (423), `NO_VAULT` (404), `ORIGIN_MISMATCH` (403), `NOT_PAIRED` (401);
  - SDK-local: `NETWORK_ERROR`, `TIMEOUT`, `ABORTED`, `INVALID_RESPONSE`, `CONFIG_ERROR`, `CANCELLED`;
  - iOS: `USER_CANCELLED`, `PRESENCE_UNAVAILABLE`, `NETWORK`;
  - the desktop native-messaging host may also answer `INVALID_REQUEST`.
- **C** `OperationStatus::AwaitingApproval` serializes as `"approval_required"` in all JSON, and `"awaiting_approval"` is accepted on input.
- **C** Additional prefixes: `aipe_` (sync-server enroll token), `aipadm_` (broker admin token), and the process-local handles `gen_` (desktop generated password) and `cr_` (extension fill handle), which are never persisted or sent to a server.
- **C** `GET /v1/connections/pair/{id}` is signed with the pending key, using `kid = connection_id`.
- **S** Replay caches are keyed by the **verifying key**, not the kid string, so `dev_<U>`/`exe_<U>` aliases share one window. In the broker, signatures from `pending` connections are refused before their nonce is recorded, and each signing key has a nonce quota.
- **S** Every 401 from the sync server and relay uses one reason, `invalid_signature_or_principal`. Unknown principals, wrong keys, revoked members and missing vaults cannot be told apart.
- **C** No 413 code exists. An oversized object or body gets `400 INVALID_REQUEST` with `details:{reason:"too_large", limit}`, except the node's resource pre-validation layer, which answers 413 without buffering. axum's built-in 405 responses keep an empty body.
- **S** A connection key signs only for the broker it was paired against when one was recorded at pairing time. Requests to any other broker are refused client-side. The audience-bound string-to-sign (adding a host line to §1.6) is deferred to v2.

### 16.2 Crypto, vault format, recovery (§2)
- **C** Audit hash: `prev_hash_bytes` = b64u-decoded previous hash (empty bytes for the first event).
- **C** Shapes:
  - `KeyringRecord {format, vault_id, key_epoch, previous:[{key_epoch, nonce, wrapped_vmk}], author_device_id, created_at}`;
  - `StorageDescription {kind, endpoint?, detail?}`;
  - `ActivitySummary` counts are integers, and `anomalies:[{kind, summary:{zh,en}, at, connection_id?, resource_id?}]`;
  - `exec::DelegationAad {policy_id, policy_digest, executor_id}`.
- **C** Every stored object is written as JCS bytes. The recovery KEK salt is the UTF-8 bytes of the `vault_id` string. A tombstone's version is the highest version including conflict versions. Entry version numbers may have gaps, because orphans from interrupted commits are skipped (and never garbage-collected).
- **A** **Recovery member.** The recovery secret also derives an owner identity: HKDF infos `aipass/v1/recovery-sign` and `aipass/v1/recovery-kem`; device id = `dev_` + ULID(SHA-256(`aipass/v1/recovery-device-id` ‖ sign_pk)[0..16]). Every new VMK epoch is sealed to it. `recovery/<epoch>-recovery_key.json` is written at creation, when the recovery key is verified for newer epochs, and when the key is replaced. Changing an existing master password rotates the key epoch, because recovery wraps are immutable.
- **C** AADs defined where v1 was open:
  - pairing hello `aipass:v1:pairing:hello:{pairing_id}:{b64u sha256 JCS(o_device)}`, join `aipass:v1:pairing:join:{pairing_id}`, welcome `aipass:v1:pairing:welcome:{pairing_id}:{n_device_id}`;
  - `.aipassx` `aipass:v1:export:aipass-export-1`;
  - outbox `aipass:v1:outbox:{vault}:{device}`.

  The `pairing.hello` ephemeral key field is literally `"eO"`. The outbox, `FileSecretStore` and local data-directory formats are specified in `vault-format.md`.
- **S** Member and manifest transition rules (enforced by clients **and** by the sync server):
  - revoking an owner/member requires a key-epoch bump that re-seals the VMK to every remaining owner/member;
  - only owners rotate, revoke, change roles, add owners or touch an owner's record;
  - device keys and platform are immutable;
  - a revoked device is never reactivated;
  - new entry versions use the manifest's epoch;
  - at least one active owner remains;
  - signers must be active.
- **C** An executor's vault member id is `dev_<U>` for its broker/relay principal `exe_<U>` (same ULID). **S** After review, executors may sign only as `exe_<U>`; the `dev_<U>` alias is refused.
- **C** A trusted device confirmed by an owner is enrolled as **owner**, even when its QR says `t=member`, so any of the user's devices can later revoke a lost one. `confirm_pairing_with_role` selects the role explicitly. An expired pairing QR maps to `APPROVAL_EXPIRED` (410).
- **A** `ApprovalRequest.excluded_fields` is an optional, per-view list of fields that are *not* requested, shown on the approval screen. It is omitted when empty and is **not** part of the digest. `StorageProfile.path` holds the directory for `kind:"local"`.
- **C** Signed objects are verified by re-serializing the typed struct, so unknown fields from newer writers make the signature fail closed. `canonical::value_jcs_without_field` verifies raw JSON instead. `normalize_scope` lowercases GitHub `owner/name` and drops empty connector sections; connectors compare repositories case-insensitively.
- **S** Conflict versions are verified (current key epoch) and pinned in the local cache when the manifest that introduces them is applied. *Deferred:* hash-binding conflict versions in the signed manifest (`conflict_versions:[{version, hash}]`) or author-signed `EntryVersion` would change §2.3 and §3.2 for every client.
- **A** `ItemSummary` gains `pending_sync`, `tags`. `ImportReport` gains `warnings`, and `DuplicateInfo` gains `row`. CSV duplicates are reported for merging, not imported.

### 16.3 Storage & sync (§3)
- **S** Member-record signer chains: when a stored record's signer was later re-signed by a device that this record vouches for (an owner revoking a device re-signs every remaining member at the new key epoch — e.g. a device recovered with the recovery key revoking the lost phone), the signer is resolved at its newest revision outside that loop. Uploads never use this fallback, and a device's own standing is always its latest revision.
- **S** Before storing anything, the sync server validates:
  - member records: key ↔ content, signature chain up to the self-signed genesis named in `vault.json`, the transition rules, and the device-key binding;
  - manifests: key ↔ seq, and a valid transition from the latest verified manifest using the clients' `verify_transition`;
  - entry versions, recovery wraps and keyring records: key ↔ content and vault id.

  Failures return `400 INVALID_REQUEST` or `422 INTEGRITY_FAILED`.
- **S** A server-wide device-key binding (`index/keys/<device_id>`) is set on first use. A record carrying another key for a bound device id is refused (422) in every vault. A device's membership follows the **latest verified manifest**, plus records vouched for by an effective member during an in-flight commit, so revoking a member also cuts off the unlisted devices it introduced.
- **D** `DELETE`: immutable keys are owner-only, as in v1. Mutable keys (`HEAD`, scratch keys such as the capability test's `_aipass_captest/`) may also be deleted by members. `vault.json` and `members/` are never deletable. Success is `204`.
- **C** `POST /v1/vaults` stores `vault_header` / `genesis_member` byte-for-byte (`RawValue`). An identical retry is idempotent; an existing vault gives `412` with `details.reason:"vault_exists"`. Enroll tokens are `aipe_…`, stored as SHA-256 hashes, and uses are reserved atomically. Client side: `SyncEngine::write_genesis` writes each genesis object create-only and accepts an existing object only if its bytes are identical.
- **A** `PUT` also returns body `{etag}`. `HEAD` ≤ 64 bytes. Quota usage deltas are reserved atomically with the check; within a process the check + reservation of one vault's writes are serialized (the policy is asked once per write). The cloud enforces the account quota **across replicas** with a conditional PostgreSQL `UPDATE vaults SET bytes_used = bytes_used + Δ WHERE … account total + Δ <= quota` under a per-account advisory lock; replica-local usage reports become relative adjustments, and an unconsumed reservation is released after 60 s (over-counting only, never overshooting).
- **C** `HttpSyncStore` maps `QUOTA_EXCEEDED` and `PAYMENT_REQUIRED` to a non-retryable `StorageError::Backend`. A WebDAV server without ETags gets a synthetic `local-<b64u sha256>` ETag and is classified `backup_only`. The sync wire types (`VaultInfo`, `ListObjectsResponse`, `PutObjectResponse`, `create_vault_body`) live in `aipass_storage::http`. `PrefixedStore`, `profile::open_store`, `validate_prefix` and `S3CredentialProvider` are additive.
- **C** `VaultClient::sync()` requires an unlocked vault and returns `LOCKED` otherwise. AI connections (`conn_`) cannot use the sync API or the relay.

### 16.4 Relay & pairing (§4, §5)
- **A** Relay additions:
  - `DELETE` returns `204`;
  - `GET` returns at most 100 messages per call (page with `after`);
  - a full mailbox gives `429 RATE_LIMITED` with `details.reason:"mailbox_full"`;
  - envelopes older than the TTL or more than 300 s in the future are refused;
  - at most 4 concurrent long-poll waiters per mailbox.
- **C** A `pair_` mailbox binds the SHA-256 of the 16-byte secret on first use (trust on first use), checks it in constant time, and expires 10 minutes after first use.
- **C** Push is triggered only for `approval.request` and `connection.pair_request` envelopes posted to `dev_` mailboxes, with payload `{mailbox, message_id}`.
- **S** Relay authorization resolves keys through the server-wide key binding and vault membership, never "the first vault that lists the id". The pluggable `RelayDirectory` is `Sync`, `Static`, `Node` or `Chain`. The node's directory also authorizes its executor ↔ the broker's active trusted devices, so phone approvals work when the vault lives on S3 or local storage.
- **C** A node's relay control channel counts as lost after 3 consecutive mailbox fetch failures; new operations get `CONTROL_CHANNEL_LOST` until it recovers. `aipass-node pair` requires the node to be running.

### 16.5 Broker (§6, §7)
- **D** `POST /v1/operations` returns the §1.5 error envelope for any failure decided **before** an operation exists (auth, validation, `IDEMPOTENCY_CONFLICT`, `NOT_FOUND`, normalize errors, `SYNC_CONFLICT`, `EXECUTOR_OFFLINE`, `CONTROL_CHANNEL_LOST`, throttling, the in-flight cap). Once an operation exists it returns `OperationResponse`: 202 while pending, 200 when terminal, with failures in `error`. Throttled requests create no operation.
- **S** `EXECUTOR_OFFLINE` and `CONTROL_CHANNEL_LOST` are checked before an approval request is created, and again when the operation runs.
- **A** Endpoints:
  - `GET /v1/approvals/{id}`, `GET /v1/connections/{id}`, `GET /v1/grants/{id}`, `GET /v1/state` (D, A);
  - `POST /v1/connections/{id}/token`, `POST /v1/admin/connections`, `GET /v1/admin/resources/{id}` (A);
  - `PUT /v1/admin/entries/{entry_id}/conflict` (D, A).

  Response shapes: `revoke_all` → `{connection, reports}`; `DELETE /v1/admin/resources/{id}` → `{resource_id, status:"deleted"}` (soft delete).
- **S** Result data goes only to the requesting connection. Decision responses, admin operation lists, state snapshots and broker events never carry `result`. Stored results are purged after `result_retention` (default 1 h).
- **S** Rules:
  - auto-approval applies to operations only; access requests always go to a person;
  - a decision may not carry mode `rule`;
  - a rule creates at most one grant per policy version per `grant_ttl` window;
  - a new policy version revokes grants from older versions;
  - rules stop applying when the resource's credential entry, config, target or environment changes, and after `revoke_all`;
  - `POST /policies/{id}/disable` is an unsigned broker-side flag (listings show `disabled`).
- **S** Access requests on postgres and github resources must carry an explicit `scope.postgres` / `scope.github`. For `http_api` the scope defaults to the requested operation names. Limits must be ≤ max limits, `duration_seconds` 1..86400, mode `task`.
- **S** Grant matching requires both `approval::scope_is_subset` (with the operation in `scope.operations`) **and** `ExecutorBackend::scope_covers`. A `once` grant is bound to the operation that triggered its approval (`bound_operation_id`), and no other request can use it.
- **S** **Approval digest v2** (§7 edited in place): the digest adds `operation_id` and `parameters_digest` (both `null` for `kind:"access"`) and `"v":2`; `ApprovalRequest` gains the optional `parameters_digest` (**A**). The broker recomputes only v2 and re-checks the binding against the waiting operation; a v1 digest, an operation request without the binding, or an access request with one is refused with `INTEGRITY_FAILED`. `test-vectors/approval-digest.json` is regenerated and also carries a `request_digest` vector. Every Rust signer goes through `aipass_types::approval::build_decision`, so vault / sync / desktop / FFI / CLI callers keep their signatures.
- **A** / **S** `GET /v1/connections` and `GET /v1/connections/{id}` return `ConnectionView` (§6.3 edited in place): `AppConnection` + `pairing_code` / `pairing_expires_at` while the connection is pending and its pairing open; D/A only, never to C principals. Rust: `Broker::get_connection_view` / `list_connection_views`, types `aipass_types::models::{ConnectionView, ConnectionViewsResponse}`. Trusted clients (CLI) should require the user to confirm this code before approving a connection.
- **S** Changing a resource's environment, config, credential entry, executor or operations, or disabling it, revokes its grants at `end_sessions` and cancels its pending approvals. Revoking a trusted device revokes the grants it approved.
- **C** Revocation levels:
  - `remove` and `revoke_all` → `revoke_upstream`; resource, policy and device revocations → `end_sessions`;
  - at `stop_access`, running operations finish but their results are withheld (cancelled + `GRANT_REVOKED`), and `end_sessions` is reported `pending` while they run;
  - bulk revocations stop every grant before the slow executor steps and continue past individual errors;
  - "全部已收回" requires sessions actually ended and the credential drop confirmed.
- **C** Shapes:
  - the pairing code is 6 decimal digits;
  - the admin token prefix is `aipadm_`;
  - `TrustedDevice = DevicePublic + {status, added_at, added_by, revoked_at?}`;
  - `max_result_bytes` is per operation, and cumulative bytes are tracked only in `usage.bytes`;
  - experimental delegation goes through `CredentialSource::install_delegated(grant, envelope, &DelegationAad)`.
- **S** UDS admin peers are opt-in per socket and require the peer uid to equal the socket owner's uid. `aipass node run` and the desktop serve `broker.sock` without admin peers. The admin API cannot replace an existing approver device's signing or KEM key. Pending pairings are capped per peer (3); all UDS peers share one key.
- **C** After a restart: running operations become `unknown`, queued ones `failed`, reserved rows count as used, and every grant's credential state is reset (`SECRET_UNAVAILABLE` until delivered again).
- **A** The node pre-validates `POST/PATCH /v1/admin/resources` configs with `Executor::validate_resource_config`, only for D/A callers and reading at most `max_body_bytes`. Unknown keys and secrets → `INVALID_REQUEST`.

### 16.6 Executor (§8)
- **C** `http_api`: the AI-facing operation is a single `http_api.call` with params `{operation, params, body?}`, and the declared names go in `GrantScope.http_api.operations`. An omitted body of an operation with a `body_schema` is `{}` and must pass the schema; the executor never invents a body.
- **A** / **S** Extra config keys:
  - postgres: `ssl_root_cert`, `connect_timeout_ms`, per-view `row_filter`, `temporary_role`;
  - github: `api_base`, `allow_private_network`, `timeout_ms`;
  - http_api: `timeout_ms`, `max_response_bytes`, `path_params`, parameter `min`/`required`/`pattern`/`description`, `response.on_secret_detected`, operation `description_zh/en`.

  Unknown keys are rejected. postgres `sslmode` defaults to `require` when omitted.
- **S** Cloud metadata, unspecified, broadcast, multicast and 240/4 addresses stay blocked even with `allow_private_network`. Members of `pg_read_server_files`, `pg_write_server_files` and `pg_execute_server_program` are refused like superusers.
- **C** Outcomes:
  - a cancelled operation → `UPSTREAM_ERROR` with `details.reason:"cancelled"`;
  - a cancelled, timed-out, 5xx or 3xx in-flight write, or a non-2xx write answer over the size cap → `UPSTREAM_OUTCOME_UNKNOWN`;
  - a 2xx write never becomes an error: if its result cannot be returned, the outcome is `Ok` with `side_effects:"applied"`, `rows:0`, data `{operation, status, withheld:true, reason}`.
- **C** Result shapes:
  - postgres `{view, fields, rows}`;
  - github `{repo}`, contents `{repo, path, type, text|entries…}`, lists `{repo, page, per_page, has_more, items}`;
  - http_api `{operation, status, items|item}`.

  An oversized non-list result is withheld with `RESULT_RESTRICTED` (`reason:"result_too_large"`); lists are truncated with `truncated:true`. `LevelReport.detail` is a single bilingual string `"<zh> / <en>"`. The executor caps rows and bytes but does not count requests; that is the broker's job.
- **C** Experimental `credentials.rotate`:
  - it is a postgres resource operation (`scope.operations:["credentials.rotate"]`, params `{scheme:"postgres.password"}`);
  - the new credential is not in the `ExecutionOutcome`; it is delivered by `Executor::seal_rotation_result(rotation_id = operation_id, device_kem_pk)` with AAD `JCS({purpose:"credentials.rotate", rotation_id, entry_id, executor_id})` and info `aipass/v1/credential`;
  - "old stays valid until new is verified" is implemented as restore-on-failure.

### 16.7 MCP bridge, host config, SDKs (§9, §10)
- **A** Tool `access_status` `{approval_request_id}` → `{approval_request_id, status, grant_id?}`. The experimental tools take `{resource_id, parameters, idempotency_key}` and map to the fixed operations `accounts.create`, `credentials.rotate` and `browser.start_task`.
- **D** Error results carry no `structuredContent`; the `{error:{code,message}}` JSON is in the text block. Outcomes `failed`, `unknown`, `denied` and `expired` are `isError:true` with a schema-valid `OperationResponse` in `structuredContent`. Requests before `initialize` get JSON-RPC `-32002`. Output schemas, titles and `structuredContent` are sent only from `2025-06-18`, annotations from `2025-03-26`, and batches are accepted only for `2025-03-26` / `2024-11-05`.
- **C** Broker URL resolution: flag > `AIPASS_BROKER_URL` > the broker recorded in the connection key (when paired with `--broker`) > `broker.json` (`{"url"}`, alias `broker_url`) > default. The Windows default is `http://127.0.0.1:7878` (no UDS on Windows in this build).
- **C** Connection key file written by `aipass-mcp` and the CLI: `{format:1, kind:"aipass-connection-key", connection_id, public_key, seed, host_type, display_name, broker_url|null, created_at}`. The SDKs write `{"format":"aipass-connection-key-1", connection_id, seed, public_key, broker_url, host_type, display_name, created_at}`. **Resolved — one canonical format:** `{"format":"aipass-connection-key-1", connection_id, seed, public_key, broker_url?, host_type, display_name, created_at}` is written by `aipass-mcp`, the CLI and both SDKs (`broker_url` omitted when unknown). Every loader reads it; an SDK file may omit `host_type` (read as `sdk`), `display_name` and `created_at`. The Rust loader still reads the legacy `{format:1, kind:"aipass-connection-key", …}` layout of earlier builds, and the SDK loaders also accept seed-only `<conn_id>.key` files.
- **A** `aipass-mcp`:
  - `pair --host` also accepts `claude_desktop`, `vscode` and `windsurf` (paired as `host_type:"custom"`);
  - extra flags: `pair --transport --configure --scope --project-dir`, `http --remote --public-url --authorization-server --allow-origin`, `doctor --json --no-probe`;
  - `handle_for_principal` / `handle_tunnel_frame` serve cloud-tunnel frames.
- **A** `aipass-hostconfig`:
  - `HostStatus.config_path: Option<PathBuf>`, plus `scope`, `existing_entry` and `config_error`;
  - `apply` and `remove` return `ApplyOutcome {path, backup_path?, changed}`;
  - `ConfigPlan` gains `host`, `scope`, `write_path` and `action`;
  - a Cursor project scope (`<dir>/.cursor/mcp.json`);
  - the `CODEX_HOME` / `CLAUDE_CONFIG_DIR` overrides are honoured.
- **C** SDKs: `limits`, when given, must carry all four integers. `idempotency_key` is 1–128 printable characters. `POST /v1/access/requests` is never resent automatically.

### 16.8 Native messaging & desktop (§11)
- **C** The `aipass-nm-host` ↔ app IPC reuses Chrome framing and starts with `{type:"auth", v:1, token, origin}` → `{type:"auth", ok, code?}`. The token is 32 CSPRNG bytes, hex, stored in `<AIPASS_HOME>/run/desktop.token` (0600). The Unix peer uid must equal the owner of the run directory. The desktop data root is `AIPASS_HOME`, so `run/desktop.sock` and `run/broker.sock` share one `run/` directory.
- **D** When the app is unreachable the host answers `hello` → `{app_version, locked:true, ai_mode_available:false}` and `status` → `{locked:true}`. Everything else, including `lock`, gets `LOCKED`. `open_app` still tries to launch the app. A refused handshake → `NOT_PAIRED`.
- **C** `match` / `fill` send `username:null` when an entry has none. `fill` of an unknown entry → `NOT_FOUND`; of an existing entry for another site → `ORIGIN_MISMATCH`. `save` may return `entry_id:null` **only** with `status:"needs_confirmation"`.
- **S** Desktop:
  - every approval decision requires re-entering the unlock password in Rust, with a lockout;
  - the window is content-protected;
  - copied secrets go Rust → clipboard, excluded from clipboard history and cloud clipboard sync, and are auto-cleared;
  - `reveal_secret` and every export require re-authentication;
  - after every sync, approvers whose member record is revoked or no longer owner/member are removed from the broker and their grants end.
- **C** The desktop enrols its embedded executor as a vault member (`dev_<U>` ⇔ `exe_<U>`, role executor, no VMK) by running the §5 protocol in-process over a memory relay. Node link sends `node_id` = that `exe_` id and `protection_level:"compatible"`. `policy.org` frames are logged, not enforced, on a personal node. The licence public key is pinned trust-on-first-use until a production key is embedded.

### 16.9 FFI (§12)
- **D** `pairing_offer` returns the `PairingSession` directly, and the QR string comes from `session.qr_payload()`. `PairingSession.wait(timeout_secs)` (0 = until the link expires) is additive, as are `confirm_code`, `progress`, `set_share_storage_secret`, `is_new_device` and `expires_at`.
- **D** `snapshot(executor_id?)`. `approve` fails with `NOT_FOUND` when the request's resource is not bound to a vault entry; `approve_with_entry` binds and approves. `ApprovedScopeFfi` is an alias of `AccessSpecFfi`.
- **A** Methods:
  - `set_locale`, `import_encrypted`, `replace_recovery_key`, `set_master_password`, `recover_with_key`;
  - `rotation_tasks`, `dismiss_rotation_task`, `save_from_autofill`;
  - `set_local_relay`, `bind_resource`, `pending_approvals`, `pending_connections`, `last_snapshot`, `deny_connection`, `set_license_public_key`;
  - free functions `default_password_rules` and `core_version`; object `LocalRelay`.
- **C** / **A** Shapes:
  - timestamps are `i64` Unix seconds, and enum-like values are snake_case strings;
  - `CoreStatus` adds `rollback_detected`, `revoked`, `key_epoch`, `relay_configured` and **`device_sign_pk` / `device_kem_pk`** (b64u);
  - `DeviceFfi` adds **`sign_pk` / `kem_pk`**, used by mobile apps for `POST /v1/devices`;
  - `TotpCode` adds `period`;
  - `LicenseStatusFfi` adds `grace_until`, `in_grace_period` and `dev_key`;
  - `CoreError` is a uniffi enum with the single variant `Failure{code, message}`. The generated Kotlin `Failure.message` clashes with `Throwable.message`; Android patches its copy, and the upstream rename is open.
- **C** The licence check is Ed25519 over the exact decoded first token segment (the JCS payload bytes). `device_id` must equal this device, and the token is valid until `max(exp, grace_until)`. FFI metadata-only state lives in `<data_dir>/ffi-state.json`. Feature `test-support` exposes `TestExecutor`; it is never in the production bindings.
- **S** (review fix, §12 edited in place) Approval TOCTOU closed: `approve(id, request_digest, narrowed?)`, `approve_with_entry(id, request_digest, narrowed?, entry_id)` and `deny(id, request_digest)` take the displayed request's digest (`aipass_types::approval::request_digest`, §7) and refuse with `INTEGRITY_FAILED` if the stored request no longer hashes to it (nothing is bound, signed or sent). A pending approval is never replaced: a second copy with different content keeps the first, sets `ApprovalRequestFfi.conflict = true`, and approving it is refused (deny stays possible). Requests (relayed or in a snapshot) are accepted only when the relay sender equals `request.executor.executor_id`, and `approval.cancelled` only from the request's sender. `ApprovalRequestFfi` adds `request_digest`, `conflict`, `parameters_digest`. Swift / Kotlin bindings regenerated; the iOS and Android apps pass the digest of the request on screen. The desktop applies the same rule: `list_approvals` rows carry `request_digest` and `approve_request` / `deny_request` require it.

### 16.10 Cloud (§13)
- The **v1.1** entries already listed in §13 are part of this build: `PATCH /v1/me`, `POST /v1/auth/verify-email/resend`, `GET /oauth/authorize/wait`, offboarding item marking, `DELETE /v1/orgs/{id}/vaults/{vault_id}`, and the tunnel frame additions (`requested_projects`, `auth.ok`, `protocol_version`, `http_method`, `error` frame, `/mcp` status pass-through).
- **D** `/oauth/token` and `/oauth/register` return RFC 6749/7591 `{error, error_description}` instead of the §1.5 envelope.
- **C** `/mcp` without the `remote_gateway` entitlement → `402 PAYMENT_REQUIRED`. When the node is offline, `tools/call` gets an `isError` result with `EXECUTOR_OFFLINE`, and other methods get JSON-RPC `-32000` with `data.code:"EXECUTOR_OFFLINE"`.
- **C** The relay store is a per-instance SQLite file (`AIPASS_CLOUD_RELAY_DB`); the tunnel registry, limiters, replay cache and long-poll are in-process (single-instance design). After every tunnel reconnect the node re-announces its remote connections' status (live first, ≤ 256), and the cloud re-sends `connection.revoke` for any connection it has as removed.
- **A** Response fields: `subscription.sync_read_only` and `via_org`. `checkout` accepts `org_id` and returns `checkout_id`. `/v1/plans` is `{plans, pricing_label, trial_days}`. Connections include `display_name_self_declared`. The invitation response includes `accept_url` once.
- **A** Env vars: `AIPASS_CLOUD_LISTEN`, `AIPASS_CLOUD_CONSOLE_URL`, `AIPASS_CLOUD_SECRETS_KEY`, `AIPASS_CLOUD_RELAY_DB`, `AIPASS_CLOUD_CONSOLE_DIST`, `AIPASS_CLOUD_DEV`, `AIPASS_CLOUD_INSECURE_FAST_KDF`, `STRIPE_API_BASE`, `APNS_BASE_URL`, `FCM_BASE_URL`, `PUSH_PROVIDER`, `APPSTORE_NOTIFICATIONS`, `PLAY_NOTIFICATIONS`.
- **S** Devices and push:
  - device rows are keyed by `(user_id, device_id)`;
  - a push is delivered only when the registration's `sign_pk` equals the device's active vault-member key and the account has `push`;
  - the push limiter is per `(user_id, device_id)`.

  *Deferred:* proof of possession (device-key signature) on `POST /v1/devices` and `PUT /v1/devices/{id}/push`.
- **S** `audit.batch` events are ingested only into the org named by each event's `org_id`, and only when the node owner is a member of it. App Store and Play notification endpoints always return `501 NOT_SUPPORTED`; unverified notifications are never applied. Mock billing and the log mailer are refused outside dev mode.
- **S** Team SSO:
  - it signs in only identities explicitly linked by the member;
  - it never creates accounts and never links to unverified accounts;
  - the SSO state is bound to the starting browser;
  - the issuer may not point to internal hosts;
  - changing the issuer drops every link;
  - org vaults are owned by the org, not by the creator's personal account;
  - accepting an invitation requires a verified e-mail;
  - the issuer must resolve to public addresses (loopback is allowed only in dev mode);
  - the dev log mailer writes mail to 0600 files in `AIPASS_CLOUD_DEV_MAIL_DIR`, never into the server log.
- **C** The licence signature covers the JCS payload bytes (the decoded first segment).

### 16.11 Mobile clients & UX (§14)
- **D** Android `values/` holds English and `values-zh-rCN/` holds zh-CN, so zh-CN devices get Chinese while zh-TW / zh-HK fall back to English. iOS uses `Localizable.strings` / `InfoPlist.strings` (zh-Hans default + en) instead of a String Catalog.
- **C** Re-authentication policy (iOS and Android):
  - the system biometric / passcode prompt is required before unlock, reveal/copy, export, recovery management, device revoke, accepting a connection, resuming a paused connection, and every approval decision;
  - deny, stop access, pause and remove never ask.
- **C** Android stores app associations as a non-sensitive custom field `android_app:<package>` (value: comma-separated SHA-256 signing-certificate fingerprints), because the core accepts only http(s) URLs. Other clients must preserve these fields.
- **C** StoreKit product ids are `com.aipass.app.personal_monthly|personal_yearly`, and `appAccountToken` is a stable UUID derived from the cloud user id. Play purchases carry the cloud `user_id` as `obfuscatedAccountId`. Premium gating follows the **cloud licence only**, never the local store receipt.
- **C** Passkeys are not offered on any client in this build (`ProvidesPasskeys=false`); the UIs say so.
