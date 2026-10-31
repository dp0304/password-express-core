<!-- SPDX-License-Identifier: Apache-2.0 -->
# aipass-storage

对象存储抽象与各后端（CONTRACTS §3.1，设计文档 §10）。存储里只有密文、签名清单和成员记录；
ETag 只用于并发控制，不能替代内容签名或完整性校验（§10.3）。

Object storage abstraction and backends for encrypted vault sync (CONTRACTS §3.1, design
doc §10), plus the relay mailbox client (CONTRACTS §4). Storage only ever holds ciphertext,
signed manifests and member records.

## What is here

| item | purpose |
| --- | --- |
| `ObjectStore` trait, `Object`, `ObjectMeta`, `PutCondition`, `PutOutcome`, `StorageError`, `StorageDescription` | the trait layer (foundation step, unchanged) |
| `MemoryStore` | in-memory, exact conditional semantics (tests) |
| `LocalDirStore` | local directory (V1) |
| `S3Store` + `sigv4` | S3-compatible buckets (V1, **only after the capability test passes**) |
| `HttpSyncStore` | client of the device-signed sync API of the official service / self-hosted node (V1) |
| `WebDavStore` | **experimental (V1.1, 实验性)** WebDAV |
| `PrefixedStore` | namespace any store below a key prefix |
| `capability_test` | read / write / list / conditional create (incl. 8-writer race) / conditional update / delete probe → `sync_capable` or `backup_only` (仅可备份) |
| `profile::open_store` | build a backend from a non-secret `StorageProfile` + separately supplied secrets |
| `relay_client::RelayClient` | POST / long-poll GET / DELETE on `/v1/relay/{mailbox}` |
| `http::{VaultInfo, ListObjectsResponse, PutObjectResponse, create_vault_body, map_api_error}` | wire shapes of the sync API, shared with `aipass-sync-server` |

## Architecture notes

### LocalDirStore
* Key → path mapping only for keys accepted by `validate_key` (`[A-Za-z0-9._-]` segments,
  no `..`, no empty segments); every existing path component under the root is checked
  not to be a symlink. Names starting with `.aipass-` are reserved; listings skip dot-files
  and symlinks. Root is canonicalized once at open.
* Writes go to `<root>/.aipass-tmp/<random>`, are `fsync`ed, then published:
  `IfAbsent` with `link(2)` (atomic `EEXIST`; fallback on filesystems without hard links:
  `O_EXCL` claim + atomic rename — a concurrent reader may then briefly see an empty file);
  `IfMatch` / `None` / delete under an exclusive `flock` on `<root>/.aipass-lock` (works
  across processes) with compare-and-rename.
* ETag = b64u(SHA-256(content)) — identical bytes have identical ETags, so writing the same
  content again is not observable as a change by compare-and-swap.
* Files `0600`, directories `0700` (Unix).

### S3Store
* SigV4 header signing with signed payload (`x-amz-content-sha256`); signed headers:
  `host`, `x-amz-content-sha256`, `x-amz-date`, `x-amz-security-token` (session
  credentials), `if-none-match` / `if-match`. The implementation in `sigv4.rs` reproduces
  the AWS published vectors: S3 developer guide examples (GET Object, PUT Object, GET Bucket
  Lifecycle, List Objects) and the `aws-sig-v4-test-suite` cases `get-vanilla`,
  `get-vanilla-query-order-key-case`, `get-vanilla-with-session-token`,
  `post-x-www-form-urlencoded`, `get-space-normalized`.
* Path-style (`host/bucket/key`, default) or virtual-host (`bucket.host/key`), region,
  key prefix, `S3CredentialProvider` for static or refreshed temporary credentials.
* `If-None-Match: *` / `If-Match: "<etag>"`; `412` and `409 ConditionalRequestConflict` →
  `PreconditionFailed`; `404` on an `If-Match` of a missing key → `PreconditionFailed`.
* ListObjectsV2 with `start-after`, `max-keys` ≤ 1000 and continuation tokens.
* TLS: rustls (aws-lc-rs) through reqwest; plain `http` only for loopback endpoints or with
  the explicit `allow_http` development flag; redirects are never followed; error messages
  carry only the S3 error *code*, never the response body (S3 echoes the string-to-sign).

### HttpSyncStore
* Every request is signed with `AIPass-Sig` (CONTRACTS §1.6) over the exact path + query
  sent (`kid` = `dev_…` or `exe_…`, never `conn_…`). 4 MiB client-side object limit.
* `create_vault` posts `{"vault_header": <exact bytes>, "genesis_member": <exact bytes>}`
  so the server stores the very bytes the client hashes into its manifests.
* Error envelopes map to `StorageError` by code only (`IDENTITY_UNVERIFIED` / `FORBIDDEN` →
  `Unauthorized`, `RATE_LIMITED` → `RateLimited`, `QUOTA_EXCEEDED` / `PAYMENT_REQUIRED` →
  `Backend{status, code}`, `INVALID_REQUEST{reason:"too_large"}` → `TooLarge`).

### WebDavStore (experimental)
* `PUT` with `If-None-Match: *` / `If-Match`, `GET`, `DELETE`, `MKCOL` for missing parents
  (top-down, cached), listing by recursive `PROPFIND Depth: 1` (servers commonly disable
  `Depth: infinity`), namespace-agnostic `multistatus` parsing with `quick-xml`.
* If a server returns no ETag on `PUT`, a `PROPFIND Depth: 0` fetches it (not atomic with
  the write). If a server returns no ETag at all, a synthetic `local-…` ETag is reported and
  conditional updates fail — such servers end up `backup_only`.
* Basic auth only over https (or loopback).

### Relay client
* `RelayAuth::Signed {kid, signer}` (device / executor) or `RelayAuth::PairingSecret` for
  `pair_…` mailboxes (`X-AIPass-Pairing-Secret`, b64u of the 16-byte QR secret).
* `fetch(mailbox, after, wait ≤ 25)` long-polls; `RelayClientError` distinguishes API
  errors, network failures and timeouts. A failed relay never means approval — callers fall
  back to "open the app to fetch pending requests".

## Build / test

```bash
cd open-source
cargo build -p aipass-storage
cargo test  -p aipass-storage
```

Tests:
* `src/sigv4.rs` — the AWS SigV4 vectors listed above.
* `tests/backends.rs` — LocalDirStore semantics, traversal / symlink refusal, private file
  modes, two-instance create-only and compare-and-swap races (exactly one winner),
  capability test `sync_capable`; S3Store against an in-test axum mock that **verifies every
  SigV4 signature** (path-style, virtual-host via DNS override, session token, small-page
  pagination, 409 mapping, wrong secret → `Unauthorized`), a mock that ignores conditions
  (→ `backup_only`); WebDavStore against strict (→ `sync_capable`) and lax (→ `backup_only`)
  mocks, MKCOL, missing-ETag fallback, Basic auth; PrefixedStore; profile factory.
* `tests/trait_layer.rs` — MemoryStore and broken stores (foundation).
* HttpSyncStore and RelayClient are tested end-to-end against the real routers in
  `crates/aipass-sync-server/tests/`.

## Limitations (honest)

* **No real S3-compatible service was exercised in this environment** (no network
  credentials, no MinIO/Docker). S3 behaviour is verified against the AWS published SigV4
  vectors and a local mock. Per design doc §10.1 / A15, a provider may only be listed as
  compatible after the full sync / concurrency / recovery tests pass **against that
  provider** — the capability test is the gate at setup time, not a promise.
* WebDAV is experimental (V1.1) and tested only against a mock server; real servers vary in
  conditional-request support.
* LocalDirStore listing reads each listed file to compute its ETag (fine for vault sizes;
  not meant for millions of objects). On filesystems without hard links the create-only
  fallback can briefly expose an empty file to concurrent readers.
* reqwest honours `HTTP(S)_PROXY` environment variables for storage traffic.
* This code has not had an independent security audit.

## Contract deviations

* Additive: `validate_prefix`, `normalize_root_prefix`, `PrefixedStore`, `profile::open_store`,
  `S3CredentialProvider` and the sync-API wire types live in this crate (the contract does not
  place them).
* Clarification: `StorageError` mapping of sync-API error codes as listed above;
  `QUOTA_EXCEEDED` is reported as `Backend{status: 429}` (not retryable), not as
  `RateLimited`.
* WebDAV: synthetic `local-<b64u sha256>` ETags when the server provides none (see above).
