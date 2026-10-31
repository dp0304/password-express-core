<!-- SPDX-License-Identifier: Apache-2.0 -->
# aipass-executor

**中文摘要**：AI 通行证的执行器与连接器。它实现 `aipass_types::exec::ExecutorBackend`，凭证只在执行器内存中按授权（grant）保存、到期或撤销即清零；提供 `postgres.query_view`（只读允许视图、参数化查询）、GitHub 指定仓库的五个读取操作、声明式 `http_api.call`，以及统一的出站防护（只允许 HTTPS、固定来源与已校验 IP、拒绝内网/元数据地址、不跟随重定向、超时与大小上限）和输出过滤（字段白名单 + 密钥检测 + 已安装凭证精确匹配）。实验性功能（`experimental` 特性，默认关闭）：PostgreSQL 密码轮换、临时数据库角色租约、通过网站适配器创建账号（仅附带的演示网站）。本组件尚未经过独立安全审计。

---

## Purpose

The executor runs operations that the Access Broker has already authorized. The broker
talks to it only through `ExecutorBackend` (CONTRACTS §8):

* **credential custody** — opens HPKE credential envelopes with the executor's X25519 key
  and the contract AAD `JCS({approval_request_id, digest, executor_id})`; keeps one
  zeroizing credential per grant with an expiry (clamped to 24 h + 60 s); drops it on expiry,
  `drop_credential`, `end_sessions` and revocation; `install_plain_credential` for the
  in-process desktop case;
* **connectors** — `postgres`, `github`, `http_api`, each with schema-validated parameters,
  allowlists, scope mapping (`required_scope`) and a JCS `parameters_digest`;
* **egress guard** and **output filter** shared by all connectors;
* **revocation levels 2 and 3** — `end_sessions` (cancel running operations, close sessions,
  wipe the credential) and `revoke_upstream` (temporary-role leases; honest
  `not_applicable` for imported static credentials).

## Architecture

| module | what it does |
| --- | --- |
| `executor` | `Executor`, `ExecutorBuilder`; running-operation registry (cancel by operation id), re-normalization check (the request's `parameters_digest` must match a fresh normalization against the resource config), resource/executor/credential binding checks, online + control-channel flags |
| `custody` | `CredentialCustody`, `InstalledCredential` (redacted `Debug`, no `Serialize`) |
| `connectors::postgres` | config, parameter normalization + SQL builder, TLS/pool/cancel, experimental rotation and leases |
| `connectors::github` | five read operations with fixed output allowlists |
| `connectors::http_api` | declarative operations → `http_api.call` |
| `egress` | address classification, resolvers (`DefaultResolver` = hickory with system config, OS fallback; `SystemResolver`; `StaticResolver`), pinned HTTPS client |
| `filter` | `FieldTree` projection, `OutputFilter` detectors, final serialized-output sweep |
| `schema` | small JSON-Schema subset for `http_api` request bodies (unsupported keywords fail closed) |
| `tls` | rustls configs (single aws-lc-rs provider) |
| `experimental` | `SiteAdapter`, `AccountCreator`, `PendingRegistrationStore`, `DemoSiteAdapter` |

Security invariants enforced in code and tests:

* raw credentials never appear in `ExecutionOutcome`, `ApiError` (messages or details),
  `Debug` output or `tracing` logs — upstream error texts, response headers and URLs (which
  can carry a query-string key) are never copied;
* the model never supplies SQL, URLs, hosts, header names or file paths outside a
  validated, allowlisted shape;
* randomness only from the OS CSPRNG (`aipass-crypto`); TLS only via rustls/aws-lc-rs;
* no automatic retries; a possibly-applied write is `UPSTREAM_OUTCOME_UNKNOWN`.
* `end_sessions` / `drop_credential` remove the credential **before** cancelling the
  running operations, and `execute` registers before it looks the credential up: an
  operation racing the teardown is either cancelled or finds no credential, and a
  finishing rotation never reinstalls a dropped credential (compare-and-swap).

### postgres

Config (contract keys plus additive optional keys):

```json
{"host": "db.internal", "port": 5432, "dbname": "lure", "sslmode": "verify-full",
 "ssl_root_cert": "-----BEGIN CERTIFICATE-----…",
 "allowed_views": {"analytics.subscription_daily": {
     "fields": ["day", "plan", "subscriptions"], "date_field": "day",
     "row_filter": [{"field": "tenant_id", "op": "eq", "value": "lure"}]}},
 "statement_timeout_ms": 5000, "max_rows_per_operation": 1000,
 "allow_superuser": false, "lease_mode": "static", "connect_timeout_ms": 10000}
```

`postgres.query_view` params: `{view, fields[], filters?:[{field, op, value?}], order_by?:[{field, direction}], limit?, period_days?}`.
Names must match the allowlist exactly; identifiers are emitted quoted from the config; each
value is a bound text parameter cast to the column type from `information_schema.columns`
(cached 5 min per role/view; a column the role cannot see is `SCOPE_DENIED`). Execution:
`BEGIN READ ONLY` (sessions also default to read-only), `SET LOCAL statement_timeout`,
`SET LOCAL search_path TO pg_catalog, pg_temp`, `SELECT row_to_json(t)::text FROM (…) t`,
rolled back afterwards. Row cap = min(`limit`, config cap, grant per-op limit, remaining
grant rows); byte cap = remaining `max_result_bytes`. Required scope =
`{operations:["postgres.query_view"], postgres:{views:{view: fields ∪ filter fields ∪ order fields}}}`.
New sessions are refused (`SCOPE_DENIED`, `details.reason = "privileged_role"`) when the role
is superuser, has `BYPASSRLS`, or is a member of `pg_read_server_files` /
`pg_write_server_files` / `pg_execute_server_program`, unless `allow_superuser`.
A credential whose vault `DatabaseInfo` names another host/port is never sent.
Per-grant pool (≤ 4 sessions), cancel = `CancellationToken` + PostgreSQL cancel request.
Result data: `{"view", "fields", "rows": [{…}]}`.

`sslmode`: `disable`; `prefer` / `require` = TLS **without** certificate verification
(libpq semantics; with `ssl_root_cert`, `require` verifies the chain but not the host name);
`verify-full` = chain + host name against Mozilla roots plus `ssl_root_cert`. Default when
omitted: `require`. Use `verify-full` for anything outside a trusted network.

### github

Config `{allowed_repos:["owner/name"], api_base?, allow_private_network?, timeout_ms?}`.
`api_base` defaults to `https://api.github.com` (a GHES base must be https; internal GHES
needs `allow_private_network`). Operations (read, retry-safe): `github.repo.get {repo}`,
`github.contents.get {repo, path, ref?}` (UTF-8 text ≤ 256 KiB, binary not returned),
`github.issues.list {repo, state?, labels?, per_page ≤ 100, page ≤ 100}`,
`github.pulls.list {repo, state?, per_page, page}`, `github.commits.list {repo, sha?, path?, per_page, page}`.
`per_page` is capped by the remaining row budget. Output field allowlists are in
`connectors::github::output_fields`. 401 → `INTERACTIVE_AUTH_REQUIRED` (message tells the
user to re-authorize on a trusted device and never to paste tokens into chat); rate limits →
`RATE_LIMITED` with `retry_after_seconds`; redirects are not followed.

### http_api

Config `{base_url (https), auth:{type:"bearer"|"header"|"query"|"basic", name?}, allow_private_network, timeout_ms?, max_response_bytes?, operations:{name:{method, path, path_params?, query?, body_schema?, side_effect, retry_safe, response:{items_path?, allowed_fields, on_secret_detected?:"redact"|"withhold"}, description_zh?, description_en?}}}`.
The AI calls **`http_api.call`** with `{operation, params, body?}`; scope is
`{operations:["http_api.call"], http_api:{operations:[name]}}`. Path parameters are encoded
as single segments (`/`, `?`, `#`, `%` escaped; `.`/`..` rejected), query values are typed
(string/integer/boolean with enum/min/max/pattern), bodies are validated by `body_schema`
(`additionalProperties` defaults to false; floats rejected). An omitted body of an
operation with a `body_schema` is `{}` and must pass the schema too (so `required` /
bounds cannot be skipped); the normalized params always carry the body that is sent, and
the executor never adds one. Row/byte budgets are checked before anything is sent. Writes
report `side_effects: applied`; a timed-out / 5xx / redirected (3xx) write, or one whose
non-2xx answer exceeds the size cap, is `UPSTREAM_OUTCOME_UNKNOWN`. Once a write was
accepted (2xx) it never turns into an error: if its result cannot be returned (secret
detected under `withhold`, final leak sweep, larger than `max_result_bytes` or the
response cap) the outcome is `Ok` with `side_effects: applied`, `rows: 0`, data
`{operation, status, withheld: true, reason}` and `restricted_fields` set (`"result"` when
no single field is named).
`Executor::resource_operation_specs` lists the declared operations inside the
`http_api.call` schema (`enum` + `x-operations`).

### Egress guard

https only; request origin must equal the configured origin; DNS resolved once and **all**
answers must pass; the HTTP client gets a resolver that only answers with the vetted
addresses (no re-resolution → DNS-rebinding safe); environment proxies ignored; redirects
never followed; total timeout ≤ 10 s; body ≤ 1 MiB; no retries; no decompression.
Blocked unless `allow_private_network`: loopback, RFC 1918, CGNAT, link-local, ULA,
site-local, documentation/benchmark/IETF ranges, IPv4-mapped/compatible, NAT64, 6to4,
Teredo. **Always** blocked: cloud metadata (`169.254.169.254`, `169.254.170.2`,
`100.100.100.200`, `fd00:ec2::254`), unspecified, broadcast, multicast, `240/4`.

### Output filter

Field allowlist projection first (primary boundary), then detectors (`ghp_`/`gho_`/`ghs_`/…,
`github_pat_`, `sk-`, `sk-ant-`, Stripe secret keys, `AKIA`/`ASIA`, `xox?-`, Google API
keys, JWTs, PEM private keys, `scheme://user:pass@`, `Bearer …`, `Authorization: …`,
`password=…`) plus exact matching of the installed credential's secret (raw, base64,
base64url, percent-encoded, JSON-escaped, `user:secret` base64) and username. Matching
values become `"[REDACTED]"` and their path goes to `restricted_fields`; a final sweep over
the serialized result withholds the whole result (`RESULT_RESTRICTED`; for an applied
`http_api` write a withheld `Ok` outcome, see above) if anything remains.
This is a **secondary** defence — it cannot stop deliberate encoding or splitting (§9.8).

### Experimental (cargo feature `experimental`, off by default — 实验性)

* `credentials.rotate` (scheme `postgres.password`) as an operation on postgres resources:
  CSPRNG candidate → `ALTER ROLE … PASSWORD '<SCRAM verifier computed client-side>'` →
  verify a fresh login → swap the grant's installed credential. The new credential is never
  in the operation result; the broker seals it to the approving device with
  `Executor::seal_rotation_result` and calls `confirm_rotation_persisted` once stored.
  PostgreSQL has one password per role, so "old stays valid until verified" is implemented
  as restore-on-failure; if neither can be confirmed the outcome is `UPSTREAM_OUTCOME_UNKNOWN`
  and the candidate is held (memory only, 24 h) for the trusted device.
* `lease_mode: "temporary_role"` with `temporary_role:{template_role, ttl_seconds, connection_limit}`:
  per-grant `CREATE ROLE … VALID UNTIL … IN ROLE template` from an issuer credential;
  `revoke_upstream` terminates the role's backends, drops it and verifies; failures are
  `failed` / `pending` with an explanation (never `done`), and the maintenance sweep retries
  and revokes expired leases. The issuer needs `CREATEROLE`, `ADMIN OPTION` on the template
  and `pg_signal_backend`.
* `experimental::{SiteAdapter, AccountCreator, PendingRegistrationStore, DemoSiteAdapter}` for
  `accounts.create` / `browser.start_task` on **adapted sites only**: password from the CSPRNG,
  pending record persisted before submit, idempotency key required, outcomes
  `created | needs_verification | unknown`, reconciliation (exists → login) before any retry.
  Only the bundled demo site (`examples/demo_site.rs`) is adapted; there is no real
  controlled-browser driver in this build.

## Build, test, run

From `open-source/`:

```sh
cargo build -p aipass-executor
cargo build -p aipass-executor --features experimental
cargo test  -p aipass-executor                       # V1
cargo test  -p aipass-executor --all-features        # + experimental rotation, leases, accounts
cargo clippy -p aipass-executor --all-targets --all-features
cargo run   -p aipass-executor --example demo_site   # demo site on 127.0.0.1:8090
```

The PostgreSQL tests start a temporary cluster with Homebrew `initdb`/`pg_ctl` (PostgreSQL 17)
on **port 55441** (TLS with a test CA, SCRAM auth, lure-store style schema: raw
`shop.customers` with e-mails and tokens, `analytics.subscription_daily`, an RLS-protected
`security_invoker` view, read-only / superuser / BYPASSRLS / file-access roles). The cluster
is stopped and deleted on drop, and a watchdog stops it if the test process dies. GitHub is
tested against a local axum mock (the base override only exists with the `test-util`
feature, enabled for this crate's tests via a self dev-dependency); `http_api` against a
local HTTPS server with an rcgen CA and a static resolver. No test contacts the internet.

Use from a host binary:

```rust
let exec = Arc::new(Executor::builder(executor_id, "my node", identity)
    .protection_level(ProtectionLevel::Compatible)
    .build()?);
let maintenance = exec.spawn_maintenance(Duration::from_secs(30));
let backend: Arc<dyn ExecutorBackend> = exec.clone();
```

## Limitations

* Not independently audited. Detection-based redaction is best effort.
* An executor embedded in the desktop app is `compatible` (兼容连接): it shares the user
  environment and cannot resist same-user code, debuggers or memory inspection (§9.3).
* `sslmode=prefer|require` without `ssl_root_cert` do not authenticate the server (libpq
  semantics); a MITM could observe a password if the server negotiates cleartext auth.
* GitHub and real public APIs are exercised only against local mocks here; `api.github.com`
  itself was not contacted. hickory DNS resolution is not exercised by the tests
  (`StaticResolver` is used).
* `revoke_upstream` for imported static credentials (DB passwords, GitHub tokens, API keys)
  is `not_applicable`: the executor cannot revoke them upstream; rotate them if exposure is
  suspected.
* Rotation results and lease issuer credentials live only in executor memory; an executor
  restart before the trusted device stores a rotated password loses it (the user must reset
  the database password manually).
* The executor caps rows/bytes per call from `remaining`; cumulative request counting
  (`max_requests_per_grant`) is the broker's job (`scope_covers` returns false at zero).
* No HTTP/1.1 response streaming beyond the 1 MiB cap; no JSON floats in `http_api`
  parameters/bodies (canonical JSON rule).

## Contract deviations

* **`http_api` operation naming** (contract leaves it implicit): the AI-facing operation is
  the single `http_api.call` with `{operation, params, body?}`; declared operation names go in
  `GrantScope.http_api.operations`. `operation_specs("http_api")` returns `http_api.call`;
  `Executor::resource_operation_specs` adds the declared operations.
* **Additive config keys** (unknown keys are rejected): postgres `ssl_root_cert`,
  `connect_timeout_ms`, per-view `row_filter`, `temporary_role`; github `api_base`,
  `allow_private_network`, `timeout_ms`; http_api `timeout_ms`, `max_response_bytes`,
  `path_params`, parameter `min`/`required`/`pattern`/`description`, response
  `on_secret_detected`, operation `description_zh`/`description_en`. `sslmode` defaults to
  `require` when omitted.
* **Stricter than the contract**: cloud metadata, unspecified, broadcast, multicast and
  reserved addresses stay blocked even with `allow_private_network: true`; members of the
  server-file roles are refused like superusers.
* **Cancelled operations** have no contract error code: the executor returns
  `UPSTREAM_ERROR` with `details.reason = "cancelled"` (the broker owns the `cancelled` state);
  a cancelled in-flight write is `UPSTREAM_OUTCOME_UNKNOWN`.
* **`credentials.rotate`** is an executor operation on postgres resources (scope
  `operations:["credentials.rotate"]`, params `{scheme:"postgres.password"}`); its new
  credential is delivered through the inherent `Executor::seal_rotation_result(rotation_id =
  operation_id, device_kem_pk)` with AAD `JCS({purpose:"credentials.rotate", rotation_id,
  entry_id, executor_id})`, `info=aipass/v1/credential`. The returned material has
  `version = old + 1` as a proposal; the vault assigns the stored version.
* **Result data shapes** (contract leaves `data` open): postgres `{view, fields, rows}`;
  github `{repo}` / `{repo, path, type, text|entries, …}` / `{repo, page, per_page, has_more, items}`;
  http_api `{operation, status, items|item}`.
* **`LevelReport.detail`** is a single string, written as `"<zh> / <en>"`.
* A non-list result larger than the byte cap is withheld with `RESULT_RESTRICTED`
  (`details.reason = "result_too_large"`); lists are truncated (`truncated: true`).
