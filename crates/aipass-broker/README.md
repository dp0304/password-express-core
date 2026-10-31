<!-- SPDX-License-Identifier: Apache-2.0 -->
# aipass-broker

授权代理（Access Broker）：决定一个 AI 连接能否执行某项操作，并如实记录发生了什么——身份、
签名策略、授权（grant）、审批、操作状态机、额度、三级撤销、哈希链审计和 HTTP API。代理本身
从不接触凭证：执行通过 `ExecutorBackend` trait 完成，凭证只以密封信封的形式经过代理。
**尚未经过独立安全审计。**

The Access Broker decides whether an AI connection may do something and records what
happened: identity, signed policies, grants, approvals, the operation state machine,
budgets, three-level revocation, the hash-chained audit log and the HTTP API (CONTRACTS §6,
§7; design doc §5.3, §7.3–7.6, §8, §9.2–9.3, §11.4–11.5, §12). It never sees credentials:
execution goes through `aipass_types::exec::ExecutorBackend`, and credentials pass through
only as HPKE envelopes sealed to the executor. **Not yet independently audited.**

## Architecture

| module | responsibility |
| --- | --- |
| `broker/` | `Broker` (shared as `Arc<Broker>`): connections & pairing, projects/resources, policies, approvals & decisions, operations pipeline, grants & revocation, trusted devices & relay messages, activity/snapshot, sweeper |
| `db` / `store` | SQLite (`<data>/broker.db`, mode 0600, WAL, forward-only migrations via `user_version`); one connection behind a mutex, every call on the blocking pool; row mapping |
| `audit` | hash chain `hash = b64u(SHA-256(prev_hash_bytes ‖ JCS(event − hash)))`, appended in the **same transaction** as the state change; full-chain verification |
| `redact` | redacted parameter summaries for audit; secret-pattern detector; resource-config secret guard |
| `summary` | zh-CN / en approval summaries in the §5.3 field order |
| `http/` | axum `router()` (all §6.3 endpoints), auth middleware (C/D/A/P), error envelope, `serve_uds` / `serve_tcp` |
| `handle` | `ConnectionHandle` — the C calls bound to one connection, mirroring `aipass_client::BrokerApi` |
| `notify` | hooks: `ApprovalNotifier`, `DeviceOutbox`, `RelayIdentity`, `CredentialSource`, `BrokerEvent` |

### Operation pipeline (CONTRACTS §6.2, re-checked on every request)

1. Connection authenticated and `active` (`IDENTITY_UNVERIFIED` / `CONNECTION_PAUSED`).
2. Idempotency `(connection_id, idempotency_key)`: exact replay → existing operation; same
   *normalized* parameters → existing operation; otherwise `IDEMPOTENCY_CONFLICT`. The
   unique index makes concurrent duplicates collapse into one operation.
3. Resource must be in the connection's `allowed_projects` (else `NOT_FOUND`, identical to a
   missing resource); entry conflict → `SYNC_CONFLICT`; disabled → `SCOPE_DENIED`.
4. `ExecutorBackend::normalize` (`INVALID_REQUEST` / `SCOPE_DENIED`); the broker recomputes
   `parameters_digest` itself.
5. Executor online and control channel up (`EXECUTOR_OFFLINE` / `CONTROL_CHANNEL_LOST`) —
   checked *before* asking anyone to approve something that cannot run.
6. Grant match: active, unexpired, same connection + resource + executor, budget left, and
   **both** the generic check (`operation ∈ grant.scope` and
   `approval::scope_is_subset(required_scope, grant.scope)`) and the executor's
   `scope_covers`. Else a signed `rule` policy with `auto_approve` (test environment +
   read-only operations, re-verified on every use) → grant + audit `rule.auto_approved`.
   Else throttle (same connection+resource+operation denied < 10 min ago, or ≥ 5 pending
   approvals → `RATE_LIMITED`). Else an `ApprovalRequest` (TTL 120 s) is created, in-process
   listeners and trusted devices are notified, and `approval_required` is returned
   immediately (exact §12.2 message). The broker never waits for a phone and never approves
   on timeout.
7. Run (in its own task, so a disconnecting caller cannot leave half-settled state): wait
   for an executor slot (`authorized` = the queue `stop_access` rejects), executor/channel
   check, credential delivered (else `SECRET_UNAVAILABLE`), then one atomic transaction
   reserves the request and `min(rows_per_operation, remaining rows)` rows and moves
   `authorized → running`. The executor gets the remaining limits. Settlement (one
   transaction) adds actual rows/bytes, releases the reservation, marks the grant
   `exhausted`, stores the filtered result and appends the audit event.
8. Outcome: results larger than `max_result_bytes`, or more rows than reserved, are withheld
   (`RESULT_RESTRICTED`); `UPSTREAM_OUTCOME_UNKNOWN` → `unknown` with `side_effects: possible`
   (one automatic retry only if the operation is `retry_safe`); broker-side timeout → read:
   `failed`/`UPSTREAM_ERROR`, write: `unknown`; executor panic → `failed`/`INTERNAL`.

Every transition goes through `store::transition`, which only applies legal
`OperationStatus::can_transition` moves from the expected current state.

### Approvals and decisions (§7)

A decision is accepted only if the signer is an **active owner/member** in the trusted
device set, the request is still pending and inside its window, the digest recomputed from
the *stored* request matches, the Ed25519 signature verifies, `approved ⊆ requested`, and
`expires_at ≤ now + duration + 60` (`aipass_types::approval::verify_decision`). The digest
is **§7 v2**: for `kind:"operation"` it binds the waiting `operation_id` and its
`parameters_digest` (carried in `ApprovalRequest.parameters_digest`), and the broker also
checks that the stored operation still has exactly that id, connection, resource, operation
and normalized-parameter digest and is linked to this request (`INTEGRITY_FAILED`
otherwise). v1 digests never verify. Rejections are audited (`approval.decision_rejected`). On approval the grant is created, the sealed
credential envelope is installed via `ExecutorBackend::install_credential` (AAD
`{approval_request_id, digest, executor_id}`) — or, without an envelope, via the in-process
`CredentialSource` — and a waiting operation is resumed only if the (possibly narrowed)
grant still covers it (else `denied`/`SCOPE_DENIED`). `DecisionResponse.operation` never
includes result data: results go only to the requesting connection. Denial → operation
`denied`/`APPROVAL_DENIED` + throttle record. Expired requests become `expired` (sweeper
**and** lazily on every read), never approved (A10).

### Budgets (A08)

Usage counters are columns updated inside transactions on the single connection, so
concurrent requests cannot both pass a check-then-act. Rows are *reserved* before execution
(`reserved_rows`), so N concurrent pages cannot each see the full remaining budget. Once
grants serve one operation; task grants until expiry/budget. A rule policy creates at most
one grant per policy version per `grant_ttl_seconds` window, so exhausting a rule grant does
not refill the budget.

### Revocation (§8.4, A09)

`revoke_grant(level)`: **stop_access** (atomic status change; queued operations cancelled
with `GRANT_REVOKED`) → **end_sessions** (cancellation tokens fired, `ExecutorBackend::cancel`
for running operations, `end_sessions`, `drop_credential`, wait for them to stop) →
**revoke_upstream** (`ExecutorBackend::revoke_upstream`, lease records updated). Each
executor call is bounded by `revoke_step_timeout`; a slow or failing executor is reported as
`pending` / `failed`, never as `done`. A result that arrives after revocation is withheld.
`completed_at` is set only when every level is `done`/`not_applicable`
(`RevocationReport::fully_revoked`). Tests assert in-process revocation < 5 s, including an
executor that ignores cancellation. Revoking a trusted device revokes the grants it approved.

### Relay and device messages

`set_relay(RelayIdentity, Arc<dyn DeviceOutbox>)`: the broker seals `approval.request`,
`approval.cancelled` and `connection.pair_request` to each active approver device (HPKE to
its `kem_pk`, signed by the broker identity) and hands envelopes to the outbox in background
tasks. `handle_device_message(&RelayEnvelope)` accepts `approval.decision`,
`connection.decision`, `grant.revoke`, `connection.control`, `state.request` only if: addressed
to the broker's mailbox, sent by an active approver device, signature + HPKE verify, at most
24 h old (≤ 5 min in the future), never seen before (persisted replay cache), control
signature valid, and connection controls not older than the last applied one. It returns
sealed replies (`state.snapshot`, `revoke.report`) for the caller to post.

### HTTP API (`router(BrokerState)`)

Auth: **C** `AIPass-Sig kid=conn_…` (any non-removed connection's key; endpoints check
status) or `Bearer aipc_…` (SHA-256 hash lookup); **D** `AIPass-Sig kid=dev_…` (active
owner/member); **A** `Bearer <admin.token>` or a same-uid peer on a socket served with
`UdsOptions { admin_peers: true }`; **P** public, rate-limited per peer. Signatures cover the
raw path+query (`OriginalUri`) and the exact buffered body (≤ 1 MiB); nonces are persisted
for 600 s and recorded only after the signature verified. Every response has
`X-Request-Id: req_…` and `Cache-Control: no-store`; errors use the §1.5 envelope (zh-CN,
English for `Accept-Language: en…`). JSON parse errors never echo values.

All §6.3 endpoints are implemented. `GET /v1/connections` and `GET /v1/connections/{id}`
(D, A only) return `ConnectionView` rows — an `AppConnection` plus `pairing_code` and
`pairing_expires_at` while the connection is `pending` and its pairing is open, so a trusted
client can compare the code with the one the AI host shows before approving
(`Broker::get_connection_view` / `list_connection_views`; `get_connection` /
`list_connections` keep returning plain `AppConnection`s). AI connections (C) are refused
on these endpoints and never see a pairing code. Additive endpoints (see deviations):
`GET /v1/approvals/{id}`, `GET /v1/connections/{id}`, `POST /v1/connections/{id}/token` (A),
`POST /v1/admin/connections` (A), `GET /v1/admin/resources/{id}`,
`PUT /v1/admin/entries/{entry_id}/conflict` (D, A), `GET /v1/grants/{id}`, `GET /v1/state`
(D, A — the `state.snapshot` shape).

## Public API (summary)

```rust
use std::sync::Arc;
use aipass_broker::*;

let broker: Arc<Broker> = Broker::open(BrokerConfig::new(data_dir))?;   // or open_with_clock
broker.register_executor(executor.clone()).await?;                     // Arc<dyn ExecutorBackend>
broker.add_trusted_device(&Actor::System, device_public).await?;       // approver set
broker.set_relay(RelayIdentity { mailbox, identity }, outbox);          // optional
let _sweeper = broker.spawn_background();                               // keep the handle alive
let app = router(BrokerState::new(broker.clone()));                     // merge into your Router
serve_uds(app.clone(), &sock, UdsOptions { admin_peers: true }, shutdown).await?;

// in-process C calls (MCP tunnel handler, desktop):
let h = broker.connection_handle(ConnectionPrincipal::in_process(conn_id), Lang::ZhCn);
let resp = h.request_operation(&req).await?;
```

Requires a tokio runtime (the broker spawns execution and delivery tasks).

## Build / test / run

```sh
cd open-source
cargo build  -p aipass-broker
cargo test   -p aipass-broker        # 85 tests: unit + tests/*.rs with a fake ExecutorBackend
cargo clippy -p aipass-broker --tests
```

Test files: `pipeline` (state machine, idempotency, throttle, pause, expiry A10, cancel,
unknown outcome, executor offline / control channel, sync conflict, output caps, panics,
timeouts, sweeper, notifiers), `approvals` (A05 digest tampering, widening, untrusted
signers, expiry bound, narrowing, change after approval, access requests), `isolation` (A04),
`budget` (A08 pagination + concurrency), `revocation` (A09 latency, post-revoke denial,
running-op cancel, honest pending/failed), `policies` (auto-approve limited to test +
read-only, signatures, rule budget window), `connections` (pairing, tokens), `relay`
(sealed round trips, replay/order protection), `http` (the CONTRACTS §1.6 vector verbatim,
auth classes, pairing over HTTP, UDS 0600 + admin peers, TCP), `audit` (chain + on-disk
tamper detection, **no credential bytes anywhere in the database files**, restart recovery).

The crate is a library; it runs inside `aipass-node`, the desktop app and `aipass node`.

## Security notes

* No credential is ever stored, logged or returned: the database holds IDs, scopes,
  digests, sealed envelopes the broker cannot open, and filtered results (purged after
  `result_retention`, default 1 h). Audit stores parameters only as digest + redacted
  summary and results never. Errors carry codes and non-sensitive details only.
* IDs are never capabilities: every object lookup is scoped to the authenticated principal,
  and foreign or nonexistent objects both return `NOT_FOUND`.
* Admin token: `<data>/admin.token` (0600, prefix `aipadm_`), kept in memory only as a hash.
  Data directory 0700, database 0600, sockets 0600 in a 0700 directory.
* `display_name` / `host_type` are self-declared labels; summaries say so.
* After a restart, operations that were `running` become `unknown` (side effects possible),
  queued ones `failed`; in-process executor memory is gone, so credentials must be delivered
  again (`SECRET_UNAVAILABLE` until then); reserved rows count as used.
* A `once` approval of an operation binds its grant to that operation
  (`grants.bound_operation_id`): no other request in the same scope — different parameters
  the user never saw — can match or consume it, even while the approved one resumes (A05).
* Bulk revocation (`revoke_all`, device revoke, resource change, policy change) stops access
  to every target grant in one transaction before any executor / upstream call, then runs
  the executor steps concurrently; one grant's failure never leaves another usable (A09).
* A security-relevant resource change (environment, config, credential entry, executor,
  operations, disable) disables the resource's signed rules in the same transaction;
  `revoke_all` / `remove` disable the connection's rules. The owner must re-sign.
* A `pending` connection may sign only `GET /v1/connections/pair/{id}`; any other signed
  request is refused before its nonce is recorded. The replay cache has a per-key quota
  (`max_nonces_per_kid`, default 20 000) below the global cap.
* Pending pairings are capped per peer (`max_pending_pairings_per_peer`, default 3) below
  the global cap; in-process `begin_pairing` callers are only subject to the global cap.
* An existing device's `sign_pk` / `kem_pk` can never be replaced through
  `add_trusted_device` (`PRECONDITION_FAILED`, audited `device.key_change_rejected`);
  rotation is revoke + join under a new id.
* `stop_access` with nothing running also ends sessions and drops the credential when one
  may be present; a credential is recorded `dropped` only when the executor confirmed it,
  so the report never says "全部已收回" for unconfirmed steps.

## Limitations

* Not independently security-audited.
* Executors are in-process `ExecutorBackend` implementations; a remote-executor adapter is
  outside this crate.
* The audit chain detects modification, reordering and deletion of stored events; dropping
  the newest events is only detectable against a `head_hash` recorded elsewhere (e.g. by a
  trusted device from `GET /v1/audit`).
* Row reservations are conservative: while operations are in flight, a concurrent request
  may get `BUDGET_EXHAUSTED` even though the earlier ones end up returning fewer rows.
* Public-endpoint rate limiting is in memory, per peer IP (TCP) or per socket (UDS). All
  UDS peers share one pairing key (`uds`), so one local process can still use up the
  per-peer pending-pairing cap for other local hosts until its pairings expire.
* Adding a *new* approver device needs only the admin credential (bearer token or same-uid
  socket peer); a vault member record signed by an existing owner device is not yet
  required (design §10 device join).
* Plain HTTP only; TLS termination is the embedder's job (`aipass-node`).
* Unattended delegation (`/credentials/delegate`) is experimental (V1.1, off by default) and
  needs a `CredentialSource` that implements `install_delegated`; otherwise `NOT_SUPPORTED`.

## Contract deviations

None that change a shape another component depends on. Clarifications and additive
behaviour:

* **Error vs. operation response.** `POST /v1/operations` returns the §1.5 error envelope for
  anything decided before an operation exists (auth, validation, idempotency conflict,
  visibility, normalization, `SYNC_CONFLICT`, executor offline / control channel lost,
  throttling, in-flight cap). Once an operation exists the answer is an `OperationResponse`:
  `202` while pending, `200` when terminal — failures carry `error` (e.g. `failed` +
  `BUDGET_EXHAUSTED` / `SECRET_UNAVAILABLE`, `unknown` + `UPSTREAM_OUTCOME_UNKNOWN`).
  Throttled requests (`RATE_LIMITED`) create no operation.
* **Executor readiness before approval.** `EXECUTOR_OFFLINE` / `CONTROL_CHANNEL_LOST` are
  checked before an approval request is created (no prompt for work that cannot run) and
  again at run time.
* **Approval digest v2** (§7, contract edited in place): `operation_id` + `parameters_digest`
  are part of the digest (null for access requests) and are re-checked against the waiting
  operation; `ApprovalRequest.parameters_digest` is additive.
* **Pairing code for trusted principals** (§6.3, contract edited in place): see the HTTP API
  section above.
* **Additive endpoints** listed above; `POST /v1/connections/{id}/revoke_all` returns
  `{connection, reports:[RevocationReport]}`; `DELETE /v1/admin/resources/{id}` returns
  `{resource_id, status:"deleted"}` (soft delete; grants revoked, policies disabled).
* **Additive in-process API:** `ConnectionHandle`, `ConnectionPrincipal::in_process`,
  `import_connection` / `import_project` / `import_resource` (restore, tests),
  `set_entry_conflict`, `record_lease`, `set_control_channel`, `rotate_admin_token`, `sweep`.
* **Results only to the requester:** `DecisionResponse.operation`, `GET /v1/operations`
  (admin), snapshots and events omit `result`.
* **Rules:** auto-approval applies to operations; explicit `access.request`s always go to a
  person. Approval decisions may not carry `mode: rule` (rules are signed policies). At most
  one rule grant per policy version per TTL window. `POST /policies/{id}/disable` is a
  broker-side flag (removing permission needs no signature); listings show
  `status:"disabled"` while the stored signed body is unchanged. A new policy version revokes
  grants of older versions.
* **Access requests:** postgres / github resources need an explicit `scope.postgres` /
  `scope.github`; http_api scopes default to the requested operation names; limits ≤
  `max_limits`; duration 1..86400 s; `mode` is `task`.
* **Resource changes:** any change to environment, config, credential entry, executor or
  operations, or disabling, revokes the resource's grants (`end_sessions`) and cancels its
  pending approvals (A05).
* **Revocation levels:** `remove` and `revoke_all` revoke at `revoke_upstream`; resource /
  policy / device revocations at `end_sessions`. At `stop_access`, running operations finish
  but their results are withheld, and `end_sessions` is reported `pending` while they run.
* **Shapes the contract leaves open:** pairing code = 6 decimal digits; admin token prefix
  `aipadm_`; `TrustedDevice = DevicePublic + {status, added_at, added_by, revoked_at?}`;
  `CredentialSource::install_delegated` receives the `DelegationAad` envelope (the
  `ExecutorBackend` trait has no delegated-install method); `max_result_bytes` is per
  operation (cumulative bytes are tracked in `usage.bytes`).
* **UDS admin peers** are opt-in per socket (`UdsOptions::admin_peers`), so an embedder can
  serve a connections-only socket to AI bridges and a separate admin socket.
