<!-- SPDX-License-Identifier: Apache-2.0 -->
# P0 端到端验收测试 / P0 end-to-end acceptance test

```bash
cd open-source
tests/e2e/run.sh                     # builds aipass-node, aipass, aipass-mcp and the TS SDK, then runs run_e2e.py
AIPASS_E2E_KEEP=1 tests/e2e/run.sh   # keep the work directory (logs, databases) for inspection
AIPASS_E2E_SKIP_SDK=1 tests/e2e/run.sh
```

Requirements: PostgreSQL 17 binaries (`initdb`, `pg_ctl`, `psql`; Homebrew paths are probed), Python ≥ 3.9 (standard library only for the driver), `uv` for the optional Python-SDK step (it installs the SDK's dependencies into a temporary venv). Ports: PostgreSQL `55432` (`AIPASS_E2E_PG_PORT`), node `57878` (`AIPASS_E2E_NODE_PORT`). Everything runs in a fresh temp directory; PostgreSQL is stopped and all processes are terminated at the end.

What it does (design doc §14.1):

1. temporary PostgreSQL with `deploy/examples/lure-store/schema.sql`; random password for the read-only role, set over stdin;
2. `aipass-node run`, then `aipass-node enroll-token create --uses 1`; `aipass vault init --storage selfhost --base-url <node>` (the CLI plays the phone / trusted device; the vault lives on the node's ciphertext sync API — `POST /v1/vaults` plus idempotent genesis); the used single-use token cannot create a second vault; `aipass item add` with the DB credential (from an env var, never argv);
3. `aipass-node pair` ↔ `aipass device pair` (both SAS codes compared, confirmed on the trusted device);
4. second trusted device: `aipass device join --relay <node>` ↔ `aipass device pair` (SAS compared), the new device verifies the chain from the node's sync API and syncs the DB entry; **A11**: both devices edit the same secret concurrently → both see the conflict, the entry is flagged (automatic use paused), resolved on the phone, resolution synced;
5. `aipass resource add` (entry reference only; a config containing a secret / unknown key is rejected);
6. `aipass-mcp pair` + `aipass connections approve`;
7. MCP over stdio: `tools/list` has no credential-returning tool (A02); `resources_list` shows no config; `operations_request` → `approval_required` with the §12.2 message;
8. `aipass approvals show/approve` (card checked; digest-bound signature, credential HPKE-sealed to the executor) → `operations_status` → `succeeded` with only `day/plan/subscriptions`, no e-mail;
9. A07: forbidden view, forbidden field, function-as-field → `SCOPE_DENIED`/`INVALID_REQUEST`;
10. task-grant reuse; A05: widening to `mrr_cents` → new approval; idempotency conflict;
11. A04: a forged connection id without its key cannot read the other connection's operation;
12. phone path: the widened request's `approval.request` arrives sealed in the device's relay mailbox (`aipass inbox`); `aipass approvals approve --via-relay` sends the signed decision back through the relay; the node's mailbox consumer applies it and the operation succeeds; `connections pause|resume --via-relay` (signed `connection.control`, confirmed by a sealed `state.snapshot`; paused → `CONNECTION_PAUSED`);
13. A09: `aipass grants revoke --level end_sessions` (the first grant `--via-relay`: signed `grant.revoke`, answered by a sealed `revoke.report`) → the next request is not served by the old grant within 5 s; grant shows `revoked`; audit chain verifies;
14. Python SDK (`sdk/python`): pairs a second connection, another connection's operation id → `NOT_FOUND`, one approved operation succeeds;
15. TypeScript SDK (`sdk/typescript/dist`, built by `run.sh`): pairs a third connection — approved with `aipass connections approve --via-relay` (signed `connection.decision`) — another connection's operation id → `NOT_FOUND`, one approved operation returns only the approved fields;
16. node log: relay control channel stayed up; A01/A18: the test password and connection string are absent from every MCP/SDK transcript, node and pairing logs, `broker.db`, `relay.db`, the sync blobs and the agent's home.

Requirements added by steps 14–15: `uv` (Python SDK venv) and Node ≥ 18 + `pnpm` (TS SDK build); `AIPASS_E2E_SKIP_SDK=1` skips both.

Note on A09: after revocation a *new* request creates a new approval request (it is not executed); `GRANT_REVOKED` is returned for operations that were queued/running on the revoked grant. Both outcomes count as blocked.
