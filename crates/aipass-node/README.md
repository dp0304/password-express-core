<!-- SPDX-License-Identifier: Apache-2.0 -->
# aipass-node — 自托管节点 / self-host node

一个进程同时提供 Access Broker `/v1/*`、密文同步 `/v1/vaults*`、端到端中继 `/v1/relay*`、远程 MCP `/mcp`（节点签发的 `aipc_` 令牌）与 `/v1/health`，并内置执行器（`aipass-executor`）。
One process serving the broker, ciphertext sync, the E2E relay, remote MCP and health, with the embedded executor.

部署与演示见 / deployment & walkthrough: [`deploy/README.md`](../../deploy/README.md).

## Architecture

```
            ┌──────────────────────────── aipass-node ─────────────────────────────┐
 AI (MCP) ─▶│ /mcp  (aipass-mcp StreamableHttp, HttpMode::Remote, NodeBearerResolver)│
 AI (SDK) ─▶│ /v1/* (aipass-broker router: C/D/A/P auth)  ──▶ Broker ──▶ Executor     │──▶ PostgreSQL / GitHub / HTTP API
 devices  ─▶│ /v1/vaults* (sync_router, FileEnrollAdmission)                          │
 devices  ◀▶│ /v1/relay*  (relay_router, ChainDirectory[SyncDirectory, NodeDirectory])│
            │ relay consumer: exe_ mailbox ─▶ Broker::handle_device_message ─▶ replies│
            │ RelayOutbox (DeviceOutbox) ─▶ own relay or relay.url (e.g. cloud + push)│
            │ optional cloud tunnel (TunnelClient + NodeTunnelHandler)                │
            └─────────────────────────────────────────────────────────────────────────┘
```

- **Identity** — `<data>/executor.key` (0600): one Ed25519 + X25519 identity; executor/broker principal `exe_X`, vault member `dev_X` (role executor), HPKE recipient of credential envelopes.
- **Broker ↔ trusted devices** — approvals reach devices as sealed `approval.request` envelopes via `RelayOutbox`; the consumer loop long-polls `exe_X`'s mailbox and hands every envelope to `Broker::handle_device_message`, posting the sealed replies. Three consecutive relay failures flip the control channel to lost (new operations → `CONTROL_CHANNEL_LOST`) until it recovers. Trusted devices can also call the broker directly with `AIPass-Sig kid=dev_…` (the reference CLI does).
- **Relay directory** — `NodeDirectory` authorises traffic between this executor and the broker's *active* trusted devices, so the relay works even when the vault itself lives on S3 / local storage; `SyncDirectory` covers vaults hosted on this node.
- **Remote MCP** — `NodeBearerResolver` turns an `aipc_` token into an in-process `BrokerApi` (`InProcessBroker` over `ConnectionHandle`); the value is the caller's identity. Tunnel frames are accepted only for active `remote_gateway` connections. After every tunnel (re)connect the node re-announces the status of its remote connections (`connection.status`, live ones first, at most 256), so changes made while the link was down reach the cloud, and the cloud re-sends `connection.revoke` for a connection the user removed in the console while the node was offline.
- **Resource config validation** — an axum middleware calls `Executor::validate_resource_config` on `POST/PATCH /v1/admin/resources` for this executor before the broker stores the resource (unknown keys / secrets → `INVALID_REQUEST`).
- **Enroll tokens** — `FileEnrollAdmission` stores only SHA-256 hashes in `<data>/enroll-tokens.json` and decrements uses persistently — a use is reserved (taken and persisted) when a vault creation is admitted, released if creation fails and only recorded on success, so concurrent creations can never exceed a token's uses.
- **Resource-config pre-validation** — the embedded executor checks `POST /v1/admin/resources` / `PATCH /v1/admin/resources/{id}` configs before the broker stores them. This layer runs before the broker authenticates, so it reads at most the broker's `max_body_bytes` (1 MiB; larger bodies get 413 without being buffered) and validates only for callers presenting a D/A credential (admin token, admin socket, or a valid device signature checked without consuming its nonce); everyone else goes straight to the broker's 401/403.
- **Pairing** — `aipass-node pair` (requires the running node) is the §5 *new device* with role executor; trusted devices from `pairing.welcome` are registered through the admin API; nothing secret is stored.
- **Logs** — tracing to stderr (text or JSON), error codes only; no secrets, request bodies or results.

## Build / test / run

```bash
cd open-source
cargo build -p aipass-node
cargo test  -p aipass-node                 # unit tests + tests/node_http.rs (ephemeral port)
tests/e2e/run.sh                           # full P0 acceptance test (see tests/e2e/README.md)

aipass-node -c node.toml init --name my-node --data-dir ./data
aipass-node -c node.toml run
aipass-node -c node.toml pair [--no-qr] [--relay URL]
aipass-node -c node.toml identity | health | check-config
aipass-node -c node.toml enroll-token create [--uses N] [--ttl-hours H] | list
aipass-node -c node.toml connection create --name ChatGPT --host chatgpt [--projects '*']
aipass-node -c node.toml cloud link --code CODE [--cloud URL] | status | unlink
```

Config reference: [`node.example.toml`](node.example.toml) (unknown keys are rejected).

## Limitations

- Plain HTTP only; TLS must be terminated by a reverse proxy (a warning is logged for non-loopback listens without `tls_terminated_by_proxy = true`).
- `aipass-node pair` needs the node running (it uses the node's relay and admin API).
- The executor is in-process; `protection_level = "isolated"` is an operator attestation, not something the node can verify.
- Org policies pushed through the cloud tunnel are stored (`org-policy.json`) but not enforced by the broker (only device-signed policies are).
- The cloud link / tunnel path is exercised end to end against a real `aipass-cloud` by `cloud/server/tests/e2e/run.sh` (OAuth consent → `connection.create` → device approval → `/mcp` through the tunnel → offline / restart / revocation); the tunnel only reconnects when `aipass-node run` starts with a `cloud.json` present (`cloud link` while running needs a restart).
- `vault init --storage selfhost` against this node currently fails because `aipass-sync`'s genesis write conflicts with objects already stored by `POST /v1/vaults` (cross-component issue, see deploy/README.md).
- Not independently security-audited.

## Contract deviations

- Additive CLI subcommands and files: `init`, `check-config`, `health`, `identity`, `enroll-token`, `connection create`, `cloud link|status|unlink`; data-dir files `executor.key`, `enroll-tokens.json`, `pairing.json`, `cloud.json`, `org-policy.json`, `broker/`, `sync/`, `relay.db`.
- Node id sent to `POST /v1/nodes/link` is the executor id (`exe_…`), signed with `kid=exe_…`.
- The relay control channel counts as lost after 3 consecutive mailbox fetch failures (contract leaves the threshold open).
