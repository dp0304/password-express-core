<!-- SPDX-License-Identifier: Apache-2.0 -->
# aipass-mcp

AI 通行证 MCP 接入桥：让 Codex、Claude Code、Cursor 等 AI 宿主在用户批准的范围内使用账号和
API，而永远拿不到原始密码、Key 或令牌。
The AI Pass MCP bridge: AI hosts use accounts and APIs within user-approved scopes and never
receive raw passwords, keys or tokens.

## Purpose

* **`McpServer`** (library) — JSON-RPC 2.0 + MCP lifecycle; protocol versions `2025-11-25`,
  `2025-06-18`, `2025-03-26`, `2024-11-05` (requested version echoed when supported, otherwise
  `2025-11-25`); `tools/list` with input schemas, output schemas (2025-06-18+) and annotations
  (2025-03-26+); `tools/call` → `aipass_client::BrokerApi`; `structuredContent` + one text block
  (JSON + short zh/en hint); `isError` mapping; bilingual server instructions (design doc §7.6);
  `resources/list`, `resources/templates/list`, `prompts/list` return empty lists.
  Entry point: `McpServer::handle(message: &[u8], ctx: &McpContext) -> Option<Value>`.
* **stdio transport** — newline-delimited JSON; stdout carries protocol messages only, all logs
  go to stderr; requests are served concurrently (≤ 32 in flight) so `ping` never waits behind a
  slow call; oversized lines (> 4 MiB) are discarded with a parse error; EOF drains in-flight
  requests (≤ 30 s) and exits 0.
* **Streamable HTTP transport** (`http::StreamableHttp`, axum) — usable by `aipass-node` for
  `/mcp` and for cloud-tunnel `mcp` frames.
* **Binary `aipass-mcp`** with `stdio | pair | http | doctor`.

### Tools (underscored names; the design doc's dotted names are aliases)

| tool | broker call | notes |
| --- | --- | --- |
| `resources_list` | `GET /v1/resources` | read-only |
| `operations_request` | `POST /v1/operations` | `approval_required` is **not** an error |
| `operations_status` | `GET /v1/operations/{id}` | |
| `operations_cancel` | `POST /v1/operations/{id}/cancel` | reports `side_effects` |
| `access_request` | `POST /v1/access/requests` | `reason` is display-only |
| `access_status` | `GET /v1/access/requests/{id}` | additive (see deviations) |
| `access_release` | `POST /v1/access/grants/{id}/release` | |
| `accounts_create`, `credentials_rotate`, `browser_start_task` | `POST /v1/operations` with the fixed operation `accounts.create` / `credentials.rotate` / `browser.start_task` | **experimental**, only with `--experimental` |

There is no tool that returns a password, key, cookie or refresh token, no export, no keyed
`exec` and no arbitrary HTTP forwarding. Arguments are validated strictly (unknown arguments
such as `password` are refused, IDs must parse with their prefix, parameters must be
canonicalizable integers/strings — no floats) before anything reaches the broker.

Results: success → `structuredContent` (2025-06-18+) equal to the JSON in the text block.
Errors (`ApiError` from the broker or argument validation) → `isError: true`, text block
`{"error":{"code","message"}}` + hint, **no** `structuredContent` (it would not match the output
schema, and spec-conforming clients validate it). Operation outcomes `failed` / `unknown` /
`denied` / `expired` are `isError: true` with the (schema-conforming) `OperationResponse`.
Every hint that involves the user says to approve on the paired phone or trusted client and
never to ask for passwords, keys, codes or tokens in chat; timeouts never approve.

Batching: accepted for sessions negotiated at `2025-03-26` / `2024-11-05` (≤ 64 entries,
`initialize` must not be batched), rejected with `-32600` for `2025-06-18` / `2025-11-25` and
before `initialize`. Requests other than `initialize`/`ping` before `initialize` get `-32002`.
Unknown tools → `-32602`; unknown methods → `-32601`; malformed JSON → `-32700` with `id: null`;
notifications and client responses produce no output.

### Streamable HTTP

* `POST /mcp`: JSON response (or a single-event `text/event-stream` if the client accepts only
  SSE); notifications → `202` without body; `415` for a non-JSON content type, `406` for an
  unusable `Accept`, `413` above 4 MiB.
* `initialize` creates a session: `Mcp-Session-Id` = 192 random bits (b64u). Missing → `400`,
  unknown/expired (30 min idle) → `404`. Sessions are bound to the authenticated principal; a
  different principal presenting the id gets `404`. ≤ 16 sessions per principal, ≤ 1024 total
  (least recently used evicted).
* `MCP-Protocol-Version`, when present, must equal the negotiated version (`400` otherwise).
* `DELETE /mcp` → `204`; `GET /mcp` → `405` (`Allow: POST, DELETE`).
* **Local mode** (`aipass-mcp http`): loopback listen addresses only; `Origin` must be
  allow-listed when present (`--allow-origin`), and `Host` must be the loopback listen address —
  DNS rebinding gets `403`.
* **Remote mode**: `Authorization: Bearer` required; missing → `401` +
  `WWW-Authenticate: Bearer resource_metadata="<url>"`, invalid → `401` with
  `error="invalid_token"`. `aipass-mcp http --remote --public-url https://…/mcp` forwards
  `aipc_…` connection tokens to the broker as the request credential (valid tokens cached 60 s
  by hash) and serves `/.well-known/oauth-protected-resource[/mcp]`. Embedders implement
  `BearerResolver` instead.
* `StreamableHttp::handle_for_principal(&Principal, McpHttpRequest)` and
  `StreamableHttp::handle_tunnel_frame(&Principal, &McpFrame) -> McpResponse` run the same logic
  without HTTP (the node uses them for cloud-tunnel frames).

## CLI

```text
aipass-mcp stdio  [--broker URL] [--connection conn_…] [--experimental] [--allow-broker-mismatch]
aipass-mcp pair   --host <host_type> --name <label> [--broker URL] [--transport stdio|http]
                  [--configure] [--scope user|project] [--project-dir DIR]
aipass-mcp http   [--listen 127.0.0.1:7879] [--broker URL] [--connection conn_…] [--experimental] [--allow-broker-mismatch]
                  [--allow-origin ORIGIN]… [--remote --public-url URL [--authorization-server URL]…]
aipass-mcp doctor [--broker URL] [--connection conn_…] [--json] [--no-probe]
```

- A connection key that recorded its broker at pairing only signs for that broker: when `--broker` / `AIPASS_BROKER_URL` names another endpoint the bridge refuses to sign (tools report an error, `doctor` reports `broker_mismatch`), because a signed request carries no audience and could be replayed to the real broker. `--allow-broker-mismatch` (never written by the host-config wizard) overrides this when the broker really moved.
- `pair` prints the pending connection's id next to the pairing code; approve exactly that id from a CLI trusted device (the display name is only a self-declared label).

```text
global: --lang zh-CN|en (env AIPASS_LANG; default zh-CN). Logs: AIPASS_LOG (tracing filter) → stderr.
```

* `stdio` without a usable key or broker still starts, and every tool returns an actionable
  `IDENTITY_UNVERIFIED` / `INTERNAL` tool error ("run `aipass-mcp pair`" / "run
  `aipass-mcp doctor`") instead of the host seeing a crashed server.
* `pair` prints the pairing code to compare on the trusted device; nothing on this machine can
  approve. `--host` accepts the `host_type` values (`codex`, `claude_code`, `cursor`, `chatgpt`,
  `claude_connector`, `sdk`, `custom`) and also `claude_desktop`, `vscode`, `windsurf` (paired
  as `custom`). After approval it shows the planned host-config diff (secret-redacted); with
  `--configure` it applies it via `aipass-hostconfig` (backup kept, only the `aipass` entry
  touched). For Claude Code it also prints the equivalent `claude mcp add` command.
* `doctor` checks the AI Pass home, key file permissions, the selected connection key (shown by
  id + public-key fingerprint only), the broker URL and its source, broker health (version,
  executor online, protection level), the pairing status (an authenticated read-only call) and
  every host config (entry present, command executable, connection id has a key). Exit code 1
  when a check fails. It never prints seeds, tokens or authorization headers.

## Build / test

```sh
cd open-source
cargo build -p aipass-mcp            # binary: target/debug/aipass-mcp
cargo test  -p aipass-mcp
```

Tests: `conformance` (in-process: negotiation per version, tools/list shape and name regex,
tools/call happy path / approval hint / error mapping, malformed input, batching rules, output
schemas validated against the actual structured content), `stdio_binary` (spawns the built
binary against the in-process mock broker over TCP **and** a Unix socket with real AIPass-Sig
verification; asserts stdout is only JSON-RPC lines, logs are on stderr, no seed or
authorization header leaks), `http_transport` (sessions, version header, Origin/Host, 401 +
`WWW-Authenticate`, session binding, token forwarding, tunnel frames, eviction) and
`cli_pair_doctor` (pair → approve → `--configure` on a temp HOME, doctor JSON/human output).

## Limitations

* **Compatible protection level only for local use.** The stdio bridge and the local HTTP
  listener run as the user; any same-user process can start the bridge or call the loopback
  endpoint and act as this connection (bounded by its approved scopes). The bridge never holds
  business secrets, but it cannot defend against code that already controls the user account
  (design doc §9.3). Web pages are blocked by the Origin/Host checks.
* `notifications/cancelled` does not cancel broker operations (use `operations_cancel`).
* No server-initiated SSE stream (`GET /mcp` → 405), no resumability, no MCP tasks, no
  elicitation (by design: secrets are never collected through MCP).
* Host compatibility is "standard protocol" only — no host has passed the full acceptance run in
  this build. Not independently audited.

## Contract deviations

* **Additive tool `access_status`** (`{approval_request_id}` → `{approval_request_id, status,
  grant_id?}`, `GET /v1/access/requests/{id}`): without it a model cannot learn when an access
  request was approved and would create new approvals by retrying.
* **Experimental tools** take `{resource_id, parameters, idempotency_key}` and call
  `POST /v1/operations` with a fixed operation name; the parameter schema comes from the
  resource's operation list (`resources_list`), so the bridge does not duplicate connector
  schemas.
* **Error results carry no `structuredContent`** (the error JSON is in the text block), because
  MCP clients validate `structuredContent` against the tool's output schema.
* Requests before `initialize` are answered with `-32002` (implementation-defined range).
