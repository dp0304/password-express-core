<!-- SPDX-License-Identifier: Apache-2.0 -->
# aipass-client

授权代理（Access Broker）API 的 Rust 客户端，以及连接密钥、配对流程和云端隧道客户端。
Rust client for the AI Pass access-broker API, plus connection keys, pairing and the cloud
tunnel client.

## Purpose

| module | what it does | contract |
| --- | --- | --- |
| `client` | `BrokerClient`: typed calls for every `/v1` endpoint (C, D, A and P principals) over a Unix domain socket or HTTP(S) | CONTRACTS §6.3 |
| `auth` | `Auth::{None, Signed, Bearer}`: `AIPass-Sig` signing (fresh CSPRNG nonce per request) or `Bearer` tokens; local admin token loader | §1.6, §6.3 |
| `api` | `BrokerApi`: the AI-facing operations as an async trait; `BrokerClient` implements it, `aipass-node` / the desktop app implement it in-process | §6.3 "C" |
| `keys` | connection keys at `<AIPASS_HOME>/connections/<conn_id>.key` (0600, directory 0700) | §9 |
| `pairing` | `POST /v1/connections/pair` → signed polling of `GET /v1/connections/pair/{id}` → key stored on approval | §6.3, design §5.2 |
| `endpoint` | `unix:///abs.sock` / `http(s)://host[:port][/prefix]` parsing; broker URL resolution | §1.7, §9 |
| `tunnel` | outbound WebSocket from a node to `<cloud>/v1/tunnel`: signed auth frame, reconnect with backoff, JSON ping/pong every 20 s, `TunnelHandler` | §13 |
| `testing` (feature `test-support`) | in-process mock broker with **real** signature verification, for tests here and in downstream crates | — |

## Architecture notes

* **Exact signing.** The client computes the wire path (`/v1/…?query`, including any base-URL
  prefix, normalized exactly like the URL parser) *before* signing and sends exactly that.
  Verified against the contract test vector and against the mock broker's verifier
  (`aipass_types::signing::verify_request_with_nonce`) over TCP and UDS.
* **Transports.** UDS: hyper HTTP/1.1, one connection per request, 8 MiB response cap.
  HTTP(S): reqwest + rustls (aws-lc-rs provider only), **redirects disabled** so an
  `Authorization` header can never be replayed to another origin, 5 s connect / 60 s request
  timeouts.
* **Errors.** Non-2xx bodies are decoded leniently: known codes become
  `ClientError::Api(ApiError)`; unknown codes fall back to the HTTP status mapping (raw code kept in
  `details.code`). Local failures (`Unreachable`, `Protocol`, `Config`, `Key`, `Io`) map to
  actionable `ApiError`s via `ClientError::to_api_error()` (e.g. `INTERNAL` +
  `details.reason="broker_unreachable"` and a "run `aipass-mcp doctor`" message).
* **Secrets.** The only secrets handled are a signing key or a bearer token. `Debug` of
  `Auth`, `ConnectionKey`, `BrokerClient` is redacted; the key file seed is held in zeroizing
  types; key files with group/other permissions are refused (like OpenSSH). Errors and logs
  contain endpoints (which can never carry credentials — URLs with user-info, query or fragment
  are rejected) but never headers or bodies. IDs are never capabilities.
* **Broker URL resolution.** `--broker` flag → `AIPASS_BROKER_URL` → the broker recorded in the
  connection key (only when pairing explicitly chose one) → `<AIPASS_HOME>/broker.json`
  (`{"url": "…"}`, alias `broker_url`) → `unix://<AIPASS_HOME>/run/broker.sock`
  (Windows: `http://127.0.0.1:7878`). Empty values count as unset; invalid values are errors,
  never silently skipped. Values are passed in explicitly (`ResolveInputs`) — the crate never
  mutates the process environment.
* **Pairing.** A fresh Ed25519 key is generated from the OS CSPRNG; the pairing code is shown
  for comparison on a trusted device; polling never approves anything; expiry yields
  `PairingOutcome::Expired`. The key is written only after approval.
* **Tunnel.** First frame `{type:"auth", node_id, ts, nonce, sig}` with
  `sig = Ed25519(node, "aipass:v1:tunnel:<node_id>:<ts>:<nonce>")`, fresh nonce per connect.
  Inbound frames are handled on their own tasks (a slow MCP call never blocks pings). Dead link
  after 60 s without inbound frames; reconnect backoff 1 s … 60 s with ±20 % CSPRNG jitter.
  Node-initiated frames (`audit.batch`, `connection.status`) go through a bounded queue (1024)
  and are flushed when connected. Unknown frame types are ignored.

## Public API (summary)

```rust
use aipass_client::{BrokerClient, BrokerEndpoint, Auth, BrokerApi, KeyStore, AipassHome};
let ep = BrokerEndpoint::parse("unix:///home/me/.aipass/run/broker.sock")?;
let key = KeyStore::new(&AipassHome::from_env()?).load_selected(None)?;
let client = BrokerClient::builder(ep).auth(key.auth()).lang(aipass_types::Lang::ZhCn).build()?;
let resources = client.list_resources(None, Some("postgres")).await?;
```

Trusted-device / admin calls for the CLI: `list_approvals`, `post_decision`,
`list_connections`, `approve_connection`, `connection_action`, `list_projects`,
`create_project`, `admin_{list,create,patch,delete}_resource(s)`, `list_policies`,
`create_policy`, `disable_policy`, `list_grants`, `revoke_grant`, `list_operations`, `audit`,
`audit_verify`, `activity_summary`, `list_executors`, `admin_{list,add,revoke}_device(s)`,
`delegate_credential`, `health`, plus `get_json` / `post_json` / `request_raw` escape hatches.

## Build / test

```sh
cd open-source
cargo build -p aipass-client
cargo test  -p aipass-client          # unit + broker_client (TCP + UDS) + tunnel tests
```

The tests start in-process servers on `127.0.0.1:0` / temp Unix sockets and stop them at the end.
One network smoke test of the `wss://` (rustls, aws-lc-rs) path against a public echo server is
`#[ignore]`d by default: `cargo test -p aipass-client --test tunnel -- --ignored` (it passed when
this crate was written; the in-repo tests use `ws://` against an in-test server).

## Limitations

* `unix://` endpoints are not available on Windows in this build (TCP `127.0.0.1:7878` is the
  default there). Key files on Windows rely on the user-profile ACL (no POSIX mode check).
* One UDS connection per request (no pooling) — fine for MCP bridge rates.
* The tunnel delivers node-initiated frames at most once: a frame whose write fails is logged
  and dropped (audit batches should be resent by the node from its own audit log).
* No independent security audit yet.

## Contract deviations

* **Broker URL resolution refinement** (additive): the broker URL recorded in a connection key
  at pairing time (only when `--broker` / `AIPASS_BROKER_URL` was used) is consulted after the
  flag and the environment and before `broker.json`, because that connection exists only on
  that broker. Default resolution is unchanged otherwise. On Windows the default is
  `http://127.0.0.1:7878` (no UDS).
* **Shapes the contract leaves open:** connection key file = the canonical JSON shared with
  both SDKs (CONTRACTS §16.7) `{"format":"aipass-connection-key-1", connection_id, seed,
  public_key, broker_url?, host_type, display_name, created_at}`; the loader also reads SDK
  files without `host_type`/`display_name`/`created_at` and the legacy
  `{format:1, kind:"aipass-connection-key", …}` layout (`tests/key_interop.rs` loads keys
  written by the Python and TypeScript SDKs); `broker.json` = `{"url": "…"}`.
* **Tunnel (additive):** `mcp` frames may carry optional `protocol_version` and `http_method`
  (`"POST"` default, `"DELETE"` ends the session); a string `body` is accepted as JSON text.
  When a request frame cannot be served the node answers `{type:"error", id,
  error:{code,message}}`. `connection.status` uses the connection statuses plus the pairing
  outcomes `denied` / `expired`. Auth acknowledgements (`auth.ok`, `auth_ok`, `authenticated`) are
  accepted but not required.
