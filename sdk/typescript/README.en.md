<!-- SPDX-License-Identifier: Apache-2.0 -->
# @aipass/sdk — AI Pass TypeScript SDK

[简体中文](./README.md)

Lets custom agents, sites and workflows use accounts and data through **AI Pass (AI 通行证)** within the scope the user approved — **without ever receiving raw passwords, API keys, tokens or connection strings**. The SDK discovers resources, requests structured operations, waits for the user's approval on their phone or trusted client, reads the results the policy allows, cancels tasks, and ships tool definitions plus a dispatcher for model function calling (design doc §3.1, §7.6, §12).

OpenAI / Anthropic tool formats follow their public protocols. End-to-end testing against
live model APIs is pending.

## Security model

- The SDK holds only **this connection's own identity** (an Ed25519 connection key or an `aipc_` / `aipa_` token). It never touches business credentials; those are used inside the executor only.
- Connection keys come from the OS CSPRNG; the private key lives only inside a `node:crypto` `KeyObject` and is never printed by `toString` / `toJSON` / `util.inspect`. Key files are written 0600 (directory 0700) and group/world-readable key files are refused on load.
- Every request is signed with `AIPass-Sig` (CONTRACTS §1.6): exact path+query, SHA-256 of the body bytes, a fresh 16-byte nonce (re-signed on every retry).
- `approval_required` is a **normal status**, not an exception. A wait that times out returns "still pending" — it is **never treated as approval**.
- IDs (`op_…`, `grt_…`) are not capabilities: the broker re-checks identity and ownership on every call; someone else's ID yields `NOT_FOUND`.
- The logger hook receives method, path (no query string), status, request id and timing only. Error messages never include request headers, bodies or credentials; non-envelope error bodies (e.g. a proxy page) are not echoed.
- The tool dispatcher only forwards structured requests; no tool can return a password, key, cookie, refresh token or vault export (§12.1).
- Not promised: a model that received business results can still pass them elsewhere; in the "compatible" protection level the executor does not resist arbitrary same-user code (design doc §9.3).

## Install

```bash
pnpm add @aipass/sdk      # Node ≥ 18, zero runtime dependencies (node:crypto / node:http / node:https only)
```

> Not yet published to npm; inside this repo run `pnpm build` and reference it via `file:` / workspace.

## Quick start

### 1. Pair (host_type = `sdk`)

```ts
import { pair } from "@aipass/sdk";

const result = await pair({
  displayName: "Lure-store analytics agent",   // a label, never identity
  keyPath: "./lure-agent.key",                  // written only after approval, mode 0600
  onPairingCode: ({ pairing_code }) => console.log(`Confirm code ${pairing_code} on your phone`),
});
if (result.status !== "approved") throw new Error(`pairing ${result.status}`);
```

Flow: generate key → `POST /v1/connections/pair` → show code → poll `GET /v1/connections/pair/{id}` signed with the pending key (`kid = connection_id`) until `approved | denied | expired`. Only the user's trusted device can approve; a local wait timeout returns `status: "pending", timedOut: true`. `startPairing()` + `session.wait()` give a two-step API.

### 2. Request an operation and wait for approval

```ts
import { AIPassClient } from "@aipass/sdk";

const client = AIPassClient.fromKeyFile("./lure-agent.key");     // or { bearerToken: "aipc_…" }
const db = await client.findResource({ alias: "路亚站测试库" });

let op = await client.requestOperation({
  resource_id: db!.resource_id,
  operation: "postgres.query_view",
  parameters: { view: "analytics.subscription_daily", fields: ["day", "plan", "subscriptions"], period_days: 30 },
  idempotency_key: "subscription-summary-2026-10-30",   // recommended: your own key, so retries are safe
});
if (op.status === "approval_required") {
  console.log(op.message);
  op = await client.waitForOperation(op.operation_id, { timeoutMs: 130_000 });
}
if (op.status === "succeeded") console.log(op.result?.data);
client.close();
```

### 3. Model function calling

```ts
import { openAITools, anthropicTools, systemPrompt, toOpenAIToolMessage, toAnthropicToolResult } from "@aipass/sdk";

const tools = openAITools({ locale: "en" });     // or anthropicTools() / openAIResponsesTools() / toolDefinitions()
const system = systemPrompt({ locale: "en" });   // explains approval_required; forbids asking for secrets in chat
const result = await client.handleToolCall(call.function.name, call.function.arguments);
messages.push(toOpenAIToolMessage(call.id, result));   // Anthropic: toAnthropicToolResult(block.id, result)
```

Tool names match the MCP bridge (CONTRACTS §9): `resources_list`, `operations_request`, `operations_status`, `operations_cancel`, `access_request`, `access_release` (the design doc's dotted aliases are accepted). Broker errors become `isError: true` results `{error:{code,message}}` plus a safe hint; invalid arguments return `INVALID_REQUEST` locally without calling the broker.

## Client options

| option | meaning |
| --- | --- |
| `brokerUrl` | `http(s)://host:port[/base]` or `unix:///abs/path.sock`; default: `AIPASS_BROKER_URL` > key file `broker_url` > `<AIPASS_HOME>/broker.json` > `unix://<AIPASS_HOME>/run/broker.sock` |
| `socketPath` | unix socket path (via `node:http` `socketPath`) |
| `connectionKey` / `keyFile` / `bearerToken` | exactly one. Tokens must be `aipc_` (node-issued) or `aipa_` (cloud access); `aipr_` / `aips_` are refused |
| `locale` | `zh-CN` (default) or `en`, sent as `Accept-Language` |
| `timeoutMs` / `maxRetries` | per-request timeout (30 s); retries only transport failures of retry-safe requests (2). `POST /v1/access/requests` is never resent |
| `ca` | extra CA for a self-hosted node; TLS verification cannot be disabled |
| `allowInsecureHttp` | plaintext http to non-loopback hosts is refused by default |
| `logger` | `{debug, warn}`, metadata only |

## API overview

- `AIPassClient`: `health()`, `listResources({project_id, service})`, `findResource({alias|resource_id})`, `requestOperation(req, {raiseOnPending})`, `getOperation(id)`, `cancelOperation(id)`, `waitForOperation(id, opts)`, `requestAccess(req)`, `getAccessRequest(id)`, `waitForAccessRequest(id, opts)`, `releaseGrant(id)`, `handleToolCall(name, args)`, `close()`.
- Wait options: `timeoutMs` (120 s; 600 s for access requests), `intervalMs`, `maxIntervalMs`, `backoff`, `jitter` (CSPRNG), `signal` (AbortSignal), `raiseOnPending`, `raiseOnFailure`, `onUpdate`. A timeout returns the latest status; if the final poll failed, that error is thrown instead of a stale status.
- Pairing: `pair()`, `startPairing()`, `PairingSession`. Keys: `ConnectionKey`, `SigningKey`, `saveConnectionKey()`, `loadConnectionKey()`. Signing: `signRequest()`, `buildStringToSign()`, `verifySignature()`, `parseAuthorization()`.
- Errors: `AIPassError {code, message, httpStatus, requestId, details}` with a subclass per CONTRACTS §1.5 code (e.g. `ScopeDeniedError`, `ExecutorOfflineError`, `InteractiveAuthRequiredError`, `UpstreamOutcomeUnknownError`, `RateLimitedError.retryAfterSeconds`); SDK-local codes `NETWORK_ERROR`, `TIMEOUT`, `ABORTED`, `INVALID_RESPONSE`, `CONFIG_ERROR`, `CANCELLED` (never on the wire).

## Key file format

```json
{"format":"aipass-connection-key-1","connection_id":"conn_…","seed":"<b64u 32B>","public_key":"<b64u>",
 "broker_url":"…","host_type":"sdk","display_name":"…","created_at":"2026-10-30T12:00:00Z"}
```

Identical to the Python SDK. The loader also accepts `private_key` / `secret_key` (32-byte seed or 64-byte seed‖public key) and plain-text files holding only the b64u seed named `<conn_id>.key` (the MCP bridge layout `<AIPASS_HOME>/connections/<conn_id>.key`). A public key that does not match the seed raises `INTEGRITY_FAILED`.

## Architecture

```
src/
  signing.ts    AIPass-Sig (node:crypto Ed25519)       auth.ts      signature / bearer authenticators
  transport.ts  node:http(s) + unix sockets            core.ts      serialise → sign → send → map errors → retry
  client.ts     C-endpoint client + waits              pairing.ts   pairing flow
  wait.ts       backoff + jitter + deadline + abort    keyfile.ts   atomic 0600 writes, permission checks
  tools.ts      tool definitions / dispatch / prompt   errors.ts    code → typed error
```

Request bodies are compact `JSON.stringify` output, byte-identical to the Python SDK for the same input (checked against the CONTRACTS test vector).

## Build & test

```bash
pnpm install
pnpm run check     # tsc → tsup build (ESM + CJS + .d.ts) → vitest → dist smoke test → publint
pnpm test          # vitest only
```

Covered: the CONTRACTS §1.6 signing vector (inline copy + `open-source/test-vectors/request-signing.json`), a real `node:http` mock broker (verifies signatures, nonces, time window, ownership, idempotency) exercising every method, every error-code mapping, transport failures and retries, timeouts and aborts, the wait loop, unix sockets, pairing, key files, tool dispatch, and the `examples/` scripts run as child processes.

## Examples

In `examples/` (run `pnpm build` first):

- `pair.mjs <key-path> <name>` — pair and save the key.
- `lure-store.mjs` — `postgres.query_view` on `analytics.subscription_daily` of "路亚站测试库", handles `approval_required`, sums subscriptions per plan.
- `tool-calling.mjs` — prints OpenAI / Anthropic tool definitions and the system prompt, and shows the tool-result payloads.

Examples read `AIPASS_KEY_FILE` or `AIPASS_TOKEN` (example-only variables); the broker URL resolves as above. Set `AIPASS_LOCALE=en` for English output.

## Limitations

- Only Node 24 / 26 are installed here; Node 18 / 20 were not run. The code only uses APIs available in Node 18 (`Error` cause, `base64url`, Ed25519 `KeyObject`).
- Not published to npm; not yet run against the real broker (implemented concurrently by another component) — tests use a mock written from CONTRACTS §6.3.
- No 0600 check on Windows (different permission model).
- Aborting a wait stops the SDK; a `POST` already sent may have been processed — retry with the same `idempotency_key`.
- The `operations_request` tool does not wait by default (`settleMs: 0`) and never blocks for approval (§7.6).

## Contract deviations

None. Clarifications (not deviations):

- `GET /v1/connections/pair/{id}` is signed with the pending key using `kid = connection_id` (`aipass_types::signing::SigHeader` requires the kid to be a principal id).
- CONTRACTS does not define the connection key file format; this SDK uses `aipass-connection-key-1` above and also reads seed-only files.
- `limits`, when given, must contain all four integers (matches `aipass_types::models::Limits`); `idempotency_key` is 1–128 printable characters.
- SDK-local error codes (`NETWORK_ERROR`, …) are client-side additions that never appear on the wire.

## License

Apache-2.0
