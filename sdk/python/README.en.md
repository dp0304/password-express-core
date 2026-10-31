<!-- SPDX-License-Identifier: Apache-2.0 -->
# aipass-sdk — AI Pass Python SDK

[简体中文](./README.md)

Lets custom agents and workflows use accounts and data through **AI Pass (AI 通行证)** within the scope the user approved — **without ever receiving raw passwords, API keys, tokens or connection strings**. Import name `aipass` (PyPI distribution `aipass-sdk`). It provides a sync `Client` and an async `AsyncClient`: discover resources, request structured operations, wait for the user's approval on their phone or trusted client, read the results the policy allows, cancel tasks, plus tool definitions and a dispatcher for model function calling (design doc §3.1, §7.6, §12).

> Status: V1 open-source component, **not yet independently audited**. OpenAI / Anthropic tool formats follow the providers' public documentation ("standard protocol"); they have not been validated end-to-end against live model APIs in this build.

## Security model

- The SDK holds only this connection's own identity (an Ed25519 connection key or an `aipc_` / `aipa_` token) and never touches business credentials.
- Keys come from the OS CSPRNG (`cryptography` / OpenSSL); `repr`/`str` show only the public key and key objects refuse to pickle. Key files are written 0600 (directory 0700); group/world-readable key files are refused on load.
- Every request is signed with `AIPass-Sig` (CONTRACTS §1.6) over the exact `raw_path` (path + query) httpx sends and the exact body bytes, with a fresh 16-byte nonce on every send, including retries.
- `approval_required` is a normal status; a wait that times out returns "still pending" — **never approval**.
- Logs (`logging.getLogger("aipass")`) carry method, path (no query string), status, request id and timing only; errors never contain request headers, bodies or credentials.
- A local broker (unix socket / loopback) never goes through environment proxies (`trust_env=False` by default); remote https nodes keep the environment's proxy settings.
- No tool can return a password, key, cookie, refresh token or vault export (§12.1).

## Install

```bash
uv add aipass-sdk        # Python ≥ 3.9; depends on httpx and cryptography
```

> Not yet published to PyPI; inside the repo use `uv pip install -e open-source/sdk/python`.

## Quick start

```python
from aipass import Client, pair

# 1) Pair (the key file is written 0600 only after approval)
result = pair("Lure-store analytics agent", key_path="./lure-agent.key", locale="en",
              on_pairing_code=lambda info: print("Confirm code on your phone:", info["pairing_code"]))
assert result.status == "approved", result.status

# 2) Request an operation and wait for approval
with Client(key_file="./lure-agent.key", locale="en") as client:     # or Client(bearer_token="aipc_…")
    db = client.find_resource(alias="路亚站测试库")
    op = client.request_operation(
        db["resource_id"], "postgres.query_view",
        {"view": "analytics.subscription_daily", "fields": ["day", "plan", "subscriptions"], "period_days": 30},
        idempotency_key="subscription-summary-2026-10-30",   # recommended: your own key, so retries are safe
    )
    if op["status"] == "approval_required":
        print(op["message"])
        op = client.wait_for_operation(op["operation_id"], timeout=130)
    if op["status"] == "succeeded":
        print(op["result"]["data"])
```

Async:

```python
from aipass import AsyncClient

async with AsyncClient(key_file="./lure-agent.key") as client:
    op = await client.request_operation(resource_id, "postgres.query_view", params, idempotency_key="…")
    op = await client.wait_for_operation(op["operation_id"])     # cancel the task or set cancel_event to stop
```

Model function calling:

```python
from aipass import openai_tools, anthropic_tools, system_prompt, to_openai_tool_message, to_anthropic_tool_result

tools = openai_tools("en")             # or anthropic_tools() / openai_responses_tools() / tool_definitions()
system = system_prompt("en")           # explains approval_required; forbids asking for secrets in chat
result = client.handle_tool_call(call.function.name, call.function.arguments)   # -> ToolCallResult
messages.append(to_openai_tool_message(call.id, result))          # Anthropic: to_anthropic_tool_result(block.id, result)
```

Tool names match the MCP bridge (CONTRACTS §9): `resources_list`, `operations_request`, `operations_status`, `operations_cancel`, `access_request`, `access_release`. `ToolCallResult` has `tool`, `is_error`, `structured_content`, `text` (JSON + short hint) and `to_dict()`. Broker errors become `{error:{code,message}}`; invalid arguments return `INVALID_REQUEST` locally. Tool definitions and system prompts are identical to the TypeScript SDK (checked by a test).

## Client parameters

| parameter | meaning |
| --- | --- |
| `broker_url` | `http(s)://host:port[/base]` or `unix:///abs/path.sock`; default: `AIPASS_BROKER_URL` > key file `broker_url` > `<AIPASS_HOME>/broker.json` > `unix://<AIPASS_HOME>/run/broker.sock` |
| `socket_path` | unix socket path (httpx `uds` transport) |
| `connection_key` / `key_file` / `bearer_token` | exactly one; tokens must be `aipc_` / `aipa_` |
| `locale` | `zh-CN` (default) or `en` |
| `timeout` / `max_retries` | per-request timeout in seconds (30); retries only transport failures of retry-safe requests (2). `request_access` is never resent |
| `ca_file` | extra CA for a self-hosted node; TLS verification cannot be disabled |
| `allow_insecure_http` | plaintext http to non-loopback hosts is refused by default |
| `trust_env` | read proxy env vars; default False for a local broker, True for remote |
| `transport` | custom httpx transport (tests use `httpx.MockTransport`) |

## API overview

- `Client` / `AsyncClient`: `health()`, `list_resources(project_id, service)`, `find_resource(alias=…)`, `request_operation(resource_id, operation, parameters, idempotency_key=, task_id=, raise_on_pending=)`, `get_operation(id)`, `cancel_operation(id)`, `wait_for_operation(id, timeout=120, interval=1, max_interval=10, backoff=1.5, jitter=0.2, cancel_event=, raise_on_pending=, raise_on_failure=, on_update=)`, `request_access(resource_id, operations, scope=, limits=, duration_seconds=, reason=)`, `get_access_request(id)`, `wait_for_access_request(id, timeout=600, …)`, `release_grant(id)`, `handle_tool_call(name, args, settle=0)`.
- Pairing: `pair()` / `apair()`, `start_pairing()` / `astart_pairing()`, `PairingSession` / `AsyncPairingSession`, `PairingResult`.
- Keys & signing: `ConnectionKey`, `SigningKey`, `save_connection_key()`, `load_connection_key()`, `sign_request()`, `build_string_to_sign()`, `verify_signature()`, `parse_authorization()`.
- Errors: `AIPassError(code, message, http_status, request_id, details)` with a subclass per CONTRACTS §1.5 code; SDK-local codes `NETWORK_ERROR`, `TIMEOUT`, `ABORTED`, `INVALID_RESPONSE`, `CONFIG_ERROR`, `CANCELLED`.
- Return values are plain `dict`s (typed with `TypedDict`, see `aipass.models`) and JSON-serialisable; ships `py.typed`.

## Key file format

Same as the TypeScript SDK: `{"format":"aipass-connection-key-1","connection_id","seed","public_key","broker_url","host_type","display_name","created_at"}`; `private_key` / `secret_key` and seed-only files named `<conn_id>.key` are also accepted. A public key that does not match the seed raises `IntegrityFailedError`.

## Architecture

```
src/aipass/
  signing.py   AIPass-Sig (cryptography Ed25519)       auth.py        httpx.Auth: SignatureAuth / BearerAuth
  _core.py     sync/async HTTP pipeline, retries, errors  client.py   Client      async_client.py  AsyncClient
  wait.py      backoff + jitter + deadline + cancel    pairing.py     pairing (sync + async)
  keyfile.py   atomic 0600 writes, permission checks   tools.py       tool definitions / dispatch / prompt
  errors.py    code → typed exception                  models.py      TypedDict wire types   urls.py  URL resolution
```

## Build & test

```bash
uv sync
uv run --python 3.9 pytest        # or --python 3.12
uv run --python 3.12 ruff check src tests examples && uv run --python 3.12 mypy
uv build
```

Covered: the CONTRACTS §1.6 signing vector (inline copy + `open-source/test-vectors/request-signing.json`); a mock broker served through `httpx.MockTransport` (sync + async) **and a real HTTP server on a unix socket**, verifying signatures, nonces, time window, ownership and idempotency, exercising every method; every error-code mapping; transport failures, retries and timeouts; the wait loop including `cancel_event` and task cancellation; pairing; key files; tool dispatch (comparing tool definitions and system prompts with the TypeScript build); the example scripts as subprocesses. Passes on Python 3.9.6 and 3.12.

## Examples

`examples/`: `pair.py <key-path> <name>`, `lure_store.py` (`postgres.query_view` on `analytics.subscription_daily` of "路亚站测试库"), `tool_calling.py`. Credentials come from `AIPASS_KEY_FILE` or `AIPASS_TOKEN` (example-only variables); `AIPASS_LOCALE=en` switches to English.

```bash
AIPASS_KEY_FILE=./lure-agent.key uv run python examples/lure_store.py
```

## Limitations

- Not published to PyPI; not yet run against the real broker (implemented concurrently by another component) — tests use a mock written from CONTRACTS §6.3.
- The sync `Client` cannot interrupt an HTTP request already in flight (bounded by `timeout`); waits stop immediately via `cancel_event`. The async client supports task cancellation.
- httpcore 1.0.x does not close its socket when a unix `connect()` fails; the SDK checks that the socket file exists first, which avoids the leak in the common case. A stale socket file with no listener still leaves a socket for GC to close.
- No 0600 check on Windows; unix sockets are not supported on Windows.
- mypy ≥ 2 cannot target 3.9, so type checking runs as 3.10; 3.9 compatibility is verified by the full test suite on 3.9.

## Contract deviations

None. Clarifications (not deviations): pairing status polls are signed with the pending key using `kid = connection_id`; the connection key file format is defined by this SDK (`aipass-connection-key-1`); `limits`, when given, must contain all four integers; `idempotency_key` is 1–128 printable characters; SDK-local error codes never appear on the wire.

## License

Apache-2.0
