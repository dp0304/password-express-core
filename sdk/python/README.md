<!-- SPDX-License-Identifier: Apache-2.0 -->
# aipass-sdk — AI 通行证 Python SDK

[English](./README.en.md)

让自研 Agent 和工作流通过 **AI 通行证（AI Pass）** 在用户批准的范围内使用账号和数据，**全程拿不到原始密码、API Key、令牌或连接串**。包名 `aipass`（PyPI 发行名 `aipass-sdk`），提供同步 `Client` 与异步 `AsyncClient`：发现资源、发起结构化操作、等待用户在手机或可信客户端批准、读取策略允许的结果、取消任务，以及模型函数调用的工具声明和调度器（设计文档 §3.1、§7.6、§12）。

OpenAI / Anthropic 工具格式按公开协议实现，真实模型 API 的端到端测试尚未完成。

## 安全模型

- SDK 只持有本连接自己的身份凭证（Ed25519 连接密钥或 `aipc_` / `aipa_` 令牌），从不接触业务凭证。
- 密钥由 OS CSPRNG 生成（`cryptography` / OpenSSL）；`repr`/`str` 只显示公钥，密钥对象禁止 pickle；落盘文件 0600（目录 0700），加载时拒绝组/其他用户可读的文件。
- 每个请求用 `AIPass-Sig`（CONTRACTS §1.6）签名：签名的是 httpx 实际发送的 `raw_path`（路径+查询串）和请求体字节，每次发送（含重试）都用新的 16 字节 nonce。
- `approval_required` 是正常状态；等待超时只返回“仍在等待”，**绝不视为批准**。
- 日志（`logging.getLogger("aipass")`）只记录方法、路径（不含查询串）、状态码、request_id、耗时；错误信息不含请求头、请求体或凭证。
- 本机 broker（unix socket / 回环地址）默认不走环境变量代理（`trust_env=False`），远程 https 节点沿用环境代理设置。
- 不存在能返回密码、Key、Cookie、刷新令牌或导出账号库的工具（§12.1）。

## 安装

```bash
uv add aipass-sdk        # Python ≥ 3.9；依赖 httpx、cryptography
```

> 尚未发布到 PyPI；仓库内可用 `uv pip install -e open-source/sdk/python`。

## 快速开始

```python
from aipass import Client, pair

# 1) 配对（仅在批准后以 0600 写入密钥文件）
result = pair("路亚站分析 Agent", key_path="./lure-agent.key",
              on_pairing_code=lambda info: print("请在手机上核对配对码：", info["pairing_code"]))
assert result.status == "approved", result.status

# 2) 发起操作并等待批准
with Client(key_file="./lure-agent.key") as client:          # 或 Client(bearer_token="aipc_…")
    db = client.find_resource(alias="路亚站测试库")
    op = client.request_operation(
        db["resource_id"], "postgres.query_view",
        {"view": "analytics.subscription_daily", "fields": ["day", "plan", "subscriptions"], "period_days": 30},
        idempotency_key="subscription-summary-2026-10-30",   # 建议自己提供，便于安全重试
    )
    if op["status"] == "approval_required":
        print(op["message"])                                   # “请在已配对的手机或可信客户端批准本次访问。”
        op = client.wait_for_operation(op["operation_id"], timeout=130)
    if op["status"] == "succeeded":
        print(op["result"]["data"])
```

异步：

```python
from aipass import AsyncClient

async with AsyncClient(key_file="./lure-agent.key") as client:
    op = await client.request_operation(resource_id, "postgres.query_view", params, idempotency_key="…")
    op = await client.wait_for_operation(op["operation_id"])     # 取消任务或设置 cancel_event 即可中止
```

模型函数调用：

```python
from aipass import openai_tools, anthropic_tools, system_prompt, to_openai_tool_message, to_anthropic_tool_result

tools = openai_tools()                 # 或 anthropic_tools() / openai_responses_tools() / tool_definitions()
system = system_prompt()               # 解释 approval_required，禁止在对话中索要密码
result = client.handle_tool_call(call.function.name, call.function.arguments)   # 返回 ToolCallResult
messages.append(to_openai_tool_message(call.id, result))          # Anthropic: to_anthropic_tool_result(block.id, result)
```

工具名与 MCP 桥一致（CONTRACTS §9）：`resources_list`、`operations_request`、`operations_status`、`operations_cancel`、`access_request`、`access_release`。`ToolCallResult` 有 `tool`、`is_error`、`structured_content`、`text`（JSON + 简短提示）和 `to_dict()`。broker 错误转为 `{error:{code,message}}`；参数错误在本地返回 `INVALID_REQUEST`。工具定义与系统提示词和 TypeScript SDK 内容完全一致（测试校验）。

## 客户端参数

| 参数 | 说明 |
| --- | --- |
| `broker_url` | `http(s)://host:port[/base]` 或 `unix:///abs/path.sock`；默认：`AIPASS_BROKER_URL` > 密钥文件 `broker_url` > `<AIPASS_HOME>/broker.json` > `unix://<AIPASS_HOME>/run/broker.sock` |
| `socket_path` | 直接指定 unix socket（httpx `uds` 传输） |
| `connection_key` / `key_file` / `bearer_token` | 三选一；令牌只接受 `aipc_` / `aipa_` |
| `locale` | `zh-CN`（默认）或 `en` |
| `timeout` / `max_retries` | 单次请求超时秒数（30）；仅对传输层失败、且可安全重发的请求重试（2）。`request_access` 从不自动重发 |
| `ca_file` | 自托管节点的额外 CA；TLS 校验不能关闭 |
| `allow_insecure_http` | 默认拒绝以明文 http 连接非本机地址 |
| `trust_env` | 是否读取代理等环境变量；默认本机 broker 为 False、远程为 True |
| `transport` | 自定义 httpx 传输（测试用 `httpx.MockTransport`） |

## API 一览

- `Client` / `AsyncClient`：`health()`、`list_resources(project_id, service)`、`find_resource(alias=…)`、`request_operation(resource_id, operation, parameters, idempotency_key=, task_id=, raise_on_pending=)`、`get_operation(id)`、`cancel_operation(id)`、`wait_for_operation(id, timeout=120, interval=1, max_interval=10, backoff=1.5, jitter=0.2, cancel_event=, raise_on_pending=, raise_on_failure=, on_update=)`、`request_access(resource_id, operations, scope=, limits=, duration_seconds=, reason=)`、`get_access_request(id)`、`wait_for_access_request(id, timeout=600, …)`、`release_grant(id)`、`handle_tool_call(name, args, settle=0)`。
- 配对：`pair()` / `apair()`、`start_pairing()` / `astart_pairing()`、`PairingSession` / `AsyncPairingSession`、`PairingResult`。
- 密钥与签名：`ConnectionKey`、`SigningKey`、`save_connection_key()`、`load_connection_key()`、`sign_request()`、`build_string_to_sign()`、`verify_signature()`、`parse_authorization()`。
- 错误：`AIPassError(code, message, http_status, request_id, details)` 及 CONTRACTS §1.5 每个错误码的子类；SDK 本地错误码 `NETWORK_ERROR`、`TIMEOUT`、`ABORTED`、`INVALID_RESPONSE`、`CONFIG_ERROR`、`CANCELLED`。
- 返回值都是普通 `dict`（`TypedDict` 类型标注，见 `aipass.models`），可直接 JSON 序列化；包含 `py.typed`。

## 密钥文件格式

与 TypeScript SDK 相同：`{"format":"aipass-connection-key-1","connection_id","seed","public_key","broker_url","host_type","display_name","created_at"}`；也接受 `private_key`/`secret_key` 以及文件名为 `<conn_id>.key` 的纯种子文件。公钥与种子不符时抛出 `IntegrityFailedError`。

## 架构

```
src/aipass/
  signing.py   AIPass-Sig（cryptography Ed25519）    auth.py        httpx.Auth：SignatureAuth / BearerAuth
  _core.py     同步/异步 HTTP 管线、重试、错误映射    client.py      Client      async_client.py  AsyncClient
  wait.py      退避 + 抖动 + 截止时间 + 取消          pairing.py     配对（同步 + 异步）
  keyfile.py   0600 原子写入、权限检查               tools.py       工具声明 / 调度 / 系统提示词
  errors.py    错误码 → 类型化异常                    models.py      TypedDict 线上类型     urls.py  地址解析
```

## 构建与测试

```bash
uv sync
uv run --python 3.9 pytest        # 也可 --python 3.12
uv run --python 3.12 ruff check src tests examples && uv run --python 3.12 mypy
uv build
```

测试内容：CONTRACTS §1.6 签名向量（内置副本 + `open-source/test-vectors/request-signing.json`）、通过 `httpx.MockTransport`（同步+异步）和**真实 unix socket HTTP 服务器**运行的模拟 broker（校验签名、nonce、时间窗、归属、幂等）覆盖每个方法、全部错误码映射、传输失败/重试/超时、等待循环（含 `cancel_event` 与任务取消）、配对、密钥文件、工具调度（并与 TypeScript 构建产物比对工具定义和系统提示词）、示例脚本子进程运行。Python 3.9.6 与 3.12 均通过。

## 示例

`examples/`：`pair.py <key-path> <名称>`、`lure_store.py`（“路亚站测试库”上的 `postgres.query_view` / `analytics.subscription_daily`）、`tool_calling.py`。凭证从 `AIPASS_KEY_FILE` 或 `AIPASS_TOKEN` 读取（仅示例使用）；`AIPASS_LOCALE=en` 输出英文。

```bash
AIPASS_KEY_FILE=./lure-agent.key uv run python examples/lure_store.py
```

## 限制

- 尚未发布到 PyPI；未对真实 broker 联调（broker 由另一组件并行实现），测试使用按 CONTRACTS §6.3 编写的模拟 broker。
- 同步 `Client` 无法中途打断一个已发出的 HTTP 请求（受 `timeout` 限制）；等待循环可用 `cancel_event` 立即中止。异步客户端支持任务取消。
- httpcore 1.0.x 在 unix socket `connect()` 失败时不关闭套接字；SDK 先检查 socket 文件是否存在以避免常见情况下的泄漏，残留 socket 文件但无人监听时仍需等 GC 回收。
- Windows 上不做 0600 权限检查；unix socket 不支持 Windows。
- mypy ≥ 2 不支持以 3.9 为目标，类型检查以 3.10 进行；3.9 兼容性由在 3.9 上运行的完整测试保证。

## Contract deviations

None. 说明（非偏离）：配对状态轮询用待批准密钥签名，`kid = connection_id`；连接密钥文件格式由本 SDK 定义（`aipass-connection-key-1`）；`limits` 若提供必须包含全部四个整数；`idempotency_key` 为 1–128 个可打印字符；SDK 本地错误码不出现在协议中。

## 许可证

Apache-2.0
