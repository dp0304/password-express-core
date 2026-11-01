<!-- SPDX-License-Identifier: Apache-2.0 -->
# @aipass/sdk — AI 通行证 TypeScript SDK

[English](./README.en.md)

让自研 Agent、网站和工作流通过 **AI 通行证（AI Pass）** 在用户批准的范围内使用账号和数据，**全程拿不到原始密码、API Key、令牌或连接串**。SDK 负责：发现资源、发起结构化操作、等待用户在手机或可信客户端上批准、读取策略允许的结果、取消任务，以及为模型函数调用提供工具声明和调度器（设计文档 §3.1、§7.6、§12）。

OpenAI / Anthropic 工具格式按公开协议实现，真实模型 API 的端到端测试尚未完成。

## 安全模型

- SDK 只持有**本连接自己的身份凭证**（Ed25519 连接密钥或 `aipc_` / `aipa_` 令牌），不接触任何业务凭证；业务凭证只在执行器里使用。
- 连接密钥由 OS CSPRNG 生成，私钥只存在于 `node:crypto` 的 `KeyObject` 中；`toString` / `toJSON` / `util.inspect` 均不会输出它；落盘文件权限 0600（目录 0700），加载时拒绝组/其他用户可读的文件。
- 每个请求都用 `AIPass-Sig`（CONTRACTS §1.6）签名：路径+查询串原样签名、请求体 SHA-256、16 字节随机 nonce（每次重试都重新签名）。
- `approval_required` 是**正常状态**，不是异常；等待超时只会返回“仍在等待”，**绝不会被当成批准**。
- ID（`op_…`、`grt_…`）不是凭证：broker 会对每次调用重新校验身份和归属，复制别人的 ID 只会得到 `NOT_FOUND`。
- 日志钩子只收到方法、路径（不含查询串）、状态码、request_id、耗时；错误信息不包含请求头、请求体或凭证；非标准错误体（如代理页面）不会被回显。
- 工具调度器只转发结构化请求；不存在任何能返回密码、Key、Cookie、刷新令牌或导出账号库的工具（§12.1）。
- 不保证：无法阻止拿到业务结果的模型把结果再交给其他服务；在“兼容连接”等级下无法抵抗同用户的任意代码（设计文档 §9.3）。

## 安装

```bash
pnpm add @aipass/sdk      # Node ≥ 18，零运行时依赖（仅用 node:crypto / node:http / node:https）
```

> 本仓库内尚未发布到 npm；在仓库中可用 `pnpm build` 后通过 `file:` / workspace 引用。

## 快速开始

### 1. 配对（host_type = `sdk`）

```ts
import { pair } from "@aipass/sdk";

const result = await pair({
  displayName: "路亚站分析 Agent",          // 只是标签，不是身份
  keyPath: "./lure-agent.key",               // 仅在批准后写入，权限 0600
  onPairingCode: ({ pairing_code }) => console.log(`请在手机上核对配对码：${pairing_code}`),
});
if (result.status !== "approved") throw new Error(`pairing ${result.status}`);
```

流程：生成密钥 → `POST /v1/connections/pair` → 显示配对码 → 用待批准密钥签名轮询 `GET /v1/connections/pair/{id}`（`kid = connection_id`）直到 `approved | denied | expired`。只有用户的可信设备能批准；本地等待超时返回 `status: "pending", timedOut: true`。也可用 `startPairing()` + `session.wait()` 分两步。

### 2. 发起操作并等待批准

```ts
import { AIPassClient } from "@aipass/sdk";

const client = AIPassClient.fromKeyFile("./lure-agent.key");     // 或 { bearerToken: "aipc_…" }
const db = await client.findResource({ alias: "路亚站测试库" });

let op = await client.requestOperation({
  resource_id: db!.resource_id,
  operation: "postgres.query_view",
  parameters: { view: "analytics.subscription_daily", fields: ["day", "plan", "subscriptions"], period_days: 30 },
  idempotency_key: "subscription-summary-2026-10-30",   // 建议自己提供，便于安全重试
});
if (op.status === "approval_required") {
  console.log(op.message);   // “请在已配对的手机或可信客户端批准本次访问。”
  op = await client.waitForOperation(op.operation_id, { timeoutMs: 130_000 });
}
if (op.status === "succeeded") console.log(op.result?.data);
client.close();
```

### 3. 接入模型函数调用

```ts
import { openAITools, anthropicTools, systemPrompt, toOpenAIToolMessage, toAnthropicToolResult } from "@aipass/sdk";

const tools = openAITools();            // 或 anthropicTools() / openAIResponsesTools() / toolDefinitions()
const system = systemPrompt();          // 说明如何处理 approval_required，并禁止在对话中索要密码
// 模型返回工具调用后：
const result = await client.handleToolCall(call.function.name, call.function.arguments);
messages.push(toOpenAIToolMessage(call.id, result));          // Anthropic: toAnthropicToolResult(block.id, result)
```

工具名与 MCP 桥一致（CONTRACTS §9）：`resources_list`、`operations_request`、`operations_status`、`operations_cancel`、`access_request`、`access_release`（也接受设计文档中的点号别名）。broker 错误会变成 `isError: true` 的结果 `{error:{code,message}}` 加一句安全提示；参数不合法时在本地返回 `INVALID_REQUEST`，不会请求 broker。

## 客户端配置

| 选项 | 说明 |
| --- | --- |
| `brokerUrl` | `http(s)://host:port[/base]` 或 `unix:///abs/path.sock`；未提供时：`AIPASS_BROKER_URL` > 密钥文件中的 `broker_url` > `<AIPASS_HOME>/broker.json` > `unix://<AIPASS_HOME>/run/broker.sock` |
| `socketPath` | 直接指定 unix socket（经 `node:http` 的 `socketPath`） |
| `connectionKey` / `keyFile` / `bearerToken` | 三选一。令牌只接受 `aipc_`（节点签发）和 `aipa_`（云端访问令牌）；`aipr_`/`aips_` 会被拒绝 |
| `locale` | `zh-CN`（默认）或 `en`，作为 `Accept-Language` 发送 |
| `timeoutMs` / `maxRetries` | 单次请求超时（默认 30 s）；仅对传输层失败、且可安全重发的请求重试（默认 2 次）。`POST /v1/access/requests` 从不自动重发 |
| `ca` | 自托管节点的额外 CA；TLS 校验不能关闭 |
| `allowInsecureHttp` | 默认拒绝以明文 http 连接非本机地址 |
| `logger` | `{debug, warn}`，只接收元数据 |

## API 一览

- `AIPassClient`：`health()`、`listResources({project_id, service})`、`findResource({alias|resource_id})`、`requestOperation(req, {raiseOnPending})`、`getOperation(id)`、`cancelOperation(id)`、`waitForOperation(id, opts)`、`requestAccess(req)`、`getAccessRequest(id)`、`waitForAccessRequest(id, opts)`、`releaseGrant(id)`、`handleToolCall(name, args)`、`close()`。
- 等待参数：`timeoutMs`（默认 120 s / 访问请求 600 s）、`intervalMs`、`maxIntervalMs`、`backoff`、`jitter`（CSPRNG 抖动）、`signal`（AbortSignal）、`raiseOnPending`、`raiseOnFailure`、`onUpdate`。超时返回最新状态；最后一次轮询失败则抛出该错误而不是返回过期状态。
- 配对：`pair()`、`startPairing()`、`PairingSession`。密钥：`ConnectionKey`、`SigningKey`、`saveConnectionKey()`、`loadConnectionKey()`。签名：`signRequest()`、`buildStringToSign()`、`verifySignature()`、`parseAuthorization()`。
- 错误：`AIPassError {code, message, httpStatus, requestId, details}` 及 CONTRACTS §1.5 每个错误码的子类（如 `ScopeDeniedError`、`ExecutorOfflineError`、`InteractiveAuthRequiredError`、`UpstreamOutcomeUnknownError`、`RateLimitedError.retryAfterSeconds`）；SDK 本地错误码：`NETWORK_ERROR`、`TIMEOUT`、`ABORTED`、`INVALID_RESPONSE`、`CONFIG_ERROR`、`CANCELLED`（从不出现在线上协议中）。

## 密钥文件格式

```json
{"format":"aipass-connection-key-1","connection_id":"conn_…","seed":"<b64u 32B>","public_key":"<b64u>",
 "broker_url":"…","host_type":"sdk","display_name":"…","created_at":"2026-10-30T12:00:00Z"}
```

与 Python SDK 完全相同。加载器也接受 `private_key`/`secret_key`（32 字节种子或 64 字节 种子‖公钥）以及只含 b64u 种子、文件名为 `<conn_id>.key` 的纯文本文件（MCP 桥的 `<AIPASS_HOME>/connections/<conn_id>.key` 布局）。若文件中的公钥与种子不符，抛出 `INTEGRITY_FAILED`。

## 架构

```
src/
  signing.ts    AIPass-Sig（node:crypto Ed25519）     auth.ts      签名 / Bearer 认证器
  transport.ts  node:http(s) + unix socket            core.ts      序列化→签名→发送→错误映射→重试
  client.ts     C 端点客户端 + 等待                     pairing.ts   配对流程
  wait.ts       指数退避 + 抖动 + 截止时间 + 中止       keyfile.ts   0600 原子写入、权限检查
  tools.ts      工具声明 / 调度 / 系统提示词            errors.ts    错误码 → 类型化错误
```

请求体使用 `JSON.stringify` 紧凑输出，与 Python SDK 对同一输入产生完全相同的字节（测试中对照 CONTRACTS 测试向量验证）。

## 构建与测试

```bash
pnpm install
pnpm run check     # tsc 类型检查 → tsup 构建（ESM + CJS + .d.ts）→ vitest → dist 冒烟测试 → publint
pnpm test          # 只跑 vitest
```

测试内容：CONTRACTS §1.6 签名向量（内置副本 + `open-source/test-vectors/request-signing.json`）、真实 `node:http` 模拟 broker（校验签名、nonce、时间窗、归属与幂等）覆盖每个方法、全部错误码映射、传输失败与重试、超时与中止、等待循环、unix socket、配对、密钥文件、工具调度，以及把 `examples/` 作为子进程运行。

## 示例

`examples/` 下（需先 `pnpm build`）：

- `pair.mjs <key-path> <名称>` — 配对并保存密钥。
- `lure-store.mjs` — 对“路亚站测试库”执行 `postgres.query_view`（`analytics.subscription_daily`），处理 `approval_required` 并按套餐汇总订阅。
- `tool-calling.mjs` — 打印 OpenAI / Anthropic 工具声明和系统提示词，并演示调度结果的回传格式。

示例从环境变量 `AIPASS_KEY_FILE` 或 `AIPASS_TOKEN` 读取凭证（仅示例使用），broker 地址按上文顺序解析。

## 限制

- 本机只有 Node 24 / 26，未在 Node 18 / 20 上实际运行；代码只使用 Node 18 已有的 API（`Error` cause、`base64url`、Ed25519 `KeyObject`）。
- 尚未发布到 npm；未对真实 broker 联调（broker 由另一组件并行实现），测试使用按 CONTRACTS §6.3 编写的模拟 broker。
- Windows 上不做 0600 权限检查（文件权限模型不同）。
- 用 `signal`（AbortSignal）中止只会停止 SDK 一侧；已发出的 `POST` 可能已被 broker 处理，请用相同 `idempotency_key` 重试。
- `operations_request` 工具默认不等待（`settleMs: 0`），不会为等待批准而长时间阻塞（§7.6）。

## Contract deviations

None. 说明（非偏离）：

- `GET /v1/connections/pair/{id}` 用待批准密钥签名，`kid` 取 `connection_id`（`aipass_types::signing::SigHeader` 要求 kid 是主体 ID）。
- CONTRACTS 未定义连接密钥文件格式，本 SDK 采用上文 `aipass-connection-key-1`，并兼容纯种子文件。
- `limits` 若提供必须包含全部四个整数（与 `aipass_types::models::Limits` 一致）；`idempotency_key` 为 1–128 个可打印字符。
- SDK 本地错误码（`NETWORK_ERROR` 等）是附加的客户端错误码，不出现在协议中。

## 许可证

Apache-2.0
