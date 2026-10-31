<!-- SPDX-License-Identifier: Apache-2.0 -->
# 部署与演示 / Deployment and walkthrough

[中文](#中文) · [English](#english)

| 文件 / file | 用途 / purpose |
| --- | --- |
| `node.example.toml` | 带注释的节点配置 / commented node configuration |
| `node.docker.toml` | 容器内配置（`0.0.0.0:7878`，TLS 由反向代理终止）/ container config |
| `Dockerfile` | 多阶段构建，非 root 运行 / multi-stage build, non-root user |
| `docker-compose.yml` | 节点 + 演示 PostgreSQL / node + demo PostgreSQL |
| `aipass-node.service` | systemd 单元（加固）/ hardened systemd unit |
| `examples/lure-store/schema.sql` | 路亚站演示库：含邮箱的原始客户表、订阅表、聚合视图、只读账号 / demo schema |

> **诚实说明 / Honesty note.** 本构建环境没有 Docker：`Dockerfile` 与 `docker-compose.yml` 只做了静态检查（YAML 可解析、配置文件通过 `aipass-node check-config`），**未实际构建或运行**。端到端测试（`tests/e2e/run.sh`）直接使用本机编译的二进制与临时 PostgreSQL，已通过。
> Docker is not installed in the build environment: the Dockerfile and compose file were only checked statically (YAML parses, configs pass `aipass-node check-config`) and were **not built or run**. The end-to-end test runs the natively built binaries against a temporary PostgreSQL and passes.

---

## 中文

### 1. 节点是什么

`aipass-node` 是一个进程，同时提供：Access Broker（`/v1/*`）、密文同步（`/v1/vaults*`）、端到端中继信箱（`/v1/relay*`）、远程 MCP（`/mcp`，节点签发的 `aipc_` 令牌）和 `/v1/health`，并内置执行器（PostgreSQL / GitHub / HTTP API 连接器）。

- 节点自身只提供 HTTP。**在任何网络上都请在前面放带 TLS 的反向代理**（Caddy、nginx），并设置 `node.public_url` 与 `tls_terminated_by_proxy = true`。
- 保护级别：默认 `compatible`（兼容连接）。只有当节点运行在与 AI 代理所在机器隔离的主机/虚拟机上时，才可设置 `isolated`（隔离执行），且必须填写 `isolation_attestation` 说明隔离方式；节点不会自行“认定”隔离。
- 中继只能看到密封信封与元数据（发件方、收件方、类型、时间、大小），看不到审批内容或凭证。

### 2. 启动

```bash
aipass-node -c node.toml init --name my-node --data-dir /var/lib/aipass
aipass-node -c node.toml run
aipass-node -c node.toml health
```

管理令牌位于 `<data_dir>/broker/admin.token`（0600），只用于本机管理命令（`pair`、`connection create`）。

### 3. 把节点配对为执行设备（§5）

```bash
aipass-node -c node.toml pair          # 打印 aipass://pair?… 链接和二维码
aipass device pair --uri 'aipass://pair?…'   # 在可信设备（手机或 aipass CLI）上
```

两边都会显示同一个 6 位配对码，必须在**可信设备**上核对确认。扫码本身不授予任何权限；执行设备永远拿不到保管库主密钥或存储密钥。配对后，节点只接受来自 `pairing.welcome` 中可信设备的审批。

### 4. 路亚站演示（P0）

```bash
createdb lure && psql -d lure -f examples/lure-store/schema.sql
psql -d lure -c "ALTER ROLE lure_readonly PASSWORD '…'"     # 只保存在保管库里
aipass item add --kind database --title "路亚站测试库" --username lure_readonly --secret-prompt \
    --db-host 127.0.0.1 --db-port 5432 --db-name lure --db-sslmode require
cat > lure-db.json <<'JSON'
{"host":"127.0.0.1","port":5432,"dbname":"lure","sslmode":"require",
 "allowed_views":{"analytics.subscription_daily":{"fields":["day","plan","subscriptions","mrr_cents"]}}}
JSON
aipass resource add --alias 路亚站测试库 --connector postgres --project lure-store --environment test \
    --entry ent_… --config lure-db.json
aipass-mcp pair --host codex --name "Codex 分析助手" --broker http://127.0.0.1:7878 --configure
aipass connections approve conn_…
```

之后在 Codex 中提问“最近 30 天各套餐订阅数”。AI 调用 `operations_request`，得到 `approval_required`；在可信设备上执行 `aipass approvals list` / `aipass approvals approve apr_…`（可用 `--narrow` 缩小字段）。批准时可信设备对审批摘要签名，并把数据库凭证用 HPKE 直接密封给执行设备；AI 只收到 `day / plan / subscriptions` 三列结果。

撤销：`aipass grants revoke grt_… --level end_sessions`。

### 5. 远程 MCP（ChatGPT / Claude 连接器）

```bash
aipass-node -c node.toml connection create --name "ChatGPT" --host chatgpt
```

令牌只显示一次；在 AI 客户端中填写 `https://<public_url>/mcp` 和该令牌。也可以通过 `aipass-node cloud link --code …` 链接官方云网关（可选、商业服务；网关能看到远程连接的 JSON-RPC 内容，但凭证始终留在节点）。

### 6. 在节点上托管密文同步

```bash
aipass-node -c node.toml enroll-token create --uses 1
AIPASS_ENROLL=aipe_… aipass vault init --storage selfhost --base-url https://node.example.com --secret-env AIPASS_ENROLL
```

注册令牌只保存哈希；同步服务器只存密文。

使用节点同步的设备可以在没有其他设备的情况下用恢复密钥恢复：`aipass vault recover --vault-id vlt_… --storage selfhost --base-url https://node.example.com --recovery-key-file 恢复包.txt`（新设备作为新所有者加入，不会自动撤销任何设备）。

---

## English

### 1. What the node is

`aipass-node` is one process serving the Access Broker (`/v1/*`), ciphertext sync (`/v1/vaults*`), the E2E relay (`/v1/relay*`), remote MCP (`/mcp`, node-issued `aipc_` bearer tokens) and `/v1/health`, with an embedded executor (PostgreSQL / GitHub / HTTP API connectors).

- The node speaks plain HTTP. **Put a TLS reverse proxy in front of it on any network** and set `node.public_url` and `tls_terminated_by_proxy = true`.
- Protection level: `compatible` by default. Use `isolated` only when the node runs on a host/VM separated from the machines where AI agents run, and describe that in `isolation_attestation`; the node never claims isolation on its own.
- The relay sees sealed envelopes plus metadata (sender, recipient, type, time, size) — never approval contents or credentials.

### 2. Run

```bash
aipass-node -c node.toml init --name my-node --data-dir /var/lib/aipass
aipass-node -c node.toml run
aipass-node -c node.toml health
```

The admin token lives in `<data_dir>/broker/admin.token` (0600) and is used only by local admin commands (`pair`, `connection create`).

### 3. Pair the node as an executor (§5)

Run `aipass-node pair`, then `aipass device pair --uri …` on the trusted device. Both show the same 6-digit code, which must be confirmed **on the trusted device**. Scanning alone grants nothing; executors never receive the vault key or storage secrets. Afterwards the broker accepts approvals only from the trusted devices listed in `pairing.welcome`.

### 4. Lure-store walkthrough (P0)

Follow the commands of the Chinese section: load `examples/lure-store/schema.sql`, set the `lure_readonly` password and store it only in the vault, register the resource with an allowlisted view, pair the AI host with `aipass-mcp pair`, approve the connection, and ask the AI for subscription counts. The AI gets `approval_required`; approve with `aipass approvals approve apr_…` (optionally `--narrow view:fields`). The trusted device signs the approval digest and seals the database credential to the executor with HPKE; the AI receives only `day / plan / subscriptions`. Revoke with `aipass grants revoke grt_… --level end_sessions`.

### 5. Remote MCP

`aipass-node connection create --name ChatGPT --host chatgpt` prints a bearer token once; configure `https://<public_url>/mcp` with it in the AI client. Optionally link the commercial cloud gateway with `aipass-node cloud link --code …` (the gateway sees the JSON-RPC of remote connections; credentials stay on the node).

### 6. Hosting ciphertext sync on the node

Create an enroll token with `aipass-node enroll-token create`, then `aipass vault init --storage selfhost --base-url … --secret-env VAR`. Only token hashes are stored; the sync server stores ciphertext only.

A device can recover the vault from the node without any other device: `aipass vault recover --vault-id vlt_… --storage selfhost --base-url https://node.example.com --recovery-key-file kit.txt` (it joins as a new owner; nothing is revoked automatically).
