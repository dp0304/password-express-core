<!-- SPDX-License-Identifier: Apache-2.0 -->
# AI 通行证（AI Pass）开源核心

> 让人少操心每一个密码，让 AI 在授权范围内使用账号。
>
> *AI Pass* is a working name. This directory is the **open-source core** (Apache-2.0) of a
> password / API-key manager that lets AI agents use accounts within user-approved scopes
> without ever seeing raw credentials. An English summary is at the end of this file.

**状态：开发中，尚未经过独立安全审计。** 请勿把本仓库的任何部分当作已审计的安全产品使用；
数据格式和接口在 1.0 之前仍可能调整（变更会附带迁移说明与测试向量）。

本目录是“核心开源”的那一部分：加密与存储核心、授权代理、执行器与连接器、MCP 桥、SDK、
参考 CLI、基础自托管服务，以及跨平台桌面 App（`desktop/`）。商业手机 App、浏览器扩展、
官方云服务与控制台、团队功能和官方维护的集成不在本目录中，本目录也不应被称为“完整开源产品”。

## 包含什么

| 目录 | 内容 |
| --- | --- |
| `crates/` | Rust 工作区（14 个 crate，见下表） |
| `sdk/typescript/`, `sdk/python/` | `@aipass/sdk` 与 `aipass-sdk`（由各自的构建步骤提供） |
| `deploy/` | Docker / systemd / 示例（由自托管构建步骤提供） |
| `desktop/` | 跨平台桌面 App（Tauri 2 + React，macOS / Windows / Linux）：内嵌授权代理 + 执行器（兼容连接）、AI 宿主接入向导、浏览器扩展原生通信程序 `aipass-nm-host`。`desktop/src-tauri` 是独立的 Cargo workspace（自带 `Cargo.lock`，已在本目录 `Cargo.toml` 中 `exclude`），通过相对路径依赖 `crates/*`；说明见 [`desktop/README.md`](desktop/README.md) |
| `test-vectors/` | 跨语言测试向量：请求签名、JCS、审批摘要、HPKE、XChaCha20-Poly1305 |

### Crate 一览

| crate | 职责 |
| --- | --- |
| `aipass-types` | 共享模型、带前缀的 ULID、错误码、规范化 JSON（RFC 8785）、请求签名、审批摘要、`ExecutorBackend` trait |
| `aipass-crypto` | XChaCha20-Poly1305、HPKE（RFC 9180）、Ed25519 / X25519 设备身份、HKDF、Argon2id、系统 CSPRNG、自动清零的秘密类型 |
| `aipass-vault` | 账号库核心：密钥层级、条目、成员、清单、恢复、密码生成、TOTP、导入导出、配对密码学 |
| `aipass-storage` | `ObjectStore` trait、Memory / 本地目录 / S3 / HTTP 同步 / WebDAV 后端与能力测试 |
| `aipass-sync` | 客户端同步引擎：清单、检查点、回滚检测、删除标记、冲突、离线队列 |
| `aipass-sync-server` | HTTP 同步 API 与端到端中继信箱（可嵌入的 axum Router） |
| `aipass-broker` | 授权代理：连接、策略、授权、审批、操作状态机、额度、撤销、审计、HTTP API |
| `aipass-executor` | 执行器与连接器（postgres、github、http_api）、出站防护、输出过滤 |
| `aipass-client` | 授权代理 API 的 Rust 客户端（签名，UDS + TCP） |
| `aipass-mcp` | MCP 桥（stdio + Streamable HTTP），二进制 `aipass-mcp` |
| `aipass-hostconfig` | AI 宿主配置向导（Codex、Claude Code、Cursor 等，均为“标准协议可接入”） |
| `aipass-node` | 自托管节点，二进制 `aipass-node`（授权代理 + 执行器 + 同步 + 中继 + 远程 MCP） |
| `aipass-cli` | 参考 CLI / 可信客户端，二进制 `aipass` |
| `aipass-ffi` | iOS / Android 的 uniffi 绑定（Swift 模块 `AIPassCore`，Kotlin 包 `com.aipass.core`） |

各 crate 的接口约定见仓库根目录 `docs/spec/CONTRACTS.md`。

## 安全设计要点

- 只使用成熟的密码学库，不自行设计算法；所有随机数来自操作系统 CSPRNG。
- 原始密码、API Key、刷新令牌和私钥不进入 AI 工具输出、日志、错误信息、调试输出或遥测；
  秘密类型在 `Debug` 中显示为 `[REDACTED]` 并在释放时清零。
- 标识（ID）不是授权凭证：持有某个 ID 不代表任何权限，每次请求都重新验证主体身份。
- 审批绑定规范化摘要；审批超时一律按失败处理，**绝不**因超时自动批准。
- 存储服务只保存密文与签名清单；ETag 仅用于并发控制，不替代签名与完整性校验。

## 快速开始 / Quick start

完整的端到端演示（临时 PostgreSQL + 自托管节点 + CLI 作为可信设备 + MCP 桥接）：
A full end-to-end run (temporary PostgreSQL, self-host node, CLI as the trusted device, MCP bridge):

```bash
cd open-source
tests/e2e/run.sh            # 需要 Homebrew PostgreSQL 17 / needs PostgreSQL 17 binaries
```

手动步骤 / Manual steps（详见 / details: [deploy/README.md](deploy/README.md)）：

```bash
cargo build -p aipass-node -p aipass-cli -p aipass-mcp
aipass-node -c node.toml init --name my-node --data-dir ./node-data
aipass-node -c node.toml run &                      # broker + executor + sync + relay + /mcp
aipass vault init --device-name laptop              # 可信设备上的保管库 / vault on the trusted device
aipass item add --kind database --title "Lure DB" --username lure_readonly --secret-prompt \
    --db-host 127.0.0.1 --db-port 5432 --db-name lure --db-sslmode require
aipass-node -c node.toml pair                       # 显示配对链接 / shows the pairing link
aipass device pair --uri 'aipass://pair?…'          # 核对 6 位码 / compare the 6-digit code
aipass resource add --alias lure-db --connector postgres --project lure-store \
    --entry ent_… --config lure-db.json             # 只发送条目引用 / only the entry id is sent
aipass-mcp pair --host codex --name my-agent --broker http://127.0.0.1:7878 --configure
aipass connections list && aipass connections approve conn_…
aipass approvals list && aipass approvals approve apr_…
aipass grants revoke grt_… --level end_sessions
```

## 构建与测试

需要 Rust（edition 2024；本仓库在 nightly 1.97 上开发与测试）。

```bash
cd open-source
cargo check --workspace
cargo test -p aipass-crypto -p aipass-types -p aipass-storage
# 重新生成测试向量（会覆盖 test-vectors/ 中由测试生成的文件）
AIPASS_REGEN_VECTORS=1 cargo test -p aipass-crypto -p aipass-types

# 桌面 App（Node 24 + pnpm；Tauri 2 的系统依赖见 desktop/README.md）
cd desktop && pnpm install && pnpm build && pnpm test
cd src-tauri && cargo test --workspace
```

TLS 统一使用 rustls + aws-lc-rs 加密后端；请勿在任何 crate 中启用 `ring` 后端
（同时编译两个后端会使 `rustls::ClientConfig::builder()` 在运行时 panic）。

## 工作区依赖说明 / Workspace dependency notes

`[workspace.dependencies]` 使用 2026 年 10 月时互相兼容的当前版本：RustCrypto / dalek 新一代
（`sha2 0.11`、`hmac 0.13`、`hkdf 0.13`、`chacha20poly1305 0.11`、`ed25519-dalek 3`、
`x25519-dalek 3`、`hpke 0.15`、`argon2 0.6`、`rand 0.10`、`rand_core 0.10`、`getrandom 0.4`），
`tokio 1.54`、`axum 0.8.9`、`tower-http 0.7`、`reqwest 0.13`（`rustls`，无 OpenSSL）、`rusqlite 0.39`（bundled）、`tokio-postgres 0.7.18`、`sqlx 0.9`、`uniffi 0.32` 等。新增依赖请优先写
`dep.workspace = true`。

### Contract deviations

- `sqlx` 启用 `tls-rustls-aws-lc-rs` 而不是 `tls-rustls`（在 sqlx 0.9 中后者等于 ring 后端），
  以保证整个工作区只编译一个 rustls 加密后端。功能等价。
- `rusqlite` 固定在 0.39（而非最新的 0.41）：0.39 依赖 `libsqlite3-sys 0.37`，是唯一能与
  `sqlx 0.9`（要求 `libsqlite3-sys < 0.38`）共存于同一依赖图的版本线（`links = "sqlite3"`
  只允许一份）。已用一个依赖全部 72 个工作区依赖的临时 crate 验证可以同时解析和编译。
- 其余 crate 级别的说明见各 crate 的 `README.md`。

## 许可证

Apache License 2.0，见 [`LICENSE`](LICENSE) 与 [`NOTICE`](NOTICE)。允许他人合法地以此核心
构建商业实现；本仓库不附加任何“禁止竞争”之类的额外限制。“AI 通行证 / AI Pass” 为暂定名称，
名称与域名尚未核实（占位域名 `aipass.example`），许可证不授予商标使用权。

安全问题请按 [`SECURITY.md`](SECURITY.md) 私下报告；贡献方式见 [`CONTRIBUTING.md`](CONTRIBUTING.md)。

---

## English summary

The open-source core of **AI Pass** (working name): vault crypto and storage formats, the
access broker, executor and connectors, MCP bridge, SDKs, reference CLI and a basic
self-host node, plus the cross-platform desktop app (`desktop/`, Tauri 2 + React) — licensed
**Apache-2.0**. The mobile apps, the browser extension, the official cloud services and console,
team features and maintained integrations are commercial and *not* part of this directory.

- **Status:** under development, **not independently audited**.
- **Crates:** see the table above (`aipass-types`, `aipass-crypto`, `aipass-vault`,
  `aipass-storage`, `aipass-sync`, `aipass-sync-server`, `aipass-broker`, `aipass-executor`,
  `aipass-client`, `aipass-mcp`, `aipass-hostconfig`, `aipass-node`, `aipass-cli`,
  `aipass-ffi`). Interfaces are specified in `docs/spec/CONTRACTS.md`.
- **Desktop app:** `desktop/` — Tauri 2 + React for macOS / Windows / Linux with an embedded
  broker + executor (protection level *compatible*), the AI-host wizard and the browser
  native-messaging host `aipass-nm-host`. `desktop/src-tauri` is a separate Cargo workspace
  (own `Cargo.lock`, excluded from `Cargo.toml` here) that depends on `crates/*` by path; see
  [`desktop/README.md`](desktop/README.md).
- **Test vectors:** `test-vectors/` (request signing, JCS, approval digest, HPKE,
  XChaCha20-Poly1305) — every implementation must reproduce them.
- **Build:** `cargo check --workspace`; tests per crate with `cargo test -p <crate>`.
- **Security reports:** see `SECURITY.md`. **Contributing:** see `CONTRIBUTING.md` (DCO).
