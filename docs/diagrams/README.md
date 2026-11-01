<!-- SPDX-License-Identifier: Apache-2.0 -->
# 软件架构与工作流程图

生成日期：2026-11-01（Asia/Shanghai）。使用内置 **imagegen** 工具，分别生成软件架构与授权工作流程位图，
再通过 imagegen 编辑校正连接线。图片尺寸均为 1672 × 941，样式取自桌面 App 的深色界面配色。
原始生成与最终编辑的完整提示词见 [`prompts.md`](prompts.md)。

| 文件 | 内容 |
| --- | --- |
| [`architecture.png`](architecture.png) | 开源组件、逻辑数据通道、桌面与自托管两种部署方式 |
| [`authorization-workflow.png`](authorization-workflow.png) | 请求校验、已有授权 / 签名规则 / 人工审批分支、执行与结果过滤 |

架构图按逻辑通道展示：可信客户端的 HPKE 凭证封装经 Broker 转交 Executor；
执行结果沿 Executor → Broker → MCP / SDK → AI 宿主返回。
桌面内嵌 Vault、Broker 与 Executor，保护等级为兼容连接；`aipass-node` 是另一种部署方式。
密文同步存储与服务调用是两条独立通道。

工作流程图中，有效授权与符合签名规则的测试环境只读操作可进入执行；
其余请求先到可信客户端确认，再签名与创建授权。桌面决策要求重新验证解锁密码。
拒绝或超时直接停止，到期与撤销按授权和执行器能力处理。

代码与协议依据：

- [`desktop/src-tauri/src/node.rs`](../../desktop/src-tauri/src/node.rs)：桌面同进程 Broker / Executor 与兼容连接等级。
- [`desktop/src-tauri/src/core_ai.rs`](../../desktop/src-tauri/src/core_ai.rs)：桌面审批、签名及凭证封装。
- [`crates/aipass-node/README.md`](../../crates/aipass-node/README.md)：自托管节点组成、可信设备配对与中继。
- [`crates/aipass-broker/README.md`](../../crates/aipass-broker/README.md)：请求流水线、授权复用、签名规则、审批、预算和撤销。
- [`crates/aipass-executor/README.md`](../../crates/aipass-executor/README.md)：授权凭证保管、连接器、出站防护与输出过滤。
- [`docs/spec/CONTRACTS.md`](../spec/CONTRACTS.md)：跨组件身份、审批摘要、凭证封装与执行约定。

图示仅覆盖本仓库的开源核心，保留“尚未经独立安全审计”的状态说明；商业客户端、官方云及团队功能不在图示范围。

Generated with the built-in imagegen tool. The diagrams describe the open-source components and current
authorization flow; full prompts and source references are retained here for review and future updates.
