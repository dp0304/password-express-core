<!-- SPDX-License-Identifier: Apache-2.0 -->
# 安全策略 / Security Policy

## 当前状态 / Status

**AI 通行证（AI Pass）开源核心尚未经过独立的第三方安全审计。** 开源不等于已审计；审计报告
将按实际完成情况发布。在审计完成前，请把本软件视为预发布质量。

**The AI Pass open-source core has not yet been independently audited.** Open source is not
the same as audited; audit reports will be published only once an audit has actually been
completed.

## 报告漏洞 / Reporting a vulnerability

请**不要**在公开 issue、讨论区或聊天群中披露漏洞细节。

- 邮件：`security@aipass.example`（占位地址；正式地址确定后会更新本文件）
- 请尽量提供：受影响的版本 / commit、组件（crate 名）、复现步骤、影响评估、是否已公开。
- **请不要发送任何真实凭证、密码库文件或个人数据**；如需样例，请使用可识别的假凭证。

我们会在 3 个工作日内确认收到，并在评估后告知修复计划与预计披露时间。默认采用协调披露，
通常在修复发布后 90 天内公开说明；如漏洞已被在野利用，会提前处理。

Please do **not** disclose vulnerabilities in public issues. Email
`security@aipass.example` (placeholder address) with affected version/commit, crate, steps
to reproduce and impact. Never send real credentials or vault files. We acknowledge within
3 business days and follow coordinated disclosure (typically within 90 days of a fix).

## 支持的版本 / Supported versions

| 版本 / version | 是否接收安全修复 / security fixes |
| --- | --- |
| `main` 分支 / branch | ✅ |
| `0.1.x`（预发布 / pre-release） | ✅ 最新补丁版本 / latest patch only |
| 更早版本 / older | ❌ |

1.0 之前的格式或接口变更会附带迁移说明和测试向量；安全修复不会静默放宽任何安全策略。

## 范围 / Scope

在范围内：本目录下的 Rust crates、SDK、测试向量与数据格式（加密、签名、审批摘要、同步、
授权代理、执行器、连接器、MCP 桥）。

已知的信任边界（按设计说明，不视为漏洞，但欢迎改进建议）：

- “兼容连接”模式下，与 AI 宿主共用同一未受限用户环境的执行器**不承诺**抵抗同用户任意代码、
  调试或整机接管；严格保护只在“隔离执行”边界内成立（设计文档 §9.3）。
- 已提供给模型的数据无法追回；已发送给外部服务的操作可能已执行（显示为结果未知）。
- 被攻破的操作系统、恶意的可信执行器、接收密码的目标网站属于信任边界之外。
- 仅面对被整体回滚的存储、且没有独立可信检查点的全新设备，无法保证识别最新状态。

## 我们的承诺 / Our commitments

- 原始凭证不进入 AI 工具输出、日志、错误、调试输出或遥测；诊断数据最小化。
- 推送通知只携带最小请求标识，绝不携带秘密或可直接批准的内容。
- 审批超时一律按失败处理，不会自动批准。
