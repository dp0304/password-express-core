<!-- SPDX-License-Identifier: Apache-2.0 -->
# 参与贡献 / Contributing

感谢参与 AI 通行证（AI Pass）开源核心！本文件说明贡献流程、DCO 签署以及连接器的审查规则。
English notes follow each section.

## 许可与 DCO / License and DCO

本目录采用 **Apache License 2.0**。所有贡献都以 Apache-2.0 授权提交。

我们使用 [Developer Certificate of Origin 1.1](https://developercertificate.org/)（DCO）而不是
CLA。每个 commit 都必须带有签署行，表示你有权以该许可证提交这些代码：

```
Signed-off-by: 你的名字 <you@example.com>
```

使用 `git commit -s` 自动添加。未签署的 commit 无法合并。不要提交你无权以 Apache-2.0
授权的代码（包括复制自不兼容许可证的项目的代码）。

All contributions are licensed under Apache-2.0. Every commit needs a DCO
`Signed-off-by:` line (`git commit -s`).

## 基本要求 / Ground rules

- 每个源文件以 `// SPDX-License-Identifier: Apache-2.0`（或对应语言的注释形式）开头。
- 先读 `docs/spec/CONTRACTS.md`。改变跨组件接口需要先更新契约并说明迁移方式。
- `cargo fmt`、`cargo clippy --all-targets`、`cargo test -p <crate>` 必须通过；测试向量
  （`test-vectors/`）必须继续被所有实现逐字复现。
- 只使用成熟的密码学库；不接受自行设计的算法或协议变体。
- 所有随机数来自操作系统 CSPRNG。
- 秘密不得进入日志、错误信息、`Debug` 输出、遥测、panic 信息或测试快照。
- 不允许“超时即批准”、“缺省放行”之类的失败开放（fail-open）逻辑。
- 文案遵循诚实原则：不宣称“已验证 / verified”兼容、“首个”、远程网关端到端不可见、
  托管执行对服务方不可见、任意网站自动注册、保证轮换、即时撤销或无恢复材料的恢复；
  V1.1 能力标注“实验性 / experimental”；说明尚未经过独立审计。
- UI 与用户可见文案：简体中文为默认且完整，英文完整。

Read `docs/spec/CONTRACTS.md` first; keep test vectors reproducible; mature crypto
libraries and the OS CSPRNG only; secrets never reach logs/errors/Debug/telemetry; no
fail-open logic; follow the honesty rules for user-facing copy.

## 连接器审查规则 / Connector review rules（设计文档 §12.5）

每个连接器必须随代码交付以下内容，缺一不可：

1. **服务标识**与**固定来源规则**：固定的服务基址 / 主机与端口；模型不能替换认证目标；
   凭证绝不转发到其他来源。
2. **认证方式**：凭证如何安装到执行器内存（按授权隔离、到期 / 撤销 / 结束会话时清零）。
3. **操作 schema**：每个操作的结构化参数 JSON Schema、副作用等级（read / write /
   irreversible）、是否可安全重试（`retry_safe`）、阶段（v1 / v1.1）。
4. **权限映射**：操作与参数如何映射到 `GrantScope`，以及 `scope_covers` 的判定规则。
5. **敏感输出字段**：字段允许列表；可能含新 Key、连接串或认证信息的字段默认截断或整体拒绝。
6. **创建与轮换流程**（如适用），以及**可撤销能力**：`end_sessions` 与 `revoke_upstream`
   的真实行为与报告（`done | pending | failed | not_applicable`）。
7. **幂等策略**：相同幂等键 + 相同规范化参数返回原结果；结果未知时报告 `unknown`。
8. **验收样例**：包括越权、重定向、私网 / 元数据地址、分页绕过额度、输出含秘密等负面用例。

审查原则：

- 连接器签名只证明来源与完整性，**不**证明业务逻辑安全。
- 新增第三方连接器进入**隔离评审**，不因“社区提供”自动获得任何账号库或凭证访问权限。
- V1 不开放任意脚本 / 连接器市场；不接受“以 SELECT 开头即安全”之类的启发式，
  不接受模型提供的原始 SQL、任意 HTTP 转发或携带秘密的任意 `exec`。
- 需要访问私有网络的资源必须由用户明确配置；默认拒绝回环、私网、链路本地、CGNAT、组播
  与云元数据地址，不跟随重定向。

Every connector ships: service identity and fixed-origin rules, auth method, operation
schemas, scope mapping, sensitive-output field rules, creation/rotation and revocation
behaviour, idempotency policy and acceptance cases (including negative ones). A connector
signature proves origin and integrity only, not safety; third-party connectors get an
isolated review and never automatic vault access; there is no script marketplace in V1.

## 报告安全问题 / Security issues

请勿公开提交安全问题，按 [`SECURITY.md`](SECURITY.md) 私下报告。
