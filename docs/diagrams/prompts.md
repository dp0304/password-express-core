<!-- SPDX-License-Identifier: Apache-2.0 -->
# Image generation prompts

生成日期：2026-11-01（Asia/Shanghai）。使用内置 imagegen 工具；两张独立生成的位图。
图中文字与箭头根据开源仓库的组件、审批与执行逻辑编写。

两张首稿经检查后通过内置 imagegen 编辑连接线；最终编辑提示词记录在本文末尾。

## Architecture

```text
Use case: infographic-diagram
Asset type: final bitmap diagram for the GitHub README of AI 通行证 (AI Pass), an Apache-2.0 open-source credential manager and AI access broker.
Primary request: Produce one beautiful, technically accurate Chinese software architecture infographic, landscape 16:9, high resolution, intended to remain legible in a GitHub README.
Style: precise flat engineering diagram, large crisp Simplified Chinese sans-serif typography, subtle rounded cards, clean orthogonal arrows, generous whitespace, no photorealism. Use the project's dark slate background (#0b1020 / #121a2f), indigo (#4f46e5) and teal (#0ea5a4) accents, pale text. The result must feel like polished open-source technical documentation.
Title (verbatim): "AI 通行证 · 开源核心架构"
Small subtitle: "AI Pass · Open-source architecture"
Main left-to-right chain, exactly these five labeled nodes:
"AI 宿主" with small line "Codex · Claude Code · Cursor"
→ "MCP 桥 / SDK" with small line "stdio / HTTP"
→ "授权代理 Broker" with small line "身份 · 范围 · 额度 · 审计"
→ "执行器 Executor" with small line "连接器 · 出站防护 · 输出过滤"
→ "外部服务" with small line "PostgreSQL · GitHub · HTTP API".
Label main request arrows "结构化请求", "权限校验", "授权操作", "服务调用", where appropriate.
Below Broker, a large side module "可信客户端 · 账号库 Vault", small line "解锁 · 加密存储 · 用户审批". Broker sends an arrow down toward Vault labeled "审批请求"; Vault sends an arrow back toward Broker labeled "签名决策". A separate teal path from Vault passes through Broker to Executor, labeled "HPKE 凭证封装"; make the arrow destination the Executor, never the AI. This is a logical dataflow diagram, not an OS isolation boundary.
Below the vault connect "同步引擎 Sync" to "密文存储" with small line "本地目录 / S3 / WebDAV / 自托管", and label the bidirectional path "密文 + 签名清单". Draw it separately from the execution request chain.
Show one thin return arrow from Executor back through Broker and MCP toward AI, labeled once "过滤后的结果".
Bottom explanatory strip in two concise lines (render verbatim):
"桌面部署：Vault + Broker + Executor 同一 Tauri 进程，保护等级为兼容连接"
"自托管部署：aipass-node 提供 Broker + Executor + 密文同步 / 中继 / 远程 MCP"
Small footer: "仅开源核心 · Apache-2.0 · 尚未经独立安全审计"
Constraints: Render Chinese text accurately; clear arrowheads; do not invent modules or claims; no raw credential arrow to AI; no vault master key to Executor; do not label the desktop isolated; do not include commercial mobile apps, extension, official cloud or teams. No watermark, no decorative clouds or unnecessary icons. All text fits without clipping.
```

## Workflow

```text
Use case: infographic-diagram
Asset type: final bitmap workflow diagram for the GitHub README of AI 通行证 (AI Pass).
Primary request: Produce a polished, technically accurate Chinese infographic explaining how an AI operation is authorized and executed. Landscape 16:9, high resolution, large readable Chinese type, spacious structured flowchart with numbered stages and clearly directed arrows.
Style: flat engineering infographic, dark slate #0b1020 / #121a2f background, indigo #4f46e5 main path, teal #0ea5a4 allowed execution, muted red for refusal; crisp pale Simplified Chinese sans-serif labels, subtle cards. Match a modern dark desktop application.
Title (verbatim): "AI 通行证 · 一次 AI 操作如何完成"
Small subtitle: "Request → Authorize → Execute → Filter"
Build this exact logical flow, with 7 numbered cards, a compact authorization decision branch and one rejection endpoint:
01 "AI 发起请求" — small line "MCP / SDK · 结构化操作与参数"
→ 02 "Broker 校验请求" — small line "连接身份 · 项目范围 · 参数 · 执行器状态"
→ 03 decision "已有有效授权？" — small line "范围 · 有效期 · 剩余额度".
Decision YES is a clearly labeled teal bypass arrow "有效授权" going directly to stage 06, skipping stages 04 and 05.
Decision NO leads through a small gate labeled "检查签名规则". A second small bypass arrow labeled "仅规则允许的测试环境只读操作" also goes to stage 06. If the rule does not allow it, arrow labeled "需要审批" leads to stage 04.
04 "用户在可信客户端确认" — small line "核对资源 · 权限 · 时长 · 额度", second small line "桌面审批需重新验证解锁密码".
→ 05 "签名决策 · 封装凭证" — small line "Broker 验签与核对摘要，创建授权", second small line "HPKE 密封凭证交给执行器".
→ 06 "执行器调用服务" — small line "按授权临时保管凭证，限制范围与额度".
→ 07 "过滤结果 · 返回 AI" — small line "字段白名单 · 秘密检测 · 审计记录".
Connect stage 04 downward to a red endpoint "拒绝 / 超时 → 不执行". Do not connect this endpoint to execution.
Add one modest bottom note, verbatim: "到期或撤销后拒绝后续使用；会话与上游撤销按实际能力报告"
Footer, verbatim: "AI 工具输出不包含原始凭据 · 本机执行器为兼容连接 · 尚未经独立安全审计"
Composition: an intentional diagram with no crossing arrows, numbered sequence easy to follow; use a two-row flow if needed and visibly join the authorized bypass paths to 06. Keep exact stage numbers only once. All text must fit, no clipping. A blue line represents requests/decisions, a teal line represents authorized execution, red represents stopping.
Constraints: Do not imply every request needs a fresh human approval. No timeout auto-approval. Do not imply same-user OS isolation, that AI gets a password, or guaranteed upstream revocation. No imaginary branding, no watermark.
```

## Final architecture edit

```text
Use case: precise-object-edit
Image 1 is the edit target: the existing AI Pass architecture infographic.
Keep the entire design, card positions, colors, title, exact node text, icons, footer and 16:9 aspect ratio. Change only the following connector details for technical accuracy:
1. The arrow labeled "审批请求" must visibly originate from the BOTTOM BORDER of the "授权代理 Broker" card and end with an arrowhead at the TOP BORDER of the Vault card.
2. The upward arrow labeled "签名决策" must visibly originate from the TOP BORDER of the Vault card and end with an arrowhead at the BOTTOM BORDER of Broker. These two vertical arrows must have no ambiguous attachment to the long horizontal result-return line; any line crossing is a non-junction, with a small bridge/gap and no junction dot.
3. Keep the separate teal "HPKE 凭证封装" path ending at Executor, and add one small clearly readable second label line directly below that text: "经 Broker 转交".
4. Replace the existing return-line label "过滤后的结果" with the two-line label "过滤后的结果" / "经 Broker / MCP 返回". Keep its destination the AI host. This is a simplified logical dataflow route.
Preserve every other element exactly. No new modules, no removed content, no watermarks. Do not add credentials or keys.
```

## Final workflow edit

```text
Use case: precise-object-edit
Image 1 is the edit target: the existing AI Pass 7-stage workflow infographic.
Keep every card, icon, number, exact text, dark palette, title and footer unchanged, and preserve the same landscape composition. Correct ONLY the connecting arrows and their small branch labels to enforce this graph:
01 → 02 → 03.
03 YES ("有效授权") → 06: preserve the existing teal bypass.
03 NO ("否") → the "检查签名规则" gate.
The rule gate ALLOWS ("仅规则允许的测试环境只读操作") → 06: preserve that teal bypass.
The rule gate does NOT allow ("需要审批") → 04 "用户在可信客户端确认".
04 user approves → 05 → 06 → 07: preserve existing horizontal stage arrows.
04 user refuses or times out → the red "拒绝 / 超时 → 不执行" endpoint: preserve it.
Specific required repairs: REMOVE the wrong vertical connection from card 02 to the rule gate; card 02 must have only its normal outgoing arrow to 03. ADD an orthogonal NO connector from card 03's bottom border to the TOP of the rule gate, running in the gap beneath the upper cards, with "否" on that connector. REMOVE the wrong downward "需要审批" connection from the rule gate to card 05. Instead, route "需要审批" from the LEFT edge of the rule gate leftwards, then downwards to the TOP CENTER of card 04. This must clearly enter 04, not 05. Use the open space above 04. Make clean right-angle bends, clear arrowheads, no unintended junctions or card overlaps. Do not modify the wording or invent new steps.
```
