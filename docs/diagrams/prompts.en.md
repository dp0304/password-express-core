<!-- SPDX-License-Identifier: Apache-2.0 -->
# English diagram localization prompts

Date: 2026-11-01 (Asia/Shanghai). Tool: built-in imagegen, image editing mode.
Inputs: `architecture.png` and `authorization-workflow.png` in this directory.
Outputs: `architecture.en.png` and `authorization-workflow.en.png`.

## Architecture

```text
Use case: text-localization
Image 1 is the edit target: the AI Pass open-source architecture infographic.
Create an ENGLISH version of this exact diagram. Preserve every card, icon, dark slate/indigo/teal color, all arrow routes and directions, relative hierarchy and landscape composition. Replace ALL Chinese text with the exact English labels below; no Chinese glyphs should remain. Fit text naturally using readable line breaks and slight typography/spacing adjustments only. Do not add components, change technical meaning, or clip labels.
Title: "AI Pass · Open-source Architecture"
Subtitle: "Vault, authorization and scoped execution"
Main row left to right:
"AI hosts" / "Codex · Claude Code · Cursor"
"MCP bridge / SDK" / "stdio / HTTP"
"Access Broker" / "Identity · Scope · Quotas · Audit"
"Executor" / "Connectors · Egress guard · Output filter"
"External services" / "PostgreSQL · GitHub · HTTP API"
Main row arrow labels: "Structured request", "Permission checks", "Authorized operation", "Service call".
Return arrow two-line label: "Filtered results" / "via Broker / MCP".
Bottom-side module: "Trusted client · Vault" / "Unlock · Encryption · User approval".
Down arrow from Broker to Vault: "Approval request".
Up arrow from Vault to Broker: "Signed decision".
Teal Vault-to-Executor logical path: "HPKE credential envelope" / "relayed by Broker".
Below Vault: "Sync engine"; connection label "Ciphertext + signed manifests".
Storage card: "Ciphertext storage" / "Local folder / S3 / WebDAV / Self-hosted".
Bottom deployment strip, two balanced columns:
"Desktop: Vault + Broker + Executor in one Tauri process · compatible protection"
"Self-hosted: aipass-node · Broker + Executor + sync / relay / remote MCP"
Footer: "Open-source core · Apache-2.0 · Not independently security audited"
Ensure the no-secret-to-AI flow is unchanged, all arrows still connect the appropriate modules, and "compatible" never becomes "isolated". Clean professional English technical documentation with no watermark.
```

## Workflow

```text
Use case: text-localization
Image 1 is the edit target: the corrected seven-stage AI Pass workflow diagram.
Produce an ENGLISH edition preserving the exact existing flowchart topology, arrow routes/directions, icons, stage numbers 01–07, card positions, dark slate background and indigo/teal/red palette. Translate all Chinese labels with the exact text below; no Chinese characters should remain. Use readable line breaks and modest layout/type adjustments when English is longer. Do not change the graph.
Title: "AI Pass · How an AI Operation Works"
Subtitle: "Request → Authorize → Execute → Filter"
01: "AI sends a request" / "MCP / SDK · Structured operation and parameters"
02: "Broker validates" / "Connection identity · Project scope · Parameters · Executor status"
03: "Valid grant?" / "Scope · Expiry · Remaining quota"
Existing teal bypass from 03 to 06: "Valid grant".
Purple NO branch from 03 to the rule gate: "No".
Rule gate: "Check signed rules".
Teal rule gate bypass into 06: "Only rule-allowed read-only operations in test environments".
Purple rule gate branch into TOP of 04: "Approval required".
04: "User confirms in a trusted client" / "Review resource · Permissions · Duration · Quotas" / "Desktop approval requires the unlock password again"
05: "Sign decision · Seal credential" / "Broker verifies signature and request digest, then creates a grant" / "HPKE envelope goes to the executor"
06: "Executor calls the service" / "Holds the credential temporarily within grant scope and quotas"
07: "Filter results · Return to AI" / "Field allowlist · Secret detection · Audit log"
Red endpoint below 04: "Denied / expired → Do not execute".
Bottom note: "Expiry or revocation blocks further use; report session and upstream revocation according to actual capabilities."
Footer: "No raw credentials in AI tool output · Local executor: compatible protection · Not independently security audited"
Critical invariants: 01→02→03. 03 No→signed-rule gate. Rule gate approval-required→04→05→06→07. Valid-grant and allowed-rule teal bypasses join 06 directly. The red endpoint is reached from 04 and NEVER leads to execution. No new arrows from 02 to the rule gate or from the gate straight to 05. Preserve topology and do not claim automatic approval on timeout or operating-system isolation. No clipping or watermark.
```
