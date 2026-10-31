<!-- SPDX-License-Identifier: Apache-2.0 -->
# aipass-cli — 参考 CLI / 可信客户端 (`aipass`)

开源参考可信客户端：创建与解锁保管库、条目、生成器、TOTP、导入导出、同步与冲突、恢复、设备配对，以及作为**可信设备**审批 AI 连接与访问请求、登记资源、签名策略、撤销授权。
The open-source reference trusted client: vault, items, generator, TOTP, import/export, sync and conflicts, recovery, device pairing — and, as a **trusted device**, approving AI connections and access requests, registering resources, signing policies and revoking grants.

## Architecture

- **Vault** — `aipass_sync::VaultClient` over `<AIPASS_HOME>/vault`; device keys live in a `FileSecretStore` (`<AIPASS_HOME>/secrets.aipass`, Argon2id with the contract parameters) unlocked by the local passphrase (`AIPASS_PASSPHRASE` for automation, otherwise asked on the terminal).
- **Broker access** — every broker call is signed as this device (`AIPass-Sig kid=dev_…`, principal class D). Approvals are built by `VaultClient::approve`: the device recomputes the digest from the displayed request, signs it, and seals the bound credential with HPKE to the executor's member-record key. The broker never receives a secret in plaintext; `resource add` sends only the vault entry id.
- **Broker URL** — `--broker` / `AIPASS_BROKER_URL`, else `cli.json` (set automatically by `device pair` with an executor, or `aipass use-broker URL`), else the embedded broker socket `<AIPASS_HOME>/run/broker.sock`.
- **Approval card** — `approvals list|show|approve` print the design doc §5.3 card (requester, resource + environment, operations, views/fields, not-included fields, limits, duration/mode, executor + protection level, recipients, expiry) plus a warning that an agent controlling the terminal could see and type into it.
- **Reveal** — `item reveal` is human-only: it requires an interactive terminal and re-asks the passphrase every time (never from the environment).
- **Human presence for approvals** — `approvals approve|deny`, `connections approve` and `policy add` require an interactive terminal, a y/N confirmation (`approvals approve --yes` skips only that) and re-entering the local passphrase there (`ctx.require_human_approval`, the same check as `item reveal`). Without a terminal they fail before any network call, unless the documented opt-in `AIPASS_UNATTENDED_APPROVALS=1` is set (prints a warning). Relay approvals accept only requests whose `executor.executor_id` equals the relay sender and refuse when the mailbox holds differing copies of one id.
- **Recovery without a phone** — `vault recover --vault-id vlt_… --storage … (--recovery-key-env VAR | --recovery-key-file KIT)` verifies the vault from storage with the recovery key, joins as a new owner and revokes nothing; `rotation list|done ENTRY` shows the credentials to rotate after `device revoke`. The recovery key is never accepted as a command-line value (argv is visible to other local processes).
- **Status** — `vault status` prints `conflicts: unknown (unlock to check)` while the vault is locked (`CoreStatus.conflicts` is `None` until unlocked).
- **Export** — `export --csv` and `export --encrypted` are human-only in the same way (an encrypted export is only as safe as whoever picks its password): an interactive terminal is required, the passphrase is re-entered, the export password is typed there (`AIPASS_EXPORT_PASSWORD` is ignored) and `--yes` no longer skips the CSV confirmation.
- **`aipass node run`** — embedded broker + executor (always `compatible`) on `<AIPASS_HOME>/run/broker.sock` (connections only; no admin peers), like the desktop app; registers this device as the approver and the embedded executor as a known executor.

## Commands

```
aipass vault init|status|unlock-check
aipass vault recover --vault-id vlt_… --storage … (--recovery-key-env VAR | --recovery-key-file KIT) [--device-name N]
aipass rotation list | done ENTRY
aipass storage test|migrate|configure --storage local|s3|selfhost|official|webdav …
aipass item add|list|show|edit|rm|reveal|generate|totp
aipass import --format chrome|firefox|safari|bitwarden|1password|lastpass|generic FILE
aipass export --encrypted FILE | --csv FILE [--yes]
aipass sync ; aipass conflicts list|resolve ID --keep N
aipass recovery kit|verify
aipass device pair --uri 'aipass://pair?…' | list | revoke DEV
aipass device join --device-name NAME --relay URL [--storage-secret-env VAR]   # new trusted device
aipass node run [--tcp 127.0.0.1:7878]
aipass connect codex|claude_code|cursor|claude_desktop|vscode|windsurf --connection conn_… [--remove] [--yes]
aipass connections list|approve ID --projects '*'|proj_… [--code 123456]|deny|pause|resume|remove [--via-relay]
aipass projects list|add NAME
aipass resource add --alias … --connector postgres|github|http_api --project … --entry ent_… --config FILE | list
aipass policy add --resource res_… --connection conn_… --view schema.view:f1,f2 [--mode rule --auto-approve] | list | disable
aipass approvals list|show ID|approve ID [--narrow view:f1,f2] [--duration S] [--max-rows N] [--yes]|deny ID
aipass grants list [--status …] | revoke ID --level stop_access|end_sessions|revoke_upstream [--via-relay]
aipass inbox [--wait S]                       # relay mailbox of this device
aipass approvals approve ID --via-relay        # decision through the E2E relay
aipass activity [--since RFC3339] ; aipass audit verify|list
```

Global flags: `--home`, `--broker`, `--json`, `--lang zh-CN|en`.

## Build / test

```bash
cd open-source
cargo build -p aipass-cli && cargo test -p aipass-cli
tests/e2e/run.sh        # drives this CLI as the trusted device end to end
```

## Limitations

- The CLI is a *trusted device on a computer*: an AI agent that controls the same terminal (a real TTY) can see approval cards and type answers, and the passphrase re-entry only helps if the agent does not know the passphrase. Use a phone or another trusted device for production data (the card says so). The desktop app has no native OS presence prompt yet.
- `AIPASS_UNATTENDED_APPROVALS=1` turns the human-presence guard off for approval-class commands (design §9.3 *compatible* mode: anything running as the same OS user can then approve). It is meant for automated tests (the e2e harness sets it) and never applies to `item reveal` / `export`.
- `connections approve <id> --projects … --code <6 digits>` requires `--projects` (comma-separated project ids, or `*` explicitly — there is no implicit all-projects grant) and the pairing code shown by `aipass-mcp pair` / the SDK (asked on the terminal without `--code`). The CLI compares it in constant time with the code the broker holds for the pending connection (`GET /v1/connections/{id}`, trusted devices only) or, with `--via-relay`, with the code in the sealed `connection.pair_request` from the paired executor; a mismatch, an expired pairing or differing relay copies refuse the approval. `connections list` never prints the code (read it on the AI host).
- By default approvals, connection decisions and revocations go over signed HTTP to the broker. With `--via-relay` they take the end-to-end relay path phones use (CONTRACTS §4): `approvals approve` (sealed `approval.request` in, sealed `approval.decision` out), `connections approve|deny` (signed `connection.decision`), `connections pause|resume|remove` (signed `connection.control`) and `grants revoke` (signed `grant.revoke`). A connection change is reported as done only when a sealed `state.snapshot` requested right after it shows the new status; a revocation only when the broker's `revoke.report` arrives — otherwise the command fails and says the change is **not** confirmed (20 s wait).
- `device join` is the new-device side of member pairing (§5): it prints the `aipass://pair` link, shows the 6-digit code after the trusted device scanned it, and installs the vault only after verifying `vault.json`, the member chain and the trusted device's checkpoint from storage.
- WebDAV is experimental (V1.1). S3 / WebDAV were not exercised against real services from this CLI.
- Not independently security-audited.

## Contract deviations

- Additive: `aipass vault recover`, `aipass rotation list|done`, `connections approve --code`, `AIPASS_UNATTENDED_APPROVALS`; `aipass use-broker`, `aipass projects`, `aipass inbox`, `aipass audit list`, `aipass approvals show`, `aipass device join`, `--via-relay` on `approvals approve`, `connections approve|deny|pause|resume|remove` and `grants revoke`; `cli.json` (`{broker_url, executors:[{executor_id, name, relay_url}]}`) and `secrets.aipass` in `AIPASS_HOME`.
- `device pair` asks the user to type the 6-digit code shown on the new device (or `y` after comparing); a mismatch cancels the pairing.
