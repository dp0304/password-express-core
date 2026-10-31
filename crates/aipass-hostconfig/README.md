<!-- SPDX-License-Identifier: Apache-2.0 -->
# aipass-hostconfig

AI 宿主配置向导：检测 Codex、Claude Code、Cursor、Claude Desktop、VS Code、Windsurf，
展示即将新增的配置并保留备份，只修改 `aipass` 这一项，配置里绝不写入任何密码或 Key。
The AI host configuration wizard: detect hosts, show the planned change, keep a backup, touch
only the `aipass` entry, and never write secrets into a host config (design doc §5.2).

## Purpose

| host | file | entry |
| --- | --- | --- |
| `codex` | `~/.codex/config.toml` (`$CODEX_HOME/config.toml` when set) | `[mcp_servers.aipass] command, args` |
| `claude_code` | user `~/.claude.json` (`$CLAUDE_CONFIG_DIR/.claude.json` when set) / project `<dir>/.mcp.json` | `mcpServers.aipass = {type:"stdio", command, args, env:{}}`, or the `claude mcp add --scope … aipass -- <cmd> <args>` command |
| `cursor` | `~/.cursor/mcp.json` / project `<dir>/.cursor/mcp.json` | `mcpServers.aipass = {command, args}` |
| `claude_desktop` | macOS `~/Library/Application Support/Claude/claude_desktop_config.json`, Windows `%APPDATA%\Claude\claude_desktop_config.json` (Linux: `unsupported`) | `mcpServers.aipass = {command, args}` |
| `vscode` | `<dir>/.vscode/mcp.json` (JSONC) | `servers.aipass = {type:"stdio", command, args}` |
| `windsurf` | `~/.codeium/windsurf/mcp_config.json` | `mcpServers.aipass = {command, args}` |
| `chatgpt`, `claude_connector` | remote — `remote_instructions()` returns the server URL, OAuth steps and caveats as data | — |

Entry = absolute path of `aipass-mcp` + `["stdio", "--connection", "conn_…"]`
(`McpEntry::stdio`). Optional safe flags: `--broker <url>` (no user-info/query/fragment),
`--experimental`, `--lang zh-CN|en`. Anything else is refused, and the command and arguments are
scanned for credential patterns (`SecretInEntry`).

## API

```rust
use aipass_hostconfig::*;
let statuses = detect()?;                                   // Vec<HostStatus>
let entry = McpEntry::stdio("/usr/local/bin/aipass-mcp", &conn_id)?;
let plan = plan(Host::Codex, Scope::User, &entry)?;         // ConfigPlan {path, before, after, unified_diff, action}
println!("{}", plan.unified_diff);                          // secret-redacted diff
let out = apply(&plan)?;                                    // ApplyOutcome {path, backup_path, changed}
remove(Host::Codex, Scope::User)?;                          // restores the original bytes
```

Explicit-environment variants for tests and embedders: `HostEnv::with_home(dir).project(dir)`,
`detect_in(&env, &DetectOptions{probe_versions, timeout, include_remote})`, `plan_in`,
`plan_remove_in`, `remove_in`, `config_location`, `claude_mcp_add_command`,
`remote_instructions(host, &RemoteTarget::{OfficialGateway(url), SelfHostNode(url)})`.

## Architecture notes

* **Only our key changes.** Codex TOML is edited with `toml_edit` (comments, formatting and every
  other table preserved; an implicit `mcp_servers` table is created without a header and removed
  again when it becomes empty). JSON/JSONC files are edited by a span-preserving parser
  (`jsonc`): it splices only the bytes of `<container>.aipass`, matching the file's indentation
  (spaces or tabs), newline style (LF/CRLF), trailing commas and comments. Removing an entry we
  inserted is the exact inverse, so `apply` followed by `remove` restores the original file
  byte-for-byte (tested for every host).
* **Safe writes.** `apply` re-reads the file and refuses with `ConcurrentModification` if it
  changed since `plan`; writes a backup `<file>.aipass-backup-<yyyymmddHHMMSS>` (suffix `-N` on
  collision) with the original's permissions; then writes a temp file in the same directory,
  fsyncs and renames it over the target (permissions preserved; new user files 0600, project
  files 0644). Symlinked configs (dotfile managers) are written through to their target.
  Unparseable files are never rewritten (`Parse { line, column }`).
* **No secret leakage through the wizard.** `ConfigPlan`'s `Debug` omits file contents;
  `unified_diff` redacts secret-looking values from the user's *other* settings (e.g. another
  server's `env` token) so the diff is safe to print — also when an AI agent runs the wizard.
  `before` / `after` hold the full text and must not be printed or logged.
* **Detection.** Installed = CLI on `PATH` (absolute entries only), config directory, or (macOS)
  app bundle in `/Applications` / `~/Applications`. Versions: `<tool> --version` run without a
  shell, stdin closed, killed after the timeout (default 3 s, all hosts probed in parallel), or
  `CFBundleShortVersionString` of the app bundle.
* **Labels** (design doc §7.1): `VERIFIED_HOST_VERSIONS` is **empty in this build**, so every
  local host reports `standard_protocol` (标准协议可接入); Claude Desktop on Linux reports
  `unsupported`. Remote hosts are `standard_protocol`; their notes state that the official
  gateway is not an end-to-end-blind relay and that availability depends on the host's plan.

## Build / test

```sh
cd open-source
cargo build -p aipass-hostconfig
cargo test  -p aipass-hostconfig      # unit tests + tests/fixtures.rs on temporary HOME dirs
```

The fixture tests cover: existing configs with comments, other servers and unrelated settings
for every host; backups; byte-exact restore on remove; idempotent re-apply; missing files;
CRLF/tab/JSONC files; concurrent modification; permission preservation; symlinks; parse errors;
`CODEX_HOME` / `CLAUDE_CONFIG_DIR`; version probing with fake CLIs (including a hanging one).

## Limitations

* Claude Code rewrites `~/.claude.json` while it runs; the concurrent-modification check narrows
  but cannot fully close that race — the `claude mcp add` command is offered as an alternative.
* If a user had an empty `mcpServers: {}` before we added our entry, `remove` drops the now
  empty container (semantically identical; not byte-identical in that one case).
* VS Code user-profile MCP config and Codex project-level config are not handled.
* Remote host UIs (ChatGPT Plugins/Apps, Claude Connectors) change often; the steps name the entry
  points current in October 2026 and link the official docs.

## Contract deviations

* `HostStatus.config_path` is `Option<PathBuf>` (remote hosts and project-scoped hosts without a
  project directory have no file); additive fields `scope`, `existing_entry`, `config_error`.
* `apply` returns `ApplyOutcome {path, backup_path: Option, changed}`; `remove(host, scope)`
  returns the same (backup kept). `ConfigPlan` additionally carries `host`, `scope`,
  `write_path` (symlink target) and `action`.
* Additive scopes: Cursor project scope (`<dir>/.cursor/mcp.json`); `CODEX_HOME` and
  `CLAUDE_CONFIG_DIR` overrides are honoured.
