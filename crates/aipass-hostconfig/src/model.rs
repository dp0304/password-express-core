// SPDX-License-Identifier: Apache-2.0
//! Hosts, scopes, labels, environment, entries and errors.

use std::ffi::OsString;
use std::fmt;
use std::path::{Path, PathBuf};

use aipass_types::models::HostType;
use aipass_types::{ConnectionId, Localized};
use serde::{Deserialize, Serialize};

use crate::secrets;

/// MCP server key we own in every host config.
pub const SERVER_KEY: &str = "aipass";

/// AI hosts known to the wizard (CONTRACTS §10).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Host {
    /// OpenAI Codex (CLI / IDE) — `~/.codex/config.toml`.
    Codex,
    /// Claude Code — `~/.claude.json` / `<project>/.mcp.json`.
    ClaudeCode,
    /// Cursor — `~/.cursor/mcp.json` / `<project>/.cursor/mcp.json`.
    Cursor,
    /// Claude Desktop — `claude_desktop_config.json`.
    ClaudeDesktop,
    /// VS Code — `<project>/.vscode/mcp.json`.
    Vscode,
    /// Windsurf — `~/.codeium/windsurf/mcp_config.json`.
    Windsurf,
    /// ChatGPT (remote MCP; instructions only).
    Chatgpt,
    /// Claude custom connector (remote MCP; instructions only).
    ClaudeConnector,
}

impl Host {
    /// Hosts configured through a local file.
    pub const LOCAL: [Host; 6] = [
        Host::Codex,
        Host::ClaudeCode,
        Host::Cursor,
        Host::ClaudeDesktop,
        Host::Vscode,
        Host::Windsurf,
    ];
    /// Remote hosts (server URL + OAuth instructions).
    pub const REMOTE: [Host; 2] = [Host::Chatgpt, Host::ClaudeConnector];

    /// Wire name.
    pub fn as_str(&self) -> &'static str {
        match self {
            Host::Codex => "codex",
            Host::ClaudeCode => "claude_code",
            Host::Cursor => "cursor",
            Host::ClaudeDesktop => "claude_desktop",
            Host::Vscode => "vscode",
            Host::Windsurf => "windsurf",
            Host::Chatgpt => "chatgpt",
            Host::ClaudeConnector => "claude_connector",
        }
    }

    /// Parse a wire name.
    pub fn parse(s: &str) -> Option<Host> {
        Host::LOCAL
            .iter()
            .chain(Host::REMOTE.iter())
            .copied()
            .find(|h| h.as_str() == s)
    }

    /// Product name.
    pub fn display_name(&self) -> &'static str {
        match self {
            Host::Codex => "Codex",
            Host::ClaudeCode => "Claude Code",
            Host::Cursor => "Cursor",
            Host::ClaudeDesktop => "Claude Desktop",
            Host::Vscode => "VS Code",
            Host::Windsurf => "Windsurf",
            Host::Chatgpt => "ChatGPT",
            Host::ClaudeConnector => "Claude (custom connector)",
        }
    }

    /// Remote host (no local file).
    pub fn is_remote(&self) -> bool {
        matches!(self, Host::Chatgpt | Host::ClaudeConnector)
    }

    /// Scopes this host supports.
    pub fn scopes(&self) -> &'static [Scope] {
        match self {
            Host::Codex | Host::ClaudeDesktop | Host::Windsurf => &[Scope::User],
            Host::ClaudeCode | Host::Cursor => &[Scope::User, Scope::Project],
            Host::Vscode => &[Scope::Project],
            Host::Chatgpt | Host::ClaudeConnector => &[],
        }
    }

    /// Default scope.
    pub fn default_scope(&self) -> Scope {
        match self {
            Host::Vscode => Scope::Project,
            _ => Scope::User,
        }
    }

    /// `AppConnection.host_type` to pair with.
    pub fn host_type(&self) -> HostType {
        match self {
            Host::Codex => HostType::Codex,
            Host::ClaudeCode => HostType::ClaudeCode,
            Host::Cursor => HostType::Cursor,
            Host::Chatgpt => HostType::Chatgpt,
            Host::ClaudeConnector => HostType::ClaudeConnector,
            Host::ClaudeDesktop | Host::Vscode | Host::Windsurf => HostType::Custom,
        }
    }

    /// CLI binary used for detection / `--version`.
    pub fn cli_name(&self) -> Option<&'static str> {
        match self {
            Host::Codex => Some("codex"),
            Host::ClaudeCode => Some("claude"),
            Host::Cursor => Some("cursor"),
            Host::Vscode => Some("code"),
            Host::Windsurf => Some("windsurf"),
            Host::ClaudeDesktop | Host::Chatgpt | Host::ClaudeConnector => None,
        }
    }
}

impl fmt::Display for Host {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Configuration scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    /// Per-user config in the home directory.
    User,
    /// Per-project config in a project directory.
    Project,
}

impl Scope {
    /// Wire name.
    pub fn as_str(&self) -> &'static str {
        match self {
            Scope::User => "user",
            Scope::Project => "project",
        }
    }
}

impl fmt::Display for Scope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Compatibility label (design doc §7.1, CONTRACTS §10).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompatLabel {
    /// Full acceptance run on this exact version/platform. **No host is verified in this build.**
    Verified,
    /// Official docs confirm the protocol entry point; not accepted by us yet.
    StandardProtocol,
    /// Needs a partnership (browser protection, session identity, extension APIs).
    NeedsPartnership,
    /// No suitable tool entry point.
    Unsupported,
}

impl CompatLabel {
    /// UI label.
    pub fn label(&self) -> Localized {
        match self {
            CompatLabel::Verified => Localized::new("已验证连接", "Verified"),
            CompatLabel::StandardProtocol => Localized::new("标准协议可接入", "Standard protocol"),
            CompatLabel::NeedsPartnership => Localized::new("需要合作适配", "Needs partnership"),
            CompatLabel::Unsupported => Localized::new("当前不可接入", "Not supported"),
        }
    }
}

/// Host versions that passed the full acceptance run. **Empty in this build** — nothing is
/// labelled "verified" (CONTRACTS §14 honesty rules).
pub const VERIFIED_HOST_VERSIONS: &[(Host, &str)] = &[];

/// Operating system family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Os {
    /// macOS.
    MacOs,
    /// Windows.
    Windows,
    /// Linux.
    Linux,
    /// Anything else.
    Other,
}

impl Os {
    /// The OS this binary runs on.
    pub fn current() -> Os {
        if cfg!(target_os = "macos") {
            Os::MacOs
        } else if cfg!(windows) {
            Os::Windows
        } else if cfg!(target_os = "linux") {
            Os::Linux
        } else {
            Os::Other
        }
    }
}

/// Label for a host at a version on an OS.
pub fn label_for(host: Host, version: Option<&str>, os: Os) -> CompatLabel {
    if host == Host::ClaudeDesktop && !matches!(os, Os::MacOs | Os::Windows) {
        return CompatLabel::Unsupported;
    }
    if let Some(v) = version
        && VERIFIED_HOST_VERSIONS.iter().any(|(h, hv)| *h == host && *hv == v)
    {
        return CompatLabel::Verified;
    }
    CompatLabel::StandardProtocol
}

/// Where host configs live. Built from the process environment by [`HostEnv::from_system`],
/// or explicitly (tests use a temporary home).
#[derive(Debug, Clone)]
pub struct HostEnv {
    /// Home directory.
    pub home: PathBuf,
    /// `%APPDATA%` (Windows).
    pub appdata: Option<PathBuf>,
    /// `CODEX_HOME` override (default `~/.codex`).
    pub codex_home: Option<PathBuf>,
    /// `CLAUDE_CONFIG_DIR` override (Claude Code then uses `$CLAUDE_CONFIG_DIR/.claude.json`).
    pub claude_config_dir: Option<PathBuf>,
    /// Project directory for project-scoped configs.
    pub project_dir: Option<PathBuf>,
    /// OS family (decides Claude Desktop's path and label).
    pub os: Os,
    /// `PATH` used to find host CLIs.
    pub path_var: Option<OsString>,
    /// Directories searched for app bundles (macOS `/Applications`, `~/Applications`).
    pub app_dirs: Vec<PathBuf>,
}

fn env_path(name: &str) -> Option<PathBuf> {
    std::env::var_os(name)
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
}

impl HostEnv {
    /// From the process environment.
    pub fn from_system() -> Result<HostEnv, crate::HostConfigError> {
        let home = dirs::home_dir().ok_or(crate::HostConfigError::NoHome)?;
        let os = Os::current();
        let app_dirs = if os == Os::MacOs {
            vec![PathBuf::from("/Applications"), home.join("Applications")]
        } else {
            Vec::new()
        };
        Ok(HostEnv {
            appdata: env_path("APPDATA"),
            codex_home: env_path("CODEX_HOME"),
            claude_config_dir: env_path("CLAUDE_CONFIG_DIR"),
            project_dir: std::env::current_dir().ok(),
            os,
            path_var: std::env::var_os("PATH"),
            app_dirs,
            home,
        })
    }

    /// Isolated environment rooted at `home` (no PATH, no app dirs, no overrides).
    pub fn with_home(home: impl Into<PathBuf>) -> HostEnv {
        let home = home.into();
        HostEnv {
            appdata: Some(home.join("AppData").join("Roaming")),
            codex_home: None,
            claude_config_dir: None,
            project_dir: None,
            os: Os::current(),
            path_var: None,
            app_dirs: Vec::new(),
            home,
        }
    }

    /// Set the project directory.
    pub fn project(mut self, dir: impl Into<PathBuf>) -> HostEnv {
        self.project_dir = Some(dir.into());
        self
    }
}

/// The `aipass` MCP entry: absolute path of `aipass-mcp` + validated arguments.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpEntry {
    /// Absolute path of the `aipass-mcp` binary.
    pub command: PathBuf,
    /// Arguments (`["stdio", "--connection", "conn_…"]` + optional safe flags).
    pub args: Vec<String>,
}

impl McpEntry {
    /// The contract entry: `<command> stdio --connection <conn_id>`.
    pub fn stdio(command: impl Into<PathBuf>, connection_id: &ConnectionId) -> Result<McpEntry, crate::HostConfigError> {
        McpEntry::new(
            command,
            vec![
                "stdio".into(),
                "--connection".into(),
                connection_id.as_str().to_owned(),
            ],
        )
    }

    /// An entry with explicit arguments. Allowed grammar:
    /// `stdio [--connection <conn_id>] [--broker <url>] [--experimental] [--lang zh-CN|en]`
    /// (the broker URL must not carry credentials, a query or a fragment). Anything else —
    /// and anything that looks like a secret — is refused: host configs never hold secrets.
    pub fn new(command: impl Into<PathBuf>, args: Vec<String>) -> Result<McpEntry, crate::HostConfigError> {
        let entry = McpEntry {
            command: command.into(),
            args,
        };
        entry.validate()?;
        Ok(entry)
    }

    /// Append `--broker <url>`.
    pub fn with_broker(mut self, url: &str) -> Result<McpEntry, crate::HostConfigError> {
        self.args.push("--broker".into());
        self.args.push(url.to_owned());
        self.validate()?;
        Ok(self)
    }

    /// Append `--experimental`.
    pub fn with_experimental(mut self) -> McpEntry {
        if !self.args.iter().any(|a| a == "--experimental") {
            self.args.push("--experimental".into());
        }
        self
    }

    /// Command as a string.
    pub fn command_str(&self) -> String {
        self.command.to_string_lossy().into_owned()
    }

    /// The connection id named by `--connection`, if any.
    pub fn connection_id(&self) -> Option<&str> {
        self.args
            .windows(2)
            .find(|w| w[0] == "--connection")
            .map(|w| w[1].as_str())
    }

    /// Validate the entry (see [`McpEntry::new`]).
    pub fn validate(&self) -> Result<(), crate::HostConfigError> {
        use crate::HostConfigError::InvalidEntry;
        let cmd = self.command_str();
        if !is_absolute_any(&self.command) {
            return Err(InvalidEntry(format!(
                "command must be an absolute path to aipass-mcp (got {cmd:?})"
            )));
        }
        if cmd.chars().any(char::is_control) {
            return Err(InvalidEntry("command contains control characters".into()));
        }
        let mut it = self.args.iter();
        if it.next().map(String::as_str) != Some("stdio") {
            return Err(InvalidEntry("the first argument must be \"stdio\"".into()));
        }
        let mut seen_conn = false;
        let mut seen_broker = false;
        let mut seen_lang = false;
        while let Some(a) = it.next() {
            match a.as_str() {
                "--connection" if !seen_conn => {
                    let v = it
                        .next()
                        .ok_or_else(|| InvalidEntry("--connection needs a value".into()))?;
                    ConnectionId::parse(v)
                        .map_err(|_| InvalidEntry(format!("{v:?} is not a connection id (conn_…)")))?;
                    seen_conn = true;
                }
                "--broker" if !seen_broker => {
                    let v = it
                        .next()
                        .ok_or_else(|| InvalidEntry("--broker needs a value".into()))?;
                    validate_broker_arg(v)?;
                    seen_broker = true;
                }
                "--lang" if !seen_lang => {
                    let v = it
                        .next()
                        .ok_or_else(|| InvalidEntry("--lang needs a value".into()))?;
                    if v != "zh-CN" && v != "en" {
                        return Err(InvalidEntry("--lang must be zh-CN or en".into()));
                    }
                    seen_lang = true;
                }
                "--experimental" => {}
                other => {
                    return Err(InvalidEntry(format!(
                        "argument {:?} is not allowed in a host config entry",
                        secrets::redact(other)
                    )));
                }
            }
        }
        let all = std::iter::once(cmd.as_str())
            .chain(self.args.iter().map(String::as_str))
            .collect::<Vec<_>>()
            .join(" ");
        if secrets::contains_secret(&all) {
            return Err(crate::HostConfigError::SecretInEntry);
        }
        Ok(())
    }
}

fn is_absolute_any(p: &Path) -> bool {
    if p.is_absolute() {
        return true;
    }
    // accept Windows absolute paths when planning for another OS (`C:\…`, `\\server\…`)
    let s = p.to_string_lossy();
    let b = s.as_bytes();
    (b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && (b[2] == b'\\' || b[2] == b'/'))
        || s.starts_with("\\\\")
}

fn validate_broker_arg(v: &str) -> Result<(), crate::HostConfigError> {
    use crate::HostConfigError::InvalidEntry;
    if let Some(rest) = v.strip_prefix("unix://") {
        if !rest.starts_with('/') || rest.contains(['?', '#']) {
            return Err(InvalidEntry("--broker unix:// needs an absolute socket path".into()));
        }
        return Ok(());
    }
    let url = url::Url::parse(v).map_err(|_| InvalidEntry("--broker is not a URL".into()))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(InvalidEntry("--broker must be unix://, http:// or https://".into()));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(crate::HostConfigError::SecretInEntry);
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(InvalidEntry("--broker must not contain a query or fragment".into()));
    }
    Ok(())
}

/// Detection result for one host (and scope).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HostStatus {
    /// Host.
    pub host: Host,
    /// Scope of `config_path` (`None` for remote hosts).
    pub scope: Option<Scope>,
    /// Whether the host appears to be installed (CLI on PATH, config dir or app bundle).
    pub installed: bool,
    /// Version from `<tool> --version` / the app bundle, when probed.
    pub version: Option<String>,
    /// Config file (`None` for remote hosts, or project-scoped hosts without a project).
    pub config_path: Option<PathBuf>,
    /// The config already has an `aipass` entry.
    pub has_aipass_entry: bool,
    /// The existing `aipass` entry (command + args), if parseable.
    pub existing_entry: Option<McpEntry>,
    /// The config file exists but could not be parsed.
    pub config_error: Option<String>,
    /// Compatibility label (`standard_protocol` in this build).
    pub label: CompatLabel,
}

/// What a plan does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PlanAction {
    /// Create a new file.
    Create,
    /// Modify an existing file.
    Update,
    /// Remove our entry.
    Remove,
    /// Nothing to do.
    Unchanged,
}

/// A planned config change. `before` / `after` may contain the user's **other** settings
/// (including secrets they put in other servers' `env`): never print or log them — show
/// [`ConfigPlan::unified_diff`], which redacts secret-looking values.
#[derive(Clone, PartialEq, Eq)]
pub struct ConfigPlan {
    /// Host.
    pub host: Host,
    /// Scope.
    pub scope: Scope,
    /// Config path as the user knows it.
    pub path: PathBuf,
    /// Real file written (symlinks resolved).
    pub write_path: PathBuf,
    /// Current content (`None` when the file does not exist).
    pub before: Option<String>,
    /// New content.
    pub after: String,
    /// Unified diff (secret-looking values redacted).
    pub unified_diff: String,
    /// Action.
    pub action: PlanAction,
}

impl fmt::Debug for ConfigPlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConfigPlan")
            .field("host", &self.host)
            .field("scope", &self.scope)
            .field("path", &self.path)
            .field("write_path", &self.write_path)
            .field("action", &self.action)
            .field("before", &self.before.as_ref().map(|b| format!("<{} bytes>", b.len())))
            .field("after", &format!("<{} bytes>", self.after.len()))
            .finish()
    }
}

/// Result of [`crate::apply`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ApplyOutcome {
    /// Path written.
    pub path: PathBuf,
    /// Backup of the previous content (`<file>.aipass-backup-<yyyymmddHHMMSS>`), when a file existed.
    pub backup_path: Option<PathBuf>,
    /// Whether anything was written.
    pub changed: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosts_and_labels() {
        for h in Host::LOCAL.iter().chain(Host::REMOTE.iter()) {
            assert_eq!(Host::parse(h.as_str()), Some(*h));
        }
        assert!(VERIFIED_HOST_VERSIONS.is_empty());
        assert_eq!(label_for(Host::Codex, Some("0.98.0"), Os::MacOs), CompatLabel::StandardProtocol);
        assert_eq!(label_for(Host::ClaudeDesktop, None, Os::Linux), CompatLabel::Unsupported);
        assert_eq!(label_for(Host::Chatgpt, None, Os::Linux), CompatLabel::StandardProtocol);
        assert_eq!(CompatLabel::StandardProtocol.label().zh, "标准协议可接入");
        assert_eq!(serde_json::to_string(&CompatLabel::StandardProtocol).unwrap(), "\"standard_protocol\"");
    }

    #[test]
    fn entry_validation() {
        let id = ConnectionId::generate();
        let e = McpEntry::stdio("/usr/local/bin/aipass-mcp", &id).unwrap();
        assert_eq!(e.args, vec!["stdio", "--connection", id.as_str()]);
        assert_eq!(e.connection_id(), Some(id.as_str()));
        assert!(McpEntry::stdio("aipass-mcp", &id).is_err());
        assert!(McpEntry::stdio("C:\\Program Files\\AI Pass\\aipass-mcp.exe", &id).is_ok());
        let ok = McpEntry::new(
            "/opt/aipass-mcp",
            vec!["stdio".into(), "--broker".into(), "https://node.example.com".into(), "--experimental".into(), "--lang".into(), "en".into()],
        );
        assert!(ok.is_ok());
        for bad in [
            vec!["http".to_string()],
            vec!["stdio".into(), "--token".into(), "x".into()],
            vec!["stdio".into(), "--connection".into(), "res_01jbz3k6w8a7m2q4t5v9x0y1z4".into()],
            vec!["stdio".into(), "--broker".into(), "https://u:p@node.example.com".into()],
            vec!["stdio".into(), "--broker".into(), "https://node.example.com/?key=1".into()],
            vec!["stdio".into(), "ghp_abcdefghijklmnopqrstuvwxyz0123456789".into()],
        ] {
            assert!(McpEntry::new("/opt/aipass-mcp", bad.clone()).is_err(), "{bad:?}");
        }
        // a secret-looking command path is refused
        assert!(matches!(
            McpEntry::new("/tmp/sk-ant-api03-abcdefghijklmnopqrstuv/aipass-mcp", vec!["stdio".into()]),
            Err(crate::HostConfigError::SecretInEntry)
        ));
    }
}
