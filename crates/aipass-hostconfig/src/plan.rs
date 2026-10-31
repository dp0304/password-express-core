// SPDX-License-Identifier: Apache-2.0
//! Config paths per host, `plan` / `apply` / `remove`.

use std::io::Write as _;
use std::path::{Path, PathBuf};

use similar::TextDiff;

use crate::codex;
use crate::jsonc::{self, Ordered};
use crate::model::{
    ApplyOutcome, ConfigPlan, Host, HostEnv, McpEntry, Os, PlanAction, SERVER_KEY, Scope,
};
use crate::secrets;
use crate::HostConfigError;

/// File format of a host config.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// TOML (`mcp_servers.<name>`).
    Toml,
    /// JSON / JSONC with the servers under `container`.
    Json {
        /// Container key (`mcpServers` or `servers`).
        container: &'static str,
    },
}

/// Config file location and format for `host` at `scope`.
pub fn config_location(env: &HostEnv, host: Host, scope: Scope) -> Result<(PathBuf, Format), HostConfigError> {
    if host.is_remote() {
        return Err(HostConfigError::RemoteHost(host));
    }
    if !host.scopes().contains(&scope) {
        return Err(HostConfigError::UnsupportedScope { host, scope });
    }
    let project = || env.project_dir.clone().ok_or(HostConfigError::NoProjectDir);
    let mcp = Format::Json { container: "mcpServers" };
    Ok(match (host, scope) {
        (Host::Codex, Scope::User) => (
            env.codex_home
                .clone()
                .unwrap_or_else(|| env.home.join(".codex"))
                .join("config.toml"),
            Format::Toml,
        ),
        (Host::ClaudeCode, Scope::User) => (
            env.claude_config_dir
                .clone()
                .unwrap_or_else(|| env.home.clone())
                .join(".claude.json"),
            mcp,
        ),
        (Host::ClaudeCode, Scope::Project) => (project()?.join(".mcp.json"), mcp),
        (Host::Cursor, Scope::User) => (env.home.join(".cursor").join("mcp.json"), mcp),
        (Host::Cursor, Scope::Project) => (project()?.join(".cursor").join("mcp.json"), mcp),
        (Host::ClaudeDesktop, Scope::User) => match env.os {
            Os::MacOs => (
                env.home
                    .join("Library")
                    .join("Application Support")
                    .join("Claude")
                    .join("claude_desktop_config.json"),
                mcp,
            ),
            Os::Windows => (
                env.appdata
                    .clone()
                    .unwrap_or_else(|| env.home.join("AppData").join("Roaming"))
                    .join("Claude")
                    .join("claude_desktop_config.json"),
                mcp,
            ),
            _ => {
                return Err(HostConfigError::Unsupported {
                    host,
                    reason: "Claude Desktop is only available for macOS and Windows".into(),
                });
            }
        },
        (Host::Vscode, Scope::Project) => (
            project()?.join(".vscode").join("mcp.json"),
            Format::Json { container: "servers" },
        ),
        (Host::Windsurf, Scope::User) => (
            env.home.join(".codeium").join("windsurf").join("mcp_config.json"),
            mcp,
        ),
        _ => return Err(HostConfigError::UnsupportedScope { host, scope }),
    })
}

/// The JSON value written under `<container>.aipass` for `host`.
pub fn entry_value(host: Host, entry: &McpEntry) -> Ordered {
    let command = ("command".to_owned(), Ordered::Str(entry.command_str()));
    let args = (
        "args".to_owned(),
        Ordered::Arr(entry.args.iter().map(|a| Ordered::Str(a.clone())).collect()),
    );
    let stdio = ("type".to_owned(), Ordered::Str("stdio".into()));
    match host {
        Host::ClaudeCode => Ordered::Obj(vec![
            stdio,
            command,
            args,
            ("env".to_owned(), Ordered::Obj(vec![])),
        ]),
        Host::Vscode => Ordered::Obj(vec![stdio, command, args]),
        _ => Ordered::Obj(vec![command, args]),
    }
}

fn read_optional(path: &Path) -> Result<Option<String>, HostConfigError> {
    match std::fs::read(path) {
        Ok(bytes) => String::from_utf8(bytes)
            .map(Some)
            .map_err(|_| HostConfigError::Parse {
                path: path.to_owned(),
                line: 0,
                column: 0,
                message: "file is not UTF-8".into(),
            }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(HostConfigError::io(path, e)),
    }
}

/// Resolve a (possibly symlinked) config path to the file that should be written.
fn resolve_write_path(path: &Path) -> Result<PathBuf, HostConfigError> {
    match std::fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_symlink() => std::fs::canonicalize(path).map_err(|e| HostConfigError::io(path, e)),
        Ok(m) if !m.is_file() => Err(HostConfigError::Io {
            path: path.to_owned(),
            message: "not a regular file".into(),
        }),
        _ => Ok(path.to_owned()),
    }
}

fn parse_error(path: &Path, src: &str, e: jsonc::EditError) -> HostConfigError {
    match e {
        jsonc::EditError::Parse(p) => {
            let (line, column) = p.line_col(src);
            HostConfigError::Parse {
                path: path.to_owned(),
                line,
                column,
                message: p.message,
            }
        }
        jsonc::EditError::NotAnObject(what) => HostConfigError::NotAnObject {
            path: path.to_owned(),
            what,
        },
    }
}

fn toml_error(path: &Path, e: codex::TomlEditError) -> HostConfigError {
    match e {
        codex::TomlEditError::Parse(m) => HostConfigError::Parse {
            path: path.to_owned(),
            line: 0,
            column: 0,
            message: m,
        },
        codex::TomlEditError::NotATable(what) => HostConfigError::NotAnObject {
            path: path.to_owned(),
            what,
        },
    }
}

/// Unified diff with secret-looking values redacted.
pub fn unified_diff(path: &Path, before: Option<&str>, after: &str) -> String {
    let b = before.unwrap_or("");
    let diff = TextDiff::from_lines(b, after);
    let name = path.display().to_string();
    let from = if before.is_some() { format!("a/{name}") } else { "/dev/null".into() };
    let text = diff
        .unified_diff()
        .context_radius(2)
        .header(&from, &format!("b/{name}"))
        .to_string();
    text.lines()
        .map(secrets::redact_for_display)
        .collect::<Vec<_>>()
        .join("\n")
        + if text.is_empty() { "" } else { "\n" }
}

fn finish_plan(
    host: Host,
    scope: Scope,
    path: PathBuf,
    write_path: PathBuf,
    before: Option<String>,
    after: String,
    removing: bool,
) -> ConfigPlan {
    let action = match (&before, removing) {
        (Some(b), _) if *b == after => PlanAction::Unchanged,
        (None, false) => PlanAction::Create,
        (_, true) => PlanAction::Remove,
        (Some(_), false) => PlanAction::Update,
    };
    let unified_diff = if action == PlanAction::Unchanged {
        String::new()
    } else {
        unified_diff(&path, before.as_deref(), &after)
    };
    ConfigPlan {
        host,
        scope,
        path,
        write_path,
        before,
        after,
        unified_diff,
        action,
    }
}

/// Plan adding/updating the `aipass` entry of `host` at `scope`.
pub fn plan_in(env: &HostEnv, host: Host, scope: Scope, entry: &McpEntry) -> Result<ConfigPlan, HostConfigError> {
    entry.validate()?;
    let (path, format) = config_location(env, host, scope)?;
    let write_path = resolve_write_path(&path)?;
    let before = read_optional(&write_path)?;
    let src = before.clone().unwrap_or_default();
    let after = match format {
        Format::Toml => codex::upsert(&src, entry).map_err(|e| toml_error(&path, e))?,
        Format::Json { container } => {
            jsonc::upsert(&src, container, SERVER_KEY, &entry_value(host, entry))
                .map_err(|e| parse_error(&path, &src, e))?
        }
    };
    // defence in depth: the rendered entry itself must not look like a secret
    if secrets::contains_secret(&entry_value(host, entry).render_compact()) {
        return Err(HostConfigError::SecretInEntry);
    }
    Ok(finish_plan(host, scope, path, write_path, before, after, false))
}

/// Plan removing the `aipass` entry (`action == Unchanged` when there is none).
pub fn plan_remove_in(env: &HostEnv, host: Host, scope: Scope) -> Result<ConfigPlan, HostConfigError> {
    let (path, format) = config_location(env, host, scope)?;
    let write_path = resolve_write_path(&path)?;
    let before = read_optional(&write_path)?;
    let Some(src) = before.clone() else {
        return Ok(ConfigPlan {
            host,
            scope,
            path,
            write_path,
            before: None,
            after: String::new(),
            unified_diff: String::new(),
            action: PlanAction::Unchanged,
        });
    };
    let after = match format {
        Format::Toml => codex::remove(&src).map_err(|e| toml_error(&path, e))?,
        Format::Json { container } => {
            jsonc::remove(&src, container, SERVER_KEY).map_err(|e| parse_error(&path, &src, e))?
        }
    }
    .unwrap_or_else(|| src.clone());
    Ok(finish_plan(host, scope, path, write_path, before, after, true))
}

fn backup_path_for(path: &Path) -> PathBuf {
    let ts = chrono::Local::now().format("%Y%m%d%H%M%S").to_string();
    let base = format!("{}.aipass-backup-{ts}", path.display());
    let mut candidate = PathBuf::from(&base);
    let mut n = 1;
    while candidate.exists() {
        candidate = PathBuf::from(format!("{base}-{n}"));
        n += 1;
    }
    candidate
}

#[cfg(unix)]
fn mode_of(path: &Path) -> Option<u32> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).ok().map(|m| m.permissions().mode() & 0o7777)
}

fn write_new_file(path: &Path, bytes: &[u8], mode: u32) -> std::io::Result<()> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(mode);
    }
    #[cfg(not(unix))]
    let _ = mode;
    let mut f = opts.open(path)?;
    f.write_all(bytes)?;
    f.sync_all()
}

fn atomic_replace(path: &Path, bytes: &[u8], mode: u32) -> std::io::Result<()> {
    let dir = path.parent().unwrap_or(Path::new("."));
    std::fs::create_dir_all(dir)?;
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("config");
    let mut rnd = [0u8; 6];
    aipass_types::crypto::rng::fill_random(&mut rnd).map_err(|_| std::io::Error::other("OS RNG unavailable"))?;
    let tmp = dir.join(format!(".{name}.aipass-tmp-{}", aipass_types::crypto::b64u::encode(rnd)));
    let r = write_new_file(&tmp, bytes, mode).and_then(|_| {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            // the umask may have narrowed the mode; set it explicitly
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(mode))?;
        }
        std::fs::rename(&tmp, path)
    });
    if r.is_err() {
        let _ = std::fs::remove_file(&tmp);
    } else {
        #[cfg(unix)]
        if let Ok(d) = std::fs::File::open(dir) {
            let _ = d.sync_all();
        }
    }
    r
}

/// Apply a plan: verify the file still matches `plan.before`, write a timestamped backup of
/// the old content, then atomically replace the file (temp file + rename, permissions kept).
pub fn apply(plan: &ConfigPlan) -> Result<ApplyOutcome, HostConfigError> {
    if plan.action == PlanAction::Unchanged {
        return Ok(ApplyOutcome {
            path: plan.path.clone(),
            backup_path: None,
            changed: false,
        });
    }
    let current = read_optional(&plan.write_path)?;
    if current != plan.before {
        return Err(HostConfigError::ConcurrentModification {
            path: plan.path.clone(),
        });
    }
    #[cfg(unix)]
    let mode = mode_of(&plan.write_path).unwrap_or(match plan.scope {
        Scope::User => 0o600,
        Scope::Project => 0o644,
    });
    #[cfg(not(unix))]
    let mode = 0o600;
    let backup_path = match &plan.before {
        Some(old) => {
            let bp = backup_path_for(&plan.path);
            write_new_file(&bp, old.as_bytes(), mode).map_err(|e| HostConfigError::io(&bp, e))?;
            Some(bp)
        }
        None => None,
    };
    atomic_replace(&plan.write_path, plan.after.as_bytes(), mode)
        .map_err(|e| HostConfigError::io(&plan.write_path, e))?;
    Ok(ApplyOutcome {
        path: plan.path.clone(),
        backup_path,
        changed: true,
    })
}

/// POSIX shell quoting.
fn sh_quote(s: &str) -> String {
    if !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_./:=@%+,".contains(&b))
    {
        s.to_owned()
    } else {
        format!("'{}'", s.replace('\'', "'\\''"))
    }
}

/// The equivalent `claude mcp add` command (CONTRACTS §10), e.g.
/// `claude mcp add --scope user aipass -- /abs/aipass-mcp stdio --connection conn_…`.
pub fn claude_mcp_add_command(scope: Scope, entry: &McpEntry) -> Result<String, HostConfigError> {
    entry.validate()?;
    let mut parts = vec![
        "claude".to_owned(),
        "mcp".into(),
        "add".into(),
        "--scope".into(),
        scope.as_str().into(),
        SERVER_KEY.into(),
        "--".into(),
        sh_quote(&entry.command_str()),
    ];
    parts.extend(entry.args.iter().map(|a| sh_quote(a)));
    Ok(parts.join(" "))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quoting() {
        assert_eq!(sh_quote("/usr/bin/x"), "/usr/bin/x");
        assert_eq!(sh_quote("/Applications/AI Pass.app/x"), "'/Applications/AI Pass.app/x'");
        assert_eq!(sh_quote("it's"), "'it'\\''s'");
        let e = McpEntry::stdio(
            "/Applications/AI Pass.app/Contents/MacOS/aipass-mcp",
            &aipass_types::ConnectionId::parse("conn_01jbz3k6w8a7m2q4t5v9x0y1z4").unwrap(),
        )
        .unwrap();
        assert_eq!(
            claude_mcp_add_command(Scope::User, &e).unwrap(),
            "claude mcp add --scope user aipass -- '/Applications/AI Pass.app/Contents/MacOS/aipass-mcp' stdio --connection conn_01jbz3k6w8a7m2q4t5v9x0y1z4"
        );
    }

    #[test]
    fn diff_redacts_neighbouring_secrets() {
        let before = "{\n  \"mcpServers\": {\n    \"gh\": {\"env\": {\"GITHUB_TOKEN\": \"ghp_abcdefghijklmnopqrstuvwxyz0123\"}}\n  }\n}\n";
        let after = jsonc::upsert(
            before,
            "mcpServers",
            "aipass",
            &Ordered::Obj(vec![("command".into(), Ordered::Str("/x".into()))]),
        )
        .unwrap();
        let d = unified_diff(Path::new("/h/.cursor/mcp.json"), Some(before), &after);
        assert!(d.contains("+    \"aipass\""), "{d}");
        assert!(!d.contains("ghp_abcdefghijklmnopqrstuvwxyz0123"), "{d}");
        assert!(d.contains("[REDACTED]"));
    }

    /// MNC-06: credentials whose value has no recognisable format (AWS secret keys) or
    /// whose key ends in `_KEY` are redacted when they fall inside the diff context.
    #[test]
    fn diff_redacts_credentials_named_by_their_key() {
        let before = "{\n  \"mcpServers\": {\n    \"aws\": {\n      \"command\": \"aws-mcp\",\n      \"env\": {\n        \"STRIPE_SECRET_KEY\": \"sk_live_51HabcdefghijklmnopQRST\",\n        \"AWS_SECRET_ACCESS_KEY\": \"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\"\n      }\n    }\n  }\n}\n";
        let after = jsonc::upsert(
            before,
            "mcpServers",
            "aipass",
            &Ordered::Obj(vec![("command".into(), Ordered::Str("/x".into()))]),
        )
        .unwrap();
        let d = unified_diff(Path::new("/h/.cursor/mcp.json"), Some(before), &after);
        assert!(d.contains("+    \"aipass\""), "{d}");
        assert!(d.contains("AWS_SECRET_ACCESS_KEY"), "the key stays visible in the context: {d}");
        assert!(!d.contains("wJalrXUtnFEMI"), "{d}");
        assert!(!d.contains("sk_live_51H"), "{d}");
    }
}
