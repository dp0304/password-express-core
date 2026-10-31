// SPDX-License-Identifier: Apache-2.0
//! Host detection: installed?, version (`<tool> --version` with a timeout, or the macOS app
//! bundle), config path, existing `aipass` entry, label.

use std::ffi::OsStr;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::codex;
use crate::jsonc;
use crate::model::{Host, HostEnv, HostStatus, McpEntry, Os, SERVER_KEY, Scope, label_for};
use crate::plan::{Format, config_location};

/// Detection options.
#[derive(Debug, Clone)]
pub struct DetectOptions {
    /// Run `<tool> --version` for hosts whose CLI is on `PATH`.
    pub probe_versions: bool,
    /// Per-probe timeout (the child is killed when it expires).
    pub timeout: Duration,
    /// Include the remote hosts (ChatGPT, Claude connector).
    pub include_remote: bool,
}

impl Default for DetectOptions {
    fn default() -> Self {
        Self {
            probe_versions: true,
            timeout: Duration::from_secs(3),
            include_remote: true,
        }
    }
}

/// Find `name` on `path_var` (honours `PATHEXT`-style suffixes on Windows).
pub fn which(name: &str, path_var: Option<&OsStr>, os: Os) -> Option<PathBuf> {
    let path_var = path_var?;
    let exts: &[&str] = if os == Os::Windows {
        &["", ".exe", ".cmd", ".bat"]
    } else {
        &[""]
    };
    for dir in std::env::split_paths(path_var) {
        if !dir.is_absolute() {
            continue; // never resolve through relative PATH entries
        }
        for ext in exts {
            let cand = dir.join(format!("{name}{ext}"));
            if is_executable(&cand) {
                return Some(cand);
            }
        }
    }
    None
}

fn is_executable(p: &Path) -> bool {
    let Ok(m) = std::fs::metadata(p) else { return false };
    if !m.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        m.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

/// Extract the first version-looking token (`1.2`, `1.2.3`, `1.2.3-beta.1`).
pub fn parse_version(text: &str) -> Option<String> {
    let re = regex::Regex::new(r"\d+\.\d+(?:\.\d+)?(?:[-+][0-9A-Za-z][0-9A-Za-z.\-]*)?").ok()?;
    re.find(text).map(|m| m.as_str().to_owned())
}

/// Run `<bin> --version` with a timeout; the child is killed on timeout. Never uses a shell.
pub fn probe_version(bin: &Path, timeout: Duration) -> Option<String> {
    let mut child = Command::new(bin)
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let mut stdout = child.stdout.take()?;
    let reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = (&mut stdout).take(64 * 1024).read_to_end(&mut buf);
        buf
    });
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    }
    let out = reader.join().ok()?;
    parse_version(&String::from_utf8_lossy(&out))
}

fn app_bundle_name(host: Host) -> Option<&'static str> {
    match host {
        Host::Cursor => Some("Cursor.app"),
        Host::ClaudeDesktop => Some("Claude.app"),
        Host::Vscode => Some("Visual Studio Code.app"),
        Host::Windsurf => Some("Windsurf.app"),
        _ => None,
    }
}

/// `CFBundleShortVersionString` of an app bundle (XML plists only).
pub fn bundle_version(app: &Path) -> Option<String> {
    let text = std::fs::read_to_string(app.join("Contents").join("Info.plist")).ok()?;
    let re = regex::Regex::new(r"<key>CFBundleShortVersionString</key>\s*<string>([^<]{1,64})</string>").ok()?;
    re.captures(&text).map(|c| c[1].trim().to_owned())
}

fn config_dir_marker(env: &HostEnv, host: Host) -> Option<PathBuf> {
    match host {
        Host::Codex => Some(env.codex_home.clone().unwrap_or_else(|| env.home.join(".codex"))),
        Host::ClaudeCode => Some(env.claude_config_dir.clone().unwrap_or_else(|| env.home.join(".claude"))),
        Host::Cursor => Some(env.home.join(".cursor")),
        Host::Windsurf => Some(env.home.join(".codeium").join("windsurf")),
        Host::Vscode => Some(env.home.join(".vscode")),
        Host::ClaudeDesktop => match env.os {
            Os::MacOs => Some(env.home.join("Library").join("Application Support").join("Claude")),
            Os::Windows => Some(
                env.appdata
                    .clone()
                    .unwrap_or_else(|| env.home.join("AppData").join("Roaming"))
                    .join("Claude"),
            ),
            _ => None,
        },
        Host::Chatgpt | Host::ClaudeConnector => None,
    }
}

/// Read the existing `aipass` entry: (present, entry, parse error).
fn existing_entry(path: &Path, format: Format) -> (bool, Option<McpEntry>, Option<String>) {
    let Ok(src) = std::fs::read_to_string(path) else {
        return (false, None, None);
    };
    match format {
        Format::Toml => match codex::get_entry(&src) {
            Ok(Some((cmd, args))) => (
                true,
                cmd.map(|c| McpEntry {
                    command: PathBuf::from(c),
                    args,
                }),
                None,
            ),
            Ok(None) => (false, None, None),
            Err(e) => (false, None, Some(format!("{e:?}"))),
        },
        Format::Json { container } => match jsonc::get_member(&src, container, SERVER_KEY) {
            Ok(Some(v)) => {
                let cmd = v.get("command").and_then(|c| c.as_str()).map(PathBuf::from);
                let args = v
                    .get("args")
                    .and_then(|a| a.as_array())
                    .map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_owned)).collect())
                    .unwrap_or_default();
                (true, cmd.map(|command| McpEntry { command, args }), None)
            }
            Ok(None) => (false, None, None),
            Err(jsonc::EditError::Parse(p)) => {
                let (l, c) = p.line_col(&src);
                (false, None, Some(format!("line {l}, column {c}: {}", p.message)))
            }
            Err(jsonc::EditError::NotAnObject(w)) => (false, None, Some(format!("{w} is not an object"))),
        },
    }
}

fn detect_host(env: &HostEnv, host: Host, opts: &DetectOptions) -> Vec<HostStatus> {
    if host.is_remote() {
        return vec![HostStatus {
            host,
            scope: None,
            installed: false,
            version: None,
            config_path: None,
            has_aipass_entry: false,
            existing_entry: None,
            config_error: None,
            label: label_for(host, None, env.os),
        }];
    }
    let cli = host
        .cli_name()
        .and_then(|n| which(n, env.path_var.as_deref(), env.os));
    let bundle = app_bundle_name(host).and_then(|name| {
        env.app_dirs
            .iter()
            .map(|d| d.join(name))
            .find(|p| p.is_dir())
    });
    let marker = config_dir_marker(env, host).filter(|p| p.exists());
    let mut version = None;
    if opts.probe_versions {
        version = cli.as_deref().and_then(|b| probe_version(b, opts.timeout));
    }
    if version.is_none() {
        version = bundle.as_deref().and_then(bundle_version);
    }
    let mut out = Vec::new();
    for &scope in host.scopes() {
        let loc = config_location(env, host, scope);
        let (config_path, has, entry, err) = match loc {
            Ok((path, format)) => {
                let (has, entry, err) = existing_entry(&path, format);
                (Some(path), has, entry, err)
            }
            Err(_) => (None, false, None, None),
        };
        if scope == Scope::Project && config_path.is_none() && host != Host::Vscode {
            continue; // no project directory: report only the user scope
        }
        let file_exists = config_path.as_ref().is_some_and(|p| p.exists());
        out.push(HostStatus {
            host,
            scope: Some(scope),
            installed: cli.is_some() || bundle.is_some() || marker.is_some() || (scope == Scope::User && file_exists),
            version: version.clone(),
            config_path,
            has_aipass_entry: has,
            existing_entry: entry,
            config_error: err,
            label: label_for(host, version.as_deref(), env.os),
        });
    }
    out
}

/// Detect every host in `env`.
pub fn detect_in(env: &HostEnv, opts: &DetectOptions) -> Vec<HostStatus> {
    let hosts: Vec<Host> = Host::LOCAL
        .iter()
        .copied()
        .chain(opts.include_remote.then_some(Host::REMOTE).into_iter().flatten())
        .collect();
    std::thread::scope(|s| {
        let handles: Vec<_> = hosts
            .iter()
            .map(|&h| s.spawn(move || detect_host(env, h, opts)))
            .collect();
        handles
            .into_iter()
            .flat_map(|h| h.join().unwrap_or_default())
            .collect()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions() {
        assert_eq!(parse_version("codex-cli 0.98.0").as_deref(), Some("0.98.0"));
        assert_eq!(parse_version("2.1.300 (Claude Code)").as_deref(), Some("2.1.300"));
        assert_eq!(parse_version("1.105.1\nabc123\narm64").as_deref(), Some("1.105.1"));
        assert_eq!(parse_version("v1.2.3-beta.4").as_deref(), Some("1.2.3-beta.4"));
        assert_eq!(parse_version("no version"), None);
    }
}
