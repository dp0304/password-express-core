// SPDX-License-Identifier: Apache-2.0
//! Host config wizard on temporary HOME fixtures: existing configs with comments and other
//! servers are preserved, backups are created, remove restores the original bytes, and no
//! secrets are ever written.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use aipass_hostconfig::{
    CompatLabel, DetectOptions, Host, HostConfigError, HostEnv, McpEntry, Os, PlanAction, Scope,
    apply, claude_mcp_add_command, config_location, detect_in, plan_in, plan_remove_in, remove_in,
    secrets,
};
use aipass_types::ConnectionId;

const CONN: &str = "conn_01jbz3k6w8a7m2q4t5v9x0y1z4";

fn entry() -> McpEntry {
    McpEntry::stdio("/opt/aipass/bin/aipass-mcp", &ConnectionId::parse(CONN).unwrap()).unwrap()
}

fn write(path: &Path, text: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
}

fn backups_of(path: &Path) -> Vec<PathBuf> {
    let name = path.file_name().unwrap().to_str().unwrap().to_owned();
    let mut v: Vec<PathBuf> = std::fs::read_dir(path.parent().unwrap())
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with(&format!("{name}.aipass-backup-")))
        })
        .collect();
    v.sort();
    v
}

/// apply → checks → remove → original bytes.
fn full_cycle(env: &HostEnv, host: Host, scope: Scope, original: &str, must_keep: &[&str]) {
    let (path, _) = config_location(env, host, scope).unwrap();
    write(&path, original);
    let plan = plan_in(env, host, scope, &entry()).unwrap();
    assert_eq!(plan.action, PlanAction::Update, "{host}");
    assert!(plan.unified_diff.contains("aipass"), "{}", plan.unified_diff);
    assert!(plan.unified_diff.contains(CONN));
    let out = apply(&plan).unwrap();
    assert!(out.changed);
    let backup = out.backup_path.clone().unwrap();
    assert!(backup.to_string_lossy().contains(".aipass-backup-"));
    assert_eq!(std::fs::read_to_string(&backup).unwrap(), original, "backup holds the original");
    let after = std::fs::read_to_string(&path).unwrap();
    for keep in must_keep {
        assert!(after.contains(keep), "{host}: lost {keep:?}\n{after}");
    }
    assert!(after.contains("/opt/aipass/bin/aipass-mcp"));
    assert!(after.contains(CONN));
    // only the user's own (pre-existing) secrets may appear; we add none
    let added: Vec<&str> = after.lines().filter(|l| !original.contains(*l)).collect();
    for l in &added {
        assert!(!secrets::contains_secret(l), "{host}: added secret-looking line {l:?}");
    }
    // idempotent
    let again = plan_in(env, host, scope, &entry()).unwrap();
    assert_eq!(again.action, PlanAction::Unchanged);
    assert!(again.unified_diff.is_empty());
    assert!(!apply(&again).unwrap().changed);
    // detect sees it
    let st = detect_in(env, &DetectOptions { probe_versions: false, ..Default::default() });
    let s = st.iter().find(|s| s.host == host && s.scope == Some(scope)).unwrap();
    assert!(s.has_aipass_entry, "{host}");
    assert_eq!(s.existing_entry.as_ref().unwrap().connection_id(), Some(CONN));
    assert_eq!(s.label, CompatLabel::StandardProtocol);
    if scope == Scope::User {
        assert!(s.installed, "a config file in the home counts as installed");
    }
    // remove restores the original exactly, with another backup
    std::thread::sleep(Duration::from_millis(5));
    let removed = remove_in(env, host, scope).unwrap();
    assert!(removed.changed);
    assert_eq!(std::fs::read_to_string(&path).unwrap(), original, "{host}: remove must restore");
    assert!(backups_of(&path).len() >= 2);
    // removing again is a no-op
    assert!(!remove_in(env, host, scope).unwrap().changed);
}

#[test]
fn codex_toml_with_comments_and_other_servers() {
    let home = tempfile::tempdir().unwrap();
    let env = HostEnv::with_home(home.path());
    full_cycle(
        &env,
        Host::Codex,
        Scope::User,
        "# my codex settings\nmodel = \"gpt-5-codex\"  # pinned\napproval_policy = \"on-request\"\n\n# docs server\n[mcp_servers.docs]\ncommand = \"npx\"\nargs = [\"-y\", \"@acme/docs-mcp\"]\n[mcp_servers.docs.env]\nDOCS_TOKEN = \"ghp_abcdefghijklmnopqrstuvwxyz0123\"\n\n[profiles.deep]\nmodel_reasoning_effort = \"high\"\n",
        &["# my codex settings", "# pinned", "[mcp_servers.docs]", "[profiles.deep]", "DOCS_TOKEN"],
    );
    // CODEX_HOME override
    let mut env2 = HostEnv::with_home(home.path());
    env2.codex_home = Some(home.path().join("alt-codex"));
    assert_eq!(
        config_location(&env2, Host::Codex, Scope::User).unwrap().0,
        home.path().join("alt-codex/config.toml")
    );
}

#[test]
fn claude_code_user_and_project_scope() {
    let home = tempfile::tempdir().unwrap();
    let proj = tempfile::tempdir().unwrap();
    let env = HostEnv::with_home(home.path()).project(proj.path());
    let claude_json = "{\n  \"numStartups\": 42,\n  \"theme\": \"dark\",\n  \"mcpServers\": {\n    \"sentry\": {\n      \"type\": \"http\",\n      \"url\": \"https://mcp.sentry.dev/mcp\"\n    }\n  },\n  \"projects\": {\n    \"/Users/me/x\": {\n      \"allowedTools\": []\n    }\n  }\n}";
    full_cycle(&env, Host::ClaudeCode, Scope::User, claude_json, &["\"numStartups\": 42", "\"sentry\"", "\"projects\""]);
    let after_plan = plan_in(&env, Host::ClaudeCode, Scope::User, &entry()).unwrap();
    assert!(after_plan.after.contains("\"type\": \"stdio\""));
    assert!(after_plan.after.contains("\"env\": {}"));
    full_cycle(
        &env,
        Host::ClaudeCode,
        Scope::Project,
        "{\n  \"mcpServers\": {\n    \"db\": {\"command\": \"pg-mcp\"}\n  }\n}\n",
        &["\"db\": {\"command\": \"pg-mcp\"}"],
    );
    let cmd = claude_mcp_add_command(Scope::User, &entry()).unwrap();
    assert_eq!(cmd, format!("claude mcp add --scope user aipass -- /opt/aipass/bin/aipass-mcp stdio --connection {CONN}"));
    // CLAUDE_CONFIG_DIR override
    let mut env2 = env.clone();
    env2.claude_config_dir = Some(home.path().join("profile"));
    assert_eq!(
        config_location(&env2, Host::ClaudeCode, Scope::User).unwrap().0,
        home.path().join("profile/.claude.json")
    );
}

#[test]
fn cursor_windsurf_claude_desktop_vscode() {
    let home = tempfile::tempdir().unwrap();
    let proj = tempfile::tempdir().unwrap();
    let mut env = HostEnv::with_home(home.path()).project(proj.path());
    let mcp = "{\n    \"mcpServers\": {\n        \"browser\": {\n            \"command\": \"npx\",\n            \"args\": [\"@playwright/mcp@latest\"],\n            \"env\": {\"OPENAI_API_KEY\": \"sk-proj-abcdefghijklmnopqrstuvwx\"}\n        }\n    }\n}\n";
    full_cycle(&env, Host::Cursor, Scope::User, mcp, &["\"browser\"", "@playwright/mcp@latest"]);
    full_cycle(&env, Host::Cursor, Scope::Project, mcp, &["\"browser\""]);
    full_cycle(&env, Host::Windsurf, Scope::User, mcp, &["\"browser\""]);
    env.os = Os::MacOs;
    full_cycle(&env, Host::ClaudeDesktop, Scope::User, "{\n  \"globalShortcut\": \"Ctrl+Space\"\n}\n", &["globalShortcut"]);
    assert!(
        config_location(&env, Host::ClaudeDesktop, Scope::User)
            .unwrap()
            .0
            .ends_with("Library/Application Support/Claude/claude_desktop_config.json")
    );
    env.os = Os::Windows;
    let (p, _) = config_location(&env, Host::ClaudeDesktop, Scope::User).unwrap();
    assert!(p.starts_with(home.path().join("AppData").join("Roaming")));
    assert!(p.ends_with("Claude/claude_desktop_config.json"));
    env.os = Os::Linux;
    assert!(matches!(
        plan_in(&env, Host::ClaudeDesktop, Scope::User, &entry()),
        Err(HostConfigError::Unsupported { .. })
    ));
    let st = detect_in(&env, &DetectOptions { probe_versions: false, ..Default::default() });
    assert_eq!(st.iter().find(|s| s.host == Host::ClaudeDesktop).unwrap().label, CompatLabel::Unsupported);
    env.os = Os::current();

    // VS Code JSONC: comments + trailing commas + tabs, `servers` container
    let vscode = "// Workspace MCP servers\n{\n\t\"inputs\": [\n\t\t{\"type\": \"promptString\", \"id\": \"k\", \"password\": true},\n\t],\n\t\"servers\": {\n\t\t// GitHub\n\t\t\"github\": {\n\t\t\t\"type\": \"http\",\n\t\t\t\"url\": \"https://api.githubcopilot.com/mcp/\",\n\t\t},\n\t},\n}\n";
    full_cycle(&env, Host::Vscode, Scope::Project, vscode, &["// Workspace MCP servers", "// GitHub", "\"inputs\""]);
    let p = plan_in(&env, Host::Vscode, Scope::Project, &entry()).unwrap();
    assert!(p.after.contains("\t\t\"aipass\": {\n\t\t\t\"type\": \"stdio\""), "{}", p.after);
    assert!(matches!(
        plan_in(&env, Host::Vscode, Scope::User, &entry()),
        Err(HostConfigError::UnsupportedScope { .. })
    ));
}

#[test]
fn missing_files_are_created_and_remove_leaves_empty_config() {
    let home = tempfile::tempdir().unwrap();
    let env = HostEnv::with_home(home.path());
    for host in [Host::Cursor, Host::Windsurf, Host::ClaudeCode] {
        let plan = plan_in(&env, host, Scope::User, &entry()).unwrap();
        assert_eq!(plan.action, PlanAction::Create);
        assert!(plan.unified_diff.starts_with("--- /dev/null"));
        let out = apply(&plan).unwrap();
        assert!(out.backup_path.is_none());
        let text = std::fs::read_to_string(&plan.path).unwrap();
        let v: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(v["mcpServers"]["aipass"]["args"][2], CONN);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&plan.path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        remove_in(&env, host, Scope::User).unwrap();
        assert_eq!(std::fs::read_to_string(&plan.path).unwrap(), "{}\n");
    }
    let plan = plan_in(&env, Host::Codex, Scope::User, &entry()).unwrap();
    apply(&plan).unwrap();
    remove_in(&env, Host::Codex, Scope::User).unwrap();
    assert_eq!(std::fs::read_to_string(&plan.path).unwrap(), "");
    // project scope without a project directory
    assert!(matches!(
        plan_in(&env, Host::ClaudeCode, Scope::Project, &entry()),
        Err(HostConfigError::NoProjectDir)
    ));
    let st = detect_in(&env, &DetectOptions { probe_versions: false, ..Default::default() });
    let vs = st.iter().find(|s| s.host == Host::Vscode).unwrap();
    assert!(vs.config_path.is_none());
    assert!(st.iter().any(|s| s.host == Host::Chatgpt && s.config_path.is_none()));
}

#[test]
fn concurrent_change_parse_errors_and_permissions() {
    let home = tempfile::tempdir().unwrap();
    let env = HostEnv::with_home(home.path());
    let (path, _) = config_location(&env, Host::Cursor, Scope::User).unwrap();
    write(&path, "{\"mcpServers\": {}}\n");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
    }
    let plan = plan_in(&env, Host::Cursor, Scope::User, &entry()).unwrap();
    write(&path, "{\"mcpServers\": {\"new\": {}}}\n");
    assert!(matches!(apply(&plan), Err(HostConfigError::ConcurrentModification { .. })));
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "{\"mcpServers\": {\"new\": {}}}\n");
    let plan = plan_in(&env, Host::Cursor, Scope::User, &entry()).unwrap();
    apply(&plan).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o640, "permissions are preserved");
    }
    // broken JSON is reported, never rewritten
    write(&path, "{\n  \"mcpServers\": {\n    \"x\": nope\n  }\n}\n");
    match plan_in(&env, Host::Cursor, Scope::User, &entry()) {
        Err(HostConfigError::Parse { line, .. }) => assert_eq!(line, 3),
        other => panic!("{other:?}"),
    }
    let st = detect_in(&env, &DetectOptions { probe_versions: false, ..Default::default() });
    assert!(st.iter().find(|s| s.host == Host::Cursor && s.scope == Some(Scope::User)).unwrap().config_error.is_some());
    // secrets are refused
    assert!(McpEntry::new("/opt/aipass-mcp", vec!["stdio".into(), "--broker".into(), "https://user:pw@node.example".into()]).is_err());
}

#[cfg(unix)]
#[test]
fn symlinked_config_is_written_through() {
    let home = tempfile::tempdir().unwrap();
    let env = HostEnv::with_home(home.path());
    let dotfiles = home.path().join("dotfiles");
    std::fs::create_dir_all(&dotfiles).unwrap();
    let target = dotfiles.join("claude.json");
    std::fs::write(&target, "{\"theme\": \"light\"}\n").unwrap();
    let link = home.path().join(".claude.json");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    let plan = plan_in(&env, Host::ClaudeCode, Scope::User, &entry()).unwrap();
    apply(&plan).unwrap();
    assert!(std::fs::symlink_metadata(&link).unwrap().file_type().is_symlink(), "symlink kept");
    assert!(std::fs::read_to_string(&target).unwrap().contains(CONN));
    remove_in(&env, Host::ClaudeCode, Scope::User).unwrap();
    assert_eq!(std::fs::read_to_string(&target).unwrap(), "{\"theme\": \"light\"}\n");
}

#[cfg(unix)]
#[test]
fn version_probe_with_timeout() {
    use std::os::unix::fs::PermissionsExt;
    let home = tempfile::tempdir().unwrap();
    let bin = home.path().join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    let mk = |name: &str, body: &str| {
        let p = bin.join(name);
        std::fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    };
    mk("codex", "echo 'codex-cli 0.98.0'");
    mk("claude", "echo '2.1.300 (Claude Code)'");
    mk("cursor", "sleep 30");
    let mut env = HostEnv::with_home(home.path());
    env.path_var = Some(bin.as_os_str().to_owned());
    let started = Instant::now();
    let st = detect_in(&env, &DetectOptions { probe_versions: true, timeout: Duration::from_secs(2), include_remote: false });
    assert!(started.elapsed() < Duration::from_secs(10), "probes run in parallel and time out");
    let get = |h: Host| st.iter().find(|s| s.host == h).unwrap().clone();
    assert_eq!(get(Host::Codex).version.as_deref(), Some("0.98.0"));
    assert!(get(Host::Codex).installed);
    assert_eq!(get(Host::Codex).label, CompatLabel::StandardProtocol, "verified list is empty");
    let cc = get(Host::ClaudeCode);
    assert_eq!(cc.version.as_deref(), Some("2.1.300"), "{cc:?}");
    assert!(get(Host::Cursor).installed);
    assert_eq!(get(Host::Cursor).version, None, "hung --version is killed");
    assert!(!get(Host::Windsurf).installed);
    assert!(!st.iter().any(|s| s.host.is_remote()));
}

#[test]
fn remove_plan_without_file_is_unchanged() {
    let home = tempfile::tempdir().unwrap();
    let env = HostEnv::with_home(home.path());
    let p = plan_remove_in(&env, Host::Windsurf, Scope::User).unwrap();
    assert_eq!(p.action, PlanAction::Unchanged);
    assert!(!apply(&p).unwrap().changed);
    assert!(!p.path.exists());
    // Debug output never contains file contents
    write(&p.path, "{\"mcpServers\": {\"x\": {\"env\": {\"TOKEN\": \"ghp_abcdefghijklmnopqrstuvwxyz0123\"}}}}");
    let plan = plan_in(&env, Host::Windsurf, Scope::User, &entry()).unwrap();
    let dbg = format!("{plan:?}");
    assert!(!dbg.contains("ghp_"), "{dbg}");
    assert!(!plan.unified_diff.contains("ghp_abcdefghijklmnopqrstuvwxyz0123"));
}
