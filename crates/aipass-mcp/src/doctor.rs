// SPDX-License-Identifier: Apache-2.0
//! `aipass-mcp doctor`: broker reachability, pairing status, connection keys and host config
//! presence. **Never prints secrets** — key files are reported by path, permission bits and a
//! public-key fingerprint only.

use std::path::Path;
use std::time::Duration;

use aipass_client::endpoint::{BrokerUrlSource, ResolveInputs, resolve_broker};
use aipass_client::keys::check_key_file;
use aipass_client::{AipassHome, BrokerClient, ClientError, KeyStore};
use aipass_hostconfig::{DetectOptions, HostEnv, detect_in};
use aipass_types::models::ExecutorStatus;
use aipass_types::{ConnectionId, ErrorCode, Lang, Localized};
use serde::Serialize;

/// Check outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckStatus {
    /// Fine.
    Ok,
    /// Works, but needs attention.
    Warn,
    /// Broken.
    Fail,
    /// Informational.
    Info,
}

impl CheckStatus {
    fn tag(&self) -> &'static str {
        match self {
            CheckStatus::Ok => "[ OK ]",
            CheckStatus::Warn => "[WARN]",
            CheckStatus::Fail => "[FAIL]",
            CheckStatus::Info => "[INFO]",
        }
    }
}

/// One check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Check {
    /// Machine id.
    pub id: String,
    /// Status.
    pub status: CheckStatus,
    /// Message.
    pub message: Localized,
}

/// Inputs (explicit so tests and embedders control the environment).
#[derive(Debug, Clone)]
pub struct DoctorInputs {
    /// AI Pass home.
    pub home: AipassHome,
    /// `--broker`.
    pub broker_flag: Option<String>,
    /// `AIPASS_BROKER_URL`.
    pub broker_env: Option<String>,
    /// `--connection`.
    pub connection: Option<ConnectionId>,
    /// Host environment for config detection.
    pub host_env: HostEnv,
    /// Run `<tool> --version`.
    pub probe_versions: bool,
    /// Broker request timeout.
    pub timeout: Duration,
    /// Message language for broker errors.
    pub lang: Lang,
}

/// The report.
#[derive(Debug, Clone, Serialize)]
pub struct DoctorReport {
    /// Checks in order.
    pub checks: Vec<Check>,
}

impl DoctorReport {
    /// No failed check.
    pub fn ok(&self) -> bool {
        !self.checks.iter().any(|c| c.status == CheckStatus::Fail)
    }

    /// Human-readable text.
    pub fn render(&self, lang: Lang) -> String {
        let mut out = String::new();
        for c in &self.checks {
            out.push_str(c.status.tag());
            out.push(' ');
            out.push_str(c.message.get(lang));
            out.push('\n');
        }
        out.push_str(match (self.ok(), lang) {
            (true, Lang::ZhCn) => "\n检查完成：未发现阻塞问题。\n",
            (true, Lang::En) => "\nDone: no blocking problems found.\n",
            (false, Lang::ZhCn) => "\n检查完成：存在需要处理的问题（见 [FAIL]）。\n",
            (false, Lang::En) => "\nDone: some problems need attention (see [FAIL]).\n",
        });
        out
    }
}

fn check(id: &str, status: CheckStatus, zh: impl Into<String>, en: impl Into<String>) -> Check {
    Check {
        id: id.to_owned(),
        status,
        message: Localized::new(zh, en),
    }
}

fn is_executable(p: &Path) -> bool {
    let Ok(m) = std::fs::metadata(p) else { return false };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        m.is_file() && m.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        m.is_file()
    }
}

/// Run every check.
pub async fn run(inputs: &DoctorInputs) -> DoctorReport {
    let mut checks = Vec::new();
    let home = &inputs.home;
    checks.push(check(
        "home",
        CheckStatus::Info,
        format!("AI 通行证目录：{}", home.root().display()),
        format!("AI Pass home: {}", home.root().display()),
    ));

    // ---- connection keys -------------------------------------------------------------
    let store = KeyStore::new(home);
    let ids = store.list().unwrap_or_default();
    let mut stored = Vec::new();
    for id in &ids {
        let path = store.path_for(id);
        match check_key_file(&path) {
            Ok(c) if c.too_open => checks.push(check(
                "key_permissions",
                CheckStatus::Fail,
                format!("连接密钥 {} 的权限过宽（{:o}），请运行 chmod 600 {}", path.display(), c.mode.unwrap_or(0), path.display()),
                format!("Connection key {} is accessible by other users ({:o}); run chmod 600 {}", path.display(), c.mode.unwrap_or(0), path.display()),
            )),
            Ok(_) => {}
            Err(_) => checks.push(check(
                "key_permissions",
                CheckStatus::Warn,
                format!("无法读取 {}", path.display()),
                format!("Cannot read {}", path.display()),
            )),
        }
        stored.push(id.as_str().to_owned());
    }
    let key = match store.load_selected(inputs.connection.as_ref()) {
        Ok(k) => {
            checks.push(check(
                "connection_key",
                CheckStatus::Ok,
                format!(
                    "连接密钥：{}（{}，“{}”，公钥指纹 {}）",
                    k.connection_id(),
                    serde_json::to_value(k.meta().host_type).ok().and_then(|v| v.as_str().map(str::to_owned)).unwrap_or_default(),
                    k.meta().display_name,
                    k.fingerprint()
                ),
                format!(
                    "Connection key: {} ({}, “{}”, public key fingerprint {})",
                    k.connection_id(),
                    serde_json::to_value(k.meta().host_type).ok().and_then(|v| v.as_str().map(str::to_owned)).unwrap_or_default(),
                    k.meta().display_name,
                    k.fingerprint()
                ),
            ));
            Some(k)
        }
        Err(e) => {
            let dir = store.dir().display().to_string();
            let (zh, en) = if inputs.connection.is_none() && ids.is_empty() {
                (format!("尚未配对任何 AI 连接（{dir} 中没有连接密钥）"), format!("No AI connection is paired yet (no connection key in {dir})"))
            } else if inputs.connection.is_none() && ids.len() > 1 {
                (format!("已配对多个连接（{}），请用 --connection 指定", stored.join("、")), format!("Several connections are paired ({}); pass --connection", stored.join(", ")))
            } else {
                let m = match &e {
                    ClientError::Key(m) => m.clone(),
                    other => other.to_string(),
                };
                (format!("连接密钥不可用：{m}"), format!("Connection key unavailable: {m}"))
            };
            checks.push(check(
                "connection_key",
                CheckStatus::Fail,
                format!("{zh}。可运行 aipass-mcp pair --host <宿主> --name <名称> 配对。"),
                format!("{en}. Pair with: aipass-mcp pair --host <host> --name <label>."),
            ));
            None
        }
    };

    // ---- broker URL + reachability ---------------------------------------------------
    let resolved = resolve_broker(ResolveInputs {
        flag: inputs.broker_flag.as_deref(),
        env: inputs.broker_env.as_deref(),
        connection_key: key.as_ref().and_then(|k| k.meta().broker_url.as_deref()),
        home,
    });
    let resolved = match resolved {
        Ok(r) => r,
        Err(e) => {
            checks.push(check("broker_url", CheckStatus::Fail, format!("授权代理地址无效：{e}"), format!("Invalid broker URL: {e}")));
            return finish(checks, inputs, &stored);
        }
    };
    if let Err(e) = aipass_client::endpoint::check_key_broker(&resolved, key.as_ref().and_then(|k| k.meta().broker_url.as_deref())) {
        checks.push(check(
            "broker_mismatch",
            CheckStatus::Fail,
            format!("授权代理地址与连接配对时记录的不一致，桥接程序将拒绝签名：{e}"),
            format!("The broker differs from the one recorded when the connection was paired; the bridge refuses to sign: {e}"),
        ));
    }
    let src = match resolved.source {
        BrokerUrlSource::Flag => ("--broker 参数", "--broker flag"),
        BrokerUrlSource::Env => ("环境变量 AIPASS_BROKER_URL", "AIPASS_BROKER_URL"),
        BrokerUrlSource::ConnectionKey => ("配对时记录的地址", "address recorded at pairing"),
        BrokerUrlSource::BrokerJson => ("broker.json", "broker.json"),
        BrokerUrlSource::Default => ("默认本地套接字", "default local socket"),
    };
    checks.push(check(
        "broker_url",
        CheckStatus::Info,
        format!("授权代理地址：{}（来源：{}）", resolved.endpoint, src.0),
        format!("Broker URL: {} (from {})", resolved.endpoint, src.1),
    ));
    let client = match BrokerClient::builder(resolved.endpoint.clone())
        .timeout(inputs.timeout)
        .lang(inputs.lang)
        .user_agent(format!("aipass-mcp-doctor/{}", env!("CARGO_PKG_VERSION")))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            checks.push(check("broker_reachable", CheckStatus::Fail, format!("无法创建客户端：{e}"), format!("Cannot create the client: {e}")));
            return finish(checks, inputs, &stored);
        }
    };
    match client.health().await {
        Ok(h) => {
            let pl = h.protection_level.label();
            let (status, zh_exec, en_exec) = if h.executor_online {
                (CheckStatus::Ok, "执行设备在线", "executor online")
            } else {
                (CheckStatus::Warn, "执行设备离线", "executor offline")
            };
            checks.push(check(
                "broker_reachable",
                status,
                format!("授权代理可连接（版本 {}，{zh_exec}，{}）", h.version, pl.zh),
                format!("Broker reachable (version {}, {en_exec}, {})", h.version, pl.en),
            ));
        }
        Err(e) => {
            checks.push(check(
                "broker_reachable",
                CheckStatus::Fail,
                format!("无法连接授权代理：{e}。请确认桌面 App 或 aipass node 正在运行。"),
                format!("Cannot reach the broker: {e}. Make sure the desktop app or `aipass node` is running."),
            ));
            return finish(checks, inputs, &stored);
        }
    }

    // ---- pairing status (an authenticated, read-only call) --------------------------
    if let Some(k) = &key {
        let c = client.with_auth(k.auth());
        match c.list_resources(None, None).await {
            Ok(r) => {
                let offline = r.resources.iter().filter(|x| x.executor_status == ExecutorStatus::Offline).count();
                checks.push(check(
                    "pairing",
                    CheckStatus::Ok,
                    format!("连接已批准，可发现 {} 个资源{}", r.resources.len(), if offline > 0 { format!("（{offline} 个的执行设备离线）") } else { String::new() }),
                    format!("Connection approved; {} resource(s) visible{}", r.resources.len(), if offline > 0 { format!(" ({offline} with the executor offline)") } else { String::new() }),
                ));
            }
            Err(ClientError::Api(e)) if e.code == ErrorCode::IdentityUnverified => checks.push(check(
                "pairing",
                CheckStatus::Fail,
                "授权代理不认识此连接：可能尚未在手机或可信客户端批准，或已被移除。请重新运行 aipass-mcp pair。",
                "The broker does not recognise this connection: it may not be approved on a trusted device yet, or it was removed. Run aipass-mcp pair again.",
            )),
            Err(ClientError::Api(e)) if e.code == ErrorCode::ConnectionPaused => checks.push(check(
                "pairing",
                CheckStatus::Warn,
                "此 AI 连接已被暂停，可在 App 的“AI 连接”中恢复。",
                "This AI connection is paused; resume it under “AI connections” in the app.",
            )),
            Err(e) => checks.push(check(
                "pairing",
                CheckStatus::Warn,
                format!("无法确认配对状态：{}", e.to_api_error().message(Lang::ZhCn)),
                format!("Could not confirm the pairing status: {}", e.to_api_error().message(Lang::En)),
            )),
        }
    }
    finish(checks, inputs, &stored)
}

fn finish(mut checks: Vec<Check>, inputs: &DoctorInputs, stored: &[String]) -> DoctorReport {
    let statuses = detect_in(
        &inputs.host_env,
        &DetectOptions {
            probe_versions: inputs.probe_versions,
            timeout: Duration::from_secs(3),
            include_remote: false,
        },
    );
    let mut any = false;
    for s in statuses {
        let project = s.scope == Some(aipass_hostconfig::Scope::Project);
        if project && !s.has_aipass_entry && s.config_error.is_none() {
            continue; // project scopes are only reported when they hold our entry
        }
        let name = if project {
            format!("{}（project）", s.host.display_name())
        } else {
            s.host.display_name().to_owned()
        };
        let path = s.config_path.as_ref().map(|p| p.display().to_string()).unwrap_or_default();
        let label = s.label.label();
        let ver = s.version.as_deref().map(|v| format!(" {v}")).unwrap_or_default();
        if let Some(err) = &s.config_error {
            checks.push(check(
                "host_config",
                CheckStatus::Warn,
                format!("{name}{ver}：配置文件 {path} 无法解析（{err}），向导不会修改它"),
                format!("{name}{ver}: config {path} does not parse ({err}); the wizard will not touch it"),
            ));
            continue;
        }
        if s.has_aipass_entry {
            any = true;
            let mut problems_zh = Vec::new();
            let mut problems_en = Vec::new();
            match &s.existing_entry {
                Some(e) => {
                    if !is_executable(&e.command) {
                        problems_zh.push(format!("命令 {} 不存在或不可执行", e.command.display()));
                        problems_en.push(format!("command {} is missing or not executable", e.command.display()));
                    }
                    match e.connection_id() {
                        Some(c) if !stored.iter().any(|x| x == c) => {
                            problems_zh.push(format!("连接 {c} 在本机没有连接密钥"));
                            problems_en.push(format!("connection {c} has no key on this machine"));
                        }
                        None if stored.len() != 1 => {
                            problems_zh.push("未指定 --connection".to_owned());
                            problems_en.push("no --connection given".to_owned());
                        }
                        _ => {}
                    }
                }
                None => {
                    problems_zh.push("条目缺少 command".to_owned());
                    problems_en.push("entry has no command".to_owned());
                }
            }
            if problems_zh.is_empty() {
                checks.push(check(
                    "host_config",
                    CheckStatus::Ok,
                    format!("{name}{ver}：{path} 已配置 aipass（{}）", label.zh),
                    format!("{name}{ver}: aipass is configured in {path} ({})", label.en),
                ));
            } else {
                checks.push(check(
                    "host_config",
                    CheckStatus::Warn,
                    format!("{name}{ver}：{path} 中的 aipass 条目有问题：{}", problems_zh.join("；")),
                    format!("{name}{ver}: the aipass entry in {path} has problems: {}", problems_en.join("; ")),
                ));
            }
        } else if s.installed {
            checks.push(check(
                "host_config",
                CheckStatus::Info,
                format!("{name}{ver}：已安装，尚未配置 aipass（{}）", label.zh),
                format!("{name}{ver}: installed, aipass not configured ({})", label.en),
            ));
        }
    }
    if !any {
        checks.push(check(
            "host_config",
            CheckStatus::Info,
            "尚未在任何 AI 宿主中配置 aipass。配对时加 --configure 可写入配置（会先显示改动并保留备份）。",
            "aipass is not configured in any AI host yet. Add --configure when pairing to write it (the change is shown first and a backup is kept).",
        ));
    }
    DoctorReport { checks }
}
