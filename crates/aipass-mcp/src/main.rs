// SPDX-License-Identifier: Apache-2.0
//! `aipass-mcp` — the AI Pass MCP bridge.
//!
//! ```text
//! aipass-mcp stdio [--broker URL] [--connection ID] [--experimental]
//! aipass-mcp pair --host <host_type> --name <label> [--broker URL] [--configure]
//! aipass-mcp http [--listen 127.0.0.1:7879] [--broker URL] [--connection ID]
//! aipass-mcp doctor [--broker URL] [--connection ID] [--json]
//! ```
//!
//! In `stdio` mode stdout carries MCP messages only; every log line goes to stderr.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use aipass_client::api::UnavailableBroker;
use aipass_client::endpoint::{BrokerUrlSource, ResolveInputs, resolve_broker};
use aipass_client::pairing::{PairingOutcome, PairingRequest, start_pairing};
use aipass_client::{AipassHome, BrokerApi, BrokerClient, ClientError, KeyStore};
use aipass_hostconfig::{Host, HostEnv, McpEntry, PlanAction, Scope};
use aipass_mcp::http::{BrokerBearerResolver, HttpConfig, HttpMode, StreamableHttp, protected_resource_metadata};
use aipass_mcp::{McpContext, McpServer, McpServerConfig, doctor, stdio};
use aipass_types::models::{HostType, Transport};
use aipass_types::{ConnectionId, Lang};
use clap::{Args, Parser, Subcommand, ValueEnum};

#[derive(Parser)]
#[command(name = "aipass-mcp", version, about = "AI 通行证 MCP 接入桥 / AI Pass MCP bridge")]
struct Cli {
    /// 输出语言 / output language
    #[arg(long, global = true, value_enum, env = "AIPASS_LANG")]
    lang: Option<LangArg>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Clone, Copy, ValueEnum)]
enum LangArg {
    #[value(name = "zh-CN")]
    ZhCn,
    #[value(name = "en")]
    En,
}

#[derive(Subcommand)]
enum Command {
    /// 以 stdio 方式运行 MCP 服务器（由 AI 宿主启动）/ run the MCP server over stdio
    Stdio(ServeArgs),
    /// 为 AI 宿主配对一个新的连接 / pair a new AI host connection
    Pair(PairArgs),
    /// 以 Streamable HTTP 方式运行 / run the MCP server over Streamable HTTP
    Http(HttpArgs),
    /// 检查授权代理、配对和宿主配置 / check broker, pairing and host configs
    Doctor(DoctorArgs),
}

#[derive(Args, Clone)]
struct ServeArgs {
    /// 授权代理地址（unix:///… 或 http(s)://…）/ broker URL
    #[arg(long)]
    broker: Option<String>,
    /// 连接 ID（conn_…）/ connection id
    #[arg(long)]
    connection: Option<String>,
    /// 提供实验性工具（V1.1）/ offer experimental (V1.1) tools
    #[arg(long)]
    experimental: bool,
    /// 允许连接密钥为与配对时不同的授权代理签名（仅在代理确实迁移时使用）/ let the connection
    /// key sign for a broker other than the one it was paired with (only if the broker moved)
    #[arg(long)]
    allow_broker_mismatch: bool,
}

#[derive(Args)]
struct PairArgs {
    /// 宿主类型：codex、claude_code、cursor、chatgpt、claude_connector、sdk、custom（也可用 claude_desktop、vscode、windsurf）
    #[arg(long)]
    host: String,
    /// 显示名称（仅作标签，不代表身份）/ display label (not identity)
    #[arg(long)]
    name: String,
    /// 授权代理地址 / broker URL
    #[arg(long)]
    broker: Option<String>,
    /// 传输方式 / transport
    #[arg(long, value_enum, default_value = "stdio")]
    transport: TransportArg,
    /// 批准后把 aipass 条目写入该宿主的配置（先显示改动并保留备份）/ write the host config after approval
    #[arg(long)]
    configure: bool,
    /// 配置范围 / config scope
    #[arg(long, value_enum)]
    scope: Option<ScopeArg>,
    /// 项目目录（project 范围）/ project directory for the project scope
    #[arg(long)]
    project_dir: Option<PathBuf>,
}

#[derive(Clone, Copy, ValueEnum)]
enum TransportArg {
    Stdio,
    Http,
}

#[derive(Clone, Copy, ValueEnum)]
enum ScopeArg {
    User,
    Project,
}

#[derive(Args)]
struct HttpArgs {
    #[command(flatten)]
    serve: ServeArgs,
    /// 监听地址 / listen address
    #[arg(long, default_value = "127.0.0.1:7879")]
    listen: SocketAddr,
    /// 允许的 Origin（可重复）/ allowed Origin (repeatable)
    #[arg(long = "allow-origin")]
    allow_origin: Vec<String>,
    /// 远程模式：要求 Bearer aipc_ 连接令牌并转交授权代理验证 / remote mode (Bearer connection tokens)
    #[arg(long)]
    remote: bool,
    /// 远程模式的公开 MCP 地址（用于 WWW-Authenticate resource_metadata）/ public MCP URL in remote mode
    #[arg(long)]
    public_url: Option<String>,
    /// OAuth 授权服务器（可重复，写入受保护资源元数据）/ authorization server(s) for the metadata
    #[arg(long = "authorization-server")]
    authorization_servers: Vec<String>,
}

#[derive(Args)]
struct DoctorArgs {
    /// 授权代理地址 / broker URL
    #[arg(long)]
    broker: Option<String>,
    /// 连接 ID / connection id
    #[arg(long)]
    connection: Option<String>,
    /// 输出 JSON / JSON output
    #[arg(long)]
    json: bool,
    /// 不运行 `<宿主> --version` / do not run `<host> --version`
    #[arg(long)]
    no_probe: bool,
}

fn init_logging(default: &str) {
    let filter = tracing_subscriber::EnvFilter::try_from_env("AIPASS_LOG")
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(default));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .with_target(false)
        .try_init();
}

fn env_opt(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.trim().is_empty())
}

fn say(lang: Lang, zh: &str, en: &str) -> String {
    match lang {
        Lang::ZhCn => zh.to_owned(),
        Lang::En => en.to_owned(),
    }
}

/// Build the connection-bound broker API for `stdio` / local `http`. Failures become an
/// [`UnavailableBroker`] so the host gets actionable tool errors instead of a dead server.
fn connection_broker(home: &AipassHome, args: &ServeArgs, lang: Lang) -> Arc<dyn BrokerApi> {
    let conn = match args.connection.as_deref().map(ConnectionId::parse).transpose() {
        Ok(c) => c,
        Err(_) => {
            tracing::error!("--connection is not a connection id (conn_…)");
            return Arc::new(UnavailableBroker::new(ClientError::Key("invalid --connection".into()).to_api_error()));
        }
    };
    let key = match KeyStore::new(home).load_selected(conn.as_ref()) {
        Ok(k) => k,
        Err(e) => {
            tracing::error!(error = %e, "no usable connection key; tools will report IDENTITY_UNVERIFIED");
            return Arc::new(UnavailableBroker::new(e.to_api_error()));
        }
    };
    let env_url = env_opt(aipass_client::home::ENV_BROKER_URL);
    let resolved = match resolve_broker(ResolveInputs {
        flag: args.broker.as_deref(),
        env: env_url.as_deref(),
        connection_key: key.meta().broker_url.as_deref(),
        home,
    }) {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = %e, "broker URL resolution failed");
            return Arc::new(UnavailableBroker::new(e.to_api_error()));
        }
    };
    if !args.allow_broker_mismatch
        && let Err(e) = aipass_client::endpoint::check_key_broker(&resolved, key.meta().broker_url.as_deref())
    {
        tracing::error!(error = %e, "broker does not match the connection key; refusing to sign requests");
        return Arc::new(UnavailableBroker::new(e.to_api_error()));
    }
    tracing::info!(broker = %resolved.endpoint, source = resolved.source.as_str(), connection = %key.connection_id(), "bridge ready");
    match BrokerClient::builder(resolved.endpoint)
        .auth(key.auth())
        .lang(lang)
        .user_agent(format!("aipass-mcp/{}", env!("CARGO_PKG_VERSION")))
        .build()
    {
        Ok(c) => Arc::new(c),
        Err(e) => {
            tracing::error!(error = %e, "cannot create the broker client");
            Arc::new(UnavailableBroker::new(e.to_api_error()))
        }
    }
}

async fn cmd_stdio(home: AipassHome, args: ServeArgs, lang: Lang) -> ExitCode {
    let broker = connection_broker(&home, &args, lang);
    let server = Arc::new(McpServer::new(McpServerConfig {
        experimental: args.experimental,
        lang,
        ..Default::default()
    }));
    match stdio::run(server, McpContext::new(broker)).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!(error = %e, "stdio transport failed");
            ExitCode::FAILURE
        }
    }
}

fn parse_host_arg(s: &str) -> Option<(HostType, Option<Host>)> {
    let configurable = Host::parse(s).filter(|h| !h.is_remote());
    if let Ok(ht) = serde_json::from_value::<HostType>(serde_json::Value::String(s.to_owned())) {
        return Some((ht, configurable));
    }
    configurable.map(|h| (h.host_type(), Some(h)))
}

async fn cmd_pair(home: AipassHome, args: PairArgs, lang: Lang) -> ExitCode {
    let Some((host_type, config_host)) = parse_host_arg(&args.host) else {
        eprintln!("{}", say(lang,
            "--host 必须是 codex、claude_code、cursor、chatgpt、claude_connector、sdk、custom、claude_desktop、vscode 或 windsurf",
            "--host must be one of codex, claude_code, cursor, chatgpt, claude_connector, sdk, custom, claude_desktop, vscode, windsurf"));
        return ExitCode::from(2);
    };
    let env_url = env_opt(aipass_client::home::ENV_BROKER_URL);
    let resolved = match resolve_broker(ResolveInputs {
        flag: args.broker.as_deref(),
        env: env_url.as_deref(),
        connection_key: None,
        home: &home,
    }) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::FAILURE;
        }
    };
    let client = match BrokerClient::builder(resolved.endpoint.clone())
        .lang(lang)
        .user_agent(format!("aipass-mcp/{}", env!("CARGO_PKG_VERSION")))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::FAILURE;
        }
    };
    let pending = match start_pairing(
        &client,
        PairingRequest {
            host_type,
            display_name: args.name.clone(),
            transport: match args.transport {
                TransportArg::Stdio => Transport::Stdio,
                TransportArg::Http => Transport::Http,
            },
            record_broker_url: matches!(resolved.source, BrokerUrlSource::Flag | BrokerUrlSource::Env),
        },
    )
    .await
    {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{}", e.to_api_error().message(lang));
            eprintln!("({e})");
            return ExitCode::FAILURE;
        }
    };
    println!("{}", say(lang, "配对码 / Pairing code:", "Pairing code:"));
    println!();
    println!("    {}", pending.pairing_code());
    println!();
    // the connection id is unique to this request (a display name is only a self-declared
    // label anyone reaching the broker can copy): a CLI approver must approve this exact id
    println!("{} {}", say(lang, "连接 ID / Connection id:", "Connection id:"), pending.connection_id());
    println!("{}", say(lang,
        "在命令行可信设备上批准时，请使用上面的连接 ID 和配对码：aipass connections approve <连接 ID> --code <配对码> --projects <项目>",
        "To approve from a CLI trusted device, use exactly this id and code: aipass connections approve <id> --code <pairing code> --projects <projects>"));
    println!("{}", say(lang,
        "请在已配对的手机或桌面 App 中核对此配对码并批准此连接。显示名称只是标签，扫码或本命令都不能自行批准。",
        "Compare this code on your paired phone or desktop app and approve the connection there. The display name is only a label; nothing on this machine can approve it."));
    println!("{} {}", say(lang, "等待批准，截止", "Waiting for approval until"), aipass_types::time::format_rfc3339(&pending.response().expires_at));
    let store = KeyStore::new(&home);
    let outcome = tokio::select! {
        r = pending.wait(&store, aipass_client::pairing::DEFAULT_POLL_INTERVAL) => r,
        _ = tokio::signal::ctrl_c() => {
            eprintln!("{}", say(lang, "已取消，未保存任何密钥。", "Cancelled; no key was stored."));
            return ExitCode::from(130);
        }
    };
    let key = match outcome {
        Ok(PairingOutcome::Approved { key, path }) => {
            println!("{} {}", say(lang, "已批准。连接 ID：", "Approved. Connection id:"), key.connection_id());
            println!("{} {}", say(lang, "连接密钥已保存到", "Connection key stored at"), path.display());
            key
        }
        Ok(PairingOutcome::Denied) => {
            eprintln!("{}", say(lang, "此连接在可信设备上被拒绝。", "The connection was denied on the trusted device."));
            return ExitCode::FAILURE;
        }
        Ok(PairingOutcome::Expired) => {
            eprintln!("{}", say(lang, "配对已过期，未获批准。请重新运行。", "The pairing expired without approval. Run the command again."));
            return ExitCode::FAILURE;
        }
        Err(e) => {
            eprintln!("{}", e.to_api_error().message(lang));
            return ExitCode::FAILURE;
        }
    };
    let Some(host) = config_host else {
        println!("{}", say(lang,
            "此宿主通过远程 MCP 或 SDK 接入；本机没有需要修改的配置文件。",
            "This host connects through remote MCP or the SDK; there is no local config file to change."));
        return ExitCode::SUCCESS;
    };
    configure_host(host, &args, &key, lang)
}

fn configure_host(host: Host, args: &PairArgs, key: &aipass_client::ConnectionKey, lang: Lang) -> ExitCode {
    let exe = match std::env::current_exe().and_then(|p| p.canonicalize()) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("cannot determine the aipass-mcp path: {e}");
            return ExitCode::FAILURE;
        }
    };
    let mut entry = match McpEntry::stdio(&exe, key.connection_id()) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::FAILURE;
        }
    };
    if let Some(b) = args.broker.as_deref() {
        entry = match entry.with_broker(b) {
            Ok(e) => e,
            Err(e) => {
                eprintln!("{e}");
                return ExitCode::FAILURE;
            }
        };
    }
    let scope = match args.scope {
        Some(ScopeArg::User) => Scope::User,
        Some(ScopeArg::Project) => Scope::Project,
        None => host.default_scope(),
    };
    let mut env = match HostEnv::from_system() {
        Ok(e) => e,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::FAILURE;
        }
    };
    if let Some(d) = &args.project_dir {
        env.project_dir = Some(d.clone());
    }
    let plan = match aipass_hostconfig::plan_in(&env, host, scope, &entry) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::FAILURE;
        }
    };
    if host == Host::ClaudeCode
        && let Ok(cmd) = aipass_hostconfig::claude_mcp_add_command(scope, &entry)
    {
        println!("{}", say(lang, "也可以运行：", "Alternatively run:"));
        println!("    {cmd}");
    }
    if plan.action == PlanAction::Unchanged {
        println!("{} {}", say(lang, "配置已是最新：", "Config already up to date:"), plan.path.display());
        return ExitCode::SUCCESS;
    }
    println!("{} {}", say(lang, "将修改", "Planned change to"), plan.path.display());
    print!("{}", plan.unified_diff);
    if !args.configure {
        println!("{}", say(lang,
            "未写入任何文件。加 --configure 重新运行可写入上述改动（会先备份原文件，只修改 aipass 条目）。",
            "Nothing was written. Re-run with --configure to apply this change (the original is backed up and only the aipass entry is touched)."));
        return ExitCode::SUCCESS;
    }
    match aipass_hostconfig::apply(&plan) {
        Ok(out) => {
            println!("{} {}", say(lang, "已写入", "Written"), out.path.display());
            if let Some(b) = out.backup_path {
                println!("{} {}", say(lang, "备份：", "Backup:"), b.display());
            }
            println!("{}", say(lang,
                "请重启或刷新该 AI 宿主的 MCP 服务器，然后运行 aipass-mcp doctor 检查。",
                "Restart or reload the AI host's MCP servers, then run aipass-mcp doctor."));
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}

async fn cmd_http(home: AipassHome, args: HttpArgs, lang: Lang) -> ExitCode {
    let server = Arc::new(McpServer::new(McpServerConfig {
        experimental: args.serve.experimental,
        lang,
        ..Default::default()
    }));
    let mode = if args.remote {
        let Some(public) = args.public_url.clone() else {
            eprintln!("--remote requires --public-url https://…/mcp");
            return ExitCode::from(2);
        };
        let env_url = env_opt(aipass_client::home::ENV_BROKER_URL);
        let resolved = match resolve_broker(ResolveInputs {
            flag: args.serve.broker.as_deref(),
            env: env_url.as_deref(),
            connection_key: None,
            home: &home,
        }) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("{e}");
                return ExitCode::FAILURE;
            }
        };
        let client = match BrokerClient::builder(resolved.endpoint).lang(lang).build() {
            Ok(c) => c,
            Err(e) => {
                eprintln!("{e}");
                return ExitCode::FAILURE;
            }
        };
        let base = public.trim_end_matches('/').trim_end_matches("/mcp").to_owned();
        HttpMode::Remote {
            resolver: Arc::new(BrokerBearerResolver::new(client)),
            resource_metadata_url: format!("{base}/.well-known/oauth-protected-resource/mcp"),
            allowed_origins: args.allow_origin.clone(),
        }
    } else {
        if !args.listen.ip().is_loopback() {
            eprintln!("{}", say(lang,
                "本地模式只能监听回环地址（127.0.0.1 / ::1）；对外提供服务请使用 --remote。",
                "Local mode only listens on loopback (127.0.0.1 / ::1); use --remote to serve other machines."));
            return ExitCode::from(2);
        }
        HttpMode::Local {
            broker: connection_broker(&home, &args.serve, lang),
            allowed_origins: args.allow_origin.clone(),
            allowed_hosts: HttpConfig::loopback_hosts(args.listen.port()),
        }
    };
    let mut config = HttpConfig::new(mode);
    if args.remote
        && let Some(public) = &args.public_url
    {
        config.protected_resource_metadata = Some(protected_resource_metadata(public, &args.authorization_servers));
    }
    let transport = StreamableHttp::new(server, config);
    let listener = match tokio::net::TcpListener::bind(args.listen).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("cannot listen on {}: {e}", args.listen);
            return ExitCode::FAILURE;
        }
    };
    tracing::info!(listen = %args.listen, remote = args.remote, "Streamable HTTP MCP endpoint at /mcp");
    let app = transport.router();
    let res = axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await;
    match res {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!(error = %e, "HTTP server failed");
            ExitCode::FAILURE
        }
    }
}

async fn cmd_doctor(home: AipassHome, args: DoctorArgs, lang: Lang) -> ExitCode {
    let connection = match args.connection.as_deref().map(ConnectionId::parse).transpose() {
        Ok(c) => c,
        Err(_) => {
            eprintln!("--connection is not a connection id (conn_…)");
            return ExitCode::from(2);
        }
    };
    let host_env = match HostEnv::from_system() {
        Ok(e) => e,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::FAILURE;
        }
    };
    let report = doctor::run(&doctor::DoctorInputs {
        home,
        broker_flag: args.broker,
        broker_env: env_opt(aipass_client::home::ENV_BROKER_URL),
        connection,
        host_env,
        probe_versions: !args.no_probe,
        timeout: Duration::from_secs(5),
        lang,
    })
    .await;
    if args.json {
        println!("{}", serde_json::to_string_pretty(&report).unwrap_or_default());
    } else {
        print!("{}", report.render(lang));
    }
    if report.ok() { ExitCode::SUCCESS } else { ExitCode::FAILURE }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let lang = match cli.lang {
        Some(LangArg::En) => Lang::En,
        _ => Lang::ZhCn,
    };
    init_logging(match cli.command {
        Command::Http(_) => "info",
        _ => "warn",
    });
    let home = match AipassHome::from_env() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::FAILURE;
        }
    };
    let rt = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("cannot start the runtime: {e}");
            return ExitCode::FAILURE;
        }
    };
    rt.block_on(async move {
        match cli.command {
            Command::Stdio(a) => cmd_stdio(home, a, lang).await,
            Command::Pair(a) => cmd_pair(home, a, lang).await,
            Command::Http(a) => cmd_http(home, a, lang).await,
            Command::Doctor(a) => cmd_doctor(home, a, lang).await,
        }
    })
}
