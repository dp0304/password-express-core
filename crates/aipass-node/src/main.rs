// SPDX-License-Identifier: Apache-2.0
//! `aipass-node` — self-host node binary.

use std::path::PathBuf;
use std::time::Duration;

use aipass_node::config::NodeConfig;
use aipass_node::{NodeIdentity, pair};
use anyhow::{Context, bail};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "aipass-node", version, about = "AI 通行证自托管节点 / AI Pass self-host node")]
struct Cli {
    /// Configuration file.
    #[arg(long, short, global = true, env = "AIPASS_NODE_CONFIG", default_value = "node.toml")]
    config: PathBuf,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Write an example configuration file.
    Init {
        /// Node display name.
        #[arg(long, default_value = "my-node")]
        name: String,
        /// Data directory.
        #[arg(long)]
        data_dir: Option<PathBuf>,
        /// Listen address.
        #[arg(long)]
        listen: Option<String>,
        /// Overwrite an existing file.
        #[arg(long)]
        force: bool,
    },
    /// Validate the configuration.
    CheckConfig,
    /// Query `/v1/health` of a running node (container health checks).
    Health {
        /// Base URL (default: loopback of node.listen).
        #[arg(long)]
        url: Option<String>,
    },
    /// Run the node (broker, executor, sync, relay, /mcp).
    Run,
    /// Pair this node as an executor with a trusted device (node must be running).
    Pair {
        /// Relay base URL to use (default: config).
        #[arg(long)]
        relay: Option<String>,
        /// Admin URL of the running node (default: loopback of node.listen).
        #[arg(long)]
        admin_url: Option<String>,
        /// Do not print the QR code.
        #[arg(long)]
        no_qr: bool,
        /// Seconds to wait for each step.
        #[arg(long, default_value_t = 600)]
        timeout_secs: u64,
    },
    /// Show this node's executor id and public keys.
    Identity,
    /// Enroll tokens for creating vaults on this node's sync server.
    #[command(subcommand)]
    EnrollToken(EnrollCmd),
    /// Remote MCP connections with node-issued bearer tokens.
    #[command(subcommand)]
    Connection(ConnCmd),
    /// Optional link to the commercial cloud gateway.
    #[command(subcommand)]
    Cloud(CloudCmd),
}

#[derive(Subcommand)]
enum EnrollCmd {
    /// Create a token (printed once).
    Create {
        /// Number of vaults it may create.
        #[arg(long, default_value_t = 1)]
        uses: u32,
        /// Lifetime in hours.
        #[arg(long, default_value_t = 24)]
        ttl_hours: i64,
    },
    /// List stored tokens (hash prefixes only).
    List,
}

#[derive(Subcommand)]
enum ConnCmd {
    /// Create an active remote connection and print its bearer token once.
    Create {
        /// Label (never identity).
        #[arg(long)]
        name: String,
        /// Host type (chatgpt, claude_connector, custom, …).
        #[arg(long, default_value = "custom")]
        host: String,
        /// Allowed projects (`*` or proj_… ids, comma-separated).
        #[arg(long, default_value = "*")]
        projects: String,
        /// Admin URL of the running node.
        #[arg(long)]
        admin_url: Option<String>,
    },
}

#[derive(Subcommand)]
enum CloudCmd {
    /// Link with a one-time code from the cloud console.
    Link {
        /// Link code.
        #[arg(long)]
        code: String,
        /// Cloud base URL (default: config cloud.url).
        #[arg(long)]
        cloud: Option<String>,
    },
    /// Show link status.
    Status,
    /// Forget the link (the tunnel stops at the next restart).
    Unlink,
}

fn init_logging(cfg: Option<&NodeConfig>) {
    let filter = std::env::var("AIPASS_LOG").ok().or_else(|| cfg.map(|c| c.log.filter.clone())).unwrap_or_else(|| "info".into());
    let env = tracing_subscriber::EnvFilter::try_new(filter).unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let json = cfg.is_some_and(|c| c.log.format == "json");
    let b = tracing_subscriber::fmt().with_env_filter(env).with_writer(std::io::stderr).with_target(false);
    if json {
        b.json().init();
    } else {
        b.init();
    }
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    match real_main(cli).await {
        Ok(()) => {}
        Err(e) => {
            eprintln!("aipass-node: {e:#}");
            std::process::exit(1);
        }
    }
}

async fn real_main(cli: Cli) -> anyhow::Result<()> {
    if let Cmd::Init { name, data_dir, listen, force } = &cli.cmd {
        if cli.config.exists() && !force {
            bail!("{} exists (use --force)", cli.config.display());
        }
        let mut text = NodeConfig::example_toml().replace("name = \"my-node\"", &format!("name = {}", toml_str(name)));
        if let Some(d) = data_dir {
            text = text.replace("data_dir = \"/var/lib/aipass\"", &format!("data_dir = {}", toml_str(&d.display().to_string())));
        }
        if let Some(l) = listen {
            text = text.replace("listen = \"127.0.0.1:7878\"", &format!("listen = {}", toml_str(l)));
        }
        let cfg: NodeConfig = toml::from_str(&text)?;
        cfg.validate()?;
        std::fs::write(&cli.config, text)?;
        println!("wrote {}", cli.config.display());
        return Ok(());
    }
    let cfg = NodeConfig::load(&cli.config)?;
    init_logging(Some(&cfg));
    match cli.cmd {
        Cmd::Init { .. } => unreachable_init(),
        Cmd::CheckConfig => {
            println!("ok: {}", cli.config.display());
            Ok(())
        }
        Cmd::Run => run(cfg).await,
        Cmd::Health { url } => {
            let base = match url {
                Some(u) => u,
                None => cfg.loopback_url()?,
            };
            let r = reqwest::Client::builder()
                .timeout(Duration::from_secs(3))
                .build()?
                .get(format!("{}/v1/health", base.trim_end_matches('/')))
                .send()
                .await
                .context("node unreachable")?;
            let v: serde_json::Value = r.json().await.context("unexpected health response")?;
            println!("{v}");
            if v.get("status").and_then(|s| s.as_str()) != Some("ok") {
                bail!("node unhealthy");
            }
            Ok(())
        }
        Cmd::Pair { relay, admin_url, no_qr, timeout_secs } => {
            pair::run_pairing(
                &cfg,
                pair::PairOptions { relay_url: relay, admin_url, timeout: Duration::from_secs(timeout_secs), show_qr: !no_qr },
            )
            .await?;
            Ok(())
        }
        Cmd::Identity => {
            let id = NodeIdentity::load_or_create(&cfg.node.data_dir)?;
            let pk = id.identity.public();
            println!("executor_id: {}", id.executor_id);
            println!("member_device_id: {}", id.member_device_id());
            println!("sign_pk: {}", aipass_crypto::b64u::encode(pk.sign_pk));
            println!("kem_pk: {}", aipass_crypto::b64u::encode(pk.kem_pk));
            Ok(())
        }
        Cmd::EnrollToken(EnrollCmd::Create { uses, ttl_hours }) => {
            aipass_node::fsutil::private_dir(&cfg.node.data_dir)?;
            let adm = aipass_node::enroll::FileEnrollAdmission::new(&cfg.node.data_dir);
            let tok = adm.create(uses, Some(ttl_hours.clamp(1, 24 * 30) * 3600))?;
            eprintln!("注册令牌仅显示一次 / the enroll token is shown only once:");
            println!("{}", tok.expose());
            Ok(())
        }
        Cmd::EnrollToken(EnrollCmd::List) => {
            let adm = aipass_node::enroll::FileEnrollAdmission::new(&cfg.node.data_dir);
            for t in adm.list()? {
                println!(
                    "{}…  uses_left={}  expires={}  vaults={}",
                    &t.hash[..8.min(t.hash.len())],
                    t.uses_left,
                    t.expires_at.map(|e| aipass_types::time::format_rfc3339(&e)).unwrap_or_else(|| "-".into()),
                    t.vaults.len()
                );
            }
            Ok(())
        }
        Cmd::Connection(ConnCmd::Create { name, host, projects, admin_url }) => {
            let admin = pair::admin_client(&cfg, admin_url.as_deref())?;
            let allowed: serde_json::Value = if projects.trim() == "*" {
                serde_json::json!(["*"])
            } else {
                serde_json::json!(projects.split(',').map(str::trim).filter(|s| !s.is_empty()).collect::<Vec<_>>())
            };
            let body = serde_json::json!({
                "host_type": host, "display_name": name, "transport": "remote_gateway", "allowed_projects": allowed,
            });
            let v: serde_json::Value = admin.post_json("/v1/admin/connections", &body).await.map_err(|e| anyhow::anyhow!("{e}"))?;
            let cid = v.pointer("/connection/connection_id").and_then(|x| x.as_str()).unwrap_or("?");
            println!("connection_id: {cid}");
            println!("mcp_url: {}/mcp", cfg.base_url());
            if let Some(t) = v.get("token").and_then(|x| x.as_str()) {
                eprintln!("令牌仅显示一次，请保存到 AI 客户端 / the bearer token is shown only once:");
                println!("token: {t}");
            }
            Ok(())
        }
        Cmd::Cloud(CloudCmd::Link { code, cloud }) => {
            let id = NodeIdentity::load_or_create(&cfg.node.data_dir)?;
            let url = cloud.unwrap_or_else(|| cfg.cloud.url.clone());
            let link = aipass_node::cloud::link(&url, &code, &cfg.node.data_dir, &id, &cfg.node.name, cfg.executor.protection_level).await?;
            println!("linked: node_id={} cloud={} (restart `aipass-node run` to open the tunnel)", link.node_id, link.cloud_url);
            Ok(())
        }
        Cmd::Cloud(CloudCmd::Status) => {
            match aipass_node::cloud::CloudLink::load(&cfg.node.data_dir)? {
                Some(l) => println!("linked: node_id={} cloud={} since {}", l.node_id, l.cloud_url, aipass_types::time::format_rfc3339(&l.linked_at)),
                None => println!("not linked"),
            }
            Ok(())
        }
        Cmd::Cloud(CloudCmd::Unlink) => {
            let p = aipass_node::cloud::CloudLink::path(&cfg.node.data_dir);
            match std::fs::remove_file(&p) {
                Ok(()) => println!("unlinked (also remove the node in the cloud console)"),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => println!("not linked"),
                Err(e) => return Err(e).context("cannot remove cloud.json"),
            }
            Ok(())
        }
    }
}

fn unreachable_init() -> anyhow::Result<()> {
    bail!("init handled earlier")
}

fn toml_str(s: &str) -> String {
    toml::Value::String(s.to_string()).to_string()
}

async fn run(cfg: NodeConfig) -> anyhow::Result<()> {
    let node = aipass_node::start(cfg, aipass_node::StartOptions::default()).await?;
    wait_for_signal().await;
    tracing::info!("shutting down");
    node.shutdown().await;
    Ok(())
}

async fn wait_for_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut term = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
                return;
            }
        };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {},
            _ = term.recv() => {},
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
