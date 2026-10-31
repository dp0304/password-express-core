// SPDX-License-Identifier: Apache-2.0
//! `node.toml` — the node's configuration file (see `deploy/node.example.toml`).

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use aipass_types::models::ProtectionLevel;
use serde::{Deserialize, Serialize};
use url::Url;

/// Default listen address (CONTRACTS §1.7, dev value; containers use `0.0.0.0:7878`).
pub const DEFAULT_LISTEN: &str = "127.0.0.1:7878";

/// Whole configuration file.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeConfig {
    /// `[node]`.
    pub node: NodeSection,
    /// `[executor]`.
    #[serde(default)]
    pub executor: ExecutorSection,
    /// `[sync]`.
    #[serde(default)]
    pub sync: SyncSection,
    /// `[relay]`.
    #[serde(default)]
    pub relay: RelaySection,
    /// `[mcp]`.
    #[serde(default)]
    pub mcp: McpSection,
    /// `[cloud]`.
    #[serde(default)]
    pub cloud: CloudSection,
    /// `[log]`.
    #[serde(default)]
    pub log: LogSection,
}

/// `[node]`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeSection {
    /// Display name shown on approval cards ("执行设备").
    pub name: String,
    /// Data directory (keys, broker.db, sync blobs, relay.db). Created 0700.
    pub data_dir: PathBuf,
    /// TCP listen address.
    #[serde(default = "default_listen")]
    pub listen: String,
    /// Public base URL as clients reach it (behind the TLS proxy), e.g.
    /// `https://node.example.com`. Used in pairing links and MCP metadata.
    #[serde(default)]
    pub public_url: Option<String>,
    /// Optional Unix socket for local administration (0600, admin for the same uid).
    #[serde(default)]
    pub admin_socket: Option<PathBuf>,
    /// Enable V1.1 experimental features (off by default).
    #[serde(default)]
    pub experimental: bool,
    /// TLS is terminated by a reverse proxy (Caddy / nginx); the node itself serves plain
    /// HTTP. Set to `true` to acknowledge a non-loopback listen without TLS in front is
    /// intentional (e.g. inside a private network). Default false: the node warns.
    #[serde(default)]
    pub tls_terminated_by_proxy: bool,
}

/// `[executor]`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutorSection {
    /// Run the embedded executor (default true).
    #[serde(default = "yes")]
    pub enabled: bool,
    /// `compatible` (default) or `isolated`.
    #[serde(default = "default_level")]
    pub protection_level: ProtectionLevel,
    /// Required for `isolated`: the operator's statement of how the executor host is
    /// separated from the AI agents' machines (shown in health / docs, never invented).
    #[serde(default)]
    pub isolation_attestation: Option<String>,
    /// Extra PEM root certificates (private CAs for GitHub Enterprise / internal APIs).
    #[serde(default)]
    pub extra_root_certs: Option<PathBuf>,
}

/// `[sync]` — ciphertext sync server (`/v1/vaults*`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyncSection {
    /// Serve the sync API (default true).
    #[serde(default = "yes")]
    pub enabled: bool,
    /// Per-vault quota in bytes (none = unlimited).
    #[serde(default)]
    pub quota_bytes_per_vault: Option<u64>,
}

/// `[relay]` — E2E relay mailboxes (`/v1/relay*`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelaySection {
    /// Serve the relay on this node (default true).
    #[serde(default = "yes")]
    pub enabled: bool,
    /// Relay the broker uses to reach trusted devices. Default: this node's own relay.
    /// Set to the official cloud (`https://cloud.aipass.example`) to use its relay + push.
    #[serde(default)]
    pub url: Option<String>,
    /// Optional push webhook (receives only `{mailbox, message_id}`), https or loopback.
    #[serde(default)]
    pub webhook_url: Option<String>,
    /// File holding the webhook HMAC secret.
    #[serde(default)]
    pub webhook_secret_file: Option<PathBuf>,
}

/// `[mcp]` — remote MCP endpoint `/mcp` with node-issued `aipc_` bearer tokens.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpSection {
    /// Serve `/mcp` (default true).
    #[serde(default = "yes")]
    pub enabled: bool,
    /// Browser `Origin`s allowed to call `/mcp` (exact match). Empty = none.
    #[serde(default)]
    pub allowed_origins: Vec<String>,
}

/// `[cloud]`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudSection {
    /// Cloud base URL used by `aipass-node cloud link`.
    #[serde(default = "default_cloud")]
    pub url: String,
    /// Keep the outbound tunnel to the cloud open once linked (default true).
    #[serde(default = "yes")]
    pub tunnel: bool,
}

/// `[log]`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogSection {
    /// `text` or `json`.
    #[serde(default = "default_log_format")]
    pub format: String,
    /// tracing filter (overridden by `AIPASS_LOG`).
    #[serde(default = "default_log_filter")]
    pub filter: String,
}

fn yes() -> bool {
    true
}
fn default_listen() -> String {
    DEFAULT_LISTEN.into()
}
fn default_level() -> ProtectionLevel {
    ProtectionLevel::Compatible
}
fn default_cloud() -> String {
    std::env::var(aipass_client::home::ENV_CLOUD_URL)
        .unwrap_or_else(|_| aipass_client::home::DEFAULT_CLOUD_URL.to_string())
}
fn default_log_format() -> String {
    "text".into()
}
fn default_log_filter() -> String {
    "info".into()
}

impl Default for ExecutorSection {
    fn default() -> Self {
        Self {
            enabled: true,
            protection_level: ProtectionLevel::Compatible,
            isolation_attestation: None,
            extra_root_certs: None,
        }
    }
}
impl Default for SyncSection {
    fn default() -> Self {
        Self { enabled: true, quota_bytes_per_vault: None }
    }
}
impl Default for RelaySection {
    fn default() -> Self {
        Self { enabled: true, url: None, webhook_url: None, webhook_secret_file: None }
    }
}
impl Default for McpSection {
    fn default() -> Self {
        Self { enabled: true, allowed_origins: Vec::new() }
    }
}
impl Default for CloudSection {
    fn default() -> Self {
        Self { url: default_cloud(), tunnel: true }
    }
}
impl Default for LogSection {
    fn default() -> Self {
        Self { format: default_log_format(), filter: default_log_filter() }
    }
}

impl NodeConfig {
    /// A configuration with defaults for `data_dir`.
    pub fn new(name: impl Into<String>, data_dir: impl Into<PathBuf>) -> Self {
        Self {
            node: NodeSection {
                name: name.into(),
                data_dir: data_dir.into(),
                listen: default_listen(),
                public_url: None,
                admin_socket: None,
                experimental: false,
                tls_terminated_by_proxy: false,
            },
            executor: ExecutorSection::default(),
            sync: SyncSection::default(),
            relay: RelaySection::default(),
            mcp: McpSection::default(),
            cloud: CloudSection::default(),
            log: LogSection::default(),
        }
    }

    /// Load and validate a TOML file. Relative `data_dir` is resolved against the file.
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("cannot read config {}", path.display()))?;
        let mut cfg: NodeConfig =
            toml::from_str(&text).with_context(|| format!("invalid config {}", path.display()))?;
        if cfg.node.data_dir.is_relative()
            && let Some(dir) = path.parent()
        {
            cfg.node.data_dir = dir.join(&cfg.node.data_dir);
        }
        cfg.validate()?;
        Ok(cfg)
    }

    /// Check consistency (fail closed on anything ambiguous).
    pub fn validate(&self) -> anyhow::Result<()> {
        let name = self.node.name.trim();
        if name.is_empty() || name.chars().count() > 64 || name.chars().any(char::is_control) {
            bail!("node.name must be 1..64 printable characters");
        }
        self.listen_addr()?;
        if let Some(u) = &self.node.public_url {
            let u = Url::parse(u).context("node.public_url is not a URL")?;
            if !matches!(u.scheme(), "https" | "http") || u.query().is_some() {
                bail!("node.public_url must be an http(s) base URL without query");
            }
        }
        if self.executor.protection_level == ProtectionLevel::Isolated
            && self.executor.isolation_attestation.as_deref().map(str::trim).unwrap_or("").is_empty()
        {
            bail!(
                "executor.protection_level = \"isolated\" requires executor.isolation_attestation: \
                 describe how this host is separated from the machines running AI agents \
                 (隔离执行需要运维者说明执行主机如何与 AI 所在机器隔离)"
            );
        }
        if let Some(u) = &self.relay.url {
            Url::parse(u).context("relay.url is not a URL")?;
        }
        if !self.relay.enabled && self.relay.url.is_none() {
            bail!("relay.enabled = false requires relay.url (the broker must reach trusted devices)");
        }
        Url::parse(&self.cloud.url).context("cloud.url is not a URL")?;
        if !matches!(self.log.format.as_str(), "text" | "json") {
            bail!("log.format must be \"text\" or \"json\"");
        }
        Ok(())
    }

    /// Parsed listen address.
    pub fn listen_addr(&self) -> anyhow::Result<SocketAddr> {
        self.node.listen.parse().with_context(|| format!("node.listen {:?} is not host:port", self.node.listen))
    }

    /// Base URL clients use to reach this node.
    pub fn base_url(&self) -> String {
        if let Some(u) = &self.node.public_url {
            return u.trim_end_matches('/').to_string();
        }
        let addr = self.node.listen.replace("0.0.0.0", "127.0.0.1").replace("[::]", "[::1]");
        format!("http://{addr}")
    }

    /// Loopback URL of this node's own HTTP listener (for in-node clients).
    pub fn loopback_url(&self) -> anyhow::Result<String> {
        let addr = self.listen_addr()?;
        let port = addr.port();
        Ok(if addr.is_ipv6() { format!("http://[::1]:{port}") } else { format!("http://127.0.0.1:{port}") })
    }

    /// Relay base URL the broker and pairing use.
    pub fn relay_url(&self) -> String {
        self.relay.url.clone().map(|u| u.trim_end_matches('/').to_string()).unwrap_or_else(|| self.base_url())
    }

    /// Broker data directory.
    pub fn broker_dir(&self) -> PathBuf {
        self.node.data_dir.join("broker")
    }

    /// Admin token file (`<data>/broker/admin.token`, 0600).
    pub fn admin_token_path(&self) -> PathBuf {
        self.broker_dir().join(aipass_broker::config::ADMIN_TOKEN_FILE)
    }

    /// Render a commented example file.
    pub fn example_toml() -> &'static str {
        include_str!("../node.example.toml")
    }
}

/// True for `http://127.0.0.1…`, `http://localhost…`, `http://[::1]…`.
pub fn is_loopback_url(u: &Url) -> bool {
    match u.host() {
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        Some(url::Host::Domain(d)) => d == "localhost",
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn example_parses_and_validates() {
        let cfg: NodeConfig = toml::from_str(NodeConfig::example_toml()).expect("example parses");
        cfg.validate().expect("example validates");
        assert_eq!(cfg.executor.protection_level, ProtectionLevel::Compatible);
    }

    #[test]
    fn isolated_requires_attestation() {
        let mut cfg = NodeConfig::new("n", "/tmp/x");
        cfg.executor.protection_level = ProtectionLevel::Isolated;
        assert!(cfg.validate().is_err());
        cfg.executor.isolation_attestation = Some("dedicated VM on a separate host".into());
        cfg.validate().expect("attested");
    }

    #[test]
    fn unknown_keys_rejected() {
        let t = "[node]\nname='n'\ndata_dir='/x'\nbogus=1\n";
        assert!(toml::from_str::<NodeConfig>(t).is_err());
    }

    #[test]
    fn urls() {
        let mut cfg = NodeConfig::new("n", "/x");
        cfg.node.listen = "0.0.0.0:7878".into();
        assert_eq!(cfg.base_url(), "http://127.0.0.1:7878");
        assert_eq!(cfg.relay_url(), "http://127.0.0.1:7878");
        cfg.node.public_url = Some("https://node.example.com/".into());
        assert_eq!(cfg.relay_url(), "https://node.example.com");
    }
}
