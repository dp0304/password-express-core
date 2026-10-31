// SPDX-License-Identifier: Apache-2.0
//! Optional link to the commercial cloud gateway (CONTRACTS §13 "Nodes & tunnel").
//!
//! `aipass-node cloud link --code …` registers the node (signed `kid=exe_…`), then
//! `aipass-node run` keeps an outbound WebSocket tunnel open. The cloud is **not** an
//! E2E-blind relay for MCP: it sees the JSON-RPC of remote connections (design doc §4.3);
//! credentials never leave the node.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use aipass_broker::{Actor, Broker, BrokerEvent, PairingInput};
use aipass_client::tunnel::{
    ConnectionCreateFrame, ConnectionCreated, McpFrame, McpResponse, RemoteConnectionStatus, TunnelClient, TunnelConfig, TunnelHandle,
    TunnelHandler, TunnelSender, TunnelState,
};
use aipass_mcp::http::StreamableHttp;
use aipass_types::error::{ApiError, Lang};
use aipass_types::ids::{ConnectionId, ExecutorId};
use aipass_types::models::{ConnectionStatus, ProtectionLevel, Transport};
use aipass_types::relay::ControlAction;
use anyhow::{Context, bail};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::fsutil;
use crate::identity::NodeIdentity;

/// File recording the link (`<data>/cloud.json`).
pub const CLOUD_FILE: &str = "cloud.json";
/// Last org policy pushed by the cloud (`<data>/org-policy.json`).
pub const ORG_POLICY_FILE: &str = "org-policy.json";

/// Persisted link.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudLink {
    /// Cloud base URL.
    pub cloud_url: String,
    /// Node id the cloud assigned (normally our executor id).
    pub node_id: String,
    /// When linked.
    #[serde(with = "aipass_types::time::rfc3339")]
    pub linked_at: aipass_types::time::Timestamp,
}

impl CloudLink {
    /// Path of the link file.
    pub fn path(data_dir: &Path) -> PathBuf {
        data_dir.join(CLOUD_FILE)
    }
    /// Load the link, if any.
    pub fn load(data_dir: &Path) -> anyhow::Result<Option<Self>> {
        fsutil::read_json(&Self::path(data_dir))
    }
}

/// Register this node with the cloud using a one-time link code from the console.
pub async fn link(
    cloud_url: &str,
    code: &str,
    data_dir: &Path,
    node: &NodeIdentity,
    name: &str,
    level: ProtectionLevel,
) -> anyhow::Result<CloudLink> {
    let code = code.trim();
    if code.is_empty() || code.len() > 64 || !code.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        bail!("invalid link code");
    }
    let base = url::Url::parse(cloud_url).context("invalid cloud URL")?;
    if base.scheme() != "https" && !crate::config::is_loopback_url(&base) {
        bail!("the cloud URL must use https");
    }
    let url = base.join("/v1/nodes/link")?;
    let pk = node.identity.public();
    let body = serde_json::to_vec(&json!({
        "code": code,
        "node_id": node.executor_id,
        "name": name,
        "sign_pk": aipass_crypto::b64u::encode(pk.sign_pk),
        "kem_pk": aipass_crypto::b64u::encode(pk.kem_pk),
        "protection_level": level,
        "version": env!("CARGO_PKG_VERSION"),
    }))?;
    let pq = url.path().to_string();
    let sig = aipass_types::signing::sign_request(node.identity.as_ref(), node.executor_id.as_str(), "POST", &pq, &body);
    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(20))
        .build()?;
    let resp = http
        .post(url)
        .header("Authorization", sig.to_header_value())
        .header("Content-Type", "application/json")
        .body(body)
        .send()
        .await
        .context("cannot reach the cloud")?;
    let status = resp.status();
    let bytes = resp.bytes().await.unwrap_or_default();
    if !status.is_success() {
        let msg = serde_json::from_slice::<aipass_types::error::ErrorBody>(&bytes)
            .map(|b| ApiError::from_body(&b).code.as_str().to_string())
            .unwrap_or_else(|_| status.to_string());
        bail!("cloud refused the link: {msg}");
    }
    let v: Value = serde_json::from_slice(&bytes).context("unexpected cloud response")?;
    let node_id = v.get("node_id").and_then(Value::as_str).unwrap_or(node.executor_id.as_str()).to_string();
    let link = CloudLink { cloud_url: base.as_str().trim_end_matches('/').to_string(), node_id, linked_at: aipass_types::time::now() };
    fsutil::write_json(&CloudLink::path(data_dir), &link)?;
    Ok(link)
}

/// Tunnel frame handler.
pub struct NodeTunnelHandler {
    broker: Arc<Broker>,
    mcp: Arc<StreamableHttp>,
    data_dir: PathBuf,
    lang: Lang,
}

#[async_trait]
impl TunnelHandler for NodeTunnelHandler {
    async fn on_mcp(&self, frame: McpFrame) -> McpResponse {
        match crate::remote_mcp::tunnel_principal(&self.broker, &frame.connection_id, self.lang).await {
            Ok(p) => self.mcp.handle_tunnel_frame(&p, &frame).await,
            Err(e) => McpResponse {
                status: e.http_status(),
                headers: Default::default(),
                body: serde_json::to_value(e.to_body(self.lang)).unwrap_or(Value::Null),
            },
        }
    }

    async fn on_connection_create(&self, frame: ConnectionCreateFrame) -> Result<ConnectionCreated, ApiError> {
        let spec = frame.connection;
        let r = self
            .broker
            .begin_pairing(PairingInput {
                host_type: spec.host_type,
                display_name: spec.display_name,
                transport: Transport::RemoteGateway,
                public_key: None,
            })
            .await?;
        Ok(ConnectionCreated { connection_id: r.connection_id, pairing_code: r.pairing_code })
    }

    async fn on_connection_revoke(&self, connection_id: ConnectionId) {
        if let Err(e) = self.broker.control_connection(&Actor::System, &connection_id, ControlAction::Remove).await {
            tracing::warn!(code = %e.code.as_str(), "cloud revoke of a connection failed");
        }
    }

    async fn on_policy_org(&self, policy: Value) {
        // Recorded for the operator / trusted devices; the broker enforces only signed
        // device policies, so an org policy never widens access by itself.
        if let Err(e) = fsutil::write_json(&self.data_dir.join(ORG_POLICY_FILE), &policy) {
            tracing::warn!(error = %e, "could not store org policy");
        }
    }

    async fn on_state(&self, state: TunnelState) {
        tracing::info!(state = ?state, "cloud tunnel");
    }
}

/// Start the tunnel and forward connection status changes of remote connections.
pub fn spawn_tunnel(
    link: &CloudLink,
    node: &NodeIdentity,
    broker: Arc<Broker>,
    mcp: Arc<StreamableHttp>,
    data_dir: PathBuf,
    lang: Lang,
) -> anyhow::Result<(TunnelHandle, tokio::task::JoinHandle<()>)> {
    let url = aipass_client::endpoint::tunnel_url(&link.cloud_url).map_err(|e| anyhow::anyhow!("tunnel URL: {e}"))?;
    let node_id = ExecutorId::parse(&link.node_id).unwrap_or_else(|_| node.executor_id.clone());
    let signer: Arc<dyn aipass_crypto::Ed25519Signer + Send + Sync> = node.identity.clone();
    let cfg = TunnelConfig::new(url, node_id, signer);
    let handler = Arc::new(NodeTunnelHandler { broker: broker.clone(), mcp, data_dir, lang });
    let handle = TunnelClient::new(cfg, handler).spawn();
    let sender = handle.sender();
    let resync = tokio::spawn(resync_on_connect(broker.clone(), handle.sender()));
    let fwd = tokio::spawn(async move {
        forward_status(broker, sender).await;
        resync.abort();
    });
    Ok((handle, fwd))
}

/// Most remote connections re-announced after each (re)connect.
pub const RESYNC_MAX: usize = 256;

fn remote_status(s: ConnectionStatus) -> RemoteConnectionStatus {
    match s {
        ConnectionStatus::Pending => RemoteConnectionStatus::Pending,
        ConnectionStatus::Active => RemoteConnectionStatus::Active,
        ConnectionStatus::Paused => RemoteConnectionStatus::Paused,
        ConnectionStatus::Removed => RemoteConnectionStatus::Removed,
    }
}

/// The `connection.status` frames to (re)announce: every live remote-gateway connection, then
/// the most recently created removed ones, at most [`RESYNC_MAX`].
pub fn resync_frames(connections: &[aipass_types::models::AppConnection]) -> Vec<(ConnectionId, RemoteConnectionStatus)> {
    let mut remote: Vec<_> = connections.iter().filter(|c| c.transport == Transport::RemoteGateway).collect();
    remote.sort_by(|a, b| {
        (a.status == ConnectionStatus::Removed).cmp(&(b.status == ConnectionStatus::Removed)).then(b.created_at.cmp(&a.created_at))
    });
    remote.into_iter().take(RESYNC_MAX).map(|c| (c.connection_id.clone(), remote_status(c.status))).collect()
}

/// After every (re)connect, re-announce the status of remote connections. Changes made while the
/// link was down (a revocation on the trusted device, a node restart that lost queued frames)
/// reach the cloud, and the cloud answers `connection.revoke` for connections it removed while
/// the node was offline. The node stays authoritative either way: it only serves active
/// `remote_gateway` connections it approved itself.
async fn resync_on_connect(broker: Arc<Broker>, mut sender: TunnelSender) {
    loop {
        if sender.wait_for(TunnelState::Connected).await == TunnelState::Stopped {
            return;
        }
        match broker.list_connections().await {
            Ok(r) => {
                for (id, st) in resync_frames(&r.connections) {
                    if sender.send_connection_status(&id, st).is_err() {
                        tracing::warn!("tunnel queue full; connection status resync incomplete");
                        break;
                    }
                }
            }
            Err(e) => tracing::warn!(code = %e.code.as_str(), "cannot list connections for the cloud resync"),
        }
        if sender.wait_for(TunnelState::Disconnected).await == TunnelState::Stopped {
            return;
        }
    }
}

async fn forward_status(broker: Arc<Broker>, sender: TunnelSender) {
    let mut rx = broker.subscribe();
    loop {
        let ev = match rx.recv().await {
            Ok(ev) => ev,
            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
            Err(_) => return,
        };
        if let BrokerEvent::ConnectionUpdated { connection } = ev
            && connection.transport == Transport::RemoteGateway
        {
            let st = remote_status(connection.status);
            if sender.send_connection_status(&connection.connection_id, st).is_err() {
                tracing::warn!("tunnel queue full; connection status not forwarded");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aipass_types::models::{AllowedProjects, AppConnection, HostType};

    fn conn(transport: Transport, status: ConnectionStatus, age_secs: i64) -> AppConnection {
        AppConnection {
            connection_id: ConnectionId::generate(),
            host_type: HostType::Custom,
            display_name: "x".into(),
            transport,
            status,
            public_key: None,
            allowed_projects: AllowedProjects::default(),
            created_at: aipass_types::time::add_secs(&aipass_types::time::now(), -age_secs),
            approved_at: None,
            approved_by: None,
            last_seen_at: None,
        }
    }

    #[test]
    fn resync_announces_remote_connections_live_first_and_bounded() {
        let mut all = vec![
            conn(Transport::Stdio, ConnectionStatus::Active, 1),
            conn(Transport::RemoteGateway, ConnectionStatus::Removed, 5),
            conn(Transport::RemoteGateway, ConnectionStatus::Active, 100),
            conn(Transport::RemoteGateway, ConnectionStatus::Paused, 50),
        ];
        let f = resync_frames(&all);
        assert_eq!(f.len(), 3, "local transports are never announced to the cloud");
        assert_eq!(f[0], (all[3].connection_id.clone(), RemoteConnectionStatus::Paused));
        assert_eq!(f[1], (all[2].connection_id.clone(), RemoteConnectionStatus::Active));
        assert_eq!(f[2], (all[1].connection_id.clone(), RemoteConnectionStatus::Removed));
        for i in 0..(RESYNC_MAX + 10) {
            all.push(conn(Transport::RemoteGateway, ConnectionStatus::Removed, 1000 + i as i64));
        }
        let f = resync_frames(&all);
        assert_eq!(f.len(), RESYNC_MAX);
        assert_eq!(f[0].1, RemoteConnectionStatus::Paused, "live connections are never crowded out");
    }
}
