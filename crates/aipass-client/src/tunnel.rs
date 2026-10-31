// SPDX-License-Identifier: Apache-2.0
//! Cloud tunnel client (CONTRACTS §13 "Nodes & tunnel").
//!
//! A self-host node (`aipass-node`) keeps one **outbound** WebSocket to
//! `<cloud>/v1/tunnel`, so the official remote MCP gateway can reach it without inbound ports.
//!
//! * First frame: `{type:"auth", node_id, ts, nonce, sig}` — Ed25519 by the node identity over
//!   `aipass:v1:tunnel:<node_id>:<ts>:<nonce>` (fresh CSPRNG nonce and timestamp per connect).
//! * Cloud → node: `mcp`, `connection.create`, `connection.revoke`, `policy.org`, `ping`/`pong`.
//! * Node → cloud: `mcp_result`, `connection.created`, `connection.status`, `audit.batch`,
//!   `ping`/`pong`, and (additive) `{type:"error", id, error:{code,message}}` when a request
//!   frame cannot be served.
//! * JSON `ping` every 20 s; the link is considered dead after 60 s without any inbound frame.
//! * Reconnect with exponential backoff (1 s … 60 s, ±20 % jitter from the OS CSPRNG).
//!
//! The cloud gateway is **not** an end-to-end-blind relay: it sees MCP bodies it forwards
//! (CONTRACTS §13). The tunnel carries no vault material; audit batches are metadata only.
//! The `connection_id` in an `mcp` frame is asserted by the cloud after token validation —
//! the node must still check that the connection exists, is a `remote_gateway` connection
//! and is active before serving it.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use aipass_crypto::{Ed25519Signer, b64u};
use aipass_types::models::{AuditEvent, HostType};
use aipass_types::{ApiError, ConnectionId, ErrorCode, ExecutorId, Lang};
use async_trait::async_trait;
use futures::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::sync::{mpsc, watch};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_util::sync::CancellationToken;
use url::Url;

/// JSON ping interval (CONTRACTS §13: every 20 s).
pub const PING_INTERVAL: Duration = Duration::from_secs(20);
/// Dead-link timeout without any inbound frame.
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(60);
/// Largest accepted WebSocket message.
pub const MAX_MESSAGE_BYTES: usize = 4 * 1024 * 1024;
/// Outbound queue capacity (frames).
pub const OUTBOUND_QUEUE: usize = 1024;

/// The string the auth frame signature covers.
pub fn auth_signing_message(node_id: &str, ts: i64, nonce: &str) -> String {
    format!("aipass:v1:tunnel:{node_id}:{ts}:{nonce}")
}

/// The auth frame.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthFrame {
    /// Always `"auth"`.
    #[serde(rename = "type")]
    pub frame_type: String,
    /// Node id (`exe_…`).
    pub node_id: ExecutorId,
    /// Unix seconds.
    pub ts: i64,
    /// b64u 16 random bytes.
    pub nonce: String,
    /// b64u Ed25519 signature over [`auth_signing_message`].
    pub sig: String,
}

impl AuthFrame {
    /// Build and sign with an explicit timestamp and nonce.
    pub fn sign_with(node_id: &ExecutorId, signer: &dyn Ed25519Signer, ts: i64, nonce: &str) -> Self {
        let msg = auth_signing_message(node_id.as_str(), ts, nonce);
        Self {
            frame_type: "auth".into(),
            node_id: node_id.clone(),
            ts,
            nonce: nonce.to_owned(),
            sig: b64u::encode(signer.sign(msg.as_bytes())),
        }
    }

    /// Build and sign now with a fresh nonce.
    pub fn sign_now(node_id: &ExecutorId, signer: &dyn Ed25519Signer) -> Result<Self, ApiError> {
        let nonce = aipass_crypto::rng::try_random_array::<16>()
            .map_err(|_| ApiError::internal())?;
        Ok(Self::sign_with(
            node_id,
            signer,
            aipass_types::time::unix_now(),
            &b64u::encode(nonce),
        ))
    }

    /// Verify (cloud side / tests): signature and `|now − ts| ≤ 300 s`.
    pub fn verify(&self, sign_pk: &[u8; 32], now: i64) -> Result<(), ApiError> {
        if self.frame_type != "auth" {
            return Err(ApiError::invalid_request("不是认证帧", "not an auth frame"));
        }
        if (now - self.ts).abs() > aipass_types::signing::MAX_SKEW_SECS {
            return Err(ApiError::identity_unverified());
        }
        b64u::decode_array::<16>(&self.nonce).map_err(|_| ApiError::identity_unverified())?;
        let sig = b64u::decode_array::<64>(&self.sig).map_err(|_| ApiError::identity_unverified())?;
        let msg = auth_signing_message(self.node_id.as_str(), self.ts, &self.nonce);
        aipass_crypto::identity::verify(sign_pk, msg.as_bytes(), &sig)
            .map_err(|_| ApiError::identity_unverified())
    }
}

/// `{type:"mcp", id, connection_id, session_id?, body}` — a Streamable HTTP request forwarded
/// by the gateway. `protocol_version` and `http_method` are optional additive fields
/// (`MCP-Protocol-Version` header, `"POST"` default or `"DELETE"`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct McpFrame {
    /// Correlation id (echoed).
    pub id: Value,
    /// Remote connection (asserted by the cloud after OAuth token validation).
    pub connection_id: ConnectionId,
    /// `Mcp-Session-Id` of the remote client.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// `MCP-Protocol-Version` of the remote client.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol_version: Option<String>,
    /// HTTP method (`POST` default, `DELETE` ends the session).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_method: Option<String>,
    /// JSON-RPC body (a JSON value; a JSON string is accepted and parsed as JSON text).
    #[serde(default)]
    pub body: Value,
}

impl McpFrame {
    /// The body as JSON bytes (decoding a string-wrapped body).
    pub fn body_bytes(&self) -> Vec<u8> {
        match &self.body {
            Value::String(s) => s.as_bytes().to_vec(),
            Value::Null => Vec::new(),
            v => serde_json::to_vec(v).unwrap_or_default(),
        }
    }
}

/// HTTP-like response to an [`McpFrame`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct McpResponse {
    /// HTTP status the gateway should return.
    pub status: u16,
    /// Response headers (e.g. `mcp-session-id`, `content-type`).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub headers: BTreeMap<String, String>,
    /// JSON body (`null` for 202/204).
    #[serde(default)]
    pub body: Value,
}

/// `connection.create` payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteConnectionSpec {
    /// Host type (`chatgpt`, `claude_connector`, …).
    pub host_type: HostType,
    /// OAuth client name — self-declared, shown marked as such.
    pub display_name: String,
    /// OAuth client id (`oac_…`).
    pub oauth_client_id: String,
    /// Cloud user id (`usr_…`).
    pub user_id: String,
}

/// `{type:"connection.create", id, connection}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectionCreateFrame {
    /// Correlation id.
    pub id: Value,
    /// Requested connection.
    pub connection: RemoteConnectionSpec,
}

/// Node's answer to `connection.create`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectionCreated {
    /// Pending connection.
    pub connection_id: ConnectionId,
    /// Pairing code shown on the consent page and the trusted device.
    pub pairing_code: String,
}

/// Status reported in `connection.status` (connection statuses plus the pairing outcomes
/// `denied` / `expired`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemoteConnectionStatus {
    /// Waiting for approval on a trusted device.
    Pending,
    /// Approved.
    Active,
    /// Paused.
    Paused,
    /// Removed / revoked.
    Removed,
    /// Pairing denied on the trusted device.
    Denied,
    /// Pairing window passed (never auto-approved).
    Expired,
}

/// Link state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelState {
    /// Not connected (initial, or between reconnects).
    Disconnected,
    /// Connecting / authenticating.
    Connecting,
    /// Auth frame sent and link alive.
    Connected,
    /// Stopped by [`TunnelHandle::shutdown`].
    Stopped,
}

/// Application callbacks for inbound frames. Each frame is handled on its own task, so a slow
/// MCP call never blocks pings or other frames.
#[async_trait]
pub trait TunnelHandler: Send + Sync + 'static {
    /// Serve one forwarded MCP HTTP request.
    async fn on_mcp(&self, frame: McpFrame) -> McpResponse;
    /// Create a pending remote connection (the user must still approve it on a trusted device).
    async fn on_connection_create(
        &self,
        frame: ConnectionCreateFrame,
    ) -> Result<ConnectionCreated, ApiError>;
    /// The cloud revoked a remote connection (tokens revoked; stop serving it).
    async fn on_connection_revoke(&self, connection_id: ConnectionId);
    /// Organisation policy pushed by the cloud.
    async fn on_policy_org(&self, policy: Value);
    /// Link state changed.
    async fn on_state(&self, _state: TunnelState) {}
}

/// Tunnel configuration.
#[derive(Clone)]
pub struct TunnelConfig {
    /// `wss://<cloud>/v1/tunnel` (see [`crate::endpoint::tunnel_url`]).
    pub url: Url,
    /// Node id (`exe_…`).
    pub node_id: ExecutorId,
    /// Node identity signer.
    pub signer: Arc<dyn Ed25519Signer + Send + Sync>,
    /// JSON ping interval.
    pub ping_interval: Duration,
    /// Dead-link timeout.
    pub idle_timeout: Duration,
    /// First reconnect delay.
    pub backoff_min: Duration,
    /// Largest reconnect delay.
    pub backoff_max: Duration,
    /// Connect (TCP + TLS + WebSocket handshake) timeout.
    pub connect_timeout: Duration,
    /// `User-Agent` of the handshake.
    pub user_agent: String,
}

impl std::fmt::Debug for TunnelConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TunnelConfig")
            .field("url", &self.url.as_str())
            .field("node_id", &self.node_id)
            .finish_non_exhaustive()
    }
}

impl TunnelConfig {
    /// Defaults per CONTRACTS §13.
    pub fn new(url: Url, node_id: ExecutorId, signer: Arc<dyn Ed25519Signer + Send + Sync>) -> Self {
        Self {
            url,
            node_id,
            signer,
            ping_interval: PING_INTERVAL,
            idle_timeout: IDLE_TIMEOUT,
            backoff_min: Duration::from_secs(1),
            backoff_max: Duration::from_secs(60),
            connect_timeout: Duration::from_secs(15),
            user_agent: format!("aipass-node-tunnel/{}", env!("CARGO_PKG_VERSION")),
        }
    }
}

/// Error from [`TunnelSender`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TunnelError {
    /// The outbound queue is full (link down for long); the frame was not queued.
    #[error("tunnel outbound queue is full")]
    QueueFull,
    /// The tunnel was shut down.
    #[error("tunnel stopped")]
    Stopped,
}

/// Cloneable handle for node-initiated frames.
#[derive(Clone)]
pub struct TunnelSender {
    tx: mpsc::Sender<Value>,
    state: watch::Receiver<TunnelState>,
}

impl TunnelSender {
    fn push(&self, frame: Value) -> Result<(), TunnelError> {
        self.tx.try_send(frame).map_err(|e| match e {
            mpsc::error::TrySendError::Full(_) => TunnelError::QueueFull,
            mpsc::error::TrySendError::Closed(_) => TunnelError::Stopped,
        })
    }

    /// `{type:"audit.batch", events}` — events must be metadata only (no bodies, no secrets).
    pub fn send_audit_batch(&self, events: Vec<Value>) -> Result<(), TunnelError> {
        self.push(json!({"type": "audit.batch", "events": events}))
    }

    /// `audit.batch` from typed audit events (hash chain included so the cloud can verify it).
    pub fn send_audit_events(&self, events: &[AuditEvent]) -> Result<(), TunnelError> {
        let values = events
            .iter()
            .filter_map(|e| serde_json::to_value(e).ok())
            .collect();
        self.send_audit_batch(values)
    }

    /// `{type:"connection.status", connection_id, status}`.
    pub fn send_connection_status(
        &self,
        connection_id: &ConnectionId,
        status: RemoteConnectionStatus,
    ) -> Result<(), TunnelError> {
        self.push(json!({
            "type": "connection.status",
            "connection_id": connection_id,
            "status": status,
        }))
    }

    /// Current link state.
    pub fn state(&self) -> TunnelState {
        *self.state.borrow()
    }

    /// Wait until the state equals `want` (or the tunnel stops).
    pub async fn wait_for(&mut self, want: TunnelState) -> TunnelState {
        loop {
            let s = *self.state.borrow_and_update();
            if s == want || s == TunnelState::Stopped {
                return s;
            }
            if self.state.changed().await.is_err() {
                return TunnelState::Stopped;
            }
        }
    }
}

/// Handle to a spawned tunnel.
pub struct TunnelHandle {
    shutdown: CancellationToken,
    join: tokio::task::JoinHandle<()>,
    sender: TunnelSender,
}

impl TunnelHandle {
    /// Sender for node-initiated frames.
    pub fn sender(&self) -> TunnelSender {
        self.sender.clone()
    }

    /// Stop and wait for the task to end.
    pub async fn shutdown(self) {
        self.shutdown.cancel();
        let _ = self.join.await;
    }
}

/// The tunnel client.
pub struct TunnelClient {
    config: TunnelConfig,
    handler: Arc<dyn TunnelHandler>,
    out_rx: mpsc::Receiver<Value>,
    state_tx: watch::Sender<TunnelState>,
    sender: TunnelSender,
    shutdown: CancellationToken,
}

enum LinkEnd {
    Shutdown,
    Lost(String),
}

impl TunnelClient {
    /// Create a client; nothing connects until [`TunnelClient::run`] / [`TunnelClient::spawn`].
    pub fn new(config: TunnelConfig, handler: Arc<dyn TunnelHandler>) -> Self {
        let (tx, out_rx) = mpsc::channel(OUTBOUND_QUEUE);
        let (state_tx, state_rx) = watch::channel(TunnelState::Disconnected);
        Self {
            config,
            handler,
            out_rx,
            state_tx,
            sender: TunnelSender { tx, state: state_rx },
            shutdown: CancellationToken::new(),
        }
    }

    /// Sender for node-initiated frames.
    pub fn sender(&self) -> TunnelSender {
        self.sender.clone()
    }

    /// Run on a new task.
    pub fn spawn(self) -> TunnelHandle {
        let shutdown = self.shutdown.clone();
        let sender = self.sender.clone();
        let join = tokio::spawn(self.run());
        TunnelHandle {
            shutdown,
            join,
            sender,
        }
    }

    async fn set_state(&self, s: TunnelState) {
        if *self.state_tx.borrow() != s {
            self.state_tx.send_replace(s);
            self.handler.on_state(s).await;
        }
    }

    /// Connect, serve and reconnect until shut down.
    pub async fn run(mut self) {
        let mut backoff = self.config.backoff_min;
        loop {
            if self.shutdown.is_cancelled() {
                break;
            }
            self.set_state(TunnelState::Connecting).await;
            let started = Instant::now();
            let end = self.connect_once().await;
            match end {
                LinkEnd::Shutdown => break,
                LinkEnd::Lost(reason) => {
                    tracing::warn!(reason = %reason, "cloud tunnel link lost; reconnecting");
                }
            }
            self.set_state(TunnelState::Disconnected).await;
            if started.elapsed() > Duration::from_secs(60) {
                backoff = self.config.backoff_min;
            }
            let delay = jitter(backoff);
            tokio::select! {
                _ = self.shutdown.cancelled() => break,
                _ = tokio::time::sleep(delay) => {}
            }
            backoff = (backoff * 2).min(self.config.backoff_max);
        }
        self.set_state(TunnelState::Stopped).await;
    }

    async fn connect_once(&mut self) -> LinkEnd {
        let mut request = match self.config.url.as_str().into_client_request() {
            Ok(r) => r,
            Err(e) => return LinkEnd::Lost(format!("invalid tunnel URL: {e}")),
        };
        if let Ok(ua) = http::HeaderValue::from_str(&self.config.user_agent) {
            request.headers_mut().insert(http::header::USER_AGENT, ua);
        }
        let ws_config = WebSocketConfig::default()
            .max_message_size(Some(MAX_MESSAGE_BYTES))
            .max_frame_size(Some(MAX_MESSAGE_BYTES));
        let connect = tokio_tungstenite::connect_async_with_config(request, Some(ws_config), true);
        let ws = tokio::select! {
            _ = self.shutdown.cancelled() => return LinkEnd::Shutdown,
            r = tokio::time::timeout(self.config.connect_timeout, connect) => match r {
                Ok(Ok((ws, _resp))) => ws,
                Ok(Err(e)) => return LinkEnd::Lost(format!("connect failed: {e}")),
                Err(_) => return LinkEnd::Lost("connect timed out".into()),
            },
        };
        let (mut sink, mut stream) = ws.split();
        let auth = match AuthFrame::sign_now(&self.config.node_id, self.config.signer.as_ref()) {
            Ok(a) => a,
            Err(_) => return LinkEnd::Lost("OS random number generator unavailable".into()),
        };
        let auth_text = match serde_json::to_string(&auth) {
            Ok(t) => t,
            Err(e) => return LinkEnd::Lost(e.to_string()),
        };
        if let Err(e) = sink.send(Message::text(auth_text)).await {
            return LinkEnd::Lost(format!("sending auth frame failed: {e}"));
        }
        self.set_state(TunnelState::Connected).await;
        tracing::info!(node_id = %self.config.node_id, "cloud tunnel connected");

        let (res_tx, mut res_rx) = mpsc::channel::<Value>(256);
        let mut ping = tokio::time::interval(self.config.ping_interval);
        ping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        ping.tick().await; // first tick is immediate
        let mut last_rx = Instant::now();

        loop {
            tokio::select! {
                _ = self.shutdown.cancelled() => {
                    let _ = sink.send(Message::Close(None)).await;
                    return LinkEnd::Shutdown;
                }
                msg = stream.next() => {
                    let Some(msg) = msg else { return LinkEnd::Lost("closed by peer".into()) };
                    let msg = match msg {
                        Ok(m) => m,
                        Err(e) => return LinkEnd::Lost(format!("read failed: {e}")),
                    };
                    last_rx = Instant::now();
                    match msg {
                        Message::Text(t) => {
                            if let Some(reply) = self.dispatch(t.as_str(), &res_tx)
                                && let Err(e) = send_value(&mut sink, &reply).await
                            {
                                return LinkEnd::Lost(e);
                            }
                        }
                        Message::Ping(p) => {
                            if let Err(e) = sink.send(Message::Pong(p)).await {
                                return LinkEnd::Lost(format!("pong failed: {e}"));
                            }
                        }
                        Message::Close(frame) => {
                            let reason = frame
                                .map(|f| format!("closed by cloud ({}: {})", u16::from(f.code), f.reason))
                                .unwrap_or_else(|| "closed by cloud".into());
                            return LinkEnd::Lost(reason);
                        }
                        Message::Binary(_) => tracing::debug!("ignoring binary tunnel frame"),
                        Message::Pong(_) | Message::Frame(_) => {}
                    }
                }
                Some(result) = res_rx.recv() => {
                    if let Err(e) = send_value(&mut sink, &result).await {
                        return LinkEnd::Lost(e);
                    }
                }
                Some(frame) = self.out_rx.recv() => {
                    if let Err(e) = send_value(&mut sink, &frame).await {
                        tracing::warn!("a queued tunnel frame was not delivered");
                        return LinkEnd::Lost(e);
                    }
                }
                _ = ping.tick() => {
                    if last_rx.elapsed() > self.config.idle_timeout {
                        return LinkEnd::Lost("no frames from the cloud within the idle timeout".into());
                    }
                    if let Err(e) = send_value(&mut sink, &json!({"type": "ping"})).await {
                        return LinkEnd::Lost(e);
                    }
                }
            }
        }
    }

    /// Handle one inbound text frame. Returns an immediate reply (pong, errors); request
    /// frames are served on spawned tasks that report through `res_tx`.
    fn dispatch(&self, text: &str, res_tx: &mpsc::Sender<Value>) -> Option<Value> {
        let value: Value = match serde_json::from_str(text) {
            Ok(v) => v,
            Err(_) => {
                tracing::warn!("ignoring malformed tunnel frame");
                return None;
            }
        };
        let frame_type = value.get("type").and_then(Value::as_str).unwrap_or("").to_owned();
        let id = value.get("id").cloned().unwrap_or(Value::Null);
        match frame_type.as_str() {
            "ping" => Some(json!({"type": "pong"})),
            "pong" => None,
            "auth.ok" | "auth_ok" | "authenticated" => {
                tracing::info!("cloud tunnel authenticated");
                None
            }
            "error" => {
                let code = value
                    .pointer("/error/code")
                    .and_then(Value::as_str)
                    .unwrap_or("UNKNOWN");
                tracing::warn!(code, "cloud tunnel reported an error");
                None
            }
            "mcp" => match serde_json::from_value::<McpFrame>(value) {
                Ok(frame) => {
                    let handler = self.handler.clone();
                    let tx = res_tx.clone();
                    tokio::spawn(async move {
                        let id = frame.id.clone();
                        let resp = handler.on_mcp(frame).await;
                        let mut out = json!({
                            "type": "mcp_result",
                            "id": id,
                            "status": resp.status,
                            "body": resp.body,
                        });
                        if !resp.headers.is_empty() {
                            out["headers"] = json!(resp.headers);
                        }
                        let _ = tx.send(out).await;
                    });
                    None
                }
                Err(_) => Some(error_frame(&id, ErrorCode::InvalidRequest)),
            },
            "connection.create" => match serde_json::from_value::<ConnectionCreateFrame>(value) {
                Ok(frame) => {
                    let handler = self.handler.clone();
                    let tx = res_tx.clone();
                    tokio::spawn(async move {
                        let id = frame.id.clone();
                        let out = match handler.on_connection_create(frame).await {
                            Ok(c) => json!({
                                "type": "connection.created",
                                "id": id,
                                "connection_id": c.connection_id,
                                "pairing_code": c.pairing_code,
                            }),
                            Err(e) => api_error_frame(&id, &e),
                        };
                        let _ = tx.send(out).await;
                    });
                    None
                }
                Err(_) => Some(error_frame(&id, ErrorCode::InvalidRequest)),
            },
            "connection.revoke" => {
                match value
                    .get("connection_id")
                    .and_then(Value::as_str)
                    .and_then(|s| ConnectionId::parse(s).ok())
                {
                    Some(cid) => {
                        let handler = self.handler.clone();
                        tokio::spawn(async move { handler.on_connection_revoke(cid).await });
                        None
                    }
                    None => Some(error_frame(&id, ErrorCode::InvalidRequest)),
                }
            }
            "policy.org" => match value.get("policy") {
                Some(p) if p.is_object() => {
                    let handler = self.handler.clone();
                    let policy = p.clone();
                    tokio::spawn(async move { handler.on_policy_org(policy).await });
                    None
                }
                _ => Some(error_frame(&id, ErrorCode::InvalidRequest)),
            },
            other => {
                tracing::debug!(frame_type = other, "ignoring unknown tunnel frame type");
                None
            }
        }
    }
}

fn error_frame(id: &Value, code: ErrorCode) -> Value {
    api_error_frame(id, &ApiError::new(code))
}

fn api_error_frame(id: &Value, e: &ApiError) -> Value {
    json!({
        "type": "error",
        "id": id,
        "error": {"code": e.code.as_str(), "message": e.message(Lang::En)},
    })
}

async fn send_value<S>(sink: &mut S, v: &Value) -> Result<(), String>
where
    S: futures::Sink<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin,
{
    let text = serde_json::to_string(v).map_err(|e| e.to_string())?;
    sink.send(Message::text(text))
        .await
        .map_err(|e| format!("write failed: {e}"))
}

/// ±20 % jitter from the OS CSPRNG.
fn jitter(d: Duration) -> Duration {
    let ms = d.as_millis() as u64;
    let spread = ms / 5;
    if spread == 0 {
        return d;
    }
    let r = aipass_crypto::rng::random_below((spread * 2).min(u32::MAX as u64) as u32).unwrap_or(0) as u64;
    Duration::from_millis(ms - spread + r)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aipass_crypto::Ed25519Keypair;

    #[test]
    fn auth_frame_signs_contract_message() {
        let kp = Ed25519Keypair::from_seed(&[9u8; 32]);
        let node = ExecutorId::generate();
        let f = AuthFrame::sign_with(&node, &kp, 1_793_318_400, "qqqqqqqqqqqqqqqqqqqqqg");
        let msg = format!("aipass:v1:tunnel:{}:1793318400:qqqqqqqqqqqqqqqqqqqqqg", node.as_str());
        assert_eq!(f.sig, kp.sign_b64u(msg.as_bytes()));
        f.verify(&kp.public_key(), 1_793_318_400 + 10).unwrap();
        assert!(f.verify(&kp.public_key(), 1_793_318_400 + 301).is_err());
        let other = Ed25519Keypair::generate();
        assert!(f.verify(&other.public_key(), 1_793_318_400).is_err());
        let v = serde_json::to_value(&f).unwrap();
        assert_eq!(v["type"], "auth");
        assert_eq!(v["node_id"], node.as_str());
    }

    #[test]
    fn jitter_bounds() {
        for _ in 0..100 {
            let j = jitter(Duration::from_secs(10));
            assert!(j >= Duration::from_secs(8) && j <= Duration::from_secs(12));
        }
        assert_eq!(jitter(Duration::from_millis(3)), Duration::from_millis(3));
    }

    #[test]
    fn mcp_frame_body_forms() {
        let f: McpFrame = serde_json::from_value(json!({
            "type": "mcp", "id": "r1", "connection_id": "conn_01jbz3k6w8a7m2q4t5v9x0y1z4",
            "body": "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}"
        }))
        .unwrap();
        assert_eq!(f.body_bytes(), br#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#.to_vec());
        let f: McpFrame = serde_json::from_value(json!({
            "id": 7, "connection_id": "conn_01jbz3k6w8a7m2q4t5v9x0y1z4", "session_id": "s",
            "body": {"jsonrpc":"2.0","id":1,"method":"ping"}
        }))
        .unwrap();
        let v: Value = serde_json::from_slice(&f.body_bytes()).unwrap();
        assert_eq!(v["method"], "ping");
    }
}
