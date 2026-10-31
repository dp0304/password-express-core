// SPDX-License-Identifier: Apache-2.0
//! Remote MCP through the official cloud gateway (CONTRACTS §13 "Nodes & tunnel"): link
//! the embedded node to the signed-in account, then keep an outbound WebSocket tunnel
//! (`aipass_client::tunnel::TunnelClient`). Forwarded `mcp` frames are served by the same
//! MCP handler as `aipass-mcp`, bound to the remote connection's in-process broker handle.
//! New remote connections arrive as `connection.create` and stay **pending** until the user
//! confirms the pairing code in the desktop app (or on the phone).
//!
//! Honesty: the official gateway sees request and result content; it is not an
//! end-to-end blind relay (§4.3). The UI says so.

use std::sync::Arc;

use aipass_broker::{Broker, BrokerEvent, ConnectionHandle, ConnectionPrincipal, PairingInput};
use aipass_client::BrokerApi;
use aipass_client::tunnel::{
    ConnectionCreateFrame, ConnectionCreated, McpFrame, McpResponse, RemoteConnectionStatus, TunnelClient, TunnelConfig,
    TunnelHandle, TunnelHandler, TunnelSender,
};
use aipass_mcp::{BearerResolver, HttpConfig, HttpMode, McpServer, McpServerConfig, Principal, StreamableHttp};
use aipass_types::ids::{ApprovalRequestId, ConnectionId, GrantId, OperationId, ProjectId};
use aipass_types::models::{
    AccessRequest, AccessRequestResponse, CancelResponse, ConnectionStatus, OperationRequest, OperationResponse,
    ReleaseResponse, ResourcesResponse, Transport,
};
use aipass_types::relay::ControlAction;
use aipass_types::{ApiError, ErrorCode, Lang};
use serde_json::{Value, json};

use crate::core::AppCore;
use crate::error::{UiError, UiResult};

/// `BrokerApi` over the broker's in-process [`ConnectionHandle`] (the value *is* the caller).
pub struct HandleApi(pub ConnectionHandle);

#[async_trait::async_trait]
impl BrokerApi for HandleApi {
    async fn list_resources(&self, p: Option<&ProjectId>, s: Option<&str>) -> Result<ResourcesResponse, ApiError> {
        self.0.list_resources(p, s).await
    }
    async fn request_operation(&self, r: &OperationRequest) -> Result<OperationResponse, ApiError> {
        self.0.request_operation(r).await
    }
    async fn get_operation(&self, id: &OperationId) -> Result<OperationResponse, ApiError> {
        self.0.get_operation(id).await
    }
    async fn cancel_operation(&self, id: &OperationId) -> Result<CancelResponse, ApiError> {
        self.0.cancel_operation(id).await
    }
    async fn request_access(&self, r: &AccessRequest) -> Result<AccessRequestResponse, ApiError> {
        self.0.request_access(r).await
    }
    async fn get_access_request(&self, id: &ApprovalRequestId) -> Result<AccessRequestResponse, ApiError> {
        self.0.get_access_request(id).await
    }
    async fn release_grant(&self, id: &GrantId) -> Result<ReleaseResponse, ApiError> {
        self.0.release_grant(id).await
    }
}

/// Bearer tokens never reach the node through the tunnel; the cloud validated them.
struct NoBearer;
#[async_trait::async_trait]
impl BearerResolver for NoBearer {
    async fn resolve(&self, _token: &str) -> Result<Principal, ApiError> {
        Err(ApiError::identity_unverified())
    }
}

/// Serves tunnel frames for the embedded broker.
pub struct DesktopTunnelHandler {
    broker: Arc<Broker>,
    http: Arc<StreamableHttp>,
    lang: Lang,
}

impl DesktopTunnelHandler {
    /// Handler for `broker`; `cloud_base` is used for the protected-resource metadata URL.
    pub fn new(broker: Arc<Broker>, cloud_base: &str, version: &str, lang: Lang) -> Arc<Self> {
        let server = Arc::new(McpServer::new(McpServerConfig { experimental: false, lang, version: version.to_owned() }));
        let base = cloud_base.trim_end_matches('/');
        let http = StreamableHttp::new(
            server,
            HttpConfig::new(HttpMode::Remote {
                resolver: Arc::new(NoBearer),
                resource_metadata_url: format!("{base}/.well-known/oauth-protected-resource/mcp"),
                allowed_origins: vec![],
            }),
        );
        Arc::new(Self { broker, http, lang })
    }
}

fn reject(status: u16, code: ErrorCode, zh: &str, en: &str) -> McpResponse {
    McpResponse {
        status,
        headers: Default::default(),
        body: json!({"error": {"code": code.as_str(), "message": format!("{zh} / {en}")}}),
    }
}

#[async_trait::async_trait]
impl TunnelHandler for DesktopTunnelHandler {
    async fn on_mcp(&self, frame: McpFrame) -> McpResponse {
        let Ok(conn) = self.broker.get_connection(&frame.connection_id).await else {
            return reject(404, ErrorCode::NotFound, "未知连接", "Unknown connection");
        };
        if conn.transport != Transport::RemoteGateway {
            return reject(403, ErrorCode::Forbidden, "该连接不是远程连接", "Not a remote-gateway connection");
        }
        match conn.status {
            ConnectionStatus::Active => {}
            ConnectionStatus::Paused => return reject(403, ErrorCode::ConnectionPaused, "连接已暂停", "Connection paused"),
            _ => return reject(403, ErrorCode::Forbidden, "连接未生效", "Connection not active"),
        }
        let handle = self.broker.connection_handle(ConnectionPrincipal::in_process(conn.connection_id.clone()), self.lang);
        let principal = Principal { key: conn.connection_id.to_string(), broker: Arc::new(HandleApi(handle)) };
        self.http.handle_tunnel_frame(&principal, &frame).await
    }

    async fn on_connection_create(&self, frame: ConnectionCreateFrame) -> Result<ConnectionCreated, ApiError> {
        let name = frame.connection.display_name.chars().take(64).collect::<String>();
        let r = self
            .broker
            .begin_pairing(PairingInput {
                host_type: frame.connection.host_type,
                display_name: name,
                transport: Transport::RemoteGateway,
                public_key: None,
            })
            .await?;
        Ok(ConnectionCreated { connection_id: r.connection_id, pairing_code: r.pairing_code })
    }

    async fn on_connection_revoke(&self, connection_id: ConnectionId) {
        let _ = self
            .broker
            .control_connection(&aipass_broker::Actor::System, &connection_id, ControlAction::Remove)
            .await;
    }

    async fn on_policy_org(&self, policy: Value) {
        // Org policy is advisory for a personal desktop node; it is recorded, not enforced here.
        tracing::info!(keys = policy.as_object().map(|o| o.len()).unwrap_or(0), "org policy received");
    }
}

/// Forward remote-connection status changes to the cloud.
pub fn spawn_status_forwarder(broker: &Broker, sender: TunnelSender) -> tokio::task::JoinHandle<()> {
    let mut rx = broker.subscribe();
    tokio::spawn(async move {
        loop {
            match rx.recv().await {
                Ok(BrokerEvent::ConnectionUpdated { connection }) if connection.transport == Transport::RemoteGateway => {
                    let st = match connection.status {
                        ConnectionStatus::Pending => RemoteConnectionStatus::Pending,
                        ConnectionStatus::Active => RemoteConnectionStatus::Active,
                        ConnectionStatus::Paused => RemoteConnectionStatus::Paused,
                        ConnectionStatus::Removed => RemoteConnectionStatus::Removed,
                    };
                    let _ = sender.send_connection_status(&connection.connection_id, st);
                }
                Ok(_) => {}
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                Err(_) => return,
            }
        }
    })
}

/// Running tunnel.
pub struct RunningTunnel {
    /// Client handle.
    pub handle: TunnelHandle,
    forwarder: tokio::task::JoinHandle<()>,
}

impl RunningTunnel {
    /// Stop.
    pub async fn stop(self) {
        self.forwarder.abort();
        self.handle.shutdown().await;
    }
}

impl AppCore {
    /// Link the embedded node to the signed-in cloud account (creates a link code with the
    /// session, then calls `POST /v1/nodes/link` signed as the executor).
    pub async fn cloud_link_node(&self) -> UiResult<Value> {
        self.require_unlocked()?;
        let session = self.cloud_session().ok_or_else(|| UiError::new("UNAUTHENTICATED", "请先登录云账户。", "Sign in to the cloud account first."))?;
        let n = self.node().await?;
        let base = self.settings().cloud_url;
        let client = aipass_client::BrokerClient::builder(
            aipass_client::BrokerEndpoint::parse(&base).map_err(UiError::from)?,
        )
        .auth(aipass_client::Auth::bearer(session.expose()))
        .build()
        .map_err(UiError::from)?;
        let code: Value = client.post_json("/v1/nodes/link-codes", &json!({})).await.map_err(UiError::from)?;
        let code = code["code"].as_str().ok_or_else(|| UiError::internal("no link code"))?.to_owned();
        let identity = self.executor_identity()?;
        let public = identity.public();
        let signer: Arc<dyn aipass_crypto::Ed25519Signer + Send + Sync> = Arc::new(identity);
        let signed = client.with_auth(aipass_client::Auth::signed(aipass_types::ids::PrincipalId::Executor(n.executor_id.clone()).to_string(), signer));
        let body = json!({
            "code": code,
            "node_id": n.executor_id,
            "name": crate::node::EXECUTOR_NAME,
            "sign_pk": aipass_crypto::b64u::encode(public.sign_pk),
            "kem_pk": aipass_crypto::b64u::encode(public.kem_pk),
            "protection_level": "compatible",
            "version": self.app_version,
        });
        let out: Value = signed.post_json("/v1/nodes/link", &body).await.map_err(UiError::from)?;
        Ok(out)
    }

    /// Start the remote-MCP tunnel to the cloud (node must be linked first).
    pub async fn start_tunnel(&self) -> UiResult<RunningTunnel> {
        self.require_unlocked()?;
        let n = self.node().await?;
        let s = self.settings();
        let url = aipass_client::endpoint::tunnel_url(&s.cloud_url).map_err(UiError::from)?;
        let identity = self.executor_identity()?;
        let signer: Arc<dyn aipass_crypto::Ed25519Signer + Send + Sync> = Arc::new(identity);
        let lang = if s.lang == "en" { Lang::En } else { Lang::ZhCn };
        let handler = DesktopTunnelHandler::new(n.broker.clone(), &s.cloud_url, &self.app_version, lang);
        let client = TunnelClient::new(TunnelConfig::new(url, n.executor_id.clone(), signer), handler);
        let forwarder = spawn_status_forwarder(&n.broker, client.sender());
        let handle = client.spawn();
        Ok(RunningTunnel { handle, forwarder })
    }

    pub(crate) fn executor_identity(&self) -> UiResult<aipass_crypto::DeviceIdentity> {
        let exe = self.settings().executor_id.ok_or_else(UiError::node_not_running)?;
        let bytes = aipass_vault::SecretStore::get(&*self.secrets, &crate::core::executor_secret_key(&exe))?
            .ok_or_else(|| UiError::internal("executor identity"))?;
        aipass_crypto::DeviceIdentity::from_secret_bytes(bytes.expose()).map_err(|_| UiError::internal("executor identity"))
    }
}
