// SPDX-License-Identifier: Apache-2.0
//! The embedded local node: an in-process [`aipass_broker::Broker`] plus one
//! [`aipass_executor::Executor`] at protection level **兼容连接 / compatible** (it shares the
//! user's session with any AI tool on this computer — design doc §9.3). The broker API is
//! served on `<home>/run/broker.sock` (0600, connections only — no admin peers) so that
//! `aipass-mcp` bridges launched by AI hosts can reach it; the desktop UI talks to the
//! broker in-process.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use aipass_broker::{
    Actor, ApprovalNotifier, BackgroundTask, Broker, BrokerConfig, BrokerState, CredentialSource,
    UdsOptions,
};
use aipass_crypto::DeviceIdentity;
use aipass_executor::Executor;
use aipass_types::ids::ExecutorId;
use aipass_types::models::ProtectionLevel;
use aipass_types::vault::DevicePublic;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::error::{UiError, UiResult};

/// Display name of the embedded executor.
pub const EXECUTOR_NAME: &str = "本机执行设备 (桌面) / This computer";

/// Everything needed to start the node.
pub struct NodeParams {
    /// Broker data directory.
    pub node_dir: PathBuf,
    /// Socket to serve the broker API on (`None` in tests that only use the in-process API).
    pub broker_socket: Option<PathBuf>,
    /// Executor id.
    pub executor_id: ExecutorId,
    /// Executor identity (X25519 opens credential envelopes; Ed25519 is its public id).
    pub executor_identity: DeviceIdentity,
    /// This desktop's vault device (the in-process approver).
    pub trusted_device: DevicePublic,
    /// Receives broker events for the UI.
    pub notifier: Arc<dyn ApprovalNotifier>,
    /// Re-delivers credentials after a restart (reads the unlocked vault in-process).
    pub credential_source: Option<Arc<dyn CredentialSource>>,
    /// App version.
    pub version: String,
}

/// A running node.
pub struct EmbeddedNode {
    /// Broker.
    pub broker: Arc<Broker>,
    /// Executor.
    pub executor: Arc<Executor>,
    /// Executor id.
    pub executor_id: ExecutorId,
    /// Socket path when served.
    pub broker_socket: Option<PathBuf>,
    shutdown: CancellationToken,
    _background: BackgroundTask,
    maintenance: JoinHandle<()>,
    uds: Option<JoinHandle<()>>,
}

impl std::fmt::Debug for EmbeddedNode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EmbeddedNode").field("executor_id", &self.executor_id).finish_non_exhaustive()
    }
}

impl EmbeddedNode {
    /// Open the broker, register the executor and start serving.
    pub async fn start(p: NodeParams) -> UiResult<Self> {
        crate::paths::ensure_private_dir(&p.node_dir)?;
        let mut cfg = BrokerConfig::new(p.node_dir.clone());
        cfg.version = p.version.clone();
        let broker = Broker::open(cfg).map_err(|e| {
            tracing::error!(error = %e, "broker open failed");
            UiError::internal("无法打开本机授权服务数据库 / cannot open the local broker database")
        })?;
        let executor = Arc::new(
            Executor::builder(p.executor_id.clone(), EXECUTOR_NAME, p.executor_identity)
                .protection_level(ProtectionLevel::Compatible)
                .build()?,
        );
        let backend: Arc<dyn aipass_types::exec::ExecutorBackend> = executor.clone();
        broker.register_executor(backend).await?;
        broker.set_control_channel(&p.executor_id, true).await?;
        broker.add_notifier(p.notifier);
        if let Some(src) = p.credential_source {
            broker.set_credential_source(src);
        }
        ensure_trusted_device(&broker, p.trusted_device).await?;
        let background = broker.spawn_background();
        let maintenance = executor.spawn_maintenance(Duration::from_secs(30));
        let shutdown = CancellationToken::new();
        #[cfg(unix)]
        let uds = match &p.broker_socket {
            Some(path) => {
                if let Some(dir) = path.parent() {
                    crate::paths::ensure_private_dir(dir)?;
                }
                let listener = aipass_broker::http::bind_uds(path)?;
                let router = aipass_broker::router(BrokerState::new(broker.clone()));
                let token = shutdown.clone();
                let path = path.clone();
                Some(tokio::spawn(async move {
                    let res = aipass_broker::http::serve_uds_listener(
                        listener,
                        &path,
                        router,
                        UdsOptions { admin_peers: false },
                        async move { token.cancelled().await },
                    )
                    .await;
                    if let Err(e) = res {
                        tracing::error!(error = %e, "broker socket stopped");
                    }
                }))
            }
            None => None,
        };
        // Windows has no broker UDS in this build: serve loopback TCP 127.0.0.1:7878, the
        // aipass-mcp default on Windows (connections still need their signed keys).
        #[cfg(windows)]
        let uds = match &p.broker_socket {
            Some(_) => {
                let listener = tokio::net::TcpListener::bind(("127.0.0.1", 7878)).await?;
                let router = aipass_broker::router(BrokerState::new(broker.clone()));
                let token = shutdown.clone();
                Some(tokio::spawn(async move {
                    if let Err(e) = aipass_broker::serve_tcp(router, listener, async move { token.cancelled().await }).await {
                        tracing::error!(error = %e, "broker tcp listener stopped");
                    }
                }))
            }
            None => None,
        };
        Ok(Self {
            broker,
            executor,
            executor_id: p.executor_id,
            broker_socket: p.broker_socket,
            shutdown,
            _background: background,
            maintenance,
            uds,
        })
    }

    /// Stop serving and wipe executor credentials.
    pub async fn stop(&self) {
        self.shutdown.cancel();
        self.maintenance.abort();
        self.executor.shutdown().await;
        if let Some(h) = &self.uds {
            h.abort();
        }
    }
}

/// Add (or keep) this desktop as an active trusted approver of the broker.
pub async fn ensure_trusted_device(broker: &Broker, device: DevicePublic) -> UiResult<()> {
    let existing = broker.list_devices().await?;
    if existing.devices.iter().any(|d| d.device.device_id == device.device_id) {
        return Ok(());
    }
    broker.add_trusted_device(&Actor::System, device).await?;
    Ok(())
}
