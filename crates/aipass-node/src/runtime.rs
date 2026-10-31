// SPDX-License-Identifier: Apache-2.0
//! The node process: broker `/v1/*`, sync `/v1/vaults*`, relay `/v1/relay*`, remote MCP
//! `/mcp` and `/v1/health` on one listener, with the embedded executor.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use aipass_broker::{Broker, BrokerConfig, BrokerState, RelayIdentity, UdsOptions};
use aipass_executor::Executor;
use aipass_mcp::http::{HttpConfig, HttpMode, StreamableHttp};
use aipass_mcp::{McpServer, McpServerConfig};
use aipass_storage::LocalDirStore;
use aipass_sync_server::relay::{ChainDirectory, LogPushNotifier, NoopPushNotifier, PushNotifier, RelayDirectory, SqliteRelayStore, SyncDirectory, WebhookPushNotifier};
use aipass_sync_server::sync::StaticQuota;
use aipass_sync_server::{RelayState, SyncState, relay_router, spawn_relay_gc, sync_router};
use aipass_types::error::{ApiError, Lang};
use aipass_types::models::{Connector, ProtectionLevel};
use aipass_types::ids::MailboxId;
use anyhow::Context;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::config::NodeConfig;
use crate::identity::NodeIdentity;
use crate::relay_link::{NodeDirectory, RelayOutbox, executor_relay_client, run_consumer};

/// Extra knobs for embedders (the CLI's `aipass node run`).
#[derive(Debug, Clone, Default)]
pub struct StartOptions {
    /// Serve AI connections on this Unix socket (0600, connections only — no admin peers).
    pub connection_socket: Option<PathBuf>,
    /// Skip the TCP listener entirely (UDS-only embedded broker).
    pub no_tcp: bool,
    /// Desktop-style embedding: trusted devices talk to the broker directly (signed HTTP
    /// over the socket), so no relay link / mailbox consumer is started.
    pub local_only: bool,
}

/// A running node.
pub struct RunningNode {
    /// Bound TCP address (if any).
    pub local_addr: Option<SocketAddr>,
    /// The broker.
    pub broker: Arc<Broker>,
    /// The embedded executor.
    pub executor: Option<Arc<Executor>>,
    /// This node's identity.
    pub identity: NodeIdentity,
    stop: watch::Sender<bool>,
    servers: Vec<JoinHandle<std::io::Result<()>>>,
    tasks: Vec<JoinHandle<()>>,
    tunnel: Option<aipass_client::tunnel::TunnelHandle>,
    _sweeper: aipass_broker::BackgroundTask,
}

impl RunningNode {
    /// Signal shutdown and wait for the listeners and background tasks.
    pub async fn shutdown(mut self) {
        let _ = self.stop.send(true);
        if let Some(t) = self.tunnel.take() {
            t.shutdown().await;
        }
        for s in self.servers.drain(..) {
            match tokio::time::timeout(Duration::from_secs(10), s).await {
                Ok(Ok(Err(e))) => tracing::warn!(error = %e, "listener ended with an error"),
                Err(_) => tracing::warn!("listener did not stop within 10 s"),
                _ => {}
            }
        }
        for t in self.tasks.drain(..) {
            t.abort();
        }
        if let Some(e) = &self.executor {
            e.shutdown().await;
        }
        tracing::info!("node stopped");
    }
}

async fn shutdown_future(mut rx: watch::Receiver<bool>) {
    while !*rx.borrow() {
        if rx.changed().await.is_err() {
            return;
        }
    }
}

/// Start the node.
pub async fn start(cfg: NodeConfig, opts: StartOptions) -> anyhow::Result<RunningNode> {
    cfg.validate()?;
    let data = cfg.node.data_dir.clone();
    crate::fsutil::private_dir(&data)?;
    let lang = Lang::ZhCn;
    let node = NodeIdentity::load_or_create(&data)?;
    let listen = cfg.listen_addr()?;
    if !listen.ip().is_loopback() && !cfg.node.tls_terminated_by_proxy {
        tracing::warn!(
            listen = %listen,
            "listening on a non-loopback address without TLS: put a TLS reverse proxy in front (see deploy/README.md) \
             and set node.tls_terminated_by_proxy = true"
        );
    }

    // bind first so an ephemeral port (`:0`) is known to the in-node relay client
    let tcp_listener = if opts.no_tcp {
        None
    } else {
        Some(tokio::net::TcpListener::bind(listen).await.with_context(|| format!("cannot listen on {listen}"))?)
    };
    let bound = tcp_listener.as_ref().map(|l| l.local_addr()).transpose()?;

    // ---- broker -----------------------------------------------------------------------
    let mut bcfg = BrokerConfig::new(cfg.broker_dir());
    bcfg.experimental = cfg.node.experimental;
    let broker = Broker::open(bcfg).map_err(|e| anyhow::anyhow!("cannot open broker: {e}"))?;

    // ---- executor ---------------------------------------------------------------------
    let mut tasks: Vec<JoinHandle<()>> = Vec::new();
    let executor = if cfg.executor.enabled {
        let mut b = Executor::builder(node.executor_id.clone(), cfg.node.name.clone(), (*node.identity).clone())
            .protection_level(cfg.executor.protection_level);
        if let Some(p) = &cfg.executor.extra_root_certs {
            let pem = std::fs::read_to_string(p).with_context(|| format!("cannot read {}", p.display()))?;
            b = b.add_root_certificates_pem(&pem).map_err(|e| anyhow::anyhow!("extra_root_certs: {}", e.code.as_str()))?;
        }
        let exe = Arc::new(b.build().map_err(|e| anyhow::anyhow!("executor: {}", e.code.as_str()))?);
        broker.register_executor(exe.clone()).await.map_err(|e| anyhow::anyhow!("register executor: {}", e.code.as_str()))?;
        tasks.push(exe.spawn_maintenance(Duration::from_secs(30)));
        Some(exe)
    } else {
        None
    };
    if cfg.executor.protection_level == ProtectionLevel::Isolated {
        tracing::info!(attestation = cfg.executor.isolation_attestation.as_deref().unwrap_or(""), "executor reported as isolated (operator attestation)");
    }

    // ---- sync + relay -----------------------------------------------------------------
    let nonce = Arc::new(aipass_types::signing::NonceCache::default());
    let blobs = Arc::new(LocalDirStore::open(data.join("sync")).map_err(|e| anyhow::anyhow!("sync storage: {e}"))?);
    let admission = Arc::new(crate::enroll::FileEnrollAdmission::new(&data));
    let sync_state = SyncState::builder(blobs, admission)
        .quota(Arc::new(StaticQuota { max_bytes_per_vault: cfg.sync.quota_bytes_per_vault, max_objects_per_vault: None }))
        .nonce_cache(nonce.clone())
        .build();
    if cfg.sync.enabled {
        let n = sync_state.rebuild_member_index().await.map_err(|e| anyhow::anyhow!("sync index: {}", e.code.as_str()))?;
        tracing::info!(vaults = n, "sync member index ready");
    }

    let sign_pk = node.identity.public().sign_pk;
    let directory: Arc<dyn RelayDirectory> = Arc::new(ChainDirectory::new(vec![
        Arc::new(SyncDirectory::new(sync_state.clone())),
        Arc::new(NodeDirectory::new(broker.clone(), node.executor_id.clone(), sign_pk)),
    ]));
    let push: Arc<dyn PushNotifier> = match &cfg.relay.webhook_url {
        Some(u) => {
            let secret = match &cfg.relay.webhook_secret_file {
                Some(p) => {
                    crate::fsutil::check_private_file(p)?;
                    Some(aipass_crypto::SecretBytes::new(std::fs::read(p)?.trim_ascii().to_vec()))
                }
                None => None,
            };
            Arc::new(WebhookPushNotifier::new(url::Url::parse(u)?, secret).map_err(|e| anyhow::anyhow!("webhook: {e}"))?)
        }
        None if cfg.log.filter.contains("debug") => Arc::new(LogPushNotifier),
        None => Arc::new(NoopPushNotifier),
    };
    let relay_store = Arc::new(SqliteRelayStore::open(data.join("relay.db")).map_err(|e| anyhow::anyhow!("relay store: {}", e.code.as_str()))?);
    let relay_state = RelayState::builder(relay_store, directory).push(push).nonce_cache(nonce).build();
    if cfg.relay.enabled {
        tasks.push(spawn_relay_gc(relay_state.clone(), Duration::from_secs(60)));
    }

    // ---- broker ↔ devices over the relay ---------------------------------------------
    let relay_base = match (&cfg.relay.url, bound) {
        (Some(_), _) => cfg.relay_url(),
        (None, Some(a)) if a.is_ipv6() => format!("http://[::1]:{}", a.port()),
        (None, Some(a)) => format!("http://127.0.0.1:{}", a.port()),
        (None, None) => cfg.loopback_url()?,
    };
    let relay_client = Arc::new(executor_relay_client(&relay_base, &node)?);
    if !opts.local_only {
        broker.set_relay(
            RelayIdentity { mailbox: MailboxId::Executor(node.executor_id.clone()), identity: node.identity.clone() },
            Arc::new(RelayOutbox::new(relay_client.clone())),
        );
    }
    let (stop_tx, stop_rx) = watch::channel(false);

    // ---- remote MCP -------------------------------------------------------------------
    let mcp_server = Arc::new(McpServer::new(McpServerConfig {
        experimental: cfg.node.experimental,
        lang,
        version: env!("CARGO_PKG_VERSION").to_string(),
    }));
    let base = cfg.base_url();
    let mcp_url = format!("{base}/mcp");
    let mut auth_servers = Vec::new();
    let link = crate::cloud::CloudLink::load(&data)?;
    if let Some(l) = &link {
        auth_servers.push(l.cloud_url.clone());
    }
    let mut hcfg = HttpConfig::new(HttpMode::Remote {
        resolver: Arc::new(crate::remote_mcp::NodeBearerResolver::new(broker.clone(), lang)),
        resource_metadata_url: format!("{base}/.well-known/oauth-protected-resource/mcp"),
        allowed_origins: cfg.mcp.allowed_origins.clone(),
    });
    hcfg.protected_resource_metadata = Some(aipass_mcp::http::protected_resource_metadata(&mcp_url, &auth_servers));
    let streamable = StreamableHttp::new(mcp_server, hcfg);

    // ---- router -----------------------------------------------------------------------
    let mut router = aipass_broker::router(BrokerState::new(broker.clone()));
    if cfg.sync.enabled {
        router = router.merge(sync_router(sync_state.clone()));
    }
    if cfg.relay.enabled {
        router = router.merge(relay_router(relay_state.clone()));
    }
    if cfg.mcp.enabled {
        router = router.merge(streamable.router());
    }
    if let Some(exe) = &executor {
        router = router.layer(axum::middleware::from_fn_with_state(
            ValidateState { broker: broker.clone(), executor: exe.clone() },
            validate_resource_config,
        ));
    }

    // ---- listeners --------------------------------------------------------------------
    let mut servers = Vec::new();
    let mut local_addr = None;
    if let Some(listener) = tcp_listener {
        local_addr = Some(listener.local_addr()?);
        servers.push(tokio::spawn(aipass_broker::serve_tcp(router.clone(), listener, shutdown_future(stop_rx.clone()))));
    }
    if let Some(sock) = &cfg.node.admin_socket {
        let sock = sock.clone();
        let r = router.clone().layer(axum::Extension(AdminSocketPeer));
        let sd = shutdown_future(stop_rx.clone());
        servers.push(tokio::spawn(async move { aipass_broker::serve_uds(r, &sock, UdsOptions { admin_peers: true }, sd).await }));
    }
    if let Some(sock) = &opts.connection_socket {
        let sock = sock.clone();
        let r = router.clone();
        let sd = shutdown_future(stop_rx.clone());
        servers.push(tokio::spawn(async move { aipass_broker::serve_uds(r, &sock, UdsOptions { admin_peers: false }, sd).await }));
    }

    // ---- background -------------------------------------------------------------------
    let sweeper = broker.spawn_background();
    if !opts.local_only {
        tasks.push(tokio::spawn(run_consumer(broker.clone(), executor.clone(), relay_client, node.executor_id.clone(), stop_rx.clone())));
    }
    let mut tunnel = None;
    if let Some(l) = &link
        && cfg.cloud.tunnel
    {
        let (h, fwd) = crate::cloud::spawn_tunnel(l, &node, broker.clone(), streamable.clone(), data.clone(), lang)?;
        tunnel = Some(h);
        tasks.push(fwd);
        tracing::info!(cloud = %l.cloud_url, "cloud tunnel enabled");
    }

    tracing::info!(
        executor_id = %node.executor_id,
        listen = ?local_addr,
        sync = cfg.sync.enabled,
        relay = cfg.relay.enabled,
        mcp = cfg.mcp.enabled,
        protection_level = ?cfg.executor.protection_level,
        "aipass-node started"
    );
    Ok(RunningNode { local_addr, broker, executor, identity: node, stop: stop_tx, servers, tasks, tunnel, _sweeper: sweeper })
}

#[derive(Clone)]
struct ValidateState {
    broker: Arc<Broker>,
    executor: Arc<Executor>,
}

/// Marker inserted on requests that arrived on the node's admin socket (mode 0600 inside a
/// 0700 directory, so only the owner — or root — can connect; the broker treats same-uid
/// peers there as the local admin).
#[derive(Debug, Clone, Copy)]
struct AdminSocketPeer;

/// Validate resource configs for this node's executor on `POST /v1/admin/resources` and
/// `PATCH /v1/admin/resources/{id}` before the broker stores them (unknown keys and
/// secrets in config are rejected — fail closed).
///
/// This layer wraps the broker router, so it runs *before* the broker authenticates the
/// request. Hence:
/// * the body is read with a hard cap (`max_body_bytes`, the broker's own limit) and an
///   oversized body is refused with 413 as soon as the cap is crossed — never buffered;
/// * the validation (and the resource lookup a PATCH needs) only runs for callers that
///   present a trusted credential (admin token, admin socket, or a valid device
///   signature — checked without consuming the nonce, which the broker records). Anyone
///   else is passed straight to the broker, which rejects them (401/403), so
///   unauthenticated callers learn nothing about resources or config validation.
async fn validate_resource_config(State(st): State<ValidateState>, req: Request, next: Next) -> Response {
    let path = req.uri().path().to_string();
    let method = req.method().clone();
    let is_create = method == http::Method::POST && path == "/v1/admin/resources";
    let patch_id = (method == http::Method::PATCH)
        .then(|| path.strip_prefix("/v1/admin/resources/").map(str::to_string))
        .flatten()
        .filter(|s| !s.contains('/'));
    if !is_create && patch_id.is_none() {
        return next.run(req).await;
    }
    let lang = aipass_sync_server::error::lang_of(req.headers());
    let (parts, body) = req.into_parts();
    let limit = st.broker.config().max_body_bytes;
    let bytes = match axum::body::to_bytes(body, limit).await {
        Ok(b) => b,
        Err(_) => {
            let mut resp = reject(
                ApiError::invalid_request("请求体过大或读取失败", "The request body is too large or could not be read.")
                    .with_detail("limit", limit as u64),
                lang,
            );
            *resp.status_mut() = http::StatusCode::PAYLOAD_TOO_LARGE;
            return resp;
        }
    };
    if !presents_trusted_credential(&st.broker, &parts, &bytes).await {
        return next.run(Request::from_parts(parts, Body::from(bytes))).await;
    }
    if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&bytes)
        && let Some(config) = v.get("config")
    {
        let ours = |exe: Option<&str>| exe.is_none_or(|e| e == st.executor.executor_id().as_str());
        let connector: Option<Connector> = if is_create {
            if ours(v.get("executor_id").and_then(|e| e.as_str())) {
                v.get("connector").and_then(|c| serde_json::from_value(c.clone()).ok())
            } else {
                None
            }
        } else {
            let id = patch_id.as_deref().and_then(|s| aipass_types::ids::ResourceId::parse(s).ok());
            match id {
                Some(id) => match st.broker.get_resource(&id).await {
                    Ok(r) if r.executor_id == *st.executor.executor_id() => Some(r.connector),
                    _ => None,
                },
                None => None,
            }
        };
        if let Some(c) = connector
            && let Err(e) = st.executor.validate_resource_config(c, config)
        {
            return reject(e, lang);
        }
    }
    next.run(Request::from_parts(parts, Body::from(bytes))).await
}

/// Whether the request carries a credential of principal class D or A (the classes the
/// broker accepts on the resource admin endpoints). Side-effect free: device signatures
/// are checked for skew and Ed25519 validity only; the broker re-verifies everything and
/// records the nonce. A `false` here never rejects a request — it only skips the
/// pre-validation.
async fn presents_trusted_credential(broker: &Broker, parts: &http::request::Parts, body: &[u8]) -> bool {
    use aipass_types::ids::PrincipalId;
    use aipass_types::signing::Authorization;
    let Some(value) = parts.headers.get(http::header::AUTHORIZATION) else {
        return parts.extensions.get::<AdminSocketPeer>().is_some();
    };
    let Ok(text) = value.to_str() else { return false };
    match Authorization::parse(text) {
        Ok(Authorization::Bearer(token)) => broker.verify_admin_token(&token),
        Ok(Authorization::Sig(h)) => {
            let Ok(PrincipalId::Device(id)) = h.principal() else { return false };
            let Ok(devices) = broker.list_devices().await else { return false };
            let Some(dev) = devices.devices.into_iter().find(|d| d.device.device_id == id && d.is_active_approver()) else {
                return false;
            };
            let path_and_query = parts.uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
            aipass_types::signing::verify_request(
                &h,
                &dev.device.sign_pk,
                parts.method.as_str(),
                path_and_query,
                body,
                aipass_types::time::unix_now(),
            )
            .is_ok()
        }
        Err(_) => false,
    }
}

fn reject(err: ApiError, lang: Lang) -> Response {
    aipass_sync_server::HttpError { err, lang }.into_response()
}
