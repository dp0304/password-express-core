// SPDX-License-Identifier: Apache-2.0
//! Remote MCP via the cloud tunnel: `connection.create` yields a *pending* connection with
//! a pairing code; MCP frames are refused until the user approves it on the desktop; then
//! `initialize` and `tools/list` are served by the in-process MCP handler.

use std::sync::Arc;

use aipass_client::tunnel::{ConnectionCreateFrame, McpFrame, TunnelHandler};
use aipass_crypto::password::Argon2Params;
use aipass_desktop_lib::core::{AppCore, CoreOptions, NullSink};
use aipass_desktop_lib::paths::AppPaths;
use aipass_desktop_lib::tunnel::DesktopTunnelHandler;
use aipass_types::Lang;
use aipass_types::models::AllowedProjects;
use serde_json::json;

#[tokio::test]
async fn tunnel_frames_need_an_approved_remote_connection() {
    let dir = tempfile::tempdir().unwrap();
    let core = AppCore::open(CoreOptions {
        paths: AppPaths::new(dir.path().join("home")),
        platform: aipass_types::vault::Platform::Macos,
        app_version: "0.1.0-test".into(),
        argon2: Argon2Params::INSECURE_FAST_FOR_TESTS_ONLY,
        serve_broker_socket: false,
        store_factory: None,
        sink: Arc::new(NullSink),
    })
    .unwrap();
    let input = serde_json::from_value(json!({
        "device_name": "Mac", "unlock_password": "correct horse battery",
        "storage": {"kind": "local", "path": dir.path().join("s").display().to_string()},
    }))
    .unwrap();
    core.create_vault(input).await.unwrap();
    let node = core.node().await.unwrap();
    let h = DesktopTunnelHandler::new(node.broker.clone(), "https://cloud.aipass.example", "0.1.0", Lang::ZhCn);

    let create: ConnectionCreateFrame = serde_json::from_value(json!({
        "id": "f1", "connection": {"host_type": "chatgpt", "display_name": "ChatGPT", "oauth_client_id": "oac_x", "user_id": "usr_x"}
    }))
    .unwrap();
    let created = h.on_connection_create(create).await.unwrap();
    assert_eq!(created.pairing_code.len(), 6);

    let init = |id: &str| -> McpFrame {
        serde_json::from_value(json!({
            "id": id, "connection_id": created.connection_id, "protocol_version": "2025-06-18",
            "body": {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t", "version": "1"}}}
        }))
        .unwrap()
    };
    let refused = h.on_mcp(init("m1")).await;
    assert_eq!(refused.status, 403, "pending connections are not served");

    // CLI-01: approving a connection needs fresh presence, not just an unlocked vault.
    assert_eq!(core.approve_connection(&created.connection_id, AllowedProjects::All, None).await.unwrap_err().code, "REAUTH_REQUIRED");
    assert_eq!(core.approve_connection(&created.connection_id, AllowedProjects::All, Some(&"nope".into())).await.unwrap_err().code, "UNAUTHENTICATED");
    assert_eq!(h.on_mcp(init("m1b")).await.status, 403, "still pending after refused approvals");
    core.approve_connection(&created.connection_id, AllowedProjects::All, Some(&"correct horse battery".into())).await.unwrap();
    let ok = h.on_mcp(init("m2")).await;
    assert_eq!(ok.status, 200, "{:?}", ok.body);
    assert_eq!(ok.body["result"]["protocolVersion"], "2025-06-18");
    assert!(ok.body["result"]["serverInfo"].is_object());

    // A local (non-remote) connection id cannot be driven through the tunnel.
    let local = node
        .broker
        .create_connection(&aipass_broker::Actor::System, aipass_broker::NewConnection {
            host_type: aipass_types::models::HostType::Codex, display_name: "Codex".into(),
            transport: aipass_types::models::Transport::Stdio, allowed_projects: AllowedProjects::All, public_key: None,
        })
        .await
        .unwrap();
    let mut f = init("m3");
    f.connection_id = local.connection.connection_id.clone();
    assert_eq!(h.on_mcp(f).await.status, 403);

    h.on_connection_revoke(created.connection_id.clone()).await;
    assert_eq!(h.on_mcp(init("m4")).await.status, 403);
    core.shutdown().await;
}
