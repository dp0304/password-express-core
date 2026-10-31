// SPDX-License-Identifier: Apache-2.0
//! TunnelClient against an in-test WebSocket server playing the cloud gateway.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use aipass_client::tunnel::{
    AuthFrame, ConnectionCreateFrame, ConnectionCreated, McpFrame, McpResponse,
    RemoteConnectionStatus, TunnelClient, TunnelConfig, TunnelHandler, TunnelState,
};
use aipass_crypto::Ed25519Keypair;
use aipass_types::{ApiError, ConnectionId, ErrorCode, ExecutorId};
use async_trait::async_trait;
use futures::{SinkExt, StreamExt};
use serde_json::{Value, json};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;

#[derive(Default)]
struct Recorder {
    events: Mutex<Vec<String>>,
}

#[async_trait]
impl TunnelHandler for Recorder {
    async fn on_mcp(&self, frame: McpFrame) -> McpResponse {
        self.events.lock().unwrap().push(format!("mcp:{}", frame.connection_id));
        let body: Value = serde_json::from_slice(&frame.body_bytes()).unwrap_or(Value::Null);
        McpResponse {
            status: 200,
            headers: [("mcp-session-id".to_string(), "sess-1".to_string())].into(),
            body: json!({"jsonrpc": "2.0", "id": body["id"], "result": {}}),
        }
    }
    async fn on_connection_create(&self, frame: ConnectionCreateFrame) -> Result<ConnectionCreated, ApiError> {
        self.events.lock().unwrap().push(format!("create:{}", frame.connection.display_name));
        if frame.connection.display_name == "reject me" {
            return Err(ApiError::new(ErrorCode::Forbidden));
        }
        Ok(ConnectionCreated {
            connection_id: ConnectionId::parse("conn_01jbz3k6w8a7m2q4t5v9x0y1z4").unwrap(),
            pairing_code: "123456".into(),
        })
    }
    async fn on_connection_revoke(&self, connection_id: ConnectionId) {
        self.events.lock().unwrap().push(format!("revoke:{connection_id}"));
    }
    async fn on_policy_org(&self, policy: Value) {
        self.events.lock().unwrap().push(format!("policy:{}", policy["max_grant_ttl_seconds"]));
    }
    async fn on_state(&self, state: TunnelState) {
        self.events.lock().unwrap().push(format!("state:{state:?}"));
    }
}

/// Server events: (connection index, frame JSON).
type ServerEvents = mpsc::UnboundedReceiver<(usize, Value)>;

/// A WebSocket "cloud": verifies the auth frame of every connection, forwards every inbound
/// text frame to the test, and runs `script` for connection `n` (by index).
async fn cloud(
    node_pk: [u8; 32],
    scripts: Vec<Vec<Value>>,
    close_after_script: Vec<bool>,
    silent: bool,
) -> (String, ServerEvents) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        let mut n = 0usize;
        loop {
            let Ok((stream, _)) = listener.accept().await else { return };
            let idx = n;
            n += 1;
            let tx = tx.clone();
            let script = scripts.get(idx).cloned().unwrap_or_default();
            let close = close_after_script.get(idx).copied().unwrap_or(false);
            tokio::spawn(async move {
                let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
                let Some(Ok(Message::Text(first))) = ws.next().await else { return };
                let auth: AuthFrame = serde_json::from_str(first.as_str()).unwrap();
                auth.verify(&node_pk, aipass_types::time::unix_now()).unwrap();
                tx.send((idx, serde_json::to_value(&auth).unwrap())).unwrap();
                if !silent {
                    ws.send(Message::text(json!({"type": "auth.ok"}).to_string())).await.unwrap();
                }
                for frame in script {
                    ws.send(Message::text(frame.to_string())).await.unwrap();
                }
                if close {
                    tokio::time::sleep(Duration::from_millis(400)).await;
                    let _ = ws.close(None).await;
                    return;
                }
                while let Some(Ok(msg)) = ws.next().await {
                    if let Message::Text(t) = msg {
                        let v: Value = serde_json::from_str(t.as_str()).unwrap();
                        if !silent && v["type"] == "ping" {
                            ws.send(Message::text(json!({"type": "pong"}).to_string())).await.unwrap();
                        }
                        tx.send((idx, v)).unwrap();
                    }
                }
            });
        }
    });
    (format!("ws://{addr}/v1/tunnel"), rx)
}

struct Inbox {
    rx: ServerEvents,
    buf: Vec<(usize, Value)>,
}

impl Inbox {
    fn new(rx: ServerEvents) -> Self {
        Self { rx, buf: Vec::new() }
    }
}

/// Take the first frame of type `ty` (buffering others, so arrival order does not matter).
async fn next_of_type(inbox: &mut Inbox, ty: &str) -> (usize, Value) {
    if let Some(pos) = inbox.buf.iter().position(|(_, v)| v["type"] == ty) {
        return inbox.buf.remove(pos);
    }
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let (i, v) = inbox.rx.recv().await.expect("server channel closed");
            if v["type"] == ty {
                return (i, v);
            }
            inbox.buf.push((i, v));
        }
    })
    .await
    .unwrap_or_else(|_| panic!("timed out waiting for {ty}"))
}

#[tokio::test]
async fn serves_frames_sends_node_frames_and_reconnects() {
    let node_kp = Arc::new(Ed25519Keypair::generate());
    let node_id = ExecutorId::generate();
    let cid = "conn_01jbz3k6w8a7m2q4t5v9x0y1z4";
    let script = vec![
        json!({"type": "ping"}),
        json!({"type": "mcp", "id": "r1", "connection_id": cid, "session_id": "sess-1",
               "body": {"jsonrpc": "2.0", "id": 5, "method": "ping"}}),
        json!({"type": "connection.create", "id": "c1", "connection": {
            "host_type": "chatgpt", "display_name": "ChatGPT (self-declared)",
            "oauth_client_id": "oac_01jbz3k6w8a7m2q4t5v9x0y1z4", "user_id": "usr_01jbz3k6w8a7m2q4t5v9x0y1z4"}}),
        json!({"type": "connection.create", "id": "c2", "connection": {
            "host_type": "chatgpt", "display_name": "reject me",
            "oauth_client_id": "oac_01jbz3k6w8a7m2q4t5v9x0y1z4", "user_id": "usr_01jbz3k6w8a7m2q4t5v9x0y1z4"}}),
        json!({"type": "mcp", "id": "bad"}),
        json!({"type": "connection.revoke", "connection_id": cid}),
        json!({"type": "policy.org", "policy": {"max_grant_ttl_seconds": 900}}),
        json!({"type": "something.new"}),
    ];
    let (url, rx) = cloud(node_kp.public_key(), vec![script], vec![false], false).await;
    let mut rx = Inbox::new(rx);
    let recorder = Arc::new(Recorder::default());
    let mut cfg = TunnelConfig::new(url.parse().unwrap(), node_id.clone(), node_kp.clone());
    cfg.ping_interval = Duration::from_millis(300);
    cfg.backoff_min = Duration::from_millis(50);
    cfg.backoff_max = Duration::from_millis(200);
    let client = TunnelClient::new(cfg, recorder.clone());
    let mut sender = client.sender();
    let handle = client.spawn();

    let (_, auth) = next_of_type(&mut rx, "auth").await;
    assert_eq!(auth["node_id"], node_id.as_str());
    assert_eq!(sender.wait_for(TunnelState::Connected).await, TunnelState::Connected);

    let (_, pong) = next_of_type(&mut rx, "pong").await;
    assert_eq!(pong, json!({"type": "pong"}));
    let (_, res) = next_of_type(&mut rx, "mcp_result").await;
    assert_eq!(res["id"], "r1");
    assert_eq!(res["status"], 200);
    assert_eq!(res["headers"]["mcp-session-id"], "sess-1");
    assert_eq!(res["body"]["id"], 5);
    let (_, created) = next_of_type(&mut rx, "connection.created").await;
    assert_eq!(created["id"], "c1");
    assert_eq!(created["pairing_code"], "123456");
    // errors: rejected create and malformed mcp frame
    let (_, e1) = next_of_type(&mut rx, "error").await;
    let (_, e2) = next_of_type(&mut rx, "error").await;
    let mut ids = vec![e1["id"].clone(), e2["id"].clone()];
    ids.sort_by_key(|v| v.to_string());
    assert_eq!(ids, vec![json!("bad"), json!("c2")]);
    // client-initiated JSON ping
    next_of_type(&mut rx, "ping").await;

    // node-initiated frames
    sender
        .send_connection_status(&ConnectionId::parse(cid).unwrap(), RemoteConnectionStatus::Active)
        .unwrap();
    let (_, st) = next_of_type(&mut rx, "connection.status").await;
    assert_eq!(st["status"], "active");
    sender.send_audit_batch(vec![json!({"action": "operation.succeeded", "seq": 1})]).unwrap();
    let (_, batch) = next_of_type(&mut rx, "audit.batch").await;
    assert_eq!(batch["events"][0]["seq"], 1);

    tokio::time::sleep(Duration::from_millis(200)).await;
    {
        let ev = recorder.events.lock().unwrap().clone();
        assert!(ev.contains(&format!("revoke:{cid}")), "{ev:?}");
        assert!(ev.contains(&"policy:900".to_string()), "{ev:?}");
        assert!(ev.contains(&format!("mcp:{cid}")), "{ev:?}");
    }
    handle.shutdown().await;
    assert_eq!(sender.state(), TunnelState::Stopped);
}

#[tokio::test]
async fn reconnects_after_close_and_after_idle_timeout() {
    let node_kp = Arc::new(Ed25519Keypair::generate());
    let node_id = ExecutorId::generate();
    // connection 0 is closed by the server; connection 1 stays open.
    let (url, rx) = cloud(node_kp.public_key(), vec![vec![], vec![]], vec![true, false], false).await;
    let mut rx = Inbox::new(rx);
    let recorder = Arc::new(Recorder::default());
    let mut cfg = TunnelConfig::new(url.parse().unwrap(), node_id.clone(), node_kp.clone());
    cfg.backoff_min = Duration::from_millis(50);
    let handle = TunnelClient::new(cfg, recorder.clone()).spawn();
    let (i0, a0) = next_of_type(&mut rx, "auth").await;
    let (i1, a1) = next_of_type(&mut rx, "auth").await;
    assert_eq!((i0, i1), (0, 1));
    assert_ne!(a0["nonce"], a1["nonce"], "every connect uses a fresh nonce");
    handle.shutdown().await;

    // a silent cloud (never answers) is treated as a dead link after the idle timeout
    let (url, rx) = cloud(node_kp.public_key(), vec![], vec![], true).await;
    let mut rx = Inbox::new(rx);
    let mut cfg = TunnelConfig::new(url.parse().unwrap(), node_id, node_kp);
    cfg.ping_interval = Duration::from_millis(100);
    cfg.idle_timeout = Duration::from_millis(400);
    cfg.backoff_min = Duration::from_millis(50);
    let handle = TunnelClient::new(cfg, Arc::new(Recorder::default())).spawn();
    let (j0, _) = next_of_type(&mut rx, "auth").await;
    let (j1, _) = next_of_type(&mut rx, "auth").await;
    assert_eq!((j0, j1), (0, 1));
    handle.shutdown().await;
    let ev = recorder.events.lock().unwrap().clone();
    assert!(ev.iter().any(|e| e == "state:Connected"));
}

#[tokio::test]
async fn unreachable_cloud_backs_off_and_stops_cleanly() {
    // nothing listens on this port
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    let mut cfg = TunnelConfig::new(
        format!("ws://{addr}/v1/tunnel").parse().unwrap(),
        ExecutorId::generate(),
        Arc::new(Ed25519Keypair::generate()),
    );
    cfg.backoff_min = Duration::from_millis(20);
    cfg.backoff_max = Duration::from_millis(80);
    let client = TunnelClient::new(cfg, Arc::new(Recorder::default()));
    let sender = client.sender();
    let handle = client.spawn();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_ne!(sender.state(), TunnelState::Connected);
    // frames queue while disconnected
    sender.send_audit_batch(vec![]).unwrap();
    tokio::time::timeout(Duration::from_secs(5), handle.shutdown()).await.unwrap();
    assert_eq!(sender.state(), TunnelState::Stopped);
}

/// Network smoke test of the rustls (aws-lc-rs) `wss://` path against a public echo server.
/// Ignored by default (needs Internet): `cargo test -p aipass-client --test tunnel -- --ignored`.
#[tokio::test]
#[ignore]
async fn wss_tls_smoke_against_public_echo_server() {
    let mut cfg = TunnelConfig::new(
        "wss://echo.websocket.org/v1/tunnel".parse().unwrap(),
        ExecutorId::generate(),
        Arc::new(Ed25519Keypair::generate()),
    );
    cfg.connect_timeout = Duration::from_secs(15);
    let client = TunnelClient::new(cfg, Arc::new(Recorder::default()));
    let mut sender = client.sender();
    let handle = client.spawn();
    let state = tokio::time::timeout(Duration::from_secs(20), sender.wait_for(TunnelState::Connected))
        .await
        .expect("TLS WebSocket handshake did not complete");
    assert_eq!(state, TunnelState::Connected);
    handle.shutdown().await;
}
