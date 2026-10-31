// SPDX-License-Identifier: Apache-2.0
//! Streamable HTTP transport: sessions, protocol-version header, Origin/Host validation
//! (local mode), Bearer + `WWW-Authenticate: Bearer resource_metadata=…` (remote mode).

mod common;

use std::net::SocketAddr;
use std::sync::Arc;

use aipass_client::testing::MockBroker;
use aipass_client::{Auth, BrokerClient, BrokerEndpoint};
use aipass_mcp::http::{
    BearerResolver, BrokerBearerResolver, HttpConfig, HttpMode, McpHttpRequest, Principal,
    StreamableHttp, protected_resource_metadata,
};
use aipass_mcp::{McpServer, McpServerConfig};
use aipass_types::{ApiError, ConnectionId};
use async_trait::async_trait;
use common::FakeBroker;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const ACCEPT: &str = "application/json, text/event-stream";

async fn serve(config: HttpConfig) -> (SocketAddr, Arc<StreamableHttp>, tokio::task::JoinHandle<()>) {
    let server = Arc::new(McpServer::new(McpServerConfig::default()));
    let transport = StreamableHttp::new(server, config);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = transport.router();
    let join = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (addr, transport, join)
}

async fn local(origins: Vec<String>) -> (SocketAddr, Arc<StreamableHttp>, tokio::task::JoinHandle<()>) {
    // bind first to learn the port, then build the config with the right Host allow-list
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let config = HttpConfig::new(HttpMode::Local {
        broker: Arc::new(FakeBroker::new()),
        allowed_origins: origins,
        allowed_hosts: HttpConfig::loopback_hosts(addr.port()),
    });
    let server = Arc::new(McpServer::new(McpServerConfig::default()));
    let transport = StreamableHttp::new(server, config);
    let app = transport.router();
    let join = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (addr, transport, join)
}

fn init_body(v: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": v, "capabilities": {}, "clientInfo": {"name": "t", "version": "1"}}})
}

async fn post(c: &reqwest::Client, url: &str, body: &Value, headers: &[(&str, &str)]) -> reqwest::Response {
    let mut r = c.post(url).header("content-type", "application/json").header("accept", ACCEPT);
    for (k, v) in headers {
        r = r.header(*k, *v);
    }
    r.body(body.to_string()).send().await.unwrap()
}

#[tokio::test]
async fn local_sessions_versions_and_methods() {
    let (addr, transport, join) = local(vec![]).await;
    let url = format!("http://{addr}/mcp");
    let c = reqwest::Client::new();

    let r = post(&c, &url, &init_body("2025-11-25"), &[]).await;
    assert_eq!(r.status(), 200);
    assert!(r.headers()["content-type"].to_str().unwrap().starts_with("application/json"));
    let sid = r.headers()["mcp-session-id"].to_str().unwrap().to_owned();
    assert!(sid.len() >= 32 && sid.bytes().all(|b| (0x21..=0x7e).contains(&b)));
    let v: Value = r.json().await.unwrap();
    assert_eq!(v["result"]["protocolVersion"], "2025-11-25");
    assert_eq!(transport.session_count(), 1);

    let list = json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"});
    // no session → 400; unknown → 404
    assert_eq!(post(&c, &url, &list, &[]).await.status(), 400);
    assert_eq!(post(&c, &url, &list, &[("mcp-session-id", "nope")]).await.status(), 404);
    // with session (+ correct version header) → 200
    let r = post(&c, &url, &list, &[("mcp-session-id", &sid), ("mcp-protocol-version", "2025-11-25")]).await;
    assert_eq!(r.status(), 200);
    let v: Value = r.json().await.unwrap();
    assert_eq!(v["result"]["tools"].as_array().unwrap().len(), 7);
    // mismatched or unsupported version header → 400
    assert_eq!(post(&c, &url, &list, &[("mcp-session-id", &sid), ("mcp-protocol-version", "2025-06-18")]).await.status(), 400);
    assert_eq!(post(&c, &url, &list, &[("mcp-session-id", &sid), ("mcp-protocol-version", "1.0")]).await.status(), 400);
    // notification → 202, no body
    let r = post(&c, &url, &json!({"jsonrpc": "2.0", "method": "notifications/initialized"}), &[("mcp-session-id", &sid)]).await;
    assert_eq!(r.status(), 202);
    assert!(r.bytes().await.unwrap().is_empty());
    // batches are rejected for 2025-11-25 (JSON-RPC error, HTTP 200)
    let r = post(&c, &url, &json!([{"jsonrpc": "2.0", "id": 3, "method": "ping"}]), &[("mcp-session-id", &sid)]).await;
    let v: Value = r.json().await.unwrap();
    assert_eq!(v["error"]["code"], -32600);
    // tools/call through HTTP
    let r = post(&c, &url, &json!({"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "resources_list", "arguments": {}}}), &[("mcp-session-id", &sid)]).await;
    let v: Value = r.json().await.unwrap();
    assert_eq!(v["result"]["isError"], false);
    // SSE-only clients get a single-event stream
    let r = c.post(&url).header("content-type", "application/json").header("accept", "text/event-stream").header("mcp-session-id", &sid)
        .body(json!({"jsonrpc": "2.0", "id": 5, "method": "ping"}).to_string()).send().await.unwrap();
    assert_eq!(r.status(), 200);
    assert!(r.headers()["content-type"].to_str().unwrap().starts_with("text/event-stream"));
    let text = r.text().await.unwrap();
    assert!(text.starts_with("event: message\ndata: {"), "{text}");
    // bad Accept / Content-Type / JSON
    let r = c.post(&url).header("content-type", "application/json").header("accept", "text/html").header("mcp-session-id", &sid).body("{}").send().await.unwrap();
    assert_eq!(r.status(), 406);
    let r = c.post(&url).header("content-type", "text/plain").header("mcp-session-id", &sid).body("{}").send().await.unwrap();
    assert_eq!(r.status(), 415);
    let r = c.post(&url).header("content-type", "application/json").header("mcp-session-id", &sid).body("{oops").send().await.unwrap();
    assert_eq!(r.status(), 400);
    let v: Value = r.json().await.unwrap();
    assert_eq!(v["error"]["code"], -32700);
    // GET → 405 with Allow
    let r = c.get(&url).header("accept", "text/event-stream").send().await.unwrap();
    assert_eq!(r.status(), 405);
    assert!(r.headers()["allow"].to_str().unwrap().contains("POST"));
    // DELETE ends the session
    assert_eq!(c.delete(&url).send().await.unwrap().status(), 400);
    assert_eq!(c.delete(&url).header("mcp-session-id", &sid).send().await.unwrap().status(), 204);
    assert_eq!(post(&c, &url, &list, &[("mcp-session-id", &sid)]).await.status(), 404);
    assert_eq!(c.delete(&url).header("mcp-session-id", &sid).send().await.unwrap().status(), 404);
    assert_eq!(transport.session_count(), 0);
    join.abort();
}

#[tokio::test]
async fn local_mode_validates_origin_and_host() {
    let (addr, _t, join) = local(vec!["http://localhost:6274".into()]).await;
    let url = format!("http://{addr}/mcp");
    let c = reqwest::Client::new();
    let r = post(&c, &url, &init_body("2025-06-18"), &[("origin", "https://evil.example")]).await;
    assert_eq!(r.status(), 403);
    let v: Value = r.json().await.unwrap();
    assert!(v.get("id").is_some_and(Value::is_null));
    let r = post(&c, &url, &init_body("2025-06-18"), &[("origin", "http://localhost:6274")]).await;
    assert_eq!(r.status(), 200);
    // DNS rebinding: the Host header names an attacker domain → 403 (raw request so the
    // client cannot normalise the Host header)
    let body = init_body("2025-06-18").to_string();
    let raw = format!(
        "POST /mcp HTTP/1.1\r\nHost: rebind.evil.example:{}\r\nContent-Type: application/json\r\nAccept: {ACCEPT}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        addr.port(),
        body.len()
    );
    let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
    s.write_all(raw.as_bytes()).await.unwrap();
    let mut resp = String::new();
    s.read_to_string(&mut resp).await.unwrap();
    assert!(resp.starts_with("HTTP/1.1 403"), "{resp}");
    join.abort();
}

struct Tokens;

#[async_trait]
impl BearerResolver for Tokens {
    async fn resolve(&self, token: &str) -> Result<Principal, ApiError> {
        match token {
            "aipc_alice" | "aipc_bob" => Ok(Principal {
                key: token.to_owned(),
                broker: Arc::new(FakeBroker::new()),
            }),
            _ => Err(ApiError::identity_unverified()),
        }
    }
}

#[tokio::test]
async fn remote_mode_bearer_and_session_binding() {
    let meta_url = "https://node.example.com/.well-known/oauth-protected-resource/mcp";
    let mut cfg = HttpConfig::new(HttpMode::Remote {
        resolver: Arc::new(Tokens),
        resource_metadata_url: meta_url.into(),
        allowed_origins: vec![],
    });
    cfg.protected_resource_metadata = Some(protected_resource_metadata("https://node.example.com/mcp", &["https://cloud.aipass.example".into()]));
    let (addr, _t, join) = serve(cfg).await;
    let url = format!("http://{addr}/mcp");
    let c = reqwest::Client::new();
    let r = post(&c, &url, &init_body("2025-06-18"), &[]).await;
    assert_eq!(r.status(), 401);
    assert_eq!(
        r.headers()["www-authenticate"].to_str().unwrap(),
        format!("Bearer resource_metadata=\"{meta_url}\"")
    );
    let r = post(&c, &url, &init_body("2025-06-18"), &[("authorization", "Bearer aipc_mallory")]).await;
    assert_eq!(r.status(), 401);
    let wa = r.headers()["www-authenticate"].to_str().unwrap().to_owned();
    assert!(wa.contains("error=\"invalid_token\"") && wa.contains("resource_metadata="), "{wa}");
    let r = post(&c, &url, &init_body("2025-06-18"), &[("authorization", "Basic abc")]).await;
    assert_eq!(r.status(), 401);
    let r = post(&c, &url, &init_body("2025-06-18"), &[("authorization", "Bearer aipc_alice")]).await;
    assert_eq!(r.status(), 200);
    let sid = r.headers()["mcp-session-id"].to_str().unwrap().to_owned();
    let list = json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"});
    let ok = post(&c, &url, &list, &[("authorization", "Bearer aipc_alice"), ("mcp-session-id", &sid), ("mcp-protocol-version", "2025-06-18")]).await;
    assert_eq!(ok.status(), 200);
    // another principal cannot use Alice's session id (IDs are not capabilities)
    let stolen = post(&c, &url, &list, &[("authorization", "Bearer aipc_bob"), ("mcp-session-id", &sid)]).await;
    assert_eq!(stolen.status(), 404);
    assert_eq!(c.delete(&url).header("authorization", "Bearer aipc_bob").header("mcp-session-id", &sid).send().await.unwrap().status(), 404);
    // Origin, when present, must be allow-listed in remote mode too
    let r = post(&c, &url, &list, &[("authorization", "Bearer aipc_alice"), ("mcp-session-id", &sid), ("origin", "https://evil.example")]).await;
    assert_eq!(r.status(), 403);
    // protected-resource metadata
    let m: Value = c.get(format!("http://{addr}/.well-known/oauth-protected-resource/mcp")).send().await.unwrap().json().await.unwrap();
    assert_eq!(m["resource"], "https://node.example.com/mcp");
    assert_eq!(m["scopes_supported"], json!(["aipass.tools"]));
    join.abort();
}

#[tokio::test]
async fn remote_mode_forwards_connection_tokens_to_the_broker() {
    let mock = MockBroker::new();
    let (baddr, bjoin) = mock.serve_tcp().await.unwrap();
    let conn = ConnectionId::generate();
    mock.add_token(&conn, "aipc_valid-connection-token");
    let client = BrokerClient::new(BrokerEndpoint::parse(&format!("http://{baddr}")).unwrap(), Auth::None).unwrap();
    let cfg = HttpConfig::new(HttpMode::Remote {
        resolver: Arc::new(BrokerBearerResolver::new(client)),
        resource_metadata_url: "https://node.example.com/.well-known/oauth-protected-resource/mcp".into(),
        allowed_origins: vec![],
    });
    let (addr, _t, join) = serve(cfg).await;
    let url = format!("http://{addr}/mcp");
    let c = reqwest::Client::new();
    assert_eq!(post(&c, &url, &init_body("2025-11-25"), &[("authorization", "Bearer aipc_wrong-token-xyz")]).await.status(), 401);
    assert_eq!(post(&c, &url, &init_body("2025-11-25"), &[("authorization", "Bearer not-a-connection-token")]).await.status(), 401);
    let r = post(&c, &url, &init_body("2025-11-25"), &[("authorization", "Bearer aipc_valid-connection-token")]).await;
    assert_eq!(r.status(), 200);
    let sid = r.headers()["mcp-session-id"].to_str().unwrap().to_owned();
    let r = post(&c, &url, &json!({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "resources_list", "arguments": {}}}),
        &[("authorization", "Bearer aipc_valid-connection-token"), ("mcp-session-id", &sid)]).await;
    let v: Value = r.json().await.unwrap();
    assert_eq!(v["result"]["isError"], false);
    assert_eq!(v["result"]["structuredContent"]["resources"].as_array().unwrap().len(), 1);
    assert!(mock.seen().iter().any(|s| s.principal.as_deref() == Some(conn.as_str())));
    join.abort();
    bjoin.abort();
}

#[tokio::test]
async fn handle_for_principal_serves_tunnel_frames() {
    let server = Arc::new(McpServer::new(McpServerConfig::default()));
    let t = StreamableHttp::new(server, HttpConfig::new(HttpMode::Remote {
        resolver: Arc::new(Tokens),
        resource_metadata_url: "https://x/.well-known/oauth-protected-resource/mcp".into(),
        allowed_origins: vec![],
    }));
    let p = Principal {
        key: "conn_01jbz3k6w8a7m2q4t5v9x0y1z4".into(),
        broker: Arc::new(FakeBroker::new()),
    };
    let body = init_body("2025-06-18").to_string();
    let r = t.handle_for_principal(&p, McpHttpRequest { method: "POST", body: body.as_bytes(), ..Default::default() }).await;
    assert_eq!(r.status, 200);
    let sid = r.header("mcp-session-id").unwrap().to_owned();
    assert_eq!(r.body_json().unwrap()["result"]["protocolVersion"], "2025-06-18");
    let ping = json!({"jsonrpc": "2.0", "id": 9, "method": "ping"}).to_string();
    let r = t.handle_for_principal(&p, McpHttpRequest { method: "POST", session_id: Some(&sid), body: ping.as_bytes(), ..Default::default() }).await;
    assert_eq!(r.body_json().unwrap()["id"], 9);
    let other = Principal { key: "conn_other".into(), broker: Arc::new(FakeBroker::new()) };
    let r = t.handle_for_principal(&other, McpHttpRequest { method: "POST", session_id: Some(&sid), body: ping.as_bytes(), ..Default::default() }).await;
    assert_eq!(r.status, 404);
    // the same through a tunnel frame
    let frame: aipass_client::tunnel::McpFrame = serde_json::from_value(json!({
        "id": "r1", "connection_id": "conn_01jbz3k6w8a7m2q4t5v9x0y1z4", "session_id": sid,
        "protocol_version": "2025-06-18", "body": {"jsonrpc": "2.0", "id": 10, "method": "tools/list"}
    })).unwrap();
    let res = t.handle_tunnel_frame(&p, &frame).await;
    assert_eq!(res.status, 200);
    assert_eq!(res.body["result"]["tools"].as_array().unwrap().len(), 7);
    let note: aipass_client::tunnel::McpFrame = serde_json::from_value(json!({
        "id": "r2", "connection_id": "conn_01jbz3k6w8a7m2q4t5v9x0y1z4", "session_id": sid,
        "body": "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}"
    })).unwrap();
    let res = t.handle_tunnel_frame(&p, &note).await;
    assert_eq!(res.status, 202);
    assert!(res.body.is_null());
    let r = t.handle_for_principal(&p, McpHttpRequest { method: "DELETE", session_id: Some(&sid), ..Default::default() }).await;
    assert_eq!(r.status, 204);
    let del: aipass_client::tunnel::McpFrame = serde_json::from_value(json!({
        "id": "r3", "connection_id": "conn_01jbz3k6w8a7m2q4t5v9x0y1z4", "session_id": sid, "http_method": "DELETE"
    })).unwrap();
    assert_eq!(t.handle_tunnel_frame(&p, &del).await.status, 404);
}

#[tokio::test]
async fn session_limits_evict_oldest() {
    let server = Arc::new(McpServer::new(McpServerConfig::default()));
    let mut cfg = HttpConfig::new(HttpMode::Remote {
        resolver: Arc::new(Tokens),
        resource_metadata_url: "https://x/m".into(),
        allowed_origins: vec![],
    });
    cfg.max_sessions_per_principal = 2;
    let t = StreamableHttp::new(server, cfg);
    let p = Principal { key: "k".into(), broker: Arc::new(FakeBroker::new()) };
    let body = init_body("2025-11-25").to_string();
    let mut ids = Vec::new();
    for _ in 0..3 {
        let r = t.handle_for_principal(&p, McpHttpRequest { method: "POST", body: body.as_bytes(), ..Default::default() }).await;
        ids.push(r.header("mcp-session-id").unwrap().to_owned());
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    assert_eq!(t.session_count(), 2);
    let ping = json!({"jsonrpc": "2.0", "id": 1, "method": "ping"}).to_string();
    let first = t.handle_for_principal(&p, McpHttpRequest { method: "POST", session_id: Some(&ids[0]), body: ping.as_bytes(), ..Default::default() }).await;
    assert_eq!(first.status, 404, "oldest session evicted");
    let last = t.handle_for_principal(&p, McpHttpRequest { method: "POST", session_id: Some(&ids[2]), body: ping.as_bytes(), ..Default::default() }).await;
    assert_eq!(last.status, 200);
}
