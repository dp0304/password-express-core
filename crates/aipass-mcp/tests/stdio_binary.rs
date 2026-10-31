// SPDX-License-Identifier: Apache-2.0
//! stdio framing: spawn the built `aipass-mcp` binary against the in-process mock broker
//! (real AIPass-Sig verification, TCP and Unix socket) and check that stdout carries only
//! newline-delimited JSON-RPC while logs go to stderr — and that no secret leaks.

use std::collections::HashMap;
use std::process::Stdio;
use std::time::Duration;

use aipass_client::testing::MockBroker;
use aipass_client::{ConnectionKey, ConnectionKeyMeta, KeyStore};
use aipass_crypto::{Ed25519Keypair, b64u};
use aipass_types::models::HostType;
use aipass_types::{ApprovalRequestId, ConnectionId};
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, Command};

struct Bridge {
    child: Child,
    stdin: ChildStdin,
    lines: tokio::io::Lines<BufReader<tokio::process::ChildStdout>>,
    responses: HashMap<String, Value>,
    all_lines: Vec<String>,
}

impl Bridge {
    fn spawn(home: &std::path::Path, broker_url: &str, extra: &[&str]) -> Bridge {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_aipass-mcp"));
        cmd.arg("stdio")
            .args(extra)
            .env("AIPASS_HOME", home)
            .env("AIPASS_BROKER_URL", broker_url)
            .env("AIPASS_LOG", "debug")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        let mut child = cmd.spawn().expect("spawn aipass-mcp");
        let stdin = child.stdin.take().unwrap();
        let lines = BufReader::new(child.stdout.take().unwrap()).lines();
        Bridge {
            child,
            stdin,
            lines,
            responses: HashMap::new(),
            all_lines: Vec::new(),
        }
    }

    async fn send_raw(&mut self, line: &str) {
        self.stdin.write_all(line.as_bytes()).await.unwrap();
        self.stdin.write_all(b"\n").await.unwrap();
        self.stdin.flush().await.unwrap();
    }

    async fn send(&mut self, v: Value) {
        self.send_raw(&v.to_string()).await;
    }

    /// Wait for the response with `id` (as a JSON string key).
    async fn response(&mut self, id: Value) -> Value {
        let key = id.to_string();
        let fut = async {
            loop {
                if let Some(v) = self.responses.remove(&key) {
                    return v;
                }
                let line = self.lines.next_line().await.unwrap().expect("stdout closed");
                // every stdout line must be one complete JSON-RPC message
                let v: Value = serde_json::from_str(&line).unwrap_or_else(|_| panic!("non-JSON on stdout: {line:?}"));
                assert_eq!(v["jsonrpc"], "2.0", "{line}");
                assert!(v.get("result").is_some() ^ v.get("error").is_some(), "{line}");
                self.all_lines.push(line);
                self.responses.insert(v["id"].to_string(), v);
            }
        };
        tokio::time::timeout(Duration::from_secs(20), fut).await.expect("timed out waiting for a response")
    }

    async fn call(&mut self, id: i64, name: &str, args: Value) -> Value {
        self.send(json!({"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": {"name": name, "arguments": args}})).await;
        self.response(json!(id)).await["result"].clone()
    }

    /// Close stdin, wait for exit, return (status, remaining stdout lines, stderr).
    async fn finish(mut self) -> (std::process::ExitStatus, Vec<String>, String) {
        drop(self.stdin);
        let mut rest = Vec::new();
        while let Ok(Some(l)) = self.lines.next_line().await {
            rest.push(l);
        }
        let mut err = String::new();
        if let Some(mut e) = self.child.stderr.take() {
            let _ = e.read_to_string(&mut err).await;
        }
        let status = tokio::time::timeout(Duration::from_secs(20), self.child.wait()).await.unwrap().unwrap();
        (status, rest, err)
    }
}

fn store_key(home: &std::path::Path, mock: &MockBroker, seed: [u8; 32]) -> ConnectionId {
    store_key_for(home, mock, seed, None)
}

fn store_key_for(home: &std::path::Path, mock: &MockBroker, seed: [u8; 32], broker_url: Option<String>) -> ConnectionId {
    let kp = Ed25519Keypair::from_seed(&seed);
    let id = ConnectionId::generate();
    mock.add_connection(&id, kp.public_key());
    KeyStore::new(&aipass_client::AipassHome::new(home))
        .save(&ConnectionKey::new(
            id.clone(),
            kp,
            ConnectionKeyMeta {
                host_type: HostType::Codex,
                display_name: "Codex".into(),
                broker_url,
                created_at: aipass_types::time::now(),
            },
        ))
        .unwrap();
    id
}

fn text_json(result: &Value) -> Value {
    let text = result["content"][0]["text"].as_str().unwrap();
    serde_json::from_str(text.split("\n\n").next().unwrap()).unwrap()
}

async fn full_session(broker_url: String, mock: MockBroker) {
    let home = tempfile::tempdir().unwrap();
    let seed = [11u8; 32];
    let conn = store_key(home.path(), &mock, seed);
    let mut b = Bridge::spawn(home.path(), &broker_url, &["--connection", conn.as_str()]);

    // garbage first: a parse error with id null, the server keeps running
    b.send_raw("this is not json").await;
    b.send(json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
        "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "Codex", "version": "0.98.0"}}})).await;
    let init = b.response(json!(1)).await;
    assert_eq!(init["result"]["protocolVersion"], "2025-06-18");
    let parse_err = b.response(Value::Null).await;
    assert_eq!(parse_err["error"]["code"], -32700);
    b.send(json!({"jsonrpc": "2.0", "method": "notifications/initialized"})).await;
    b.send(json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})).await;
    let tools = b.response(json!(2)).await;
    assert_eq!(tools["result"]["tools"].as_array().unwrap().len(), 7);

    let res = b.call(3, "resources_list", json!({})).await;
    assert_eq!(res["isError"], false);
    let rid = res["structuredContent"]["resources"][0]["resource_id"].as_str().unwrap().to_owned();
    // the broker verified a real signature from our connection
    assert!(mock.seen().iter().any(|s| s.principal.as_deref() == Some(conn.as_str())));

    let res = b.call(4, "operations_request", json!({
        "resource_id": rid, "operation": "postgres.query_view",
        "parameters": {"view": "analytics.subscription_daily", "fields": ["day", "plan", "subscriptions"], "period_days": 30},
        "idempotency_key": "subscription-summary-request-001"
    })).await;
    assert_eq!(res["isError"], false);
    assert_eq!(res["structuredContent"]["status"], "approval_required");
    let op = res["structuredContent"]["operation_id"].as_str().unwrap().to_owned();
    let apr = ApprovalRequestId::parse(res["structuredContent"]["approval_request_id"].as_str().unwrap()).unwrap();
    // the user approves on the trusted device
    mock.approve(&apr).unwrap();
    let res = b.call(5, "operations_status", json!({"operation_id": op})).await;
    assert_eq!(res["structuredContent"]["status"], "succeeded");
    assert_eq!(res["structuredContent"]["result"]["rows"], 1);

    // error mapping through the real client: unknown resource → NOT_FOUND
    let res = b.call(6, "operations_request", json!({
        "resource_id": "res_01jbz3k6w8a7m2q4t5v9x0y1z2", "operation": "postgres.query_view",
        "parameters": {}, "idempotency_key": "x-1"})).await;
    assert_eq!(res["isError"], true);
    assert_eq!(text_json(&res)["error"]["code"], "NOT_FOUND");
    // paused connection → CONNECTION_PAUSED
    mock.set_connection_status(&conn, aipass_types::models::ConnectionStatus::Paused);
    let res = b.call(7, "resources_list", json!({})).await;
    assert_eq!(text_json(&res)["error"]["code"], "CONNECTION_PAUSED");

    // concurrent pings while requests are in flight
    for i in 100..110 {
        b.send(json!({"jsonrpc": "2.0", "id": i, "method": "ping"})).await;
    }
    for i in 100..110 {
        assert_eq!(b.response(json!(i)).await["result"], json!({}));
    }

    let all = b.all_lines.clone();
    let (status, rest, stderr) = b.finish().await;
    assert!(status.success(), "exit status {status:?}; stderr:\n{stderr}");
    assert!(rest.is_empty(), "unexpected stdout after EOF: {rest:?}");
    // logs went to stderr
    assert!(stderr.contains("tools/call"), "stderr: {stderr}");
    assert!(stderr.contains("bridge ready"));
    // no secret anywhere
    let seed_b64 = b64u::encode(seed);
    for text in all.iter().map(String::as_str).chain(std::iter::once(stderr.as_str())) {
        assert!(!text.contains(&seed_b64));
        assert!(!text.contains("AIPass-Sig kid="), "authorization header leaked");
    }
}

#[tokio::test]
async fn stdio_session_over_tcp() {
    let mock = MockBroker::new();
    let (addr, server) = mock.serve_tcp().await.unwrap();
    full_session(format!("http://{addr}"), mock).await;
    server.abort();
}

#[cfg(unix)]
#[tokio::test]
async fn stdio_session_over_unix_socket() {
    let mock = MockBroker::new();
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("broker.sock");
    let server = mock.serve_unix(&sock).await.unwrap();
    full_session(format!("unix://{}", sock.display()), mock).await;
    server.abort();
}

#[tokio::test]
async fn unpaired_bridge_reports_actionable_tool_errors() {
    let home = tempfile::tempdir().unwrap();
    let mut b = Bridge::spawn(home.path(), "http://127.0.0.1:9", &["--experimental"]);
    b.send(json!({"jsonrpc": "2.0", "id": "i", "method": "initialize", "params": {"protocolVersion": "2024-11-05"}})).await;
    let r = b.response(json!("i")).await;
    assert_eq!(r["result"]["protocolVersion"], "2024-11-05");
    b.send(json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})).await;
    let tools = b.response(json!(1)).await;
    assert_eq!(tools["result"]["tools"].as_array().unwrap().len(), 10, "--experimental adds 3 tools");
    assert!(tools["result"]["tools"][0].get("outputSchema").is_none(), "2024-11-05 has no output schemas");
    let res = b.call(2, "resources_list", json!({})).await;
    assert_eq!(res["isError"], true);
    assert!(res.get("structuredContent").is_none());
    assert_eq!(text_json(&res)["error"]["code"], "IDENTITY_UNVERIFIED");
    assert!(res["content"][0]["text"].as_str().unwrap().contains("aipass-mcp pair"));
    // a 2024-11-05 session accepts batches
    b.send_raw(r#"[{"jsonrpc":"2.0","id":"b1","method":"ping"},{"jsonrpc":"2.0","method":"notifications/initialized"}]"#).await;
    let line = tokio::time::timeout(Duration::from_secs(10), b.lines.next_line()).await.unwrap().unwrap().unwrap();
    let v: Value = serde_json::from_str(&line).unwrap();
    assert_eq!(v.as_array().unwrap().len(), 1);
    let (status, _, _) = b.finish().await;
    assert!(status.success());
}

#[tokio::test]
async fn unreachable_broker_is_a_tool_error_not_a_crash() {
    let home = tempfile::tempdir().unwrap();
    let mock = MockBroker::new();
    let _conn = store_key(home.path(), &mock, [3u8; 32]);
    let mut b = Bridge::spawn(home.path(), "http://127.0.0.1:9", &[]);
    b.send(json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-11-25"}})).await;
    b.response(json!(1)).await;
    let res = b.call(2, "resources_list", json!({})).await;
    assert_eq!(res["isError"], true);
    let j = text_json(&res);
    assert_eq!(j["error"]["code"], "INTERNAL");
    assert!(j["error"]["message"].as_str().unwrap().contains("aipass-mcp doctor"));
    let (status, _, stderr) = b.finish().await;
    assert!(status.success());
    assert!(!stderr.contains(&b64u::encode([3u8; 32])));
}

/// MNC-07: a key that recorded broker A never signs requests for a broker B taken from
/// `AIPASS_BROKER_URL` / `--broker` (e.g. a tampered host config), unless explicitly allowed.
#[tokio::test]
async fn key_never_signs_for_a_different_broker() {
    let home = tempfile::tempdir().unwrap();
    let other = MockBroker::new();
    let (addr, server) = other.serve_tcp().await.unwrap();
    let conn = store_key_for(home.path(), &other, [5u8; 32], Some("https://node.example.com/aipass".into()));
    let mut b = Bridge::spawn(home.path(), &format!("http://{addr}"), &["--connection", conn.as_str()]);
    b.send(json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-11-25"}})).await;
    b.response(json!(1)).await;
    let res = b.call(2, "resources_list", json!({})).await;
    assert_eq!(res["isError"], true);
    assert!(other.seen().is_empty(), "no signed request may reach the other broker");
    let (status, _, stderr) = b.finish().await;
    assert!(status.success());
    assert!(stderr.contains("refusing to sign"), "{stderr}");

    // the explicit escape hatch (the broker really moved) restores the old behaviour
    let mut b = Bridge::spawn(home.path(), &format!("http://{addr}"), &["--connection", conn.as_str(), "--allow-broker-mismatch"]);
    b.send(json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-11-25"}})).await;
    b.response(json!(1)).await;
    let _ = b.call(2, "resources_list", json!({})).await;
    assert!(!other.seen().is_empty());
    let _ = b.finish().await;
    server.abort();
}
