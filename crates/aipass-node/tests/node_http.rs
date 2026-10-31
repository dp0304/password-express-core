// SPDX-License-Identifier: Apache-2.0
//! Starts a node on an ephemeral port and checks the merged HTTP surface.

use aipass_node::{NodeConfig, StartOptions};

#[tokio::test]
async fn node_serves_health_sync_relay_and_mcp() {
    let dir = tempfile::tempdir().expect("tmp");
    let mut cfg = NodeConfig::new("test-node", dir.path().join("data"));
    cfg.node.listen = "127.0.0.1:0".into();
    let node = aipass_node::start(cfg.clone(), StartOptions::default()).await.expect("start");
    let addr = node.local_addr.expect("tcp");
    let base = format!("http://{addr}");
    let http = reqwest::Client::new();

    let h: serde_json::Value = http.get(format!("{base}/v1/health")).send().await.expect("health").json().await.expect("json");
    assert_eq!(h["status"], "ok");
    assert_eq!(h["protection_level"], "compatible");

    // remote MCP needs a node-issued bearer token
    let r = http.post(format!("{base}/mcp")).body("{}").send().await.expect("mcp");
    assert_eq!(r.status().as_u16(), 401);
    assert!(r.headers().get("www-authenticate").and_then(|v| v.to_str().ok()).unwrap_or("").contains("resource_metadata"));
    let meta = http.get(format!("{base}/.well-known/oauth-protected-resource/mcp")).send().await.expect("meta");
    assert_eq!(meta.status().as_u16(), 200);

    // vault creation without an enroll token is refused
    let r = http.post(format!("{base}/v1/vaults")).json(&serde_json::json!({})).send().await.expect("vaults");
    assert!(r.status().is_client_error());

    // relay reads need the mailbox owner's signature
    let r = http.get(format!("{base}/v1/relay/dev_01jzzzzzzzzzzzzzzzzzzzzzzz")).send().await.expect("relay");
    assert_eq!(r.status().as_u16(), 401);

    // admin endpoints need the admin token; the token file is private
    let r = http.get(format!("{base}/v1/connections")).send().await.expect("conns");
    assert_eq!(r.status().as_u16(), 401);
    let admin = aipass_node::pair::admin_client(&cfg, Some(&base)).expect("admin client");
    let conns = admin.list_connections().await.expect("admin list");
    assert!(conns.connections.is_empty());

    // resource configs are validated by the embedded executor before the broker stores them
    let r = http
        .post(format!("{base}/v1/admin/resources"))
        .bearer_auth(std::fs::read_to_string(cfg.admin_token_path()).expect("token").trim())
        .json(&serde_json::json!({
            "alias": "x", "service": "pg", "connector": "postgres", "project_id": "proj_01jzzzzzzzzzzzzzzzzzzzzzzz",
            "environment": "test", "config": {"host": "db", "dbname": "d", "password": "nope", "allowed_views": {"a.b": {"fields": ["x"]}}},
            "credential_entry_id": "ent_01jzzzzzzzzzzzzzzzzzzzzzzz", "executor_id": node.identity.executor_id,
        }))
        .send()
        .await
        .expect("create");
    assert_eq!(r.status().as_u16(), 400);
    let body: serde_json::Value = r.json().await.expect("json");
    assert_eq!(body["error"]["code"], "INVALID_REQUEST");

    node.shutdown().await;
}

/// MNC-01: the node's resource-config pre-validation runs before the broker authenticates.
/// It must never buffer an unbounded body and must not reveal anything to unauthenticated
/// callers.
#[tokio::test]
async fn resource_validation_is_bounded_and_needs_auth() {
    let dir = tempfile::tempdir().expect("tmp");
    let mut cfg = NodeConfig::new("test-node", dir.path().join("data"));
    cfg.node.listen = "127.0.0.1:0".into();
    let node = aipass_node::start(cfg.clone(), StartOptions::default()).await.expect("start");
    let base = format!("http://{}", node.local_addr.expect("tcp"));
    let http = reqwest::Client::new();
    let token = std::fs::read_to_string(cfg.admin_token_path()).expect("token").trim().to_string();

    // 3 MiB streamed (chunked, no Content-Length) without auth: refused once the cap is crossed
    let status = chunked_post(node.local_addr.expect("tcp"), "/v1/admin/resources", 3 * 1024 * 1024).await;
    assert!(matches!(status, 401 | 413), "status {status}");
    // with the admin token the cap is the same
    // The node answers 413 as soon as the cap is crossed and closes the connection; the
    // client may still be uploading and then sees a reset instead of the response (timing-
    // and OS-dependent). Both mean the body was not buffered; anything else fails.
    match http
        .post(format!("{base}/v1/admin/resources"))
        .bearer_auth(&token)
        .body(vec![b' '; 3 * 1024 * 1024])
        .send()
        .await
    {
        Ok(r) => assert_eq!(r.status().as_u16(), 413),
        Err(e) => {
            let reset = std::error::Error::source(&e)
                .map(|s| format!("{s:?}"))
                .is_some_and(|d| d.contains("BodyWrite") || d.contains("ConnectionReset") || d.contains("BrokenPipe"));
            assert!(e.is_request() && reset, "big: {e:?}");
        }
    }

    // an existing resource of this executor
    let admin = aipass_node::pair::admin_client(&cfg, Some(&base)).expect("admin client");
    let project = admin.create_project("p").await.expect("project");
    let r = http
        .post(format!("{base}/v1/admin/resources"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "alias": "x", "service": "pg", "connector": "postgres", "project_id": project.project_id,
            "environment": "test", "config": {"host": "db", "dbname": "d", "allowed_views": {"a.b": {"fields": ["x"]}}},
            "credential_entry_id": "ent_01jzzzzzzzzzzzzzzzzzzzzzzz", "executor_id": node.identity.executor_id,
        }))
        .send()
        .await
        .expect("create");
    assert_eq!(r.status().as_u16(), 201, "{:?}", r.text().await);
    let res: serde_json::Value = r.json().await.expect("json");
    let rid = res["resource_id"].as_str().expect("id").to_string();
    let bad = serde_json::json!({"config": {"host": "db", "dbname": "d", "allowed_views": {"a.b": {"fields": ["x"]}}, "password": "nope"}});

    // unauthenticated PATCH with invalid config: 401, not the validation error
    let r = http.patch(format!("{base}/v1/admin/resources/{rid}")).json(&bad).send().await.expect("patch");
    assert_eq!(r.status().as_u16(), 401);
    // a forged admin token is not trusted either
    let r = http
        .patch(format!("{base}/v1/admin/resources/{rid}"))
        .bearer_auth("not-the-admin-token")
        .json(&bad)
        .send()
        .await
        .expect("patch");
    assert_eq!(r.status().as_u16(), 401);
    // the admin still gets the validation error
    let r = http
        .patch(format!("{base}/v1/admin/resources/{rid}"))
        .bearer_auth(&token)
        .json(&bad)
        .send()
        .await
        .expect("patch");
    assert_eq!(r.status().as_u16(), 400);

    node.shutdown().await;
}

/// Stream `total` bytes as a chunked request body over raw TCP (writes stop when the server
/// closes the connection) and return the response status.
async fn chunked_post(addr: std::net::SocketAddr, path: &str, total: usize) -> u16 {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut s = tokio::net::TcpStream::connect(addr).await.expect("connect");
    let head = format!(
        "POST {path} HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n"
    );
    s.write_all(head.as_bytes()).await.expect("head");
    let chunk = vec![b' '; 64 * 1024];
    let mut sent = 0;
    while sent < total {
        let frame = [format!("{:x}\r\n", chunk.len()).into_bytes(), chunk.clone(), b"\r\n".to_vec()].concat();
        if s.write_all(&frame).await.is_err() {
            break;
        }
        sent += chunk.len();
    }
    let _ = s.write_all(b"0\r\n\r\n").await;
    let mut buf = vec![0u8; 1024];
    let mut got = Vec::new();
    while !got.windows(2).any(|w| w == b"\r\n") {
        match tokio::time::timeout(std::time::Duration::from_secs(10), s.read(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => got.extend_from_slice(&buf[..n]),
            _ => break,
        }
    }
    let line = String::from_utf8_lossy(&got);
    line.split_whitespace().nth(1).and_then(|c| c.parse().ok()).unwrap_or(0)
}
