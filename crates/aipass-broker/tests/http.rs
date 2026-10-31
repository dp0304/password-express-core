// SPDX-License-Identifier: Apache-2.0
//! HTTP layer with real `AIPass-Sig` signatures (the CONTRACTS §1.6 vector), auth classes,
//! error envelope, pairing over HTTP, bearer tokens, UDS serving.

mod common;

use std::time::Duration;

use aipass_broker::{BrokerState, UdsOptions, router};
use aipass_crypto::Ed25519Keypair;
use aipass_types::approval;
use aipass_types::exec::{CredentialAad, seal_credential};
use aipass_types::ids::{ConnectionId, ProjectId, ResourceId};
use aipass_types::models::{
    AllowedProjects, AppConnection, ConnectionStatus, Connector, Decision, Environment, HostType,
    Project, Resource, ResourceStatus, Transport,
};
use aipass_types::signing::sign_request_with;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use common::*;
use serde_json::{Value, json};
use tower::ServiceExt;

const VECTOR_POST_BODY: &str = "{\"resource_id\":\"res_01jbz3k6w8a7m2q4t5v9x0y1z2\",\"operation\":\"postgres.query_view\",\"parameters\":{\"view\":\"analytics.subscription_daily\",\"fields\":[\"day\",\"plan\",\"subscriptions\"],\"period_days\":30},\"idempotency_key\":\"subscription-summary-request-001\"}";
const VECTOR_POST_AUTH: &str = "AIPass-Sig kid=conn_01jbz3k6w8a7m2q4t5v9x0y1z4, ts=1793318400, nonce=qqqqqqqqqqqqqqqqqqqqqg, sig=bkY5XhOuTqE-0g0GA_J5SPOZgk67xYrVj77Koc0EBsWGH-APHWHBuGx1MojhxBSiYyV4Cj2Llu1xmAyRITt1Aw";
const VECTOR_GET_PATH: &str = "/v1/resources?project_id=proj_01jbz3k6w8a7m2q4t5v9x0y1z3";
const VECTOR_GET_AUTH: &str = "AIPass-Sig kid=conn_01jbz3k6w8a7m2q4t5v9x0y1z4, ts=1793318400, nonce=qqqqqqqqqqqqqqqqqqqqqg, sig=z-FXrTabpsAztih0b7vQ-r9wqLCSnkTZtGHBrGgL9U5aT6Nt4usP6qgRQb_FBzyl_DQ0xrNb0oSuphvOvmOjDg";

fn vector_key() -> Ed25519Keypair {
    let seed: [u8; 32] = core::array::from_fn(|i| i as u8);
    Ed25519Keypair::from_seed(&seed)
}

/// Harness + the exact objects of the contract vector.
async fn vector_harness() -> Harness {
    let h = Harness::persistent().await;
    let project = ProjectId::parse("proj_01jbz3k6w8a7m2q4t5v9x0y1z3").unwrap();
    h.broker.import_project(Project { project_id: project.clone(), name: "lure".into() }).await.unwrap();
    h.broker
        .import_resource(Resource {
            resource_id: ResourceId::parse("res_01jbz3k6w8a7m2q4t5v9x0y1z2").unwrap(),
            alias: "路亚站统计视图".into(),
            service: "postgres".into(),
            connector: Connector::Postgres,
            project_id: project.clone(),
            environment: Environment::Test,
            config: json!({"allowed_views": {"analytics.subscription_daily": {"fields": ["day", "plan", "subscriptions"]}}}),
            credential_entry_id: aipass_types::ids::EntryId::generate(),
            executor_id: h.exe.id.clone(),
            operations: vec!["postgres.query_view".into()],
            status: ResourceStatus::Available,
            created_at: h.clock.now_ts(),
        })
        .await
        .unwrap();
    h.broker
        .import_connection(AppConnection {
            connection_id: ConnectionId::parse("conn_01jbz3k6w8a7m2q4t5v9x0y1z4").unwrap(),
            host_type: HostType::ClaudeCode,
            display_name: "Claude Code".into(),
            transport: Transport::Stdio,
            status: ConnectionStatus::Active,
            public_key: Some(vector_key().public_key_b64u()),
            allowed_projects: AllowedProjects::Only([project].into()),
            created_at: h.clock.now_ts(),
            approved_at: Some(h.clock.now_ts()),
            approved_by: None,
            last_seen_at: None,
        })
        .await
        .unwrap();
    h
}

async fn call(h: &Harness, method: &str, path: &str, auth: Option<&str>, body: &str, lang: Option<&str>) -> (StatusCode, Value, axum::http::HeaderMap) {
    let mut b = Request::builder().method(method).uri(path);
    if let Some(a) = auth {
        b = b.header("authorization", a);
    }
    if let Some(l) = lang {
        b = b.header("accept-language", l);
    }
    if !body.is_empty() {
        b = b.header("content-type", "application/json");
    }
    let req = b.body(Body::from(body.to_owned())).unwrap();
    let resp = router(BrokerState::new(h.broker.clone())).oneshot(req).await.unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let v = if bytes.is_empty() { Value::Null } else { serde_json::from_slice(&bytes).unwrap_or(Value::Null) };
    (status, v, headers)
}

fn device_auth(h: &Harness, method: &str, path: &str, body: &str) -> String {
    let nonce = aipass_crypto::b64u::encode(aipass_crypto::rng::random_array::<16>());
    sign_request_with(&h.device, h.device_id.as_str(), method, path, body.as_bytes(), h.clock.unix_now(), &nonce).to_header_value()
}

fn conn_auth(key: &Ed25519Keypair, kid: &str, h: &Harness, method: &str, path: &str, body: &str) -> String {
    let nonce = aipass_crypto::b64u::encode(aipass_crypto::rng::random_array::<16>());
    sign_request_with(key, kid, method, path, body.as_bytes(), h.clock.unix_now(), &nonce).to_header_value()
}

trait UnixNow {
    fn unix_now(&self) -> i64;
}
impl UnixNow for aipass_broker::ManualClock {
    fn unix_now(&self) -> i64 {
        aipass_broker::Clock::unix(self)
    }
}

#[tokio::test]
async fn contract_vector_requests_are_accepted_exactly_once() {
    let h = vector_harness().await;
    let (s, v, headers) = call(&h, "POST", "/v1/operations", Some(VECTOR_POST_AUTH), VECTOR_POST_BODY, None).await;
    assert_eq!(s, StatusCode::ACCEPTED, "{v}");
    assert_eq!(v["status"], "approval_required");
    assert_eq!(v["expires_in_seconds"], 120);
    assert_eq!(v["message"], "请在已配对的手机或可信客户端批准本次访问。");
    assert!(v["operation_id"].as_str().unwrap().starts_with("op_"));
    assert!(v["approval_request_id"].as_str().unwrap().starts_with("apr_"));
    assert!(headers.get("x-request-id").unwrap().to_str().unwrap().starts_with("req_"));

    // replay of the same signed request → nonce reuse → 401
    let (s, v, _) = call(&h, "POST", "/v1/operations", Some(VECTOR_POST_AUTH), VECTOR_POST_BODY, Some("en-US")).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert_eq!(v["error"]["code"], "IDENTITY_UNVERIFIED");
    assert_eq!(v["error"]["message"], "The caller's identity could not be verified.");
    assert!(v["error"]["request_id"].as_str().unwrap().starts_with("req_"));
    // both vectors share kid + nonce, so the GET vector is a replay on this broker too
    let (s, _, _) = call(&h, "GET", VECTOR_GET_PATH, Some(VECTOR_GET_AUTH), "", None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);

    // …and is accepted by a fresh broker
    let h = vector_harness().await;
    let (s, v, _) = call(&h, "GET", VECTOR_GET_PATH, Some(VECTOR_GET_AUTH), "", None).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["resources"].as_array().unwrap().len(), 1);
    let r = &v["resources"][0];
    assert_eq!(r["resource_id"], "res_01jbz3k6w8a7m2q4t5v9x0y1z2");
    assert_eq!(r["protection_level"], "compatible");
    assert!(r.get("config").is_none());
}

#[tokio::test]
async fn signatures_bind_body_path_and_time() {
    let h = vector_harness().await;
    // body changed
    let tampered = VECTOR_POST_BODY.replace("\"day\",", "\"day\",\"email\",");
    let (s, v, _) = call(&h, "POST", "/v1/operations", Some(VECTOR_POST_AUTH), &tampered, None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert_eq!(v["error"]["message"], "无法验证调用方身份");
    // path changed
    let (s, _, _) = call(&h, "GET", "/v1/resources?project_id=proj_01jbz3k6w8a7m2q4t5v9x0y1z5", Some(VECTOR_GET_AUTH), "", None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    // clock skew > 300 s
    h.clock.advance(301);
    let (s, _, _) = call(&h, "GET", VECTOR_GET_PATH, Some(VECTOR_GET_AUTH), "", None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    // garbage header
    let (s, _, _) = call(&h, "GET", VECTOR_GET_PATH, Some("AIPass-Sig kid=conn_x"), "", None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    // no auth at all
    let (s, v, _) = call(&h, "GET", "/v1/resources", None, "", None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert_eq!(v["error"]["code"], "IDENTITY_UNVERIFIED");
}

#[tokio::test]
async fn full_flow_over_http_with_device_signed_decision() {
    let h = vector_harness().await;
    let (_, v, _) = call(&h, "POST", "/v1/operations", Some(VECTOR_POST_AUTH), VECTOR_POST_BODY, None).await;
    let op_id = v["operation_id"].as_str().unwrap().to_owned();
    let apr_id = v["approval_request_id"].as_str().unwrap().to_owned();

    // trusted device lists pending approvals
    let path = "/v1/approvals?status=pending";
    let (s, v, _) = call(&h, "GET", path, Some(&device_auth(&h, "GET", path, "")), "", None).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let req: aipass_types::models::ApprovalRequest = serde_json::from_value(v["approvals"][0].clone()).unwrap();
    assert_eq!(req.approval_request_id.as_str(), apr_id);

    // the device signs the decision computed from the displayed fields
    let mut d = approval::build_decision(&h.device, &h.device_id, &req, Decision::Approve, None, &h.clock.now_ts()).unwrap();
    let aad = CredentialAad {
        approval_request_id: req.approval_request_id.clone(),
        digest: d.digest.clone(),
        executor_id: req.executor.executor_id.clone(),
    };
    let res = h.broker.get_resource(&req.resource.resource_id).await.unwrap();
    d.credential_envelope = Some(seal_credential(&h.exe.kem.public_key(), &aad.to_bytes().unwrap(), &h.material(&res)).unwrap());
    let body = serde_json::to_string(&d).unwrap();
    let path = format!("/v1/approvals/{apr_id}/decision");
    let (s, v, _) = call(&h, "POST", &path, Some(&device_auth(&h, "POST", &path, &body)), &body, None).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["status"], "approved");
    assert_eq!(v["operation"]["status"], "succeeded");
    assert!(v["operation"].get("result").is_none());

    // the connection fetches its result
    let key = vector_key();
    let path = format!("/v1/operations/{op_id}");
    let (s, v, _) = call(&h, "GET", &path, Some(&conn_auth(&key, "conn_01jbz3k6w8a7m2q4t5v9x0y1z4", &h, "GET", &path, "")), "", None).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["status"], "succeeded");
    assert_eq!(v["result"]["rows"], 3);
    assert_no_secret(&v.to_string());

    // audit chain over HTTP
    let path = "/v1/audit/verify";
    let (s, v, _) = call(&h, "GET", path, Some(&device_auth(&h, "GET", path, "")), "", None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["valid"], true);
}

#[tokio::test]
async fn auth_classes_are_enforced() {
    let h = vector_harness().await;
    let token = std::fs::read_to_string(h.broker.admin_token_path().unwrap()).unwrap();
    let admin = format!("Bearer {}", token.trim());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let m = std::fs::metadata(h.broker.admin_token_path().unwrap()).unwrap().permissions().mode();
        assert_eq!(m & 0o777, 0o600);
    }
    // A endpoint: admin ok, device forbidden, connection forbidden, wrong token unverified
    let (s, _, _) = call(&h, "GET", "/v1/admin/devices", Some(&admin), "", None).await;
    assert_eq!(s, StatusCode::OK);
    let (s, v, _) = call(&h, "GET", "/v1/admin/devices", Some(&device_auth(&h, "GET", "/v1/admin/devices", "")), "", None).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert_eq!(v["error"]["code"], "FORBIDDEN");
    let (s, _, _) = call(&h, "GET", "/v1/admin/devices", Some("Bearer aipadm_wrong-token-value-123"), "", None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    // D/A endpoint refuses connections
    let key = vector_key();
    let (s, _, _) = call(&h, "GET", "/v1/approvals", Some(&conn_auth(&key, "conn_01jbz3k6w8a7m2q4t5v9x0y1z4", &h, "GET", "/v1/approvals", "")), "", None).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    // C endpoint refuses devices/admin
    let (s, _, _) = call(&h, "GET", "/v1/resources", Some(&admin), "", None).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    // admin provisions a remote connection with a bearer token
    let body = json!({"host_type":"sdk","display_name":"remote","transport":"sdk","allowed_projects":["proj_01jbz3k6w8a7m2q4t5v9x0y1z3"]}).to_string();
    let (s, v, _) = call(&h, "POST", "/v1/admin/connections", Some(&admin), &body, None).await;
    assert_eq!(s, StatusCode::CREATED, "{v}");
    let ctoken = v["token"].as_str().unwrap().to_owned();
    let (s, v, _) = call(&h, "GET", "/v1/resources", Some(&format!("Bearer {ctoken}")), "", None).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["resources"].as_array().unwrap().len(), 1);
    // public
    let (s, v, _) = call(&h, "GET", "/v1/health", None, "", None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["status"], "ok");
    assert_eq!(v["executor_online"], true);
    // fallback 404 envelope + invalid JSON never echoes values
    let (s, v, _) = call(&h, "GET", "/v1/nope", None, "", None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    assert_eq!(v["error"]["code"], "NOT_FOUND");
    let bad = "{\"resource_id\":\"res_x\",\"secret-ish\":\"hunter2\"";
    let (s, v, _) = call(&h, "POST", "/v1/projects", Some(&admin), bad, None).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert!(!v.to_string().contains("hunter2"));
}

#[tokio::test]
async fn pairing_over_http() {
    let h = vector_harness().await;
    let key = Ed25519Keypair::generate();
    let body = json!({"host_type":"codex","display_name":"Codex CLI","transport":"stdio","public_key": key.public_key_b64u()}).to_string();
    let (s, v, _) = call(&h, "POST", "/v1/connections/pair", None, &body, None).await;
    assert_eq!(s, StatusCode::CREATED, "{v}");
    let pid = v["pairing_request_id"].as_str().unwrap().to_owned();
    let cid = v["connection_id"].as_str().unwrap().to_owned();
    assert!(pid.starts_with("pair_"));
    let path = format!("/v1/connections/pair/{pid}");
    // unsigned poll is refused; signed by the pending key works
    let (s, _, _) = call(&h, "GET", &path, None, "", None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let (s, v, _) = call(&h, "GET", &path, Some(&conn_auth(&key, &cid, &h, "GET", &path, "")), "", None).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["status"], "pending");
    // pending connection cannot use C endpoints
    let (s, _, _) = call(&h, "GET", "/v1/resources", Some(&conn_auth(&key, &cid, &h, "GET", "/v1/resources", "")), "", None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    // device approves
    let path_a = format!("/v1/connections/{cid}/approve");
    let body = json!({"allowed_projects": ["proj_01jbz3k6w8a7m2q4t5v9x0y1z3"]}).to_string();
    let (s, v, _) = call(&h, "POST", &path_a, Some(&device_auth(&h, "POST", &path_a, &body)), &body, None).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["status"], "active");
    let (_, v, _) = call(&h, "GET", &path, Some(&conn_auth(&key, &cid, &h, "GET", &path, "")), "", None).await;
    assert_eq!(v["status"], "approved");
    let (s, v, _) = call(&h, "GET", "/v1/resources", Some(&conn_auth(&key, &cid, &h, "GET", "/v1/resources", "")), "", None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["resources"].as_array().unwrap().len(), 1);
    // device pauses it over HTTP
    let path_p = format!("/v1/connections/{cid}/pause");
    let (s, v, _) = call(&h, "POST", &path_p, Some(&device_auth(&h, "POST", &path_p, "")), "", None).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let (s, v, _) = call(&h, "GET", "/v1/resources", Some(&conn_auth(&key, &cid, &h, "GET", "/v1/resources", "")), "", Some("en")).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert_eq!(v["error"]["code"], "CONNECTION_PAUSED");
    assert_eq!(v["error"]["message"], "This AI connection is paused.");
}

#[tokio::test]
async fn revoke_over_http_returns_report() {
    let h = vector_harness().await;
    let r = h.broker.request_operation(&h.conn, h.query("a", &["day"]), aipass_types::error::Lang::ZhCn).await.unwrap();
    let grant = h.approve(r.approval_request_id.as_ref().unwrap()).await.grant_id.unwrap();
    let path = format!("/v1/grants/{grant}/revoke");
    let body = json!({"level": "revoke_upstream"}).to_string();
    let (s, v, _) = call(&h, "POST", &path, Some(&device_auth(&h, "POST", &path, &body)), &body, None).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["stop_access"]["status"], "done");
    assert_eq!(v["end_sessions"]["status"], "done");
    assert_eq!(v["revoke_upstream"]["status"], "not_applicable");
    let (s, v, _) = call(&h, "GET", "/v1/grants?status=revoked", Some(&device_auth(&h, "GET", "/v1/grants?status=revoked", "")), "", None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["grants"].as_array().unwrap().len(), 1);
    let path = "/v1/activity/summary";
    let (s, v, _) = call(&h, "GET", path, Some(&device_auth(&h, "GET", path, "")), "", None).await;
    assert_eq!(s, StatusCode::OK);
    assert!(v["anomalies"].is_array());
}

#[tokio::test]
async fn uds_admin_peer_and_socket_mode() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let h = Harness::persistent().await;
    let base = h.dir.as_ref().unwrap().path().join("run");
    let admin_sock = base.join("admin.sock");
    let conn_sock = base.join("broker.sock");
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let (tx2, rx2) = tokio::sync::oneshot::channel::<()>();
    let r1 = router(BrokerState::new(h.broker.clone()));
    let r2 = router(BrokerState::new(h.broker.clone()));
    let p1 = admin_sock.clone();
    let p2 = conn_sock.clone();
    let s1 = tokio::spawn(async move {
        aipass_broker::serve_uds(r1, &p1, UdsOptions { admin_peers: true }, async {
            let _ = rx.await;
        })
        .await
    });
    let s2 = tokio::spawn(async move {
        aipass_broker::serve_uds(r2, &p2, UdsOptions { admin_peers: false }, async {
            let _ = rx2.await;
        })
        .await
    });
    for _ in 0..200 {
        if admin_sock.exists() && conn_sock.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&admin_sock).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(std::fs::metadata(&base).unwrap().permissions().mode() & 0o777, 0o700);
    }
    async fn get(path: &std::path::Path, uri: &str) -> String {
        let mut s = tokio::net::UnixStream::connect(path).await.unwrap();
        s.write_all(format!("GET {uri} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
        let mut out = String::new();
        s.read_to_string(&mut out).await.unwrap();
        out
    }
    let out = get(&admin_sock, "/v1/connections").await;
    assert!(out.starts_with("HTTP/1.1 200"), "{out}");
    assert!(out.contains("\"connections\""));
    let out = get(&conn_sock, "/v1/connections").await;
    assert!(out.starts_with("HTTP/1.1 401"), "{out}");
    let out = get(&conn_sock, "/v1/health").await;
    assert!(out.starts_with("HTTP/1.1 200"), "{out}");
    let _ = tx.send(());
    let _ = tx2.send(());
    s1.await.unwrap().unwrap();
    s2.await.unwrap().unwrap();
    assert!(!admin_sock.exists(), "socket removed on shutdown");
    // admin actions through the trusted actor are audited as admin
    let audit = h.broker.audit_events(0, 1000).await.unwrap();
    assert!(audit.events.iter().any(|e| e.actor == "admin"));
}

#[tokio::test]
async fn tcp_serving_helper() {
    let h = Harness::new().await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let app = router(BrokerState::new(h.broker.clone()));
    let server = tokio::spawn(aipass_broker::serve_tcp(app, listener, async {
        let _ = rx.await;
    }));
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
    s.write_all(b"GET /v1/health HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").await.unwrap();
    let mut out = String::new();
    s.read_to_string(&mut out).await.unwrap();
    assert!(out.starts_with("HTTP/1.1 200"), "{out}");
    assert!(out.to_ascii_lowercase().contains("x-request-id: req_"));
    let _ = tx.send(());
    server.await.unwrap().unwrap();
}

/// BRK-04: a `pending` connection may sign only its pairing poll. Any other signed request
/// is refused before its nonce is recorded — so the very same signed request is still
/// fresh once the connection is approved (it was never stored in the replay cache).
#[tokio::test]
async fn pending_connection_signatures_are_refused_before_the_nonce_is_recorded() {
    let h = vector_harness().await;
    let key = Ed25519Keypair::generate();
    let body = json!({"host_type":"codex","display_name":"Codex CLI","transport":"stdio","public_key": key.public_key_b64u()}).to_string();
    let (s, v, _) = call(&h, "POST", "/v1/connections/pair", None, &body, None).await;
    assert_eq!(s, StatusCode::CREATED, "{v}");
    let cid = v["connection_id"].as_str().unwrap().to_owned();
    let pid = v["pairing_request_id"].as_str().unwrap().to_owned();
    let early = conn_auth(&key, &cid, &h, "GET", "/v1/resources", "");
    let (s, v, _) = call(&h, "GET", "/v1/resources", Some(&early), "", None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert_eq!(v["error"]["code"], "IDENTITY_UNVERIFIED");
    // health / other paths are not a loophole either
    let (s, _, _) = call(&h, "GET", "/v1/health", Some(&conn_auth(&key, &cid, &h, "GET", "/v1/health", "")), "", None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    // the pairing poll itself works
    let poll = format!("/v1/connections/pair/{pid}");
    let (s, _, _) = call(&h, "GET", &poll, Some(&conn_auth(&key, &cid, &h, "GET", &poll, "")), "", None).await;
    assert_eq!(s, StatusCode::OK);
    // approve, then send the exact earlier request: not a replay (no nonce was stored)
    let path_a = format!("/v1/connections/{cid}/approve");
    let body = json!({"allowed_projects": ["proj_01jbz3k6w8a7m2q4t5v9x0y1z3"]}).to_string();
    let (s, v, _) = call(&h, "POST", &path_a, Some(&device_auth(&h, "POST", &path_a, &body)), &body, None).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let (s, v, _) = call(&h, "GET", "/v1/resources", Some(&early), "", None).await;
    assert_eq!(s, StatusCode::OK, "{v}");
}

/// BRK-04: the replay cache has a per-key quota — one key that floods it is rate limited
/// alone; other principals keep working.
#[tokio::test]
async fn nonce_quota_is_per_signing_key() {
    let mut cfg = test_config();
    cfg.max_nonces_per_kid = 3;
    let h = Harness::build(cfg, true).await;
    let key = Ed25519Keypair::generate();
    let body = json!({"host_type":"codex","display_name":"Codex CLI","transport":"stdio","public_key": key.public_key_b64u()}).to_string();
    let (_, v, _) = call(&h, "POST", "/v1/connections/pair", None, &body, None).await;
    let cid = v["connection_id"].as_str().unwrap().to_owned();
    let path_a = format!("/v1/connections/{cid}/approve");
    let body = json!({"allowed_projects": [h.project.as_str()]}).to_string();
    let (s, v, _) = call(&h, "POST", &path_a, Some(&device_auth(&h, "POST", &path_a, &body)), &body, None).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    for _ in 0..3 {
        let (s, _, _) = call(&h, "GET", "/v1/resources", Some(&conn_auth(&key, &cid, &h, "GET", "/v1/resources", "")), "", None).await;
        assert_eq!(s, StatusCode::OK);
    }
    let (s, v, _) = call(&h, "GET", "/v1/resources", Some(&conn_auth(&key, &cid, &h, "GET", "/v1/resources", "")), "", None).await;
    assert_eq!(s, StatusCode::TOO_MANY_REQUESTS, "{v}");
    assert_eq!(v["error"]["code"], "RATE_LIMITED");
    // the device (another key) is unaffected
    let (s, v, _) = call(&h, "GET", "/v1/approvals", Some(&device_auth(&h, "GET", "/v1/approvals", "")), "", None).await;
    assert_eq!(s, StatusCode::OK, "{v}");
}

/// CONTRACTS §6.3: trusted devices and admins see the pairing code of a *pending*
/// connection (single and list views) so they can compare it with the code the AI host
/// shows; AI connections never do, and the code disappears once the pairing is decided
/// or expired.
#[tokio::test]
async fn pairing_code_is_shown_only_to_trusted_principals_while_pending() {
    let h = vector_harness().await;
    let token = std::fs::read_to_string(h.broker.admin_token_path().unwrap()).unwrap();
    let admin = format!("Bearer {}", token.trim());
    let key = Ed25519Keypair::generate();
    let body = json!({"host_type":"codex","display_name":"Codex CLI","transport":"stdio","public_key": key.public_key_b64u()}).to_string();
    let (s, v, _) = call(&h, "POST", "/v1/connections/pair", None, &body, None).await;
    assert_eq!(s, StatusCode::CREATED, "{v}");
    let cid = v["connection_id"].as_str().unwrap().to_owned();
    let code = v["pairing_code"].as_str().unwrap().to_owned();
    let exp = v["expires_at"].as_str().unwrap().to_owned();
    let one = format!("/v1/connections/{cid}");

    // D and A: single view and the pending list row carry the code + expiry.
    for auth in [device_auth(&h, "GET", &one, ""), admin.clone()] {
        let (s, v, _) = call(&h, "GET", &one, Some(&auth), "", None).await;
        assert_eq!(s, StatusCode::OK, "{v}");
        assert_eq!(v["status"], "pending");
        assert_eq!(v["pairing_code"], code.as_str());
        assert_eq!(v["pairing_expires_at"], exp.as_str());
        // still a valid AppConnection for older readers
        let _: AppConnection = serde_json::from_value(v.clone()).unwrap();
    }
    for auth in [device_auth(&h, "GET", "/v1/connections", ""), admin.clone()] {
        let (s, v, _) = call(&h, "GET", "/v1/connections", Some(&auth), "", None).await;
        assert_eq!(s, StatusCode::OK, "{v}");
        let rows = v["connections"].as_array().unwrap();
        let row = rows.iter().find(|r| r["connection_id"] == cid.as_str()).unwrap();
        assert_eq!(row["pairing_code"], code.as_str());
        // the active connection of the harness has no code
        assert!(rows.iter().filter(|r| r["status"] == "active").all(|r| r.get("pairing_code").is_none()));
        let parsed: aipass_types::models::ConnectionViewsResponse = serde_json::from_value(v.clone()).unwrap();
        assert!(parsed.connections.iter().any(|c| c.pairing_code.as_deref() == Some(code.as_str())));
    }

    // C principals: refused — neither the pending key nor an active connection sees it.
    let (s, v, _) = call(&h, "GET", &one, Some(&conn_auth(&key, &cid, &h, "GET", &one, "")), "", None).await;
    assert_ne!(s, StatusCode::OK);
    assert!(!v.to_string().contains(&code));
    let vk = vector_key();
    for path in [one.as_str(), "/v1/connections"] {
        let (s, v, _) = call(&h, "GET", path, Some(&conn_auth(&vk, "conn_01jbz3k6w8a7m2q4t5v9x0y1z4", &h, "GET", path, "")), "", None).await;
        assert_eq!(s, StatusCode::FORBIDDEN);
        assert!(!v.to_string().contains(&code));
    }
    // unauthenticated
    let (s, _, _) = call(&h, "GET", &one, None, "", None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);

    // Once approved the code is gone.
    let path_a = format!("/v1/connections/{cid}/approve");
    let body = json!({"allowed_projects": ["proj_01jbz3k6w8a7m2q4t5v9x0y1z3"]}).to_string();
    let (s, _, _) = call(&h, "POST", &path_a, Some(&device_auth(&h, "POST", &path_a, &body)), &body, None).await;
    assert_eq!(s, StatusCode::OK);
    let (_, v, _) = call(&h, "GET", &one, Some(&admin), "", None).await;
    assert_eq!(v["status"], "active");
    assert!(v.get("pairing_code").is_none() && v.get("pairing_expires_at").is_none());

    // An expired pending pairing shows no code either.
    let key2 = Ed25519Keypair::generate();
    let body = json!({"host_type":"cursor","display_name":"Cursor","transport":"stdio","public_key": key2.public_key_b64u()}).to_string();
    let (_, v, _) = call(&h, "POST", "/v1/connections/pair", None, &body, None).await;
    let cid2 = v["connection_id"].as_str().unwrap().to_owned();
    h.clock.advance(3600);
    let (_, v, _) = call(&h, "GET", &format!("/v1/connections/{cid2}"), Some(&admin), "", None).await;
    assert!(v.get("pairing_code").is_none(), "{v}");
}
