// SPDX-License-Identifier: Apache-2.0
//! BrokerClient against the contract signing vector and the in-process mock broker
//! (TCP and Unix socket), including pairing, approvals, replay and cross-connection IDs.

use std::sync::Arc;
use std::time::Duration;

use aipass_client::pairing::{PairingOutcome, PairingRequest, start_pairing};
use aipass_client::testing::MockBroker;
use aipass_client::{Auth, BrokerApi, BrokerClient, BrokerEndpoint, ClientError, ConnectionKey, KeyStore};
use aipass_crypto::{Ed25519Keypair, b64u};
use aipass_types::models::{
    AccessRequest, ApprovalStatus, ConnectionStatus, GrantStatus, HostType, OperationRequest,
    OperationStatus, Transport,
};
use aipass_types::signing::SigHeader;
use aipass_types::{ConnectionId, ErrorCode, OperationId};
use serde_json::{Value, json};

fn vector() -> Value {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../test-vectors/request-signing.json");
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

#[test]
fn reproduces_contract_signing_vector() {
    let v = vector();
    let seed = b64u::decode_array::<32>(v["seed"].as_str().unwrap()).unwrap();
    let kp = Ed25519Keypair::from_seed(&seed);
    assert_eq!(kp.public_key_b64u(), v["public_key"].as_str().unwrap());
    let auth = Auth::signed(v["kid"].as_str().unwrap(), Arc::new(kp));
    for case in v["cases"].as_array().unwrap() {
        let header = auth
            .header_value_with(
                case["method"].as_str().unwrap(),
                case["path"].as_str().unwrap(),
                case["body"].as_str().unwrap().as_bytes(),
                v["ts"].as_i64().unwrap(),
                v["nonce"].as_str().unwrap(),
            )
            .unwrap();
        let parsed = SigHeader::parse(&header).unwrap();
        assert_eq!(parsed.sig, case["signature"].as_str().unwrap());
        assert_eq!(parsed.kid, v["kid"].as_str().unwrap());
        assert_eq!(parsed.ts, v["ts"].as_i64().unwrap());
        assert_eq!(parsed.nonce, v["nonce"].as_str().unwrap());
        assert_eq!(
            aipass_types::signing::string_to_sign(
                case["method"].as_str().unwrap(),
                case["path"].as_str().unwrap(),
                parsed.ts,
                &parsed.nonce,
                case["body"].as_str().unwrap().as_bytes()
            ),
            case["string_to_sign"].as_str().unwrap()
        );
    }
}

fn op_request(resource: &aipass_types::ResourceId, key: &str) -> OperationRequest {
    OperationRequest {
        resource_id: resource.clone(),
        operation: "postgres.query_view".into(),
        parameters: json!({"view": "analytics.subscription_daily", "fields": ["day", "plan", "subscriptions"], "period_days": 30}),
        idempotency_key: key.into(),
        task_id: None,
    }
}

async fn exercise(endpoint: BrokerEndpoint, mock: MockBroker, home: &std::path::Path) {
    let store = KeyStore::at(home.join("connections"));
    let public = BrokerClient::new(endpoint.clone(), Auth::None).unwrap();

    // health is public
    let h = public.health().await.unwrap();
    assert_eq!(h.status, "ok");

    // --- pairing: approval only via the "trusted device" (mock control) --------------
    let pending = start_pairing(
        &public,
        PairingRequest {
            host_type: HostType::Codex,
            display_name: "Codex test".into(),
            transport: Transport::Stdio,
            record_broker_url: true,
        },
    )
    .await
    .unwrap();
    assert_eq!(pending.pairing_code().len(), 6);
    let cid = pending.connection_id().clone();
    assert_eq!(pending.poll_once().await.unwrap(), aipass_types::models::PairStatus::Pending);
    // a pending connection cannot call C endpoints
    assert!(store.list().unwrap().is_empty());
    let approver = {
        let mock = mock.clone();
        let cid = cid.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(300)).await;
            assert!(mock.approve_pairing(&cid));
        })
    };
    let outcome = pending.wait(&store, Duration::from_millis(100)).await.unwrap();
    approver.await.unwrap();
    let key = match outcome {
        PairingOutcome::Approved { key, path } => {
            assert_eq!(path, store.path_for(&cid));
            key
        }
        other => panic!("unexpected {other:?}"),
    };
    assert_eq!(key.meta().broker_url.as_deref(), Some(endpoint.to_string().as_str()));
    let loaded = store.load(&cid).unwrap();
    assert_eq!(loaded.public_key(), key.public_key());

    // --- C endpoints with the stored key ------------------------------------------------
    let client = public.with_auth(loaded.auth());
    let api: Arc<dyn BrokerApi> = Arc::new(client.clone());
    let res = api.list_resources(None, None).await.unwrap();
    assert_eq!(res.resources.len(), 1);
    let resource = res.resources[0].clone();
    let filtered = api
        .list_resources(Some(&resource.project_id), Some("postgres"))
        .await
        .unwrap();
    assert_eq!(filtered.resources.len(), 1);
    let none = api.list_resources(None, Some("no such & service")).await.unwrap();
    assert!(none.resources.is_empty());
    // the query string was signed exactly as sent
    assert!(mock.seen().iter().any(|s| s.path_and_query.contains("service=no+such+%26+service")));

    let first = api.request_operation(&op_request(&resource.resource_id, "k-1")).await.unwrap();
    assert_eq!(first.status, OperationStatus::AwaitingApproval);
    assert_eq!(first.expires_in_seconds, Some(120));
    assert_eq!(first.message.as_deref(), Some(aipass_types::models::APPROVAL_REQUIRED_MESSAGE));
    let apr = first.approval_request_id.clone().unwrap();
    // same idempotency key + same params → same operation
    let again = api.request_operation(&op_request(&resource.resource_id, "k-1")).await.unwrap();
    assert_eq!(again.operation_id, first.operation_id);
    // same key, different params → IDEMPOTENCY_CONFLICT
    let mut changed = op_request(&resource.resource_id, "k-1");
    changed.parameters["period_days"] = json!(31);
    let err = api.request_operation(&changed).await.unwrap_err();
    assert_eq!(err.code, ErrorCode::IdempotencyConflict);

    mock.approve(&apr).unwrap();
    let done = api.get_operation(&first.operation_id).await.unwrap();
    assert_eq!(done.status, OperationStatus::Succeeded);
    assert_eq!(done.result.unwrap().rows, Some(1));

    // a second operation reuses the grant
    let second = api.request_operation(&op_request(&resource.resource_id, "k-2")).await.unwrap();
    assert_eq!(second.status, OperationStatus::Succeeded);

    // cancel a pending op
    let mock2 = MockBroker::new();
    drop(mock2);
    let cancel = api.cancel_operation(&second.operation_id).await.unwrap();
    assert!(!cancel.cancelled);

    // access requests
    let acc = api
        .request_access(&AccessRequest {
            resource_id: resource.resource_id.clone(),
            operations: vec!["postgres.query_view".into()],
            scope: None,
            limits: None,
            duration_seconds: Some(900),
            reason: Some("weekly report".into()),
        })
        .await
        .unwrap();
    assert_eq!(acc.status, ApprovalStatus::Pending);
    let grant = mock.approve(&acc.approval_request_id).unwrap();
    let st = api.get_access_request(&acc.approval_request_id).await.unwrap();
    assert_eq!(st.status, ApprovalStatus::Approved);
    assert_eq!(st.grant_id.as_ref(), Some(&grant));
    let rel = api.release_grant(&grant).await.unwrap();
    assert_eq!(rel.status, GrantStatus::Released);

    // --- IDs are not capabilities: another connection cannot read this operation ------
    let other_kp = Ed25519Keypair::generate();
    let other_id = ConnectionId::generate();
    mock.add_connection(&other_id, other_kp.public_key());
    let other = public.with_auth(Auth::signed(other_id.as_str(), Arc::new(other_kp)));
    let err = other.get_operation(&first.operation_id).await.unwrap_err();
    assert_eq!(err.code(), Some(ErrorCode::NotFound));
    let err = other.release_grant(&grant).await.unwrap_err();
    assert_eq!(err.code(), Some(ErrorCode::NotFound));
    // forged display name / wrong key for an existing kid
    let forged = public.with_auth(Auth::signed(cid.as_str(), Arc::new(Ed25519Keypair::generate())));
    let err = forged.list_resources(None, None).await.unwrap_err();
    assert_eq!(err.code(), Some(ErrorCode::IdentityUnverified));
    // unknown op id
    let err = api.get_operation(&OperationId::generate()).await.unwrap_err();
    assert_eq!(err.code, ErrorCode::NotFound);

    // paused connection
    mock.set_connection_status(&cid, ConnectionStatus::Paused);
    let err = api.list_resources(None, None).await.unwrap_err();
    assert_eq!(err.code, ErrorCode::ConnectionPaused);
    mock.set_connection_status(&cid, ConnectionStatus::Active);

    // bearer connection tokens
    let token_id = ConnectionId::generate();
    mock.add_token(&token_id, "aipc_test-token-value");
    let bearer = public.with_auth(Auth::bearer("aipc_test-token-value"));
    assert_eq!(bearer.list_resources(None, None).await.unwrap().resources.len(), 1);
    let bad = public.with_auth(Auth::bearer("aipc_wrong"));
    assert_eq!(
        bad.list_resources(None, None).await.unwrap_err().code(),
        Some(ErrorCode::IdentityUnverified)
    );
}

#[tokio::test]
async fn end_to_end_over_tcp() {
    let mock = MockBroker::new();
    let (addr, server) = mock.serve_tcp().await.unwrap();
    let dir = tempfile::tempdir().unwrap();
    let ep = BrokerEndpoint::parse(&format!("http://{addr}")).unwrap();
    exercise(ep, mock, dir.path()).await;
    server.abort();
}

#[cfg(unix)]
#[tokio::test]
async fn end_to_end_over_unix_socket() {
    let mock = MockBroker::new();
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("broker.sock");
    let server = mock.serve_unix(&sock).await.unwrap();
    let ep = BrokerEndpoint::parse(&format!("unix://{}", sock.display())).unwrap();
    exercise(ep, mock, dir.path()).await;
    server.abort();
}

#[tokio::test]
async fn replayed_signature_is_rejected() {
    let mock = MockBroker::new();
    let (addr, server) = mock.serve_tcp().await.unwrap();
    let kp = Ed25519Keypair::generate();
    let id = ConnectionId::generate();
    mock.add_connection(&id, kp.public_key());
    let auth = Auth::signed(id.as_str(), Arc::new(kp));
    let header = auth
        .header_value_with(
            "GET",
            "/v1/resources",
            b"",
            aipass_types::time::unix_now(),
            "AAAAAAAAAAAAAAAAAAAAAA",
        )
        .unwrap();
    let http = reqwest::Client::new();
    let url = format!("http://{addr}/v1/resources");
    let first = http
        .get(&url)
        .header("authorization", header.as_str())
        .send()
        .await
        .unwrap();
    assert_eq!(first.status(), 200);
    let replay = http
        .get(&url)
        .header("authorization", header.as_str())
        .send()
        .await
        .unwrap();
    assert_eq!(replay.status(), 401);
    let body: Value = replay.json().await.unwrap();
    assert_eq!(body["error"]["code"], "IDENTITY_UNVERIFIED");
    // a stale timestamp is rejected too
    let stale = auth
        .header_value_with("GET", "/v1/resources", b"", aipass_types::time::unix_now() - 301, "BBBBBBBBBBBBBBBBBBBBBA")
        .unwrap();
    let r = http.get(&url).header("authorization", stale.as_str()).send().await.unwrap();
    assert_eq!(r.status(), 401);
    // tampering with the query after signing fails
    let signed = auth
        .header_value_with("GET", "/v1/resources?service=postgres", b"", aipass_types::time::unix_now(), "CCCCCCCCCCCCCCCCCCCCCA")
        .unwrap();
    let r = http
        .get(format!("{url}?service=github"))
        .header("authorization", signed.as_str())
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401);
    server.abort();
}

#[tokio::test]
async fn pairing_denied_stores_nothing() {
    let mock = MockBroker::new();
    let (addr, server) = mock.serve_tcp().await.unwrap();
    let dir = tempfile::tempdir().unwrap();
    let store = KeyStore::at(dir.path().join("connections"));
    let public = BrokerClient::new(BrokerEndpoint::parse(&format!("http://{addr}")).unwrap(), Auth::None).unwrap();
    let pending = start_pairing(
        &public,
        PairingRequest {
            host_type: HostType::ClaudeCode,
            display_name: "Claude Code".into(),
            transport: Transport::Stdio,
            record_broker_url: false,
        },
    )
    .await
    .unwrap();
    assert!(mock.deny_pairing(pending.connection_id()));
    let outcome = pending.wait(&store, Duration::from_millis(50)).await.unwrap();
    assert!(matches!(outcome, PairingOutcome::Denied));
    assert!(store.list().unwrap().is_empty());
    server.abort();
}

#[tokio::test]
async fn unreachable_broker_errors_carry_no_secrets() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("missing.sock");
    let ep = if cfg!(unix) {
        BrokerEndpoint::parse(&format!("unix://{}", sock.display())).unwrap()
    } else {
        BrokerEndpoint::parse("http://127.0.0.1:9").unwrap()
    };
    let kp = Ed25519Keypair::from_seed(&[42u8; 32]);
    let seed_b64 = b64u::encode([42u8; 32]);
    let key = ConnectionKey::new(
        ConnectionId::generate(),
        kp,
        aipass_client::ConnectionKeyMeta {
            host_type: HostType::Cursor,
            display_name: "Cursor".into(),
            broker_url: None,
            created_at: aipass_types::time::now(),
        },
    );
    for auth in [key.auth(), Auth::bearer("aipc_do-not-leak")] {
        let c = BrokerClient::builder(ep.clone())
            .auth(auth)
            .timeout(Duration::from_secs(2))
            .build()
            .unwrap();
        let err = c.list_resources(None, None).await.unwrap_err();
        assert!(matches!(err, ClientError::Unreachable { .. }), "{err:?}");
        let api = err.to_api_error();
        let text = format!("{err} {err:?} {api} {:?} {c:?}", api.to_body(aipass_types::Lang::En));
        assert!(!text.contains("do-not-leak"));
        assert!(!text.contains(&seed_b64));
        assert_eq!(api.details.get("reason").unwrap(), "broker_unreachable");
    }
}

/// MNC-03: with an `http(s)://host/prefix` endpoint the prefix is sent exactly once, and the
/// signed path equals the request line.
#[tokio::test]
async fn http_endpoint_prefix_is_sent_once_and_signed() {
    use std::sync::Mutex;
    type Seen = Arc<Mutex<Vec<(String, Option<String>)>>>;
    let seen: Seen = Arc::default();
    let s2 = seen.clone();
    let app = axum::Router::new().fallback(move |req: axum::extract::Request| {
        let s2 = s2.clone();
        async move {
            let pq = req.uri().path_and_query().map(|p| p.as_str().to_owned()).unwrap_or_default();
            let auth = req.headers().get("authorization").and_then(|v| v.to_str().ok()).map(str::to_owned);
            s2.lock().unwrap().push((pq, auth));
            axum::Json(json!({"ok": true}))
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let kp = Arc::new(Ed25519Keypair::generate());
    let pk = kp.public_key();
    let ep = BrokerEndpoint::parse(&format!("http://{addr}/aipass")).unwrap();
    let client = BrokerClient::new(ep, Auth::signed("conn_01jzzzzzzzzzzzzzzzzzzzzzzz", kp)).unwrap();
    let r = client.request_raw(http::Method::GET, "/v1/health?x=1", None).await.unwrap();
    assert_eq!(r.status, 200);
    let (path, auth) = seen.lock().unwrap().pop().unwrap();
    assert_eq!(path, "/aipass/v1/health?x=1");
    let header = SigHeader::parse(&auth.unwrap()).unwrap();
    aipass_types::signing::verify_request(&header, &pk, "GET", &path, b"", aipass_types::time::unix_now())
        .expect("signature covers the path actually sent");
    server.abort();
}
