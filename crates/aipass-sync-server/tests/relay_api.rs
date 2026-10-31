// SPDX-License-Identifier: Apache-2.0
//! Relay mailbox tests: `RelayClient` (aipass-storage) ↔ `relay_router` in-process.

mod common;

use std::sync::Arc;
use std::time::{Duration, Instant};

use aipass_storage::relay_client::{RelayAuth, RelayClient, RelayClientError};
use aipass_sync_server::relay::{MemoryRelayStore, RelayStore, SqliteRelayStore, StaticDirectory};
use aipass_sync_server::{Clock, RelayConfig};
use aipass_types::ErrorCode;
use aipass_types::ids::{ApprovalRequestId, MailboxId, PairingId, PrincipalId};
use aipass_types::relay::{
    ApprovalCancelled, RelayEnvelope, RelayMessage, StateRequest, open_envelope,
    open_envelope_unverified, seal_envelope,
};
use aipass_types::vault::{MemberRole, MemberStatus};
use common::*;

fn approval_request() -> aipass_types::models::ApprovalRequest {
    let now = aipass_types::time::now();
    serde_json::from_value(serde_json::json!({
        "approval_request_id": ApprovalRequestId::generate(),
        "kind": "operation",
        "connection": {"connection_id": "conn_01jbz3k6w8a7m2q4t5v9x0y1z4", "display_name": "Codex", "host_type": "codex", "verified": true},
        "resource": {"resource_id": "res_01jbz3k6w8a7m2q4t5v9x0y1z2", "alias": "lure-store", "service": "postgres", "environment": "test"},
        "summary": {"zh": "查询订阅汇总", "en": "Query subscription summary"},
        "requested": {
            "operations": ["postgres.query_view"],
            "scope": {"operations": ["postgres.query_view"]},
            "limits": {"max_rows_per_operation": 1000, "max_rows_per_grant": 5000, "max_requests_per_grant": 20, "max_result_bytes": 262144},
            "duration_seconds": 900,
            "mode": "once"
        },
        "executor": {"executor_id": "exe_01jbz3k6w8a7m2q4t5v9x0y1z5", "name": "Desktop", "protection_level": "compatible"},
        "recipients": [{"connection_id": "conn_01jbz3k6w8a7m2q4t5v9x0y1z4", "display_name": "Codex"}],
        "status": "pending",
        "created_at": aipass_types::time::format_rfc3339(&now),
        "expires_at": aipass_types::time::format_rfc3339(&aipass_types::time::add_secs(&now, 120)),
    }))
    .expect("approval request fixture")
}

fn cancelled() -> RelayMessage {
    RelayMessage::ApprovalCancelled(ApprovalCancelled {
        approval_request_id: ApprovalRequestId::generate(),
        reason: "expired".into(),
    })
}

fn client(srv: &Server, kid: PrincipalId, dev: &Device) -> RelayClient {
    RelayClient::with_client(
        srv.base.clone(),
        RelayAuth::Signed {
            kid,
            signer: dev.signer(),
        },
        http(),
        false,
    )
    .unwrap()
}

fn seal(
    from: &Device,
    from_id: MailboxId,
    to: &Device,
    to_id: MailboxId,
    msg: &RelayMessage,
) -> RelayEnvelope {
    seal_envelope(
        from.ident.as_ref(),
        from_id,
        to_id,
        &to.kem_pk(),
        msg,
        aipass_types::time::now(),
    )
    .unwrap()
}

struct World {
    srv: Server,
    phone: Device,
    node: Device,
    outsider_owner: Device,
}

async fn world(opts: Options) -> World {
    let srv = start(opts).await;
    let phone = Device::new();
    let node = Device::new();
    let vault = srv.create_vault(&phone).await;
    srv.add_member(
        &vault,
        &node,
        1,
        MemberRole::Executor,
        MemberStatus::Active,
        &phone,
    )
    .await;
    let outsider_owner = Device::new();
    srv.create_vault(&outsider_owner).await;
    World {
        srv,
        phone,
        node,
        outsider_owner,
    }
}

fn api_code(e: RelayClientError) -> ErrorCode {
    match e {
        RelayClientError::Api(a) => a.code,
        other => panic!("expected API error, got {other:?}"),
    }
}

#[tokio::test]
async fn long_poll_delivery_and_minimal_push() {
    let w = world(Options::default()).await;
    let phone_mb = MailboxId::Device(w.phone.id.clone());
    let exe = w.node.executor_principal();
    let exe_mb = MailboxId::parse(exe.as_str()).unwrap();
    let phone_client = client(&w.srv, w.phone.principal(), &w.phone);
    let node_client = client(&w.srv, exe.clone(), &w.node);

    // the phone starts a long-poll before anything is in its mailbox
    let mb = phone_mb.clone();
    let pc = phone_client.clone();
    let started = Instant::now();
    let waiter = tokio::spawn(async move { pc.fetch(&mb, None, 20).await });
    tokio::time::sleep(Duration::from_millis(200)).await;

    // the executor (broker) sends an approval request sealed to the phone
    let req = approval_request();
    let env = seal(
        &w.node,
        exe_mb.clone(),
        &w.phone,
        phone_mb.clone(),
        &RelayMessage::ApprovalRequest(Box::new(req.clone())),
    );
    let id = node_client.post(&env).await.unwrap();

    let msgs = waiter.await.unwrap().unwrap();
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "long-poll returned on delivery"
    );
    assert_eq!(msgs.len(), 1);
    assert_eq!(msgs[0].message_id, id);
    let opened = open_envelope(
        w.phone.ident.kem_keypair(),
        &w.node.sign_pk(),
        &msgs[0].envelope,
    )
    .unwrap();
    assert_eq!(opened, RelayMessage::ApprovalRequest(Box::new(req)));

    // the push hook got exactly {mailbox, message_id}
    for _ in 0..50 {
        if !w.srv.push.hints.lock().unwrap().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let hints = w.srv.push.hints.lock().unwrap().clone();
    assert_eq!(hints.len(), 1);
    let obj = hints[0].as_object().unwrap();
    assert_eq!(
        obj.len(),
        2,
        "push payload must only carry mailbox + message_id: {obj:?}"
    );
    assert_eq!(obj["mailbox"], phone_mb.as_str());
    assert_eq!(obj["message_id"], id.as_str());

    // the phone answers to the executor mailbox; no push for exe_ mailboxes / other types
    let reply = seal(
        &w.phone,
        phone_mb.clone(),
        &w.node,
        exe_mb.clone(),
        &RelayMessage::StateRequest(StateRequest {}),
    );
    phone_client.post(&reply).await.unwrap();
    let got = node_client.fetch(&exe_mb, None, 0).await.unwrap();
    assert_eq!(got.len(), 1);
    let cancel = seal(
        &w.node,
        exe_mb.clone(),
        &w.phone,
        phone_mb.clone(),
        &cancelled(),
    );
    node_client.post(&cancel).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        w.srv.push.hints.lock().unwrap().len(),
        1,
        "only approval.request / connection.pair_request push"
    );

    // cursor + ack
    let all = phone_client.fetch(&phone_mb, None, 0).await.unwrap();
    assert_eq!(all.len(), 2);
    let after_first = phone_client
        .fetch(&phone_mb, Some(&all[0].message_id), 0)
        .await
        .unwrap();
    assert_eq!(after_first.len(), 1);
    assert_eq!(after_first[0].message_id, all[1].message_id);
    phone_client
        .delete(&phone_mb, &all[0].message_id)
        .await
        .unwrap();
    // cursor still works after the cursor message was deleted
    let again = phone_client
        .fetch(&phone_mb, Some(&all[0].message_id), 0)
        .await
        .unwrap();
    assert_eq!(again.len(), 1);
    assert_eq!(
        phone_client.fetch(&phone_mb, None, 0).await.unwrap().len(),
        1
    );

    // an empty long-poll times out with an empty list
    let t = Instant::now();
    let none = node_client
        .fetch(&exe_mb, Some(&got[0].message_id), 1)
        .await
        .unwrap();
    assert!(none.is_empty());
    assert!(t.elapsed() >= Duration::from_millis(900));
}

#[tokio::test]
async fn relay_authorization_rules() {
    let w = world(Options::default()).await;
    let phone_mb = MailboxId::Device(w.phone.id.clone());
    let exe = w.node.executor_principal();
    let exe_mb = MailboxId::parse(exe.as_str()).unwrap();
    let node_client = client(&w.srv, exe.clone(), &w.node);
    let phone_client = client(&w.srv, w.phone.principal(), &w.phone);

    // a member of another vault may not post to the phone
    let outsider = client(&w.srv, w.outsider_owner.principal(), &w.outsider_owner);
    let env = seal(
        &w.outsider_owner,
        MailboxId::Device(w.outsider_owner.id.clone()),
        &w.phone,
        phone_mb.clone(),
        &cancelled(),
    );
    assert_eq!(
        api_code(outsider.post(&env).await.unwrap_err()),
        ErrorCode::Forbidden
    );

    // unknown device
    let stranger = Device::new();
    let sc = client(&w.srv, stranger.principal(), &stranger);
    let env = seal(
        &stranger,
        MailboxId::Device(stranger.id.clone()),
        &w.phone,
        phone_mb.clone(),
        &cancelled(),
    );
    assert_eq!(
        api_code(sc.post(&env).await.unwrap_err()),
        ErrorCode::IdentityUnverified
    );

    // spoofed `from`
    let env = seal(
        &w.node,
        phone_mb.clone(),
        &w.phone,
        phone_mb.clone(),
        &cancelled(),
    );
    assert_eq!(
        api_code(node_client.post(&env).await.unwrap_err()),
        ErrorCode::Forbidden
    );

    // tampered envelope (signature no longer matches)
    let mut env = seal(
        &w.node,
        exe_mb.clone(),
        &w.phone,
        phone_mb.clone(),
        &cancelled(),
    );
    env.created_at = aipass_types::time::add_secs(&env.created_at, -1);
    assert_eq!(
        api_code(node_client.post(&env).await.unwrap_err()),
        ErrorCode::IntegrityFailed
    );

    // only the owner reads a mailbox
    assert_eq!(
        api_code(node_client.fetch(&phone_mb, None, 0).await.unwrap_err()),
        ErrorCode::IdentityUnverified
    );
    assert_eq!(
        api_code(
            phone_client
                .delete(&exe_mb, &aipass_types::ids::MessageId::generate())
                .await
                .unwrap_err()
        ),
        ErrorCode::IdentityUnverified
    );

    // AI connections cannot use the relay at all
    let conn = PrincipalId::parse("conn_01jbz3k6w8a7m2q4t5v9x0y1z4").unwrap();
    assert!(
        RelayClient::with_client(
            w.srv.base.clone(),
            RelayAuth::Signed {
                kid: conn,
                signer: w.phone.signer()
            },
            http(),
            false
        )
        .is_err()
    );

    // a revoked executor loses relay access immediately on this server
    let vault = w.srv.sync.vaults_of(&w.phone.id).await.unwrap()[0].clone();
    w.srv
        .add_member(
            &vault,
            &w.node,
            2,
            MemberRole::Executor,
            MemberStatus::Revoked,
            &w.phone,
        )
        .await;
    let env = seal(
        &w.node,
        exe_mb.clone(),
        &w.phone,
        phone_mb.clone(),
        &cancelled(),
    );
    assert_eq!(
        api_code(node_client.post(&env).await.unwrap_err()),
        ErrorCode::IdentityUnverified
    );
}

#[tokio::test]
async fn relay_replay_is_rejected() {
    let w = world(Options::default()).await;
    let c = http();
    let path = format!("/v1/relay/{}?wait=0", w.phone.id);
    let now = aipass_types::time::unix_now();
    let nonce = aipass_crypto::b64u::encode([42u8; 16]);
    let h = aipass_types::signing::sign_request_with(
        w.phone.ident.as_ref(),
        w.phone.id.as_str(),
        "GET",
        &path,
        &[],
        now,
        &nonce,
    );
    let url = w.srv.base.join(path.trim_start_matches('/')).unwrap();
    let r1 = c
        .get(url.clone())
        .header("authorization", h.to_header_value())
        .send()
        .await
        .unwrap();
    assert_eq!(r1.status(), 200);
    let r2 = c
        .get(url)
        .header("authorization", h.to_header_value())
        .send()
        .await
        .unwrap();
    assert_eq!(r2.status(), 401);
}

#[tokio::test]
async fn ttl_expiry_and_gc() {
    let w = world(Options::default()).await;
    let phone_mb = MailboxId::Device(w.phone.id.clone());
    let exe = w.node.executor_principal();
    let node_client = client(&w.srv, exe.clone(), &w.node);
    let env = seal(
        &w.node,
        MailboxId::parse(exe.as_str()).unwrap(),
        &w.phone,
        phone_mb.clone(),
        &cancelled(),
    );
    node_client.post(&env).await.unwrap();
    let phone_client = client(&w.srv, w.phone.principal(), &w.phone);
    assert_eq!(
        phone_client.fetch(&phone_mb, None, 0).await.unwrap().len(),
        1
    );

    // 24 h later the message is gone, even before GC runs
    w.srv.clock.advance(24 * 3600 + 1);
    let c = http();
    let path = format!("/v1/relay/{}", w.phone.id);
    let h = aipass_types::signing::sign_request_with(
        w.phone.ident.as_ref(),
        w.phone.id.as_str(),
        "GET",
        &path,
        &[],
        w.srv.clock.unix(),
        &aipass_crypto::b64u::encode([5u8; 16]),
    );
    let r = c
        .get(w.srv.base.join(path.trim_start_matches('/')).unwrap())
        .header("authorization", h.to_header_value())
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let body: serde_json::Value = r.json().await.unwrap();
    assert_eq!(body["messages"].as_array().unwrap().len(), 0);
    let stats = w.srv.relay.gc_once().await.unwrap();
    assert_eq!(stats.messages, 1);
    // envelopes older than the TTL are refused outright
    let old = seal(
        &w.node,
        MailboxId::parse(exe.as_str()).unwrap(),
        &w.phone,
        phone_mb.clone(),
        &cancelled(),
    );
    let body = serde_json::to_vec(&old).unwrap();
    let path = format!("/v1/relay/{}", w.phone.id);
    let h = aipass_types::signing::sign_request_with(
        w.node.ident.as_ref(),
        exe.as_str(),
        "POST",
        &path,
        &body,
        w.srv.clock.unix(),
        &aipass_crypto::b64u::encode([6u8; 16]),
    );
    let r = c
        .post(w.srv.base.join(path.trim_start_matches('/')).unwrap())
        .header("authorization", h.to_header_value())
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 400);
}

#[tokio::test]
async fn pairing_mailbox_secret() {
    let srv = start(Options::default()).await;
    let pid = PairingId::generate();
    let mb = MailboxId::Pairing(pid.clone());
    let secret = aipass_crypto::rng::random_array::<16>();
    let new_dev = Device::new();
    let old_dev = Device::new();
    let n = RelayClient::with_client(
        srv.base.clone(),
        RelayAuth::PairingSecret(zeroize::Zeroizing::new(secret)),
        http(),
        false,
    )
    .unwrap();
    let o = RelayClient::with_client(
        srv.base.clone(),
        RelayAuth::PairingSecret(zeroize::Zeroizing::new(secret)),
        http(),
        false,
    )
    .unwrap();
    // N registers the mailbox by polling first (right after showing its QR code)
    assert!(n.fetch(&mb, None, 0).await.unwrap().is_empty());
    let mbc = mb.clone();
    let nc = n.clone();
    let waiter = tokio::spawn(async move { nc.fetch(&mbc, None, 10).await });
    tokio::time::sleep(Duration::from_millis(100)).await;
    // O posts (sealed to N's key; envelope sig by O, verified by N later)
    let env = seal(&old_dev, mb.clone(), &new_dev, mb.clone(), &cancelled());
    let id = o.post(&env).await.unwrap();
    let got = waiter.await.unwrap().unwrap();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].message_id, id);
    let opened = open_envelope_unverified(new_dev.ident.kem_keypair(), &got[0].envelope).unwrap();
    assert!(matches!(opened, RelayMessage::ApprovalCancelled(_)));

    // wrong secret / missing secret
    let wrong = RelayClient::with_client(
        srv.base.clone(),
        RelayAuth::PairingSecret(zeroize::Zeroizing::new([0u8; 16])),
        http(),
        false,
    )
    .unwrap();
    assert_eq!(
        api_code(wrong.fetch(&mb, None, 0).await.unwrap_err()),
        ErrorCode::IdentityUnverified
    );
    assert_eq!(
        api_code(wrong.post(&env).await.unwrap_err()),
        ErrorCode::IdentityUnverified
    );
    let signed = client(&srv, new_dev.principal(), &new_dev);
    assert_eq!(
        api_code(signed.fetch(&mb, None, 0).await.unwrap_err()),
        ErrorCode::IdentityUnverified
    );

    // no push for pairing mailboxes
    assert!(srv.push.hints.lock().unwrap().is_empty());

    // 10 minutes later the pairing mailbox is gone
    srv.clock.advance(601);
    let stats = srv.relay.gc_once().await.unwrap();
    assert_eq!(stats.pairings, 1);
    assert_eq!(stats.messages, 1);
}

#[tokio::test]
async fn mailbox_cap() {
    let w = world(Options {
        relay_cfg: RelayConfig {
            max_messages_per_mailbox: 3,
            ..Default::default()
        },
        ..Default::default()
    })
    .await;
    let phone_mb = MailboxId::Device(w.phone.id.clone());
    let exe = w.node.executor_principal();
    let nc = client(&w.srv, exe.clone(), &w.node);
    for _ in 0..3 {
        let env = seal(
            &w.node,
            MailboxId::parse(exe.as_str()).unwrap(),
            &w.phone,
            phone_mb.clone(),
            &cancelled(),
        );
        nc.post(&env).await.unwrap();
    }
    let env = seal(
        &w.node,
        MailboxId::parse(exe.as_str()).unwrap(),
        &w.phone,
        phone_mb.clone(),
        &cancelled(),
    );
    match nc.post(&env).await.unwrap_err() {
        RelayClientError::Api(a) => {
            assert_eq!(a.code, ErrorCode::RateLimited);
            assert_eq!(a.details["reason"], "mailbox_full");
        }
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn sqlite_store_end_to_end_and_persistence() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("relay.db");
    let store = Arc::new(SqliteRelayStore::open(&path).unwrap());
    let w = world(Options {
        relay_store: store.clone(),
        ..Default::default()
    })
    .await;
    let phone_mb = MailboxId::Device(w.phone.id.clone());
    let exe = w.node.executor_principal();
    let nc = client(&w.srv, exe.clone(), &w.node);
    let pc = client(&w.srv, w.phone.principal(), &w.phone);
    let mbc = phone_mb.clone();
    let pcc = pc.clone();
    let waiter = tokio::spawn(async move { pcc.fetch(&mbc, None, 10).await });
    tokio::time::sleep(Duration::from_millis(100)).await;
    let env = seal(
        &w.node,
        MailboxId::parse(exe.as_str()).unwrap(),
        &w.phone,
        phone_mb.clone(),
        &RelayMessage::ApprovalRequest(Box::new(approval_request())),
    );
    let id = nc.post(&env).await.unwrap();
    let got = waiter.await.unwrap().unwrap();
    assert_eq!(got[0].message_id, id);
    assert_eq!(got[0].envelope, env);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o077, 0, "relay database must be private");
    }
    drop(w);
    // reopen: message persisted, new ids stay monotonic
    let reopened = SqliteRelayStore::open(&path).unwrap();
    let now = aipass_types::time::now();
    let msgs = reopened.fetch(&phone_mb, None, now, 10).await.unwrap();
    assert_eq!(msgs.len(), 1);
    assert_eq!(msgs[0].envelope, env);
    let out = reopened
        .insert(
            &phone_mb,
            &env,
            now,
            aipass_types::time::add_secs(&now, 60),
            500,
        )
        .await
        .unwrap();
    match out {
        aipass_sync_server::relay::InsertOutcome::Inserted(new_id) => {
            assert!(new_id.as_str() > id.as_str())
        }
        other => panic!("{other:?}"),
    }
    // pairing secret binding + gc
    let pid = PairingId::generate();
    let h = [9u8; 32];
    let exp = aipass_types::time::add_secs(&now, 600);
    assert!(matches!(
        reopened.pairing_secret(&pid, &h, exp, now).await.unwrap(),
        aipass_sync_server::relay::PairingCheck::Registered { .. }
    ));
    assert!(matches!(
        reopened.pairing_secret(&pid, &h, exp, now).await.unwrap(),
        aipass_sync_server::relay::PairingCheck::Matched { .. }
    ));
    assert_eq!(
        reopened
            .pairing_secret(&pid, &[1u8; 32], exp, now)
            .await
            .unwrap(),
        aipass_sync_server::relay::PairingCheck::Mismatch
    );
    let later = aipass_types::time::add_secs(&now, 24 * 3600 + 5);
    let st = reopened.gc(later).await.unwrap();
    assert_eq!(st.messages, 2);
    assert_eq!(st.pairings, 1);
}

#[tokio::test]
async fn static_directory_for_self_host_nodes() {
    // a node whose vault lives on the user's own S3: approvers come from pairing, not from
    // the co-located sync server
    let dir = Arc::new(StaticDirectory::new());
    let srv = start(Options {
        directory: Some(dir.clone()),
        relay_store: Arc::new(MemoryRelayStore::new()),
        ..Default::default()
    })
    .await;
    let phone = Device::new();
    let node = Device::new();
    let exe = node.executor_principal();
    dir.insert(
        phone.principal(),
        phone.sign_pk(),
        ["vlt_01jbz3k6w8a7m2q4t5v9x0y1z0".to_owned()],
    );
    dir.insert(
        exe.clone(),
        node.sign_pk(),
        ["vlt_01jbz3k6w8a7m2q4t5v9x0y1z0".to_owned()],
    );
    let nc = client(&srv, exe.clone(), &node);
    let phone_mb = MailboxId::Device(phone.id.clone());
    let env = seal(
        &node,
        MailboxId::parse(exe.as_str()).unwrap(),
        &phone,
        phone_mb.clone(),
        &cancelled(),
    );
    nc.post(&env).await.unwrap();
    dir.remove(&phone.principal());
    let env = seal(
        &node,
        MailboxId::parse(exe.as_str()).unwrap(),
        &phone,
        phone_mb.clone(),
        &cancelled(),
    );
    assert_eq!(
        api_code(nc.post(&env).await.unwrap_err()),
        ErrorCode::Forbidden
    );
}

#[tokio::test]
async fn webhook_push_is_minimal_and_signed() {
    use aipass_sync_server::relay::{PushNotifier, WEBHOOK_SIGNATURE_HEADER, WebhookPushNotifier};
    type Calls = Arc<tokio::sync::Mutex<Vec<(String, Vec<u8>)>>>;
    let got: Calls = Default::default();
    let g = got.clone();
    let app = axum::Router::new().route(
        "/hook",
        axum::routing::post(
            move |headers: axum::http::HeaderMap, body: axum::body::Bytes| {
                let g = g.clone();
                async move {
                    let sig = headers
                        .get(WEBHOOK_SIGNATURE_HEADER)
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("")
                        .to_owned();
                    g.lock().await.push((sig, body.to_vec()));
                    axum::http::StatusCode::NO_CONTENT
                }
            },
        ),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    let secret = aipass_crypto::SecretBytes::new(vec![7u8; 32]);
    let n = WebhookPushNotifier::new(
        url::Url::parse(&format!("http://127.0.0.1:{}/hook", addr.port())).unwrap(),
        Some(secret.clone()),
    )
    .unwrap();
    assert!(
        WebhookPushNotifier::new(
            url::Url::parse("http://push.example.com/hook").unwrap(),
            None
        )
        .is_err()
    );
    let hint = aipass_types::relay::PushHint {
        mailbox: MailboxId::Device(aipass_types::ids::DeviceId::generate()),
        message_id: aipass_types::ids::MessageId::generate(),
    };
    n.notify(hint.clone()).await;
    let calls = got.lock().await.clone();
    assert_eq!(calls.len(), 1);
    let (sig, body) = &calls[0];
    let v: serde_json::Value = serde_json::from_slice(body).unwrap();
    assert_eq!(v.as_object().unwrap().len(), 2);
    assert_eq!(v["message_id"], hint.message_id.as_str());
    let tag = aipass_crypto::hash::hmac_sha256(secret.expose(), body);
    assert_eq!(sig, &format!("v1={}", hex::encode(tag)));
}
