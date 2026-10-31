// SPDX-License-Identifier: Apache-2.0
//! Connection pairing, approval, tokens and control.

mod common;

use aipass_broker::{Actor, NewConnection, PairingInput};
use aipass_crypto::Ed25519Keypair;
use aipass_types::error::{ErrorCode, Lang};
use aipass_types::models::{AllowedProjects, ConnectionStatus, HostType, OperationStatus, PairStatus, Transport};
use aipass_types::relay::ControlAction;
use common::*;

fn input(name: &str) -> PairingInput {
    PairingInput {
        host_type: HostType::Codex,
        display_name: name.into(),
        transport: Transport::Stdio,
        public_key: Some(Ed25519Keypair::generate().public_key_b64u()),
    }
}

#[tokio::test]
async fn pairing_requires_trusted_approval_with_projects() {
    let h = Harness::new().await;
    let mut events = h.broker.subscribe();
    let p = h.broker.begin_pairing(input("Codex CLI")).await.unwrap();
    assert_eq!(p.pairing_code.len(), 6);
    assert!(p.pairing_code.chars().all(|c| c.is_ascii_digit()));
    match events.recv().await.unwrap() {
        aipass_broker::BrokerEvent::ConnectionPairingRequested { connection, pairing_code } => {
            assert_eq!(connection.connection_id, p.connection_id);
            assert_eq!(pairing_code, p.pairing_code);
        }
        other => panic!("unexpected {other:?}"),
    }
    let principal = aipass_broker::ConnectionPrincipal::in_process(p.connection_id.clone());
    // a pending connection can do nothing
    assert_eq!(h.broker.list_resources(&principal, None, None, Lang::ZhCn).await.unwrap_err().code, ErrorCode::IdentityUnverified);
    assert_eq!(h.broker.pair_status(&p.pairing_request_id, &p.connection_id).await.unwrap().status, PairStatus::Pending);
    // another connection cannot poll it
    assert_eq!(
        h.broker.pair_status(&p.pairing_request_id, h.conn.connection_id()).await.unwrap_err().code,
        ErrorCode::NotFound
    );
    // unknown project in the approval
    let e = h
        .broker
        .approve_connection(&Actor::Device(h.device_id.clone()), &p.connection_id, AllowedProjects::Only([aipass_types::ids::ProjectId::generate()].into()))
        .await
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::InvalidRequest);
    let c = h
        .broker
        .approve_connection(&Actor::Device(h.device_id.clone()), &p.connection_id, AllowedProjects::Only([h.project.clone()].into()))
        .await
        .unwrap();
    assert_eq!(c.status, ConnectionStatus::Active);
    assert_eq!(c.approved_by.as_ref(), Some(&h.device_id));
    assert_eq!(h.broker.pair_status(&p.pairing_request_id, &p.connection_id).await.unwrap().status, PairStatus::Approved);
    assert_eq!(h.broker.list_resources(&principal, None, None, Lang::ZhCn).await.unwrap().resources.len(), 1);
}

#[tokio::test]
async fn pairing_deny_expiry_and_flood_limits() {
    let h = Harness::new().await;
    let p = h.broker.begin_pairing(input("Denied")).await.unwrap();
    h.broker.deny_connection(&Actor::Admin, &p.connection_id).await.unwrap();
    assert_eq!(h.broker.pair_status(&p.pairing_request_id, &p.connection_id).await.unwrap().status, PairStatus::Denied);

    let p = h.broker.begin_pairing(input("Late")).await.unwrap();
    h.clock.advance(601);
    assert_eq!(h.broker.pair_status(&p.pairing_request_id, &p.connection_id).await.unwrap().status, PairStatus::Expired);
    let e = h
        .broker
        .approve_connection(&Actor::Admin, &p.connection_id, AllowedProjects::All)
        .await
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::NotFound, "an expired pairing's connection is removed");

    for i in 0..10 {
        h.broker.begin_pairing(input(&format!("flood {i}"))).await.unwrap();
    }
    assert_eq!(h.broker.begin_pairing(input("one too many")).await.unwrap_err().code, ErrorCode::RateLimited);
    h.clock.advance(601);
    let s = h.broker.sweep().await.unwrap();
    assert_eq!(s.pairings_expired, 10);
    h.broker.begin_pairing(input("after sweep")).await.unwrap();

    // validation
    let mut bad = input("x");
    bad.public_key = Some("not-a-key".into());
    assert_eq!(h.broker.begin_pairing(bad).await.unwrap_err().code, ErrorCode::InvalidRequest);
    assert_eq!(h.broker.begin_pairing(input("  ")).await.unwrap_err().code, ErrorCode::InvalidRequest);
    assert_eq!(h.broker.begin_pairing(input(&"长".repeat(65))).await.unwrap_err().code, ErrorCode::InvalidRequest);
}

#[tokio::test]
async fn bearer_tokens_are_hashed_and_die_with_the_connection() {
    let h = Harness::new().await;
    let created = h
        .broker
        .create_connection(
            &Actor::Admin,
            NewConnection {
                host_type: HostType::Sdk,
                display_name: "remote agent".into(),
                transport: Transport::Sdk,
                allowed_projects: AllowedProjects::All,
                public_key: None,
            },
        )
        .await
        .unwrap();
    let token = created.token.clone().unwrap();
    assert!(token.starts_with("aipc_"));
    let p = h.broker.authenticate_connection_token(&token).await.unwrap();
    assert_eq!(p.connection_id(), &created.connection.connection_id);
    assert_eq!(p.via(), aipass_broker::AuthVia::ConnectionToken);
    assert!(h.broker.authenticate_connection_token("aipc_wrong").await.is_err());
    // the database holds only the hash
    let audit = serde_json::to_string(&h.broker.audit_events(0, 1000).await.unwrap()).unwrap();
    assert!(!audit.contains(&token));
    let r = h.broker.request_operation(&p, h.query("t", &["day"]), Lang::ZhCn).await.unwrap();
    assert_eq!(r.status, OperationStatus::AwaitingApproval);
    h.broker.control_connection(&Actor::Admin, &created.connection.connection_id, ControlAction::Remove).await.unwrap();
    assert_eq!(h.broker.authenticate_connection_token(&token).await.unwrap_err().code, ErrorCode::IdentityUnverified);
}

#[tokio::test]
async fn import_connection_keeps_given_identity() {
    let h = Harness::new().await;
    let id = aipass_types::ids::ConnectionId::parse("conn_01jbz3k6w8a7m2q4t5v9x0y1z4").unwrap();
    let conn = aipass_types::models::AppConnection {
        connection_id: id.clone(),
        host_type: HostType::Custom,
        display_name: "imported".into(),
        transport: Transport::Http,
        status: ConnectionStatus::Active,
        public_key: Some("A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg".into()),
        allowed_projects: AllowedProjects::All,
        created_at: h.clock.now_ts(),
        approved_at: None,
        approved_by: None,
        last_seen_at: None,
    };
    h.broker.import_connection(conn.clone()).await.unwrap();
    assert_eq!(h.broker.get_connection(&id).await.unwrap().display_name, "imported");
    let mut renamed = conn;
    renamed.display_name = "renamed".into();
    h.broker.import_connection(renamed).await.unwrap();
    assert_eq!(h.broker.get_connection(&id).await.unwrap().display_name, "renamed");
}

/// BRK-06: one peer cannot take every pending-pairing slot (nor keep the devices busy
/// with prompts): it is capped per peer, while other peers can still pair.
#[tokio::test]
async fn pending_pairings_are_capped_per_peer() {
    let h = Harness::new().await;
    let cap = h.broker.config().max_pending_pairings_per_peer;
    for k in 0..cap {
        h.broker.begin_pairing_from(input(&format!("A{k}")), Some("203.0.113.7")).await.unwrap();
    }
    let e = h.broker.begin_pairing_from(input("A-extra"), Some("203.0.113.7")).await.unwrap_err();
    assert_eq!(e.code, ErrorCode::RateLimited);
    // another peer and an in-process caller are unaffected
    h.broker.begin_pairing_from(input("B"), Some("198.51.100.2")).await.unwrap();
    h.broker.begin_pairing(input("local")).await.unwrap();
    // once the peer's pairings expire it may pair again
    h.clock.advance(601);
    h.broker.begin_pairing_from(input("A-again"), Some("203.0.113.7")).await.unwrap();
}
