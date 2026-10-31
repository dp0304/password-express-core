// SPDX-License-Identifier: Apache-2.0
//! Device ↔ broker relay messages: sealed approval requests, inbound decisions and
//! controls, snapshots, revoke reports, replay and ordering protection.

mod common;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use aipass_broker::{DeviceOutbox, RelayIdentity};
use aipass_crypto::DeviceIdentity;
use aipass_types::approval;
use aipass_types::error::{ApiError, ErrorCode, Lang};
use aipass_types::exec::{CredentialAad, seal_credential};
use aipass_types::ids::MailboxId;
use aipass_types::models::{ConnectionStatus, Decision, GrantStatus, OperationStatus, RevocationLevel};
use aipass_types::relay::{
    ConnectionControl, ControlAction, DeviceSigned, GrantRevoke, RelayEnvelope, RelayMessage, RelayMessageType,
    StateRequest, open_envelope, seal_envelope,
};
use async_trait::async_trait;
use common::*;

#[derive(Default)]
struct Capture(Mutex<Vec<RelayEnvelope>>);

#[async_trait]
impl DeviceOutbox for Capture {
    async fn deliver(&self, envelope: RelayEnvelope) -> Result<(), ApiError> {
        self.0.lock().unwrap().push(envelope);
        Ok(())
    }
}

struct Relay {
    outbox: Arc<Capture>,
    broker_id: Arc<DeviceIdentity>,
    mailbox: MailboxId,
}

fn wire(h: &Harness) -> Relay {
    let outbox = Arc::new(Capture::default());
    let broker_id = Arc::new(DeviceIdentity::generate());
    let mailbox = MailboxId::Executor(h.exe.id.clone());
    h.broker.set_relay(
        RelayIdentity {
            mailbox: mailbox.clone(),
            identity: broker_id.clone(),
        },
        outbox.clone(),
    );
    Relay { outbox, broker_id, mailbox }
}

impl Relay {
    fn seal_from_device(&self, h: &Harness, msg: &RelayMessage) -> RelayEnvelope {
        seal_envelope(
            &h.device,
            MailboxId::Device(h.device_id.clone()),
            self.mailbox.clone(),
            &self.broker_id.public().kem_pk,
            msg,
            h.clock.now_ts(),
        )
        .unwrap()
    }
    fn open(&self, h: &Harness, env: &RelayEnvelope) -> RelayMessage {
        open_envelope(h.device.kem_keypair(), &self.broker_id.public().sign_pk, env).unwrap()
    }
    async fn wait_for(&self, t: RelayMessageType) -> RelayEnvelope {
        for _ in 0..200 {
            if let Some(e) = self.outbox.0.lock().unwrap().iter().find(|e| e.message_type == t) {
                return e.clone();
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!("no {t:?} delivered");
    }
}

#[tokio::test]
async fn approval_round_trip_over_the_relay() {
    let h = Harness::new().await;
    let relay = wire(&h);
    let r = h.broker.request_operation(&h.conn, h.query("a", &["day"]), Lang::ZhCn).await.unwrap();
    let env = relay.wait_for(RelayMessageType::ApprovalRequest).await;
    assert_eq!(env.to, MailboxId::Device(h.device_id.clone()));
    let text = serde_json::to_string(&env).unwrap();
    assert!(!text.contains("路亚站测试库"), "the relay sees only ciphertext");
    let RelayMessage::ApprovalRequest(req) = relay.open(&h, &env) else { panic!() };
    assert_eq!(Some(&req.approval_request_id), r.approval_request_id.as_ref());

    // the phone recomputes the digest from what it displayed, signs, seals the credential
    let mut d = approval::build_decision(&h.device, &h.device_id, &req, Decision::Approve, None, &h.clock.now_ts()).unwrap();
    let aad = CredentialAad {
        approval_request_id: req.approval_request_id.clone(),
        digest: d.digest.clone(),
        executor_id: req.executor.executor_id.clone(),
    };
    d.credential_envelope = Some(seal_credential(&req_kem(&h), &aad.to_bytes().unwrap(), &h.material(&h.resource)).unwrap());
    let inbound = relay.seal_from_device(&h, &RelayMessage::ApprovalDecision(Box::new(d)));
    let replies = h.broker.handle_device_message(&inbound).await.unwrap();
    assert!(replies.is_empty());
    let s = h.broker.get_operation(&h.conn, &r.operation_id, Lang::ZhCn).await.unwrap();
    assert_eq!(s.status, OperationStatus::Succeeded);
    // replaying the same envelope is refused
    assert!(h.broker.handle_device_message(&inbound).await.is_err());
}

fn req_kem(h: &Harness) -> [u8; 32] {
    h.exe.kem.public_key()
}

#[tokio::test]
async fn state_request_and_grant_revoke_produce_sealed_replies() {
    let h = Harness::new().await;
    let relay = wire(&h);
    let r = h.broker.request_operation(&h.conn, h.query("a", &["day"]), Lang::ZhCn).await.unwrap();
    let grant = h.approve(r.approval_request_id.as_ref().unwrap()).await.grant_id.unwrap();

    let env = relay.seal_from_device(&h, &RelayMessage::StateRequest(StateRequest {}));
    let replies = h.broker.handle_device_message(&env).await.unwrap();
    assert_eq!(replies.len(), 1);
    assert_eq!(replies[0].to, MailboxId::Device(h.device_id.clone()));
    let RelayMessage::StateSnapshot(snap) = relay.open(&h, &replies[0]) else { panic!() };
    assert_eq!(snap.grants.len(), 1);
    assert!(!snap.connections.is_empty());
    assert!(snap.recent_operations.iter().all(|o| o.result.is_none()), "snapshots carry metadata, never results");
    assert_no_secret(&serde_json::to_string(&snap.grants).unwrap());

    let mut rv = GrantRevoke {
        grant_id: grant.clone(),
        level: RevocationLevel::EndSessions,
        signed_at: h.clock.now_ts(),
        signature: String::new(),
    };
    rv.sign_control(&h.device).unwrap();
    let replies = h.broker.handle_device_message(&relay.seal_from_device(&h, &RelayMessage::GrantRevoke(rv.clone()))).await.unwrap();
    let RelayMessage::RevokeReport(rep) = relay.open(&h, &replies[0]) else { panic!() };
    assert_eq!(rep.grant_id, grant);
    assert!(rep.fully_revoked());
    assert_eq!(h.broker.get_grant(&grant).await.unwrap().status, GrantStatus::Revoked);

    // a control message with a broken signature is refused
    let mut forged = rv;
    forged.level = RevocationLevel::RevokeUpstream;
    let e = h.broker.handle_device_message(&relay.seal_from_device(&h, &RelayMessage::GrantRevoke(forged))).await.unwrap_err();
    assert_eq!(e.code, ErrorCode::IntegrityFailed);
}

#[tokio::test]
async fn connection_controls_apply_in_order() {
    let h = Harness::new().await;
    let relay = wire(&h);
    let ctl = |action: ControlAction, at| {
        let mut c = ConnectionControl {
            connection_id: h.conn.connection_id().clone(),
            action,
            signed_at: at,
            signature: String::new(),
        };
        c.sign_control(&h.device).unwrap();
        RelayMessage::ConnectionControl(c)
    };
    let t_resume = h.clock.now_ts();
    h.clock.advance(5);
    let pause = ctl(ControlAction::Pause, h.clock.now_ts());
    let old_resume = ctl(ControlAction::Resume, t_resume);
    h.broker.handle_device_message(&relay.seal_from_device(&h, &pause)).await.unwrap();
    assert_eq!(h.broker.get_connection(h.conn.connection_id()).await.unwrap().status, ConnectionStatus::Paused);
    // an older resume delivered late (or replayed by the relay) does not undo the pause
    assert!(h.broker.handle_device_message(&relay.seal_from_device(&h, &old_resume)).await.is_err());
    assert_eq!(h.broker.get_connection(h.conn.connection_id()).await.unwrap().status, ConnectionStatus::Paused);
    h.clock.advance(5);
    h.broker
        .handle_device_message(&relay.seal_from_device(&h, &ctl(ControlAction::Resume, h.clock.now_ts())))
        .await
        .unwrap();
    assert_eq!(h.broker.get_connection(h.conn.connection_id()).await.unwrap().status, ConnectionStatus::Active);
}

#[tokio::test]
async fn envelopes_from_strangers_or_stale_are_refused() {
    let h = Harness::new().await;
    let relay = wire(&h);
    let stranger = DeviceIdentity::generate();
    let env = seal_envelope(
        &stranger,
        MailboxId::Device(aipass_types::ids::DeviceId::generate()),
        relay.mailbox.clone(),
        &relay.broker_id.public().kem_pk,
        &RelayMessage::StateRequest(StateRequest {}),
        h.clock.now_ts(),
    )
    .unwrap();
    assert_eq!(h.broker.handle_device_message(&env).await.unwrap_err().code, ErrorCode::IdentityUnverified);
    // trusted device id but signed by someone else
    let env = seal_envelope(
        &stranger,
        MailboxId::Device(h.device_id.clone()),
        relay.mailbox.clone(),
        &relay.broker_id.public().kem_pk,
        &RelayMessage::StateRequest(StateRequest {}),
        h.clock.now_ts(),
    )
    .unwrap();
    assert_eq!(h.broker.handle_device_message(&env).await.unwrap_err().code, ErrorCode::IntegrityFailed);
    // stale
    let env = relay.seal_from_device(&h, &RelayMessage::StateRequest(StateRequest {}));
    h.clock.advance(25 * 3600);
    assert_eq!(h.broker.handle_device_message(&env).await.unwrap_err().code, ErrorCode::InvalidRequest);
    let audit = h.broker.audit_events(0, 1000).await.unwrap();
    assert!(audit.events.iter().filter(|e| e.action == "relay.message_rejected").count() >= 3);
}

#[tokio::test]
async fn pairing_requests_reach_devices() {
    let h = Harness::new().await;
    let relay = wire(&h);
    let p = h
        .broker
        .begin_pairing(aipass_broker::PairingInput {
            host_type: aipass_types::models::HostType::Cursor,
            display_name: "Cursor".into(),
            transport: aipass_types::models::Transport::Stdio,
            public_key: Some(aipass_crypto::Ed25519Keypair::generate().public_key_b64u()),
        })
        .await
        .unwrap();
    let env = relay.wait_for(RelayMessageType::ConnectionPairRequest).await;
    let RelayMessage::ConnectionPairRequest(m) = relay.open(&h, &env) else { panic!() };
    assert_eq!(m.pairing_code, p.pairing_code);
    // the device answers with a signed connection.decision
    let mut d = aipass_types::relay::ConnectionDecision {
        connection_id: p.connection_id.clone(),
        decision: Decision::Approve,
        allowed_projects: aipass_types::models::AllowedProjects::Only([h.project.clone()].into()),
        signed_at: h.clock.now_ts(),
        signature: String::new(),
    };
    d.sign_control(&h.device).unwrap();
    h.broker.handle_device_message(&relay.seal_from_device(&h, &RelayMessage::ConnectionDecision(d))).await.unwrap();
    assert_eq!(h.broker.get_connection(&p.connection_id).await.unwrap().status, ConnectionStatus::Active);
}
