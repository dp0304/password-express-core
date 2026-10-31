// SPDX-License-Identifier: Apache-2.0
//! Pairing (happy path, man-in-the-middle with SAS mismatch, expired QR, executor) and
//! approval signing verified with the broker-side verifier of `aipass-types`.

mod common;

use std::collections::BTreeMap;
use std::sync::Arc;

use aipass_crypto::DeviceIdentity;
use aipass_sync::VaultError;
use aipass_types::approval::{credential_aad_bytes, verify_decision};
use aipass_types::exec::open_credential;
use aipass_types::ids::*;
use aipass_types::models::*;
use aipass_types::pairing::{PairingOffer, PairingRole};
use aipass_types::relay::{ControlAction, DeviceSigned, RelayMessage};
use aipass_types::vault::{EntryKind, MemberRole, Platform};
use aipass_types::{ErrorCode, Localized};
use aipass_vault::MemoryRelay;
use aipass_vault::member::{device_public, member_executor_id};
use aipass_vault::pairing::{NewDeviceSession, TrustedSession};
use common::*;

#[tokio::test]
async fn member_pairing_happy_path() {
    let f = Arc::new(TestFactory::default());
    let relay = MemoryRelay::new();
    let a = device(&f, Platform::Ios);
    let b = device(&f, Platform::Macos);
    create(&a).await;
    let id = a
        .client
        .save_item(login("Example", "https://example.com", "u", "pw"))
        .await
        .unwrap();
    a.client.sync().await.unwrap();

    let mut ns = b.client.begin_join("MacBook Pro", RELAY).unwrap();
    let qr = ns.qr_payload();
    assert!(qr.starts_with("aipass://pair?v=1&p=pair_"));
    assert!(
        !qr.contains(&a.client.vault_id().unwrap().to_string()),
        "the QR never carries vault material"
    );
    let mut ts = a.client.scan_pairing(&qr, &relay).await.unwrap();
    let hello = ns.wait_for_hello(&relay, WAIT).await.unwrap();
    assert_eq!(hello.vault_id, a.client.vault_id().unwrap());
    let peer = ts.wait_for_join(&relay, WAIT).await.unwrap();
    assert_eq!(peer.name, "MacBook Pro");
    assert_eq!(hello.sas.len(), 6);
    assert_eq!(ts.sas(), hello.sas);
    // scanning alone grants nothing: the member is written only after confirmation
    assert_eq!(a.client.devices().unwrap().len(), 2);
    assert!(
        a.client
            .confirm_pairing(&mut ts, &relay, true)
            .await
            .is_err()
    );
    ts.confirm().unwrap();
    let info = a
        .client
        .confirm_pairing(&mut ts, &relay, true)
        .await
        .unwrap();
    assert_eq!(info.role, MemberRole::Owner);
    let welcome = ns.wait_for_welcome(&relay, WAIT).await.unwrap();
    assert!(
        welcome
            .trusted_devices
            .iter()
            .all(|d| !aipass_vault::member::is_recovery_device(d))
    );
    b.client.complete_join(&ns, welcome, None).await.unwrap();
    assert_eq!(secret_of(&b.client, &id), "pw");
    assert!(b.client.status().unlocked);
    // B can write and A sees it
    let id2 = b
        .client
        .save_item(login("From Mac", "https://mac.example", "u", "x"))
        .await
        .unwrap();
    b.client.sync().await.unwrap();
    a.client.sync().await.unwrap();
    assert_eq!(secret_of(&a.client, &id2), "x");
}

#[tokio::test]
async fn substituted_qr_is_caught_by_the_sas() {
    let f = Arc::new(TestFactory::default());
    let relay = MemoryRelay::new();
    let a = device(&f, Platform::Ios);
    let b = device(&f, Platform::Macos);
    create(&a).await;
    let members_before = a.client.devices().unwrap().len();

    // the real new device shows its QR …
    let mut real = b.client.begin_join("Office PC", RELAY).unwrap();
    // … but an attacker substitutes its own QR (same name) and talks to both sides
    let m_id = DeviceIdentity::generate();
    let m_dev = device_public(
        &DeviceId::generate(),
        &m_id,
        "Office PC",
        Platform::Windows,
        MemberRole::Member,
    );
    let mut mitm_new =
        NewDeviceSession::start(m_dev, m_id.clone(), PairingRole::Member, RELAY).unwrap();
    let fake_o = device_public(
        &DeviceId::generate(),
        &m_id,
        "Your iPhone",
        Platform::Ios,
        MemberRole::Owner,
    );
    let mut mitm_trusted = TrustedSession::scan(
        &real.qr_payload(),
        m_id.clone(),
        fake_o,
        VaultId::generate(),
        &relay,
    )
    .await
    .unwrap();

    let mut ts = a
        .client
        .scan_pairing(&mitm_new.qr_payload(), &relay)
        .await
        .unwrap();
    mitm_new.wait_for_hello(&relay, WAIT).await.unwrap();
    ts.wait_for_join(&relay, WAIT).await.unwrap();
    let on_new_device = real.wait_for_hello(&relay, WAIT).await.unwrap();
    mitm_trusted.wait_for_join(&relay, WAIT).await.unwrap();

    assert_ne!(
        ts.sas(),
        on_new_device.sas,
        "codes differ under interception"
    );
    let e = ts.confirm_code(&on_new_device.sas).unwrap_err();
    assert!(matches!(e, VaultError::Cancelled(_)));
    assert!(
        a.client
            .confirm_pairing(&mut ts, &relay, true)
            .await
            .is_err()
    );
    a.client.sync().await.unwrap();
    assert_eq!(
        a.client.devices().unwrap().len(),
        members_before,
        "nothing was enrolled"
    );
}

#[tokio::test]
async fn expired_or_malformed_qr_is_refused() {
    let f = Arc::new(TestFactory::default());
    let relay = MemoryRelay::new();
    let a = device(&f, Platform::Ios);
    let b = device(&f, Platform::Linux);
    create(&a).await;
    let ns = b.client.begin_join("Laptop", RELAY).unwrap();
    let mut offer: PairingOffer = ns.offer().clone();
    offer.expires_at = aipass_types::time::unix_now() - 1;
    let e = a
        .client
        .scan_pairing(&offer.to_uri(), &relay)
        .await
        .unwrap_err();
    assert!(matches!(e, VaultError::Expired(_)), "{e:?}");
    offer.expires_at = aipass_types::time::unix_now() + 7200; // claims too long a lifetime
    assert!(
        a.client
            .scan_pairing(&offer.to_uri(), &relay)
            .await
            .is_err()
    );
    assert!(
        a.client
            .scan_pairing("https://evil.example/pair", &relay)
            .await
            .is_err()
    );
    // the joining side gives up at expiry too
    let mut stale = b.client.begin_join("Laptop", RELAY).unwrap();
    let e = stale
        .wait_for_hello(&relay, std::time::Duration::from_millis(1100))
        .await
        .unwrap_err();
    assert!(matches!(e, VaultError::Expired(_)));
}

fn request(executor: &ExecutorId, resource: &ResourceId) -> ApprovalRequest {
    let now = aipass_types::time::now();
    let scope = GrantScope {
        operations: vec!["postgres.query_view".into()],
        postgres: Some(PostgresScope {
            views: BTreeMap::from([(
                "analytics.subscription_daily".into(),
                vec!["day".into(), "plan".into(), "subscriptions".into()],
            )]),
        }),
        github: None,
        http_api: None,
    };
    ApprovalRequest {
        approval_request_id: ApprovalRequestId::generate(),
        kind: ApprovalKind::Access,
        connection: ApprovalConnection {
            connection_id: ConnectionId::generate(),
            display_name: "Claude Code".into(),
            host_type: HostType::ClaudeCode,
            verified: true,
        },
        resource: ApprovalResource {
            resource_id: resource.clone(),
            alias: "路亚站测试库".into(),
            service: "postgres".into(),
            environment: Environment::Test,
        },
        summary: Localized::new("查询订阅统计视图", "Query the subscription view"),
        requested: AccessSpec {
            operations: vec!["postgres.query_view".into()],
            scope,
            limits: Limits::default(),
            duration_seconds: 900,
            mode: ApprovalMode::Task,
        },
        excluded_fields: BTreeMap::new(),
        executor: ApprovalExecutor {
            executor_id: executor.clone(),
            name: "我的服务器".into(),
            protection_level: ProtectionLevel::Isolated,
        },
        recipients: vec![],
        status: ApprovalStatus::Pending,
        created_at: now,
        expires_at: aipass_types::time::add_secs(&now, 600),
        operation_id: None,
        parameters_digest: None,
    }
}

#[tokio::test]
async fn executor_pairing_and_approval_envelopes() {
    let f = Arc::new(TestFactory::default());
    let relay = MemoryRelay::new();
    let a = device(&f, Platform::Ios);
    create(&a).await;
    let mut db = aipass_sync::ItemInput::new(EntryKind::Database, "Lure store test DB");
    db.username = Some("readonly".into());
    db.secret = Some(aipass_crypto::SecretString::from("pg-pass-DO-NOT-LEAK"));
    db.database = Some(aipass_types::vault::DatabaseInfo {
        engine: "postgres".into(),
        host: "db.internal".into(),
        port: 5432,
        dbname: "lure".into(),
        sslmode: "require".into(),
    });
    let entry = a.client.save_item(db).await.unwrap();
    a.client.sync().await.unwrap();

    // a node pairs as executor (no VaultClient: executors never hold the vault key)
    let exe_identity = DeviceIdentity::generate();
    let exe_dev = DeviceId::generate();
    let exe_id = member_executor_id(&exe_dev);
    let dp = device_public(
        &exe_dev,
        &exe_identity,
        "我的服务器",
        Platform::Node,
        MemberRole::Executor,
    );
    let mut node =
        NewDeviceSession::start(dp, exe_identity.clone(), PairingRole::Executor, RELAY).unwrap();
    let mut ts = a
        .client
        .scan_pairing(&node.qr_payload(), &relay)
        .await
        .unwrap();
    let hello = node.wait_for_hello(&relay, WAIT).await.unwrap();
    ts.wait_for_join(&relay, WAIT).await.unwrap();
    ts.confirm_code(&hello.sas).unwrap();
    let info = a
        .client
        .confirm_pairing(&mut ts, &relay, true)
        .await
        .unwrap();
    assert_eq!(info.role, MemberRole::Executor);
    let welcome = node.wait_for_welcome(&relay, WAIT).await.unwrap();
    assert!(
        welcome.storage_secret.is_none(),
        "executors never receive storage secrets"
    );
    let approvers = welcome.trusted_devices.clone();
    assert_eq!(approvers.len(), 1);
    assert_eq!(approvers[0].device_id, a.client.device_id().unwrap());
    let store = f.mem.store(&profile(), &a.client.vault_id().unwrap());
    let rec: aipass_types::vault::MemberRecord = serde_json::from_slice(
        &aipass_storage::ObjectStore::get(
            store.as_ref(),
            &aipass_types::vault::keys::member(&exe_dev, 1),
        )
        .await
        .unwrap()
        .unwrap()
        .bytes,
    )
    .unwrap();
    assert!(rec.wrapped_vmk.is_none());

    // approval with credential envelope for the executor
    let resource = ResourceId::generate();
    a.client.bind_resource(&resource, &entry).unwrap();
    let req = request(&exe_id, &resource);
    let dec = a.client.approve(&req, None).await.unwrap();
    let signer_pk = approvers[0].sign_pk;
    verify_decision(&dec, &req, &signer_pk, &aipass_types::time::now()).unwrap();
    let env = dec.credential_envelope.clone().unwrap();
    let aad = credential_aad_bytes(&req.approval_request_id, &dec.digest, &exe_id).unwrap();
    let material = open_credential(exe_identity.kem_keypair(), &aad, &env).unwrap();
    assert_eq!(material.secret.expose(), "pg-pass-DO-NOT-LEAK");
    assert_eq!(material.entry_id, entry);
    assert_eq!(material.expires_at, dec.expires_at);
    // the envelope is bound to the digest: another approval's AAD cannot open it
    let other = credential_aad_bytes(&req.approval_request_id, "other-digest", &exe_id).unwrap();
    assert!(open_credential(exe_identity.kem_keypair(), &other, &env).is_err());
    // nothing secret in Debug output of the decision
    assert!(!format!("{dec:?}").contains("pg-pass"));

    // narrowed approval stays a subset and verifies; widening is refused
    let mut narrow = req.requested.clone();
    narrow.limits.max_rows_per_operation = 100;
    narrow.duration_seconds = 300;
    let dn = a.client.approve(&req, Some(narrow)).await.unwrap();
    verify_decision(&dn, &req, &signer_pk, &aipass_types::time::now()).unwrap();
    let mut wide = req.requested.clone();
    wide.duration_seconds = 86_400;
    assert!(a.client.approve(&req, Some(wide)).await.is_err());
    // tampering with the decision breaks verification
    let mut t = dec.clone();
    t.digest = dn.digest.clone();
    assert!(verify_decision(&t, &req, &signer_pk, &aipass_types::time::now()).is_err());

    // deny is signed too
    let deny = a.client.deny(&req).unwrap();
    verify_decision(&deny, &req, &signer_pk, &aipass_types::time::now()).unwrap();
    assert!(deny.credential_envelope.is_none());

    // expired requests are never approved
    let mut old = request(&exe_id, &resource);
    old.expires_at = aipass_types::time::add_secs(&aipass_types::time::now(), -1);
    let e = a.client.approve(&old, None).await.unwrap_err();
    assert_eq!(e.code(), ErrorCode::ApprovalExpired);

    // unknown executors get nothing
    let e = a
        .client
        .approve(&request(&ExecutorId::generate(), &resource), None)
        .await
        .unwrap_err();
    assert_eq!(e.code(), ErrorCode::SecretUnavailable);

    // signed control messages verify with the device key
    let ctl = a
        .client
        .sign_connection_control(&ConnectionId::generate(), ControlAction::Pause)
        .unwrap();
    ctl.verify_control(&signer_pk).unwrap();
    let gr = a
        .client
        .sign_grant_revoke(&GrantId::generate(), RevocationLevel::EndSessions)
        .unwrap();
    gr.verify_control(&signer_pk).unwrap();
    let cd = a
        .client
        .sign_connection_decision(
            &ConnectionId::generate(),
            Decision::Approve,
            AllowedProjects::All,
        )
        .unwrap();
    cd.verify_control(&signer_pk).unwrap();

    // relay envelopes both ways
    let env = a
        .client
        .seal_for_executor(
            &exe_id,
            &RelayMessage::ApprovalDecision(Box::new(dec.clone())),
        )
        .unwrap();
    let opened =
        aipass_vault::relay::open_message(exe_identity.kem_keypair(), &signer_pk, &env).unwrap();
    assert_eq!(opened, RelayMessage::ApprovalDecision(Box::new(dec)));
    let back = aipass_vault::relay::seal_message(
        &exe_identity,
        MailboxId::Executor(exe_id.clone()),
        MailboxId::Device(a.client.device_id().unwrap()),
        &approvers[0].kem_pk,
        &RelayMessage::ApprovalRequest(Box::new(req.clone())),
        aipass_types::time::now(),
    )
    .unwrap();
    aipass_vault::RelayTransport::post(
        &relay,
        &MailboxId::Device(a.client.device_id().unwrap()),
        &back,
        None,
    )
    .await
    .unwrap();
    let (inbox, cursor) = a.client.fetch_inbox(&relay, None, 0).await.unwrap();
    assert_eq!(inbox.len(), 1);
    assert!(cursor.is_some());
    assert_eq!(inbox[0].1, exe_id);
    assert_eq!(inbox[0].2, RelayMessage::ApprovalRequest(Box::new(req)));

    // revoking the executor (no key rotation needed: it never had the VMK)
    let r = a.client.revoke_device(&exe_dev).await.unwrap();
    assert_eq!(r.key_epoch, 1);
    // …but it received the long-term password in plaintext: rotate it (CVS-05, §9.4)
    let ids: Vec<_> = r
        .rotation_tasks
        .iter()
        .map(|t| t.entry_id.clone())
        .collect();
    assert_eq!(ids, vec![entry.clone()]);
    assert!(
        a.client
            .rotation_tasks()
            .unwrap()
            .iter()
            .any(|t| t.entry_id == entry),
        "the task is persisted"
    );
    let e = a
        .client
        .approve(&request(&exe_id, &resource), None)
        .await
        .unwrap_err();
    assert_eq!(e.code(), ErrorCode::Forbidden);
}
