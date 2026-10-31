// SPDX-License-Identifier: Apache-2.0
//! End-to-end tests of the FFI surface through the real Rust core (run with
//! `cargo test -p aipass-ffi --features test-support`).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use aipass_ffi::*;

#[derive(Default)]
struct MemStore {
    items: Mutex<HashMap<String, (Vec<u8>, bool)>>,
}

impl SecretStore for MemStore {
    fn get(&self, key: String) -> Result<Option<Vec<u8>>, SecretStoreError> {
        Ok(self.items.lock().unwrap().get(&key).map(|v| v.0.clone()))
    }
    fn set(&self, key: String, value: Vec<u8>, upr: bool) -> Result<(), SecretStoreError> {
        self.items.lock().unwrap().insert(key, (value, upr));
        Ok(())
    }
    fn delete(&self, key: String) -> Result<(), SecretStoreError> {
        self.items.lock().unwrap().remove(&key);
        Ok(())
    }
}

fn core(dir: &std::path::Path, name: &str) -> (Arc<AipassCore>, Arc<MemStore>) {
    let store = Arc::new(MemStore::default());
    let c = AipassCore::new(
        dir.join(name).to_string_lossy().into_owned(),
        store.clone(),
        "ios".into(),
        "0.1.0-test".into(),
    )
    .unwrap();
    (c, store)
}

fn local_storage(dir: &std::path::Path) -> StorageProfileFfi {
    StorageProfileFfi {
        kind: "local".into(),
        path: Some(dir.join("storage").to_string_lossy().into_owned()),
        ..Default::default()
    }
}

fn login(title: &str, user: &str, secret: &str) -> ItemInputFfi {
    ItemInputFfi {
        entry_id: None,
        kind: "login".into(),
        title: title.into(),
        username: Some(user.into()),
        secret: Some(secret.into()),
        clear_secret: false,
        urls: vec!["https://github.com/login".into()],
        notes: Some("note".into()),
        totp: Some("JBSWY3DPEHPK3PXP".into()),
        clear_totp: false,
        fields: vec![],
        database: None,
        project_id: None,
        tags: vec!["work".into()],
        lifecycle: None,
        password_rules: None,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn vault_items_recovery_export_lock() {
    let tmp = tempfile::tempdir().unwrap();
    let (c, store) = core(tmp.path(), "a");
    assert!(!c.has_vault());
    assert_eq!(
        c.list_items(None, None).unwrap_err().code_str(),
        "NO_VAULT"
    );
    let created = c
        .create_vault("iPhone".into(), local_storage(tmp.path()), None)
        .await
        .unwrap();
    assert!(created.recovery_key.starts_with("AIPR-"));
    assert!(!format!("{created:?}").contains(&created.recovery_key));
    // the device key was stored with user presence
    let dev_key = format!("aipass.device.{}", created.device_id);
    assert!(store.items.lock().unwrap().get(&dev_key).unwrap().1);

    let st = c.status();
    assert!(st.unlocked && st.vault_id.as_deref() == Some(created.vault_id.as_str()));
    assert_eq!(st.storage_kind.as_deref(), Some("local"));
    // public keys for the cloud's POST /v1/devices (b64u of 32 bytes; public, not secret)
    let sign_pk = st.device_sign_pk.clone().expect("sign_pk");
    let kem_pk = st.device_kem_pk.clone().expect("kem_pk");
    for k in [&sign_pk, &kem_pk] {
        assert_eq!(k.len(), 43, "b64u of 32 bytes");
        assert!(k.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'));
    }
    assert_ne!(sign_pk, kem_pk);
    let device_json: serde_json::Value =
        serde_json::from_slice(&std::fs::read(tmp.path().join("a").join("device.json")).unwrap()).unwrap();
    assert_eq!(device_json["sign_pk"], sign_pk.as_str());
    assert_eq!(device_json["kem_pk"], kem_pk.as_str());

    let id = c
        .save_item(login("GitHub", "octo", "s3cret-pass-123"))
        .await
        .unwrap();
    let items = c.list_items(Some("git".into()), None).unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].kind, "login");
    let detail = c.get_item(id.clone()).unwrap();
    assert!(detail.has_secret && detail.has_totp);
    assert!(!format!("{detail:?}").contains("s3cret-pass-123"));
    assert_eq!(
        c.reveal_secret(id.clone(), "secret".into()).unwrap(),
        "s3cret-pass-123"
    );
    let totp = c.totp_now(id.clone()).unwrap();
    assert_eq!(totp.code.len(), 6);
    assert_eq!(totp.period, 30);

    let rules = PasswordRulesFfi {
        length: 24,
        ..default_password_rules()
    };
    assert_eq!(c.generate_password(rules).unwrap().chars().count(), 24);

    let cands = c
        .autofill_candidates("https://github.com/session".into())
        .unwrap();
    assert_eq!(cands.len(), 1);
    assert_eq!(cands[0].match_kind, "exact_origin");
    let cred = c.autofill_credential(id.clone()).unwrap();
    assert_eq!(cred.password, "s3cret-pass-123");
    assert!(!format!("{cred:?}").contains("s3cret"));
    assert_eq!(c.all_credential_identities().unwrap().len(), 1);

    let csv = b"name,url,username,password,note\nExample,https://example.com,alice,pw-alice,\n".to_vec();
    let rep = c.import_csv("chrome".into(), csv).await.unwrap();
    assert_eq!(rep.imported, 1);
    assert_eq!(c.list_items(None, None).unwrap().len(), 2);

    let export = c.export_encrypted("export-password-1".into()).unwrap();
    assert!(export.len() > 64);

    assert!(c.verify_recovery_key(created.recovery_key.clone()).unwrap());
    assert!(!c.verify_recovery_key("AIPR-0000-0000".into()).unwrap_or(false));
    assert!(c.status().recovery_verified);

    let sync = c.sync().await.unwrap();
    assert_eq!(sync.status, "ok");
    let devices = c.devices().unwrap();
    assert!(devices.iter().any(|d| d.is_this_device && d.role == "owner"));
    let me = devices.iter().find(|d| d.is_this_device).unwrap();
    assert_eq!(me.sign_pk, sign_pk);
    assert_eq!(me.kem_pk, kem_pk);

    let cap = c
        .test_storage(local_storage(&tmp.path().join("other")), None)
        .await
        .unwrap();
    assert_eq!(cap.verdict, "sync_capable");

    c.lock();
    assert!(!c.is_unlocked());
    assert_eq!(c.list_items(None, None).unwrap_err().code_str(), "LOCKED");
    c.unlock().await.unwrap();
    assert_eq!(c.list_items(None, None).unwrap().len(), 2);

    // re-open from disk (app restart)
    drop(c);
    let c2 = AipassCore::new(
        tmp.path().join("a").to_string_lossy().into_owned(),
        store.clone(),
        "ios".into(),
        "0.1.0-test".into(),
    )
    .unwrap();
    assert!(c2.has_vault() && !c2.is_unlocked());
    c2.unlock().await.unwrap();
    c2.delete_item(id.clone()).await.unwrap();
    assert_eq!(c2.list_items(None, None).unwrap().len(), 1);

    // input validation
    assert_eq!(
        c2.get_item("not-an-id".into()).unwrap_err().code_str(),
        "INVALID_REQUEST"
    );
    let mut bad = login("x", "y", "z");
    bad.kind = "spaceship".into();
    assert_eq!(c2.save_item(bad).await.unwrap_err().code_str(), "INVALID_REQUEST");
}

#[tokio::test(flavor = "multi_thread")]
async fn pairing_approvals_snapshot_revoke_license() {
    let tmp = tempfile::tempdir().unwrap();
    let relay = LocalRelay::new();
    let (a, _) = core(tmp.path(), "phone");
    a.set_local_relay(relay.clone());
    let created = a
        .create_vault("Phone".into(), local_storage(tmp.path()), None)
        .await
        .unwrap();
    let entry = a
        .save_item(login("Orders DB", "readonly", "db-password-xyz"))
        .await
        .unwrap();

    // --- second device joins (B shows QR, A scans) ---------------------------------
    let (b, _) = core(tmp.path(), "tablet");
    b.set_local_relay(relay.clone());
    let offer = b.pairing_offer("Tablet".into()).await.unwrap();
    assert!(offer.is_new_device());
    let scan = a.pairing_scan(offer.qr_payload()).await.unwrap();
    assert_eq!(scan.peer_name().await.as_deref(), Some("Tablet"));
    let (pb, pa) = tokio::join!(offer.wait(30), scan.wait(30));
    let (pb, pa) = (pb.unwrap(), pa.unwrap());
    assert_eq!(pb.stage, "confirm_code");
    assert_eq!(pa.stage, "confirm_code");
    assert_eq!(pa.sas, pb.sas);
    assert_eq!(pa.sas.as_ref().unwrap().len(), 6);
    let (rb, ra) = tokio::join!(offer.confirm(), scan.confirm());
    assert_eq!(ra.unwrap().stage, "completed");
    let rb = rb.unwrap();
    assert_eq!(rb.stage, "completed");
    assert!(b.has_vault());
    assert_eq!(b.status().vault_id, Some(created.vault_id.clone()));
    if !b.is_unlocked() {
        b.unlock().await.unwrap();
    }
    assert_eq!(b.list_items(None, None).unwrap().len(), 1);
    assert!(a.devices().unwrap().iter().filter(|d| d.status == "active").count() >= 2);

    // --- executor pairs (executor shows QR, A scans) --------------------------------
    let exe = TestExecutor::new(relay.clone(), "Home node".into()).unwrap();
    let scan = a.pairing_scan(exe.qr_payload()).await.unwrap();
    assert_eq!(scan.peer_role().await.as_deref(), Some("executor"));
    let (sas_exe, pa) = tokio::join!(exe.wait_for_hello(30), scan.wait(30));
    assert_eq!(Some(sas_exe.unwrap()), pa.unwrap().sas);
    let pa = scan.confirm().await.unwrap();
    assert_eq!(pa.device.unwrap().role, "executor");
    assert!(exe.wait_for_welcome(30).await.unwrap() >= 2);

    // --- approval via relay ----------------------------------------------------------
    let dev_a = created.device_id.clone();
    let res = "res_01jc0000000000000000000000";
    let apr = exe
        .send_approval_request(dev_a.clone(), res.into(), vec!["query".into()])
        .await
        .unwrap();
    let inbox = a.fetch_inbox().await.unwrap();
    assert_eq!(inbox.len(), 1);
    let r = &inbox[0];
    assert_eq!(r.approval_request_id, apr);
    assert_eq!(r.environment, "test");
    assert_eq!(r.requested.scope.postgres_views[0].view, "public.orders_summary");
    assert_eq!(r.excluded_fields[0].fields, vec!["customer_email"]);
    assert!(!r.credential_bound);
    assert_eq!(r.sender_executor_id, exe.executor_id());
    // unbound resource → explicit error, nothing sent
    assert!(!r.conflict);
    assert_eq!(r.request_digest.len(), 43);
    assert_eq!(
        a.approve(apr.clone(), r.request_digest.clone(), None).await.unwrap_err().code_str(),
        "NOT_FOUND"
    );
    // a digest that is not the displayed request's → refused before anything is bound
    assert_eq!(
        a.approve_with_entry(apr.clone(), "AAAA".into(), None, entry.clone())
            .await
            .unwrap_err()
            .code_str(),
        "INTEGRITY_FAILED"
    );
    assert!(!a.pending_approvals()[0].credential_bound);
    // narrowed approval with the chosen entry
    let mut narrowed = r.requested.clone();
    narrowed.limits.max_rows_per_grant = 100;
    narrowed.duration_seconds = 300;
    let d = a
        .approve_with_entry(apr.clone(), r.request_digest.clone(), Some(narrowed), entry.clone())
        .await
        .unwrap();
    assert_eq!(d.decision, "approve");
    assert!(d.credential_sealed);
    let got = exe.receive_decision(30).await.unwrap();
    assert!(got.verified, "{:?}", got.verify_error);
    assert!(got.credential_opened);
    assert_eq!(got.credential_username.as_deref(), Some("readonly"));
    assert_eq!(got.credential_secret_len, "db-password-xyz".len() as u32);
    assert!(a.pending_approvals().is_empty());

    // second request: bound now → approve() works; third: deny
    let apr2 = exe
        .send_approval_request(dev_a.clone(), res.into(), vec!["query".into()])
        .await
        .unwrap();
    let apr3 = exe
        .send_approval_request(dev_a.clone(), res.into(), vec!["query".into()])
        .await
        .unwrap();
    let inbox = a.fetch_inbox().await.unwrap();
    assert_eq!(inbox.len(), 2);
    assert!(inbox.iter().all(|r| r.credential_bound));
    let digest_of = |id: &str| {
        a.pending_approvals()
            .into_iter()
            .find(|r| r.approval_request_id == id)
            .unwrap()
            .request_digest
    };
    let (d2, d3) = (digest_of(&apr2), digest_of(&apr3));
    a.approve(apr2.clone(), d2, None).await.unwrap();
    assert!(exe.receive_decision(30).await.unwrap().verified);
    let dd = a.deny(apr3.clone(), d3.clone()).await.unwrap();
    assert_eq!(dd.decision, "deny");
    let got = exe.receive_decision(30).await.unwrap();
    assert_eq!(got.decision, "deny");
    assert!(!got.credential_opened);
    // unknown / already handled
    assert_eq!(a.approve(apr3, d3, None).await.unwrap_err().code_str(), "NOT_FOUND");

    // --- approval TOCTOU ---------------------------------------------------------------
    // (1) the same id re-sent with different content: first copy kept, conflict surfaced,
    //     approving refused, denying still possible.
    let apr4 = exe
        .send_approval_request(dev_a.clone(), res.into(), vec!["query".into()])
        .await
        .unwrap();
    let shown = a.fetch_inbox().await.unwrap();
    let shown = shown.iter().find(|r| r.approval_request_id == apr4).unwrap().clone();
    assert!(!shown.conflict);
    exe.send_approval_request_variant(
        dev_a.clone(),
        res.into(),
        vec!["query".into(), "export".into()],
        "access".into(),
        Some(apr4.clone()),
        Some("Export the whole database".into()),
        None,
    )
    .await
    .unwrap();
    let after = a.fetch_inbox().await.unwrap();
    let after = after.iter().find(|r| r.approval_request_id == apr4).unwrap().clone();
    assert!(after.conflict);
    assert_eq!(after.request_digest, shown.request_digest, "first copy kept");
    assert_eq!(after.requested.operations, vec!["query".to_string()]);
    assert_eq!(
        a.approve(apr4.clone(), shown.request_digest.clone(), None).await.unwrap_err().code_str(),
        "INTEGRITY_FAILED"
    );
    assert_eq!(
        a.approve_with_entry(apr4.clone(), shown.request_digest.clone(), None, entry.clone())
            .await
            .unwrap_err()
            .code_str(),
        "INTEGRITY_FAILED"
    );
    // wrong displayed digest refused for deny too
    assert_eq!(
        a.deny(apr4.clone(), "AAAA".into()).await.unwrap_err().code_str(),
        "INTEGRITY_FAILED"
    );
    assert_eq!(a.deny(apr4.clone(), shown.request_digest.clone()).await.unwrap().decision, "deny");
    let got = exe.receive_decision(30).await.unwrap();
    assert!(got.verified && got.decision == "deny", "{:?}", got.verify_error);

    // (2) a request naming another executor than its relay sender is ignored.
    let other_exe = "exe_01jc0000000000000000000001";
    let apr5 = exe
        .send_approval_request_variant(
            dev_a.clone(),
            res.into(),
            vec!["query".into()],
            "access".into(),
            None,
            None,
            Some(other_exe.into()),
        )
        .await
        .unwrap();
    assert!(a.fetch_inbox().await.unwrap().iter().all(|r| r.approval_request_id != apr5));

    // (3) operation requests: parameters digest shown, v2 digest verified by the executor.
    let apr6 = exe
        .send_approval_request_variant(dev_a.clone(), res.into(), vec!["query".into()], "operation".into(), None, None, None)
        .await
        .unwrap();
    let r6 = a.fetch_inbox().await.unwrap().into_iter().find(|r| r.approval_request_id == apr6).unwrap();
    assert_eq!(r6.kind, "operation");
    assert!(r6.operation_id.is_some() && r6.parameters_digest.is_some());
    let d6 = a.approve(apr6.clone(), r6.request_digest.clone(), None).await.unwrap();
    let got = exe.receive_decision(30).await.unwrap();
    assert!(got.verified, "{:?}", got.verify_error);
    assert_eq!(got.decision, "approve");
    assert_eq!(d6.decision, "approve");

    // (4) a re-sent connection.pair_request cannot swap the pairing code the user compares.
    let conn = exe
        .send_connection_pair_request(dev_a.clone(), None, "111111".into())
        .await
        .unwrap();
    a.fetch_inbox().await.unwrap();
    exe.send_connection_pair_request(dev_a.clone(), Some(conn.clone()), "222222".into())
        .await
        .unwrap();
    a.fetch_inbox().await.unwrap();
    let pending: Vec<_> = a.pending_connections().into_iter().filter(|c| c.connection_id == conn).collect();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].pairing_code, "111111", "first copy kept");

    // --- snapshot & revoke round trips ----------------------------------------------
    let (snap, served) = tokio::join!(a.snapshot(None), exe.serve_once(30));
    assert_eq!(served.unwrap(), "state.request");
    let snap = snap.unwrap();
    assert_eq!(snap.executor_id, exe.executor_id());
    assert!(a.last_snapshot().is_some());
    let grant = "grt_01jc0000000000000000000000";
    let (rep, served) = tokio::join!(
        a.revoke_grant(grant.into(), "end_sessions".into()),
        exe.serve_once(30)
    );
    assert_eq!(served.unwrap(), "grant.revoke");
    let rep = rep.unwrap();
    assert!(rep.confirmed && rep.fully_revoked);
    let (ctl, served) = tokio::join!(
        a.control_connection("conn_01jc0000000000000000000000".into(), "pause".into()),
        exe.serve_once(30)
    );
    ctl.unwrap();
    assert_eq!(served.unwrap(), "connection.control");

    // --- license (dev key) ----------------------------------------------------------
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let payload = format!(
        r#"{{"device_id":"{dev_a}","exp":{},"features":["official_sync"],"grace_until":{},"iat":{now},"plan_id":"personal_monthly","sub":"usr_test","v":1}}"#,
        now + 3600,
        now + 7200
    );
    let kp = aipass_crypto::Ed25519Keypair::from_seed(&aipass_crypto::sha256(DEV_LICENSE_SEED_LABEL));
    let token = format!(
        "{}.{}",
        aipass_crypto::b64u::encode(payload.as_bytes()),
        aipass_crypto::b64u::encode(kp.sign(payload.as_bytes()))
    );
    let lic = a.verify_license(token.clone());
    assert!(lic.valid && lic.dev_key, "{lic:?}");
    assert_eq!(a.status().license.unwrap().plan_id.as_deref(), Some("personal_monthly"));
    // the same token is bound to device A
    assert_eq!(b.verify_license(token).reason.as_deref(), Some("wrong_device"));
}
