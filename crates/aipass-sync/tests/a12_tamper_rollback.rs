// SPDX-License-Identifier: Apache-2.0
//! A12 — storage tampering, known-version rollback, a revoked device coming back and a
//! resurrected tombstone are detected; nothing is restored silently.

mod common;

use std::sync::Arc;

use aipass_crypto::DeviceIdentity;
use aipass_storage::{MemoryStore, ObjectStore, PutCondition};
use aipass_sync::{SyncEngine, SyncStatus, VaultError};
use aipass_types::ErrorCode;
use aipass_types::ids::DeviceId;
use aipass_types::vault::{Platform, keys};
use aipass_vault::manifest::ManifestDraft;
use aipass_vault::{MemoryRelay, SecretStore};
use common::*;

async fn raw_view(
    store: Arc<MemoryStore>,
    vault: &aipass_types::ids::VaultId,
) -> (SyncEngine, aipass_vault::VaultView) {
    let eng = SyncEngine::new(store, Arc::new(MemoryStore::new()), vault.clone());
    let g = eng.genesis_view().await.unwrap();
    let (v, _) = eng.pull(&g).await.unwrap();
    (eng, v)
}

#[tokio::test]
async fn tampered_entry_and_manifest_are_rejected() {
    let f = Arc::new(TestFactory::default());
    let relay = MemoryRelay::new();
    let a = device(&f, Platform::Macos);
    let b = device(&f, Platform::Ios);
    create(&a).await;
    pair(&a.client, &b.client, &relay, "Phone").await;
    let vault = a.client.vault_id().unwrap();
    let store = f.mem.store(&profile(), &vault);

    let id = a
        .client
        .save_item(login("Bank", "https://bank.example", "u", "v1-pw"))
        .await
        .unwrap();
    a.client.sync().await.unwrap();
    b.client.sync().await.unwrap();
    let mut upd = login("Bank", "https://bank.example", "u", "v2-pw");
    upd.entry_id = Some(id.clone());
    a.client.save_item(upd).await.unwrap();
    a.client.sync().await.unwrap();

    // flip one ciphertext byte of the new version on storage
    let v2 = a.client.get_item(&id).unwrap().version.unwrap();
    let key = keys::entry(&id, v2);
    let original = store.get(&key).await.unwrap().unwrap().bytes;
    let mut obj = original.clone();
    let pos = obj.len() / 2;
    obj[pos] ^= if obj[pos] == b'A' { 2 } else { 1 };
    store.tamper(&key, obj).await;
    let r = b.client.sync().await.unwrap();
    assert_eq!(r.status, SyncStatus::Error);
    assert_eq!(r.error_code.as_deref(), Some("INTEGRITY_FAILED"));
    // B keeps its last verified state
    assert_eq!(secret_of(&b.client, &id), "v1-pw");

    // a tampered member record is rejected as well
    let a_id = a.client.device_id().unwrap();
    let mkey = keys::member(&a_id, 1);
    let mrec = store.get(&mkey).await.unwrap().unwrap().bytes;
    store
        .tamper(
            &mkey,
            String::from_utf8(mrec.clone())
                .unwrap()
                .replace("Laptop", "Evil")
                .into_bytes(),
        )
        .await;
    let fresh = device(&f, Platform::Linux);
    let mut ns = fresh.client.begin_join("Fresh", RELAY).unwrap();
    let mut ts = a
        .client
        .scan_pairing(&ns.qr_payload(), &relay)
        .await
        .unwrap();
    let hello = ns.wait_for_hello(&relay, WAIT).await.unwrap();
    ts.wait_for_join(&relay, WAIT).await.unwrap();
    ts.confirm_code(&hello.sas).unwrap();
    store.tamper(&mkey, mrec).await;
    store.tamper(&key, original.clone()).await;
    a.client
        .confirm_pairing(&mut ts, &relay, true)
        .await
        .unwrap();
    let welcome = ns.wait_for_welcome(&relay, WAIT).await.unwrap();
    let genesis_key = keys::member(&a_id, 1);
    let good = store.get(&genesis_key).await.unwrap().unwrap().bytes;
    store
        .tamper(
            &genesis_key,
            String::from_utf8(good.clone())
                .unwrap()
                .replace("Laptop", "Evil")
                .into_bytes(),
        )
        .await;
    let e = fresh
        .client
        .complete_join(&ns, welcome.clone(), None)
        .await
        .unwrap_err();
    assert_eq!(e.code(), ErrorCode::IntegrityFailed);
    store.tamper(&genesis_key, good).await;

    // once storage is intact again B verifies and applies the new version
    let r = b.client.sync().await.unwrap();
    assert_eq!(r.status, SyncStatus::Ok, "{r:?}");
    assert_eq!(secret_of(&b.client, &id), "v2-pw");
}

#[tokio::test]
async fn forged_manifest_from_storage_is_rejected() {
    let f = Arc::new(TestFactory::default());
    let a = device(&f, Platform::Macos);
    create(&a).await;
    let vault = a.client.vault_id().unwrap();
    let store = f.mem.store(&profile(), &vault);
    let id = a
        .client
        .save_item(login("Git", "https://git.example", "dev", "pw"))
        .await
        .unwrap();
    a.client.sync().await.unwrap();
    let (_eng, view) = raw_view(store.clone(), &vault).await;
    // an attacker with storage write access but no member key signs with its own key
    let attacker = DeviceIdentity::generate();
    let mut d = ManifestDraft::from_view(&view);
    d.tombstone(&id, &aipass_types::time::now()).unwrap();
    let (cand, _) = d
        .finish(&attacker, &DeviceId::generate(), &aipass_types::time::now())
        .unwrap();
    store
        .put(&cand.key(), cand.bytes.clone(), PutCondition::IfAbsent)
        .await
        .unwrap();
    let r = a.client.sync().await.unwrap();
    assert_eq!(r.status, SyncStatus::Error);
    assert_eq!(r.error_code.as_deref(), Some("INTEGRITY_FAILED"));
    assert_eq!(secret_of(&a.client, &id), "pw");
    // a manifest whose bytes were altered after signing is also rejected
    store.delete(&cand.key()).await.unwrap();
    let dev_secret = a
        .secrets
        .get(&format!("aipass.device.{}", a.client.device_id().unwrap()))
        .unwrap()
        .unwrap();
    let me = DeviceIdentity::from_secret_bytes(dev_secret.expose()).unwrap();
    let mut d = ManifestDraft::from_view(&view);
    d.tombstone(&id, &aipass_types::time::now()).unwrap();
    let (cand, _) = d
        .finish(
            &me,
            &a.client.device_id().unwrap(),
            &aipass_types::time::now(),
        )
        .unwrap();
    let mut m = cand.manifest.clone();
    m.key_epoch += 1; // tamper after signing
    store
        .put(
            &cand.key(),
            serde_json::to_vec(&m).unwrap(),
            PutCondition::IfAbsent,
        )
        .await
        .unwrap();
    let r = a.client.sync().await.unwrap();
    assert_eq!(r.error_code.as_deref(), Some("INTEGRITY_FAILED"));
}

#[tokio::test]
async fn known_version_rollback_stops_writes() {
    let f = Arc::new(TestFactory::default());
    let a = device(&f, Platform::Windows);
    create(&a).await;
    let vault = a.client.vault_id().unwrap();
    let store = f.mem.store(&profile(), &vault);
    for i in 0..3 {
        a.client
            .save_item(login(
                &format!("Site {i}"),
                &format!("https://s{i}.example"),
                "u",
                "pw",
            ))
            .await
            .unwrap();
        a.client.sync().await.unwrap();
    }
    let cp = a.client.status();
    assert!(cp.last_sync_at.is_some());
    // storage is restored from an older snapshot: the two newest manifests disappear
    let seq = keys::parse_manifest(
        store
            .keys()
            .await
            .iter()
            .filter(|k| k.starts_with("manifests/"))
            .max()
            .unwrap(),
    )
    .unwrap();
    let m_last = store
        .get(&keys::manifest(seq))
        .await
        .unwrap()
        .unwrap()
        .bytes;
    let m_prev = store
        .get(&keys::manifest(seq - 1))
        .await
        .unwrap()
        .unwrap()
        .bytes;
    store.delete(&keys::manifest(seq)).await.unwrap();
    store.delete(&keys::manifest(seq - 1)).await.unwrap();

    a.client
        .save_item(login("New", "https://new.example", "u", "pw"))
        .await
        .unwrap();
    let r = a.client.sync().await.unwrap();
    assert_eq!(r.status, SyncStatus::RollbackDetected);
    assert_eq!(r.error_code.as_deref(), Some("ROLLBACK_DETECTED"));
    let st = a.client.status();
    assert!(st.rollback_detected);
    assert_eq!(
        st.pending_changes, 1,
        "writes are refused; the change stays local"
    );
    assert_eq!(
        store.get(&keys::manifest(seq - 1)).await.unwrap(),
        None,
        "nothing was written over the rollback"
    );

    // the same manifest number with different content is also a rollback / replacement
    store.tamper(&keys::manifest(seq - 1), b"{}".to_vec()).await;
    store.tamper(&keys::manifest(seq), b"{}".to_vec()).await;
    let r = a.client.sync().await.unwrap();
    assert_eq!(r.status, SyncStatus::RollbackDetected);

    // storage restored properly → sync resumes and the outbox is pushed
    store.tamper(&keys::manifest(seq - 1), m_prev).await;
    store.tamper(&keys::manifest(seq), m_last).await;
    let r = a.client.sync().await.unwrap();
    assert_eq!(r.status, SyncStatus::Ok, "{r:?}");
    assert!(!a.client.status().rollback_detected);
    assert_eq!(a.client.status().pending_changes, 0);
}

#[tokio::test]
async fn revoked_device_cannot_return() {
    let f = Arc::new(TestFactory::default());
    let relay = MemoryRelay::new();
    let a = device(&f, Platform::Macos);
    let b = device(&f, Platform::Android);
    create(&a).await;
    pair(&a.client, &b.client, &relay, "Old phone").await;
    let vault = a.client.vault_id().unwrap();
    let store = f.mem.store(&profile(), &vault);
    let id = a
        .client
        .save_item(login("CRM", "https://crm.example", "ops", "before"))
        .await
        .unwrap();
    a.client.sync().await.unwrap();
    b.client.sync().await.unwrap();
    let b_id = b.client.device_id().unwrap();
    let b_identity = DeviceIdentity::from_secret_bytes(
        b.secrets
            .get(&format!("aipass.device.{b_id}"))
            .unwrap()
            .unwrap()
            .expose(),
    )
    .unwrap();

    let res = a.client.revoke_device(&b_id).await.unwrap();
    assert_eq!(res.key_epoch, 2);
    assert!(res.rotation_tasks.iter().any(|t| t.entry_id == id));
    assert_eq!(a.client.rotation_tasks().unwrap().len(), 1);
    let mut upd = login("CRM", "https://crm.example", "ops", "after-rotation");
    upd.entry_id = Some(id.clone());
    a.client.save_item(upd).await.unwrap();
    a.client.sync().await.unwrap();
    assert!(
        a.client.rotation_tasks().unwrap().is_empty(),
        "changing the secret completes the task"
    );

    // the revoked device learns it is revoked and wipes its local copies
    let e = b.client.sync().await.unwrap_err();
    assert!(matches!(e, VaultError::Revoked));
    let st = b.client.status();
    assert!(st.revoked && !st.unlocked);
    assert!(!b.dir.path().join("cache").exists());
    assert!(b.client.unlock().await.is_err());

    // with its retained key it can neither open the new epoch …
    let (_eng, view) = raw_view(store.clone(), &vault).await;
    assert!(matches!(
        aipass_vault::UnlockedVault::open(&view, b_id.clone(), b_identity.clone(), None),
        Err(VaultError::Revoked)
    ));
    let me = view.manifest.entries.get(&id).unwrap();
    let obj: aipass_types::vault::EntryVersion = serde_json::from_slice(
        &store
            .get(&keys::entry(&id, me.version))
            .await
            .unwrap()
            .unwrap()
            .bytes,
    )
    .unwrap();
    assert_eq!(obj.key_epoch, 2);
    // … nor author manifests (e.g. re-activating itself)
    let mut d = ManifestDraft::from_view(&view);
    d.tombstone(&id, &aipass_types::time::now()).unwrap();
    let (cand, _) = d
        .finish(&b_identity, &b_id, &aipass_types::time::now())
        .unwrap();
    store
        .put(&cand.key(), cand.bytes.clone(), PutCondition::IfAbsent)
        .await
        .unwrap();
    let r = a.client.sync().await.unwrap();
    assert_eq!(r.error_code.as_deref(), Some("INTEGRITY_FAILED"));
    assert_eq!(secret_of(&a.client, &id), "after-rotation");
    assert!(
        a.client
            .devices()
            .unwrap()
            .iter()
            .any(|d| d.device_id == b_id && d.status == aipass_types::vault::MemberStatus::Revoked)
    );
}

#[tokio::test]
async fn deleted_entry_is_not_resurrected_by_an_offline_device() {
    let f = Arc::new(TestFactory::default());
    let relay = MemoryRelay::new();
    let a = device(&f, Platform::Macos);
    let b = device(&f, Platform::Ios);
    create(&a).await;
    pair(&a.client, &b.client, &relay, "Tablet").await;
    let vault = a.client.vault_id().unwrap();
    let store = f.mem.store(&profile(), &vault);
    let id = a
        .client
        .save_item(login("Old", "https://old.example", "u", "pw"))
        .await
        .unwrap();
    a.client.sync().await.unwrap();
    b.client.sync().await.unwrap();

    // B edits offline while A deletes
    let mut ib = login("Old (edited)", "https://old.example", "u", "pw2");
    ib.entry_id = Some(id.clone());
    b.client.save_item(ib).await.unwrap();
    a.client.delete_item(&id).await.unwrap();
    a.client.sync().await.unwrap();
    assert!(a.client.list_items(None, None).unwrap().is_empty());

    let r = b.client.sync().await.unwrap();
    assert_eq!(r.rejected, vec![id.clone()]);
    assert!(
        b.client.list_items(None, None).unwrap().is_empty(),
        "tombstone wins over the old edit"
    );
    assert_eq!(b.client.rejected_changes().unwrap(), vec![id.clone()]);
    a.client.sync().await.unwrap();
    assert!(a.client.list_items(None, None).unwrap().is_empty());

    // a forged manifest that resurrects the entry with an old version is rejected
    let (_eng, view) = raw_view(store.clone(), &vault).await;
    let a_id = a.client.device_id().unwrap();
    let a_identity = DeviceIdentity::from_secret_bytes(
        a.secrets
            .get(&format!("aipass.device.{a_id}"))
            .unwrap()
            .unwrap()
            .expose(),
    )
    .unwrap();
    let mut d = ManifestDraft::from_view(&view);
    let t = d.tombstones.remove(&id).unwrap();
    let old_hash = store.get(&keys::entry(&id, 1)).await.unwrap().unwrap().etag;
    d.entries.insert(
        id.clone(),
        aipass_types::vault::ManifestEntry {
            version: 1,
            hash: old_hash,
            conflict_versions: vec![],
        },
    );
    assert!(t.version >= 1);
    let (cand, _) = d
        .finish(&a_identity, &a_id, &aipass_types::time::now())
        .unwrap();
    store
        .put(&cand.key(), cand.bytes.clone(), PutCondition::IfAbsent)
        .await
        .unwrap();
    let r = b.client.sync().await.unwrap();
    assert_eq!(
        r.error_code.as_deref(),
        Some(ErrorCode::IntegrityFailed.as_str())
    );
    store.delete(&cand.key()).await.unwrap();

    // explicit restore = a new version above the tombstone
    b.client.restore_rejected(&id).await.unwrap();
    let r = b.client.sync().await.unwrap();
    assert_eq!(r.status, SyncStatus::Ok, "{r:?}");
    let restored = b.client.get_item(&id).unwrap();
    assert!(restored.version.unwrap() > t.version);
    assert_eq!(restored.summary.title, "Old (edited)");
    a.client.sync().await.unwrap();
    assert_eq!(secret_of(&a.client, &id), "pw2");
}
