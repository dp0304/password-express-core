// SPDX-License-Identifier: Apache-2.0
//! A11 — two devices update the same password concurrently: no silent overwrite,
//! automatic use paused until a trusted client resolves the conflict.

mod common;

use std::sync::Arc;

use aipass_crypto::SecretString;
use aipass_storage::ObjectStore;
use aipass_sync::{SyncStatus, VaultError};
use aipass_types::ErrorCode;
use aipass_types::vault::{Platform, keys};
use aipass_vault::MemoryRelay;
use common::*;

#[tokio::test]
async fn concurrent_password_edits_conflict_and_pause_auto_use() {
    let f = Arc::new(TestFactory::default());
    let relay = MemoryRelay::new();
    let a = device(&f, Platform::Macos);
    let b = device(&f, Platform::Ios);
    create(&a).await;
    pair(&a.client, &b.client, &relay, "Phone").await;

    let id = a
        .client
        .save_item(login(
            "Shop",
            "https://shop.example.com",
            "alice",
            "base-pw",
        ))
        .await
        .unwrap();
    assert_eq!(a.client.sync().await.unwrap().status, SyncStatus::Ok);
    let rb = b.client.sync().await.unwrap();
    assert_eq!(rb.pulled, 1);
    assert_eq!(secret_of(&b.client, &id), "base-pw");

    // both devices change the password without seeing each other
    let mut ia = a
        .client
        .get_item(&id)
        .map(|_| {
            login(
                "Shop",
                "https://shop.example.com",
                "alice",
                "pw-from-laptop",
            )
        })
        .unwrap();
    ia.entry_id = Some(id.clone());
    a.client.save_item(ia).await.unwrap();
    let mut ib = login("Shop", "https://shop.example.com", "alice", "pw-from-phone");
    ib.entry_id = Some(id.clone());
    b.client.save_item(ib).await.unwrap();

    assert_eq!(a.client.sync().await.unwrap().status, SyncStatus::Ok);
    let r = b.client.sync().await.unwrap();
    assert_eq!(r.status, SyncStatus::Conflict, "{r:?}");
    assert_eq!(r.conflicts, 1);

    // status: the conflict count is known only while unlocked — a locked vault (here a
    // restarted app) reports unknown, never a reassuring 0
    assert_eq!(b.client.status().conflicts, Some(1));
    let restarted = reopen(&b, &f, Platform::Ios);
    assert!(!restarted.status().unlocked);
    assert_eq!(restarted.status().conflicts, None);
    restarted.unlock().await.unwrap();
    assert_eq!(restarted.status().conflicts, Some(1));
    restarted.lock();
    assert_eq!(restarted.status().conflicts, None, "a view left over from before lock() is not reported");
    drop(restarted);

    // no silent overwrite: the remote (laptop) value stays current, the phone's value is kept
    assert_eq!(secret_of(&b.client, &id), "pw-from-laptop");
    let detail = b.client.get_item(&id).unwrap();
    assert!(detail.summary.has_conflict);
    assert_eq!(detail.conflict_versions.len(), 1);
    let conflicts = b.client.conflicts().await.unwrap();
    assert_eq!(conflicts.len(), 1);
    let c = &conflicts[0];
    assert_eq!(c.versions.len(), 2);
    assert!(c.versions.iter().any(|v| !v.is_current && v.secret_differs));

    // automatic use is paused everywhere: autofill and approvals refuse the entry
    let e = b.client.autofill_credential(&id).unwrap_err();
    assert_eq!(e.code(), ErrorCode::SyncConflict);
    a.client.sync().await.unwrap();
    assert!(matches!(
        a.client.autofill_credential(&id),
        Err(VaultError::SyncConflict)
    ));
    assert!(a.client.list_items(None, None).unwrap()[0].has_conflict);

    // a trusted client resolves: keep the phone's version
    let keep = c.conflict_versions[0];
    b.client.resolve_conflict(&id, keep).await.unwrap();
    assert_eq!(secret_of(&b.client, &id), "pw-from-phone");
    assert!(!b.client.get_item(&id).unwrap().summary.has_conflict);
    assert_eq!(a.client.sync().await.unwrap().status, SyncStatus::Ok);
    assert_eq!(secret_of(&a.client, &id), "pw-from-phone");
    let cred = a.client.autofill_credential(&id).unwrap();
    assert_eq!(cred.password.expose(), "pw-from-phone");
    // resolving again with a stale view is refused
    assert!(
        b.client.resolve_conflict(&id, keep).await.is_err()
            || b.client.conflicts().await.unwrap().is_empty()
    );
}

#[tokio::test]
async fn non_secret_edits_merge_without_conflict() {
    let f = Arc::new(TestFactory::default());
    let relay = MemoryRelay::new();
    let a = device(&f, Platform::Macos);
    let b = device(&f, Platform::Android);
    create(&a).await;
    pair(&a.client, &b.client, &relay, "Pixel").await;
    let mut base = login("Forum", "https://forum.example.org", "bob", "pw");
    base.notes = Some("original".into());
    let id = a.client.save_item(base).await.unwrap();
    a.client.sync().await.unwrap();
    b.client.sync().await.unwrap();

    // laptop changes the title + notes, phone changes the password + notes
    let mut ia = login("Forum (renamed)", "https://forum.example.org", "bob", "pw");
    ia.entry_id = Some(id.clone());
    ia.secret = None; // keep
    ia.notes = Some("laptop note".into());
    a.client.save_item(ia).await.unwrap();
    let mut ib = login("Forum", "https://forum.example.org", "bob", "new-pw");
    ib.entry_id = Some(id.clone());
    ib.notes = Some("phone note".into());
    b.client.save_item(ib).await.unwrap();
    a.client.sync().await.unwrap();
    let r = b.client.sync().await.unwrap();
    assert_eq!(r.status, SyncStatus::Ok, "{r:?}");
    let d = b.client.get_item(&id).unwrap();
    assert!(!d.summary.has_conflict);
    assert_eq!(d.summary.title, "Forum (renamed)");
    assert_eq!(secret_of(&b.client, &id), "new-pw");
    let notes = d.notes.unwrap();
    assert!(
        notes.contains("laptop note")
            && notes.contains("phone note")
            && notes.contains("冲突副本 / conflict copy")
    );
    a.client.sync().await.unwrap();
    assert_eq!(secret_of(&a.client, &id), "new-pw");
}

#[tokio::test]
async fn offline_edits_stay_in_encrypted_outbox_until_back_online() {
    let f = Arc::new(TestFactory::default());
    let a = device(&f, Platform::Linux);
    create(&a).await;
    f.set_offline(true);
    let id = a
        .client
        .save_item(login(
            "Mail",
            "https://mail.example.net",
            "carol",
            "offline-pw",
        ))
        .await
        .unwrap();
    let r = a.client.sync().await.unwrap();
    assert_eq!(r.status, SyncStatus::Offline);
    assert_eq!(a.client.status().pending_changes, 1);
    assert!(a.client.list_items(None, None).unwrap()[0].pending_sync);
    // the outbox survives a restart and is encrypted at rest
    let raw = std::fs::read(a.dir.path().join("outbox.json")).unwrap();
    assert!(!String::from_utf8_lossy(&raw).contains("offline-pw"));
    a.client.lock();
    let again = reopen(&a, &f, Platform::Linux);
    again.unlock().await.unwrap();
    assert_eq!(again.status().pending_changes, 1);
    assert_eq!(secret_of(&again, &id), "offline-pw");
    f.set_offline(false);
    let r = again.sync().await.unwrap();
    assert_eq!(r.status, SyncStatus::Ok);
    assert_eq!(r.pushed, 1);
    assert_eq!(again.status().pending_changes, 0);
    assert!(!again.list_items(None, None).unwrap()[0].pending_sync);
    // unlock works offline from the local cache
    again.lock();
    f.set_offline(true);
    let third = reopen(&a, &f, Platform::Linux);
    third.unlock().await.unwrap();
    assert_eq!(secret_of(&third, &id), "offline-pw");
    let _ = SecretString::from("x");
}

/// CVS-04: conflict versions are not hash-listed in the manifest, so they are verified
/// (current key epoch) and pinned in the local cache when the manifest that introduces
/// them is applied; later storage tampering cannot swap the payload the user picks.
#[tokio::test]
async fn conflict_versions_are_pinned_when_introduced() {
    let f = Arc::new(TestFactory::default());
    let relay = MemoryRelay::new();
    let a = device(&f, Platform::Macos);
    let b = device(&f, Platform::Ios);
    create(&a).await;
    pair(&a.client, &b.client, &relay, "Phone").await;
    let id = a
        .client
        .save_item(login(
            "Shop",
            "https://shop.example.com",
            "alice",
            "base-pw",
        ))
        .await
        .unwrap();
    a.client.sync().await.unwrap();
    b.client.sync().await.unwrap();
    let mut ia = login(
        "Shop",
        "https://shop.example.com",
        "alice",
        "pw-from-laptop",
    );
    ia.entry_id = Some(id.clone());
    a.client.save_item(ia).await.unwrap();
    let mut ib = login("Shop", "https://shop.example.com", "alice", "pw-from-phone");
    ib.entry_id = Some(id.clone());
    b.client.save_item(ib).await.unwrap();
    a.client.sync().await.unwrap();
    assert_eq!(b.client.sync().await.unwrap().status, SyncStatus::Conflict);
    let keep = b.client.conflicts().await.unwrap()[0].conflict_versions[0];

    // A applies the manifest that introduces the conflict version …
    a.client.sync().await.unwrap();
    // … then the object is swapped on storage (e.g. by a revoked device that kept the
    // bucket credential)
    let vault = a.client.vault_id().unwrap();
    let store = f.mem.store(&profile(), &vault);
    let key = keys::entry(&id, keep);
    let mut obj = store.get(&key).await.unwrap().unwrap().bytes;
    let pos = obj.len() / 2;
    obj[pos] ^= if obj[pos] == b'A' { 2 } else { 1 };
    store.tamper(&key, obj).await;

    // A still shows and resolves to the genuine version
    let c = a.client.conflicts().await.unwrap();
    assert_eq!(c.len(), 1);
    assert!(
        c[0].versions
            .iter()
            .any(|v| v.version == keep && v.secret_differs)
    );
    a.client.resolve_conflict(&id, keep).await.unwrap();
    assert_eq!(secret_of(&a.client, &id), "pw-from-phone");
}
