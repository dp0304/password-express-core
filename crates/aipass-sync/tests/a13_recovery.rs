// SPDX-License-Identifier: Apache-2.0
//! A13 — replacing a phone / losing a device: recovery with the recovery key on a fresh
//! device, recovery through a second trusted device, wrong keys rejected, the lost device
//! revoked afterwards. A14 — the vault stays usable without any cloud service.

mod common;

use std::sync::Arc;

use aipass_crypto::SecretString;
use aipass_sync::{SyncStatus, VaultClient, VaultError};
use aipass_types::vault::{MemberRole, MemberStatus, Platform};
use aipass_vault::MemoryRelay;
use common::*;

#[tokio::test]
async fn recover_on_a_fresh_device_with_the_recovery_key() {
    let f = Arc::new(TestFactory::default());
    let a = device(&f, Platform::Ios);
    let rk = create(&a).await;
    let vault = a.client.vault_id().unwrap();
    let id = a
        .client
        .save_item(login("Shop", "https://shop.example", "me", "keep-me"))
        .await
        .unwrap();
    a.client.sync().await.unwrap();
    assert!(!a.client.status().recovery_verified);

    // recovery verification: wrong key → false, right key → verified, pending copy removed
    assert!(!a.client.verify_recovery_key("AIPR-0000-0000").unwrap());
    let other = aipass_vault::RecoveryKey::generate().unwrap();
    assert!(
        !a.client
            .verify_recovery_key(other.format().expose())
            .unwrap()
    );
    let kit_before = a.client.recovery_kit_text(false).unwrap();
    assert!(kit_before.expose().contains(&rk));
    assert!(
        a.client
            .verify_recovery_key(&rk.to_lowercase().replace('-', " "))
            .unwrap()
    );
    assert!(a.client.status().recovery_verified);
    assert!(
        !a.client
            .recovery_kit_text(false)
            .unwrap()
            .expose()
            .contains(&rk)
    );

    // phone lost; the user installs the app on a new phone
    let dir = tempfile::tempdir().unwrap();
    let secrets = Arc::new(aipass_vault::MemorySecretStore::new());
    let bad = VaultClient::recover_with_key(
        config(dir.path(), Platform::Ios),
        secrets.clone(),
        f.clone(),
        &vault,
        profile(),
        Some(SecretString::from("s3-secret-key")),
        other.format().expose(),
        "New phone",
    )
    .await;
    assert!(bad.is_err(), "a key of another vault must be rejected");
    let typo = format!("{}X", &rk[..rk.len() - 1]);
    let bad = VaultClient::recover_with_key(
        config(dir.path(), Platform::Ios),
        secrets.clone(),
        f.clone(),
        &vault,
        profile(),
        None,
        &typo,
        "New phone",
    )
    .await;
    assert!(bad.is_err(), "a mistyped key fails the checksum");
    let n = VaultClient::recover_with_key(
        config(dir.path(), Platform::Ios),
        secrets.clone(),
        f.clone(),
        &vault,
        profile(),
        Some(SecretString::from("s3-secret-key")),
        &rk,
        "New phone",
    )
    .await
    .unwrap();
    assert_eq!(secret_of(&n, &id), "keep-me");
    let me = n
        .devices()
        .unwrap()
        .into_iter()
        .find(|d| d.is_this_device)
        .unwrap();
    assert_eq!(me.role, MemberRole::Owner);

    // revoke the lost phone; it can no longer sync
    let lost = a.client.device_id().unwrap();
    let r = n.revoke_device(&lost).await.unwrap();
    assert_eq!(r.key_epoch, 2);
    assert!(!r.rotation_tasks.is_empty());
    assert!(matches!(a.client.sync().await, Err(VaultError::Revoked)));
    n.save_item(login("After", "https://after.example", "me", "new"))
        .await
        .unwrap();
    assert_eq!(n.sync().await.unwrap().status, SyncStatus::Ok);

    // the same recovery key still works after the rotation (sealed to the recovery member)
    let dir2 = tempfile::tempdir().unwrap();
    let n2 = VaultClient::recover_with_key(
        config(dir2.path(), Platform::Android),
        Arc::new(aipass_vault::MemorySecretStore::new()),
        f.clone(),
        &vault,
        profile(),
        None,
        &rk,
        "Second new phone",
    )
    .await
    .unwrap();
    assert_eq!(secret_of(&n2, &id), "keep-me");
    assert_eq!(n2.status().key_epoch, Some(2));
    assert_eq!(n2.list_items(None, None).unwrap().len(), 2);
}

#[tokio::test]
async fn replacing_the_recovery_key_revokes_the_old_one() {
    let f = Arc::new(TestFactory::default());
    let a = device(&f, Platform::Macos);
    let old = create(&a).await;
    let vault = a.client.vault_id().unwrap();
    let res = a.client.replace_recovery_key().await.unwrap();
    assert_ne!(res.recovery_key.expose(), old);
    assert!(
        res.recovery_kit_text
            .expose()
            .contains(res.recovery_key.expose())
    );
    assert!(!a.client.verify_recovery_key(&old).unwrap());
    let rec: Vec<_> = a
        .client
        .devices()
        .unwrap()
        .into_iter()
        .filter(|d| d.is_recovery_key)
        .collect();
    assert_eq!(rec.len(), 2);
    assert_eq!(
        rec.iter()
            .filter(|d| d.status == MemberStatus::Active)
            .count(),
        1
    );
    let dir = tempfile::tempdir().unwrap();
    let bad = VaultClient::recover_with_key(
        config(dir.path(), Platform::Cli),
        Arc::new(aipass_vault::MemorySecretStore::new()),
        f.clone(),
        &vault,
        profile(),
        None,
        &old,
        "x",
    )
    .await;
    assert!(bad.is_err());
    let ok = VaultClient::recover_with_key(
        config(dir.path(), Platform::Cli),
        Arc::new(aipass_vault::MemorySecretStore::new()),
        f.clone(),
        &vault,
        profile(),
        None,
        res.recovery_key.expose(),
        "CLI",
    )
    .await;
    assert!(ok.is_ok());
}

#[tokio::test]
async fn recover_through_a_second_trusted_device() {
    let f = Arc::new(TestFactory::default());
    let relay = MemoryRelay::new();
    let a = device(&f, Platform::Ios);
    let b = device(&f, Platform::Macos);
    create(&a).await;
    pair(&a.client, &b.client, &relay, "MacBook").await;
    let id = a
        .client
        .save_item(login("Docs", "https://docs.example", "me", "secret-doc"))
        .await
        .unwrap();
    a.client.sync().await.unwrap();
    b.client.sync().await.unwrap();
    // the phone is lost; the MacBook pairs the new phone and revokes the old one
    let c = device(&f, Platform::Ios);
    pair(&b.client, &c.client, &relay, "New iPhone").await;
    assert_eq!(secret_of(&c.client, &id), "secret-doc");
    b.client
        .revoke_device(&a.client.device_id().unwrap())
        .await
        .unwrap();
    c.client.sync().await.unwrap();
    assert_eq!(c.client.status().key_epoch, Some(2));
    assert_eq!(secret_of(&c.client, &id), "secret-doc");
    // the storage secret travelled end-to-end encrypted in the welcome
    assert!(
        c.secrets
            .keys()
            .iter()
            .any(|k| k.starts_with("aipass.storage."))
    );
}

#[tokio::test]
async fn master_password_and_offline_use_without_services() {
    let f = Arc::new(TestFactory::default());
    let a = device(&f, Platform::Windows);
    create(&a).await;
    let vault = a.client.vault_id().unwrap();
    let store = f.mem.store(&profile(), &vault);
    a.client
        .set_master_password(&SecretString::from("correct horse battery staple"))
        .await
        .unwrap();
    assert!(
        store
            .keys()
            .await
            .iter()
            .any(|k| k == "recovery/1-master_password.json")
    );
    // changing it rotates the key epoch (wraps are immutable per epoch)
    a.client
        .set_master_password(&SecretString::from("another long passphrase"))
        .await
        .unwrap();
    assert_eq!(a.client.status().key_epoch, Some(2));
    assert!(
        store
            .keys()
            .await
            .iter()
            .any(|k| k == "recovery/2-master_password.json")
    );
    let id = a
        .client
        .save_item(login("Local", "https://local.example", "me", "pw"))
        .await
        .unwrap();
    a.client.sync().await.unwrap();

    // A14: the service disappears — unlock, read, export and recovery checks still work
    f.set_offline(true);
    a.client.lock();
    let again = reopen(&a, &f, Platform::Windows);
    again.unlock().await.unwrap();
    assert_eq!(secret_of(&again, &id), "pw");
    let export = again
        .export_encrypted(&SecretString::from("export-password"))
        .unwrap();
    assert!(!export.is_empty());
    assert!(again.export_csv().unwrap().len() > 10);
    assert_eq!(again.sync().await.unwrap().status, SyncStatus::Offline);
}
