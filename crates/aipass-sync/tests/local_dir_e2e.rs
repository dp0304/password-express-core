// SPDX-License-Identifier: Apache-2.0
//! End-to-end over the real `aipass-storage` LocalDirStore (StandardStoreFactory) with the
//! passphrase-encrypted FileSecretStore — the CLI / self-host setup without any service.

use std::sync::Arc;

use aipass_crypto::{Argon2Params, SecretString};
use aipass_storage::{StorageKind, StorageProfile};
use aipass_sync::{ClientConfig, ItemInput, StandardStoreFactory, SyncStatus, VaultClient};
use aipass_types::vault::{EntryKind, Platform};
use aipass_vault::{FileSecretStore, MemoryRelay};

fn cfg(dir: &std::path::Path) -> ClientConfig {
    let mut c = ClientConfig::new(dir, Platform::Cli, "test");
    c.argon2 = Argon2Params::INSECURE_FAST_FOR_TESTS_ONLY;
    c.auto_sync = true;
    c
}

#[tokio::test]
async fn two_cli_devices_over_a_local_directory() {
    let storage = tempfile::tempdir().unwrap();
    let mut profile = StorageProfile::new(StorageKind::Local);
    profile.path = Some(storage.path().to_string_lossy().into_owned());
    let factory = Arc::new(StandardStoreFactory::new());
    let pass = SecretString::from("cli passphrase");

    let d1 = tempfile::tempdir().unwrap();
    let s1 = Arc::new(
        FileSecretStore::open_or_create(
            d1.path().join("secrets.bin"),
            &pass,
            Argon2Params::INSECURE_FAST_FOR_TESTS_ONLY,
        )
        .unwrap(),
    );
    let a = VaultClient::open(cfg(d1.path()), s1.clone(), factory.clone()).unwrap();
    let created = a
        .create_vault("cli-a", profile.clone(), None, None)
        .await
        .unwrap();
    let mut item = ItemInput::new(EntryKind::ApiKey, "OpenAI");
    item.secret = Some(SecretString::from("sk-test-local-dir"));
    let id = a.save_item(item).await.unwrap();
    assert_eq!(a.status().pending_changes, 0, "auto-sync pushed the change");
    // storage holds only ciphertext
    for entry in walk(storage.path()) {
        let bytes = std::fs::read(&entry).unwrap();
        let t = String::from_utf8_lossy(&bytes);
        assert!(
            !t.contains("sk-test-local-dir") && !t.contains("OpenAI"),
            "{entry:?}"
        );
    }

    // second device pairs through an in-memory relay and reads the same directory
    let relay = MemoryRelay::new();
    let d2 = tempfile::tempdir().unwrap();
    let s2 = Arc::new(
        FileSecretStore::open_or_create(
            d2.path().join("secrets.bin"),
            &pass,
            Argon2Params::INSECURE_FAST_FOR_TESTS_ONLY,
        )
        .unwrap(),
    );
    let b = VaultClient::open(cfg(d2.path()), s2.clone(), factory.clone()).unwrap();
    let mut ns = b.begin_join("cli-b", "http://127.0.0.1:7878").unwrap();
    let mut ts = a.scan_pairing(&ns.qr_payload(), &relay).await.unwrap();
    let hello = ns
        .wait_for_hello(&relay, std::time::Duration::from_secs(5))
        .await
        .unwrap();
    ts.wait_for_join(&relay, std::time::Duration::from_secs(5))
        .await
        .unwrap();
    ts.confirm_code(&hello.sas).unwrap();
    a.confirm_pairing(&mut ts, &relay, false).await.unwrap();
    let welcome = ns
        .wait_for_welcome(&relay, std::time::Duration::from_secs(5))
        .await
        .unwrap();
    b.complete_join(&ns, welcome, None).await.unwrap();
    assert_eq!(
        b.reveal_secret(&id, &aipass_sync::SecretField::Secret)
            .unwrap()
            .expose(),
        "sk-test-local-dir"
    );

    // restart device B: the passphrase-protected secret store unlocks it offline
    drop(b);
    let s2b = Arc::new(
        FileSecretStore::open_or_create(
            d2.path().join("secrets.bin"),
            &pass,
            Argon2Params::INSECURE_FAST_FOR_TESTS_ONLY,
        )
        .unwrap(),
    );
    let b2 = VaultClient::open(cfg(d2.path()), s2b, factory.clone()).unwrap();
    b2.unlock().await.unwrap();
    assert_eq!(b2.list_items(None, None).unwrap().len(), 1);
    assert_eq!(b2.sync().await.unwrap().status, SyncStatus::Ok);

    // recovery on a third device from the same directory with the recovery key
    let d3 = tempfile::tempdir().unwrap();
    let s3 = Arc::new(
        FileSecretStore::open_or_create(
            d3.path().join("secrets.bin"),
            &pass,
            Argon2Params::INSECURE_FAST_FOR_TESTS_ONLY,
        )
        .unwrap(),
    );
    let c = VaultClient::recover_with_key(
        cfg(d3.path()),
        s3,
        factory.clone(),
        &created.vault_id,
        profile,
        None,
        created.recovery_key.expose(),
        "cli-c",
    )
    .await
    .unwrap();
    assert_eq!(
        c.reveal_secret(&id, &aipass_sync::SecretField::Secret)
            .unwrap()
            .expose(),
        "sk-test-local-dir"
    );
    assert_eq!(
        c.devices()
            .unwrap()
            .iter()
            .filter(|d| !d.is_recovery_key)
            .count(),
        3
    );
}

fn walk(p: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    for e in std::fs::read_dir(p).unwrap() {
        let e = e.unwrap();
        if e.file_type().unwrap().is_dir() {
            out.extend(walk(&e.path()));
        } else {
            out.push(e.path());
        }
    }
    out
}
