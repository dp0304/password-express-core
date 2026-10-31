// SPDX-License-Identifier: Apache-2.0
//! VaultClient facade: lifecycle, masking, reveal, TOTP, import / export, autofill,
//! storage test + migration, concurrent commits, the 90-day offline rule.

mod common;

use std::sync::Arc;

use aipass_crypto::SecretString;
use aipass_storage::{
    Object, ObjectMeta, ObjectStore, PutCondition, PutOutcome, StorageDescription, StorageError,
    StorageKind, StorageProfile, StorageVerdict,
};
use aipass_sync::{
    FieldInput, ItemInput, SaveStatus, SecretField, StoreContext, StoreFactory, SyncStatus,
    VaultClient, VaultError,
};
use aipass_types::ErrorCode;
use aipass_types::vault::{EntryKind, Lifecycle, Platform};
use aipass_vault::import::CsvFormat;
use aipass_vault::matching::MatchKind;
use aipass_vault::{MemoryRelay, MemorySecretStore};
use async_trait::async_trait;
use common::*;

#[tokio::test]
async fn lifecycle_masking_reveal_and_totp() {
    let f = Arc::new(TestFactory::default());
    let a = device(&f, Platform::Macos);
    assert!(!a.client.has_vault());
    assert!(matches!(a.client.unlock().await, Err(VaultError::NoVault)));
    let created = a
        .client
        .create_vault(
            "MacBook",
            profile(),
            Some(SecretString::from("storage-secret-value")),
            None,
        )
        .await
        .unwrap();
    assert!(created.recovery_key.expose().starts_with("AIPR-"));
    assert!(!format!("{created:?}").contains("AIPR"));
    assert!(
        a.secrets
            .requires_presence(&format!("aipass.device.{}", created.device_id))
            .unwrap()
    );
    // nothing secret in the data directory
    for f in ["device.json", "state.json"] {
        let t = std::fs::read_to_string(a.dir.path().join(f)).unwrap();
        assert!(
            !t.contains("AIPR") && !t.contains("storage-secret-value"),
            "{f}"
        );
    }

    let mut i = login("GitHub", "github.com", "octocat", "gh-secret");
    i.totp = Some(SecretString::from(
        "otpauth://totp/GitHub:octocat?secret=JBSWY3DPEHPK3PXP&issuer=GitHub",
    ));
    i.fields = vec![
        FieldInput {
            name: "recovery code".into(),
            value: Some(SecretString::from("rc-1")),
            sensitive: true,
        },
        FieldInput {
            name: "plan".into(),
            value: Some(SecretString::from("pro")),
            sensitive: false,
        },
    ];
    let id = a.client.save_item(i).await.unwrap();
    a.client.sync().await.unwrap();
    let d = a.client.get_item(&id).unwrap();
    assert_eq!(d.urls, vec!["https://github.com".to_owned()]);
    assert_eq!(d.secret_masked.as_deref(), Some("••••••••"));
    assert!(d.has_totp);
    assert_eq!(d.fields[0].value, None);
    assert_eq!(d.fields[1].value.as_deref(), Some("pro"));
    assert_eq!(d.summary.lifecycle, Lifecycle::Verified);
    let json = serde_json::to_string(&d).unwrap();
    assert!(!json.contains("gh-secret") && !json.contains("rc-1") && !json.contains("JBSWY3"));
    assert_eq!(secret_of(&a.client, &id), "gh-secret");
    assert_eq!(
        a.client
            .reveal_secret(&id, &SecretField::Field("recovery code".into()))
            .unwrap()
            .expose(),
        "rc-1"
    );
    assert_eq!(
        a.client
            .reveal_secret(&id, &SecretField::TotpSecret)
            .unwrap()
            .expose(),
        "JBSWY3DPEHPK3PXP"
    );
    let code = a.client.totp_now(&id).unwrap();
    assert_eq!(code.code.expose().len(), 6);

    // update without resending secrets keeps them
    let mut upd = ItemInput::new(EntryKind::Login, "GitHub (work)");
    upd.entry_id = Some(id.clone());
    upd.urls = vec!["https://github.com".into()];
    upd.username = Some("octocat".into());
    upd.fields = vec![FieldInput {
        name: "recovery code".into(),
        value: None,
        sensitive: true,
    }];
    a.client.save_item(upd).await.unwrap();
    assert_eq!(secret_of(&a.client, &id), "gh-secret");
    assert_eq!(
        a.client
            .reveal_secret(&id, &SecretField::Field("recovery code".into()))
            .unwrap()
            .expose(),
        "rc-1"
    );
    assert!(a.client.get_item(&id).unwrap().has_totp);

    // search / filter
    a.client
        .save_item(login("Bank", "https://bank.example", "me", "x"))
        .await
        .unwrap();
    assert_eq!(a.client.list_items(Some("git"), None).unwrap().len(), 1);
    assert_eq!(a.client.list_items(None, None).unwrap().len(), 2);
    assert!(
        a.client
            .save_item(ItemInput::new(EntryKind::Login, "  "))
            .await
            .is_err()
    );
    let mut bad = login("Bad", "javascript:alert(1)", "x", "y");
    bad.urls = vec!["javascript:alert(1)".into()];
    assert!(a.client.save_item(bad).await.is_err());

    // lock drops everything from memory
    a.client.lock();
    assert!(matches!(
        a.client.list_items(None, None),
        Err(VaultError::Locked)
    ));
    assert_eq!(
        a.client
            .reveal_secret(&id, &SecretField::Secret)
            .unwrap_err()
            .code(),
        ErrorCode::Locked
    );
    a.client.unlock().await.unwrap();
    assert_eq!(secret_of(&a.client, &id), "gh-secret");
    // a missing device key in the secret store prevents unlock
    a.client.lock();
    let dev = a.client.device_id().unwrap();
    let k = format!("aipass.device.{dev}");
    let saved = aipass_vault::SecretStore::get(a.secrets.as_ref(), &k)
        .unwrap()
        .unwrap();
    aipass_vault::SecretStore::delete(a.secrets.as_ref(), &k).unwrap();
    assert_eq!(
        a.client.unlock().await.unwrap_err().code(),
        ErrorCode::SecretUnavailable
    );
    aipass_vault::SecretStore::set(a.secrets.as_ref(), &k, saved.expose(), true).unwrap();
    a.client.unlock().await.unwrap();
    // delete
    a.client.delete_item(&id).await.unwrap();
    a.client.sync().await.unwrap();
    assert_eq!(a.client.list_items(None, None).unwrap().len(), 1);
    let st = a.client.status();
    assert_eq!(st.pending_changes, 0);
    assert!(st.unlocked && st.key_epoch == Some(1) && st.storage_kind == Some(StorageKind::S3));
}

#[tokio::test]
async fn import_export_and_autofill() {
    let f = Arc::new(TestFactory::default());
    let a = device(&f, Platform::Windows);
    create(&a).await;
    let csv = "name,url,username,password,note\nShop,https://shop.example.com/login,alice,shop-pw,\nShop dup,https://www.shop.example.com,ALICE,x,\n";
    let r = a
        .client
        .import_csv(CsvFormat::Chrome, csv.as_bytes())
        .await
        .unwrap();
    assert_eq!(r.imported, 1);
    assert_eq!(r.duplicates.len(), 1);
    // a second import of the same file finds the existing entry
    let r2 = a
        .client
        .import_csv(CsvFormat::Chrome, csv.as_bytes())
        .await
        .unwrap();
    assert_eq!(r2.imported, 0);
    assert_eq!(r2.duplicates.len(), 2);
    a.client.sync().await.unwrap();
    let items = a.client.list_items(None, None).unwrap();
    assert_eq!(items[0].lifecycle, Lifecycle::Imported);
    let id = items[0].entry_id.clone();

    // autofill: exact origin vs same site; never on http
    let c = a
        .client
        .autofill_candidates("https://shop.example.com/cart")
        .unwrap();
    assert_eq!(c[0].match_kind, MatchKind::ExactOrigin);
    let c = a
        .client
        .autofill_candidates("https://pay.shop.example.com")
        .unwrap();
    assert_eq!(c[0].match_kind, MatchKind::SameSite);
    assert!(
        a.client
            .autofill_candidates("http://shop.example.com")
            .unwrap()
            .is_empty()
    );
    assert!(
        a.client
            .autofill_candidates("https://shop.example.com.evil.example")
            .unwrap()
            .is_empty()
    );
    let cred = a.client.autofill_credential(&id).unwrap();
    assert_eq!(cred.password.expose(), "shop-pw");
    assert!(!format!("{cred:?}").contains("shop-pw"));
    let ids = a.client.all_credential_identities().unwrap();
    assert_eq!(ids[0].service_identifier, "shop.example.com");

    // browser save: update existing / new / ambiguous
    let (s, sid) = a
        .client
        .save_from_browser(
            "https://shop.example.com",
            Some("alice"),
            SecretString::from("new-shop-pw"),
            "change_password",
        )
        .await
        .unwrap();
    assert_eq!(s, SaveStatus::Updated);
    assert_eq!(sid.as_ref(), Some(&id));
    assert_eq!(secret_of(&a.client, &id), "new-shop-pw");
    let (s, nid) = a
        .client
        .save_from_browser(
            "https://other.example",
            Some("bob"),
            SecretString::from("bob-pw"),
            "signup",
        )
        .await
        .unwrap();
    assert_eq!(s, SaveStatus::Saved);
    assert_eq!(
        a.client.get_item(&nid.unwrap()).unwrap().summary.lifecycle,
        Lifecycle::NeedsAttention
    );

    // encrypted export → import into a fresh vault
    let pw = SecretString::from("export-password-xyz");
    let bytes = a.client.export_encrypted(&pw).unwrap();
    assert!(!String::from_utf8_lossy(&bytes).contains("new-shop-pw"));
    assert!(
        a.client
            .export_encrypted(&SecretString::from("short"))
            .is_err()
    );
    let b = device(&f, Platform::Linux);
    let mut p2 = profile();
    p2.bucket = Some("other-bucket".into());
    b.client
        .create_vault("Linux", p2, None, None)
        .await
        .unwrap();
    assert!(
        b.client
            .import_encrypted(&bytes, &SecretString::from("wrong-password!!"))
            .await
            .is_err()
    );
    let rep = b.client.import_encrypted(&bytes, &pw).await.unwrap();
    assert_eq!(rep.imported, 2);
    b.client.sync().await.unwrap();
    assert_eq!(secret_of(&b.client, &id), "new-shop-pw");
    assert_eq!(
        b.client
            .import_encrypted(&bytes, &pw)
            .await
            .unwrap()
            .duplicates
            .len(),
        2
    );

    // CSV export carries the contract header
    let csv_out = a.client.export_csv().unwrap();
    let text = String::from_utf8(csv_out.to_vec()).unwrap();
    assert!(text.starts_with("title,url,username,password,notes,totp,kind"));
    assert!(text.contains("new-shop-pw"));
}

/// A backend whose conditional writes are ignored (fails the capability test).
struct IgnoresConditions(Arc<dyn ObjectStore>);

#[async_trait]
impl ObjectStore for IgnoresConditions {
    async fn get(&self, k: &str) -> Result<Option<Object>, StorageError> {
        self.0.get(k).await
    }
    async fn put(&self, k: &str, b: Vec<u8>, _c: PutCondition) -> Result<PutOutcome, StorageError> {
        self.0.put(k, b, PutCondition::None).await
    }
    async fn delete(&self, k: &str) -> Result<(), StorageError> {
        self.0.delete(k).await
    }
    async fn list(
        &self,
        p: &str,
        a: Option<&str>,
        l: usize,
    ) -> Result<Vec<ObjectMeta>, StorageError> {
        self.0.list(p, a, l).await
    }
    fn describe(&self) -> StorageDescription {
        StorageDescription {
            kind: "broken".into(),
            endpoint: None,
            detail: None,
        }
    }
}

struct MixedFactory(Arc<TestFactory>);

#[async_trait]
impl StoreFactory for MixedFactory {
    async fn open(
        &self,
        p: &StorageProfile,
        s: Option<&SecretString>,
        ctx: &StoreContext,
    ) -> aipass_sync::Result<Arc<dyn ObjectStore>> {
        let inner = self.0.open(p, s, ctx).await?;
        if p.bucket.as_deref() == Some("broken") {
            return Ok(Arc::new(IgnoresConditions(inner)));
        }
        Ok(inner)
    }
}

#[tokio::test]
async fn storage_test_and_migration() {
    let tf = Arc::new(TestFactory::default());
    let f = Arc::new(MixedFactory(tf.clone()));
    let dir = tempfile::tempdir().unwrap();
    let secrets = Arc::new(MemorySecretStore::new());
    let a = VaultClient::open(
        config(dir.path(), Platform::Macos),
        secrets.clone(),
        f.clone(),
    )
    .unwrap();
    a.create_vault("Mac", profile(), Some(SecretString::from("old-key")), None)
        .await
        .unwrap();
    let vault = a.vault_id().unwrap();
    let id = a
        .save_item(login("Keep", "https://keep.example", "u", "kept"))
        .await
        .unwrap();
    a.sync().await.unwrap();

    let mut good = profile();
    good.bucket = Some("new-bucket".into());
    let mut broken = profile();
    broken.bucket = Some("broken".into());
    let rep = a.test_storage(&good, None).await.unwrap();
    assert_eq!(rep.verdict, StorageVerdict::SyncCapable);
    let rep = a.test_storage(&broken, None).await.unwrap();
    assert_eq!(rep.verdict, StorageVerdict::BackupOnly);
    assert!(
        a.migrate_storage(broken, None).await.is_err(),
        "backup-only storage cannot become primary"
    );

    let m = a
        .migrate_storage(good.clone(), Some(SecretString::from("new-key")))
        .await
        .unwrap();
    assert!(m.old_storage_kept);
    assert_eq!(m.entries_verified, 1);
    assert!(m.objects_copied > 5);
    assert_eq!(
        Some(m.verified_checkpoint.clone()),
        a.lock_status_checkpoint()
    );
    // the old copy is untouched and the client now writes to the new one
    let old_store = tf.mem.store(&profile(), &vault);
    let new_store = tf.mem.store(&good, &vault);
    let old_keys = old_store.keys().await;
    a.save_item(login("After", "https://after.example", "u", "x"))
        .await
        .unwrap();
    assert_eq!(a.sync().await.unwrap().status, SyncStatus::Ok);
    assert_eq!(old_store.keys().await, old_keys);
    assert!(new_store.keys().await.len() > old_keys.len());
    assert_eq!(
        aipass_vault::SecretStore::get(secrets.as_ref(), &format!("aipass.storage.{vault}"))
            .unwrap()
            .unwrap()
            .expose(),
        b"new-key"
    );
    assert_eq!(secret_of(&a, &id), "kept");
    // migrating into a location that holds different data is refused
    let mut taken = profile();
    taken.bucket = Some("taken".into());
    tf.mem
        .store(&taken, &vault)
        .put("vault.json", b"{}".to_vec(), PutCondition::None)
        .await
        .unwrap();
    assert!(a.migrate_storage(taken, None).await.is_err());
}

trait CheckpointPeek {
    fn lock_status_checkpoint(&self) -> Option<aipass_types::vault::Checkpoint>;
}
impl CheckpointPeek for VaultClient {
    fn lock_status_checkpoint(&self) -> Option<aipass_types::vault::Checkpoint> {
        let state: aipass_sync::StateFile =
            serde_json::from_slice(&std::fs::read(self.data_dir().join("state.json")).unwrap())
                .unwrap();
        state.checkpoint
    }
}

#[tokio::test]
async fn concurrent_commits_rebase() {
    let f = Arc::new(TestFactory::default());
    let relay = MemoryRelay::new();
    let a = device(&f, Platform::Macos);
    let b = device(&f, Platform::Ios);
    create(&a).await;
    pair(&a.client, &b.client, &relay, "Phone").await;
    for i in 0..5 {
        a.client
            .save_item(login(
                &format!("A{i}"),
                &format!("https://a{i}.example"),
                "u",
                "p",
            ))
            .await
            .unwrap();
        b.client
            .save_item(login(
                &format!("B{i}"),
                &format!("https://b{i}.example"),
                "u",
                "p",
            ))
            .await
            .unwrap();
    }
    let (ra, rb) = tokio::join!(a.client.sync(), b.client.sync());
    assert_eq!(ra.unwrap().status, SyncStatus::Ok);
    assert_eq!(rb.unwrap().status, SyncStatus::Ok);
    a.client.sync().await.unwrap();
    b.client.sync().await.unwrap();
    assert_eq!(a.client.list_items(None, None).unwrap().len(), 10);
    assert_eq!(b.client.list_items(None, None).unwrap().len(), 10);
    // orphan objects of a crashed writer do not block others
    let vault = a.client.vault_id().unwrap();
    let store = f.mem.store(&profile(), &vault);
    let id = a.client.list_items(Some("A0"), None).unwrap()[0]
        .entry_id
        .clone();
    let v = a.client.get_item(&id).unwrap().version.unwrap();
    store
        .put(
            &aipass_types::vault::keys::entry(&id, v + 1),
            b"orphan".to_vec(),
            PutCondition::IfAbsent,
        )
        .await
        .unwrap();
    let mut upd = login("A0 renamed", "https://a0.example", "u", "p2");
    upd.entry_id = Some(id.clone());
    a.client.save_item(upd).await.unwrap();
    assert_eq!(a.client.sync().await.unwrap().status, SyncStatus::Ok);
    assert!(a.client.get_item(&id).unwrap().version.unwrap() > v + 1);
    b.client.sync().await.unwrap();
    assert_eq!(secret_of(&b.client, &id), "p2");
}

#[tokio::test]
async fn long_offline_device_reverifies_before_pushing() {
    let f = Arc::new(TestFactory::default());
    let a = device(&f, Platform::Linux);
    create(&a).await;
    a.client.lock();
    // pretend the last verification was 120 days ago
    let path = a.dir.path().join("state.json");
    let mut st: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    st["membership_verified_at"] = serde_json::json!("2026-06-01T00:00:00Z");
    st["last_sync_at"] = serde_json::json!("2026-06-01T00:00:00Z");
    std::fs::write(&path, serde_json::to_vec(&st).unwrap()).unwrap();
    let c = reopen(&a, &f, Platform::Linux);
    c.unlock().await.unwrap();
    // storage replaced vault.json → the re-verification catches it and nothing is pushed
    let store = f.mem.store(&profile(), &c.vault_id().unwrap());
    let orig = store.get("vault.json").await.unwrap().unwrap().bytes;
    store.tamper("vault.json", b"{\"format\":1}".to_vec()).await;
    c.save_item(login("x", "https://x.example", "u", "p"))
        .await
        .unwrap();
    let r = c.sync().await.unwrap();
    assert_eq!(r.error_code.as_deref(), Some("INTEGRITY_FAILED"));
    assert_eq!(c.status().pending_changes, 1);
    store.tamper("vault.json", orig).await;
    assert_eq!(c.sync().await.unwrap().status, SyncStatus::Ok);
    assert_eq!(c.status().pending_changes, 0);
}
