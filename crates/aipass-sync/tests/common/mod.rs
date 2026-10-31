// SPDX-License-Identifier: Apache-2.0
//! Shared helpers for the aipass-sync integration tests.
#![allow(dead_code)]

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use aipass_crypto::{Argon2Params, SecretString};
use aipass_storage::{
    Object, ObjectMeta, ObjectStore, PutCondition, PutOutcome, StorageDescription, StorageError,
    StorageKind, StorageProfile,
};
use aipass_sync::{ClientConfig, MemoryStoreFactory, StoreContext, StoreFactory, VaultClient};
use aipass_types::vault::{EntryKind, Platform};
use aipass_vault::{MemoryRelay, MemorySecretStore, Result};
use async_trait::async_trait;

pub const RELAY: &str = "https://relay.aipass.example";
pub const WAIT: Duration = Duration::from_secs(5);

/// Factory over shared in-memory stores that can be switched offline.
#[derive(Default)]
pub struct TestFactory {
    pub mem: MemoryStoreFactory,
    pub offline: Arc<AtomicBool>,
}

pub struct ToggleStore {
    inner: Arc<dyn ObjectStore>,
    offline: Arc<AtomicBool>,
}

impl ToggleStore {
    fn check(&self) -> std::result::Result<(), StorageError> {
        if self.offline.load(Ordering::SeqCst) {
            Err(StorageError::Network("simulated offline".into()))
        } else {
            Ok(())
        }
    }
}

#[async_trait]
impl ObjectStore for ToggleStore {
    async fn get(&self, key: &str) -> std::result::Result<Option<Object>, StorageError> {
        self.check()?;
        self.inner.get(key).await
    }
    async fn put(
        &self,
        key: &str,
        bytes: Vec<u8>,
        cond: PutCondition,
    ) -> std::result::Result<PutOutcome, StorageError> {
        self.check()?;
        self.inner.put(key, bytes, cond).await
    }
    async fn delete(&self, key: &str) -> std::result::Result<(), StorageError> {
        self.check()?;
        self.inner.delete(key).await
    }
    async fn list(
        &self,
        prefix: &str,
        after: Option<&str>,
        limit: usize,
    ) -> std::result::Result<Vec<ObjectMeta>, StorageError> {
        self.check()?;
        self.inner.list(prefix, after, limit).await
    }
    fn describe(&self) -> StorageDescription {
        self.inner.describe()
    }
}

#[async_trait]
impl StoreFactory for TestFactory {
    async fn open(
        &self,
        profile: &StorageProfile,
        secret: Option<&SecretString>,
        ctx: &StoreContext,
    ) -> Result<Arc<dyn ObjectStore>> {
        let inner = self.mem.open(profile, secret, ctx).await?;
        Ok(Arc::new(ToggleStore {
            inner,
            offline: self.offline.clone(),
        }))
    }
}

impl TestFactory {
    pub fn set_offline(&self, v: bool) {
        self.offline.store(v, Ordering::SeqCst);
    }
}

pub fn profile() -> StorageProfile {
    let mut p = StorageProfile::new(StorageKind::S3);
    p.endpoint = Some("https://s3.example.test".into());
    p.bucket = Some("vault-bucket".into());
    p.prefix = Some("aipass/".into());
    p
}

pub struct Device {
    pub dir: tempfile::TempDir,
    pub secrets: Arc<MemorySecretStore>,
    pub client: VaultClient,
}

pub fn config(dir: &std::path::Path, platform: Platform) -> ClientConfig {
    let mut cfg = ClientConfig::new(dir, platform, "test");
    cfg.argon2 = Argon2Params::INSECURE_FAST_FOR_TESTS_ONLY;
    cfg.auto_sync = false;
    cfg
}

pub fn device(factory: &Arc<TestFactory>, platform: Platform) -> Device {
    let dir = tempfile::tempdir().unwrap();
    let secrets = Arc::new(MemorySecretStore::new());
    let client = VaultClient::open(
        config(dir.path(), platform),
        secrets.clone(),
        factory.clone(),
    )
    .unwrap();
    Device {
        dir,
        secrets,
        client,
    }
}

/// Re-open a device's client from disk (simulates an app restart).
pub fn reopen(d: &Device, factory: &Arc<TestFactory>, platform: Platform) -> VaultClient {
    VaultClient::open(
        config(d.dir.path(), platform),
        d.secrets.clone(),
        factory.clone(),
    )
    .unwrap()
}

/// Create a vault on `d`; returns the formatted recovery key.
pub async fn create(d: &Device) -> String {
    let r = d
        .client
        .create_vault(
            "Laptop",
            profile(),
            Some(SecretString::from("s3-secret-key")),
            None,
        )
        .await
        .unwrap();
    r.recovery_key.expose().to_owned()
}

/// Pair `new` into `trusted`'s vault through the in-memory relay.
pub async fn pair(trusted: &VaultClient, new: &VaultClient, relay: &MemoryRelay, name: &str) {
    let mut ns = new.begin_join(name, RELAY).unwrap();
    let mut ts = trusted.scan_pairing(&ns.qr_payload(), relay).await.unwrap();
    let hello = ns.wait_for_hello(relay, WAIT).await.unwrap();
    ts.wait_for_join(relay, WAIT).await.unwrap();
    assert_eq!(hello.sas, ts.sas());
    ts.confirm_code(&hello.sas).unwrap();
    trusted.confirm_pairing(&mut ts, relay, true).await.unwrap();
    let welcome = ns.wait_for_welcome(relay, WAIT).await.unwrap();
    new.complete_join(&ns, welcome, None).await.unwrap();
}

pub fn login(title: &str, url: &str, user: &str, pw: &str) -> aipass_sync::ItemInput {
    let mut i = aipass_sync::ItemInput::new(EntryKind::Login, title);
    i.urls = vec![url.into()];
    i.username = Some(user.into());
    i.secret = Some(SecretString::from(pw));
    i
}

pub fn secret_of(c: &VaultClient, id: &aipass_types::ids::EntryId) -> String {
    c.reveal_secret(id, &aipass_sync::SecretField::Secret)
        .unwrap()
        .expose()
        .to_owned()
}
