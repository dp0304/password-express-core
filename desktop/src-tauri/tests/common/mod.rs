// SPDX-License-Identifier: Apache-2.0
//! Shared helpers for the desktop integration tests and the `nm_test_core` example:
//! a desktop core in test mode (fast Argon2, local-folder storage), a second vault device
//! ("phone") joined through the real pairing protocol, and a forced sync conflict.
#![allow(dead_code)]

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use aipass_crypto::SecretString;
use aipass_crypto::password::Argon2Params;
use aipass_desktop_lib::core::{AppCore, CoreOptions, EventSink};
use aipass_desktop_lib::paths::AppPaths;
use aipass_sync::{ClientConfig, ItemInput, StandardStoreFactory, VaultClient};
use aipass_types::ids::EntryId;
use aipass_types::vault::{EntryKind, Platform};
use aipass_vault::{MemoryRelay, MemorySecretStore};
use serde_json::json;

/// Local unlock password used by every test core.
pub const PASSWORD: &str = "correct horse battery";
/// Pairing wait.
pub const WAIT: Duration = Duration::from_secs(10);

/// Open a desktop core on `home` (does not create a vault).
pub fn open_core(home: &Path, serve_broker_socket: bool, sink: Arc<dyn EventSink>) -> Arc<AppCore> {
    AppCore::open(CoreOptions {
        paths: AppPaths::new(home.to_path_buf()),
        platform: Platform::Macos,
        app_version: "0.1.0-test".into(),
        argon2: Argon2Params::INSECURE_FAST_FOR_TESTS_ONLY,
        serve_broker_socket,
        store_factory: None,
        sink,
    })
    .expect("open core")
}

/// Create a vault on `core` with local-folder storage at `storage`.
pub async fn create_vault(core: &AppCore, storage: &Path) {
    let input = serde_json::from_value(json!({
        "device_name": "Test Mac",
        "unlock_password": PASSWORD,
        "storage": {"kind": "local", "path": storage.display().to_string()},
    }))
    .unwrap();
    core.create_vault(input).await.expect("create vault");
}

/// Save a login on the desktop.
pub async fn add_login(core: &AppCore, title: &str, url: &str, username: Option<&str>, password: &str, totp: Option<&str>) -> EntryId {
    let form = serde_json::from_value(json!({
        "kind": "login", "title": title, "username": username, "secret": password,
        "urls": [url], "tags": [], "totp": totp,
    }))
    .unwrap();
    core.save_item(form).await.expect("save login")
}

/// A second vault device (plays the phone): its own data dir and secret store, the same
/// local-folder storage, joined into `core`'s vault through the real §5 pairing protocol
/// (SAS compared on both sides, confirmed on the desktop).
pub async fn join_phone(core: &AppCore, dir: &Path) -> VaultClient {
    let mut cfg = ClientConfig::new(dir, Platform::Ios, "phone-test");
    cfg.argon2 = Argon2Params::INSECURE_FAST_FOR_TESTS_ONLY;
    cfg.auto_sync = false;
    let phone = VaultClient::open(cfg, Arc::new(MemorySecretStore::new()), Arc::new(StandardStoreFactory::default())).expect("open phone");
    let relay = MemoryRelay::new();
    let mut ns = phone.begin_join("Test Phone", "https://relay.invalid").unwrap();
    let mut ts = core.vault().scan_pairing(&ns.qr_payload(), &relay).await.unwrap();
    let hello = ns.wait_for_hello(&relay, WAIT).await.unwrap();
    ts.wait_for_join(&relay, WAIT).await.unwrap();
    assert_eq!(hello.sas, ts.sas());
    ts.confirm_code(&hello.sas).unwrap();
    core.vault().confirm_pairing(&mut ts, &relay, true).await.unwrap();
    let welcome = ns.wait_for_welcome(&relay, WAIT).await.unwrap();
    phone.complete_join(&ns, welcome, None).await.unwrap();
    phone
}

/// Make `entry` (a login on `url`) conflicted on the desktop: the phone changes the
/// password and pushes first, then the desktop changes it without having pulled.
pub async fn make_conflict(core: &AppCore, phone: &VaultClient, entry: &EntryId, title: &str, url: &str, username: &str) {
    core.sync_now().await.unwrap();
    phone.sync().await.unwrap();
    let mut i = ItemInput::new(EntryKind::Login, title);
    i.entry_id = Some(entry.clone());
    i.urls = vec![url.into()];
    i.username = Some(username.into());
    i.secret = Some(SecretString::from("FAKE-conflict-from-phone"));
    phone.save_item(i).await.unwrap();
    phone.sync().await.unwrap();
    let form = serde_json::from_value(json!({
        "entry_id": entry, "kind": "login", "title": title, "username": username,
        "secret": "FAKE-conflict-from-desktop", "urls": [url], "tags": [],
    }))
    .unwrap();
    core.save_item(form).await.unwrap();
    let _ = core.sync_now().await;
    assert!(core.get_item(entry).unwrap().summary.has_conflict, "conflict expected");
}
