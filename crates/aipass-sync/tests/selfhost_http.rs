// SPDX-License-Identifier: Apache-2.0
//! Vault creation on the device-signed HTTP sync API (`selfhost` profile) against the real
//! `aipass-sync-server` router: `POST /v1/vaults` stores `vault.json` and the genesis member
//! record, then the client's genesis write meets those keys again (immutable → 412) and must
//! accept them because the bytes are identical. Regression test for
//! `aipass vault init --storage selfhost|official` failing with "already exists".

mod common;

use std::net::SocketAddr;
use std::sync::Arc;

use aipass_crypto::SecretString;
use aipass_storage::{MemoryStore, StorageKind, StorageProfile};
use aipass_sync::{StandardStoreFactory, VaultClient};
use aipass_sync_server::sync::EnrollTokenAdmission;
use aipass_sync_server::{SyncState, sync_router};
use aipass_types::vault::{Platform, keys};
use aipass_vault::MemorySecretStore;

async fn server() -> (String, Arc<MemoryStore>, Arc<EnrollTokenAdmission>) {
    let blobs = Arc::new(MemoryStore::new());
    let admission = Arc::new(EnrollTokenAdmission::new());
    let state = SyncState::builder(blobs.clone(), admission.clone()).build();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            sync_router(state).into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await;
    });
    (format!("http://{addr}"), blobs, admission)
}

fn client(dir: &std::path::Path) -> VaultClient {
    VaultClient::open(
        common::config(dir, Platform::Cli),
        Arc::new(MemorySecretStore::new()),
        Arc::new(StandardStoreFactory::new()),
    )
    .unwrap()
}

fn selfhost(base: &str) -> StorageProfile {
    let mut p = StorageProfile::new(StorageKind::Selfhost);
    p.base_url = Some(base.to_owned());
    p
}

#[tokio::test(flavor = "multi_thread")]
async fn selfhost_vault_init_with_enroll_token_then_sync_and_reopen() {
    let (base, blobs, admission) = server().await;
    let token: SecretString = admission.generate(Some(1), None).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let c = client(dir.path());
    let created = c
        .create_vault("cli", selfhost(&base), Some(token.clone()), None)
        .await
        .expect("vault init on the HTTP sync API must succeed");
    let vault = created.vault_id.to_string();
    // the server holds the genesis objects (stored by POST /v1/vaults and re-confirmed by
    // the client) plus the first manifest written by the client
    let all = aipass_storage::list_all(blobs.as_ref(), "").await.unwrap();
    let has = |suffix: &str| {
        all.iter()
            .any(|m| m.key.contains(&vault) && m.key.ends_with(suffix))
    };
    assert!(
        has(keys::VAULT_HEADER) && has(&keys::manifest(1)),
        "{all:?}"
    );

    let id = c
        .save_item(common::login(
            "GitHub",
            "https://github.com",
            "octo",
            "s3cret-1",
        ))
        .await
        .unwrap();
    let r = c.sync().await.unwrap();
    assert_eq!(r.status, aipass_sync::models::SyncStatus::Ok, "{r:?}");
    c.lock();
    c.unlock().await.unwrap();
    c.sync().await.unwrap();
    assert_eq!(c.get_item(&id).unwrap().summary.title, "GitHub");

    // the single-use enroll token cannot create a second vault
    let dir2 = tempfile::tempdir().unwrap();
    let c2 = client(dir2.path());
    assert!(
        c2.create_vault("other", selfhost(&base), Some(token), None)
            .await
            .is_err()
    );
    assert!(
        !c2.has_vault(),
        "a failed creation leaves no local vault behind"
    );
}
