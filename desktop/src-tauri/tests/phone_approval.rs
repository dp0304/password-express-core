// SPDX-License-Identifier: Apache-2.0
//! Phone approvals for desktop-hosted requests with a *separate* phone vault device — the
//! same `aipass_sync::VaultClient` approval code the mobile FFI calls — over a real relay
//! (in-process `aipass-sync-server` relay router on loopback):
//!
//! * the phone only knows the desktop's embedded executor from the vault member record
//!   (role executor, synced through storage) — nothing is registered on the phone;
//! * the desktop's broker seals `approval.request` to the phone's `dev_` mailbox, the phone
//!   approves with `approve_with_entry` (sealing the credential to the executor's member
//!   KEM key) and posts `approval.decision`; the desktop's relay consumer feeds the broker,
//!   which installs the credential in the real executor.
//!
//! Both pairing directions: the phone joins the desktop's vault (desktop confirms the SAS),
//! and the desktop joins the phone's vault (`join_begin`, phone confirms).

mod common;

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use aipass_broker::{Actor, ConnectionPrincipal, NewConnection};
use aipass_crypto::{DeviceIdentity, SecretString, password::Argon2Params};
use aipass_desktop_lib::core::{AppCore, EventSink};
use aipass_storage::RelayClient;
use aipass_storage::relay_client::RelayAuth;
use aipass_sync::{ClientConfig, StandardStoreFactory, VaultClient};
use aipass_sync_server::relay::{MemoryRelayStore, StaticDirectory};
use aipass_sync_server::{RelayState, relay_router};
use aipass_types::ids::PrincipalId;
use aipass_types::models::{AccessRequest, AllowedProjects, HostType, Transport};
use aipass_types::relay::RelayMessage;
use aipass_types::storage::{StorageKind, StorageProfile};
use aipass_types::vault::{MemberRole, MemberStatus, Platform};
use aipass_vault::{MemorySecretStore, SecretStore};
use serde_json::{Value, json};

#[derive(Default)]
struct Sink {
    events: Mutex<Vec<(String, Value)>>,
}
impl EventSink for Sink {
    fn emit(&self, event: &str, payload: Value) {
        self.events.lock().unwrap().push((event.to_owned(), payload));
    }
}
impl Sink {
    async fn wait_pairing(&self, stage: &str) -> Value {
        for _ in 0..200 {
            let found = self.events.lock().unwrap().iter().find(|(e, p)| e == "pairing" && p["stage"] == stage).map(|(_, p)| p.clone());
            if let Some(p) = found {
                return p;
            }
            if let Some((_, p)) = self.events.lock().unwrap().iter().find(|(e, p)| e == "pairing" && p["stage"] == "failed") {
                panic!("pairing failed: {p}");
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("no pairing event {stage}");
    }
}

async fn relay_server() -> (String, Arc<StaticDirectory>, tokio::task::JoinHandle<()>) {
    let directory = Arc::new(StaticDirectory::new());
    let state = RelayState::new(Arc::new(MemoryRelayStore::new()), directory.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(listener, relay_router(state).into_make_service_with_connect_info::<SocketAddr>()).await.unwrap();
    });
    (format!("http://{addr}"), directory, server)
}

/// The phone: its own data dir and in-memory key store (Keychain stand-in).
fn phone_client(dir: &std::path::Path) -> (VaultClient, Arc<MemorySecretStore>) {
    let mut cfg = ClientConfig::new(dir, Platform::Ios, "phone-test");
    cfg.argon2 = Argon2Params::INSECURE_FAST_FOR_TESTS_ONLY;
    cfg.auto_sync = false;
    let secrets = Arc::new(MemorySecretStore::new());
    let c = VaultClient::open(cfg, secrets.clone(), Arc::new(StandardStoreFactory::default())).unwrap();
    (c, secrets)
}

fn identity_of(store: &dyn SecretStore, dev: &aipass_types::ids::DeviceId) -> Arc<DeviceIdentity> {
    let bytes = store.get(&format!("aipass.device.{dev}")).unwrap().expect("device key in the secret store");
    Arc::new(DeviceIdentity::from_secret_bytes(bytes.expose()).unwrap())
}

/// Resource + AI connection on the desktop, an access request, and the phone approving it
/// through the relay. Returns after the executor holds the credential.
async fn phone_approves(core: &Arc<AppCore>, phone: &VaultClient, phone_secrets: &MemorySecretStore, relay_url: &str, directory: &StaticDirectory) -> aipass_types::GrantId {
    let node = core.node().await.unwrap();
    let exe = node.executor_id.clone();
    let phone_dev = phone.device_id().unwrap();
    let phone_identity = identity_of(phone_secrets, &phone_dev);

    // The desktop's broker accepts the phone as an approver.
    let approvers = node.broker.list_devices().await.unwrap().devices;
    assert!(
        approvers.iter().any(|d| d.device.device_id == phone_dev && d.status == MemberStatus::Active),
        "phone must be an approver of the desktop broker"
    );

    // The relay knows the principals (in production: from vault membership).
    let exe_keys = core.vault().executor_keys(&exe).unwrap();
    directory.insert(PrincipalId::Executor(exe.clone()), exe_keys.sign_pk, ["vault".to_string()]);
    directory.insert(PrincipalId::Device(phone_dev.clone()), phone_identity.public().sign_pk, ["vault".to_string()]);
    let mut s = core.settings();
    s.relay_url = Some(relay_url.to_owned());
    core.update_settings(s).unwrap();
    assert!(core.restart_relay().await.unwrap());

    let entry = core
        .save_item(serde_json::from_value(json!({"kind": "api_key", "title": "Lure API", "secret": "sk-phone-relay-0123456789", "urls": [], "tags": []})).unwrap())
        .await
        .unwrap();
    let project = core.create_project("relay").await.unwrap();
    let resource = core
        .create_resource(
            serde_json::from_value(json!({
                "alias": "api", "service": "API", "connector": "http_api", "project_id": project["project_id"], "environment": "test",
                "config": {"base_url": "https://api.example.com", "auth": {"type": "bearer"},
                           "operations": {"list": {"method": "GET", "path": "/items", "side_effect": "read", "response": {"allowed_fields": ["id"]}}}},
                "credential_entry_id": entry.to_string(),
            }))
            .unwrap(),
        )
        .await
        .unwrap();
    core.sync_now().await.unwrap();

    // The phone learns the executor only from the synced member record (role executor).
    phone.sync().await.unwrap();
    let member = aipass_vault::member::executor_member_id(&exe);
    let rec = phone.devices().unwrap().into_iter().find(|d| d.device_id == member).expect("executor member record on the phone");
    assert_eq!(rec.role, MemberRole::Executor);
    assert_eq!(rec.status, MemberStatus::Active);
    let k = phone.executor_keys(&exe).expect("executor keys from the member record");
    assert_eq!(k.kem_pk, exe_keys.kem_pk);

    let conn = node
        .broker
        .create_connection(&Actor::System, NewConnection { host_type: HostType::Codex, display_name: "Codex".into(), transport: Transport::Stdio, allowed_projects: AllowedProjects::All, public_key: None })
        .await
        .unwrap();
    let principal = ConnectionPrincipal::in_process(conn.connection.connection_id.clone());
    let r = node
        .broker
        .request_access(&principal, AccessRequest {
            resource_id: resource.resource_id.clone(),
            operations: vec!["http_api.call".into()],
            scope: Some(serde_json::from_value(json!({"operations": ["http_api.call"], "http_api": {"operations": ["list"]}})).unwrap()),
            limits: None,
            duration_seconds: Some(600),
            reason: Some("weekly report".into()),
        })
        .await
        .unwrap();

    let relay = RelayClient::new(url::Url::parse(relay_url).unwrap(), RelayAuth::Signed { kid: PrincipalId::Device(phone_dev.clone()), signer: phone_identity.clone() }).unwrap();
    let mut request = None;
    for _ in 0..50 {
        let (msgs, _) = phone.fetch_inbox(&relay, None, 1).await.unwrap();
        request = msgs.into_iter().find_map(|(_, from, m)| match m {
            RelayMessage::ApprovalRequest(req) if from == exe && req.approval_request_id == r.approval_request_id => Some(req),
            _ => None,
        });
        if request.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let request = request.expect("approval.request delivered to the phone over the relay");
    assert!(!serde_json::to_string(&request).unwrap().contains("sk-phone-relay"));
    // The FFI's approve_with_entry path: digest recomputed, signed, credential sealed.
    let decision = phone.approve_with_entry(&request, None, Some(&entry)).await.unwrap();
    phone.send_to_executor(&relay, &exe, &RelayMessage::ApprovalDecision(Box::new(decision))).await.unwrap();

    let mut grant = None;
    for _ in 0..100 {
        let st = node.broker.get_access_request(&principal, &r.approval_request_id).await.unwrap();
        if let Some(g) = st.grant_id {
            grant = Some(g);
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let grant = grant.expect("grant created from the phone's relayed decision");
    assert!(node.executor.has_credential(grant.as_str()));
    grant
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn phone_paired_to_the_desktop_approves_desktop_requests() {
    let (relay_url, directory, server) = relay_server().await;
    let dir = tempfile::tempdir().unwrap();
    let sink = Arc::new(Sink::default());
    let core = common::open_core(&dir.path().join("home"), false, sink.clone());
    common::create_vault(&core, &dir.path().join("storage")).await;

    // Phone shows a QR; the desktop scans it, compares the SAS and confirms.
    let phone_dir = dir.path().join("phone");
    std::fs::create_dir_all(&phone_dir).unwrap();
    let (phone, phone_secrets) = phone_client(&phone_dir);
    let mut ns = phone.begin_join("Test Phone", &relay_url).unwrap();
    let pair_relay = RelayClient::for_pairing(url::Url::parse(&relay_url).unwrap(), ns.offer().secret).unwrap();
    core.pair_scan(&ns.qr_payload()).await.unwrap();
    let hello = ns.wait_for_hello(&pair_relay, common::WAIT).await.unwrap();
    let sas = sink.wait_pairing("sas").await;
    assert_eq!(sas["sas"], hello.sas.as_str());
    let mut confirmed = false;
    for _ in 0..50 {
        if core.pair_confirm(Some(hello.sas.clone()), true).await.is_ok() {
            confirmed = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(confirmed);
    let welcome = ns.wait_for_welcome(&pair_relay, common::WAIT).await.unwrap();
    phone.complete_join(&ns, welcome, None).await.unwrap();

    let grant = phone_approves(&core, &phone, &phone_secrets, &relay_url, &directory).await;

    // A device revoked elsewhere stops approving here once the desktop sees the member
    // chain (simulated: revoke in the vault only, then reconcile as the sync loop does).
    let phone_dev = phone.device_id().unwrap();
    core.vault().revoke_device(&phone_dev).await.unwrap();
    let node = core.node().await.unwrap();
    assert_eq!(aipass_desktop_lib::core::reconcile_approvers(core.vault(), &node.broker).await.unwrap(), 1);
    let d = node.broker.list_devices().await.unwrap().devices.into_iter().find(|d| d.device.device_id == phone_dev).unwrap();
    assert_eq!(d.status, MemberStatus::Revoked);
    // …and the grant it approved is revoked with it.
    let g = node.broker.list_grants(None).await.unwrap().grants.into_iter().find(|g| g.grant_id == grant).unwrap();
    assert_ne!(serde_json::to_value(g.status).unwrap(), json!("active"));
    assert!(!node.executor.has_credential(grant.as_str()));

    core.shutdown().await;
    server.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn desktop_joined_from_the_phone_enrols_its_executor_and_accepts_phone_approvals() {
    let (relay_url, directory, server) = relay_server().await;
    let dir = tempfile::tempdir().unwrap();

    // The phone created the vault (local-folder storage shared with the desktop).
    let phone_dir = dir.path().join("phone");
    std::fs::create_dir_all(&phone_dir).unwrap();
    let (phone, phone_secrets) = phone_client(&phone_dir);
    let mut profile = StorageProfile::new(StorageKind::Local);
    profile.path = Some(dir.path().join("storage").display().to_string());
    phone.create_vault("Test Phone", profile, None, None).await.unwrap();

    // The desktop shows a QR (join_begin); the phone scans it and confirms the SAS.
    let sink = Arc::new(Sink::default());
    let core = common::open_core(&dir.path().join("home"), false, sink.clone());
    let offer = core.join_begin("Test Mac", &relay_url, SecretString::from(common::PASSWORD)).await.unwrap();
    let uri = offer["qr_payload"].as_str().unwrap();
    let parsed = aipass_types::pairing::PairingOffer::parse(uri).unwrap();
    let pair_relay = RelayClient::for_pairing(url::Url::parse(&relay_url).unwrap(), parsed.secret).unwrap();
    let mut ts = phone.scan_pairing(uri, &pair_relay).await.unwrap();
    ts.wait_for_join(&pair_relay, common::WAIT).await.unwrap();
    let sas = sink.wait_pairing("sas").await;
    assert_eq!(sas["sas"], ts.sas());
    ts.confirm_code(sas["sas"].as_str().unwrap()).unwrap();
    phone.confirm_pairing(&mut ts, &pair_relay, true).await.unwrap();
    sink.wait_pairing("done").await;
    assert!(core.is_unlocked());

    // The embedded executor became a vault member right after the join (not only after
    // the next unlock), and the welcoming phone approves for the desktop's broker.
    let node = core.node().await.unwrap();
    let member = aipass_vault::member::executor_member_id(&node.executor_id);
    assert!(core.devices().unwrap().iter().any(|d| d.device_id == member && d.role == MemberRole::Executor));

    phone_approves(&core, &phone, &phone_secrets, &relay_url, &directory).await;
    core.shutdown().await;
    server.abort();
}
