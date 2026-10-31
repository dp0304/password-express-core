// SPDX-License-Identifier: Apache-2.0
//! Phone-approval path over a real relay (in-process `aipass-sync-server` relay router on
//! loopback): the embedded broker seals `approval.request` to the approver's `dev_` mailbox,
//! a trusted device fetches it, approves with its vault and posts `approval.decision` to the
//! executor mailbox; the desktop's relay consumer feeds it to the broker, which installs the
//! credential in the real executor. The desktop's own device plays the phone here.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use aipass_broker::{Actor, ConnectionPrincipal, NewConnection};
use aipass_crypto::{DeviceIdentity, SecretString, password::Argon2Params};
use aipass_desktop_lib::core::{AppCore, CoreOptions, NullSink};
use aipass_desktop_lib::paths::AppPaths;
use aipass_storage::RelayClient;
use aipass_storage::relay_client::RelayAuth;
use aipass_sync_server::relay::{MemoryRelayStore, StaticDirectory};
use aipass_sync_server::{RelayState, relay_router};
use aipass_types::ids::PrincipalId;
use aipass_types::models::{AccessRequest, AllowedProjects, HostType, Transport};
use aipass_types::relay::RelayMessage;
use aipass_vault::SecretStore;
use serde_json::json;

const PASSWORD: &str = "correct horse battery";

#[tokio::test]
async fn phone_style_approval_over_relay() {
    // Relay server.
    let directory = Arc::new(StaticDirectory::new());
    let state = RelayState::new(Arc::new(MemoryRelayStore::new()), directory.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(listener, relay_router(state).into_make_service_with_connect_info::<SocketAddr>()).await.unwrap();
    });
    let relay_url = format!("http://{addr}");

    // Desktop core with a vault.
    let dir = tempfile::tempdir().unwrap();
    let core = AppCore::open(CoreOptions {
        paths: AppPaths::new(dir.path().join("home")),
        platform: aipass_types::vault::Platform::Macos,
        app_version: "0.1.0-test".into(),
        argon2: Argon2Params::INSECURE_FAST_FOR_TESTS_ONLY,
        serve_broker_socket: false,
        store_factory: None,
        sink: Arc::new(NullSink),
    })
    .unwrap();
    let input = serde_json::from_value(json!({
        "device_name": "Test Mac", "unlock_password": PASSWORD,
        "storage": {"kind": "local", "path": dir.path().join("storage").display().to_string()},
    }))
    .unwrap();
    core.create_vault(input).await.unwrap();
    let node = core.node().await.unwrap();
    let exe = node.executor_id.clone();

    // The embedded executor was enrolled as a vault member (role executor).
    let devices = core.devices().unwrap();
    assert!(devices.iter().any(|d| d.device_id == aipass_vault::member::executor_member_id(&exe)
        && serde_json::to_value(d.role).unwrap() == json!("executor")));

    // Device identity of this desktop (plays the phone) from the encrypted secret store.
    let dev = core.vault().device_id().unwrap();
    let store = aipass_vault::FileSecretStore::open_or_create(
        core.paths().secrets_file(),
        &SecretString::from(PASSWORD),
        Argon2Params::INSECURE_FAST_FOR_TESTS_ONLY,
    )
    .unwrap();
    let dev_identity = Arc::new(DeviceIdentity::from_secret_bytes(store.get(&format!("aipass.device.{dev}")).unwrap().unwrap().expose()).unwrap());
    let exe_keys = core.vault().executor_keys(&exe).unwrap();
    directory.insert(PrincipalId::Executor(exe.clone()), exe_keys.sign_pk, ["vault".to_string()]);
    directory.insert(PrincipalId::Device(dev.clone()), dev_identity.public().sign_pk, ["vault".to_string()]);

    // Point the desktop at the relay (starts outbox + consumer).
    let mut s = core.settings();
    s.relay_url = Some(relay_url.clone());
    core.update_settings(s).unwrap();
    assert!(core.restart_relay().await.unwrap());

    // Resource + AI connection + access request.
    let entry = core
        .save_item(serde_json::from_value(json!({"kind": "api_key", "title": "API", "secret": "sk-relay-0123456789", "urls": [], "tags": []})).unwrap())
        .await
        .unwrap();
    let project = core.create_project("relay").await.unwrap();
    let resource = core
        .create_resource(serde_json::from_value(json!({
            "alias": "api", "service": "API", "connector": "http_api", "project_id": project["project_id"], "environment": "test",
            "config": {"base_url": "https://api.example.com", "auth": {"type": "bearer"},
                       "operations": {"list": {"method": "GET", "path": "/items", "side_effect": "read", "response": {"allowed_fields": ["id"]}}}},
            "credential_entry_id": entry.to_string(),
        })).unwrap())
        .await
        .unwrap();
    let conn = node
        .broker
        .create_connection(&Actor::System, NewConnection { host_type: HostType::Cursor, display_name: "Cursor".into(), transport: Transport::Stdio, allowed_projects: AllowedProjects::All, public_key: None })
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
            reason: None,
        })
        .await
        .unwrap();

    // "Phone": fetch the sealed request from its own mailbox, approve, send the decision.
    let phone = RelayClient::new(
        url::Url::parse(&relay_url).unwrap(),
        RelayAuth::Signed { kid: PrincipalId::Device(dev.clone()), signer: dev_identity.clone() },
    )
    .unwrap();
    let mut request = None;
    for _ in 0..20 {
        let (msgs, _) = core.vault().fetch_inbox(&phone, None, 1).await.unwrap();
        request = msgs.into_iter().find_map(|(_, from, m)| match m {
            RelayMessage::ApprovalRequest(req) if from == exe && req.approval_request_id == r.approval_request_id => Some(req),
            _ => None,
        });
        if request.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let request = request.expect("approval.request delivered over the relay");
    let decision = core.vault().approve(&request, None).await.unwrap();
    core.vault().send_to_executor(&phone, &exe, &RelayMessage::ApprovalDecision(Box::new(decision))).await.unwrap();

    // The desktop's consumer hands it to the broker → grant + credential in the executor.
    let mut grant = None;
    for _ in 0..60 {
        let st = node.broker.get_access_request(&principal, &r.approval_request_id).await.unwrap();
        if let Some(g) = st.grant_id {
            grant = Some(g);
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let grant = grant.expect("grant created from the relayed decision");
    assert!(node.executor.has_credential(grant.as_str()));

    core.shutdown().await;
    server.abort();
}
