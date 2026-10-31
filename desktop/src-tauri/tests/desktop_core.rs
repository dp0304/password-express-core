// SPDX-License-Identifier: Apache-2.0
//! End-to-end tests of the desktop core without a WebView: vault lifecycle, re-auth
//! gating, native-messaging rules, the IPC token handshake, and the approval flow through
//! the embedded broker with the real executor.

use std::sync::{Arc, Mutex};

use aipass_broker::{Actor, ConnectionPrincipal, NewConnection};
use aipass_crypto::password::Argon2Params;
use aipass_desktop_lib::core::{AppCore, CoreOptions, EventSink};
use aipass_desktop_lib::paths::AppPaths;
use aipass_types::models::{AccessRequest, AllowedProjects, HostType, RevocationLevel, Transport};
use serde_json::{Value, json};

#[derive(Default)]
struct RecordingSink {
    events: Mutex<Vec<(String, Value)>>,
}
impl EventSink for RecordingSink {
    fn emit(&self, event: &str, payload: Value) {
        self.events.lock().unwrap().push((event.to_owned(), payload));
    }
}

const PASSWORD: &str = "correct horse battery";

async fn new_core(dir: &std::path::Path, sink: Arc<RecordingSink>) -> Arc<AppCore> {
    AppCore::open(CoreOptions {
        paths: AppPaths::new(dir.join("home")),
        platform: aipass_types::vault::Platform::Macos,
        app_version: "0.1.0-test".into(),
        argon2: Argon2Params::INSECURE_FAST_FOR_TESTS_ONLY,
        serve_broker_socket: false,
        store_factory: None,
        sink,
    })
    .unwrap()
}

async fn create(core: &AppCore, dir: &std::path::Path) -> String {
    let input = serde_json::from_value(json!({
        "device_name": "Test Mac",
        "unlock_password": PASSWORD,
        "storage": {"kind": "local", "path": dir.join("storage").display().to_string()},
    }))
    .unwrap();
    let out = core.create_vault(input).await.unwrap();
    assert!(out.recovery_key.starts_with("AIPR-"));
    out.recovery_key
}

async fn add_login(core: &AppCore, title: &str, url: &str, password: &str) -> String {
    let form = serde_json::from_value(json!({
        "kind": "login", "title": title, "username": "alice", "secret": password, "urls": [url], "tags": [],
    }))
    .unwrap();
    core.save_item(form).await.unwrap().to_string()
}

#[tokio::test]
async fn vault_lifecycle_and_reauth() {
    let dir = tempfile::tempdir().unwrap();
    let sink = Arc::new(RecordingSink::default());
    let core = new_core(dir.path(), sink.clone()).await;
    assert!(!core.status().await.has_vault);
    let key = create(&core, dir.path()).await;
    let st = core.status().await;
    assert!(st.has_vault && st.unlocked && st.node_running);
    assert!(!st.core.recovery_verified);
    assert!(!core.verify_recovery_key("AIPR-WRONG").unwrap());
    assert!(core.verify_recovery_key(&key).unwrap());

    let id = add_login(&core, "Example", "https://example.com", "s3cret-Pa55").await;
    let items = core.list_items(None, None).unwrap();
    assert_eq!(items.len(), 1);
    let listed = serde_json::to_string(&items).unwrap();
    assert!(!listed.contains("s3cret-Pa55"), "list must not carry secrets");
    let detail = serde_json::to_string(&core.get_item(&id.parse().unwrap()).unwrap()).unwrap();
    assert!(!detail.contains("s3cret-Pa55"), "detail must be masked");

    // Reveal needs a fresh re-authentication.
    let err = core.reveal_secret(&id.parse().unwrap(), "secret").unwrap_err();
    assert_eq!(err.code, "REAUTH_REQUIRED");
    assert!(core.reauth("wrong password".into()).is_err());
    core.reauth(PASSWORD.into()).unwrap();
    assert_eq!(core.reveal_secret(&id.parse().unwrap(), "secret").unwrap().expose(), "s3cret-Pa55");

    // Generated passwords stay in Rust behind a handle.
    let rules = aipass_types::vault::PasswordRules::default();
    let g = core.generate_password(rules).unwrap();
    assert!(g.handle.starts_with("gen_") && g.length == 20 && !g.masked.contains(|c: char| c.is_ascii_alphanumeric()));
    let form = serde_json::from_value(json!({"kind": "login", "title": "Gen", "secret_ref": g.handle, "urls": [], "tags": []})).unwrap();
    let gid = core.save_item(form).await.unwrap();
    core.reauth(PASSWORD.into()).unwrap();
    assert_eq!(core.reveal_secret(&gid, "secret").unwrap().expose().chars().count(), 20);
    let reuse = serde_json::from_value(json!({"kind": "login", "title": "Again", "secret_ref": g.handle, "urls": [], "tags": []})).unwrap();
    assert!(core.save_item(reuse).await.is_err(), "a handle is single-use");

    // Lock → everything sensitive refuses; unlock with the password works again.
    core.lock_app().await;
    assert_eq!(core.list_items(None, None).unwrap_err().code, "LOCKED");
    assert!(core.unlock("not the password".into()).await.is_err());
    core.unlock(PASSWORD.into()).await.unwrap();
    assert_eq!(core.list_items(None, None).unwrap().len(), 2);
    assert!(sink.events.lock().unwrap().iter().any(|(e, p)| e == "app-status" && p["unlocked"] == false));

    // A second core on the same home sees the vault and needs the password.
    core.shutdown().await;
    let again = new_core(dir.path(), Arc::new(RecordingSink::default())).await;
    let st = again.status().await;
    assert!(st.has_vault && !st.unlocked);
    again.unlock(PASSWORD.into()).await.unwrap();
    assert_eq!(again.list_items(Some("Example".into()), None).unwrap().len(), 1);
    again.shutdown().await;
}

fn req(id: &str, kind: &str, extra: Value) -> Value {
    let mut v = json!({"id": id, "type": kind});
    if let (Value::Object(m), Value::Object(e)) = (&mut v, extra) {
        m.extend(e);
    }
    v
}

/// CLI-01: guessing the unlock password through the approval UI locks the app after
/// `PRESENCE_MAX_FAILURES` consecutive misses; a correct confirmation resets the count.
#[tokio::test]
async fn approval_presence_lockout() {
    use aipass_desktop_lib::core::PRESENCE_MAX_FAILURES;
    use aipass_types::ids::{ApprovalRequestId, ConnectionId};
    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path(), Arc::new(RecordingSink::default())).await;
    create(&core, dir.path()).await;
    let apr = ApprovalRequestId::generate();
    for _ in 1..PRESENCE_MAX_FAILURES {
        assert_eq!(core.approve(&apr, "x", None, Some(&"guess".into())).await.unwrap_err().code, "UNAUTHENTICATED");
    }
    // A correct confirmation resets the counter (the unknown id then fails later, harmlessly).
    assert_ne!(core.approve(&apr, "x", None, Some(&PASSWORD.into())).await.unwrap_err().code, "UNAUTHENTICATED");
    let conn = ConnectionId::generate();
    for _ in 1..PRESENCE_MAX_FAILURES {
        assert_eq!(core.approve_connection(&conn, AllowedProjects::All, Some(&"guess".into())).await.unwrap_err().code, "UNAUTHENTICATED");
    }
    assert!(core.is_unlocked());
    assert_eq!(core.approve_connection(&conn, AllowedProjects::All, Some(&"guess".into())).await.unwrap_err().code, "LOCKED");
    assert!(!core.is_unlocked(), "too many misses lock the app");
    core.shutdown().await;
}

#[tokio::test]
async fn native_messaging_rules() {
    let dir = tempfile::tempdir().unwrap();
    let core = new_core(dir.path(), Arc::new(RecordingSink::default())).await;
    create(&core, dir.path()).await;
    let id = add_login(&core, "Shop", "https://shop.example.com", "pw-shop-123").await;

    let hello = core.handle_nm(&req("a1", "hello", json!({"extension_version": "0.1.0"}))).await;
    assert_eq!(hello, json!({"id": "a1", "ok": true, "app_version": "0.1.0-test", "locked": false, "ai_mode_available": false}));

    let m = core.handle_nm(&req("a2", "match", json!({"origin": "https://shop.example.com", "url": "https://shop.example.com/login"}))).await;
    assert_eq!(m["ok"], true);
    assert_eq!(m["candidates"][0]["entry_id"], id);
    assert_eq!(m["candidates"][0]["match"], "exact_origin");
    assert!(!m.to_string().contains("pw-shop-123"));

    // http origin never gets the https entry.
    let m = core.handle_nm(&req("a3", "match", json!({"origin": "http://shop.example.com", "url": "http://shop.example.com/"}))).await;
    assert_eq!(m["candidates"].as_array().unwrap().len(), 0);

    // Fill: wrong frame origin → ORIGIN_MISMATCH; no gesture → refused; right origin → ok.
    let f = core.handle_nm(&req("a4", "fill", json!({"entry_id": id, "origin": "https://shop.example.com", "frame_origin": "https://evil.example.net", "user_gesture": true}))).await;
    assert_eq!(f["error"]["code"], "ORIGIN_MISMATCH");
    let f = core.handle_nm(&req("a5", "fill", json!({"entry_id": id, "origin": "https://shop.example.com", "frame_origin": "https://shop.example.com", "user_gesture": false}))).await;
    assert_eq!(f["ok"], false);
    let f = core.handle_nm(&req("a6", "fill", json!({"entry_id": id, "origin": "https://shop.example.com", "frame_origin": "http://shop.example.com", "user_gesture": true}))).await;
    assert_eq!(f["error"]["code"], "ORIGIN_MISMATCH");
    let f = core.handle_nm(&req("a6b", "fill", json!({"entry_id": "ent_01jbz3k6w8a7m2q4t5v9x0y1z9", "origin": "https://shop.example.com", "frame_origin": "https://shop.example.com", "user_gesture": true}))).await;
    assert_eq!(f["error"]["code"], "NOT_FOUND", "unknown entry");
    let f = core.handle_nm(&req("a7", "fill", json!({"entry_id": id, "origin": "https://shop.example.com", "frame_origin": "https://shop.example.com", "user_gesture": true}))).await;
    assert_eq!(f["ok"], true, "{f}");
    assert_eq!(f["password"], "pw-shop-123");
    assert_eq!(f["username"], "alice");

    let g = core.handle_nm(&req("a8", "generate", json!({"origin": "https://shop.example.com", "passwordrules": "minlength: 12; required: digit;", "length": 16}))).await;
    assert_eq!(g["ok"], true);
    assert!(g["password"].as_str().unwrap().len() >= 12);
    let g = core.handle_nm(&req("a9", "generate", json!({"origin": "https://shop.example.com", "length": 4}))).await;
    assert_eq!(g["ok"], false);

    let s = core.handle_nm(&req("b1", "save", json!({"origin": "https://new.example.org", "url": "https://new.example.org/signup", "username": "bob", "password": "n3w-Pass-w0rd", "form_kind": "signup"}))).await;
    assert_eq!(s["ok"], true, "{s}");
    assert!(matches!(s["status"].as_str(), Some("saved" | "needs_confirmation")));

    // Locked → LOCKED.
    core.lock_app().await;
    let st = core.handle_nm(&req("b2", "status", json!({}))).await;
    assert_eq!(st["locked"], true);
    let m = core.handle_nm(&req("b3", "match", json!({"origin": "https://shop.example.com", "url": "https://shop.example.com/"}))).await;
    assert_eq!(m["error"]["code"], "LOCKED");

    // Rate limit on fill (20/min).
    core.unlock(PASSWORD.into()).await.unwrap();
    let mut limited = false;
    for i in 0..30 {
        let f = core.handle_nm(&req(&format!("r{i}"), "fill", json!({"entry_id": id, "origin": "https://shop.example.com", "frame_origin": "https://shop.example.com", "user_gesture": true}))).await;
        if f["error"]["code"] == "RATE_LIMITED" {
            limited = true;
            break;
        }
    }
    assert!(limited);
    core.shutdown().await;
}

#[cfg(unix)]
#[tokio::test]
async fn ipc_requires_token_and_extension_origin() {
    use aipass_nm::frame::{read_frame, write_frame};
    // Keep the socket path short (macOS limits sun_path to 104 bytes).
    let dir = tempfile::Builder::new().prefix("apd").tempdir_in("/tmp").unwrap();
    let core = new_core(dir.path(), Arc::new(RecordingSink::default())).await;
    let token = tokio_util::sync::CancellationToken::new();
    let server = tokio::spawn(aipass_desktop_lib::nm_server::serve_ipc(core.clone(), token.clone()));
    let home = core.paths().home().to_path_buf();
    let sock = aipass_nm::ipc::socket_path(&home);
    for _ in 0..100 {
        if sock.exists() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(std::fs::metadata(&sock).unwrap().permissions().mode() & 0o777, 0o600);
    assert_eq!(std::fs::metadata(aipass_nm::ipc::token_path(&home)).unwrap().permissions().mode() & 0o777, 0o600);
    let good = aipass_nm::ipc::read_token(&home).unwrap();
    let origin = format!("chrome-extension://{}/", "c".repeat(32));

    // Wrong token.
    let mut s = aipass_nm::ipc::connect(&home).await.unwrap();
    let r = aipass_nm::ipc::client_handshake(&mut s, &"0".repeat(64), &origin).await;
    assert!(matches!(r, Err(aipass_nm::ipc::HandshakeError::Refused(c)) if c == "NOT_PAIRED"));
    // Not an extension origin.
    let mut s = aipass_nm::ipc::connect(&home).await.unwrap();
    assert!(aipass_nm::ipc::client_handshake(&mut s, &good, "https://evil.example").await.is_err());
    // Good handshake, then a forwarded request.
    let mut s = aipass_nm::ipc::connect(&home).await.unwrap();
    aipass_nm::ipc::client_handshake(&mut s, &good, &origin).await.unwrap();
    write_frame(&mut s, br#"{"id":"0123456789abcdef0123456789abcdef","type":"hello","extension_version":"0.1.0"}"#).await.unwrap();
    let reply: Value = serde_json::from_slice(&read_frame(&mut s).await.unwrap().unwrap()).unwrap();
    assert_eq!(reply["ok"], true);
    assert_eq!(reply["locked"], true, "no vault yet → locked");
    assert_eq!(reply["ai_mode_available"], false);

    // Allow-list in settings restricts origins.
    let mut st = core.settings();
    st.allowed_extension_origins = vec![format!("chrome-extension://{}/", "d".repeat(32))];
    core.update_settings(st).unwrap();
    let mut s = aipass_nm::ipc::connect(&home).await.unwrap();
    assert!(aipass_nm::ipc::client_handshake(&mut s, &good, &origin).await.is_err());

    // The real aipass-nm-host binary, driven with Chrome framing on stdin/stdout.
    let mut st = core.settings();
    st.allowed_extension_origins = vec![];
    core.update_settings(st).unwrap();
    let host_bin = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("target/debug/aipass-nm-host");
    assert!(host_bin.is_file(), "build it first: cargo build -p aipass-nm-host");
    let mut child = tokio::process::Command::new(&host_bin)
        .arg(&origin)
        .env("AIPASS_HOME", &home)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = child.stdout.take().unwrap();
    write_frame(&mut stdin, br#"{"id":"abcdefabcdefabcdefabcdefabcdefab","type":"status"}"#).await.unwrap();
    let reply: Value = serde_json::from_slice(&read_frame(&mut stdout).await.unwrap().unwrap()).unwrap();
    assert_eq!(reply, json!({"id":"abcdefabcdefabcdefabcdefabcdefab","ok":true,"locked":true}));
    write_frame(&mut stdin, br#"{"id":"x2","type":"match","origin":"https://a.example","url":"https://a.example/"}"#).await.unwrap();
    let reply: Value = serde_json::from_slice(&read_frame(&mut stdout).await.unwrap().unwrap()).unwrap();
    assert_eq!(reply["error"]["code"], "LOCKED");
    drop(stdin);
    assert!(child.wait().await.unwrap().success());

    token.cancel();
    let _ = server.await;

    // With the desktop app gone the host answers itself instead of hanging: `hello` /
    // `status` report locked (so the extension can still offer open_app), the rest LOCKED.
    let mut child = tokio::process::Command::new(&host_bin)
        .arg(&origin)
        .env("AIPASS_HOME", &home)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = child.stdout.take().unwrap();
    write_frame(&mut stdin, br#"{"id":"x3","type":"hello","extension_version":"0.1.0"}"#).await.unwrap();
    let reply: Value = serde_json::from_slice(&read_frame(&mut stdout).await.unwrap().unwrap()).unwrap();
    assert_eq!(reply["ok"], true, "{reply}");
    assert_eq!(reply["locked"], true);
    assert_eq!(reply["ai_mode_available"], false);
    write_frame(&mut stdin, br#"{"id":"x4","type":"fill","entry_id":"ent_x","origin":"https://a.example","frame_origin":"https://a.example","user_gesture":true}"#).await.unwrap();
    let reply: Value = serde_json::from_slice(&read_frame(&mut stdout).await.unwrap().unwrap()).unwrap();
    assert_eq!(reply["error"]["code"], "LOCKED");
    write_frame(&mut stdin, br#"{"id":"x5","type":"lock"}"#).await.unwrap();
    let reply: Value = serde_json::from_slice(&read_frame(&mut stdout).await.unwrap().unwrap()).unwrap();
    assert_eq!(reply["error"]["code"], "LOCKED", "a lock is never reported done without the app");
    drop(stdin);
    let _ = child.wait().await;
}

#[tokio::test]
async fn approval_flow_through_embedded_broker_and_real_executor() {
    let dir = tempfile::tempdir().unwrap();
    let sink = Arc::new(RecordingSink::default());
    let core = new_core(dir.path(), sink.clone()).await;
    create(&core, dir.path()).await;
    let key_entry = {
        let form = serde_json::from_value(json!({"kind": "api_key", "title": "Lure API", "secret": "sk-test-ABCDEF0123456789", "urls": [], "tags": []})).unwrap();
        core.save_item(form).await.unwrap()
    };
    let project = core.create_project("路亚站").await.unwrap();
    let project_id = project["project_id"].as_str().unwrap().to_owned();
    let form = serde_json::from_value(json!({
        "alias": "lure-api", "service": "Lure Store API", "connector": "http_api", "project_id": project_id, "environment": "test",
        "config": {
            "base_url": "https://api.lure.example",
            "auth": {"type": "bearer"},
            "operations": {"list_items": {"method": "GET", "path": "/items", "side_effect": "read", "response": {"allowed_fields": ["id", "name"]}}}
        },
        "credential_entry_id": key_entry.to_string(),
    }))
    .unwrap();
    let resource = core.create_resource(form).await.unwrap();

    // Secrets in resource config are refused by the executor's validator.
    let bad = serde_json::from_value(json!({
        "alias": "bad", "service": "x", "connector": "http_api", "project_id": project_id, "environment": "test",
        "config": {"base_url": "https://x.example", "auth": {"type": "bearer"}, "token": "sk-live-123", "operations": {}},
        "credential_entry_id": key_entry.to_string(),
    }))
    .unwrap();
    assert!(core.create_resource(bad).await.is_err());

    let node = core.node().await.unwrap();
    let created = node
        .broker
        .create_connection(
            &Actor::System,
            NewConnection {
                host_type: HostType::Codex,
                display_name: "Codex".into(),
                transport: Transport::Stdio,
                allowed_projects: AllowedProjects::All,
                public_key: None,
            },
        )
        .await
        .unwrap();
    let principal = ConnectionPrincipal::in_process(created.connection.connection_id.clone());
    let access = |reason: &str| AccessRequest {
        resource_id: resource.resource_id.clone(),
        operations: vec!["http_api.call".into()],
        scope: Some(serde_json::from_value(json!({"operations": ["http_api.call"], "http_api": {"operations": ["list_items"]}})).unwrap()),
        limits: None,
        duration_seconds: Some(900),
        reason: Some(reason.into()),
    };
    let r = node.broker.request_access(&principal, access("weekly report")).await.unwrap();
    let apr = r.approval_request_id.clone();

    // The UI saw the request as a broker event, and it carries no secret.
    let events = sink.events.lock().unwrap().clone();
    let ev = events.iter().find(|(e, p)| e == "broker-event" && p["type"] == "approval_requested").expect("approval event");
    assert!(!ev.1.to_string().contains("sk-test-ABCDEF"));
    let pending = core.list_approvals().await.unwrap();
    assert_eq!(pending["approvals"].as_array().unwrap().len(), 1);
    // the UI keeps the digest of the request it displays and passes it back
    let shown = pending["approvals"][0]["request_digest"].as_str().unwrap().to_owned();
    assert_eq!(shown, aipass_types::approval::request_digest(&node.broker.get_approval(&apr).await.unwrap()).unwrap());

    // CLI-01: an unlocked vault alone is not enough to approve. A click without fresh
    // presence (no password) is refused with REAUTH_REQUIRED, a wrong password is refused,
    // a recent reveal/export re-auth window does not count, and no decision reaches the
    // broker in any of these cases.
    assert_eq!(core.approve(&apr, &shown, None, None).await.unwrap_err().code, "REAUTH_REQUIRED");
    assert_eq!(core.approve(&apr, &shown, None, Some(&"".into())).await.unwrap_err().code, "REAUTH_REQUIRED");
    assert_eq!(core.approve(&apr, &shown, None, Some(&"wrong password".into())).await.unwrap_err().code, "UNAUTHENTICATED");
    core.reauth(PASSWORD.into()).unwrap();
    assert_eq!(core.approve(&apr, &shown, None, None).await.unwrap_err().code, "REAUTH_REQUIRED");
    // a digest that is not the displayed request's is refused before anything is signed
    assert_eq!(core.approve(&apr, "AAAA", None, Some(&PASSWORD.into())).await.unwrap_err().code, "INTEGRITY_FAILED");
    assert_eq!(core.deny(&apr, "AAAA").await.unwrap_err().code, "INTEGRITY_FAILED");
    let still = node.broker.get_access_request(&principal, &apr).await.unwrap();
    assert!(still.grant_id.is_none(), "no decision reached the broker");
    assert_eq!(core.list_approvals().await.unwrap()["approvals"].as_array().unwrap().len(), 1);

    // Approve on the desktop: vault signs + seals the credential to the embedded executor.
    let decision = core.approve(&apr, &shown, None, Some(&PASSWORD.into())).await.unwrap();
    assert!(!decision.to_string().contains("sk-test-ABCDEF"));
    let st = node.broker.get_access_request(&principal, &apr).await.unwrap();
    let grant = st.grant_id.clone().expect("grant created");
    assert!(node.executor.has_credential(grant.as_str()), "credential installed in the executor");
    let grants = core.list_grants().await.unwrap();
    assert!(!grants.to_string().contains("sk-test-ABCDEF"));

    // Revoke at stop_access: credential wiped, report says what happened.
    let rep = core.revoke_grant(&grant, RevocationLevel::EndSessions).await.unwrap();
    assert!(rep["report"].is_object());
    assert!(!node.executor.has_credential(grant.as_str()));

    // A second request is denied with a signed decision.
    let r2 = node.broker.request_access(&principal, access("again")).await.unwrap();
    let shown2 = aipass_types::approval::request_digest(&node.broker.get_approval(&r2.approval_request_id).await.unwrap()).unwrap();
    core.deny(&r2.approval_request_id, &shown2).await.unwrap();
    let st2 = node.broker.get_access_request(&principal, &r2.approval_request_id).await.unwrap();
    assert!(st2.grant_id.is_none());
    assert_eq!(serde_json::to_value(st2.status).unwrap(), json!("denied"));

    // Approving while locked is refused (no auto-approval).
    let r3 = node.broker.request_access(&principal, access("third")).await;
    if let Ok(r3) = r3 {
        core.lock_app().await;
        assert_eq!(core.approve(&r3.approval_request_id, "x", None, Some(&PASSWORD.into())).await.unwrap_err().code, "LOCKED");
    }

    let audit = core.verify_audit().await.unwrap();
    assert_eq!(audit["valid"], true, "{audit}");
    core.shutdown().await;
}
