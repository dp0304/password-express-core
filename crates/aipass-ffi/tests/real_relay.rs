// SPDX-License-Identifier: Apache-2.0
//! The phone path against a REAL `aipass-node` (in-process: broker + executor + HTTP relay +
//! sync), with the FFI [`AipassCore`] as the phone:
//!
//! 1. the node pairs as an executor with the phone over the node's HTTP relay (`set_relay`);
//! 2. an AI connection (`aipass-client`, host_type sdk) is approved from the phone with a
//!    signed `connection.decision` through the relay;
//! 3. `operations_request` → the broker seals `approval.request` into the phone's mailbox →
//!    `fetch_inbox` → `approve_with_entry` posts `approval.decision` (digest-signed, DB
//!    credential HPKE-sealed to the executor) → the operation succeeds against PostgreSQL;
//! 4. `revoke_grant` through the relay → confirmed `revoke.report`; the next request is not
//!    served by the revoked grant.
//!
//! Needs PostgreSQL 17 binaries (`initdb`, `pg_ctl`, `psql`; Homebrew paths are probed). The
//! test is skipped with a message when they are missing. The temporary cluster is stopped
//! when the test ends (and by a watchdog if the test process dies).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use aipass_client::pairing::{PairingRequest, start_pairing};
use aipass_client::{BrokerClient, BrokerEndpoint};
use aipass_ffi::*;
use aipass_storage::RelayClient;
use aipass_types::models::{Connector, Environment, HostType, OperationRequest, OperationStatus, ResourceInput, Transport};
use aipass_types::pairing::PairingRole;
use aipass_types::vault::{DevicePublic, MemberRole, Platform};
use aipass_vault::pairing::NewDeviceSession;

const VIEW: &str = "analytics.subscription_daily";

#[derive(Default)]
struct MemStore {
    items: Mutex<HashMap<String, (Vec<u8>, bool)>>,
}

impl SecretStore for MemStore {
    fn get(&self, key: String) -> Result<Option<Vec<u8>>, SecretStoreError> {
        Ok(self.items.lock().unwrap().get(&key).map(|v| v.0.clone()))
    }
    fn set(&self, key: String, value: Vec<u8>, upr: bool) -> Result<(), SecretStoreError> {
        self.items.lock().unwrap().insert(key, (value, upr));
        Ok(())
    }
    fn delete(&self, key: String) -> Result<(), SecretStoreError> {
        self.items.lock().unwrap().remove(&key);
        Ok(())
    }
}

// ---------------------------------------------------------------------------------------
// temporary PostgreSQL with the lure-store demo schema
// ---------------------------------------------------------------------------------------

fn pg_bin() -> Option<PathBuf> {
    let mut dirs: Vec<PathBuf> = std::env::var_os("PATH").map(|p| std::env::split_paths(&p).collect()).unwrap_or_default();
    for d in ["/opt/homebrew/opt/postgresql@17/bin", "/usr/local/opt/postgresql@17/bin", "/usr/lib/postgresql/17/bin"] {
        dirs.push(d.into());
    }
    dirs.into_iter().find(|d| ["initdb", "pg_ctl", "psql"].iter().all(|t| d.join(t).exists()))
}

struct TempPg {
    bin: PathBuf,
    data: PathBuf,
    sock: tempfile::TempDir,
    port: u16,
    _dir: tempfile::TempDir,
}

impl TempPg {
    fn start(ro_password: &str) -> Option<Self> {
        let bin = pg_bin()?;
        let dir = tempfile::tempdir().expect("tmp");
        let sock = tempfile::Builder::new().prefix("aipg").tempdir_in("/tmp").expect("sock dir");
        let data = dir.path().join("data");
        let port = free_port();
        let pw = dir.path().join("super.pw");
        std::fs::write(&pw, aipass_crypto::rng::random_token("pg_", 16).unwrap().expose()).unwrap();
        let st = Command::new(bin.join("initdb"))
            .env("LC_ALL", "C")
            .env("LANG", "C")
            .args(["-D", data.to_str().unwrap(), "-U", "postgres", "--auth-local=trust", "--auth-host=scram-sha-256", "-E", "UTF8", "--locale=C"])
            .arg(format!("--pwfile={}", pw.display()))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("initdb");
        assert!(st.success(), "initdb failed");
        let st = Command::new(bin.join("pg_ctl"))
            .env("LC_ALL", "C")
            .env("LANG", "C")
            .args(["-D", data.to_str().unwrap(), "-l", dir.path().join("pg.log").to_str().unwrap(), "-w", "-t", "30", "start", "-o"])
            .arg(format!("-p {port} -k {} -c listen_addresses=127.0.0.1", sock.path().display()))
            .stdout(Stdio::null())
            .status()
            .expect("pg_ctl start");
        assert!(st.success(), "pg_ctl start failed: {}", std::fs::read_to_string(dir.path().join("pg.log")).unwrap_or_default());
        // watchdog: stop the cluster even if this test process is killed
        let _ = Command::new("sh")
            .arg("-c")
            .arg(format!(
                "while kill -0 {pid} 2>/dev/null; do sleep 1; done; '{pg_ctl}' -D '{data}' -m immediate stop >/dev/null 2>&1",
                pid = std::process::id(),
                pg_ctl = bin.join("pg_ctl").display(),
                data = data.display()
            ))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn();
        let pg = TempPg { bin, data, sock, port, _dir: dir };
        pg.psql("postgres", Some("CREATE DATABASE lure"), None);
        let schema = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deploy/examples/lure-store/schema.sql");
        pg.psql("lure", None, Some(&std::fs::read_to_string(schema).expect("lure-store schema")));
        // password set over stdin, never on a command line
        pg.psql("lure", None, Some(&format!("ALTER ROLE lure_readonly PASSWORD '{ro_password}';\n")));
        Some(pg)
    }

    fn psql(&self, db: &str, cmd: Option<&str>, stdin: Option<&str>) {
        use std::io::Write as _;
        let mut c = Command::new(self.bin.join("psql"));
        c.args(["-h", self.sock.path().to_str().unwrap(), "-p", &self.port.to_string(), "-U", "postgres", "-v", "ON_ERROR_STOP=1", "-q", "-d", db]);
        if let Some(cmd) = cmd {
            c.args(["-c", cmd]);
        }
        let mut ch = c.stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::piped()).spawn().expect("psql");
        if let Some(input) = stdin {
            ch.stdin.as_mut().unwrap().write_all(input.as_bytes()).unwrap();
        }
        drop(ch.stdin.take());
        let out = ch.wait_with_output().unwrap();
        assert!(out.status.success(), "psql failed: {}", String::from_utf8_lossy(&out.stderr));
    }
}

impl Drop for TempPg {
    fn drop(&mut self) {
        let _ = Command::new(self.bin.join("pg_ctl"))
            .args(["-D", self.data.to_str().unwrap(), "-m", "immediate", "-w", "stop"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

// ---------------------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------------------

async fn eventually<T, F, Fut>(what: &str, secs: u64, mut f: F) -> T
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Option<T>>,
{
    let deadline = Instant::now() + Duration::from_secs(secs);
    loop {
        if let Some(t) = f().await {
            return t;
        }
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

fn db_item(port: u16, password: &str) -> ItemInputFfi {
    ItemInputFfi {
        entry_id: None,
        kind: "database".into(),
        title: "Lure store DB".into(),
        username: Some("lure_readonly".into()),
        secret: Some(password.into()),
        clear_secret: false,
        urls: vec![],
        notes: None,
        totp: None,
        clear_totp: false,
        fields: vec![],
        database: Some(DatabaseInfoFfi {
            engine: "postgres".into(),
            host: "127.0.0.1".into(),
            port,
            dbname: "lure".into(),
            sslmode: "disable".into(),
        }),
        project_id: None,
        tags: vec![],
        lifecycle: None,
        password_rules: None,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn phone_approves_and_revokes_through_the_real_node_relay() {
    let db_password = aipass_crypto::rng::random_token("ffi-", 18).unwrap().expose().to_owned();
    let Some(pg) = TempPg::start(&db_password) else {
        eprintln!("SKIPPED: PostgreSQL 17 binaries (initdb, pg_ctl, psql) not found");
        return;
    };
    let tmp = tempfile::tempdir().unwrap();

    // ---- the real node -------------------------------------------------------------
    let mut cfg = aipass_node::NodeConfig::new("ffi-relay-node", tmp.path().join("node"));
    cfg.node.listen = "127.0.0.1:0".into();
    let node = aipass_node::start(cfg.clone(), aipass_node::StartOptions::default()).await.expect("node start");
    let base = format!("http://{}", node.local_addr.expect("tcp"));
    let admin = aipass_node::pair::admin_client(&cfg, Some(&base)).expect("admin client");

    // ---- the phone: FFI core with the node's HTTP relay ----------------------------
    let phone = AipassCore::new(tmp.path().join("phone").to_string_lossy().into_owned(), Arc::new(MemStore::default()), "ios".into(), "0.1.0-test".into()).unwrap();
    let created = phone
        .create_vault("Phone".into(), StorageProfileFfi { kind: "local".into(), path: Some(tmp.path().join("storage").to_string_lossy().into_owned()), ..Default::default() }, None)
        .await
        .unwrap();
    phone.set_relay(base.clone()).unwrap();
    assert!(phone.status().relay_configured);
    let entry = phone.save_item(db_item(pg.port, &db_password)).await.unwrap();

    // ---- 1. executor pairing over the node's relay (what `aipass-node pair` does) ---
    let ident = aipass_node::NodeIdentity::load_or_create(&cfg.node.data_dir).unwrap();
    let pk = ident.identity.public();
    let node_dev = DevicePublic {
        device_id: ident.member_device_id(),
        name: cfg.node.name.clone(),
        platform: Platform::Node,
        role: MemberRole::Executor,
        sign_pk: pk.sign_pk,
        kem_pk: pk.kem_pk,
    };
    let mut ns = NewDeviceSession::start(node_dev, (*ident.identity).clone(), PairingRole::Executor, &base).unwrap();
    let offer = ns.offer().clone();
    let node_relay = RelayClient::for_pairing(url::Url::parse(&offer.relay).unwrap(), offer.secret).unwrap();
    let scan = phone.pairing_scan(ns.qr_payload()).await.unwrap();
    assert_eq!(scan.peer_role().await.as_deref(), Some("executor"));
    let (hello, prog) = tokio::join!(ns.wait_for_hello(&node_relay, Duration::from_secs(30)), scan.wait(30));
    let (hello, prog) = (hello.unwrap(), prog.unwrap());
    assert_eq!(prog.stage, "confirm_code");
    assert_eq!(prog.sas.as_deref(), Some(hello.sas.as_str()), "both sides show the same SAS");
    let (done, welcome) = tokio::join!(scan.confirm_code(hello.sas.clone()), async {
        // the welcome is sent only after the user confirmed on the phone
        ns.wait_for_welcome(&node_relay, Duration::from_secs(30)).await
    });
    assert_eq!(done.unwrap().stage, "completed");
    let welcome = welcome.unwrap();
    assert!(welcome.storage_secret.is_none(), "executors never receive storage secrets");
    for d in welcome.trusted_devices.iter().filter(|d| matches!(d.role, MemberRole::Owner | MemberRole::Member)) {
        admin.admin_add_device(&serde_json::to_value(d).unwrap()).await.expect("register approver");
    }
    assert!(welcome.trusted_devices.iter().any(|d| d.device_id.as_str() == created.device_id));

    // ---- resource: only a reference to the vault entry goes to the broker ----------
    let project = admin.create_project("ffi").await.unwrap();
    let resource = admin
        .admin_create_resource(&ResourceInput {
            alias: "lure-db".into(),
            service: "PostgreSQL".into(),
            connector: Connector::Postgres,
            project_id: project.project_id.clone(),
            environment: Environment::Test,
            config: serde_json::json!({
                "host": "127.0.0.1", "port": pg.port, "dbname": "lure", "sslmode": "disable",
                "allowed_views": { VIEW: { "fields": ["day", "plan", "subscriptions"] } }
            }),
            credential_entry_id: aipass_types::ids::EntryId::parse(&entry).unwrap(),
            executor_id: ident.executor_id.clone(),
            operations: None,
        })
        .await
        .unwrap();

    // ---- 2. AI connection approved from the phone through the relay ----------------
    let ep = BrokerEndpoint::parse(&base).unwrap();
    let anon = BrokerClient::builder(ep).build().unwrap();
    let pending = start_pairing(
        &anon,
        PairingRequest { host_type: HostType::Sdk, display_name: "ffi-agent".into(), transport: Transport::Sdk, record_broker_url: false },
    )
    .await
    .unwrap();
    let conn_id = pending.connection_id().to_string();
    let code = pending.pairing_code().to_owned();
    let req = eventually("connection.pair_request in the phone mailbox", 30, || async {
        phone.fetch_inbox().await.unwrap();
        phone.pending_connections().into_iter().find(|c| c.connection_id == conn_id)
    })
    .await;
    assert_eq!(req.pairing_code, code, "the phone shows the code the agent displays");
    assert_eq!(req.sender_executor_id, ident.executor_id.as_str());
    phone.approve_connection(conn_id.clone(), vec!["*".into()]).await.unwrap();
    let keys = aipass_client::KeyStore::at(tmp.path().join("agent-keys"));
    let outcome = tokio::time::timeout(Duration::from_secs(60), pending.wait(&keys, Duration::from_millis(300))).await.expect("pairing wait").unwrap();
    let key = match outcome {
        aipass_client::pairing::PairingOutcome::Approved { key, .. } => key,
        other => panic!("connection not approved: {other:?}"),
    };
    let ai = anon.with_auth(key.auth());

    // ---- 3. operation → approval.request (sealed) → approve via relay → succeeded --
    let params = serde_json::json!({ "view": VIEW, "fields": ["day", "plan", "subscriptions"], "limit": 5 });
    let op = ai
        .request_operation(&OperationRequest {
            resource_id: resource.resource_id.clone(),
            operation: "postgres.query_view".into(),
            parameters: params.clone(),
            idempotency_key: "ffi-1".into(),
            task_id: None,
        })
        .await
        .unwrap();
    assert_eq!(op.status, OperationStatus::AwaitingApproval);
    let apr = op.approval_request_id.clone().expect("approval request").to_string();
    let card = eventually("approval.request in the phone mailbox", 30, || async {
        phone.fetch_inbox().await.unwrap().into_iter().find(|a| a.approval_request_id == apr)
    })
    .await;
    assert_eq!(card.sender_executor_id, ident.executor_id.as_str());
    assert_eq!(card.environment, "test");
    assert_eq!(card.requested.scope.postgres_views[0].view, VIEW);
    // §7 v2: the card carries the waiting operation and its parameters digest
    assert_eq!(card.kind, "operation");
    assert_eq!(card.operation_id.as_deref(), Some(op.operation_id.as_str()));
    assert!(card.parameters_digest.is_some());
    assert!(!card.conflict);
    let d = phone.approve_with_entry(apr.clone(), card.request_digest.clone(), None, entry.clone()).await.unwrap();
    assert_eq!(d.decision, "approve");
    assert!(d.credential_sealed, "credential HPKE-sealed to the executor");
    let done = eventually("operation to finish", 60, || async {
        let o = ai.get_operation(&op.operation_id).await.unwrap();
        (!matches!(o.status, OperationStatus::AwaitingApproval | OperationStatus::Authorized | OperationStatus::Running | OperationStatus::Received | OperationStatus::PolicyChecked)).then_some(o)
    })
    .await;
    assert_eq!(done.status, OperationStatus::Succeeded, "{done:?}");
    let body = serde_json::to_value(&done).unwrap();
    let rows = body["result"]["data"]["rows"].as_array().cloned().unwrap_or_default();
    assert!(!rows.is_empty());
    for r in &rows {
        let mut k: Vec<_> = r.as_object().unwrap().keys().cloned().collect();
        k.sort();
        assert_eq!(k, ["day", "plan", "subscriptions"]);
    }
    let text = body.to_string();
    assert!(!text.contains(&db_password) && !text.contains("@example.com"), "no credential / customer data in the result");

    // ---- 4. revoke_grant through the relay ------------------------------------------
    let snap = phone.snapshot(None).await.unwrap();
    assert_eq!(snap.executor_id, ident.executor_id.as_str());
    let grant = snap.grants.iter().find(|g| g.connection_id == conn_id && g.status == "active").expect("active grant in the snapshot").grant_id.clone();
    let rep = phone.revoke_grant(grant.clone(), "end_sessions".into()).await.unwrap();
    assert!(rep.confirmed, "the broker answered with revoke.report: {rep:?}");
    let next = ai
        .request_operation(&OperationRequest {
            resource_id: resource.resource_id.clone(),
            operation: "postgres.query_view".into(),
            parameters: serde_json::json!({ "view": VIEW, "fields": ["day", "plan", "subscriptions"], "limit": 3 }),
            idempotency_key: "ffi-2".into(),
            task_id: None,
        })
        .await;
    match next {
        Ok(o) => assert_eq!(o.status, OperationStatus::AwaitingApproval, "the revoked grant must not serve: {o:?}"),
        Err(e) => assert_eq!(e.code(), Some(aipass_types::ErrorCode::GrantRevoked), "{e}"),
    }
    let snap = phone.snapshot(None).await.unwrap();
    assert!(snap.grants.iter().any(|g| g.grant_id == grant && g.status == "revoked"));

    // nothing the phone or agent saw carries the DB password
    assert!(!format!("{snap:?}{card:?}{rep:?}").contains(&db_password));
    node.shutdown().await;
    drop(pg);
}
