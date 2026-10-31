// SPDX-License-Identifier: Apache-2.0
//! The real `aipass-mcp` bridge binary against the desktop's embedded broker on its Unix
//! socket (`<AIPASS_HOME>/run/broker.sock`, found by the bridge's default discovery):
//!
//! 1. `aipass-mcp pair --host codex` → pending connection → the user compares the code and
//!    approves it through `AppCore::approve_connection`;
//! 2. `aipass-mcp stdio` → `resources_list` → `operations_request` (postgres.query_view)
//!    → `approval_required` → approve through `AppCore::approve` (desktop = trusted
//!    device: the vault signs and seals the database credential to the embedded executor)
//!    → `operations_status` → `succeeded` with rows from a real PostgreSQL;
//! 3. revoke the grant (credential + sessions gone, a new request needs a new approval),
//!    then revoke the whole connection (the bridge is refused).
//!
//! PostgreSQL: a throw-away cluster (Homebrew `initdb` / `pg_ctl`) on 127.0.0.1:55451 (or
//! the next free port), always stopped and deleted at the end. Without PostgreSQL the test
//! is skipped unless `AIPASS_REQUIRE_PG=1`.

#![cfg(unix)]

mod common;

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use aipass_desktop_lib::core::NullSink;
use aipass_types::ids::{ApprovalRequestId, ConnectionId, GrantId};
use aipass_types::models::{AllowedProjects, RevocationLevel};
use aipass_types::relay::ControlAction;
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

const DB_PASSWORD: &str = "FAKE-pg-reader-Pw-7731";

// ------------------------------------------------------------------------------------
// throw-away PostgreSQL
// ------------------------------------------------------------------------------------

fn pg_bin(name: &str) -> Option<PathBuf> {
    let mut dirs: Vec<PathBuf> = std::env::var_os("PATH").map(|p| std::env::split_paths(&p).collect()).unwrap_or_default();
    dirs.push("/opt/homebrew/opt/postgresql@17/bin".into());
    dirs.push("/usr/local/opt/postgresql@17/bin".into());
    dirs.into_iter().map(|d| d.join(name)).find(|p| p.is_file())
}

struct TempPg {
    pg_ctl: PathBuf,
    psql: PathBuf,
    data: PathBuf,
    sock: PathBuf,
    port: u16,
}

impl TempPg {
    fn start(root: &Path) -> Option<Self> {
        let (initdb, pg_ctl, psql) = (pg_bin("initdb")?, pg_bin("pg_ctl")?, pg_bin("psql")?);
        let data = root.join("pg");
        let sock = root.join("s");
        std::fs::create_dir_all(&sock).ok()?;
        // A valid C locale: with a non-C LANG the macOS postmaster refuses to start
        // ("postmaster became multithreaded during startup").
        let ok = Command::new(&initdb)
            .env("LC_ALL", "C")
            .args(["-D"])
            .arg(&data)
            .args(["-U", "postgres", "--auth-local=trust", "--auth-host=scram-sha-256", "-E", "UTF8", "--no-locale"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .ok()?
            .success();
        assert!(ok, "initdb failed");
        let port = (55451u16..55470)
            .find(|p| std::net::TcpListener::bind(("127.0.0.1", *p)).is_ok())
            .expect("a free port near 55451");
        let pg = TempPg { pg_ctl, psql, data, sock, port };
        let opts = format!("-p {} -k {} -c listen_addresses=127.0.0.1", pg.port, pg.sock.display());
        let ok = Command::new(&pg.pg_ctl)
            .env("LC_ALL", "C")
            .arg("-D")
            .arg(&pg.data)
            .args(["-o", &opts, "-l"])
            .arg(root.join("pg.log"))
            .args(["-w", "-t", "30", "start"])
            .stdout(Stdio::null())
            .status()
            .expect("pg_ctl start")
            .success();
        assert!(ok, "pg_ctl start failed");
        Some(pg)
    }

    fn sql(&self, db: &str, sql: &str) {
        let out = Command::new(&self.psql)
            .env("LC_ALL", "C")
            .arg("-h")
            .arg(&self.sock)
            .args(["-p", &self.port.to_string(), "-U", "postgres", "-d", db, "-v", "ON_ERROR_STOP=1", "-q", "-c", sql])
            .output()
            .expect("psql");
        assert!(out.status.success(), "psql failed: {}", String::from_utf8_lossy(&out.stderr));
    }
}

impl Drop for TempPg {
    fn drop(&mut self) {
        let _ = Command::new(&self.pg_ctl)
            .env("LC_ALL", "C")
            .arg("-D")
            .arg(&self.data)
            .args(["-m", "immediate", "-w", "stop"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        let _ = std::fs::remove_dir_all(&self.data);
    }
}

// ------------------------------------------------------------------------------------
// the aipass-mcp binary
// ------------------------------------------------------------------------------------

fn mcp_binary() -> PathBuf {
    if let Some(p) = std::env::var_os("AIPASS_MCP_PATH") {
        return PathBuf::from(p);
    }
    let os = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let bin = os.join("target/debug/aipass-mcp");
    if !bin.is_file() {
        let ok = Command::new(env!("CARGO"))
            .args(["build", "-q", "-p", "aipass-mcp", "--manifest-path"])
            .arg(os.join("Cargo.toml"))
            .status()
            .expect("cargo build aipass-mcp")
            .success();
        assert!(ok, "building aipass-mcp failed");
    }
    bin
}

fn bridge_cmd(home: &Path, host_home: &Path, args: &[&str]) -> tokio::process::Command {
    let mut c = tokio::process::Command::new(mcp_binary());
    c.args(args)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", host_home)
        .env("AIPASS_HOME", home)
        .env("AIPASS_LANG", "en")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    c
}

struct Bridge {
    child: tokio::process::Child,
    stdin: tokio::process::ChildStdin,
    lines: tokio::io::Lines<BufReader<tokio::process::ChildStdout>>,
    transcript: String,
}

impl Bridge {
    async fn send(&mut self, v: Value) {
        let mut line = serde_json::to_vec(&v).unwrap();
        line.push(b'\n');
        self.stdin.write_all(&line).await.unwrap();
        self.stdin.flush().await.unwrap();
    }

    async fn response(&mut self, id: Value) -> Value {
        loop {
            let line = tokio::time::timeout(Duration::from_secs(30), self.lines.next_line())
                .await
                .expect("bridge reply in time")
                .unwrap()
                .expect("bridge stdout open");
            self.transcript.push_str(&line);
            let v: Value = serde_json::from_str(&line).expect("stdout carries JSON-RPC only");
            if v.get("id") == Some(&id) {
                return v;
            }
        }
    }

    async fn call(&mut self, id: u64, name: &str, args: Value) -> Value {
        self.send(json!({"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": {"name": name, "arguments": args}})).await;
        self.response(json!(id)).await["result"].clone()
    }
}

fn error_code(result: &Value) -> String {
    let text = result["content"][0]["text"].as_str().unwrap_or("");
    let first = text.split("\n\n").next().unwrap_or("");
    serde_json::from_str::<Value>(first).ok().and_then(|v| v["error"]["code"].as_str().map(str::to_owned)).unwrap_or_default()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_mcp_bridge_pairs_requests_and_is_revoked_through_the_desktop() {
    // Short paths: macOS limits Unix socket paths to 104 bytes.
    let root = tempfile::Builder::new().prefix("apm").tempdir_in("/tmp").unwrap();
    let Some(pg) = TempPg::start(root.path()) else {
        assert!(std::env::var("AIPASS_REQUIRE_PG").as_deref() != Ok("1"), "PostgreSQL (initdb/pg_ctl/psql) not found");
        eprintln!("skipping: PostgreSQL binaries not found");
        return;
    };
    pg.sql("postgres", "CREATE DATABASE lure");
    pg.sql(
        "lure",
        &format!(
            "CREATE SCHEMA analytics;
             CREATE TABLE analytics.subs (day date, plan text, subscriptions int, secret_note text);
             INSERT INTO analytics.subs VALUES ('2026-10-01','pro',12,'internal'),('2026-10-02','basic',30,'internal');
             CREATE VIEW analytics.subscription_daily AS SELECT day, plan, subscriptions FROM analytics.subs;
             CREATE ROLE aipass_reader LOGIN PASSWORD '{DB_PASSWORD}';
             GRANT USAGE ON SCHEMA analytics TO aipass_reader;
             GRANT SELECT ON analytics.subscription_daily TO aipass_reader;"
        ),
    );

    // Desktop core serving the broker socket.
    let home = root.path().join("h");
    let host_home = root.path().join("u");
    std::fs::create_dir_all(&host_home).unwrap();
    let core = common::open_core(&home, true, Arc::new(NullSink));
    common::create_vault(&core, &root.path().join("storage")).await;
    let node = core.node().await.unwrap();
    let sock = node.broker_socket.clone().expect("broker socket served");
    assert_eq!(sock, home.join("run/broker.sock"));
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&sock).unwrap().permissions().mode() & 0o777, 0o600);
    }
    let entry = {
        let form = serde_json::from_value(json!({"kind": "database", "title": "Lure DB (reader)", "username": "aipass_reader", "secret": DB_PASSWORD, "urls": [], "tags": []})).unwrap();
        core.save_item(form).await.unwrap()
    };
    let project = core.create_project("路亚站").await.unwrap();
    let resource = core
        .create_resource(
            serde_json::from_value(json!({
                "alias": "lure-analytics", "service": "Lure analytics DB", "connector": "postgres",
                "project_id": project["project_id"], "environment": "test",
                "config": {"host": "127.0.0.1", "port": pg.port, "dbname": "lure", "sslmode": "disable",
                           "allowed_views": {"analytics.subscription_daily": {"fields": ["day", "plan", "subscriptions"], "date_field": "day"}}},
                "credential_entry_id": entry.to_string(),
            }))
            .unwrap(),
        )
        .await
        .unwrap();

    // 1. Pair the real bridge; the code is compared and approved on the desktop.
    let mut pair = bridge_cmd(&home, &host_home, &["pair", "--host", "codex", "--name", "Codex (test)"]).spawn().unwrap();
    let mut out = BufReader::new(pair.stdout.take().unwrap()).lines();
    let mut code = None;
    while let Some(line) = tokio::time::timeout(Duration::from_secs(30), out.next_line()).await.expect("pair output").unwrap() {
        let t = line.trim();
        if t.len() == 6 && t.bytes().all(|b| b.is_ascii_digit()) {
            code = Some(t.to_owned());
            break;
        }
    }
    let code = code.expect("pairing code printed");
    let conns = core.list_connections().await.unwrap();
    let pending = conns.as_array().unwrap().iter().find(|c| c["pairing"]["code"] == code.as_str()).expect("pending connection with the printed code");
    assert_eq!(pending["status"], "pending");
    let conn_id = ConnectionId::parse(pending["connection_id"].as_str().unwrap()).unwrap();
    core.approve_connection(&conn_id, AllowedProjects::All, Some(&common::PASSWORD.into())).await.unwrap();
    let rest = tokio::time::timeout(Duration::from_secs(30), async {
        let mut s = String::new();
        while let Ok(Some(l)) = out.next_line().await {
            s.push_str(&l);
            s.push('\n');
        }
        s
    })
    .await
    .unwrap();
    let st = tokio::time::timeout(Duration::from_secs(30), pair.wait()).await.unwrap().unwrap();
    assert!(st.success(), "pair exited with {st}: {rest}");
    assert!(rest.contains(conn_id.as_str()), "{rest}");

    // 2. The bridge over stdio.
    let mut child = bridge_cmd(&home, &host_home, &["stdio"]).spawn().unwrap();
    let mut b = Bridge {
        stdin: child.stdin.take().unwrap(),
        lines: BufReader::new(child.stdout.take().unwrap()).lines(),
        child,
        transcript: String::new(),
    };
    b.send(json!({"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {
        "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "Codex", "version": "0.98.0"}}})).await;
    assert_eq!(b.response(json!(0)).await["result"]["protocolVersion"], "2025-06-18");
    b.send(json!({"jsonrpc": "2.0", "method": "notifications/initialized"})).await;

    let res = b.call(1, "resources_list", json!({})).await;
    assert_eq!(res["isError"], false, "{res}");
    let listed = res["structuredContent"]["resources"].as_array().unwrap();
    let r = listed.iter().find(|r| r["resource_id"] == resource.resource_id.as_str()).expect("resource listed");
    assert_eq!(r["status"], "available");
    assert_eq!(r["protection_level"], "compatible");
    assert_eq!(r["executor_status"], "online");

    let params = json!({"view": "analytics.subscription_daily", "fields": ["day", "plan", "subscriptions"], "limit": 10});
    let req = |key: &str| json!({"resource_id": resource.resource_id, "operation": "postgres.query_view", "parameters": params, "idempotency_key": key});
    let res = b.call(2, "operations_request", req("lure-weekly-0001")).await;
    assert_eq!(res["isError"], false, "{res}");
    assert_eq!(res["structuredContent"]["status"], "approval_required");
    let op = res["structuredContent"]["operation_id"].as_str().unwrap().to_owned();
    let apr = ApprovalRequestId::parse(res["structuredContent"]["approval_request_id"].as_str().unwrap()).unwrap();

    // The desktop sees the request (no secret in it) and approves as the trusted device.
    let pending = core.list_approvals().await.unwrap();
    assert!(pending.to_string().contains(apr.as_str()));
    assert!(!pending.to_string().contains(DB_PASSWORD));
    let row = pending["approvals"].as_array().unwrap().iter().find(|r| r["approval_request_id"] == apr.as_str()).unwrap();
    // §7 v2: an operation approval names the waiting operation and its parameters digest
    assert_eq!(row["operation_id"], op.as_str());
    assert!(row["parameters_digest"].is_string());
    let shown = row["request_digest"].as_str().unwrap().to_owned();
    let decision = core.approve(&apr, &shown, None, Some(&common::PASSWORD.into())).await.unwrap();
    assert!(!decision.to_string().contains(DB_PASSWORD));

    let mut done = Value::Null;
    for i in 0..60 {
        let res = b.call(10 + i, "operations_status", json!({"operation_id": op})).await;
        let s = res["structuredContent"]["status"].as_str().unwrap_or("").to_owned();
        if matches!(s.as_str(), "succeeded" | "failed" | "unknown" | "denied" | "expired" | "cancelled") {
            done = res;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert_eq!(done["structuredContent"]["status"], "succeeded", "{done}");
    let result = &done["structuredContent"]["result"];
    assert_eq!(result["rows"], 2, "{done}");
    assert_eq!(result["restricted"], false);
    let rows = result["data"]["rows"].as_array().unwrap_or_else(|| panic!("rows: {done}")).clone();
    assert_eq!(rows.len(), 2, "{done}");
    assert!(rows.iter().any(|r| r["plan"] == "pro" && r["subscriptions"] == 12));
    assert!(!done.to_string().contains("secret_note") && !done.to_string().contains("internal"));

    // 3a. Revoke the grant (end sessions): credential and PostgreSQL sessions are gone and
    //     the same request needs a fresh approval.
    let grants = core.list_grants().await.unwrap();
    let grant = grants["grants"]
        .as_array()
        .and_then(|g| g.iter().find(|g| g["connection_id"] == conn_id.as_str()))
        .map(|g| GrantId::parse(g["grant_id"].as_str().unwrap()).unwrap())
        .expect("grant for the bridge connection");
    assert!(node.executor.has_credential(grant.as_str()));
    let rep = core.revoke_grant(&grant, RevocationLevel::EndSessions).await.unwrap();
    assert!(rep["report"].is_object(), "{rep}");
    assert!(!node.executor.has_credential(grant.as_str()));
    assert_eq!(node.executor.postgres_open_sessions(grant.as_str()), 0);
    let res = b.call(100, "operations_request", req("lure-weekly-0002")).await;
    assert_eq!(res["structuredContent"]["status"], "approval_required", "{res}");

    // 3b. Revoke everything the connection holds, then remove it: the bridge is refused.
    let r = core.control_connection(&conn_id, ControlAction::RevokeAll).await.unwrap();
    assert!(!r.to_string().contains(DB_PASSWORD));
    let grants = core.list_grants().await.unwrap();
    assert!(
        grants["grants"].as_array().unwrap().iter().filter(|g| g["connection_id"] == conn_id.as_str()).all(|g| g["status"] != "active"),
        "{grants}"
    );
    core.control_connection(&conn_id, ControlAction::Remove).await.unwrap();
    let res = b.call(101, "resources_list", json!({})).await;
    assert_eq!(res["isError"], true, "{res}");
    let code = error_code(&res);
    assert!(matches!(code.as_str(), "CONNECTION_REVOKED" | "CONNECTION_REMOVED" | "UNAUTHENTICATED" | "IDENTITY_UNVERIFIED"), "{res}");

    // Nothing the bridge printed ever carried the database password.
    assert!(!b.transcript.contains(DB_PASSWORD));
    drop(b.stdin);
    let _ = tokio::time::timeout(Duration::from_secs(10), b.child.wait()).await;
    let audit = core.verify_audit().await.unwrap();
    assert_eq!(audit["valid"], true, "{audit}");
    core.shutdown().await;
    drop(pg);
}
