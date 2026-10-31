// SPDX-License-Identifier: Apache-2.0
//! `aipass-mcp pair --configure` and `aipass-mcp doctor` against the mock broker, with a
//! temporary HOME and AIPASS_HOME (nothing outside the temp dirs is touched).

use std::process::Stdio;
use std::time::Duration;

use aipass_client::testing::MockBroker;
use aipass_client::{AipassHome, KeyStore};
use serde_json::Value;
use tokio::io::AsyncReadExt;
use tokio::process::Command;

fn cmd(home: &std::path::Path, aipass_home: &std::path::Path) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_aipass-mcp"));
    c.env("HOME", home)
        .env("AIPASS_HOME", aipass_home)
        .env_remove("CODEX_HOME")
        .env_remove("CLAUDE_CONFIG_DIR")
        .env_remove("AIPASS_BROKER_URL")
        .env("AIPASS_LANG", "en")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    c
}

#[tokio::test]
async fn pair_configure_then_doctor() {
    let mock = MockBroker::new();
    let (addr, server) = mock.serve_tcp().await.unwrap();
    let broker = format!("http://{addr}");
    let home = tempfile::tempdir().unwrap();
    let aph = tempfile::tempdir().unwrap();
    // an existing Codex config with a comment and another server
    let codex_dir = home.path().join(".codex");
    std::fs::create_dir_all(&codex_dir).unwrap();
    let original = "# mine\nmodel = \"gpt-5-codex\"\n\n[mcp_servers.docs]\ncommand = \"npx\"\nargs = [\"docs\"]\n";
    std::fs::write(codex_dir.join("config.toml"), original).unwrap();

    let mut child = cmd(home.path(), aph.path())
        .args(["pair", "--host", "codex", "--name", "Codex on laptop", "--broker", &broker, "--configure"])
        .spawn()
        .unwrap();
    // the "trusted device" approves once the request shows up
    let approved = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            if let Some(c) = mock.pending_pairings().first() {
                assert!(mock.approve_pairing(c));
                return c.clone();
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap();
    let status = tokio::time::timeout(Duration::from_secs(30), child.wait()).await.unwrap().unwrap();
    let mut out = String::new();
    child.stdout.take().unwrap().read_to_string(&mut out).await.unwrap();
    let mut err = String::new();
    child.stderr.take().unwrap().read_to_string(&mut err).await.unwrap();
    assert!(status.success(), "stdout:\n{out}\nstderr:\n{err}");
    assert!(out.contains("Pairing code"), "{out}");
    assert!(out.contains(approved.as_str()));
    assert!(out.contains("+[mcp_servers.aipass]"), "diff shown: {out}");
    assert!(out.contains("Backup:"));
    let key = KeyStore::new(&AipassHome::new(aph.path())).load(&approved).unwrap();
    assert_eq!(key.meta().broker_url.as_deref(), Some(broker.as_str()), "explicit --broker is recorded");
    let cfg = std::fs::read_to_string(codex_dir.join("config.toml")).unwrap();
    assert!(cfg.starts_with(original.trim_end()), "{cfg}");
    assert!(cfg.contains("[mcp_servers.aipass]"));
    assert!(cfg.contains(approved.as_str()));
    assert!(cfg.contains("\"--broker\""));
    assert!(!cfg.contains(&aipass_crypto::b64u::encode(key.public_key())), "no key material in host config");

    // doctor: broker reachable, pairing approved, codex configured
    let o = cmd(home.path(), aph.path()).args(["doctor", "--json", "--no-probe"]).output().await.unwrap();
    let report: Value = serde_json::from_slice(&o.stdout).unwrap_or_else(|_| panic!("{}", String::from_utf8_lossy(&o.stdout)));
    let find = |id: &str| -> Vec<Value> {
        report["checks"].as_array().unwrap().iter().filter(|c| c["id"] == id).cloned().collect()
    };
    assert!(o.status.success(), "{report:#}");
    assert_eq!(find("connection_key")[0]["status"], "ok");
    assert_eq!(find("broker_reachable")[0]["status"], "ok", "{report:#}");
    assert_eq!(find("pairing")[0]["status"], "ok");
    let hc = find("host_config");
    assert!(hc.iter().any(|c| c["status"] == "ok" && c["message"]["en"].as_str().unwrap().contains("Codex")), "{hc:?}");
    let text = String::from_utf8_lossy(&o.stdout).to_string();
    let seed_free = !text.contains("\"seed\"") && !text.contains("aipc_");
    assert!(seed_free);

    // human output, and a failing doctor when the connection is unknown to the broker
    mock.set_connection_status(&approved, aipass_types::models::ConnectionStatus::Removed);
    let o = cmd(home.path(), aph.path()).args(["doctor", "--no-probe"]).output().await.unwrap();
    let human = String::from_utf8_lossy(&o.stdout);
    assert!(!o.status.success());
    assert!(human.contains("[FAIL]") && human.contains("does not recognise this connection"), "{human}");
    server.abort();
}

#[tokio::test]
async fn pair_denied_and_bad_host() {
    let mock = MockBroker::new();
    let (addr, server) = mock.serve_tcp().await.unwrap();
    let home = tempfile::tempdir().unwrap();
    let aph = tempfile::tempdir().unwrap();
    let o = cmd(home.path(), aph.path()).args(["pair", "--host", "nonsense", "--name", "x"]).output().await.unwrap();
    assert_eq!(o.status.code(), Some(2));
    let mut child = cmd(home.path(), aph.path())
        .args(["pair", "--host", "cursor", "--name", "Cursor", "--broker", &format!("http://{addr}")])
        .spawn()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            if let Some(c) = mock.pending_pairings().first() {
                assert!(mock.deny_pairing(c));
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap();
    let status = tokio::time::timeout(Duration::from_secs(30), child.wait()).await.unwrap().unwrap();
    assert!(!status.success());
    assert!(KeyStore::new(&AipassHome::new(aph.path())).list().unwrap().is_empty());
    assert!(!home.path().join(".cursor/mcp.json").exists(), "nothing configured after a denial");
    // doctor without any key fails with guidance
    let o = cmd(home.path(), aph.path()).args(["doctor", "--no-probe", "--broker", &format!("http://{addr}")]).output().await.unwrap();
    assert!(!o.status.success());
    assert!(String::from_utf8_lossy(&o.stdout).contains("aipass-mcp pair"));
    server.abort();
}

#[tokio::test]
async fn http_local_mode_refuses_non_loopback() {
    let home = tempfile::tempdir().unwrap();
    let o = cmd(home.path(), home.path()).args(["http", "--listen", "0.0.0.0:0"]).output().await.unwrap();
    assert_eq!(o.status.code(), Some(2));
    let o = cmd(home.path(), home.path()).args(["http", "--remote", "--listen", "127.0.0.1:0"]).output().await.unwrap();
    assert_eq!(o.status.code(), Some(2), "remote mode needs --public-url");
}
