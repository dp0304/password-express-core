// SPDX-License-Identifier: Apache-2.0
//! Test-mode desktop core for the native-messaging conformance harness
//! (`clients/browser-extension/test/nativeHostConformance.test.ts`).
//!
//! Usage: `nm_test_core <fresh empty dir>` (keep the path short: macOS limits socket paths
//! to 104 bytes). It creates a throw-away vault (fast test Argon2, local-folder storage)
//! under that directory, seeds **fake** logins — including one with a real sync conflict
//! made by a second paired device — and serves the desktop IPC endpoint
//! `<dir>/home/run/desktop.sock` that the real `aipass-nm-host` connects to.
//!
//! stdout: one JSON line `{"ready":true,"home":…,"entries":{…ids…}}`, then one JSON line
//! per stdin command: `lock`, `unlock`, `stop_ipc`. EOF on stdin shuts down.
//! Entry ids and the fixture values below are the only data ever printed.

#[path = "../tests/common/mod.rs"]
mod common;

use std::sync::Arc;

use aipass_crypto::SecretString;
use aipass_desktop_lib::core::NullSink;
use serde_json::json;
use tokio::io::AsyncBufReadExt;
use tokio_util::sync::CancellationToken;

#[tokio::main]
async fn main() {
    let Some(root) = std::env::args().nth(1).map(std::path::PathBuf::from) else {
        eprintln!("usage: nm_test_core <fresh empty dir>");
        std::process::exit(2);
    };
    if std::fs::read_dir(&root).map(|mut d| d.next().is_some()).unwrap_or(false) {
        eprintln!("nm_test_core: {} must be empty (it holds a throw-away test vault)", root.display());
        std::process::exit(2);
    }
    let home = root.join("home");
    let core = common::open_core(&home, false, Arc::new(NullSink));
    common::create_vault(&core, &root.join("storage")).await;

    // Fake fixtures only (the harness knows these values to check where they appear).
    let shop = common::add_login(&core, "Shop", "https://shop.example.com", Some("alice"), "FAKE-shop-pw-1", Some("JBSWY3DPEHPK3PXP")).await;
    let related = common::add_login(&core, "Accounts", "https://accounts.example.com", Some("alice2"), "FAKE-accounts-pw", None).await;
    let nouser = common::add_login(&core, "No user", "https://nouser.example.com", None, "FAKE-nouser-pw", None).await;
    let legacy = common::add_login(&core, "Legacy", "http://legacy.example.net", Some("leo"), "FAKE-legacy-pw", None).await;
    let dup_a = common::add_login(&core, "Dup A", "https://dup.example.com", Some("dana"), "FAKE-dup-a", None).await;
    let dup_b = common::add_login(&core, "Dup B", "https://dup.example.com", Some("dana"), "FAKE-dup-b", None).await;
    let conflicted = common::add_login(&core, "Conflicted", "https://conflict.example.org", Some("carol"), "FAKE-conflict-base", None).await;
    let phone_dir = root.join("phone");
    std::fs::create_dir_all(&phone_dir).unwrap();
    let phone = common::join_phone(&core, &phone_dir).await;
    common::make_conflict(&core, &phone, &conflicted, "Conflicted", "https://conflict.example.org", "carol").await;

    let mut ipc = Some(start_ipc(&core));
    for _ in 0..200 {
        if core.paths().desktop_socket().exists() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    println!(
        "{}",
        json!({
            "ready": true,
            "home": home.display().to_string(),
            "entries": {
                "shop": shop, "related": related, "nouser": nouser, "legacy": legacy,
                "dup_a": dup_a, "dup_b": dup_b, "conflicted": conflicted,
            },
        })
    );

    let mut lines = tokio::io::BufReader::new(tokio::io::stdin()).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        let reply = match line.trim() {
            "lock" => {
                core.lock_app().await;
                json!({"cmd": "lock", "ok": true})
            }
            "unlock" => json!({"cmd": "unlock", "ok": core.unlock(SecretString::from(common::PASSWORD)).await.is_ok()}),
            "stop_ipc" => {
                if let Some((token, task)) = ipc.take() {
                    token.cancel();
                    let _ = task.await;
                }
                json!({"cmd": "stop_ipc", "ok": !core.paths().desktop_socket().exists()})
            }
            other => json!({"cmd": other, "ok": false}),
        };
        println!("{reply}");
    }
    if let Some((token, task)) = ipc.take() {
        token.cancel();
        let _ = task.await;
    }
    core.shutdown().await;
}

fn start_ipc(core: &Arc<aipass_desktop_lib::core::AppCore>) -> (CancellationToken, tokio::task::JoinHandle<()>) {
    let token = CancellationToken::new();
    let task = tokio::spawn({
        let core = core.clone();
        let token = token.clone();
        async move {
            if let Err(e) = aipass_desktop_lib::nm_server::serve_ipc(core, token).await {
                eprintln!("nm_test_core: ipc server stopped: {e}");
            }
        }
    });
    (token, task)
}
