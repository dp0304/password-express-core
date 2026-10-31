// SPDX-License-Identifier: Apache-2.0
//! A13 on the CLI, without a phone: a fresh device recovers the vault from storage with the
//! recovery key alone, joins as a new owner member (nothing is revoked automatically), then
//! revokes the lost device and sees the credentials to rotate.

use std::path::Path;
use std::process::{Command, Output, Stdio};

const PASS: &str = "correct horse battery staple";

fn aipass(home: &Path, args: &[&str], env: &[(&str, &str)]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_aipass"))
        .args(args)
        .env("AIPASS_HOME", home)
        .env("AIPASS_PASSPHRASE", PASS)
        .env("AIPASS_LANG", "en")
        .env_remove("AIPASS_BROKER_URL")
        .envs(env.iter().copied())
        .stdin(Stdio::null())
        .output()
        .expect("run aipass")
}

fn ok(home: &Path, args: &[&str], env: &[(&str, &str)]) -> String {
    let r = aipass(home, args, env);
    assert!(r.status.success(), "{args:?}: {}{}", String::from_utf8_lossy(&r.stdout), String::from_utf8_lossy(&r.stderr));
    String::from_utf8_lossy(&r.stdout).into_owned()
}

#[test]
fn fresh_device_recovers_from_storage_with_the_recovery_key() {
    let dir = tempfile::tempdir().expect("tmp");
    let lost = dir.path().join("lost-phone");
    let fresh = dir.path().join("new-laptop");
    let storage = dir.path().join("storage");
    let kit = dir.path().join("kit.txt");
    let s = storage.to_str().unwrap();

    let out = ok(&lost, &["vault", "init", "--device-name", "lost-phone", "--storage", "local", "--path", s, "--kit-out", kit.to_str().unwrap()], &[]);
    let vault_id = out.lines().find_map(|l| l.strip_prefix("vault_id: ")).expect("vault id").trim().to_owned();
    let lost_dev = out.lines().find_map(|l| l.strip_prefix("device_id: ")).expect("device id").trim().to_owned();
    ok(&lost, &["item", "add", "--kind", "api_key", "--title", "Deploy token", "--secret-env", "TOKEN"], &[("TOKEN", "tok-for-a13-drill")]);
    ok(&lost, &["sync"], &[]);

    // the recovery key is never taken as a command-line value
    let r = aipass(&fresh, &["vault", "recover", "--vault-id", &vault_id, "--storage", "local", "--path", s], &[]);
    assert!(!r.status.success());
    assert!(String::from_utf8_lossy(&r.stderr).contains("--recovery-key-env"), "{}", String::from_utf8_lossy(&r.stderr));
    // a wrong key is refused and leaves no vault behind
    let r = aipass(&fresh, &["vault", "recover", "--vault-id", &vault_id, "--storage", "local", "--path", s, "--recovery-key-env", "RK"], &[("RK", "AIPR-0000-0000")]);
    assert!(!r.status.success(), "a wrong recovery key must fail");
    std::fs::remove_dir_all(&fresh).ok();

    // recover from the kit file (the AIPR-… key inside it)
    let out = ok(&fresh, &["vault", "recover", "--vault-id", &vault_id, "--device-name", "new-laptop", "--storage", "local", "--path", s, "--recovery-key-file", kit.to_str().unwrap()], &[]);
    assert!(out.contains(&vault_id) && out.contains("No device was revoked"), "{out}");
    let items: serde_json::Value = serde_json::from_str(&ok(&fresh, &["--json", "item", "list"], &[])).unwrap();
    assert!(items.as_array().unwrap().iter().any(|i| i["title"] == "Deploy token"), "{items}");

    // nothing revoked automatically: the lost phone is still a member
    let devs: serde_json::Value = serde_json::from_str(&ok(&fresh, &["--json", "device", "list"], &[])).unwrap();
    let lost_row = devs.as_array().unwrap().iter().find(|d| d["device_id"] == lost_dev.as_str()).cloned().expect("lost device listed");
    assert_eq!(lost_row["status"], "active", "{lost_row}");
    assert!(devs.as_array().unwrap().iter().any(|d| d["is_this_device"] == true && d["name"] == "new-laptop" && d["role"] == "owner"), "{devs}");
    assert!(ok(&fresh, &["rotation", "list"], &[]).contains("no credentials to rotate"));

    // the user revokes the lost device → the long-term credential becomes a rotation task
    ok(&fresh, &["device", "revoke", &lost_dev], &[]);
    let tasks: serde_json::Value = serde_json::from_str(&ok(&fresh, &["--json", "rotation", "list"], &[])).unwrap();
    let t = tasks.as_array().unwrap();
    assert!(t.iter().any(|x| x["title"] == "Deploy token"), "{tasks}");
    let entry = t[0]["entry_id"].as_str().unwrap().to_owned();
    ok(&fresh, &["rotation", "done", &entry], &[]);
    let tasks: serde_json::Value = serde_json::from_str(&ok(&fresh, &["--json", "rotation", "list"], &[])).unwrap();
    assert!(tasks.as_array().unwrap().iter().all(|x| x["entry_id"] != entry.as_str()), "{tasks}");
    // and the lost device can no longer read new vault versions
    let r = aipass(&lost, &["sync"], &[]);
    let text = format!("{}{}", String::from_utf8_lossy(&r.stdout), String::from_utf8_lossy(&r.stderr));
    assert!(!r.status.success() || text.to_lowercase().contains("revoked"), "{text}");
}
