// SPDX-License-Identifier: Apache-2.0
//! MNC-05: commands that hand out decryptable secrets are human-only. With
//! `AIPASS_PASSPHRASE` set and stdin not a terminal (an AI agent's shell) they fail
//! before touching the vault, exactly like `item reveal`.

use std::process::{Command, Stdio};

fn aipass(home: &std::path::Path, args: &[&str]) -> std::process::Output {
    aipass_env(home, args, &[])
}

fn aipass_env(home: &std::path::Path, args: &[&str], env: &[(&str, &str)]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_aipass"))
        .args(args)
        .env_remove("AIPASS_UNATTENDED_APPROVALS")
        .envs(env.iter().copied())
        .env("AIPASS_HOME", home)
        .env("AIPASS_PASSPHRASE", "correct horse battery staple")
        .env("AIPASS_EXPORT_PASSWORD", "agent-chosen")
        .env("AIPASS_BROKER_URL", "http://127.0.0.1:9")
        .env("AIPASS_LANG", "en")
        .stdin(Stdio::null())
        .output()
        .expect("run aipass")
}

#[test]
fn export_and_reveal_need_a_human_on_a_terminal() {
    let dir = tempfile::tempdir().expect("tmp");
    let home = dir.path().join("home");

    let csv = dir.path().join("x.csv");
    let enc = dir.path().join("x.aipassx");
    let cases: [(&[&str], &std::path::Path); 3] = [
        (&["export", "--csv", csv.to_str().unwrap(), "--yes"], &csv),
        (&["export", "--encrypted", enc.to_str().unwrap()], &enc),
        (&["item", "reveal", "ent_01jzzzzzzzzzzzzzzzzzzzzzzz"], &csv),
    ];
    for (args, out) in cases {
        // the approvals opt-in never unlocks secret-revealing commands
        let r = aipass_env(&home, args, &[("AIPASS_UNATTENDED_APPROVALS", "1")]);
        let err = String::from_utf8_lossy(&r.stderr);
        assert!(!r.status.success(), "{args:?} must fail without a terminal");
        assert!(err.contains("interactive terminal"), "{args:?}: {err}");
        assert!(!out.exists(), "{args:?} must not write anything");
    }
}

/// Approval-class commands: an AI agent's non-interactive shell with `AIPASS_PASSPHRASE`
/// cannot approve (or deny) its own requests, approve its own connection or add a policy;
/// the refusal happens before any network call.
const APPROVAL_COMMANDS: [&[&str]; 6] = [
    &["approvals", "approve", "apr_01jzzzzzzzzzzzzzzzzzzzzzzz", "--yes"],
    &["approvals", "approve", "apr_01jzzzzzzzzzzzzzzzzzzzzzzz", "--yes", "--via-relay"],
    &["approvals", "deny", "apr_01jzzzzzzzzzzzzzzzzzzzzzzz"],
    &["connections", "approve", "conn_01jzzzzzzzzzzzzzzzzzzzzzzz", "--projects", "*", "--code", "123456"],
    &["connections", "approve", "conn_01jzzzzzzzzzzzzzzzzzzzzzzz", "--projects", "*", "--code", "123456", "--via-relay"],
    &["policy", "add", "--resource", "res_01jzzzzzzzzzzzzzzzzzzzzzzz", "--connection", "conn_01jzzzzzzzzzzzzzzzzzzzzzzz", "--operations", "db.query"],
];

#[test]
fn approvals_need_a_human_on_a_terminal() {
    let dir = tempfile::tempdir().expect("tmp");
    let home = dir.path().join("home");
    for args in APPROVAL_COMMANDS {
        let r = aipass(&home, args);
        let err = String::from_utf8_lossy(&r.stderr);
        assert!(!r.status.success(), "{args:?} must fail without a terminal");
        assert!(err.contains("interactive terminal") && err.contains("AIPASS_UNATTENDED_APPROVALS"), "{args:?}: {err}");
        // nothing else is attempted: no vault was opened or created
        assert!(!home.join("secrets.aipass").exists(), "{args:?}");
    }
}

#[test]
fn unattended_opt_in_must_be_exactly_one() {
    let dir = tempfile::tempdir().expect("tmp");
    let home = dir.path().join("home");
    for v in ["0", "true", "yes", ""] {
        let r = aipass_env(&home, APPROVAL_COMMANDS[0], &[("AIPASS_UNATTENDED_APPROVALS", v)]);
        let err = String::from_utf8_lossy(&r.stderr);
        assert!(err.contains("interactive terminal"), "value {v:?} must not opt in: {err}");
    }
    // with the opt-in the guard is passed (the command then fails later: no vault/broker)
    for args in APPROVAL_COMMANDS {
        let r = aipass_env(&home, args, &[("AIPASS_UNATTENDED_APPROVALS", "1")]);
        let err = String::from_utf8_lossy(&r.stderr);
        assert!(!r.status.success());
        assert!(!err.contains("interactive terminal"), "{args:?}: {err}");
    }
}
