// SPDX-License-Identifier: Apache-2.0
//! Connection key files are interchangeable between this crate (`aipass-mcp`, the CLI) and
//! the Python / TypeScript SDKs (CONTRACTS §16.7): one canonical format,
//! `{"format":"aipass-connection-key-1",…}`, plus the legacy Rust layout on read.
//!
//! `tests/fixtures/python-sdk.key` and `tests/fixtures/ts-sdk.key` were written by the SDKs'
//! own `save_connection_key` / `saveConnectionKey` with a fixed dummy test seed (0x07 × 32).

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use aipass_client::keys::{KEY_FILE_FORMAT, load_key_file};
use aipass_client::{ConnectionKey, ConnectionKeyMeta, KeyStore};
use aipass_crypto::Ed25519Keypair;
use aipass_types::ConnectionId;
use aipass_types::models::HostType;

/// Public key of the dummy fixture seed.
const FIXTURE_PK: &str = "6kpsY-KcUgq-9VB7Ey7F-ZVHdq6-vnuSQh7qaRRG0iw";

/// Copy a fixture into a private temp file (git does not keep the 0600 mode).
fn private_copy(dir: &Path, name: &str) -> PathBuf {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures").join(name);
    let dst = dir.join(name);
    std::fs::copy(&src, &dst).expect("copy fixture");
    std::fs::set_permissions(&dst, std::fs::Permissions::from_mode(0o600)).expect("chmod");
    dst
}

#[test]
fn loads_a_key_written_by_the_python_sdk() {
    let dir = tempfile::tempdir().expect("tmp");
    let key = load_key_file(&private_copy(dir.path(), "python-sdk.key")).expect("python sdk key");
    assert_eq!(key.connection_id().as_str(), "conn_01jabcdefghjkmnpqrstvwxyz0");
    assert_eq!(key.public_key_b64u(), FIXTURE_PK);
    assert_eq!(key.meta().host_type, HostType::Sdk);
    assert_eq!(key.meta().display_name, "py-sdk");
    assert_eq!(key.meta().broker_url.as_deref(), Some("http://127.0.0.1:7878"));
}

#[test]
fn loads_a_minimal_key_written_by_the_typescript_sdk() {
    // the TS SDK wrote no host_type / display_name / broker_url: defaults apply
    let dir = tempfile::tempdir().expect("tmp");
    let key = load_key_file(&private_copy(dir.path(), "ts-sdk.key")).expect("ts sdk key");
    assert_eq!(key.connection_id().as_str(), "conn_01jabcdefghjkmnpqrstvwxyz1");
    assert_eq!(key.public_key_b64u(), FIXTURE_PK);
    assert_eq!(key.meta().host_type, HostType::Sdk);
    assert_eq!(key.meta().broker_url, None);
}

#[test]
fn sdk_key_with_a_wrong_public_key_or_loose_mode_is_refused() {
    let dir = tempfile::tempdir().expect("tmp");
    let path = private_copy(dir.path(), "python-sdk.key");
    let text = std::fs::read_to_string(&path).unwrap().replace(FIXTURE_PK, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    std::fs::write(&path, text).unwrap();
    let err = load_key_file(&path).unwrap_err().to_string();
    assert!(err.contains("public key mismatch"), "{err}");

    let path = private_copy(dir.path(), "ts-sdk.key");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(load_key_file(&path).is_err(), "a group/world-readable key must be refused");

    let path = dir.path().join("other.key");
    std::fs::write(&path, r#"{"format":"aipass-connection-key-9","connection_id":"conn_01jabcdefghjkmnpqrstvwxyz1","seed":"BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc"}"#).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let err = load_key_file(&path).unwrap_err().to_string();
    assert!(err.contains("unsupported format"), "{err}");
}

#[test]
fn writes_the_canonical_format_the_sdks_read() {
    let dir = tempfile::tempdir().expect("tmp");
    let store = KeyStore::at(dir.path().join("connections"));
    let id = ConnectionId::parse("conn_01jabcdefghjkmnpqrstvwxyz2").unwrap();
    let meta = ConnectionKeyMeta {
        host_type: HostType::Codex,
        display_name: "Codex".into(),
        broker_url: None,
        created_at: aipass_types::time::now(),
    };
    let key = ConnectionKey::new(id.clone(), Ed25519Keypair::generate(), meta.clone());
    let path = store.save(&key).expect("save");
    let doc: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    // exactly the fields the SDK loaders look for, and no legacy `kind`
    assert_eq!(doc["format"], KEY_FILE_FORMAT);
    assert_eq!(doc["connection_id"], id.as_str());
    assert_eq!(doc["public_key"], key.public_key_b64u());
    assert!(doc["seed"].as_str().is_some_and(|s| s.len() == 43));
    assert_eq!(doc["host_type"], "codex");
    assert_eq!(doc["display_name"], "Codex");
    assert!(doc.get("kind").is_none() && doc.get("broker_url").is_none(), "{doc}");
    // and it round-trips through this loader
    let back = store.load(&id).expect("load");
    assert_eq!(back.public_key_b64u(), key.public_key_b64u());
    assert_eq!(back.meta().host_type, HostType::Codex);
    assert_eq!(back.meta().display_name, "Codex");
}

#[test]
fn still_loads_the_legacy_rust_layout() {
    let dir = tempfile::tempdir().expect("tmp");
    let path = dir.path().join("conn_01jabcdefghjkmnpqrstvwxyz3.key");
    let legacy = format!(
        r#"{{"format":1,"kind":"aipass-connection-key","connection_id":"conn_01jabcdefghjkmnpqrstvwxyz3","public_key":"{FIXTURE_PK}","seed":"BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc","host_type":"cursor","display_name":"Cursor","broker_url":null,"created_at":"2026-10-30T12:00:00Z"}}"#
    );
    std::fs::write(&path, legacy).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let key = load_key_file(&path).expect("legacy key");
    assert_eq!(key.meta().host_type, HostType::Cursor);
    assert_eq!(key.meta().display_name, "Cursor");
    // the legacy layout must still carry its metadata (only SDK files may omit it)
    let partial = format!(
        r#"{{"format":1,"kind":"aipass-connection-key","connection_id":"conn_01jabcdefghjkmnpqrstvwxyz3","public_key":"{FIXTURE_PK}","seed":"BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc"}}"#
    );
    std::fs::write(&path, partial).unwrap();
    assert!(load_key_file(&path).is_err());
}
