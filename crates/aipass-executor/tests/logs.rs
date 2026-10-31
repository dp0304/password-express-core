// SPDX-License-Identifier: Apache-2.0
//! Credentials never reach logs (A01 / A18): run operations — including failures whose
//! upstream text and URL contain the key — under a TRACE-level subscriber and search the
//! captured output.

mod support;

use std::io::Write;
use std::sync::{Arc, Mutex};

use aipass_executor::StaticResolver;
use aipass_types::exec::{CredentialAad, ExecutorBackend};
use aipass_types::models::Connector;
use aipass_types::vault::EntryKind;
use aipass_types::{ApprovalRequestId, GrantId};
use serde_json::json;
use support::tls_server::{Hit, Reply, TlsServer};
use support::*;

const SECRET: &str = "log_probe_key_9f8e7d6c5b4a39281706";

#[derive(Clone, Default)]
struct Buf(Arc<Mutex<Vec<u8>>>);

impl Write for Buf {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[tokio::test(flavor = "current_thread")]
async fn credentials_never_logged() {
    let buf = Buf::default();
    let b2 = buf.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_ansi(false)
        .with_writer(move || b2.clone())
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let server = TlsServer::start(
        &["api.test.example"],
        Arc::new(|h: &Hit| {
            if h.target.starts_with("/v1/fail") {
                Reply::json(500, json!({"error": format!("bad key in {}", h.target)}))
            } else {
                Reply::json(
                    200,
                    json!({"data": [{"id": 1, "note": format!("echo {}", h.target)}]}),
                )
            }
        }),
    )
    .await;
    let resolver = Arc::new(StaticResolver::new());
    resolver.set("api.test.example", vec!["127.0.0.1".parse().unwrap()]);
    let exec = Arc::new(
        builder()
            .resolver(resolver)
            .webpki_roots(false)
            .add_root_certificates_pem(&server.pki.ca_pem)
            .unwrap()
            .build()
            .unwrap(),
    );
    let cfg = json!({
        "base_url": format!("https://api.test.example:{}/v1", server.addr.port()),
        "auth": {"type": "query", "name": "api_key"}, "allow_private_network": true,
        "operations": {
            "list": {"method": "GET", "path": "/items", "side_effect": "read", "response": {"items_path": "data", "allowed_fields": ["id", "note"]}},
            "fail": {"method": "GET", "path": "/fail", "side_effect": "read", "response": {"allowed_fields": ["error"]}}
        }
    });
    let r = resource(&exec, Connector::HttpApi, cfg, &["http_api.call"]);
    // Sealed install path.
    let aad = CredentialAad {
        approval_request_id: ApprovalRequestId::generate(),
        digest: "d".into(),
        executor_id: exec.executor_id().clone(),
    };
    let m = material(
        &r,
        EntryKind::ApiKey,
        Some("svc-user-for-logs"),
        SECRET,
        600,
    );
    let sealed =
        aipass_types::exec::seal_credential(&exec.info().kem_pk, &aad.to_bytes().unwrap(), &m)
            .unwrap();
    let g = GrantId::generate();
    exec.install_credential(g.as_str(), &sealed, &aad)
        .await
        .unwrap();

    let ok = run(
        &exec,
        &r,
        &g,
        "http_api.call",
        json!({"operation": "list"}),
        limits(),
    )
    .await;
    assert_no_leak(&ok, SECRET, "echoed URL");
    let fail = run(
        &exec,
        &r,
        &g,
        "http_api.call",
        json!({"operation": "fail"}),
        limits(),
    )
    .await;
    assert!(fail.is_err());
    assert_no_leak(&fail, SECRET, "error");
    exec.end_sessions(g.as_str()).await;
    exec.revoke_upstream(g.as_str()).await;

    let logs = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
    assert!(logs.contains("operation succeeded"), "{logs}");
    assert!(logs.contains("credential installed"), "{logs}");
    assert!(!logs.contains(SECRET), "credential found in logs");
    assert!(
        !logs.contains("svc-user-for-logs"),
        "username found in logs"
    );
}
