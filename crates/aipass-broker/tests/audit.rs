// SPDX-License-Identifier: Apache-2.0
//! Audit hash chain, tamper detection, persistence across restarts, and the "no secrets
//! at rest" property of the broker database (A01 / A18).

mod common;

use std::sync::Arc;
use std::time::Duration;

use aipass_broker::{Broker, ManualClock};
use aipass_types::error::Lang;
use aipass_types::models::OperationStatus;
use common::*;

#[tokio::test]
async fn chain_verifies_and_detects_tampering_on_disk() {
    let h = Harness::persistent().await;
    let r = h.broker.request_operation(&h.conn, h.query("a", &["day"]), Lang::ZhCn).await.unwrap();
    h.approve(r.approval_request_id.as_ref().unwrap()).await;
    h.broker.request_operation(&h.conn, h.query("b", &["day"]), Lang::ZhCn).await.unwrap();
    let v = h.broker.verify_audit().await.unwrap();
    assert!(v.valid);
    assert!(v.events_checked >= 8);
    let page = h.broker.audit_events(0, 3).await.unwrap();
    assert_eq!(page.events.len(), 3);
    assert_eq!(page.head_hash, v.head_hash);
    assert_eq!(page.events[0].prev_hash, "");
    assert_eq!(page.events[1].prev_hash, page.events[0].hash);

    // an attacker with file access rewrites one event
    let path = h.broker.db_path().unwrap().to_path_buf();
    let c = rusqlite::Connection::open(&path).unwrap();
    let body: String = c.query_row("SELECT body FROM audit WHERE seq = 5", [], |r| r.get(0)).unwrap();
    let mut ev: serde_json::Value = serde_json::from_str(&body).unwrap();
    ev["outcome"] = "ok-but-edited".into();
    c.execute("UPDATE audit SET body = ?1 WHERE seq = 5", [ev.to_string()]).unwrap();
    drop(c);
    let v = h.broker.verify_audit().await.unwrap();
    assert!(!v.valid);
}

#[tokio::test]
async fn database_never_contains_the_credential() {
    let h = Harness::persistent().await;
    let r = h.broker.request_operation(&h.conn, h.query("a", &["day"]), Lang::ZhCn).await.unwrap();
    h.approve(r.approval_request_id.as_ref().unwrap()).await;
    for k in ["b", "c"] {
        h.broker.request_operation(&h.conn, h.query(k, &["day", "plan"]), Lang::ZhCn).await.unwrap();
    }
    h.exe.set(|b| b.fail_with = Some(aipass_types::error::ErrorCode::UpstreamError));
    h.broker.request_operation(&h.conn, h.query("d", &["day"]), Lang::ZhCn).await.unwrap();
    let dir = h.broker.db_path().unwrap().parent().unwrap().to_path_buf();
    for entry in std::fs::read_dir(&dir).unwrap() {
        let p = entry.unwrap().path();
        let bytes = std::fs::read(&p).unwrap();
        let text = String::from_utf8_lossy(&bytes);
        assert_no_secret(&text);
    }
    let snapshot = h.broker.state_snapshot().await.unwrap();
    assert_no_secret(&serde_json::to_string(&snapshot).unwrap());
}

#[tokio::test]
async fn audit_records_redacted_parameters_only() {
    let h = Harness::new().await;
    let mut q = h.query("a", &["day"]);
    q.parameters = serde_json::json!({"view": "analytics.subscription_daily", "fields": ["day"], "limit": 2});
    let r = h.broker.request_operation(&h.conn, q, Lang::ZhCn).await.unwrap();
    h.approve(r.approval_request_id.as_ref().unwrap()).await;
    let audit = h.broker.audit_events(0, 1000).await.unwrap();
    let ev = audit.events.iter().find(|e| e.action == "approval.requested").unwrap();
    assert_eq!(ev.detail["parameters"]["view"], "analytics.subscription_daily");
    assert_eq!(ev.detail["parameters"]["limit"], 2);
    assert!(ev.detail["parameters_digest"].as_str().unwrap().len() > 20);
    let done = audit.events.iter().find(|e| e.action == "operation.succeeded").unwrap();
    assert_eq!(done.detail["rows"], 2);
    assert!(done.detail.get("data").is_none());
}

#[tokio::test]
async fn restart_recovers_conservatively_and_keeps_the_chain() {
    let h = Harness::persistent().await;
    let r = h.broker.request_operation(&h.conn, h.query("a", &["day"]), Lang::ZhCn).await.unwrap();
    let apr = r.approval_request_id.clone().unwrap();
    let grant = h.approve(&apr).await.grant_id.unwrap();
    let pending = h.broker.request_operation(&h.conn, h.query("p", &["email"]), Lang::ZhCn).await.unwrap();
    // a run in flight when the process dies
    h.exe.set(|b| b.delay = Duration::from_secs(60));
    let b = h.broker.clone();
    let c = h.conn.clone();
    let q = h.query("inflight", &["day"]);
    let t = tokio::spawn(async move { b.request_operation(&c, q, Lang::ZhCn).await });
    for _ in 0..200 {
        if h.exe.running.load(std::sync::atomic::Ordering::SeqCst) == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    t.abort();
    let cfg = {
        let mut c = test_config();
        c.data_dir = h.broker.config().data_dir.clone();
        c
    };
    // reopen the same database (simulated restart)
    let clock = Arc::new(ManualClock::at_unix(T0));
    let b2 = Broker::open_with_clock(cfg, clock).unwrap();
    let ops = b2.list_operations(10).await.unwrap().operations;
    let inflight = ops.iter().find(|o| o.idempotency_key == "inflight").unwrap();
    assert_eq!(inflight.status, OperationStatus::Unknown);
    let p = ops.iter().find(|o| o.operation_id == pending.operation_id).unwrap();
    assert_eq!(p.status, OperationStatus::AwaitingApproval, "pending approvals survive; they still expire normally");
    let g = b2.get_grant(&grant).await.unwrap();
    assert!(g.usage.rows >= 3);
    assert!(b2.verify_audit().await.unwrap().valid);
    let audit = b2.audit_events(0, 1000).await.unwrap();
    assert!(audit.events.iter().any(|e| e.action == "broker.recovered"));
}
