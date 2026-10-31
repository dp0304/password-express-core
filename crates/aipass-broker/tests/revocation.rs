// SPDX-License-Identifier: Apache-2.0
//! A09 — three-level revocation, latency, post-revoke denial, running-op cancellation,
//! honest reporting.

mod common;

use std::time::{Duration, Instant};

use aipass_broker::{Actor, BrokerConfig};
use aipass_types::error::{ErrorCode, Lang};
use aipass_types::models::{GrantStatus, LevelReport, LevelStatus, OperationStatus, RevocationLevel};
use aipass_types::relay::ControlAction;
use common::*;

async fn approved(h: &Harness) -> aipass_types::ids::GrantId {
    let r = h.broker.request_operation(&h.conn, h.query("seed", &["day"]), Lang::ZhCn).await.unwrap();
    h.approve(r.approval_request_id.as_ref().unwrap()).await.grant_id.unwrap()
}

async fn wait_running(h: &Harness, n: usize) {
    for _ in 0..300 {
        if h.exe.running.load(std::sync::atomic::Ordering::SeqCst) >= n {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("executor never reached {n} running operations");
}

#[tokio::test]
async fn end_sessions_cancels_running_and_blocks_further_use_within_5s() {
    let h = Harness::new().await;
    let grant = approved(&h).await;
    assert!(h.exe.has_cred(grant.as_str()));
    h.exe.set(|b| b.delay = Duration::from_secs(60));
    let b = h.broker.clone();
    let c = h.conn.clone();
    let q = h.query("long", &["day"]);
    let running = tokio::spawn(async move { b.request_operation(&c, q, Lang::ZhCn).await });
    wait_running(&h, 1).await;

    let t = Instant::now();
    let report = h
        .broker
        .revoke_grant(&Actor::Device(h.device_id.clone()), &grant, RevocationLevel::EndSessions)
        .await
        .unwrap();
    let elapsed = t.elapsed();
    assert!(elapsed < Duration::from_secs(5), "revocation took {elapsed:?}");
    assert_eq!(report.stop_access.status, LevelStatus::Done);
    assert_eq!(report.end_sessions.status, LevelStatus::Done, "{report:?}");
    assert_eq!(report.revoke_upstream.status, LevelStatus::NotApplicable);
    assert!(report.fully_revoked());
    assert_eq!(report.summary_label().zh, "全部已收回");
    assert!(report.completed_at.is_some());

    let resp = running.await.unwrap().unwrap();
    assert_eq!(resp.status, OperationStatus::Cancelled);
    assert_eq!(resp.error.unwrap().code, ErrorCode::GrantRevoked);
    assert!(!h.exe.has_cred(grant.as_str()), "credential dropped at the executor");
    assert_eq!(h.exe.end_sessions_calls.lock().unwrap().as_slice(), &[grant.as_str().to_owned()]);

    // post-revoke: the same request is not executed under the revoked grant
    h.exe.set(|b| b.delay = Duration::ZERO);
    let n = h.exe.executions();
    let after = h.broker.request_operation(&h.conn, h.query("after", &["day"]), Lang::ZhCn).await.unwrap();
    assert_eq!(after.status, OperationStatus::AwaitingApproval);
    assert_eq!(h.exe.executions(), n);
    let g = h.broker.get_grant(&grant).await.unwrap();
    assert_eq!(g.status, GrantStatus::Revoked);
    assert!(g.revocation.unwrap().fully_revoked());
}

#[tokio::test]
async fn stop_access_rejects_queued_and_reports_running_honestly() {
    let mut cfg = test_config();
    cfg.executor_concurrency = 1;
    let h = Harness::with_config(cfg).await;
    let grant = approved(&h).await;
    h.exe.set(|b| b.delay = Duration::from_millis(1500));
    let spawn = |key: &str| {
        let b = h.broker.clone();
        let c = h.conn.clone();
        let q = h.query(key, &["day"]);
        tokio::spawn(async move { b.request_operation(&c, q, Lang::ZhCn).await })
    };
    let first = spawn("first");
    wait_running(&h, 1).await;
    let second = spawn("second"); // queued in `authorized` behind the single executor slot
    tokio::time::sleep(Duration::from_millis(100)).await;

    let report = h.broker.revoke_grant(&Actor::Admin, &grant, RevocationLevel::StopAccess).await.unwrap();
    assert_eq!(report.stop_access.status, LevelStatus::Done);
    assert_eq!(report.end_sessions.status, LevelStatus::Pending, "a running operation continues at stop_access: {report:?}");
    assert!(!report.fully_revoked());
    assert_eq!(report.summary_label().zh, "待处理");

    let second = second.await.unwrap().unwrap();
    assert_eq!(second.status, OperationStatus::Cancelled, "queued item rejected: {second:?}");
    assert_eq!(second.error.unwrap().code, ErrorCode::GrantRevoked);
    let first = first.await.unwrap().unwrap();
    // it finished upstream, but the result is withheld because access was stopped
    assert_eq!(first.status, OperationStatus::Cancelled);
    assert!(first.result.is_none());
    // once nothing runs, the credential is dropped
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(!h.exe.has_cred(grant.as_str()));
}

#[tokio::test]
async fn upstream_failure_is_reported_not_hidden() {
    let h = Harness::new().await;
    let grant = approved(&h).await;
    h.exe.set(|b| b.upstream = LevelReport::failed("token revocation rejected by upstream"));
    let report = h.broker.revoke_grant(&Actor::Admin, &grant, RevocationLevel::RevokeUpstream).await.unwrap();
    assert_eq!(report.end_sessions.status, LevelStatus::Done);
    assert_eq!(report.revoke_upstream.status, LevelStatus::Failed);
    assert!(!report.fully_revoked());
    assert_eq!(report.summary_label().zh, "部分撤销失败");
    assert!(report.completed_at.is_none());
    let summary = h.broker.activity_summary(None).await.unwrap();
    assert!(summary.anomalies.iter().any(|a| a.kind == "revocation_incomplete"));
}

#[tokio::test]
async fn slow_executor_is_reported_pending_within_bound() {
    let h = Harness::new().await;
    let grant = approved(&h).await;
    h.exe.set(|b| b.end_sessions_hang = true);
    let t = Instant::now();
    let report = h.broker.revoke_grant(&Actor::Admin, &grant, RevocationLevel::EndSessions).await.unwrap();
    assert!(t.elapsed() < Duration::from_secs(5));
    assert_eq!(report.end_sessions.status, LevelStatus::Pending);
    assert!(!report.fully_revoked());
}

#[tokio::test]
async fn executor_ignoring_cancel_is_still_stopped() {
    let mut cfg = BrokerConfig::in_memory();
    cfg.revoke_step_timeout = Duration::from_millis(1500);
    cfg.cancel_grace = Duration::from_millis(300);
    let h = Harness::with_config(cfg).await;
    let grant = approved(&h).await;
    h.exe.set(|b| {
        b.delay = Duration::from_secs(60);
        b.honor_cancel = false;
    });
    let b = h.broker.clone();
    let c = h.conn.clone();
    let q = h.query("stubborn", &["day"]);
    let running = tokio::spawn(async move { b.request_operation(&c, q, Lang::ZhCn).await });
    wait_running(&h, 1).await;
    let t = Instant::now();
    let report = h.broker.revoke_grant(&Actor::Admin, &grant, RevocationLevel::EndSessions).await.unwrap();
    assert!(t.elapsed() < Duration::from_secs(5));
    assert_eq!(report.end_sessions.status, LevelStatus::Done, "{report:?}");
    let resp = running.await.unwrap().unwrap();
    assert_eq!(resp.status, OperationStatus::Cancelled);
}

#[tokio::test]
async fn revoke_all_and_remove_connection() {
    let h = Harness::new().await;
    let g1 = approved(&h).await;
    let api = h.add_api_resource(aipass_types::models::Environment::Test).await;
    let r = h
        .broker
        .request_operation(
            &h.conn,
            aipass_types::models::OperationRequest {
                resource_id: api.resource_id.clone(),
                operation: "demo.get_status".into(),
                parameters: serde_json::json!({}),
                idempotency_key: "s".into(),
                task_id: None,
            },
            Lang::ZhCn,
        )
        .await
        .unwrap();
    let g2 = h.approve(r.approval_request_id.as_ref().unwrap()).await.grant_id.unwrap();
    let pending = h.broker.request_operation(&h.conn, h.query("pending", &["plan"]), Lang::ZhCn).await.unwrap();
    assert_eq!(pending.status, OperationStatus::AwaitingApproval);

    let out = h
        .broker
        .control_connection(&Actor::Admin, h.conn.connection_id(), ControlAction::RevokeAll)
        .await
        .unwrap();
    assert_eq!(out.reports.len(), 2);
    assert!(out.reports.iter().all(|r| r.fully_revoked()));
    for g in [&g1, &g2] {
        assert_eq!(h.broker.get_grant(g).await.unwrap().status, GrantStatus::Revoked);
    }
    let p = h.broker.get_operation(&h.conn, &pending.operation_id, Lang::ZhCn).await.unwrap();
    assert_eq!(p.status, OperationStatus::Cancelled);

    // remove → the connection can no longer authenticate any call
    h.broker.control_connection(&Actor::Admin, h.conn.connection_id(), ControlAction::Remove).await.unwrap();
    let e = h.broker.list_resources(&h.conn, None, None, Lang::ZhCn).await.unwrap_err();
    assert_eq!(e.code, ErrorCode::IdentityUnverified);
}

#[tokio::test]
async fn revoking_a_device_revokes_what_it_approved() {
    let h = Harness::new().await;
    let grant = approved(&h).await;
    h.broker.revoke_device(&Actor::Admin, &h.device_id).await.unwrap();
    assert_eq!(h.broker.get_grant(&grant).await.unwrap().status, GrantStatus::Revoked);
    // its future decisions are rejected
    let r = h.broker.request_operation(&h.conn, h.query("x", &["plan"]), Lang::ZhCn).await.unwrap();
    let d = h.decision(r.approval_request_id.as_ref().unwrap(), aipass_types::models::Decision::Approve, None).await;
    assert_eq!(h.broker.submit_decision(d).await.unwrap_err().code, ErrorCode::IdentityUnverified);
}

#[tokio::test]
async fn release_by_the_connection() {
    let h = Harness::new().await;
    let grant = approved(&h).await;
    let other = h.new_connection("Other").await;
    assert_eq!(h.broker.release_grant(&other, &grant).await.unwrap_err().code, ErrorCode::NotFound);
    let r = h.broker.release_grant(&h.conn, &grant).await.unwrap();
    assert_eq!(r.status, GrantStatus::Released);
    assert!(!h.exe.has_cred(grant.as_str()));
    let next = h.broker.request_operation(&h.conn, h.query("n", &["day"]), Lang::ZhCn).await.unwrap();
    assert_eq!(next.status, OperationStatus::AwaitingApproval);
}

#[tokio::test]
async fn expired_grants_drop_credentials() {
    let h = Harness::new().await;
    let grant = approved(&h).await;
    h.clock.advance(901);
    let s = h.broker.sweep().await.unwrap();
    assert_eq!(s.grants_expired, 1);
    assert_eq!(h.broker.get_grant(&grant).await.unwrap().status, GrantStatus::Expired);
    assert!(!h.exe.has_cred(grant.as_str()));
    let r = h.broker.request_operation(&h.conn, h.query("late", &["day"]), Lang::ZhCn).await.unwrap();
    assert_eq!(r.status, OperationStatus::AwaitingApproval);
}

/// BRK-02: revoke-all stops access to **every** grant before any executor / upstream call,
/// so a slow upstream revocation of one grant never leaves the next grant usable.
#[tokio::test]
async fn revoke_all_stops_every_grant_before_slow_executor_steps() {
    let h = std::sync::Arc::new(Harness::new().await);
    let mut grants = Vec::new();
    for (key, field) in [("g1", "day"), ("g2", "plan"), ("g3", "subscriptions")] {
        let r = h.broker.request_operation(&h.conn, h.query(key, &[field]), Lang::ZhCn).await.unwrap();
        assert_eq!(r.status, OperationStatus::AwaitingApproval);
        grants.push(h.approve(r.approval_request_id.as_ref().unwrap()).await.grant_id.unwrap());
    }
    // Slow upstream revocation (each one hits the step timeout).
    h.exe.set(|b| b.upstream_delay = Duration::from_secs(2));
    let h2 = h.clone();
    let revoking = tokio::spawn(async move {
        h2.broker
            .control_connection(&Actor::Admin, h2.conn.connection_id(), ControlAction::RevokeAll)
            .await
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    let before = h.exe.executions();
    // A request only the last grant covers must not run under it.
    let r = h.broker.request_operation(&h.conn, h.query("after", &["subscriptions"]), Lang::ZhCn).await.unwrap();
    assert_ne!(r.status, OperationStatus::Succeeded, "grant 3 still usable during revoke-all");
    assert_eq!(h.exe.executions(), before);
    for g in &grants {
        assert_eq!(h.broker.get_grant(g).await.unwrap().status, GrantStatus::Revoked);
    }
    let out = revoking.await.unwrap().unwrap();
    assert_eq!(out.reports.len(), 3);
    for rep in &out.reports {
        assert_eq!(rep.stop_access.status, LevelStatus::Done);
        assert_eq!(rep.revoke_upstream.status, LevelStatus::Pending, "slow upstream reported honestly");
        assert!(rep.completed_at.is_none());
    }
}

/// BRK-07: `stop_access` with nothing running really ends the executor's sessions and
/// drops the credential — and when the executor does not confirm, the report says
/// `pending` instead of "全部已收回".
#[tokio::test]
async fn stop_access_without_running_ops_reports_sessions_honestly() {
    let h = Harness::new().await;
    let grant = approved(&h).await;
    assert!(h.exe.has_cred(grant.as_str()));
    let report = h.broker.revoke_grant(&Actor::Admin, &grant, RevocationLevel::StopAccess).await.unwrap();
    assert_eq!(report.end_sessions.status, LevelStatus::Done, "{report:?}");
    assert!(report.fully_revoked());
    assert!(h.exe.end_sessions_calls.lock().unwrap().contains(&grant.as_str().to_owned()));
    assert!(!h.exe.has_cred(grant.as_str()));

    // an executor that never confirms ending sessions → pending, not fully revoked
    let r = h.broker.request_operation(&h.conn, h.query("other", &["plan"]), Lang::ZhCn).await.unwrap();
    let g2 = h.approve(r.approval_request_id.as_ref().unwrap()).await.grant_id.unwrap();
    h.exe.set(|b| b.end_sessions_hang = true);
    let report = h.broker.revoke_grant(&Actor::Admin, &g2, RevocationLevel::StopAccess).await.unwrap();
    assert_eq!(report.end_sessions.status, LevelStatus::Pending, "{report:?}");
    assert!(!report.fully_revoked());
    assert!(report.completed_at.is_none());
    assert_ne!(report.summary_label().zh, "全部已收回");
}
