// SPDX-License-Identifier: Apache-2.0
//! Operation pipeline and state machine (CONTRACTS §6.2).

mod common;

use std::time::Duration;

use aipass_broker::{Actor, BrokerConfig};
use aipass_types::error::{ErrorCode, Lang};
use aipass_types::models::{
    ApprovalStatus, Decision, Environment, GrantStatus, OperationRequest, OperationStatus,
    SideEffects, APPROVAL_REQUIRED_MESSAGE,
};
use aipass_types::relay::ControlAction;
use common::*;
use serde_json::json;

#[tokio::test]
async fn approval_flow_resumes_and_task_grant_avoids_repeat_prompts() {
    let h = Harness::new().await;
    let r = h
        .broker
        .request_operation(&h.conn, h.query("k1", &["day", "plan", "subscriptions"]), Lang::ZhCn)
        .await
        .unwrap();
    assert_eq!(r.status, OperationStatus::AwaitingApproval);
    assert_eq!(r.http_status(), 202);
    assert_eq!(r.expires_in_seconds, Some(120));
    assert_eq!(r.message.as_deref(), Some(APPROVAL_REQUIRED_MESSAGE));
    let v = serde_json::to_value(&r).unwrap();
    assert_eq!(v["status"], "approval_required");
    let apr = r.approval_request_id.clone().unwrap();

    // The approval request renders the §5.3 fields.
    let req = h.request(&apr).await;
    assert!(req.connection.verified);
    assert_eq!(req.resource.alias, "路亚站测试库");
    assert_eq!(req.requested.operations, vec!["postgres.query_view".to_string()]);
    assert_eq!(req.excluded_fields["analytics.subscription_daily"], vec!["email".to_string()]);
    assert!(req.summary.zh.contains("不含 email"), "{}", req.summary.zh);
    assert!(req.summary.zh.contains("最长 15 分钟"), "{}", req.summary.zh);
    assert!(req.summary.zh.contains("每次最多返回 1,000 行"), "{}", req.summary.zh);
    assert_eq!(req.recipients[0].connection_id, *h.conn.connection_id());

    // Nothing ran before approval; never blocks.
    assert_eq!(h.exe.executions(), 0);
    let d = h.approve(&apr).await;
    assert_eq!(d.status, ApprovalStatus::Approved);
    let grant = d.grant_id.clone().unwrap();
    let op = d.operation.unwrap();
    assert_eq!(op.status, OperationStatus::Succeeded);
    assert!(op.result.is_none(), "the approving device never receives result data");
    assert!(h.exe.has_cred(grant.as_str()));

    // The AI gets the result.
    let got = h.broker.get_operation(&h.conn, &r.operation_id, Lang::ZhCn).await.unwrap();
    assert_eq!(got.status, OperationStatus::Succeeded);
    assert_eq!(got.result.as_ref().unwrap().rows, Some(3));

    // Same read inside the approved task → automatic, no new prompt.
    let again = h
        .broker
        .request_operation(&h.conn, h.query("k2", &["plan", "day"]), Lang::ZhCn)
        .await
        .unwrap();
    assert_eq!(again.status, OperationStatus::Succeeded);
    assert_eq!(again.http_status(), 200);
    assert_eq!(h.exe.executions(), 2);
    let g = h.broker.get_grant(&grant).await.unwrap();
    assert_eq!(g.usage.requests, 2);
    assert_eq!(g.usage.rows, 6);

    // Audit shows the transitions without parameters values or results.
    let audit = h.broker.audit_events(0, 1000).await.unwrap();
    let actions: Vec<&str> = audit.events.iter().map(|e| e.action.as_str()).collect();
    for a in ["approval.requested", "approval.approved", "grant.created", "credential.installed", "operation.authorized", "operation.succeeded"] {
        assert!(actions.contains(&a), "missing audit action {a}: {actions:?}");
    }
    let text = serde_json::to_string(&audit).unwrap();
    assert_no_secret(&text);
    assert!(!text.contains("\"pad\""), "results never enter the audit log");
}

#[tokio::test]
async fn idempotency_replay_and_conflict() {
    let h = Harness::new().await;
    let r1 = h.broker.request_operation(&h.conn, h.query("same", &["day", "plan"]), Lang::ZhCn).await.unwrap();
    // exact replay
    let r2 = h.broker.request_operation(&h.conn, h.query("same", &["day", "plan"]), Lang::ZhCn).await.unwrap();
    assert_eq!(r1.operation_id, r2.operation_id);
    assert_eq!(r1.approval_request_id, r2.approval_request_id);
    // same normalized parameters, different raw order → same operation
    let r3 = h.broker.request_operation(&h.conn, h.query("same", &["plan", "day", "day"]), Lang::ZhCn).await.unwrap();
    assert_eq!(r1.operation_id, r3.operation_id);
    // different parameters → conflict
    let e = h
        .broker
        .request_operation(&h.conn, h.query("same", &["day", "subscriptions"]), Lang::ZhCn)
        .await
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::IdempotencyConflict);
    // only one approval was created
    let pending = h.broker.list_approvals(Some(ApprovalStatus::Pending)).await.unwrap().approvals;
    assert_eq!(pending.len(), 1);

    // after completion the replay returns the stored result without executing again
    h.approve(r1.approval_request_id.as_ref().unwrap()).await;
    let n = h.exe.executions();
    let r4 = h.broker.request_operation(&h.conn, h.query("same", &["day", "plan"]), Lang::ZhCn).await.unwrap();
    assert_eq!(r4.operation_id, r1.operation_id);
    assert_eq!(r4.status, OperationStatus::Succeeded);
    assert_eq!(h.exe.executions(), n);
}

#[tokio::test]
async fn concurrent_idempotent_requests_create_one_operation() {
    let h = Harness::new().await;
    let mut tasks = Vec::new();
    for _ in 0..8 {
        let b = h.broker.clone();
        let c = h.conn.clone();
        let q = h.query("race", &["day"]);
        tasks.push(tokio::spawn(async move { b.request_operation(&c, q, Lang::ZhCn).await }));
    }
    let mut ids = std::collections::BTreeSet::new();
    for t in tasks {
        ids.insert(t.await.unwrap().unwrap().operation_id);
    }
    assert_eq!(ids.len(), 1);
    assert_eq!(h.broker.list_approvals(Some(ApprovalStatus::Pending)).await.unwrap().approvals.len(), 1);
}

#[tokio::test]
async fn deny_then_throttle_then_window_passes() {
    let h = Harness::new().await;
    let r = h.broker.request_operation(&h.conn, h.query("a", &["day"]), Lang::ZhCn).await.unwrap();
    let d = h.deny(r.approval_request_id.as_ref().unwrap()).await;
    assert_eq!(d.status, ApprovalStatus::Denied);
    let op = h.broker.get_operation(&h.conn, &r.operation_id, Lang::En).await.unwrap();
    assert_eq!(op.status, OperationStatus::Denied);
    assert_eq!(op.error.unwrap().code, ErrorCode::ApprovalDenied);
    // same connection + resource + operation within 10 minutes → RATE_LIMITED
    let e = h.broker.request_operation(&h.conn, h.query("b", &["day"]), Lang::ZhCn).await.unwrap_err();
    assert_eq!(e.code, ErrorCode::RateLimited);
    assert_eq!(e.details["reason"], "recently_denied");
    assert_eq!(h.exe.executions(), 0);
    // another connection is not throttled by this denial
    let other = h.new_connection("Cursor").await;
    let r2 = h.broker.request_operation(&other, h.query("b", &["day"]), Lang::ZhCn).await.unwrap();
    assert_eq!(r2.status, OperationStatus::AwaitingApproval);
    // after the window a fresh approval may be requested
    h.clock.advance(601);
    let r3 = h.broker.request_operation(&h.conn, h.query("c", &["day"]), Lang::ZhCn).await.unwrap();
    assert_eq!(r3.status, OperationStatus::AwaitingApproval);
}

#[tokio::test]
async fn more_than_five_pending_approvals_are_rate_limited() {
    let h = Harness::new().await;
    for i in 0..5 {
        let r = h.broker.request_operation(&h.conn, h.query(&format!("p{i}"), &[["day", "plan", "subscriptions", "email", "day"][i]]), Lang::ZhCn).await;
        // fields differ so each is a distinct request; the 5th repeats "day" with a new key
        assert_eq!(r.unwrap().status, OperationStatus::AwaitingApproval);
    }
    let e = h.broker.request_operation(&h.conn, h.query("p6", &["plan", "day"]), Lang::ZhCn).await.unwrap_err();
    assert_eq!(e.code, ErrorCode::RateLimited);
    assert_eq!(e.details["reason"], "too_many_pending_approvals");
}

#[tokio::test]
async fn paused_connection_is_refused_and_resume_restores() {
    let h = Harness::new().await;
    let r = h.broker.request_operation(&h.conn, h.query("a", &["day"]), Lang::ZhCn).await.unwrap();
    h.broker.control_connection(&Actor::Admin, h.conn.connection_id(), ControlAction::Pause).await.unwrap();
    let e = h.broker.request_operation(&h.conn, h.query("b", &["day"]), Lang::ZhCn).await.unwrap_err();
    assert_eq!(e.code, ErrorCode::ConnectionPaused);
    assert_eq!(h.broker.list_resources(&h.conn, None, None, Lang::ZhCn).await.unwrap_err().code, ErrorCode::ConnectionPaused);
    // pending approvals of a paused connection are cancelled
    let a = h.broker.get_approval(r.approval_request_id.as_ref().unwrap()).await.unwrap();
    assert_eq!(a.status, ApprovalStatus::Cancelled);
    // a late approval for it is refused
    let d = h.decision(r.approval_request_id.as_ref().unwrap(), Decision::Approve, None).await;
    assert!(h.broker.submit_decision(d).await.is_err());
    h.broker.control_connection(&Actor::Admin, h.conn.connection_id(), ControlAction::Resume).await.unwrap();
    let r2 = h.broker.request_operation(&h.conn, h.query("c", &["day"]), Lang::ZhCn).await.unwrap();
    assert_eq!(r2.status, OperationStatus::AwaitingApproval);
}

#[tokio::test]
async fn expired_approval_is_never_approved_a10() {
    let h = Harness::new().await;
    let r = h.broker.request_operation(&h.conn, h.query("a", &["day"]), Lang::ZhCn).await.unwrap();
    let apr = r.approval_request_id.clone().unwrap();
    // a decision signed in time but delivered late (phone was locked)
    let late = h.decision(&apr, Decision::Approve, None).await;
    h.clock.advance(119);
    let s = h.broker.get_operation(&h.conn, &r.operation_id, Lang::ZhCn).await.unwrap();
    assert_eq!(s.status, OperationStatus::AwaitingApproval);
    assert_eq!(s.expires_in_seconds, Some(1));
    h.clock.advance(1);
    let report = h.broker.sweep().await.unwrap();
    assert_eq!(report.approvals_expired, 1);
    let s = h.broker.get_operation(&h.conn, &r.operation_id, Lang::ZhCn).await.unwrap();
    assert_eq!(s.status, OperationStatus::Expired);
    assert_eq!(s.error.unwrap().code, ErrorCode::ApprovalExpired);
    let e = h.broker.submit_decision(late).await.unwrap_err();
    assert_eq!(e.code, ErrorCode::ApprovalExpired);
    assert!(h.broker.list_grants(None).await.unwrap().grants.is_empty());
    assert_eq!(h.exe.executions(), 0);
    let a = h.broker.get_approval(&apr).await.unwrap();
    assert_eq!(a.status, ApprovalStatus::Expired);
}

#[tokio::test]
async fn lazy_expiry_without_sweeper() {
    let h = Harness::new().await;
    let r = h.broker.request_operation(&h.conn, h.query("a", &["day"]), Lang::ZhCn).await.unwrap();
    h.clock.advance(500);
    let s = h.broker.get_operation(&h.conn, &r.operation_id, Lang::ZhCn).await.unwrap();
    assert_eq!(s.status, OperationStatus::Expired);
    let late = h.broker.list_approvals(Some(ApprovalStatus::Pending)).await.unwrap();
    assert!(late.approvals.is_empty());
}

#[tokio::test]
async fn cancel_semantics() {
    let h = Harness::new().await;
    // awaiting approval → cancelled, approval cancelled
    let r = h.broker.request_operation(&h.conn, h.query("a", &["day"]), Lang::ZhCn).await.unwrap();
    let c = h.broker.cancel_operation(&h.conn, &r.operation_id, Lang::ZhCn).await.unwrap();
    assert!(c.cancelled);
    assert_eq!(c.status, OperationStatus::Cancelled);
    assert_eq!(c.side_effects, SideEffects::None);
    assert_eq!(h.request(r.approval_request_id.as_ref().unwrap()).await.status, ApprovalStatus::Cancelled);

    // running → cancelled (read op: no side effects)
    let r = h.broker.request_operation(&h.conn, h.query("b", &["day"]), Lang::ZhCn).await.unwrap();
    h.approve(r.approval_request_id.as_ref().unwrap()).await;
    h.exe.set(|b| b.delay = Duration::from_secs(30));
    let b = h.broker.clone();
    let conn = h.conn.clone();
    let q = h.query("c", &["day"]);
    let running = tokio::spawn(async move { b.request_operation(&conn, q, Lang::ZhCn).await });
    let op_id = wait_for_status(&h, OperationStatus::Running).await;
    let started = std::time::Instant::now();
    let c = h.broker.cancel_operation(&h.conn, &op_id, Lang::En).await.unwrap();
    assert!(c.cancelled, "{c:?}");
    assert_eq!(c.side_effects, SideEffects::None);
    assert!(started.elapsed() < Duration::from_secs(3));
    assert!(h.exe.cancels.lock().unwrap().contains(&op_id.as_str().to_owned()));
    let resp = running.await.unwrap().unwrap();
    assert_eq!(resp.status, OperationStatus::Cancelled);

    // terminal → cannot cancel
    h.exe.set(|b| b.delay = Duration::ZERO);
    let done = h.broker.request_operation(&h.conn, h.query("d", &["day"]), Lang::ZhCn).await.unwrap();
    assert_eq!(done.status, OperationStatus::Succeeded);
    let c = h.broker.cancel_operation(&h.conn, &done.operation_id, Lang::ZhCn).await.unwrap();
    assert!(!c.cancelled);
    assert_eq!(c.status, OperationStatus::Succeeded);
}

/// Wait until some operation of the harness connection reaches `status`.
async fn wait_for_status(h: &Harness, status: OperationStatus) -> aipass_types::ids::OperationId {
    for _ in 0..200 {
        let ops = h.broker.list_operations(50).await.unwrap().operations;
        if let Some(op) = ops.iter().find(|o| o.status == status) {
            return op.operation_id.clone();
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("no operation reached {status:?}");
}

#[tokio::test]
async fn unknown_outcome_is_not_retried_for_writes_but_is_for_retry_safe_reads() {
    let h = Harness::new().await;
    let api = h.add_api_resource(Environment::Test).await;
    let write = OperationRequest {
        resource_id: api.resource_id.clone(),
        operation: "demo.create_order".into(),
        parameters: json!({"item": "lure-42"}),
        idempotency_key: "order-1".into(),
        task_id: None,
    };
    let r = h.broker.request_operation(&h.conn, write.clone(), Lang::ZhCn).await.unwrap();
    h.exe.set(|b| b.unknown_times = 1);
    let d = h.approve(r.approval_request_id.as_ref().unwrap()).await;
    let op = d.operation.unwrap();
    assert_eq!(op.status, OperationStatus::Unknown);
    assert_eq!(op.error.as_ref().unwrap().code, ErrorCode::UpstreamOutcomeUnknown);
    assert_eq!(h.exe.executions(), 1, "a write with uncertain outcome is never retried automatically");
    let s = h.broker.get_operation(&h.conn, &r.operation_id, Lang::ZhCn).await.unwrap();
    assert_eq!(s.status, OperationStatus::Unknown);
    assert!(s.message.unwrap().contains("核实"));
    let ops = h.broker.list_operations(10).await.unwrap().operations;
    assert_eq!(ops.iter().find(|o| o.operation_id == r.operation_id).unwrap().side_effects, SideEffects::Possible);
    // replay with the same key returns the unknown op, never re-executes
    let replay = h.broker.request_operation(&h.conn, write, Lang::ZhCn).await.unwrap();
    assert_eq!(replay.status, OperationStatus::Unknown);
    assert_eq!(h.exe.executions(), 1);

    // retry_safe read: one transparent retry
    let read = OperationRequest {
        resource_id: api.resource_id.clone(),
        operation: "demo.get_status".into(),
        parameters: json!({}),
        idempotency_key: "status-1".into(),
        task_id: None,
    };
    let r = h.broker.request_operation(&h.conn, read, Lang::ZhCn).await.unwrap();
    h.exe.set(|b| b.unknown_times = 1);
    let d = h.approve(r.approval_request_id.as_ref().unwrap()).await;
    assert_eq!(d.operation.unwrap().status, OperationStatus::Succeeded);
    assert_eq!(h.exe.executions(), 3);
}

#[tokio::test]
async fn executor_offline_and_control_channel_lost() {
    let h = Harness::new().await;
    // executor offline before anything: no approval is created
    h.exe.online.store(false, std::sync::atomic::Ordering::SeqCst);
    let e = h.broker.request_operation(&h.conn, h.query("a", &["day"]), Lang::ZhCn).await.unwrap_err();
    assert_eq!(e.code, ErrorCode::ExecutorOffline);
    assert!(h.broker.list_approvals(None).await.unwrap().approvals.is_empty());
    let view = h.broker.list_resources(&h.conn, None, None, Lang::ZhCn).await.unwrap();
    assert_eq!(serde_json::to_value(&view.resources[0]).unwrap()["executor_status"], "offline");
    h.exe.online.store(true, std::sync::atomic::Ordering::SeqCst);

    // approved, then the executor goes offline before the run → authorized → failed
    let r = h.broker.request_operation(&h.conn, h.query("b", &["day"]), Lang::ZhCn).await.unwrap();
    let apr = r.approval_request_id.clone().unwrap();
    let d = h.decision(&apr, Decision::Approve, None).await;
    h.exe.online.store(false, std::sync::atomic::Ordering::SeqCst);
    let resp = h.broker.submit_decision(d).await.unwrap();
    let op = resp.operation.unwrap();
    assert_eq!(op.status, OperationStatus::Failed);
    assert_eq!(op.error.unwrap().code, ErrorCode::ExecutorOffline);
    h.exe.online.store(true, std::sync::atomic::Ordering::SeqCst);

    // control channel lost → new operations denied
    h.broker.set_control_channel(&h.exe.id, false).await.unwrap();
    let e = h.broker.request_operation(&h.conn, h.query("c", &["day"]), Lang::ZhCn).await.unwrap_err();
    assert_eq!(e.code, ErrorCode::ControlChannelLost);
    assert!(!h.broker.health().executor_online);
    h.broker.set_control_channel(&h.exe.id, true).await.unwrap();
    let ok = h.broker.request_operation(&h.conn, h.query("c", &["day"]), Lang::ZhCn).await.unwrap();
    assert_eq!(ok.status, OperationStatus::Succeeded, "grant from the earlier approval still covers it");
}

#[tokio::test]
async fn sync_conflict_pauses_automatic_use() {
    let h = Harness::new().await;
    let r = h.broker.request_operation(&h.conn, h.query("a", &["day"]), Lang::ZhCn).await.unwrap();
    h.approve(r.approval_request_id.as_ref().unwrap()).await;
    let res = h
        .broker
        .set_entry_conflict(&Actor::Device(h.device_id.clone()), &h.resource.credential_entry_id, true)
        .await
        .unwrap();
    assert_eq!(res.resources_affected, 1);
    let e = h.broker.request_operation(&h.conn, h.query("b", &["day"]), Lang::ZhCn).await.unwrap_err();
    assert_eq!(e.code, ErrorCode::SyncConflict);
    let views = h.broker.list_resources(&h.conn, None, None, Lang::ZhCn).await.unwrap();
    assert_eq!(serde_json::to_value(&views.resources[0]).unwrap()["status"], "sync_conflict");
    h.broker
        .set_entry_conflict(&Actor::Admin, &h.resource.credential_entry_id, false)
        .await
        .unwrap();
    let ok = h.broker.request_operation(&h.conn, h.query("b", &["day"]), Lang::ZhCn).await.unwrap();
    assert_eq!(ok.status, OperationStatus::Succeeded);
}

#[tokio::test]
async fn output_caps_withhold_oversized_results() {
    let mut cfg = test_config();
    cfg.default_limits.max_result_bytes = 400;
    let h = Harness::with_config(cfg).await;
    h.exe.set(|b| {
        b.rows_available = 3;
        b.row_padding = 500;
    });
    let r = h.broker.request_operation(&h.conn, h.query("a", &["day"]), Lang::ZhCn).await.unwrap();
    let d = h.approve(r.approval_request_id.as_ref().unwrap()).await;
    let op = d.operation.unwrap();
    assert_eq!(op.status, OperationStatus::Failed);
    assert_eq!(op.error.unwrap().code, ErrorCode::ResultRestricted);
    let s = h.broker.get_operation(&h.conn, &r.operation_id, Lang::ZhCn).await.unwrap();
    assert!(s.result.is_none());

    // an executor that ignores the remaining-row cap is caught too
    h.exe.set(|b| {
        b.row_padding = 0;
        b.rows_available = 5000;
        b.overreport_rows = true;
    });
    let s = h.broker.request_operation(&h.conn, h.query("b", &["day"]), Lang::ZhCn).await.unwrap();
    assert_eq!(s.status, OperationStatus::Failed);
    assert_eq!(s.error.unwrap().code, ErrorCode::ResultRestricted);
}

#[tokio::test]
async fn missing_credential_is_secret_unavailable() {
    let h = Harness::new().await;
    let r = h.broker.request_operation(&h.conn, h.query("a", &["day"]), Lang::ZhCn).await.unwrap();
    let mut d = h.decision(r.approval_request_id.as_ref().unwrap(), Decision::Approve, None).await;
    d.credential_envelope = None;
    let resp = h.broker.submit_decision(d).await.unwrap();
    let op = resp.operation.unwrap();
    assert_eq!(op.status, OperationStatus::Failed);
    assert_eq!(op.error.unwrap().code, ErrorCode::SecretUnavailable);
    assert_eq!(h.exe.executions(), 0);
}

#[tokio::test]
async fn validation_and_visibility_errors_create_no_operation() {
    let h = Harness::new().await;
    // field outside the allowlist → SCOPE_DENIED from normalize
    let e = h.broker.request_operation(&h.conn, h.query("a", &["password_hash"]), Lang::ZhCn).await.unwrap_err();
    assert_eq!(e.code, ErrorCode::ScopeDenied);
    // operation not offered
    let mut q = h.query("b", &["day"]);
    q.operation = "get_password".into();
    assert_eq!(h.broker.request_operation(&h.conn, q, Lang::ZhCn).await.unwrap_err().code, ErrorCode::ScopeDenied);
    // experimental op hidden unless experimental is enabled
    let mut q = h.query("c", &["day"]);
    q.operation = "postgres.experimental_rotate".into();
    assert_eq!(h.broker.request_operation(&h.conn, q, Lang::ZhCn).await.unwrap_err().code, ErrorCode::ScopeDenied);
    // bad idempotency key
    let q = h.query("", &["day"]);
    assert_eq!(h.broker.request_operation(&h.conn, q, Lang::ZhCn).await.unwrap_err().code, ErrorCode::InvalidRequest);
    // unknown resource
    let q = h.query_on(&aipass_types::ids::ResourceId::generate(), "d", &["day"]);
    assert_eq!(h.broker.request_operation(&h.conn, q, Lang::ZhCn).await.unwrap_err().code, ErrorCode::NotFound);
    assert!(h.broker.list_operations(10).await.unwrap().operations.is_empty());
    // rejections are audited
    let audit = h.broker.audit_events(0, 1000).await.unwrap();
    assert!(audit.events.iter().filter(|e| e.action == "operation.rejected").count() >= 5);
}

#[tokio::test]
async fn once_grant_serves_exactly_one_operation() {
    let h = Harness::new().await;
    let r = h.broker.request_operation(&h.conn, h.query("a", &["day"]), Lang::ZhCn).await.unwrap();
    let apr = r.approval_request_id.clone().unwrap();
    let req = h.request(&apr).await;
    let mut narrowed = req.requested.clone();
    narrowed.mode = aipass_types::models::ApprovalMode::Once;
    let d = h.decision(&apr, Decision::Approve, Some(narrowed)).await;
    let resp = h.broker.submit_decision(d).await.unwrap();
    assert_eq!(resp.operation.unwrap().status, OperationStatus::Succeeded);
    let g = h.broker.get_grant(resp.grant_id.as_ref().unwrap()).await.unwrap();
    assert_eq!(g.status, GrantStatus::Exhausted);
    let next = h.broker.request_operation(&h.conn, h.query("b", &["day"]), Lang::ZhCn).await.unwrap();
    assert_eq!(next.status, OperationStatus::AwaitingApproval);
}

#[tokio::test]
async fn experimental_operations_need_the_flag() {
    let mut cfg = BrokerConfig::in_memory();
    cfg.experimental = true;
    let h = Harness::with_config(cfg).await;
    let views = h.broker.list_resources(&h.conn, None, None, Lang::En).await.unwrap();
    let names: Vec<String> = views.resources[0].operations.iter().map(|o| o.name.clone()).collect();
    assert!(names.contains(&"postgres.experimental_rotate".to_string()));
    assert!(views.resources[0].operations[0].description.starts_with("Test operation"));
}

#[tokio::test]
async fn panicking_connector_fails_the_operation_cleanly() {
    let h = Harness::new().await;
    let r = h.broker.request_operation(&h.conn, h.query("a", &["day"]), Lang::ZhCn).await.unwrap();
    h.approve(r.approval_request_id.as_ref().unwrap()).await;
    h.exe.set(|b| b.panic_on_execute = true);
    let r = h.broker.request_operation(&h.conn, h.query("b", &["day"]), Lang::ZhCn).await.unwrap();
    assert_eq!(r.status, OperationStatus::Failed);
    assert_eq!(r.error.unwrap().code, ErrorCode::Internal);
    // nothing is left in flight and the grant's reservation was released
    h.exe.set(|b| b.panic_on_execute = false);
    let r = h.broker.request_operation(&h.conn, h.query("c", &["day"]), Lang::ZhCn).await.unwrap();
    assert_eq!(r.status, OperationStatus::Succeeded);
}

#[tokio::test]
async fn broker_timeout_marks_reads_failed_and_writes_unknown() {
    let mut cfg = test_config();
    cfg.operation_timeout = Duration::from_millis(200);
    let h = Harness::with_config(cfg).await;
    let r = h.broker.request_operation(&h.conn, h.query("a", &["day"]), Lang::ZhCn).await.unwrap();
    h.approve(r.approval_request_id.as_ref().unwrap()).await;
    h.exe.set(|b| {
        b.delay = Duration::from_secs(30);
        b.honor_cancel = false;
    });
    let r = h.broker.request_operation(&h.conn, h.query("slow", &["day"]), Lang::ZhCn).await.unwrap();
    assert_eq!(r.status, OperationStatus::Failed);
    assert_eq!(r.error.unwrap().code, ErrorCode::UpstreamError);

    let api = h.add_api_resource(Environment::Test).await;
    h.exe.set(|b| b.delay = Duration::ZERO);
    let write = OperationRequest {
        resource_id: api.resource_id.clone(),
        operation: "demo.create_order".into(),
        parameters: json!({"item": "x"}),
        idempotency_key: "w".into(),
        task_id: None,
    };
    let r = h.broker.request_operation(&h.conn, write, Lang::ZhCn).await.unwrap();
    h.exe.set(|b| b.delay = Duration::from_secs(30));
    let d = h.approve(r.approval_request_id.as_ref().unwrap()).await;
    let op = d.operation.unwrap();
    assert_eq!(op.status, OperationStatus::Unknown, "a write that timed out may have happened upstream");
    assert_eq!(op.error.unwrap().code, ErrorCode::UpstreamOutcomeUnknown);
}

#[tokio::test]
async fn background_sweeper_expires_without_requests() {
    let mut cfg = test_config();
    cfg.sweep_interval = Duration::from_millis(20);
    let h = Harness::with_config(cfg).await;
    let _task = h.broker.spawn_background();
    let r = h.broker.request_operation(&h.conn, h.query("a", &["day"]), Lang::ZhCn).await.unwrap();
    let mut events = h.broker.subscribe();
    h.clock.advance(121);
    let ev = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if let aipass_broker::BrokerEvent::ApprovalResolved { status, .. } = events.recv().await.unwrap() {
                return status;
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(ev, ApprovalStatus::Expired);
    let ops = h.broker.list_operations(5).await.unwrap().operations;
    assert_eq!(ops.iter().find(|o| o.operation_id == r.operation_id).unwrap().status, OperationStatus::Expired);
}

#[tokio::test]
async fn in_process_notifiers_receive_events_without_results() {
    struct Collect(std::sync::Mutex<Vec<String>>);
    impl aipass_broker::ApprovalNotifier for Collect {
        fn notify(&self, event: &aipass_broker::BrokerEvent) {
            self.0.lock().unwrap().push(serde_json::to_string(event).unwrap());
        }
    }
    let h = Harness::new().await;
    let c = std::sync::Arc::new(Collect(Default::default()));
    h.broker.add_notifier(c.clone());
    let r = h.broker.request_operation(&h.conn, h.query("a", &["day"]), Lang::ZhCn).await.unwrap();
    h.approve(r.approval_request_id.as_ref().unwrap()).await;
    let all = c.0.lock().unwrap().join("\n");
    assert!(all.contains("\"type\":\"approval_requested\""));
    assert!(all.contains("\"type\":\"approval_resolved\""));
    assert!(all.contains("\"type\":\"operation_updated\""));
    assert!(!all.contains("\"pad\""), "events never carry result data");
    assert_no_secret(&all);
}
