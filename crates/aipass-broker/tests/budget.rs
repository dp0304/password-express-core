// SPDX-License-Identifier: Apache-2.0
//! A08 — cumulative budgets hold under pagination and concurrency.

mod common;

use std::time::Duration;

use aipass_types::error::{ErrorCode, Lang};
use aipass_types::models::{Decision, GrantStatus, Limits, OperationStatus};
use common::*;
use serde_json::json;

/// Approve the first request with narrowed limits; returns the grant id.
async fn approve_with_limits(h: &Harness, limits: Limits) -> aipass_types::ids::GrantId {
    let r = h
        .broker
        .request_operation(&h.conn, h.query("seed", &["day"]), Lang::ZhCn)
        .await
        .unwrap();
    let apr = r.approval_request_id.unwrap();
    let mut spec = h.request(&apr).await.requested;
    spec.limits = limits;
    let d = h.decision(&apr, Decision::Approve, Some(spec)).await;
    let resp = h.broker.submit_decision(d).await.unwrap();
    resp.grant_id.unwrap()
}

#[tokio::test]
async fn pagination_cannot_exceed_rows_per_grant() {
    let h = Harness::new().await;
    h.exe.set(|b| b.rows_available = 20);
    let grant = approve_with_limits(
        &h,
        Limits {
            max_rows_per_operation: 20,
            max_rows_per_grant: 50,
            max_requests_per_grant: 20,
            max_result_bytes: 262_144,
        },
    )
    .await;
    // seed op used 20 rows; page through the rest
    let mut total = 20u64;
    let mut pages = 0;
    loop {
        let mut q = h.query(&format!("page-{pages}"), &["day"]);
        q.parameters = json!({"view": "analytics.subscription_daily", "fields": ["day"], "page": pages});
        let r = h.broker.request_operation(&h.conn, q, Lang::ZhCn).await.unwrap();
        pages += 1;
        match r.status {
            OperationStatus::Succeeded => total += r.result.unwrap().rows.unwrap(),
            OperationStatus::AwaitingApproval => break,
            other => panic!("unexpected {other:?}"),
        }
        assert!(pages < 10);
    }
    assert_eq!(total, 50, "exactly the grant's row budget was returned");
    let g = h.broker.get_grant(&grant).await.unwrap();
    assert_eq!(g.usage.rows, 50);
    assert_eq!(g.status, GrantStatus::Exhausted);
    // the executor was always told how much was left
    let seen = h.exe.seen_remaining.lock().unwrap().clone();
    assert_eq!(seen.iter().map(|l| l.max_rows_per_operation).collect::<Vec<_>>(), vec![20, 20, 10]);
}

#[tokio::test]
async fn requests_per_grant_are_enforced() {
    let h = Harness::new().await;
    approve_with_limits(
        &h,
        Limits {
            max_rows_per_operation: 10,
            max_rows_per_grant: 1000,
            max_requests_per_grant: 3,
            max_result_bytes: 262_144,
        },
    )
    .await;
    for i in 0..2 {
        let r = h.broker.request_operation(&h.conn, h.query(&format!("r{i}"), &["day"]), Lang::ZhCn).await.unwrap();
        assert_eq!(r.status, OperationStatus::Succeeded);
    }
    let r = h.broker.request_operation(&h.conn, h.query("r3", &["day"]), Lang::ZhCn).await.unwrap();
    assert_eq!(r.status, OperationStatus::AwaitingApproval, "a fresh approval is needed, the old budget never refills");
    assert_eq!(h.exe.executions(), 3);
}

#[tokio::test]
async fn concurrency_cannot_exceed_request_budget() {
    let mut cfg = test_config();
    cfg.max_inflight_per_connection = 100;
    let h = Harness::with_config(cfg).await;
    approve_with_limits(
        &h,
        Limits {
            max_rows_per_operation: 1,
            max_rows_per_grant: 1000,
            max_requests_per_grant: 5,
            max_result_bytes: 262_144,
        },
    )
    .await;
    h.exe.set(|b| b.delay = Duration::from_millis(150));
    let mut tasks = Vec::new();
    for i in 0..20 {
        let b = h.broker.clone();
        let c = h.conn.clone();
        let q = h.query(&format!("c{i}"), &["day"]);
        tasks.push(tokio::spawn(async move { b.request_operation(&c, q, Lang::ZhCn).await }));
    }
    let mut succeeded = 0;
    let mut refused = 0;
    for t in tasks {
        match t.await.unwrap() {
            Ok(r) if r.status == OperationStatus::Succeeded => succeeded += 1,
            Ok(r) if r.status == OperationStatus::AwaitingApproval => refused += 1,
            Ok(r) if r.status == OperationStatus::Failed => {
                assert_eq!(r.error.unwrap().code, ErrorCode::BudgetExhausted);
                refused += 1
            }
            Err(e) => {
                assert_eq!(e.code, ErrorCode::RateLimited, "{e:?}");
                refused += 1
            }
            Ok(r) => panic!("unexpected {r:?}"),
        }
    }
    // seed op used 1 request; 4 remain
    assert_eq!(succeeded, 4, "succeeded={succeeded} refused={refused}");
    assert_eq!(h.exe.executions(), 5);
}

#[tokio::test]
async fn concurrency_cannot_exceed_row_budget() {
    let mut cfg = test_config();
    cfg.max_inflight_per_connection = 100;
    let h = Harness::with_config(cfg).await;
    h.exe.set(|b| b.rows_available = 20);
    let grant = approve_with_limits(
        &h,
        Limits {
            max_rows_per_operation: 20,
            max_rows_per_grant: 70,
            max_requests_per_grant: 20,
            max_result_bytes: 262_144,
        },
    )
    .await;
    h.exe.set(|b| b.delay = Duration::from_millis(100));
    let mut tasks = Vec::new();
    for i in 0..12 {
        let b = h.broker.clone();
        let c = h.conn.clone();
        let q = h.query(&format!("c{i}"), &["day"]);
        tasks.push(tokio::spawn(async move { b.request_operation(&c, q, Lang::ZhCn).await }));
    }
    let mut rows = 20u64; // seed
    for t in tasks {
        if let Ok(r) = t.await.unwrap()
            && let Some(res) = r.result {
                rows += res.rows.unwrap();
            }
    }
    assert!(rows <= 70, "returned {rows} rows with a 70-row budget");
    let g = h.broker.get_grant(&grant).await.unwrap();
    assert!(g.usage.rows <= 70);
    assert_eq!(g.usage.rows, rows);
}
