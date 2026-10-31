// SPDX-License-Identifier: Apache-2.0
//! PostgreSQL connector against a temporary cluster on port 55441 with a lure-store style
//! schema (A07 database overreach, A08 budgets, A18 output filter, cancellation, superuser
//! refusal, sslmode handling, credential custody). Experimental rotation and temporary-role
//! leases run when built with `--features experimental`.
//!
//! All scenarios share one cluster and run sequentially inside a single test so the cluster
//! is always stopped and deleted (Drop + watchdog), even when an assertion fails.

mod support;

use std::sync::Arc;
use std::time::{Duration, Instant};

use aipass_executor::Executor;
use aipass_types::exec::{CredentialAad, ExecutorBackend};
use aipass_types::models::{Connector, Limits, Resource};
use aipass_types::vault::EntryKind;
use aipass_types::{ApprovalRequestId, ErrorCode, ExecutorId, GrantId, OperationId};
use serde_json::{Value, json};
use support::pg::TempCluster;
use support::*;
use tokio_util::sync::CancellationToken;

const PORT: u16 = 55441;
const READER: &str = "ai_reader";
const READER_PASS: &str = "Reader-Pw-6d1e44b7c2";
const SUPER_ROLE_PASS: &str = "SuperRole-Pw-91aa";
const BYPASS_PASS: &str = "Bypass-Pw-77b2";
const FILES_PASS: &str = "Files-Pw-3c4d";
const ISSUER_PASS: &str = "Issuer-Pw-5e6f7a";
const ROTATE_OLD: &str = "Rotate-Old-Pw-0a1b2c";
const GHP: &str = "ghp_0123456789abcdefghijABCDEFGHIJ012345";

fn setup_sql() -> String {
    format!(
        r#"
CREATE SCHEMA shop;
CREATE SCHEMA analytics;
CREATE TABLE shop.customers (id serial PRIMARY KEY, tenant_id text NOT NULL, email text NOT NULL, full_name text, api_token text);
INSERT INTO shop.customers (tenant_id, email, full_name, api_token) VALUES
  ('lure','alice@example.com','Alice','tok_alice'),('lure','bob@example.com','Bob','tok_bob'),('other','carol@other.example','Carol','tok_carol');
CREATE TABLE shop.subscriptions (id serial PRIMARY KEY, tenant_id text NOT NULL, customer_id int, plan text NOT NULL, started_on date NOT NULL);
INSERT INTO shop.subscriptions (tenant_id, customer_id, plan, started_on)
  SELECT 'lure', 1, (ARRAY['basic','pro','team'])[1 + g % 3], current_date - (g % 40) FROM generate_series(1, 360) g;
INSERT INTO shop.subscriptions (tenant_id, customer_id, plan, started_on)
  SELECT 'other', 3, 'enterprise', current_date - (g % 10) FROM generate_series(1, 30) g;
CREATE VIEW analytics.subscription_daily AS
  SELECT tenant_id, started_on AS day, plan, count(*)::int AS subscriptions FROM shop.subscriptions GROUP BY tenant_id, started_on, plan;
CREATE VIEW analytics.customer_emails AS SELECT tenant_id, email FROM shop.customers;
CREATE TABLE analytics.notes (id int, plan text, note text);
INSERT INTO analytics.notes VALUES
  (1,'pro','normal note'),
  (2,'pro','leaked reader password: {READER_PASS}'),
  (3,'team','token {GHP}'),
  (4,'basic','aws AKIAIOSFODNN7EXAMPLE'),
  (5,'basic','dsn postgres://admin:hunter2@db.internal/app');
CREATE FUNCTION analytics.slow_n(n int) RETURNS int LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(0.3); RETURN n; END $$;
CREATE VIEW analytics.slow_view AS SELECT analytics.slow_n(g) AS n FROM generate_series(1, 60) g;
CREATE FUNCTION analytics.sneaky_write() RETURNS int LANGUAGE plpgsql SECURITY DEFINER AS $$
  BEGIN INSERT INTO shop.customers (tenant_id, email) VALUES ('x', 'pwned@evil.example'); RETURN 1; END $$;
CREATE VIEW analytics.sneaky AS SELECT analytics.sneaky_write() AS x;
CREATE VIEW analytics.file_reader AS SELECT pg_read_file('/etc/hosts') AS content;
CREATE TABLE shop.orders (tenant_id text, amount int);
INSERT INTO shop.orders VALUES ('lure', 10), ('lure', 20), ('lure', 30), ('other', 999), ('other', 1000);
ALTER TABLE shop.orders ENABLE ROW LEVEL SECURITY;
CREATE VIEW analytics.orders_v WITH (security_invoker = true) AS SELECT tenant_id, amount FROM shop.orders;

CREATE ROLE {READER} LOGIN PASSWORD '{READER_PASS}';
GRANT USAGE ON SCHEMA analytics TO {READER};
GRANT USAGE ON SCHEMA shop TO {READER};
GRANT SELECT ON analytics.subscription_daily, analytics.customer_emails, analytics.notes, analytics.slow_view,
  analytics.sneaky, analytics.file_reader, analytics.orders_v TO {READER};
GRANT SELECT ON shop.orders TO {READER};
CREATE POLICY lure_only ON shop.orders FOR SELECT TO {READER} USING (tenant_id = 'lure');

CREATE ROLE ai_super LOGIN SUPERUSER PASSWORD '{SUPER_ROLE_PASS}';
CREATE ROLE ai_bypass LOGIN BYPASSRLS PASSWORD '{BYPASS_PASS}';
GRANT USAGE ON SCHEMA analytics, shop TO ai_bypass;
GRANT SELECT ON analytics.orders_v, shop.orders, analytics.subscription_daily TO ai_bypass;
CREATE ROLE ai_files LOGIN PASSWORD '{FILES_PASS}';
GRANT pg_read_server_files TO ai_files;
GRANT USAGE ON SCHEMA analytics TO ai_files;
GRANT SELECT ON analytics.subscription_daily TO ai_files;

CREATE ROLE analytics_reader NOLOGIN;
GRANT USAGE ON SCHEMA analytics TO analytics_reader;
GRANT SELECT ON analytics.subscription_daily TO analytics_reader;
CREATE ROLE lease_issuer LOGIN CREATEROLE PASSWORD '{ISSUER_PASS}';
GRANT analytics_reader TO lease_issuer WITH ADMIN OPTION;
GRANT pg_signal_backend TO lease_issuer;
CREATE ROLE rotating_user LOGIN PASSWORD '{ROTATE_OLD}';
GRANT USAGE ON SCHEMA analytics TO rotating_user;
GRANT SELECT ON analytics.subscription_daily TO rotating_user;
"#
    )
}

fn views() -> Value {
    json!({
        "analytics.subscription_daily": {"fields": ["day", "plan", "subscriptions"], "date_field": "day",
            "row_filter": [{"field": "tenant_id", "op": "eq", "value": "lure"}]},
        "analytics.notes": {"fields": ["id", "plan", "note"]},
        "analytics.slow_view": {"fields": ["n"]},
        "analytics.sneaky": {"fields": ["x"]},
        "analytics.file_reader": {"fields": ["content"]},
        "analytics.orders_v": {"fields": ["tenant_id", "amount"]}
    })
}

fn config(extra: Value) -> Value {
    let mut base = json!({
        "host": "127.0.0.1", "port": PORT, "dbname": "lure", "sslmode": "disable",
        "allowed_views": views(), "statement_timeout_ms": 5000, "max_rows_per_operation": 1000,
        "allow_superuser": false, "lease_mode": "static"
    });
    if let (Value::Object(b), Value::Object(e)) = (&mut base, extra) {
        for (k, v) in e {
            b.insert(k, v);
        }
    }
    base
}

const QV: &str = "postgres.query_view";

struct Ctx {
    cluster: TempCluster,
    exec: Arc<Executor>,
}

impl Ctx {
    fn res(&self, extra: Value) -> Resource {
        resource(
            &self.exec,
            Connector::Postgres,
            config(extra),
            &[QV, "credentials.rotate"],
        )
    }
    async fn grant(&self, r: &Resource, user: &str, pass: &str) -> GrantId {
        grant_with(&self.exec, db_material(r, user, pass, "127.0.0.1", PORT)).await
    }
    async fn reader(&self, r: &Resource) -> GrantId {
        self.grant(r, READER, READER_PASS).await
    }
}

fn daily(extra: Value) -> Value {
    let mut p =
        json!({"view": "analytics.subscription_daily", "fields": ["day", "plan", "subscriptions"]});
    if let (Value::Object(b), Value::Object(e)) = (&mut p, extra) {
        for (k, v) in e {
            b.insert(k, v);
        }
    }
    p
}

async fn reader_backends(su: &tokio_postgres::Client) -> i64 {
    su.query_one(
        "SELECT count(*) FROM pg_stat_activity WHERE usename = $1 AND application_name = 'aipass-executor'",
        &[&READER],
    )
    .await
    .unwrap()
    .get(0)
}

#[cfg(feature = "experimental")]
async fn role_count(su: &tokio_postgres::Client, role: &str) -> i64 {
    su.query_one("SELECT count(*) FROM pg_roles WHERE rolname = $1", &[&role])
        .await
        .unwrap()
        .get(0)
}

fn code(
    r: &Result<aipass_types::exec::ExecutionOutcome, aipass_types::ApiError>,
) -> Option<ErrorCode> {
    r.as_ref().err().map(|e| e.code)
}

fn reason(
    r: &Result<aipass_types::exec::ExecutionOutcome, aipass_types::ApiError>,
) -> Option<String> {
    r.as_ref().err().and_then(|e| {
        e.details
            .get("reason")
            .and_then(|v| v.as_str())
            .map(str::to_owned)
    })
}

async fn allowed_view_and_fields(c: &Ctx) {
    let r = c.res(json!({}));
    let g = c.reader(&r).await;
    let out = run(
        &c.exec,
        &r,
        &g,
        QV,
        daily(json!({"period_days": 7, "order_by": [{"field": "day", "direction": "desc"}]})),
        limits(),
    )
    .await
    .expect("allowed query");
    let rows = out.data["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 24, "{}", out.data);
    assert_eq!(out.rows, Some(24));
    assert!(!out.truncated);
    for row in rows {
        let keys: Vec<&String> = row.as_object().unwrap().keys().collect();
        assert_eq!(keys, vec!["day", "plan", "subscriptions"]);
        assert!(
            ["basic", "pro", "team"].contains(&row["plan"].as_str().unwrap()),
            "tenant filter leaked: {row}"
        );
        assert_eq!(row["subscriptions"], 3);
    }
    assert_eq!(out.data["fields"], json!(["day", "plan", "subscriptions"]));
    // filters with typed casts
    let out = run(
        &c.exec,
        &r,
        &g,
        QV,
        daily(json!({"filters": [
            {"field": "plan", "op": "in", "value": ["pro", "team"]},
            {"field": "subscriptions", "op": "gte", "value": 3},
            {"field": "day", "op": "between", "value": ["2000-01-01", "2999-12-31"]}
        ]})),
        limits(),
    )
    .await
    .expect("filters");
    assert_eq!(out.rows, Some(80));
    // the same normalized request again is served from the session pool
    assert!(c.exec.postgres_open_sessions(g.as_str()) >= 1);
}

async fn overreach_is_refused(c: &Ctx) {
    let r = c.res(json!({}));
    let g = c.reader(&r).await;
    // Views / tables / functions that are not allowlisted never reach the database.
    for (params, want) in [
        (
            json!({"view": "analytics.customer_emails", "fields": ["email"]}),
            ErrorCode::ScopeDenied,
        ),
        (
            json!({"view": "shop.customers", "fields": ["email", "api_token"]}),
            ErrorCode::ScopeDenied,
        ),
        (
            json!({"view": "pg_read_file('/etc/passwd')", "fields": ["x"]}),
            ErrorCode::ScopeDenied,
        ),
        (
            json!({"view": "analytics.subscription_daily", "fields": ["pg_read_file('/etc/passwd')"]}),
            ErrorCode::ScopeDenied,
        ),
        (
            json!({"view": "analytics.subscription_daily", "fields": ["tenant_id"]}),
            ErrorCode::ScopeDenied,
        ),
        (
            json!({"view": "analytics.subscription_daily", "fields": ["day"], "filters": [{"field": "tenant_id", "op": "eq", "value": "other"}]}),
            ErrorCode::ScopeDenied,
        ),
        (
            json!({"view": "analytics.subscription_daily", "fields": ["day"], "order_by": [{"field": "(SELECT 1)"}]}),
            ErrorCode::ScopeDenied,
        ),
        (
            json!({"sql": "SELECT * FROM shop.customers"}),
            ErrorCode::InvalidRequest,
        ),
    ] {
        let res = run(&c.exec, &r, &g, QV, params.clone(), limits()).await;
        assert_eq!(code(&res), Some(want), "{params}");
    }
    // Operations that are not offered (writes / raw SQL) are refused.
    for op in ["postgres.execute", "postgres.insert", "get_password"] {
        let e = c.exec.normalize(&r, op, &json!({})).unwrap_err();
        assert_eq!(e.code, ErrorCode::ScopeDenied, "{op}");
    }
    // Writes hidden inside an allowlisted view are stopped by the READ ONLY transaction.
    let res = run(
        &c.exec,
        &r,
        &g,
        QV,
        json!({"view": "analytics.sneaky", "fields": ["x"]}),
        limits(),
    )
    .await;
    assert_eq!(code(&res), Some(ErrorCode::ScopeDenied), "{res:?}");
    // A (mis)allowlisted view that calls pg_read_file fails on database privileges.
    let res = run(
        &c.exec,
        &r,
        &g,
        QV,
        json!({"view": "analytics.file_reader", "fields": ["content"]}),
        limits(),
    )
    .await;
    assert_eq!(code(&res), Some(ErrorCode::ScopeDenied), "{res:?}");
    // Even if a trusted client wrongly allowlists the raw table, the role cannot read it.
    let mis =
        c.res(json!({"allowed_views": {"shop.customers": {"fields": ["email", "api_token"]}}}));
    let g2 = c.reader(&mis).await;
    let res = run(
        &c.exec,
        &mis,
        &g2,
        QV,
        json!({"view": "shop.customers", "fields": ["email"]}),
        limits(),
    )
    .await;
    assert_eq!(code(&res), Some(ErrorCode::ScopeDenied), "{res:?}");
    // Nothing was written.
    let su = c.cluster.superuser("lure").await;
    let n: i64 = su
        .query_one(
            "SELECT count(*) FROM shop.customers WHERE email = 'pwned@evil.example'",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(n, 0);
}

async fn cross_tenant_rows(c: &Ctx) {
    let r = c.res(json!({}));
    let g = c.reader(&r).await;
    let out = run(
        &c.exec,
        &r,
        &g,
        QV,
        json!({"view": "analytics.orders_v", "fields": ["tenant_id", "amount"]}),
        limits(),
    )
    .await
    .unwrap();
    assert_eq!(out.rows, Some(3), "{}", out.data);
    let out = run(
        &c.exec,
        &r,
        &g,
        QV,
        json!({"view": "analytics.orders_v", "fields": ["amount"],
        "filters": [{"field": "tenant_id", "op": "eq", "value": "other"}]}),
        limits(),
    )
    .await
    .unwrap();
    assert_eq!(
        out.rows,
        Some(0),
        "RLS must hide other tenants: {}",
        out.data
    );
    // row_filter on subscription_daily: the other tenant's 'enterprise' plan never appears.
    let out = run(
        &c.exec,
        &r,
        &g,
        QV,
        daily(json!({"filters": [{"field": "plan", "op": "eq", "value": "enterprise"}]})),
        limits(),
    )
    .await
    .unwrap();
    assert_eq!(out.rows, Some(0));
}

async fn injection_in_every_param(c: &Ctx) {
    let r = c.res(json!({}));
    let g = c.reader(&r).await;
    let payloads = [
        "'; DROP TABLE shop.customers; --",
        "x' OR '1'='1",
        "1); SELECT pg_read_file('/etc/passwd'); --",
        "\" OR 1=1 --",
        "$1",
        "') UNION SELECT email FROM shop.customers --",
    ];
    for p in payloads {
        let cases = [
            json!({"view": p, "fields": ["day"]}),
            json!({"view": "analytics.subscription_daily", "fields": [p]}),
            json!({"view": "analytics.subscription_daily", "fields": ["day"], "filters": [{"field": p, "op": "eq", "value": "x"}]}),
            json!({"view": "analytics.subscription_daily", "fields": ["day"], "filters": [{"field": "plan", "op": p, "value": "x"}]}),
            json!({"view": "analytics.subscription_daily", "fields": ["day"], "order_by": [{"field": p}]}),
            json!({"view": "analytics.subscription_daily", "fields": ["day"], "order_by": [{"field": "day", "direction": p}]}),
            json!({"view": "analytics.subscription_daily", "fields": ["day"], "limit": p}),
            json!({"view": "analytics.subscription_daily", "fields": ["day"], "period_days": p}),
        ];
        for case in cases {
            let res = run(&c.exec, &r, &g, QV, case.clone(), limits()).await;
            assert!(
                matches!(
                    code(&res),
                    Some(ErrorCode::ScopeDenied | ErrorCode::InvalidRequest)
                ),
                "{case}: {res:?}"
            );
        }
        // As values they are bound parameters: harmless.
        let res = run(
            &c.exec,
            &r,
            &g,
            QV,
            daily(json!({"filters": [{"field": "plan", "op": "eq", "value": p}]})),
            limits(),
        )
        .await;
        assert_eq!(res.expect("bound text value").rows, Some(0), "{p}");
        let res = run(
            &c.exec,
            &r,
            &g,
            QV,
            daily(json!({"filters": [{"field": "day", "op": "eq", "value": p}]})),
            limits(),
        )
        .await;
        assert_eq!(code(&res), Some(ErrorCode::InvalidRequest), "{p}");
        let res = run(
            &c.exec,
            &r,
            &g,
            QV,
            daily(json!({"filters": [{"field": "subscriptions", "op": "in", "value": [1, p]}]})),
            limits(),
        )
        .await;
        assert_eq!(code(&res), Some(ErrorCode::InvalidRequest), "{p}");
    }
    let su = c.cluster.superuser("lure").await;
    let n: i64 = su
        .query_one("SELECT count(*) FROM shop.customers", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(n, 3, "customers table intact");
}

async fn budgets(c: &Ctx) {
    let r = c.res(json!({}));
    let g = c.reader(&r).await;
    let small = Limits {
        max_rows_per_operation: 1000,
        max_rows_per_grant: 5,
        max_requests_per_grant: 20,
        max_result_bytes: 262_144,
    };
    let out = run(&c.exec, &r, &g, QV, daily(json!({})), small)
        .await
        .unwrap();
    assert_eq!(out.rows, Some(5));
    assert!(out.truncated);
    let out = run(&c.exec, &r, &g, QV, daily(json!({"limit": 2})), small)
        .await
        .unwrap();
    assert_eq!(out.rows, Some(2));
    let per_op = Limits {
        max_rows_per_operation: 7,
        ..limits()
    };
    let out = run(&c.exec, &r, &g, QV, daily(json!({"limit": 5000})), per_op)
        .await
        .unwrap();
    assert_eq!(out.rows, Some(7));
    assert!(out.truncated);
    let exhausted = Limits {
        max_rows_per_grant: 0,
        ..limits()
    };
    let res = run(&c.exec, &r, &g, QV, daily(json!({})), exhausted).await;
    assert_eq!(code(&res), Some(ErrorCode::BudgetExhausted));
    let bytes = Limits {
        max_result_bytes: 400,
        ..limits()
    };
    let out = run(&c.exec, &r, &g, QV, daily(json!({})), bytes)
        .await
        .unwrap();
    assert!(out.truncated && out.bytes <= 400, "{} bytes", out.bytes);
    assert!(out.rows.unwrap() > 0);
    // Concurrency: many parallel requests on one grant share at most 4 sessions.
    let mut tasks = Vec::new();
    for _ in 0..10 {
        let exec = c.exec.clone();
        let (r, g) = (r.clone(), g.clone());
        tasks.push(tokio::spawn(async move {
            run(&exec, &r, &g, QV, daily(json!({"limit": 3})), limits()).await
        }));
    }
    for t in tasks {
        assert_eq!(t.await.unwrap().unwrap().rows, Some(3));
    }
    assert!(c.exec.postgres_open_sessions(g.as_str()) <= 4);
    // scope_covers checks scope + limits
    let norm = c.exec.normalize(&r, QV, &daily(json!({}))).unwrap();
    let scope = aipass_types::models::GrantScope {
        operations: vec![QV.into()],
        postgres: Some(aipass_types::models::PostgresScope {
            views: [(
                "analytics.subscription_daily".to_owned(),
                vec!["day".into(), "plan".into(), "subscriptions".into()],
            )]
            .into(),
        }),
        ..Default::default()
    };
    assert!(c.exec.scope_covers(&scope, &limits(), &norm));
    let narrower = aipass_types::models::GrantScope {
        postgres: Some(aipass_types::models::PostgresScope {
            views: [(
                "analytics.subscription_daily".to_owned(),
                vec!["day".into()],
            )]
            .into(),
        }),
        ..scope.clone()
    };
    assert!(!c.exec.scope_covers(&narrower, &limits(), &norm));
    assert!(!c.exec.scope_covers(
        &scope,
        &Limits {
            max_requests_per_grant: 0,
            ..limits()
        },
        &norm
    ));
}

async fn timeout_and_cancel(c: &Ctx) {
    // statement_timeout
    let r = c.res(json!({"statement_timeout_ms": 500}));
    let g = c.reader(&r).await;
    let t = Instant::now();
    let res = run(
        &c.exec,
        &r,
        &g,
        QV,
        json!({"view": "analytics.slow_view", "fields": ["n"]}),
        limits(),
    )
    .await;
    assert_eq!(code(&res), Some(ErrorCode::UpstreamError));
    assert_eq!(reason(&res).as_deref(), Some("statement_timeout"));
    assert!(t.elapsed() < Duration::from_secs(4), "{:?}", t.elapsed());

    // operations.cancel → PostgreSQL cancel request
    let r = c.res(json!({"statement_timeout_ms": 30000}));
    let g = c.reader(&r).await;
    let op = OperationId::generate();
    let exec = c.exec.clone();
    let (r2, g2, op2) = (r.clone(), g.clone(), op.clone());
    let t = Instant::now();
    let task = tokio::spawn(async move {
        run_with(
            &exec,
            &r2,
            &g2,
            QV,
            json!({"view": "analytics.slow_view", "fields": ["n"]}),
            limits(),
            op2,
            CancellationToken::new(),
        )
        .await
    });
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert!(
        c.exec.cancel(op.as_str()).await,
        "operation should be running"
    );
    let res = task.await.unwrap();
    assert_eq!(reason(&res).as_deref(), Some("cancelled"), "{res:?}");
    assert!(t.elapsed() < Duration::from_secs(5), "{:?}", t.elapsed());
    assert!(!c.exec.cancel(op.as_str()).await, "no longer running");
    let su = c.cluster.superuser("lure").await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let active: i64 = su
        .query_one(
            "SELECT count(*) FROM pg_stat_activity WHERE usename = $1 AND state = 'active'",
            &[&READER],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(
        active, 0,
        "the slow statement must have been cancelled server-side"
    );

    // broker cancellation token
    let token = CancellationToken::new();
    let exec = c.exec.clone();
    let (r2, g2, t2) = (r.clone(), g.clone(), token.clone());
    let task = tokio::spawn(async move {
        run_with(
            &exec,
            &r2,
            &g2,
            QV,
            json!({"view": "analytics.slow_view", "fields": ["n"]}),
            limits(),
            OperationId::generate(),
            t2,
        )
        .await
    });
    tokio::time::sleep(Duration::from_millis(400)).await;
    token.cancel();
    assert_eq!(reason(&task.await.unwrap()).as_deref(), Some("cancelled"));
}

async fn end_sessions_and_expiry(c: &Ctx) {
    let r = c.res(json!({"statement_timeout_ms": 30000}));
    let su = c.cluster.superuser("lure").await;
    // Sessions of other grants (earlier scenarios) stay open; compare against them.
    let baseline = reader_backends(&su).await;
    let g = c.reader(&r).await;
    run(&c.exec, &r, &g, QV, daily(json!({"limit": 1})), limits())
        .await
        .unwrap();
    assert_eq!(c.exec.postgres_open_sessions(g.as_str()), 1);
    assert_eq!(reader_backends(&su).await, baseline + 1);
    // a running operation is cancelled by end_sessions
    let exec = c.exec.clone();
    let (r2, g2) = (r.clone(), g.clone());
    let running = tokio::spawn(async move {
        run(
            &exec,
            &r2,
            &g2,
            QV,
            json!({"view": "analytics.slow_view", "fields": ["n"]}),
            limits(),
        )
        .await
    });
    tokio::time::sleep(Duration::from_millis(500)).await;
    let t = Instant::now();
    let report = c.exec.end_sessions(g.as_str()).await;
    assert_eq!(
        report.status,
        aipass_types::models::LevelStatus::Done,
        "{report:?}"
    );
    assert!(
        t.elapsed() < Duration::from_secs(5),
        "A09 target: {:?}",
        t.elapsed()
    );
    assert_eq!(
        reason(&running.await.unwrap()).as_deref(),
        Some("cancelled")
    );
    assert!(!c.exec.has_credential(g.as_str()));
    assert_eq!(c.exec.postgres_open_sessions(g.as_str()), 0);
    let mut n = baseline + 1;
    for _ in 0..40 {
        n = reader_backends(&su).await;
        if n == baseline {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(n, baseline, "the grant's database sessions must be closed");
    let res = run(&c.exec, &r, &g, QV, daily(json!({})), limits()).await;
    assert_eq!(code(&res), Some(ErrorCode::SecretUnavailable));

    // expiry
    let mut m = db_material(&r, READER, READER_PASS, "127.0.0.1", PORT);
    m.expires_at = chrono::Utc::now() + chrono::Duration::seconds(1);
    let g = grant_with(&c.exec, m).await;
    run(&c.exec, &r, &g, QV, daily(json!({"limit": 1})), limits())
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(1600)).await;
    let res = run(&c.exec, &r, &g, QV, daily(json!({})), limits()).await;
    assert_eq!(code(&res), Some(ErrorCode::SecretUnavailable));
    c.exec.sweep().await;
    assert_eq!(c.exec.postgres_open_sessions(g.as_str()), 0);

    // drop_credential
    let g = c.reader(&r).await;
    run(&c.exec, &r, &g, QV, daily(json!({"limit": 1})), limits())
        .await
        .unwrap();
    c.exec.drop_credential(g.as_str()).await;
    assert!(!c.exec.has_credential(g.as_str()));
    assert_eq!(c.exec.postgres_open_sessions(g.as_str()), 0);
}

async fn privileged_roles_refused(c: &Ctx) {
    let r = c.res(json!({}));
    for (user, pass) in [
        ("ai_super", SUPER_ROLE_PASS),
        ("ai_bypass", BYPASS_PASS),
        ("ai_files", FILES_PASS),
    ] {
        let g = c.grant(&r, user, pass).await;
        let res = run(&c.exec, &r, &g, QV, daily(json!({})), limits()).await;
        assert_eq!(code(&res), Some(ErrorCode::ScopeDenied), "{user}: {res:?}");
        assert_eq!(reason(&res).as_deref(), Some("privileged_role"), "{user}");
        assert_no_leak(&res, pass, user);
    }
    let allowed = c.res(json!({"allow_superuser": true}));
    let g = c.grant(&allowed, "ai_super", SUPER_ROLE_PASS).await;
    run(
        &c.exec,
        &allowed,
        &g,
        QV,
        daily(json!({"limit": 1})),
        limits(),
    )
    .await
    .expect("allow_superuser permits it");
}

async fn output_filter_redacts_injected_credentials(c: &Ctx) {
    let r = c.res(json!({}));
    let g = c.reader(&r).await;
    let res = run(&c.exec, &r, &g, QV, json!({"view": "analytics.notes", "fields": ["id", "plan", "note"], "order_by": [{"field": "id"}]}), limits()).await;
    assert_no_leak(&res, READER_PASS, "reader password");
    assert_no_leak(&res, GHP, "ghp token");
    assert_no_leak(&res, "AKIAIOSFODNN7EXAMPLE", "aws key");
    assert_no_leak(&res, "hunter2", "dsn");
    let out = res.unwrap();
    let rows = out.data["rows"].as_array().unwrap();
    assert_eq!(rows[0]["note"], "normal note");
    for row in &rows[1..5] {
        assert_eq!(row["note"], "[REDACTED]", "{row}");
        assert!(row["plan"].is_string());
    }
    assert_eq!(out.restricted_fields, vec!["note".to_owned()]);
}

async fn credential_custody(c: &Ctx) {
    let r = c.res(json!({}));
    let info = c.exec.info();
    let m = db_material(&r, READER, READER_PASS, "127.0.0.1", PORT);
    let aad = CredentialAad {
        approval_request_id: ApprovalRequestId::generate(),
        digest: "digest-1".into(),
        executor_id: c.exec.executor_id().clone(),
    };
    let sealed =
        aipass_types::exec::seal_credential(&info.kem_pk, &aad.to_bytes().unwrap(), &m).unwrap();
    let g = GrantId::generate();
    // Wrong digest / wrong executor → INTEGRITY_FAILED.
    let wrong = CredentialAad {
        digest: "digest-2".into(),
        ..aad.clone()
    };
    let e = c
        .exec
        .install_credential(g.as_str(), &sealed, &wrong)
        .await
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::IntegrityFailed);
    let other = CredentialAad {
        executor_id: ExecutorId::generate(),
        ..aad.clone()
    };
    let e = c
        .exec
        .install_credential(g.as_str(), &sealed, &other)
        .await
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::IntegrityFailed);
    assert!(!format!("{e:?}").contains(READER_PASS));
    // Correct envelope installs and works.
    c.exec
        .install_credential(g.as_str(), &sealed, &aad)
        .await
        .unwrap();
    run(&c.exec, &r, &g, QV, daily(json!({"limit": 1})), limits())
        .await
        .unwrap();
    let dbg = format!("{:?}", c.exec);
    assert!(!dbg.contains(READER_PASS) && !dbg.contains(READER), "{dbg}");

    // Credential of another resource (entry mismatch) → refused.
    let other_res = c.res(json!({}));
    let res = run(&c.exec, &other_res, &g, QV, daily(json!({})), limits()).await;
    assert_eq!(reason(&res).as_deref(), Some("credential_entry_mismatch"));
    // Credential saved for another server → refused before connecting.
    let g2 = grant_with(
        &c.exec,
        db_material(&r, READER, READER_PASS, "db.elsewhere.example", 5432),
    )
    .await;
    let res = run(&c.exec, &r, &g2, QV, daily(json!({})), limits()).await;
    assert_eq!(reason(&res).as_deref(), Some("credential_target_mismatch"));
    // Wrong password → INTERACTIVE_AUTH_REQUIRED, password never echoed.
    let g3 = c.grant(&r, READER, "Wrong-Pw-xyz-123").await;
    let res = run(&c.exec, &r, &g3, QV, daily(json!({})), limits()).await;
    assert_eq!(
        code(&res),
        Some(ErrorCode::InteractiveAuthRequired),
        "{res:?}"
    );
    assert_no_leak(&res, "Wrong-Pw-xyz-123", "wrong pw");
    // Tampered normalized request (digest does not match params) → INTEGRITY_FAILED.
    let mut norm = c.exec.normalize(&r, QV, &daily(json!({}))).unwrap();
    norm.params["view"] = json!("analytics.notes");
    norm.params["fields"] = json!(["note"]);
    let res = c
        .exec
        .execute(aipass_types::exec::ExecutionRequest {
            operation_id: OperationId::generate(),
            grant_id: g.clone(),
            resource: r.clone(),
            normalized: norm,
            remaining: limits(),
            cancel: CancellationToken::new(),
        })
        .await;
    assert_eq!(code(&res), Some(ErrorCode::IntegrityFailed));
    // Resource bound to another executor → refused.
    let mut foreign = r.clone();
    foreign.executor_id = ExecutorId::generate();
    let res = run(&c.exec, &foreign, &g, QV, daily(json!({})), limits()).await;
    assert_eq!(reason(&res).as_deref(), Some("wrong_executor"));
    // Control channel lost → new operations denied.
    c.exec.set_control_channel_ok(false);
    let res = run(&c.exec, &r, &g, QV, daily(json!({})), limits()).await;
    assert_eq!(code(&res), Some(ErrorCode::ControlChannelLost));
    c.exec.set_control_channel_ok(true);
    // Static credentials: nothing to revoke upstream, reported honestly.
    let rep = c.exec.revoke_upstream(g.as_str()).await;
    assert_eq!(
        rep.status,
        aipass_types::models::LevelStatus::NotApplicable,
        "{rep:?}"
    );
}

async fn sslmodes(c: &Ctx) {
    let ca = c.cluster.pki.ca_pem.clone();
    let other_ca = support::certs::TestPki::new(&["unrelated"]).ca_pem;
    for (extra, ok) in [
        (json!({"sslmode": "disable"}), true),
        (json!({"sslmode": "prefer"}), true),
        (json!({"sslmode": "require"}), true),
        (json!({"sslmode": "require", "ssl_root_cert": ca}), true),
        (
            json!({"sslmode": "require", "ssl_root_cert": other_ca}),
            false,
        ),
        (json!({"sslmode": "verify-full", "ssl_root_cert": ca}), true),
        (
            json!({"sslmode": "verify-full", "ssl_root_cert": other_ca}),
            false,
        ),
        (json!({"sslmode": "verify-full"}), false),
    ] {
        let r = c.res(extra.clone());
        let g = c.reader(&r).await;
        let res = run(&c.exec, &r, &g, QV, daily(json!({"limit": 1})), limits()).await;
        assert_eq!(res.is_ok(), ok, "{extra}: {res:?}");
        if !ok {
            assert_eq!(code(&res), Some(ErrorCode::UpstreamError));
        }
    }
    // The TLS session really is encrypted.
    let r = c.res(json!({"sslmode": "verify-full", "ssl_root_cert": c.cluster.pki.ca_pem.clone()}));
    let g = c.reader(&r).await;
    run(&c.exec, &r, &g, QV, daily(json!({"limit": 1})), limits())
        .await
        .unwrap();
    let su = c.cluster.superuser("lure").await;
    let ssl: i64 = su
        .query_one(
            "SELECT count(*) FROM pg_stat_ssl s JOIN pg_stat_activity a USING (pid) WHERE a.usename = $1 AND s.ssl",
            &[&READER],
        )
        .await
        .unwrap()
        .get(0);
    assert!(ssl >= 1);
}

#[cfg(feature = "experimental")]
async fn rotation(c: &Ctx) {
    use aipass_executor::open_rotation_result;
    let r = c.res(json!({}));
    let g = c.grant(&r, "rotating_user", ROTATE_OLD).await;
    run(&c.exec, &r, &g, QV, daily(json!({"limit": 1})), limits())
        .await
        .unwrap();

    // Fault injection: verification fails → old password restored.
    c.exec.force_rotation_verify_failure_for_tests(true);
    let res = run(
        &c.exec,
        &r,
        &g,
        "credentials.rotate",
        json!({"scheme": "postgres.password"}),
        limits(),
    )
    .await;
    c.exec.force_rotation_verify_failure_for_tests(false);
    let e = res.unwrap_err();
    assert_eq!(
        e.details.get("rotation").and_then(|v| v.as_str()),
        Some("rolled_back"),
        "{e:?}"
    );
    TempCluster::connect_as(PORT, "lure", "rotating_user", ROTATE_OLD)
        .await
        .expect("old password still valid");

    // Real rotation.
    let op = OperationId::generate();
    let out = run_with(
        &c.exec,
        &r,
        &g,
        "credentials.rotate",
        json!({"scheme": "postgres.password"}),
        limits(),
        op.clone(),
        CancellationToken::new(),
    )
    .await
    .expect("rotation");
    assert_eq!(out.data["status"], "rotated");
    assert_eq!(out.side_effects, aipass_types::models::SideEffects::Applied);
    assert!(
        TempCluster::connect_as(PORT, "lure", "rotating_user", ROTATE_OLD)
            .await
            .is_err(),
        "old password revoked"
    );
    // The executor uses the new credential for subsequent operations.
    run(&c.exec, &r, &g, QV, daily(json!({"limit": 1})), limits())
        .await
        .expect("works with new password");
    // Only the approving device can open the result.
    let device = aipass_crypto::KemKeypair::generate();
    let (sealed, aad) = c
        .exec
        .seal_rotation_result(&op, &device.public_key())
        .unwrap();
    let new = open_rotation_result(&device, &aad, &sealed).unwrap();
    assert_eq!(new.version, 2);
    assert_ne!(new.secret.expose(), ROTATE_OLD);
    let leaked = format!("{out:?} {}", serde_json::to_string(&out).unwrap());
    assert!(
        !leaked.contains(new.secret.expose()),
        "new password must not reach the AI"
    );
    TempCluster::connect_as(PORT, "lure", "rotating_user", new.secret.expose())
        .await
        .expect("new password valid");
    let wrong_device = aipass_crypto::KemKeypair::generate();
    assert!(open_rotation_result(&wrong_device, &aad, &sealed).is_err());
    assert!(c.exec.confirm_rotation_persisted(&op));
    assert_eq!(
        c.exec
            .seal_rotation_result(&op, &device.public_key())
            .unwrap_err()
            .code,
        ErrorCode::NotFound
    );
    // Privileged roles are not rotated.
    let g = c.grant(&r, "ai_super", SUPER_ROLE_PASS).await;
    let res = run(
        &c.exec,
        &r,
        &g,
        "credentials.rotate",
        json!({"scheme": "postgres.password"}),
        limits(),
    )
    .await;
    assert_eq!(reason(&res).as_deref(), Some("privileged_role"));
    // Unknown schemes are refused.
    assert_eq!(
        c.exec
            .normalize(&r, "credentials.rotate", &json!({"scheme": "aws.iam"}))
            .unwrap_err()
            .code,
        ErrorCode::InvalidRequest
    );
}

#[cfg(feature = "experimental")]
async fn temporary_role_leases(c: &Ctx) {
    let r = c.res(json!({"lease_mode": "temporary_role", "temporary_role": {"template_role": "analytics_reader", "ttl_seconds": 600}}));
    let g = c.grant(&r, "lease_issuer", ISSUER_PASS).await;
    let out = run(&c.exec, &r, &g, QV, daily(json!({"limit": 3})), limits())
        .await
        .expect("query as temporary role");
    assert_eq!(out.rows, Some(3));
    let leases = c.exec.leases(g.as_str());
    assert_eq!(leases.len(), 1);
    let role = leases[0].upstream_ref.clone();
    assert!(role.starts_with("aipass_l_"));
    let su = c.cluster.superuser("lure").await;
    assert_eq!(role_count(&su, &role).await, 1);
    let backends: i64 = su
        .query_one(
            "SELECT count(*) FROM pg_stat_activity WHERE usename = $1",
            &[&role],
        )
        .await
        .unwrap()
        .get(0);
    assert!(backends >= 1, "queries ran as the temporary role");
    // Reused for the next operation.
    run(&c.exec, &r, &g, QV, daily(json!({"limit": 1})), limits())
        .await
        .unwrap();
    assert_eq!(c.exec.leases(g.as_str()).len(), 1);
    let rep = c.exec.revoke_upstream(g.as_str()).await;
    assert_eq!(
        rep.status,
        aipass_types::models::LevelStatus::Done,
        "{rep:?}"
    );
    assert_eq!(role_count(&su, &role).await, 0, "role dropped");
    assert!(c.exec.leases(g.as_str()).is_empty());

    // Honest failure: the issuer cannot log in any more → failed, role kept, retry later.
    let g = c.grant(&r, "lease_issuer", ISSUER_PASS).await;
    run(&c.exec, &r, &g, QV, daily(json!({"limit": 1})), limits())
        .await
        .unwrap();
    let role = c.exec.leases(g.as_str())[0].upstream_ref.clone();
    su.batch_execute("ALTER ROLE lease_issuer PASSWORD 'changed-elsewhere-123'")
        .await
        .unwrap();
    let rep = c.exec.revoke_upstream(g.as_str()).await;
    assert_eq!(
        rep.status,
        aipass_types::models::LevelStatus::Failed,
        "{rep:?}"
    );
    assert!(rep.detail.as_deref().unwrap_or("").contains(&role));
    assert_eq!(
        role_count(&su, &role).await,
        1,
        "not dropped, and not reported as done"
    );
    su.batch_execute(&format!("ALTER ROLE lease_issuer PASSWORD '{ISSUER_PASS}'"))
        .await
        .unwrap();
    let rep = c.exec.revoke_upstream(g.as_str()).await;
    assert_eq!(
        rep.status,
        aipass_types::models::LevelStatus::Done,
        "{rep:?}"
    );
    assert_eq!(role_count(&su, &role).await, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn postgres_connector_against_temp_cluster() {
    let cluster = TempCluster::start(PORT);
    {
        let su = cluster.superuser("postgres").await;
        su.batch_execute("CREATE DATABASE lure").await.unwrap();
    }
    cluster
        .superuser("lure")
        .await
        .batch_execute(&setup_sql())
        .await
        .expect("schema");
    let c = Ctx {
        cluster,
        exec: executor(),
    };
    macro_rules! scenario {
        ($f:ident) => {{
            eprintln!("--- scenario: {}", stringify!($f));
            $f(&c).await;
        }};
    }
    scenario!(allowed_view_and_fields);
    scenario!(overreach_is_refused);
    scenario!(cross_tenant_rows);
    scenario!(injection_in_every_param);
    scenario!(budgets);
    scenario!(timeout_and_cancel);
    scenario!(end_sessions_and_expiry);
    scenario!(privileged_roles_refused);
    scenario!(output_filter_redacts_injected_credentials);
    scenario!(credential_custody);
    scenario!(sslmodes);
    #[cfg(feature = "experimental")]
    {
        scenario!(rotation);
        scenario!(temporary_role_leases);
    }
    c.exec.shutdown().await;
    let _ = EntryKind::Database;
}
