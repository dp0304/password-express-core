// SPDX-License-Identifier: Apache-2.0
//! Declarative `http_api` connector and the egress guard (A06 SSRF / redirects / DNS,
//! A18 output filter and error hygiene) against a local HTTPS server with a test CA.

mod support;

use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use aipass_executor::{EgressResolver, StaticResolver};
use aipass_types::ErrorCode;
use aipass_types::exec::ExecutorBackend;
use aipass_types::models::{Connector, Limits, SideEffects};
use aipass_types::vault::EntryKind;
use async_trait::async_trait;
use serde_json::{Value, json};
use support::tls_server::{Hit, Reply, TlsServer};
use support::*;

const SECRET: &str = "live_key_7b1f2c3d4e5f6a7b8c9d";
const OP: &str = "http_api.call";

fn handler(port: u16) -> Arc<dyn Fn(&Hit) -> Reply + Send + Sync> {
    Arc::new(move |hit: &Hit| {
        let path = hit.target.split('?').next().unwrap_or("").to_owned();
        match path.as_str() {
            "/v1/orders" => Reply::json(
                200,
                json!({
                    "data": [
                        {"id": 1, "status": "open", "customer_email": "a@example.com", "note": "ok"},
                        {"id": 2, "status": "open", "customer_email": "b@example.com", "note": format!("Bearer {SECRET}")}
                    ],
                    "meta": {"internal_cursor": "abc"}
                }),
            ),
            p if p.starts_with("/v1/orders/") => Reply::json(
                200,
                json!({"id": p.trim_start_matches("/v1/orders/"), "status": "open", "internal": "x"}),
            ),
            "/v1/echo" => {
                let headers: serde_json::Map<String, Value> = hit
                    .headers
                    .iter()
                    .map(|(k, v)| (k.clone(), Value::String(v.clone())))
                    .collect();
                let mut r = Reply::json(
                    200,
                    json!({"headers": headers, "query": hit.target.split_once('?').map(|x| x.1).unwrap_or("")}),
                );
                r.headers
                    .push(("set-cookie".into(), "session=server-side-secret".into()));
                r
            }
            "/v1/redirect" => Reply {
                status: 302,
                headers: vec![(
                    "location".into(),
                    format!("https://evil.test.example:{port}/steal"),
                )],
                body: Vec::new(),
                delay: None,
            },
            "/v1/big" => Reply {
                status: 200,
                headers: vec![("content-type".into(), "application/json".into())],
                body: format!("{{\"x\":\"{}\"}}", "a".repeat(2 * 1024 * 1024)).into_bytes(),
                delay: None,
            },
            "/v1/slow" | "/v1/slow-write" => Reply {
                delay: Some(Duration::from_secs(2)),
                ..Reply::json(200, json!({"id": 1}))
            },
            "/v1/fail" => Reply::json(
                500,
                json!({"error": format!("bad key {SECRET} in {}", hit.target)}),
            ),
            "/v1/refunds" => Reply::json(
                201,
                json!({"id": "rf_1", "status": "succeeded", "card": "4242 4242 4242 4242"}),
            ),
            "/v1/keys" => Reply::json(200, json!({"key": "sk-live-abcdefghijklmnopqrstuvwx"})),
            _ => Reply::json(404, json!({"error": "nope"})),
        }
    })
}

fn ops() -> Value {
    json!({
        "list_orders": {"method": "GET", "path": "/orders",
            "query": {"status": {"type": "string", "enum": ["open", "closed"]}, "limit": {"type": "integer", "min": 1, "max": 100}},
            "side_effect": "read", "retry_safe": true,
            "response": {"items_path": "data", "allowed_fields": ["id", "status", "note"]}},
        "get_order": {"method": "GET", "path": "/orders/{order_id}", "path_params": {"order_id": {"type": "string", "max": 64}},
            "side_effect": "read", "retry_safe": true, "response": {"allowed_fields": ["id", "status"]}},
        "echo": {"method": "GET", "path": "/echo", "side_effect": "read", "retry_safe": true,
            "response": {"allowed_fields": ["headers", "query"]}},
        "redirect": {"method": "GET", "path": "/redirect", "side_effect": "read", "response": {"allowed_fields": ["x"]}},
        "big": {"method": "GET", "path": "/big", "side_effect": "read", "response": {"allowed_fields": ["x"]}},
        "slow": {"method": "GET", "path": "/slow", "side_effect": "read", "response": {"allowed_fields": ["id"]}},
        "slow_write": {"method": "POST", "path": "/slow-write", "side_effect": "write",
            "body_schema": {"type": "object", "properties": {"n": {"type": "integer"}}}, "response": {"allowed_fields": ["id"]}},
        "fail": {"method": "GET", "path": "/fail", "side_effect": "read", "response": {"allowed_fields": ["error"]}},
        "refund": {"method": "POST", "path": "/refunds", "side_effect": "irreversible", "retry_safe": false,
            "body_schema": {"type": "object", "required": ["amount"], "properties": {
                "amount": {"type": "integer", "minimum": 1, "maximum": 10000}, "reason": {"type": "string", "enum": ["duplicate", "fraud"]}}},
            "response": {"allowed_fields": ["id", "status"]}},
        "keys": {"method": "GET", "path": "/keys", "side_effect": "read",
            "response": {"allowed_fields": ["key"], "on_secret_detected": "withhold"}}
    })
}

fn cfg(base: &str, auth: Value, private: bool, extra: Value) -> Value {
    let mut c = json!({"base_url": base, "auth": auth, "allow_private_network": private, "operations": ops()});
    if let (Value::Object(b), Value::Object(e)) = (&mut c, extra) {
        for (k, v) in e {
            b.insert(k, v);
        }
    }
    c
}

fn call(op: &str, params: Value) -> Value {
    json!({"operation": op, "params": params})
}

/// Answers 127.0.0.1 once, then 127.0.0.2 (nothing listens there): proves the client uses
/// the vetted address rather than resolving again.
#[derive(Debug, Default)]
struct FlipResolver {
    n: AtomicUsize,
}

#[async_trait]
impl EgressResolver for FlipResolver {
    async fn resolve(
        &self,
        _host: &str,
    ) -> Result<Vec<IpAddr>, aipass_executor::egress::EgressError> {
        let i = self.n.fetch_add(1, Ordering::SeqCst);
        Ok(vec![if i == 0 {
            "127.0.0.1".parse().unwrap()
        } else {
            "127.0.0.2".parse().unwrap()
        }])
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http_api_connector_and_egress_guard() {
    // The redirect target needs the port, known only after bind: look it up lazily.
    let port_cell = Arc::new(std::sync::atomic::AtomicU16::new(0));
    let pc = port_cell.clone();
    let server = TlsServer::start(
        &["api.test.example", "evil.test.example"],
        Arc::new(move |h: &Hit| handler(pc.load(Ordering::SeqCst))(h)),
    )
    .await;
    let port = server.addr.port();
    port_cell.store(port, Ordering::SeqCst);

    let resolver = Arc::new(StaticResolver::new());
    let lo: IpAddr = "127.0.0.1".parse().unwrap();
    resolver.set("api.test.example", vec![lo]);
    resolver.set("evil.test.example", vec![lo]);
    resolver.set("localhost.test.example", vec![lo]);
    resolver.set("internal.test.example", vec!["10.0.0.5".parse().unwrap()]);
    resolver.set(
        "mixed.test.example",
        vec!["93.184.216.34".parse().unwrap(), lo],
    );
    resolver.set(
        "meta.test.example",
        vec!["169.254.169.254".parse().unwrap()],
    );
    resolver.set("v6local.test.example", vec!["::1".parse().unwrap()]);
    let exec = Arc::new(
        builder()
            .resolver(resolver.clone())
            .webpki_roots(false)
            .add_root_certificates_pem(&server.pki.ca_pem)
            .unwrap()
            .build()
            .unwrap(),
    );
    let base = format!("https://api.test.example:{port}/v1");
    let r = resource(
        &exec,
        Connector::HttpApi,
        cfg(&base, json!({"type": "bearer"}), true, json!({})),
        &[OP],
    );
    let g = grant_with(&exec, material(&r, EntryKind::ApiKey, None, SECRET, 600)).await;

    // Happy path: allowlisted fields, secret in an allowed field redacted.
    let before = resolver.lookups();
    let res = run(
        &exec,
        &r,
        &g,
        OP,
        call("list_orders", json!({"status": "open", "limit": 10})),
        limits(),
    )
    .await;
    assert_no_leak(&res, SECRET, "list_orders");
    let out = res.unwrap();
    assert_eq!(
        resolver.lookups() - before,
        1,
        "exactly one DNS resolution per request"
    );
    assert_eq!(out.rows, Some(2));
    assert_eq!(
        out.data["items"][0],
        json!({"id": 1, "status": "open", "note": "ok"})
    );
    assert_eq!(out.data["items"][1]["note"], "[REDACTED]");
    assert_eq!(out.restricted_fields, vec!["note".to_owned()]);
    assert!(!out.data.to_string().contains("customer_email"));
    assert_eq!(out.side_effects, SideEffects::None);
    let hit = server.hits().last().cloned().unwrap();
    assert_eq!(hit.host, format!("api.test.example:{port}"));
    assert_eq!(
        hit.target, "/v1/orders?limit=10&status=open",
        "normalized (sorted) query"
    );
    assert_eq!(
        hit.header("authorization"),
        Some(format!("Bearer {SECRET}").as_str())
    );

    // Path params are encoded as one segment; no traversal, no query injection.
    let out = run(
        &exec,
        &r,
        &g,
        OP,
        call("get_order", json!({"order_id": "a/../../admin?x=1#y"})),
        limits(),
    )
    .await
    .unwrap();
    assert_eq!(
        server.hits().last().unwrap().target,
        "/v1/orders/a%2F..%2F..%2Fadmin%3Fx%3D1%23y"
    );
    assert_eq!(
        out.data["item"],
        json!({"id": "a%2F..%2F..%2Fadmin%3Fx%3D1%23y", "status": "open"})
    );
    for bad in [
        call("get_order", json!({"order_id": ".."})),
        call("get_order", json!({})),
        call("list_orders", json!({"status": "deleted"})),
        call("list_orders", json!({"limit": 1000})),
        call("list_orders", json!({"url": "https://evil.test.example/"})),
        json!({"operation": "list_orders", "url": "https://evil.test.example/"}),
        call("delete_all", json!({})),
        json!({"operation": "refund", "body": {"amount": 0}}),
        json!({"operation": "refund", "body": {"amount": 5, "to_account": "evil"}}),
        json!({"operation": "refund", "body": {"amount": 1.5}}),
    ] {
        let e = run(&exec, &r, &g, OP, bad.clone(), limits())
            .await
            .unwrap_err();
        assert!(
            matches!(e.code, ErrorCode::InvalidRequest | ErrorCode::ScopeDenied),
            "{bad}: {e:?}"
        );
    }

    // Writes: validated body sent, side effects applied.
    let out = run(
        &exec,
        &r,
        &g,
        OP,
        json!({"operation": "refund", "body": {"amount": 5, "reason": "duplicate"}}),
        limits(),
    )
    .await
    .unwrap();
    assert_eq!(out.side_effects, SideEffects::Applied);
    assert_eq!(
        out.data["item"],
        json!({"id": "rf_1", "status": "succeeded"})
    );
    let hit = server.hits().last().cloned().unwrap();
    assert_eq!(hit.method, "POST");
    assert_eq!(
        serde_json::from_slice::<Value>(&hit.body).unwrap(),
        json!({"amount": 5, "reason": "duplicate"})
    );

    // Redirect to another origin: not followed, the other origin never sees a request.
    let res = run(&exec, &r, &g, OP, call("redirect", json!({})), limits()).await;
    let e = res.unwrap_err();
    assert_eq!(e.code, ErrorCode::UpstreamError);
    assert_eq!(e.details["reason"], "redirect_not_followed");
    assert!(
        server
            .hits()
            .iter()
            .all(|h| h.host.starts_with("api.test.example")),
        "credentials only ever went to the pinned origin"
    );

    // Size cap, timeouts, upstream errors without secrets.
    let e = run(&exec, &r, &g, OP, call("big", json!({})), limits())
        .await
        .unwrap_err();
    assert_eq!(e.details["reason"], "response_too_large");
    let fast = resource(
        &exec,
        Connector::HttpApi,
        cfg(
            &base,
            json!({"type": "query", "name": "api_key"}),
            true,
            json!({"timeout_ms": 500}),
        ),
        &[OP],
    );
    let gq = grant_with(&exec, material(&fast, EntryKind::ApiKey, None, SECRET, 600)).await;
    let res = run(&exec, &fast, &gq, OP, call("slow", json!({})), limits()).await;
    assert_eq!(res.as_ref().unwrap_err().details["reason"], "timeout");
    assert_no_leak(&res, SECRET, "timeout error");
    let res = run(
        &exec,
        &fast,
        &gq,
        OP,
        json!({"operation": "slow_write", "body": {"n": 1}}),
        limits(),
    )
    .await;
    assert_eq!(
        res.as_ref().unwrap_err().code,
        ErrorCode::UpstreamOutcomeUnknown,
        "a timed-out write may have been applied"
    );
    assert_no_leak(&res, SECRET, "write timeout");
    let res = run(&exec, &fast, &gq, OP, call("fail", json!({})), limits()).await;
    assert_eq!(res.as_ref().unwrap_err().code, ErrorCode::UpstreamError);
    assert_no_leak(&res, SECRET, "500 with key in body and URL");
    assert!(
        server.hits().last().unwrap().target.contains("api_key="),
        "query auth was used"
    );

    // Withhold policy → RESULT_RESTRICTED.
    let e = run(&exec, &r, &g, OP, call("keys", json!({})), limits())
        .await
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::ResultRestricted);
    assert!(!error_text(&e).contains("sk-live"));

    // Every auth placement; an upstream echoing the credential back is redacted (A18).
    for (auth, user) in [
        (json!({"type": "bearer"}), None),
        (json!({"type": "header", "name": "X-Api-Key"}), None),
        (json!({"type": "query", "name": "api_key"}), None),
        (json!({"type": "basic"}), Some("svc-account")),
    ] {
        let ra = resource(
            &exec,
            Connector::HttpApi,
            cfg(&base, auth.clone(), true, json!({})),
            &[OP],
        );
        let ga = grant_with(
            &exec,
            material(
                &ra,
                if user.is_some() {
                    EntryKind::Login
                } else {
                    EntryKind::ApiKey
                },
                user,
                SECRET,
                600,
            ),
        )
        .await;
        let res = run(&exec, &ra, &ga, OP, call("echo", json!({})), limits()).await;
        assert_no_leak(&res, SECRET, &auth);
        assert_no_leak(
            &res,
            "server-side-secret",
            "response headers are never returned",
        );
        let out = res.unwrap();
        assert!(!out.restricted_fields.is_empty(), "{auth}: {}", out.data);
        if let Some(u) = user {
            assert_no_leak(&Ok(out.clone()), u, "basic username");
        }
    }

    // Budget caps.
    let one = Limits {
        max_rows_per_grant: 1,
        ..limits()
    };
    let out = run(&exec, &r, &g, OP, call("list_orders", json!({})), one)
        .await
        .unwrap();
    assert_eq!(out.rows, Some(1));
    assert!(out.truncated);
    let none = Limits {
        max_rows_per_grant: 0,
        ..limits()
    };
    let e = run(&exec, &r, &g, OP, call("list_orders", json!({})), none)
        .await
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::BudgetExhausted);

    // SSRF table (A06): nothing reaches the server and the credential is never sent.
    let hits_before = server.hits().len();
    let blocked = [
        format!("https://127.0.0.1:{port}/v1"),
        format!("https://localhost.test.example:{port}/v1"),
        "https://internal.test.example/v1".to_owned(),
        "https://10.1.2.3/v1".to_owned(),
        "https://172.16.0.9/v1".to_owned(),
        "https://192.168.1.1/v1".to_owned(),
        "https://169.254.169.254/latest/meta-data".to_owned(),
        format!("https://[::1]:{port}/v1"),
        format!("https://[::ffff:127.0.0.1]:{port}/v1"),
        "https://[fd00:ec2::254]/v1".to_owned(),
        "https://[fe80::1]/v1".to_owned(),
        format!("https://0x7f000001:{port}/v1"),
        format!("https://2130706433:{port}/v1"),
        format!("https://127.1:{port}/v1"),
        "https://100.64.0.1/v1".to_owned(),
        "https://mixed.test.example/v1".to_owned(),
        format!("https://v6local.test.example:{port}/v1"),
        "https://224.0.0.1/v1".to_owned(),
        "https://0.0.0.0/v1".to_owned(),
    ];
    for b in &blocked {
        let rb = resource(
            &exec,
            Connector::HttpApi,
            cfg(b, json!({"type": "bearer"}), false, json!({})),
            &[OP],
        );
        let gb = grant_with(&exec, material(&rb, EntryKind::ApiKey, None, SECRET, 600)).await;
        let res = run(
            &exec,
            &rb,
            &gb,
            OP,
            call("list_orders", json!({})),
            limits(),
        )
        .await;
        let e = res.as_ref().unwrap_err();
        assert_eq!(e.code, ErrorCode::ScopeDenied, "{b}: {e:?}");
        assert_eq!(e.details["reason"], "blocked_address", "{b}");
        assert_no_leak(&res, SECRET, b);
    }
    // Metadata stays blocked even with allow_private_network.
    for b in [
        "https://169.254.169.254/v1",
        "https://meta.test.example/v1",
        "https://[fd00:ec2::254]/v1",
        "https://100.100.100.200/v1",
    ] {
        let rb = resource(
            &exec,
            Connector::HttpApi,
            cfg(b, json!({"type": "bearer"}), true, json!({})),
            &[OP],
        );
        let gb = grant_with(&exec, material(&rb, EntryKind::ApiKey, None, SECRET, 600)).await;
        let e = run(
            &exec,
            &rb,
            &gb,
            OP,
            call("list_orders", json!({})),
            limits(),
        )
        .await
        .unwrap_err();
        assert_eq!(e.details["range"], "cloud_metadata", "{b}");
    }
    assert_eq!(
        server.hits().len(),
        hits_before,
        "no blocked destination was contacted"
    );
    // Plain http / user-info in the base URL are invalid configurations.
    for b in [
        format!("http://api.test.example:{port}/v1"),
        format!("https://user:pw@api.test.example:{port}/v1"),
    ] {
        let rb = resource(
            &exec,
            Connector::HttpApi,
            cfg(&b, json!({"type": "bearer"}), true, json!({})),
            &[OP],
        );
        let e = exec
            .normalize(&rb, OP, &call("list_orders", json!({})))
            .unwrap_err();
        assert_eq!(e.code, ErrorCode::InvalidRequest, "{b}");
    }

    // DNS pinning: the vetted address is used even though "DNS" changes afterwards.
    let flip = Arc::new(FlipResolver::default());
    let exec2 = Arc::new(
        builder()
            .resolver(flip.clone())
            .webpki_roots(false)
            .add_root_certificates_pem(&server.pki.ca_pem)
            .unwrap()
            .build()
            .unwrap(),
    );
    let r2 = resource(
        &exec2,
        Connector::HttpApi,
        cfg(&base, json!({"type": "bearer"}), true, json!({})),
        &[OP],
    );
    let g2 = grant_with(&exec2, material(&r2, EntryKind::ApiKey, None, SECRET, 600)).await;
    run(
        &exec2,
        &r2,
        &g2,
        OP,
        call("list_orders", json!({})),
        limits(),
    )
    .await
    .expect("pinned to the vetted 127.0.0.1");
    assert_eq!(flip.n.load(Ordering::SeqCst), 1);
    // TLS: an executor that does not trust the test CA refuses the server.
    let untrusting = Arc::new(builder().resolver(resolver.clone()).build().unwrap());
    let r3 = resource(
        &untrusting,
        Connector::HttpApi,
        cfg(&base, json!({"type": "bearer"}), true, json!({})),
        &[OP],
    );
    let g3 = grant_with(
        &untrusting,
        material(&r3, EntryKind::ApiKey, None, SECRET, 600),
    )
    .await;
    let e = run(
        &untrusting,
        &r3,
        &g3,
        OP,
        call("list_orders", json!({})),
        limits(),
    )
    .await
    .unwrap_err();
    assert_eq!(e.code, ErrorCode::UpstreamError);

    // Resource-level specs list the declared operations.
    let specs = exec.resource_operation_specs(&r);
    assert_eq!(specs.len(), 1);
    assert_eq!(specs[0].name, OP);
    assert_eq!(
        specs[0].side_effect,
        aipass_types::models::SideEffectClass::Irreversible
    );
    assert!(
        specs[0].parameters_schema["properties"]["operation"]["enum"]
            .as_array()
            .unwrap()
            .contains(&json!("list_orders"))
    );
    assert!(specs[0].parameters_schema["x-operations"]["refund"]["body"].is_object());
    // scope: http_api.operations must cover the declared operation.
    let norm = exec
        .normalize(&r, OP, &call("list_orders", json!({})))
        .unwrap();
    let scope = aipass_types::models::GrantScope {
        operations: vec![OP.into()],
        http_api: Some(aipass_types::models::HttpApiScope {
            operations: vec!["get_order".into()],
        }),
        ..Default::default()
    };
    assert!(!exec.scope_covers(&scope, &limits(), &norm));
    let scope = aipass_types::models::GrantScope {
        http_api: Some(aipass_types::models::HttpApiScope {
            operations: vec!["list_orders".into()],
        }),
        ..scope
    };
    assert!(exec.scope_covers(&scope, &limits(), &norm));
}

/// Upstream for the write-path regressions (EGR-01/02/03).
fn write_handler(port: u16) -> Arc<dyn Fn(&Hit) -> Reply + Send + Sync> {
    Arc::new(move |hit: &Hit| {
        let path = hit.target.split('?').next().unwrap_or("").to_owned();
        match path.as_str() {
            "/v1/refunds" => Reply::json(201, json!({"id": "rf_1", "status": "succeeded"})),
            "/v1/things" => Reply::json(201, json!({"id": "t_1"})),
            "/v1/payments" => Reply {
                status: 303,
                headers: vec![(
                    "location".into(),
                    format!("https://api.test.example:{port}/v1/payments/pay_1"),
                )],
                body: Vec::new(),
                delay: None,
            },
            "/v1/exports" => Reply {
                status: 201,
                headers: vec![("content-type".into(), "application/json".into())],
                body: format!("{{\"id\":\"{}\"}}", "e".repeat(2 * 1024 * 1024)).into_bytes(),
                delay: None,
            },
            "/v1/keys" => Reply::json(
                201,
                json!({"id": "key_1", "key": "sk-live-abcdefghijklmnopqrstuvwx"}),
            ),
            "/v1/notes" => Reply::json(201, json!({"id": "n_1", "text": "x".repeat(400)})),
            "/v1/bulk" => Reply::json(201, json!([{"id": 1}, {"id": 2}])),
            _ => Reply::json(404, json!({"error": "nope"})),
        }
    })
}

fn write_ops() -> Value {
    let obj = json!({"type": "object", "properties": {"n": {"type": "integer"}}});
    json!({
        "refund": {"method": "POST", "path": "/refunds", "side_effect": "irreversible", "retry_safe": false,
            "body_schema": {"type": "object", "required": ["amount"], "properties": {
                "amount": {"type": "integer", "minimum": 1, "maximum": 10000}}},
            "response": {"allowed_fields": ["id", "status"]}},
        "create_thing": {"method": "POST", "path": "/things", "side_effect": "write",
            "body_schema": obj, "response": {"allowed_fields": ["id"]}},
        "create_payment": {"method": "POST", "path": "/payments", "side_effect": "irreversible",
            "body_schema": obj, "response": {"allowed_fields": ["id"]}},
        "create_export": {"method": "POST", "path": "/exports", "side_effect": "write",
            "body_schema": obj, "response": {"allowed_fields": ["id"]}},
        "create_key": {"method": "POST", "path": "/keys", "side_effect": "write",
            "body_schema": obj,
            "response": {"allowed_fields": ["id", "key"], "on_secret_detected": "withhold"}},
        "create_note": {"method": "POST", "path": "/notes", "side_effect": "write",
            "body_schema": obj, "response": {"allowed_fields": ["id", "text"]}},
        "bulk_create": {"method": "POST", "path": "/bulk", "side_effect": "write",
            "body_schema": obj, "response": {"allowed_fields": ["id"]}}
    })
}

/// EGR-01 (bodies always schema-validated), EGR-02 (delivered writes answered 3xx /
/// oversized are never "failed, no side effects") and EGR-03 (post-2xx processing errors
/// keep the applied side effect visible to the broker).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http_api_write_paths_are_validated_and_honest() {
    let port_cell = Arc::new(std::sync::atomic::AtomicU16::new(0));
    let pc = port_cell.clone();
    let server = TlsServer::start(
        &["api.test.example"],
        Arc::new(move |h: &Hit| write_handler(pc.load(Ordering::SeqCst))(h)),
    )
    .await;
    let port = server.addr.port();
    port_cell.store(port, Ordering::SeqCst);
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
    let base = format!("https://api.test.example:{port}/v1");
    let r = resource(
        &exec,
        Connector::HttpApi,
        json!({"base_url": base, "auth": {"type": "bearer"}, "allow_private_network": true,
               "operations": write_ops()}),
        &[OP],
    );
    let g = grant_with(&exec, material(&r, EntryKind::ApiKey, None, SECRET, 600)).await;

    // EGR-01: omitting the body does not bypass body_schema; nothing reaches the upstream.
    let hits = server.hits().len();
    for bad in [
        json!({"operation": "refund"}),
        json!({"operation": "refund", "body": null}),
        json!({"operation": "refund", "params": {}}),
    ] {
        let e = exec.normalize(&r, OP, &bad).unwrap_err();
        assert_eq!(e.code, ErrorCode::InvalidRequest, "{bad}: {e:?}");
        assert_eq!(e.details["parameter"], "body", "{bad}: {e:?}");
    }
    assert_eq!(server.hits().len(), hits, "no unvalidated write was sent");
    // A body-less call to a schema that accepts {} sends exactly the normalized {} (and the
    // digest / approval display covers it).
    let norm = exec
        .normalize(&r, OP, &json!({"operation": "create_thing"}))
        .unwrap();
    assert_eq!(norm.params["body"], json!({}), "{}", norm.params);
    let out = run(
        &exec,
        &r,
        &g,
        OP,
        json!({"operation": "create_thing"}),
        limits(),
    )
    .await
    .unwrap();
    assert_eq!(out.side_effects, SideEffects::Applied);
    let hit = server.hits().last().cloned().unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&hit.body).unwrap(),
        json!({})
    );

    // EGR-02: a delivered write answered 303 may have been applied.
    let res = run(
        &exec,
        &r,
        &g,
        OP,
        json!({"operation": "create_payment"}),
        limits(),
    )
    .await;
    let e = res.as_ref().unwrap_err();
    assert_eq!(e.code, ErrorCode::UpstreamOutcomeUnknown, "{e:?}");
    assert_eq!(e.details["reason"], "redirect");
    assert_no_leak(&res, SECRET, "303 write");
    // EGR-02: a 2xx write with an oversized body was applied; only the result is withheld.
    let res = run(
        &exec,
        &r,
        &g,
        OP,
        json!({"operation": "create_export"}),
        limits(),
    )
    .await;
    assert_no_leak(&res, SECRET, "oversized write");
    let out = res.unwrap();
    assert_eq!(out.side_effects, SideEffects::Applied);
    assert_eq!(out.rows, Some(0));
    assert_eq!(out.data["withheld"], true);
    assert_eq!(out.data["reason"], "response_too_large");
    assert_eq!(out.data["status"], 201);
    assert!(out.bytes < 1024 && !out.data.to_string().contains("eeee"));

    // EGR-03: withhold policy on a write → applied, result withheld, nothing leaked.
    let res = run(
        &exec,
        &r,
        &g,
        OP,
        json!({"operation": "create_key"}),
        limits(),
    )
    .await;
    assert_no_leak(&res, "sk-live", "withheld write");
    let out = res.unwrap();
    assert_eq!(out.side_effects, SideEffects::Applied);
    assert_eq!(out.data["withheld"], true);
    assert_eq!(out.data["reason"], "secret_detected");
    assert_eq!(out.rows, Some(0));
    assert!(!out.restricted_fields.is_empty());
    // EGR-03: result larger than max_result_bytes on a write → applied, withheld.
    let small = Limits {
        max_result_bytes: 120,
        ..limits()
    };
    let out = run(
        &exec,
        &r,
        &g,
        OP,
        json!({"operation": "create_note"}),
        small,
    )
    .await
    .unwrap();
    assert_eq!(out.side_effects, SideEffects::Applied);
    assert_eq!(out.data["reason"], "result_too_large");
    assert!(out.bytes <= 120, "{}", out.bytes);
    // EGR-03: an exhausted row budget is refused before the write is sent.
    let hits = server.hits().len();
    let none = Limits {
        max_rows_per_grant: 0,
        ..limits()
    };
    let e = run(&exec, &r, &g, OP, json!({"operation": "bulk_create"}), none)
        .await
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::BudgetExhausted);
    assert_eq!(server.hits().len(), hits, "budget checked before sending");
    let out = run(
        &exec,
        &r,
        &g,
        OP,
        json!({"operation": "bulk_create"}),
        limits(),
    )
    .await
    .unwrap();
    assert_eq!(out.rows, Some(2));
    assert_eq!(out.side_effects, SideEffects::Applied);
}
