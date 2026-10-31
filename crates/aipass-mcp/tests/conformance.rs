// SPDX-License-Identifier: Apache-2.0
//! MCP conformance of the in-process server core: lifecycle and version negotiation,
//! tools/list shape, tools/call results and error mapping, malformed input, batching rules.

mod common;

use std::sync::Arc;

use aipass_mcp::{McpContext, McpServer, McpServerConfig, SUPPORTED_VERSIONS};
use common::{FakeBroker, validate};
use serde_json::{Value, json};

fn server(experimental: bool) -> Arc<McpServer> {
    Arc::new(McpServer::new(McpServerConfig {
        experimental,
        ..Default::default()
    }))
}

async fn send(s: &McpServer, ctx: &McpContext, v: Value) -> Option<Value> {
    s.handle(&serde_json::to_vec(&v).unwrap(), ctx).await
}

async fn init(s: &McpServer, ctx: &McpContext, version: &str) -> Value {
    let r = send(s, ctx, json!({"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {
        "protocolVersion": version, "capabilities": {}, "clientInfo": {"name": "test-host", "version": "1.0"}}}))
    .await
    .unwrap();
    assert!(send(s, ctx, json!({"jsonrpc": "2.0", "method": "notifications/initialized"})).await.is_none());
    r
}

fn ctx_with(b: Arc<FakeBroker>) -> McpContext {
    McpContext::new(b)
}

async fn call(s: &McpServer, ctx: &McpContext, id: i64, name: &str, args: Value) -> Value {
    let r = send(s, ctx, json!({"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": {"name": name, "arguments": args}}))
        .await
        .unwrap();
    assert_eq!(r["id"], id);
    r["result"].clone()
}

#[tokio::test]
async fn initialize_negotiates_each_version() {
    let s = server(false);
    for v in SUPPORTED_VERSIONS {
        let ctx = ctx_with(Arc::new(FakeBroker::new()));
        let r = init(&s, &ctx, v).await;
        assert_eq!(r["jsonrpc"], "2.0");
        assert_eq!(r["id"], 0);
        assert_eq!(r["result"]["protocolVersion"], v, "echoes a supported version");
        assert_eq!(r["result"]["capabilities"]["tools"]["listChanged"], false);
        assert_eq!(r["result"]["serverInfo"]["name"], "aipass");
        let instr = r["result"]["instructions"].as_str().unwrap();
        assert!(instr.contains("approval_required") && instr.contains("operations_status"));
        assert!(instr.contains("绝不在聊天中向用户索要密码"));
        assert_eq!(ctx.session.protocol_version().unwrap().as_str(), v);
        assert!(ctx.session.is_initialized());
        // a second initialize on the same session is rejected
        let again = send(&s, &ctx, json!({"jsonrpc": "2.0", "id": 9, "method": "initialize", "params": {"protocolVersion": v}})).await.unwrap();
        assert_eq!(again["error"]["code"], -32600);
    }
    // unknown version → newest supported
    let ctx = ctx_with(Arc::new(FakeBroker::new()));
    let r = init(&s, &ctx, "2099-01-01").await;
    assert_eq!(r["result"]["protocolVersion"], "2025-11-25");
    // title only from 2025-06-18
    let ctx = ctx_with(Arc::new(FakeBroker::new()));
    assert!(init(&s, &ctx, "2025-03-26").await["result"]["serverInfo"].get("title").is_none());
    // missing protocolVersion
    let ctx = ctx_with(Arc::new(FakeBroker::new()));
    let r = send(&s, &ctx, json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})).await.unwrap();
    assert_eq!(r["error"]["code"], -32602);
    assert!(ctx.session.protocol_version().is_none());
}

#[tokio::test]
async fn lifecycle_gating_ping_and_empty_lists() {
    let s = server(false);
    let ctx = ctx_with(Arc::new(FakeBroker::new()));
    let r = send(&s, &ctx, json!({"jsonrpc": "2.0", "id": "a", "method": "tools/list"})).await.unwrap();
    assert_eq!(r["error"]["code"], -32002);
    assert_eq!(r["id"], "a");
    let p = send(&s, &ctx, json!({"jsonrpc": "2.0", "id": "p", "method": "ping"})).await.unwrap();
    assert_eq!(p["result"], json!({}));
    init(&s, &ctx, "2025-11-25").await;
    for (m, k) in [("resources/list", "resources"), ("prompts/list", "prompts"), ("resources/templates/list", "resourceTemplates")] {
        let r = send(&s, &ctx, json!({"jsonrpc": "2.0", "id": 2, "method": m})).await.unwrap();
        assert_eq!(r["result"][k], json!([]));
    }
    let r = send(&s, &ctx, json!({"jsonrpc": "2.0", "id": 3, "method": "sampling/createMessage"})).await.unwrap();
    assert_eq!(r["error"]["code"], -32601);
    let r = send(&s, &ctx, json!({"jsonrpc": "2.0", "id": 4, "method": "tools/list", "params": {"cursor": "x"}})).await.unwrap();
    assert_eq!(r["error"]["code"], -32602);
}

#[tokio::test]
async fn tools_list_shape_per_version() {
    let name_re = regex::Regex::new(r"^[a-zA-Z0-9_-]{1,64}$").unwrap();
    for (experimental, expect) in [(false, 7usize), (true, 10)] {
        let s = server(experimental);
        for v in SUPPORTED_VERSIONS {
            let ctx = ctx_with(Arc::new(FakeBroker::new()));
            init(&s, &ctx, v).await;
            let r = send(&s, &ctx, json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})).await.unwrap();
            let tools = r["result"]["tools"].as_array().unwrap();
            assert_eq!(tools.len(), expect, "{v}");
            assert!(r["result"].get("nextCursor").is_none());
            let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
            for want in ["resources_list", "operations_request", "operations_status", "operations_cancel", "access_request", "access_release"] {
                assert!(names.contains(&want), "{want} missing");
            }
            assert_eq!(names.contains(&"credentials_rotate"), experimental);
            for t in tools {
                let name = t["name"].as_str().unwrap();
                assert!(name_re.is_match(name), "{name}");
                assert!(!name.contains('.'));
                assert_eq!(t["inputSchema"]["type"], "object");
                assert!(t["description"].as_str().unwrap().len() > 20);
                let modern = v >= "2025-06-18";
                assert_eq!(t.get("outputSchema").is_some(), modern, "{v} {name}");
                assert_eq!(t.get("title").is_some(), modern);
                if modern {
                    assert_eq!(t["outputSchema"]["type"], "object");
                }
                assert_eq!(t.get("annotations").is_some(), v >= "2025-03-26");
                // no tool can name a raw-secret capability
                for banned in ["password", "export", "cookie", "refresh_token", "exec"] {
                    assert!(!name.contains(banned), "{name}");
                }
            }
        }
    }
}

#[tokio::test]
async fn tools_call_happy_path_and_approval_hint() {
    let s = server(false);
    let broker = Arc::new(FakeBroker::new());
    let ctx = ctx_with(broker.clone());
    init(&s, &ctx, "2025-11-25").await;
    let tools = send(&s, &ctx, json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})).await.unwrap();
    let schema_of = |name: &str| {
        tools["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .find(|t| t["name"] == name)
            .unwrap()["outputSchema"]
            .clone()
    };

    let res = call(&s, &ctx, 2, "resources_list", json!({})).await;
    assert_eq!(res["isError"], false);
    validate(&schema_of("resources_list"), &res["structuredContent"], "$").unwrap();
    let rid = res["structuredContent"]["resources"][0]["resource_id"].as_str().unwrap().to_owned();
    assert_eq!(res["content"][0]["type"], "text");
    let text = res["content"][0]["text"].as_str().unwrap();
    let json_part: Value = serde_json::from_str(text.split("\n\n").next().unwrap()).unwrap();
    assert_eq!(json_part, res["structuredContent"], "text block carries the same JSON");

    let res = call(&s, &ctx, 3, "operations_request", json!({
        "resource_id": rid, "operation": "postgres.query_view",
        "parameters": {"view": "analytics.subscription_daily", "fields": ["day", "plan", "subscriptions"], "period_days": 30},
        "idempotency_key": "subscription-summary-request-001"
    })).await;
    assert_eq!(res["isError"], false, "approval_required is not an error");
    let sc = &res["structuredContent"];
    validate(&schema_of("operations_request"), sc, "$").unwrap();
    assert_eq!(sc["status"], "approval_required");
    assert_eq!(sc["expires_in_seconds"], 120);
    assert_eq!(sc["message"], "请在已配对的手机或可信客户端批准本次访问。");
    let text = res["content"][0]["text"].as_str().unwrap();
    assert!(text.contains("operations_status"));
    assert!(text.contains("手机或可信客户端"));
    assert!(text.contains("Never ask the user for passwords"));
    let op_id = sc["operation_id"].as_str().unwrap().to_owned();

    broker.approve_all();
    let res = call(&s, &ctx, 4, "operations_status", json!({"operation_id": op_id})).await;
    assert_eq!(res["isError"], false);
    validate(&schema_of("operations_status"), &res["structuredContent"], "$").unwrap();
    assert_eq!(res["structuredContent"]["status"], "succeeded");
    assert!(res["content"][0]["text"].as_str().unwrap().contains("[REDACTED]"), "restricted fields are mentioned");

    let res = call(&s, &ctx, 5, "operations_cancel", json!({"operation_id": op_id})).await;
    validate(&schema_of("operations_cancel"), &res["structuredContent"], "$").unwrap();
    assert_eq!(res["structuredContent"]["cancelled"], false);

    let res = call(&s, &ctx, 6, "access_request", json!({"resource_id": rid, "operations": ["postgres.query_view"], "duration_seconds": 900, "reason": "weekly report"})).await;
    validate(&schema_of("access_request"), &res["structuredContent"], "$").unwrap();
    assert_eq!(res["structuredContent"]["status"], "pending");
    let apr = res["structuredContent"]["approval_request_id"].as_str().unwrap().to_owned();
    assert!(res["content"][0]["text"].as_str().unwrap().contains("access_status"));
    let res = call(&s, &ctx, 7, "access_status", json!({"approval_request_id": apr})).await;
    validate(&schema_of("access_status"), &res["structuredContent"], "$").unwrap();
    let grant = res["structuredContent"]["grant_id"].as_str().unwrap().to_owned();
    let res = call(&s, &ctx, 8, "access_release", json!({"grant_id": grant})).await;
    validate(&schema_of("access_release"), &res["structuredContent"], "$").unwrap();
    assert_eq!(res["structuredContent"]["status"], "released");
}

#[tokio::test]
async fn tool_errors_are_is_error_results() {
    let s = server(false);
    let broker = Arc::new(FakeBroker::new());
    let ctx = ctx_with(broker.clone());
    init(&s, &ctx, "2025-06-18").await;
    // broker error → isError with {error:{code,message}}, no structuredContent
    broker.fail(Some(common::scope_denied()));
    let res = call(&s, &ctx, 1, "resources_list", json!({})).await;
    assert_eq!(res["isError"], true);
    assert!(res.get("structuredContent").is_none());
    let text = res["content"][0]["text"].as_str().unwrap();
    let j: Value = serde_json::from_str(text.split("\n\n").next().unwrap()).unwrap();
    assert_eq!(j, json!({"error": {"code": "SCOPE_DENIED", "message": "超出本次授权范围"}}));
    assert!(text.contains("access_request"));
    broker.fail(None);
    // invalid arguments → INVALID_REQUEST tool error (never reaches the broker)
    let before = broker.calls.lock().unwrap().len();
    for bad in [
        json!({"resource_id": "res_x", "operation": "postgres.query_view", "parameters": {}, "idempotency_key": "k"}),
        json!({"resource_id": "res_01jbz3k6w8a7m2q4t5v9x0y1z2", "operation": "Bad Op", "parameters": {}, "idempotency_key": "k"}),
        json!({"resource_id": "res_01jbz3k6w8a7m2q4t5v9x0y1z2", "operation": "postgres.query_view", "parameters": [], "idempotency_key": "k"}),
        json!({"resource_id": "res_01jbz3k6w8a7m2q4t5v9x0y1z2", "operation": "postgres.query_view", "parameters": {}, "idempotency_key": ""}),
        json!({"resource_id": "res_01jbz3k6w8a7m2q4t5v9x0y1z2", "operation": "postgres.query_view", "parameters": {}, "idempotency_key": "k", "password": "hunter2"}),
    ] {
        let res = call(&s, &ctx, 2, "operations_request", bad.clone()).await;
        assert_eq!(res["isError"], true, "{bad}");
        let j: Value = serde_json::from_str(res["content"][0]["text"].as_str().unwrap().split("\n\n").next().unwrap()).unwrap();
        assert_eq!(j["error"]["code"], "INVALID_REQUEST", "{bad}");
    }
    assert_eq!(broker.calls.lock().unwrap().len(), before);
    // arguments not an object
    let r = send(&s, &ctx, json!({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "resources_list", "arguments": [1]}})).await.unwrap();
    assert_eq!(r["result"]["isError"], true);
    // unknown tool / experimental tool not offered → protocol error
    for name in ["get_password", "credentials_rotate"] {
        let r = send(&s, &ctx, json!({"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": name, "arguments": {}}})).await.unwrap();
        assert_eq!(r["error"]["code"], -32602, "{name}");
    }
    let r = send(&s, &ctx, json!({"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {}})).await.unwrap();
    assert_eq!(r["error"]["code"], -32602);
    // not found operation (another connection's id) → NOT_FOUND tool error
    let res = call(&s, &ctx, 6, "operations_status", json!({"operation_id": "op_01jbz5c2v7k9m3n4p5q6r7s8t9"})).await;
    let j: Value = serde_json::from_str(res["content"][0]["text"].as_str().unwrap().split("\n\n").next().unwrap()).unwrap();
    assert_eq!(j["error"]["code"], "NOT_FOUND");
}

#[tokio::test]
async fn malformed_input_and_notifications() {
    let s = server(false);
    let ctx = ctx_with(Arc::new(FakeBroker::new()));
    let r = s.handle(b"{not json", &ctx).await.unwrap();
    assert_eq!(r["error"]["code"], -32700);
    assert_eq!(r["id"], Value::Null);
    let r = s.handle(b"", &ctx).await.unwrap();
    assert_eq!(r["error"]["code"], -32700);
    for (msg, code) in [
        (json!(42), -32600),
        (json!({"id": 1, "method": "ping"}), -32600),
        (json!({"jsonrpc": "1.0", "id": 1, "method": "ping"}), -32600),
        (json!({"jsonrpc": "2.0", "id": null, "method": "ping"}), -32600),
        (json!({"jsonrpc": "2.0", "id": 1.5, "method": "ping"}), -32600),
        (json!({"jsonrpc": "2.0", "id": 1, "method": 7}), -32600),
        (json!({"jsonrpc": "2.0", "id": 1}), -32600),
        (json!({"jsonrpc": "2.0", "id": 1, "method": "ping", "params": [1]}), -32602),
    ] {
        let r = send(&s, &ctx, msg.clone()).await.unwrap();
        assert_eq!(r["error"]["code"], code, "{msg}");
        assert_eq!(r["jsonrpc"], "2.0");
    }
    // notifications and client responses produce nothing
    for msg in [
        json!({"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": 3}}),
        json!({"jsonrpc": "2.0", "method": "notifications/roots/list_changed"}),
        json!({"jsonrpc": "2.0", "method": "unknown/notification"}),
        json!({"jsonrpc": "2.0", "id": 5, "result": {}}),
        json!({"jsonrpc": "2.0", "id": 5, "error": {"code": 1, "message": "x"}}),
        json!({"jsonrpc": "2.0", "method": "notifications/initialized", "params": [1]}),
    ] {
        assert!(send(&s, &ctx, msg.clone()).await.is_none(), "{msg}");
    }
    // initialized before initialize does not mark the session
    assert!(!ctx.session.is_initialized());
}

#[tokio::test]
async fn batching_rules_per_version() {
    let s = server(false);
    // 2025-03-26 accepts batches
    let ctx = ctx_with(Arc::new(FakeBroker::new()));
    init(&s, &ctx, "2025-03-26").await;
    let r = send(&s, &ctx, json!([
        {"jsonrpc": "2.0", "id": 1, "method": "ping"},
        {"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": 0}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        {"jsonrpc": "2.0", "id": 3, "method": "initialize", "params": {"protocolVersion": "2025-03-26"}}
    ])).await.unwrap();
    let arr = r.as_array().unwrap();
    assert_eq!(arr.len(), 3);
    assert!(arr.iter().any(|x| x["id"] == 1 && x["result"] == json!({})));
    assert!(arr.iter().any(|x| x["id"] == 2 && x["result"]["tools"].is_array()));
    assert!(arr.iter().any(|x| x["id"] == 3 && x["error"]["code"] == -32600), "initialize must not be batched");
    // only notifications → nothing
    assert!(send(&s, &ctx, json!([{"jsonrpc": "2.0", "method": "notifications/cancelled"}])).await.is_none());
    assert_eq!(send(&s, &ctx, json!([])).await.unwrap()["error"]["code"], -32600);
    // 2024-11-05 too
    let ctx = ctx_with(Arc::new(FakeBroker::new()));
    init(&s, &ctx, "2024-11-05").await;
    assert!(send(&s, &ctx, json!([{"jsonrpc": "2.0", "id": 1, "method": "ping"}])).await.unwrap().is_array());
    // 2025-06-18 and 2025-11-25 reject batches; so does an uninitialized session
    for v in ["2025-06-18", "2025-11-25"] {
        let ctx = ctx_with(Arc::new(FakeBroker::new()));
        init(&s, &ctx, v).await;
        let r = send(&s, &ctx, json!([{"jsonrpc": "2.0", "id": 1, "method": "ping"}])).await.unwrap();
        assert_eq!(r["error"]["code"], -32600, "{v}");
    }
    let ctx = ctx_with(Arc::new(FakeBroker::new()));
    let r = send(&s, &ctx, json!([{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-03-26"}}])).await.unwrap();
    assert_eq!(r["error"]["code"], -32600);
}

#[tokio::test]
async fn experimental_tools_map_to_fixed_operations() {
    let s = server(true);
    let broker = Arc::new(FakeBroker::new());
    let ctx = ctx_with(broker.clone());
    init(&s, &ctx, "2025-11-25").await;
    let rid = broker.resources.resources[0].resource_id.as_str().to_owned();
    let res = call(&s, &ctx, 1, "credentials_rotate", json!({"resource_id": rid, "parameters": {"scheme": "postgres.password"}, "idempotency_key": "rot-1"})).await;
    assert_eq!(res["structuredContent"]["status"], "approval_required");
    let res = call(&s, &ctx, 2, "credentials_rotate", json!({"resource_id": rid, "operation": "postgres.query_view", "parameters": {}, "idempotency_key": "rot-2"})).await;
    assert_eq!(res["isError"], true, "the operation of an experimental tool is fixed");
    let r = send(&s, &ctx, json!({"jsonrpc": "2.0", "id": 3, "method": "initialize", "params": {"protocolVersion": "2025-11-25"}})).await.unwrap();
    assert!(r.get("error").is_some());
    assert!(s.instructions().contains("credentials_rotate"));
}
