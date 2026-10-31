// SPDX-License-Identifier: Apache-2.0
//! The trusted-device approval helpers sign the CONTRACTS §7 **v2** digest (operation
//! binding included) and refuse operation requests without a binding.

use aipass_crypto::DeviceIdentity;
use aipass_types::approval;
use aipass_types::ids::DeviceId;
use aipass_types::models::{ApprovalRequest, Decision};
use aipass_vault::approval::{approve_request, deny_request};

fn request(kind: &str, binding: bool) -> ApprovalRequest {
    let now = aipass_types::time::now();
    let mut v = serde_json::json!({
        "approval_request_id": "apr_01jbz3k6w8a7m2q4t5v9x0y1z5",
        "kind": kind,
        "connection": {"connection_id": "conn_01jbz3k6w8a7m2q4t5v9x0y1z4", "display_name": "Claude Code", "host_type": "claude_code", "verified": true},
        "resource": {"resource_id": "res_01jbz3k6w8a7m2q4t5v9x0y1z2", "alias": "test-db", "service": "postgres", "environment": "test"},
        "summary": {"zh": "查询", "en": "Query"},
        "requested": {
            "operations": ["postgres.query_view"],
            "scope": {"operations": ["postgres.query_view"], "postgres": {"views": {"analytics.subscription_daily": ["day"]}}},
            "limits": {"max_rows_per_operation": 100, "max_rows_per_grant": 500, "max_requests_per_grant": 10, "max_result_bytes": 65536},
            "duration_seconds": 900,
            "mode": "task"
        },
        "executor": {"executor_id": "exe_01jbz3k6w8a7m2q4t5v9x0y1z7", "name": "node", "protection_level": "isolated"},
        "recipients": [{"connection_id": "conn_01jbz3k6w8a7m2q4t5v9x0y1z4", "display_name": "Claude Code"}],
        "status": "pending",
        "created_at": aipass_types::time::format_rfc3339(&now),
        "expires_at": aipass_types::time::format_rfc3339(&aipass_types::time::add_secs(&now, 120)),
    });
    if binding {
        v["operation_id"] = "op_01jbz3k6w8a7m2q4t5v9x0y1z6".into();
        v["parameters_digest"] = aipass_types::exec::parameters_digest("postgres.query_view", &serde_json::json!({"view": "analytics.subscription_daily"}))
            .unwrap()
            .into();
    }
    serde_json::from_value(v).unwrap()
}

#[test]
fn helpers_sign_the_v2_digest() {
    let id = DeviceIdentity::generate();
    let dev = DeviceId::generate();
    let pk = id.public().sign_pk;
    let now = aipass_types::time::now();
    for req in [request("operation", true), request("access", false)] {
        let a = approve_request(&id, &dev, &req, None, None, &now).unwrap();
        assert_eq!(a.digest, approval::digest_for(&req, a.approved.as_ref().unwrap(), &a.expires_at).unwrap());
        approval::verify_decision(&a, &req, &pk, &now).unwrap();
        let d = deny_request(&id, &dev, &req, &now).unwrap();
        assert_eq!(d.decision, Decision::Deny);
        approval::verify_decision(&d, &req, &pk, &now).unwrap();
        // the signature does not carry over to other parameters
        if req.parameters_digest.is_some() {
            let mut other = req.clone();
            other.parameters_digest = Some("AAAA".into());
            assert!(approval::verify_decision(&a, &other, &pk, &now).is_err());
        }
    }
    // an operation request without its binding is never signed
    let unbound = request("operation", false);
    assert!(approve_request(&id, &dev, &unbound, None, None, &now).is_err());
    assert!(deny_request(&id, &dev, &unbound, &now).is_err());
}
