// SPDX-License-Identifier: Apache-2.0
//! Cross-implementation test vectors in `open-source/test-vectors/`:
//! * `request-signing.json` — CONTRACTS §1.6 (copied verbatim; must reproduce exactly);
//! * `jcs.json` — RFC 8785 canonicalization cases and rejections (generated + checked);
//! * `approval-digest.json` — a fully specified ApprovalRequest / ApprovalDecision with the
//!   expected digest and signature from a fixed seed (generated + checked).
//!
//! Set `AIPASS_REGEN_VECTORS=1` to regenerate the generated files.

use aipass_crypto::{Ed25519Keypair, b64u};
use aipass_types::approval::{self, DigestInput};
use aipass_types::canonical::{self, CanonicalError};
use aipass_types::models::*;
use aipass_types::signing::{self, SigHeader};
use aipass_types::*;
use serde_json::{Value, json};

fn dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../test-vectors")
}

fn read(name: &str) -> Value {
    serde_json::from_str(&std::fs::read_to_string(dir().join(name)).unwrap()).unwrap()
}

fn check_generated(name: &str, generated: &Value) {
    let path = dir().join(name);
    if std::env::var_os("AIPASS_REGEN_VECTORS").is_some() || !path.exists() {
        std::fs::write(
            &path,
            serde_json::to_string_pretty(generated).unwrap() + "\n",
        )
        .unwrap();
    }
    assert_eq!(
        &read(name),
        generated,
        "test-vectors/{name} is stale (AIPASS_REGEN_VECTORS=1 to regenerate)"
    );
}

// ---------------------------------------------------------------------------------------
// §1.6 request signing — contract vector
// ---------------------------------------------------------------------------------------

#[test]
fn request_signing_contract_vector() {
    let v = read("request-signing.json");
    let seed = b64u::decode_array::<32>(v["seed"].as_str().unwrap()).unwrap();
    assert_eq!(seed, core::array::from_fn::<u8, 32, _>(|i| i as u8));
    let key = Ed25519Keypair::from_seed(&seed);
    assert_eq!(key.public_key_b64u(), v["public_key"].as_str().unwrap());
    let kid = v["kid"].as_str().unwrap();
    let ts = v["ts"].as_i64().unwrap();
    let nonce = v["nonce"].as_str().unwrap();
    assert_eq!(b64u::decode(nonce).unwrap().len(), 16);
    for case in v["cases"].as_array().unwrap() {
        let method = case["method"].as_str().unwrap();
        let path = case["path"].as_str().unwrap();
        let body = case["body"].as_str().unwrap().as_bytes();
        assert_eq!(
            signing::body_hash_b64u(body),
            case["body_sha256"].as_str().unwrap()
        );
        let sts = signing::string_to_sign(method, path, ts, nonce, body);
        assert_eq!(sts, case["string_to_sign"].as_str().unwrap());
        let h = signing::sign_request_with(&key, kid, method, path, body, ts, nonce);
        assert_eq!(
            h.sig,
            case["signature"].as_str().unwrap(),
            "{method} {path}"
        );
        // header roundtrip + verification (within / outside skew window)
        let parsed = SigHeader::parse(&h.to_header_value()).unwrap();
        assert_eq!(parsed, h);
        signing::verify_request(&parsed, &key.public_key(), method, path, body, ts + 299).unwrap();
        assert!(
            signing::verify_request(&parsed, &key.public_key(), method, path, body, ts + 301)
                .is_err()
        );
        let cache = signing::NonceCache::default();
        signing::verify_request_with_nonce(
            &parsed,
            &key.public_key(),
            method,
            path,
            body,
            ts,
            &cache,
        )
        .unwrap();
        assert_eq!(
            signing::verify_request_with_nonce(
                &parsed,
                &key.public_key(),
                method,
                path,
                body,
                ts,
                &cache
            ),
            Err(signing::SigError::Replay)
        );
    }
}

// ---------------------------------------------------------------------------------------
// §1.4 JCS
// ---------------------------------------------------------------------------------------

fn jcs_cases() -> Value {
    let ok_inputs = [
        ("empty object", "{}"),
        (
            "rfc8785 3.2.3 sorting (UTF-16 code units)",
            r#"{"\u20ac":"Euro Sign","\r":"Carriage Return","\ufb33":"Hebrew Letter Dalet With Dagesh","1":"One","\ud83d\ude00":"Emoji: Grinning Face","\u0080":"Control","\u00f6":"Latin Small Letter O With Diaeresis"}"#,
        ),
        (
            "rfc8785 3.2.2 strings and literals (numbers omitted: floats are rejected)",
            r#"{"string":"\u20ac$\u000F\u000aA'\u0042\u0022\u005c\\\"\/","literals":[null,true,false]}"#,
        ),
        (
            "nested objects and arrays keep array order",
            r#"{ "b" : [3, 1, {"z":1,"a":2}], "a" : {"y":null,"x":true} }"#,
        ),
        (
            "control characters",
            "\"\\u0000\\u0001\\u001f\\b\\t\\n\\f\\r\\u007f\"",
        ),
        (
            "safe integer bounds",
            "[9007199254740991,-9007199254740991,0,-1]",
        ),
        (
            "unicode passthrough incl. U+2028",
            "\"中文 \u{2028} e\u{301}\"",
        ),
        (
            "approval-style document",
            r#"{"v":1,"mode":"task","operations":["postgres.query_view"],"limits":{"max_rows_per_operation":1000,"max_rows_per_grant":5000,"max_requests_per_grant":20,"max_result_bytes":262144}}"#,
        ),
    ];
    let reject_inputs = [
        ("float", "1.5", "float"),
        ("integral float", "[1.0]", "float"),
        ("exponent", "1E30", "float"),
        ("2^53", "9007199254740992", "integer_out_of_range"),
        ("-2^53", "-9007199254740992", "integer_out_of_range"),
        ("u64 max", "18446744073709551615", "integer_out_of_range"),
    ];
    let ok: Vec<Value> = ok_inputs
        .iter()
        .map(|(name, input)| {
            let out = String::from_utf8(canonical::canonicalize_json_text(input).unwrap_or_else(|e| panic!("{name}: {e}"))).unwrap();
            json!({"name": name, "input": input, "canonical": out, "sha256_b64u": aipass_crypto::sha256_b64u(out.as_bytes())})
        })
        .collect();
    let rejected: Vec<Value> = reject_inputs
        .iter()
        .map(|(name, input, why)| {
            let err = canonical::canonicalize_json_text(input).unwrap_err();
            let kind = match err {
                CanonicalError::Float => "float",
                CanonicalError::IntegerOutOfRange => "integer_out_of_range",
                _ => "other",
            };
            assert_eq!(kind, *why, "{name}");
            json!({"name": name, "input": input, "error": kind})
        })
        .collect();
    json!({
        "description": "RFC 8785 JCS for the AI Pass value subset (CONTRACTS §1.4): strings, integers |n| < 2^53, booleans, null, arrays, objects. Floats and unsafe integers are rejected. Generated and checked by crates/aipass-types/tests/vectors.rs.",
        "valid": ok,
        "rejected": rejected
    })
}

#[test]
fn jcs_vector_file() {
    let generated = jcs_cases();
    check_generated("jcs.json", &generated);
    // Independent re-check from the file contents.
    let v = read("jcs.json");
    for c in v["valid"].as_array().unwrap() {
        let out = canonical::canonicalize_json_text(c["input"].as_str().unwrap()).unwrap();
        assert_eq!(
            String::from_utf8(out).unwrap(),
            c["canonical"].as_str().unwrap()
        );
        // canonical form is a fixed point
        let again = canonical::canonicalize_json_text(c["canonical"].as_str().unwrap()).unwrap();
        assert_eq!(
            String::from_utf8(again).unwrap(),
            c["canonical"].as_str().unwrap()
        );
    }
    for c in v["rejected"].as_array().unwrap() {
        assert!(canonical::canonicalize_json_text(c["input"].as_str().unwrap()).is_err());
    }
}

// ---------------------------------------------------------------------------------------
// §7 approval digest
// ---------------------------------------------------------------------------------------

fn ts(s: &str) -> Timestamp {
    aipass_types::time::parse_rfc3339(s).unwrap()
}

fn sample_request() -> ApprovalRequest {
    let conn = ConnectionId::parse("conn_01jbz3k6w8a7m2q4t5v9x0y1z4").unwrap();
    ApprovalRequest {
        approval_request_id: ApprovalRequestId::parse("apr_01jbz3k6w8a7m2q4t5v9x0y1z5").unwrap(),
        kind: ApprovalKind::Operation,
        connection: ApprovalConnection {
            connection_id: conn.clone(),
            display_name: "Claude Code".into(),
            host_type: HostType::ClaudeCode,
            verified: true,
        },
        resource: ApprovalResource {
            resource_id: ResourceId::parse("res_01jbz3k6w8a7m2q4t5v9x0y1z2").unwrap(),
            alias: "路亚站测试库".into(),
            service: "postgres".into(),
            environment: Environment::Test,
        },
        summary: Localized::new("查询订阅统计视图", "Query the subscription statistics view"),
        requested: AccessSpec {
            // deliberately unsorted / duplicated: the digest normalizes
            operations: vec!["postgres.query_view".into(), "postgres.query_view".into()],
            scope: GrantScope {
                operations: vec!["postgres.query_view".into()],
                postgres: Some(PostgresScope {
                    views: [(
                        "analytics.subscription_daily".to_string(),
                        vec!["subscriptions".into(), "day".into(), "plan".into()],
                    )]
                    .into(),
                }),
                github: None,
                http_api: None,
            },
            limits: Limits::default(),
            duration_seconds: 900,
            mode: ApprovalMode::Task,
        },
        excluded_fields: [(
            "analytics.subscription_daily".to_string(),
            vec!["customer_email".into()],
        )]
        .into(),
        executor: ApprovalExecutor {
            executor_id: ExecutorId::parse("exe_01jbz3k6w8a7m2q4t5v9x0y1z7").unwrap(),
            name: "我的服务器".into(),
            protection_level: ProtectionLevel::Isolated,
        },
        recipients: vec![Recipient {
            connection_id: conn,
            display_name: "Claude Code".into(),
        }],
        status: ApprovalStatus::Pending,
        created_at: ts("2026-10-30T12:00:00Z"),
        expires_at: ts("2026-10-30T12:02:00Z"),
        operation_id: Some(OperationId::parse("op_01jbz3k6w8a7m2q4t5v9x0y1z6").unwrap()),
        parameters_digest: Some(
            aipass_types::exec::parameters_digest(
                "postgres.query_view",
                &json!({"view": "analytics.subscription_daily", "fields": ["day", "plan", "subscriptions"], "limit": 100}),
            )
            .unwrap(),
        ),
    }
}

fn signer() -> (Ed25519Keypair, DeviceId) {
    let seed: [u8; 32] = core::array::from_fn(|i| 0x20 + i as u8);
    (
        Ed25519Keypair::from_seed(&seed),
        DeviceId::parse("dev_01jbz3k6w8a7m2q4t5v9x0y1z8").unwrap(),
    )
}

fn approval_vectors() -> Value {
    let req = sample_request();
    let (key, dev) = signer();
    let now = ts("2026-10-30T12:00:30Z");

    // 1. approve as requested
    let full = approval::build_decision(&key, &dev, &req, Decision::Approve, None, &now).unwrap();
    // 2. approve a narrowed scope ("选择较小权限"): fewer fields, smaller limits, once
    let mut narrowed_spec = req.requested.clone();
    narrowed_spec.scope.postgres.as_mut().unwrap().views.insert(
        "analytics.subscription_daily".into(),
        vec!["day".into(), "subscriptions".into()],
    );
    narrowed_spec.limits.max_rows_per_operation = 100;
    narrowed_spec.duration_seconds = 300;
    narrowed_spec.mode = ApprovalMode::Once;
    let narrowed = approval::build_decision(
        &key,
        &dev,
        &req,
        Decision::Approve,
        Some(narrowed_spec.clone()),
        &now,
    )
    .unwrap();
    // 3. deny
    let deny = approval::build_decision(&key, &dev, &req, Decision::Deny, None, &now).unwrap();

    let doc = |d: &ApprovalDecision| {
        let eff = d.approved.clone().unwrap_or_else(|| req.requested.clone());
        let recipients: Vec<ConnectionId> = req
            .recipients
            .iter()
            .map(|r| r.connection_id.clone())
            .collect();
        let bytes = approval::digest_document(&DigestInput {
            approval_request_id: &req.approval_request_id,
            connection_id: &req.connection.connection_id,
            resource_id: &req.resource.resource_id,
            executor_id: &req.executor.executor_id,
            operations: &eff.operations,
            scope: &eff.scope,
            limits: &eff.limits,
            mode: eff.mode,
            expires_at: &d.expires_at,
            recipients: &recipients,
            operation_id: req.operation_id.as_ref(),
            parameters_digest: req.parameters_digest.as_deref(),
        })
        .unwrap();
        String::from_utf8(bytes).unwrap()
    };
    let case = |name: &str, d: &ApprovalDecision| {
        json!({
            "name": name,
            "decision": serde_json::to_value(d).unwrap(),
            "digest_document": doc(d),
            "digest": d.digest,
            "signing_message": approval::signing_message(d.decision, &d.digest),
            "signature": d.signature,
        })
    };
    json!({
        "description": "CONTRACTS §7 approval digest v2: digest = b64u(SHA-256(JCS(digest_document))); signature = Ed25519(signer, signing_message). Signer seed is bytes 0x20..0x3f. `now` is the verification time. Generated and checked by crates/aipass-types/tests/vectors.rs.",
        "signer_seed": b64u::encode(core::array::from_fn::<u8, 32, _>(|i| 0x20 + i as u8)),
        "signer_public_key": key.public_key_b64u(),
        "signer_device_id": dev,
        "now": "2026-10-30T12:00:30Z",
        "approval_request": serde_json::to_value(&req).unwrap(),
        "request_digest_note": "request_digest = b64u(SHA-256(JCS(approval_request minus \"status\"))) — display-level hash clients pass back with approve/deny (FFI)",
        "request_digest": approval::request_digest(&req).unwrap(),
        "cases": [
            case("approve as requested", &full),
            case("approve narrowed (fewer fields, lower limits, shorter, once)", &narrowed),
            case("deny", &deny),
        ]
    })
}

#[test]
fn approval_digest_vector_file() {
    let generated = approval_vectors();
    check_generated("approval-digest.json", &generated);

    // Independent check from file contents: digest = sha256(digest_document), signature
    // verifies, and the broker-side verification accepts each decision.
    let v = read("approval-digest.json");
    let req: ApprovalRequest = serde_json::from_value(v["approval_request"].clone()).unwrap();
    let pk = b64u::decode_array::<32>(v["signer_public_key"].as_str().unwrap()).unwrap();
    let now = ts(v["now"].as_str().unwrap());
    assert_eq!(
        approval::request_digest(&req).unwrap(),
        v["request_digest"].as_str().unwrap()
    );
    for c in v["cases"].as_array().unwrap() {
        let d: ApprovalDecision = serde_json::from_value(c["decision"].clone()).unwrap();
        assert_eq!(
            aipass_crypto::sha256_b64u(c["digest_document"].as_str().unwrap().as_bytes()),
            c["digest"].as_str().unwrap()
        );
        assert_eq!(d.digest, c["digest"].as_str().unwrap());
        aipass_crypto::identity::verify_b64u(
            v["signer_public_key"].as_str().unwrap(),
            c["signing_message"].as_str().unwrap().as_bytes(),
            c["signature"].as_str().unwrap(),
        )
        .unwrap();
        approval::verify_decision(&d, &req, &pk, &now).unwrap();
    }
    // The first digest document is the exact shape of CONTRACTS §7.
    let doc: Value =
        serde_json::from_str(v["cases"][0]["digest_document"].as_str().unwrap()).unwrap();
    let keys: Vec<&String> = doc.as_object().unwrap().keys().collect();
    let mut expected = vec![
        "approval_request_id",
        "connection_id",
        "executor_id",
        "expires_at",
        "limits",
        "mode",
        "operation_id",
        "operations",
        "parameters_digest",
        "recipients",
        "resource_id",
        "scope",
        "v",
    ];
    expected.sort();
    let mut got: Vec<&str> = keys.iter().map(|s| s.as_str()).collect();
    got.sort();
    assert_eq!(got, expected);
    assert_eq!(doc["operations"], json!(["postgres.query_view"]));
    assert_eq!(
        doc["scope"]["postgres"]["views"]["analytics.subscription_daily"],
        json!(["day", "plan", "subscriptions"])
    );
    assert_eq!(doc["expires_at"], "2026-10-30T12:15:30Z");
    assert_eq!(doc["v"], 2);
    assert_eq!(doc["operation_id"], "op_01jbz3k6w8a7m2q4t5v9x0y1z6");
    assert_eq!(
        doc["parameters_digest"].as_str(),
        req.parameters_digest.as_deref()
    );
}

/// The v1 document (no operation binding) for `d` — what a pre-v2 client would sign.
fn v1_digest(req: &ApprovalRequest, d: &ApprovalDecision) -> String {
    let eff = d.approved.clone().unwrap_or_else(|| req.requested.clone());
    let mut recipients: Vec<String> = req
        .recipients
        .iter()
        .map(|r| r.connection_id.to_string())
        .collect();
    recipients.sort();
    recipients.dedup();
    let doc = json!({
        "v": 1,
        "approval_request_id": req.approval_request_id,
        "connection_id": req.connection.connection_id,
        "resource_id": req.resource.resource_id,
        "executor_id": req.executor.executor_id,
        "operations": approval::normalize_operations(&eff.operations),
        "scope": approval::normalize_scope(&eff.scope),
        "limits": eff.limits,
        "mode": eff.mode,
        "expires_at": aipass_types::time::format_rfc3339(&d.expires_at),
        "recipients": recipients,
    });
    canonical::jcs_sha256_b64u(&doc).unwrap()
}

#[test]
fn v1_and_unbound_digests_are_rejected() {
    let req = sample_request();
    let (key, dev) = signer();
    let now = ts("2026-10-30T12:00:30Z");
    let pk = key.public_key();
    let good = approval::build_decision(&key, &dev, &req, Decision::Approve, None, &now).unwrap();
    approval::verify_decision(&good, &req, &pk, &now).unwrap();

    // A correctly signed v1 digest (no operation binding) is refused.
    for base in [good.clone(), approval::build_decision(&key, &dev, &req, Decision::Deny, None, &now).unwrap()] {
        let mut v1 = base.clone();
        v1.digest = v1_digest(&req, &base);
        assert_ne!(v1.digest, base.digest);
        v1.signature = approval::sign_decision(&key, v1.decision, &v1.digest);
        assert_eq!(
            approval::verify_decision(&v1, &req, &pk, &now).unwrap_err().code,
            ErrorCode::IntegrityFailed
        );
    }

    // A decision signed for other parameters / another operation does not verify
    // against the stored request (the user saw different parameters).
    let mut other_params = req.clone();
    other_params.parameters_digest = Some(
        aipass_types::exec::parameters_digest("postgres.query_view", &json!({"view": "analytics.customers"})).unwrap(),
    );
    assert_eq!(
        approval::verify_decision(&good, &other_params, &pk, &now).unwrap_err().code,
        ErrorCode::IntegrityFailed
    );
    let mut other_op = req.clone();
    other_op.operation_id = Some(OperationId::generate());
    assert_eq!(
        approval::verify_decision(&good, &other_op, &pk, &now).unwrap_err().code,
        ErrorCode::IntegrityFailed
    );

    // Operation requests without a binding are never signed nor accepted.
    let mut unbound = req.clone();
    unbound.parameters_digest = None;
    assert_eq!(
        approval::build_decision(&key, &dev, &unbound, Decision::Approve, None, &now).unwrap_err().code,
        ErrorCode::IntegrityFailed
    );
    assert_eq!(
        approval::verify_decision(&good, &unbound, &pk, &now).unwrap_err().code,
        ErrorCode::IntegrityFailed
    );
    // …and access requests may not carry one.
    let mut access = req.clone();
    access.kind = ApprovalKind::Access;
    assert_eq!(
        approval::build_decision(&key, &dev, &access, Decision::Approve, None, &now).unwrap_err().code,
        ErrorCode::IntegrityFailed
    );
    access.operation_id = None;
    access.parameters_digest = None;
    let d = approval::build_decision(&key, &dev, &access, Decision::Approve, None, &now).unwrap();
    approval::verify_decision(&d, &access, &pk, &now).unwrap();
    // access digests carry explicit nulls
    let bytes = approval::digest_document(&DigestInput {
        approval_request_id: &access.approval_request_id,
        connection_id: &access.connection.connection_id,
        resource_id: &access.resource.resource_id,
        executor_id: &access.executor.executor_id,
        operations: &access.requested.operations,
        scope: &access.requested.scope,
        limits: &access.requested.limits,
        mode: access.requested.mode,
        expires_at: &d.expires_at,
        recipients: &[access.recipients[0].connection_id.clone()],
        operation_id: None,
        parameters_digest: None,
    })
    .unwrap();
    let doc: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(doc["operation_id"], Value::Null);
    assert_eq!(doc["parameters_digest"], Value::Null);
    assert_eq!(aipass_crypto::sha256_b64u(&bytes), d.digest);
}

#[test]
fn request_digest_covers_every_displayed_field() {
    let req = sample_request();
    let base = approval::request_digest(&req).unwrap();
    assert_eq!(approval::request_digest(&req.clone()).unwrap(), base);
    // status is not part of it (a snapshot copy and a relayed copy hash the same)
    let mut st = req.clone();
    st.status = ApprovalStatus::Approved;
    assert_eq!(approval::request_digest(&st).unwrap(), base);
    // a JSON round trip keeps it
    let rt: ApprovalRequest = serde_json::from_value(serde_json::to_value(&req).unwrap()).unwrap();
    assert_eq!(approval::request_digest(&rt).unwrap(), base);
    let changed: Vec<ApprovalRequest> = vec![
        { let mut r = req.clone(); r.summary = Localized::new("别的", "other"); r },
        { let mut r = req.clone(); r.excluded_fields.clear(); r },
        { let mut r = req.clone(); r.connection.display_name = "Codex".into(); r },
        { let mut r = req.clone(); r.resource.alias = "生产库".into(); r },
        { let mut r = req.clone(); r.executor.name = "x".into(); r },
        { let mut r = req.clone(); r.requested.limits.max_rows_per_operation = 1; r },
        { let mut r = req.clone(); r.parameters_digest = Some("x".into()); r },
        { let mut r = req.clone(); r.expires_at = ts("2026-10-30T12:03:00Z"); r },
    ];
    for r in changed {
        assert_ne!(approval::request_digest(&r).unwrap(), base);
    }
}

#[test]
fn approval_tampering_is_rejected() {
    let req = sample_request();
    let (key, dev) = signer();
    let now = ts("2026-10-30T12:00:30Z");
    let pk = key.public_key();
    let good = approval::build_decision(&key, &dev, &req, Decision::Approve, None, &now).unwrap();
    approval::verify_decision(&good, &req, &pk, &now).unwrap();

    // A05: any change to resource / view / fields / operation / executor / recipients
    let mut r2 = req.clone();
    r2.resource.resource_id = ResourceId::generate();
    assert_eq!(
        approval::verify_decision(&good, &r2, &pk, &now)
            .unwrap_err()
            .code,
        ErrorCode::IntegrityFailed
    );
    let mut r3 = req.clone();
    r3.executor.executor_id = ExecutorId::generate();
    assert!(approval::verify_decision(&good, &r3, &pk, &now).is_err());
    let mut r4 = req.clone();
    r4.recipients.push(Recipient {
        connection_id: ConnectionId::generate(),
        display_name: "x".into(),
    });
    assert!(approval::verify_decision(&good, &r4, &pk, &now).is_err());

    // widening the approved scope after signing
    let mut d2 = good.clone();
    d2.approved
        .as_mut()
        .unwrap()
        .scope
        .postgres
        .as_mut()
        .unwrap()
        .views
        .insert("analytics.customers".into(), vec!["email".into()]);
    assert!(approval::verify_decision(&d2, &req, &pk, &now).is_err());
    // flipping deny → approve
    let deny = approval::build_decision(&key, &dev, &req, Decision::Deny, None, &now).unwrap();
    approval::verify_decision(&deny, &req, &pk, &now).unwrap();
    let mut flipped = deny.clone();
    flipped.decision = Decision::Approve;
    flipped.approved = Some(req.requested.clone());
    assert!(approval::verify_decision(&flipped, &req, &pk, &now).is_err());
    // wrong signer
    let other = Ed25519Keypair::generate();
    assert_eq!(
        approval::verify_decision(&good, &req, &other.public_key(), &now)
            .unwrap_err()
            .code,
        ErrorCode::IdentityUnverified
    );
    // never approve after the approval window
    let late = ts("2026-10-30T12:02:01Z");
    assert_eq!(
        approval::verify_decision(&good, &req, &pk, &late)
            .unwrap_err()
            .code,
        ErrorCode::ApprovalExpired
    );
    let mut expired = req.clone();
    expired.status = ApprovalStatus::Expired;
    assert_eq!(
        approval::verify_decision(&good, &expired, &pk, &now)
            .unwrap_err()
            .code,
        ErrorCode::ApprovalExpired
    );
    // expires_at beyond now + duration + 60 (re-signed so only the bound fails)
    let mut long = good.clone();
    long.expires_at = ts("2026-10-30T12:20:00Z");
    long.digest =
        approval::digest_for(&req, long.approved.as_ref().unwrap(), &long.expires_at).unwrap();
    long.signature = approval::sign_decision(&key, Decision::Approve, &long.digest);
    assert!(approval::verify_decision(&long, &req, &pk, &now).is_err());
    // building a decision that widens is refused
    let mut wide = req.requested.clone();
    wide.limits.max_rows_per_grant = 1_000_000;
    assert!(
        approval::build_decision(&key, &dev, &req, Decision::Approve, Some(wide), &now).is_err()
    );
}

#[test]
fn subset_rules() {
    let req = sample_request().requested;
    assert!(approval::approved_is_subset(&req, &req));
    let mut a = req.clone();
    a.mode = ApprovalMode::Rule;
    assert!(
        !approval::approved_is_subset(&a, &req),
        "mode may not widen"
    );
    let mut b = req.clone();
    b.duration_seconds = 901;
    assert!(!approval::approved_is_subset(&b, &req));
    let mut c = req.clone();
    c.operations.push("postgres.write".into());
    assert!(!approval::approved_is_subset(&c, &req));
    let mut d = req.clone();
    d.scope.github = Some(GithubScope {
        repos: vec!["o/r".into()],
    });
    assert!(!approval::approved_is_subset(&d, &req));
    let mut e = req.clone();
    e.scope.postgres = None;
    assert!(
        approval::approved_is_subset(&e, &req),
        "dropping a section narrows"
    );
    // GitHub repo names compare case-insensitively after normalization
    let gh = |r: &str| GrantScope {
        operations: vec![],
        postgres: None,
        github: Some(GithubScope {
            repos: vec![r.into()],
        }),
        http_api: None,
    };
    assert!(approval::scope_is_subset(
        &gh("Owner/Repo"),
        &gh("owner/repo")
    ));
    assert!(!approval::scope_is_subset(
        &gh("owner/other"),
        &gh("owner/repo")
    ));
    // normalization is idempotent
    let n = approval::normalize_scope(&req.scope);
    assert_eq!(approval::normalize_scope(&n), n);
}

#[test]
fn digest_changes_with_every_bound_field() {
    let req = sample_request();
    let exp = ts("2026-10-30T12:15:30Z");
    let base = approval::digest_for(&req, &req.requested, &exp).unwrap();
    let mut s = req.requested.clone();
    s.limits.max_result_bytes -= 1;
    assert_ne!(approval::digest_for(&req, &s, &exp).unwrap(), base);
    assert_ne!(
        approval::digest_for(&req, &req.requested, &ts("2026-10-30T12:15:31Z")).unwrap(),
        base
    );
    let mut r = req.clone();
    r.connection.connection_id = ConnectionId::generate();
    assert_ne!(
        approval::digest_for(&r, &req.requested, &exp).unwrap(),
        base
    );
    let mut r = req.clone();
    r.operation_id = Some(OperationId::generate());
    assert_ne!(approval::digest_for(&r, &req.requested, &exp).unwrap(), base);
    let mut r = req.clone();
    r.parameters_digest = Some("AAAA".into());
    assert_ne!(approval::digest_for(&r, &req.requested, &exp).unwrap(), base);
    // Display-only fields do not affect the digest.
    let mut cosmetic = req.clone();
    cosmetic.summary = Localized::new("别的", "other");
    cosmetic.excluded_fields.clear();
    assert_eq!(
        approval::digest_for(&cosmetic, &req.requested, &exp).unwrap(),
        base
    );
}
