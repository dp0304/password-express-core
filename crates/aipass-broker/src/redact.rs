// SPDX-License-Identifier: Apache-2.0
//! Redacted parameter summaries for audit events (design doc §9.8, §12.4: "敏感参数不进普通日志").
//!
//! Audit stores the parameters only as their digest plus this summary: structural
//! identifiers (view, field and repository names, paging numbers) are kept so the user can
//! see *what* was asked; every value that could be business data or a secret (filter
//! values, paths, free text, unknown keys) is replaced by a type marker. Strings that look
//! like credentials are always redacted, whatever their key.

use serde_json::{Map, Value, json};

/// Keys whose string / string-array values are structural identifiers.
const IDENT_KEYS: &[&str] = &[
    "view",
    "fields",
    "field",
    "repo",
    "state",
    "direction",
    "op",
    "operation",
];
/// Keys whose integer values are paging / sizing hints.
const NUMBER_KEYS: &[&str] = &["limit", "page", "per_page", "period_days", "offset"];
/// Keys whose values are arrays of structural objects to recurse into.
const NESTED_KEYS: &[&str] = &["filters", "order_by"];

const MAX_ITEMS: usize = 64;
const MAX_IDENT_LEN: usize = 128;

/// Produce the audit summary of operation parameters.
pub(crate) fn summarize_params(params: &Value) -> Value {
    match params {
        Value::Object(m) => Value::Object(summarize_object(m, 0)),
        other => json!(type_marker(other)),
    }
}

fn summarize_object(m: &Map<String, Value>, depth: usize) -> Map<String, Value> {
    let mut out = Map::new();
    for (k, v) in m.iter().take(MAX_ITEMS) {
        let key = if is_ident(k) {
            k.clone()
        } else {
            // keys themselves may be data in exotic connectors; keep only safe ones
            "[key]".to_owned()
        };
        let val = if depth > 3 {
            json!(type_marker(v))
        } else if IDENT_KEYS.contains(&k.as_str()) {
            ident_value(v)
        } else if NUMBER_KEYS.contains(&k.as_str()) {
            match v {
                Value::Number(n) if n.is_i64() || n.is_u64() => v.clone(),
                other => json!(type_marker(other)),
            }
        } else if NESTED_KEYS.contains(&k.as_str()) {
            match v {
                Value::Array(items) => Value::Array(
                    items
                        .iter()
                        .take(MAX_ITEMS)
                        .map(|i| match i {
                            Value::Object(o) => Value::Object(summarize_object(o, depth + 1)),
                            other => json!(type_marker(other)),
                        })
                        .collect(),
                ),
                other => json!(type_marker(other)),
            }
        } else {
            json!(type_marker(v))
        };
        if out.contains_key(&key) {
            continue;
        }
        out.insert(key, val);
    }
    if m.len() > MAX_ITEMS {
        out.insert("[truncated]".into(), json!(m.len() - MAX_ITEMS));
    }
    out
}

fn ident_value(v: &Value) -> Value {
    match v {
        Value::String(s) if is_ident(s) && !looks_secret(s) => Value::String(s.clone()),
        Value::Array(items) => Value::Array(
            items
                .iter()
                .take(MAX_ITEMS)
                .map(|i| match i {
                    Value::String(s) if is_ident(s) && !looks_secret(s) => Value::String(s.clone()),
                    other => json!(type_marker(other)),
                })
                .collect(),
        ),
        other => json!(type_marker(other)),
    }
}

fn is_ident(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_IDENT_LEN
        && s
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-' | b'/'))
}

fn type_marker(v: &Value) -> &'static str {
    match v {
        Value::Null => "[null]",
        Value::Bool(_) => "[bool]",
        Value::Number(_) => "[number]",
        Value::String(s) if looks_secret(s) => "[REDACTED]",
        Value::String(_) => "[string]",
        Value::Array(_) => "[array]",
        Value::Object(_) => "[object]",
    }
}

/// Heuristic secret detector (secondary defence only).
pub(crate) fn looks_secret(s: &str) -> bool {
    const PREFIXES: &[&str] = &[
        "ghp_",
        "gho_",
        "ghs_",
        "ghu_",
        "github_pat_",
        "sk-",
        "sk_live_",
        "rk_live_",
        "xoxa-",
        "xoxb-",
        "xoxp-",
        "xoxr-",
        "xoxs-",
        "aipc_",
        "aipa_",
        "aipr_",
        "aips_",
        "aipadm_",
        "AIPR-",
    ];
    let t = s.trim();
    if PREFIXES.iter().any(|p| t.starts_with(p)) {
        return true;
    }
    if t.contains("-----BEGIN") && t.contains("PRIVATE KEY") {
        return true;
    }
    let lower = t.to_ascii_lowercase();
    if lower.starts_with("bearer ") || lower.starts_with("basic ") {
        return true;
    }
    // AWS access key id
    if t.len() == 20
        && t.starts_with("AKIA")
        && t[4..]
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
    {
        return true;
    }
    // JWT: three b64u segments, header starting with eyJ
    if t.starts_with("eyJ") && t.matches('.').count() == 2 {
        return true;
    }
    // scheme://user:pass@host
    if let Some(idx) = t.find("://") {
        let rest = &t[idx + 3..];
        if let Some(at) = rest.find('@') {
            let userinfo = &rest[..at];
            if userinfo.contains(':') && !userinfo.contains('/') {
                return true;
            }
        }
    }
    false
}

/// Recursively scan a resource config for credential material (resources must never carry
/// secrets — the credential is a vault entry reference, CONTRACTS §6.1).
pub(crate) fn config_contains_secret(v: &Value) -> bool {
    const SECRET_KEYS: &[&str] = &[
        "password",
        "passwd",
        "secret",
        "client_secret",
        "api_key",
        "apikey",
        "access_token",
        "refresh_token",
        "private_key",
        "token",
        "authorization",
    ];
    match v {
        Value::Object(m) => m.iter().any(|(k, val)| {
            let key = k.to_ascii_lowercase();
            (SECRET_KEYS.contains(&key.as_str())
                && matches!(val, Value::String(s) if !s.is_empty()))
                || config_contains_secret(val)
        }),
        Value::Array(a) => a.iter().any(config_contains_secret),
        Value::String(s) => looks_secret(s),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_structure_redacts_values() {
        let p = json!({
            "view": "analytics.subscription_daily",
            "fields": ["day", "plan", "subscriptions"],
            "period_days": 30,
            "filters": [{"field": "email", "op": "eq", "value": "alice@example.com"}],
            "note": "customer alice@example.com",
            "token": "ghp_abcdefghijklmnopqrstuvwxyz0123456789"
        });
        let s = summarize_params(&p);
        let text = s.to_string();
        assert_eq!(s["view"], "analytics.subscription_daily");
        assert_eq!(s["fields"], json!(["day", "plan", "subscriptions"]));
        assert_eq!(s["period_days"], 30);
        assert_eq!(s["filters"][0]["field"], "email");
        assert_eq!(s["filters"][0]["value"], "[string]");
        assert!(!text.contains("alice"));
        assert!(!text.contains("ghp_"));
        assert_eq!(s["token"], "[REDACTED]");
    }

    #[test]
    fn secret_detection() {
        assert!(looks_secret("ghp_x"));
        assert!(looks_secret("postgres://u:p@db/x"));
        assert!(looks_secret("AKIAABCDEFGHIJKLMNOP"));
        assert!(looks_secret("eyJhbGciOi.eyJzdWIiOi.sig"));
        assert!(!looks_secret("analytics.subscription_daily"));
        assert!(!looks_secret("https://api.github.com"));
    }

    #[test]
    fn config_guard() {
        assert!(config_contains_secret(&json!({"host":"db","password":"x"})));
        assert!(config_contains_secret(
            &json!({"base_url":"https://u:p@api.example.com"})
        ));
        assert!(!config_contains_secret(&json!({
            "host":"db","port":5432,
            "auth":{"type":"bearer"},
            "operations":{"list":{"query":{"token":{"type":"string"}}}}
        })));
    }
}
