// SPDX-License-Identifier: Apache-2.0
//! CONTRACTS §11 envelope helpers. Requests are `{id, type, …}`; responses are
//! `{id, ok:true, …}` or `{id, ok:false, error:{code, message}}`.

use serde_json::{Map, Value, json};

/// Request types defined by CONTRACTS §11.
pub const REQUEST_TYPES: &[&str] = &[
    "hello", "status", "match", "fill", "generate", "save", "open_app", "lock",
];

/// Error codes the extension understands (CONTRACTS §11).
pub mod codes {
    /// Vault locked or the desktop app is not running.
    pub const LOCKED: &str = "LOCKED";
    /// Unknown entry / nothing to act on.
    pub const NOT_FOUND: &str = "NOT_FOUND";
    /// Entry does not belong to the requesting frame's origin.
    pub const ORIGIN_MISMATCH: &str = "ORIGIN_MISMATCH";
    /// Too many requests.
    pub const RATE_LIMITED: &str = "RATE_LIMITED";
    /// The extension / host is not authorised by the desktop app.
    pub const NOT_PAIRED: &str = "NOT_PAIRED";
    /// Entry has unresolved sync conflicts.
    pub const SYNC_CONFLICT: &str = "SYNC_CONFLICT";
}

/// A request id is 1–64 characters of `[0-9A-Za-z_-]` (the extension sends 32 hex chars).
pub fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Extract a valid request id from a parsed message.
pub fn request_id(v: &Value) -> Option<&str> {
    v.get("id").and_then(Value::as_str).filter(|s| valid_id(s))
}

/// Build `{id, ok:true, ...fields}`.
pub fn ok(id: &str, fields: Value) -> Value {
    let mut m = match fields {
        Value::Object(m) => m,
        _ => Map::new(),
    };
    m.insert("id".into(), Value::String(id.to_owned()));
    m.insert("ok".into(), Value::Bool(true));
    Value::Object(m)
}

/// Build `{id, ok:false, error:{code, message}}`.
pub fn err(id: &str, code: &str, message: &str) -> Value {
    json!({"id": id, "ok": false, "error": {"code": code, "message": message}})
}

/// Message shown when the desktop app cannot be reached.
pub const APP_NOT_RUNNING: &str =
    "AI 通行证桌面 App 未运行或未解锁 / The AI Pass desktop app is not running or is locked";

/// Reply for a request the host must answer itself because the desktop app cannot be
/// reached (not running, or its IPC endpoint is gone). The vault is then effectively
/// locked, so:
///
/// * `hello` → `{app_version, locked:true, ai_mode_available:false}` (the host ships with
///   the app, so its version is the app's version) — the extension must be able to finish
///   its `hello` to offer 打开桌面 App (`open_app`);
/// * `status` → `{locked:true}`;
/// * everything else (`match`, `fill`, `generate`, `save`, `lock` — the host cannot prove
///   the app's vault is closed, so it never reports a lock as done — and `open_app` when
///   launching failed) → `LOCKED`.
pub fn offline_reply(id: &str, kind: &str, host_version: &str) -> Value {
    match kind {
        "hello" => ok(id, json!({"app_version": host_version, "locked": true, "ai_mode_available": false})),
        "status" => ok(id, json!({"locked": true})),
        _ => err(id, codes::LOCKED, APP_NOT_RUNNING),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelopes() {
        assert!(valid_id("0123456789abcdef0123456789abcdef"));
        assert!(!valid_id(""));
        assert!(!valid_id("a b"));
        assert!(!valid_id(&"a".repeat(65)));
        let v = ok("abc", json!({"locked": true}));
        assert_eq!(v, json!({"id":"abc","ok":true,"locked":true}));
        let e = err("abc", codes::LOCKED, "x");
        assert_eq!(e["error"]["code"], "LOCKED");
        assert_eq!(request_id(&json!({"id":"zz"})), Some("zz"));
        assert_eq!(request_id(&json!({"id":5})), None);
    }

    #[test]
    fn offline_replies_follow_contract_shapes() {
        assert_eq!(
            offline_reply("h", "hello", "0.1.0"),
            json!({"id":"h","ok":true,"app_version":"0.1.0","locked":true,"ai_mode_available":false})
        );
        assert_eq!(offline_reply("s", "status", "0.1.0"), json!({"id":"s","ok":true,"locked":true}));
        for kind in ["match", "fill", "generate", "save", "lock", "open_app", "bogus"] {
            let v = offline_reply("x", kind, "0.1.0");
            assert_eq!(v["ok"], false);
            assert_eq!(v["error"]["code"], codes::LOCKED, "{kind}");
        }
    }
}
