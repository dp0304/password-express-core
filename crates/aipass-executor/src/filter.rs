// SPDX-License-Identifier: Apache-2.0
//! Output filter used by every connector (CONTRACTS §8, design doc §9.8, A18).
//!
//! Two layers, applied in this order:
//!
//! 1. **Field allowlist** ([`FieldTree::project`]) — only configured fields survive. This is
//!    the primary output boundary together with the connector's own allowlists.
//! 2. **Secret detection** ([`OutputFilter`]) — string values that look like credentials
//!    (`ghp_…`, `github_pat_…`, `sk-…`, `AKIA…`, `xox?-…`, JWTs, PEM private keys,
//!    `scheme://user:pass@`, `Bearer …`, `password=…`) or that contain the installed
//!    credential's own username/secret (also in base64 / URL-encoded form) are replaced
//!    with `"[REDACTED]"` and their field path is added to `restricted_fields`.
//!
//! Detection is a **secondary** defence: it cannot stop arbitrary encodings, splitting or
//! deliberate exfiltration (§9.8). The real boundary is what each connector is allowed to
//! fetch and which fields it may return.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::LazyLock;

use aipass_types::exec::CredentialMaterial;
use base64::Engine as _;
use regex::Regex;
use serde_json::{Map, Value};
use zeroize::Zeroizing;

/// Replacement text for redacted values.
pub const REDACTED: &str = "[REDACTED]";

/// Minimum length of an installed secret for substring matching (shorter values would
/// redact ordinary data).
pub const MIN_EXACT_SECRET_LEN: usize = 4;
/// Usernames at least this long are also matched as substrings; shorter ones only when a
/// value equals the username exactly.
pub const MIN_USERNAME_SUBSTRING_LEN: usize = 8;

// ======================================================================================
// Field allowlist
// ======================================================================================

/// A tree of allowed dotted field paths (`"owner.login"`, `"labels.name"`). Arrays are
/// traversed transparently: `labels.name` applied to `{"labels":[{"name":"x","color":"f"}]}`
/// yields `{"labels":[{"name":"x"}]}`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FieldTree {
    children: BTreeMap<String, FieldTree>,
    /// The path ends here: keep the whole value.
    leaf: bool,
}

impl FieldTree {
    /// Build from dotted paths. Empty segments are ignored.
    pub fn from_paths<I, S>(paths: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut root = FieldTree::default();
        for p in paths {
            let mut node = &mut root;
            let segs: Vec<&str> = p.as_ref().split('.').filter(|s| !s.is_empty()).collect();
            if segs.is_empty() {
                continue;
            }
            for s in segs {
                node = node.children.entry(s.to_owned()).or_default();
            }
            node.leaf = true;
        }
        root
    }

    /// True when no path is allowed.
    pub fn is_empty(&self) -> bool {
        self.children.is_empty() && !self.leaf
    }

    /// Project `value` onto the allowed paths. Keys that are not allowed are dropped; a
    /// value whose shape does not match (scalar where an object was expected) becomes
    /// `null`.
    pub fn project(&self, value: &Value) -> Value {
        if self.leaf {
            return value.clone();
        }
        match value {
            Value::Object(map) => {
                let mut out = Map::new();
                for (k, child) in &self.children {
                    if let Some(v) = map.get(k) {
                        out.insert(k.clone(), child.project(v));
                    }
                }
                Value::Object(out)
            }
            Value::Array(items) => Value::Array(items.iter().map(|i| self.project(i)).collect()),
            Value::Null => Value::Null,
            _ => Value::Null,
        }
    }
}

// ======================================================================================
// Secret detectors
// ======================================================================================

struct Detector {
    name: &'static str,
    re: Regex,
    /// Extra check on the matched text (reduces false positives in prose).
    validate: fn(&str) -> bool,
    /// Context-based (`password=…`, `Authorization: …`) rather than token-shaped. Skipped by
    /// the serialized-output sweep, where JSON punctuation would make `"password":"…"`
    /// match for any value.
    contextual: bool,
}

fn always(_: &str) -> bool {
    true
}

fn has_digit_or_symbol(m: &str) -> bool {
    // The token part after the scheme word must look machine-generated.
    let token = m.split_whitespace().last().unwrap_or("");
    token
        .chars()
        .any(|c| c.is_ascii_digit() || "-._~+/=".contains(c))
}

fn d(name: &'static str, pattern: &str, validate: fn(&str) -> bool) -> Detector {
    Detector {
        name,
        // The patterns are constants; failing to compile one is a programming error caught
        // by the unit tests.
        re: Regex::new(pattern).unwrap_or_else(|e| panic!("detector {name}: {e}")),
        validate,
        contextual: false,
    }
}

fn contextual(mut det: Detector) -> Detector {
    det.contextual = true;
    det
}

static DETECTORS: LazyLock<Vec<Detector>> = LazyLock::new(|| {
    vec![
        d("github_token", r"\bgh[pousr]_[A-Za-z0-9]{20,255}", always),
        d("github_pat", r"\bgithub_pat_[A-Za-z0-9_]{20,255}", always),
        d("anthropic_key", r"\bsk-ant-[A-Za-z0-9_\-]{16,}", always),
        d("openai_style_key", r"\bsk-[A-Za-z0-9_\-]{16,}", always),
        d(
            "stripe_secret",
            r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{10,}",
            always,
        ),
        d("aws_access_key", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b", always),
        d("slack_token", r"\bxox[abprs]-[A-Za-z0-9\-]{10,}", always),
        d("google_api_key", r"\bAIza[0-9A-Za-z_\-]{35}", always),
        d(
            "jwt",
            r"\beyJ[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}",
            always,
        ),
        d(
            "pem_private_key",
            r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY( BLOCK)?-----",
            always,
        ),
        d(
            "url_credentials",
            r"[A-Za-z][A-Za-z0-9+.\-]*://[^\s/:@]+:[^\s/@]+@",
            always,
        ),
        d(
            "bearer_token",
            r"(?i)\bbearer\s+[A-Za-z0-9\-._~+/]{12,}=*",
            has_digit_or_symbol,
        ),
        contextual(d(
            "authorization_header",
            r#"(?i)\bauthorization["']?\s*[:=]\s*["']?(?:basic|bearer|token|digest)\s+\S{8,}"#,
            always,
        )),
        contextual(d(
            "secret_assignment",
            r#"(?i)\b(?:password|passwd|pwd|secret|client_secret|api[_\-]?key|access[_\-]?token|refresh[_\-]?token|auth[_\-]?token|private[_\-]?key)\b["']?\s*[:=]\s*["']?[^\s"',;&]{8,}"#,
            always,
        )),
    ]
});

/// Names of the built-in detectors (for documentation and tests).
pub fn detector_names() -> Vec<&'static str> {
    DETECTORS.iter().map(|d| d.name).collect()
}

/// Why a string was redacted (never contains the matched text).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Detection {
    /// A built-in pattern matched.
    Pattern(&'static str),
    /// The installed credential (or an encoding of it) appeared.
    InstalledCredential,
}

/// The secret detector, optionally armed with the installed credential's own values.
#[derive(Default)]
pub struct OutputFilter {
    /// Substrings that must never appear (secret + encodings, long usernames).
    needles: Vec<Zeroizing<String>>,
    /// Values that must not appear as a whole value (short usernames).
    whole_values: Vec<Zeroizing<String>>,
}

impl std::fmt::Debug for OutputFilter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OutputFilter")
            .field("detectors", &DETECTORS.len())
            .field("credential_needles", &self.needles.len())
            .finish()
    }
}

impl OutputFilter {
    /// Pattern detectors only.
    pub fn new() -> Self {
        Self::default()
    }

    /// Pattern detectors plus exact matching of `material`'s username and secret.
    pub fn for_credential(material: &CredentialMaterial) -> Self {
        let mut f = Self::new();
        f.add_secret(material.secret.expose());
        if let Some(u) = &material.username {
            f.add_username(u);
            if !material.secret.is_empty() {
                let basic = Zeroizing::new(format!("{u}:{}", material.secret.expose()));
                f.push_needle(base64::engine::general_purpose::STANDARD.encode(basic.as_bytes()));
            }
        }
        f
    }

    fn push_needle(&mut self, s: String) {
        let s = Zeroizing::new(s);
        if s.len() >= MIN_EXACT_SECRET_LEN && !self.needles.iter().any(|n| **n == *s) {
            self.needles.push(s);
        }
    }

    /// Add a secret value; its common encodings (base64, base64url, percent-encoding, JSON
    /// escaping) are matched too.
    pub fn add_secret(&mut self, secret: &str) {
        if secret.len() < MIN_EXACT_SECRET_LEN {
            return;
        }
        const COMPONENT: &percent_encoding::AsciiSet = &percent_encoding::NON_ALPHANUMERIC
            .remove(b'-')
            .remove(b'_')
            .remove(b'.')
            .remove(b'~');
        let b = secret.as_bytes();
        // The padded base64 form contains the unpadded one, so matching unpadded suffices.
        self.push_needle(secret.to_owned());
        self.push_needle(base64::engine::general_purpose::STANDARD_NO_PAD.encode(b));
        self.push_needle(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b));
        self.push_needle(
            percent_encoding::utf8_percent_encode(secret, percent_encoding::NON_ALPHANUMERIC)
                .to_string(),
        );
        self.push_needle(percent_encoding::utf8_percent_encode(secret, COMPONENT).to_string());
        if let Ok(js) = serde_json::to_string(secret) {
            // JSON-escaped form without the surrounding quotes (matters for the final sweep
            // over serialized output).
            let inner = js[1..js.len() - 1].to_owned();
            self.push_needle(inner);
        }
    }

    /// Add a username (account identifier).
    pub fn add_username(&mut self, username: &str) {
        if username.is_empty() {
            return;
        }
        if username.len() >= MIN_USERNAME_SUBSTRING_LEN {
            self.push_needle(username.to_owned());
        } else {
            self.whole_values.push(Zeroizing::new(username.to_owned()));
        }
    }

    /// Scan one string.
    pub fn scan_str(&self, s: &str) -> Option<Detection> {
        if self.needles.iter().any(|n| s.contains(n.as_str()))
            || self.whole_values.iter().any(|w| s.trim() == w.as_str())
        {
            return Some(Detection::InstalledCredential);
        }
        for det in DETECTORS.iter() {
            if let Some(m) = det.re.find(s) {
                if (det.validate)(m.as_str()) {
                    return Some(Detection::Pattern(det.name));
                }
                // A rejected match may hide a valid one later in the string.
                if det.re.find_iter(s).any(|m| (det.validate)(m.as_str())) {
                    return Some(Detection::Pattern(det.name));
                }
            }
        }
        None
    }

    /// Redact `value` in place. `path` is the dotted path of `value` itself (`""` at the
    /// root); array indices are not part of paths. Paths of redacted values are added to
    /// `restricted`.
    pub fn redact(&self, value: &mut Value, path: &str, restricted: &mut BTreeSet<String>) {
        match value {
            Value::String(s) => {
                if self.scan_str(s).is_some() {
                    *value = Value::String(REDACTED.to_owned());
                    restricted.insert(if path.is_empty() {
                        "value".to_owned()
                    } else {
                        path.to_owned()
                    });
                }
            }
            Value::Number(n) => {
                let text = n.to_string();
                if self.needles.iter().any(|x| text == x.as_str())
                    || self.whole_values.iter().any(|x| text == x.as_str())
                {
                    *value = Value::String(REDACTED.to_owned());
                    restricted.insert(if path.is_empty() {
                        "value".to_owned()
                    } else {
                        path.to_owned()
                    });
                }
            }
            Value::Array(items) => {
                for i in items {
                    self.redact(i, path, restricted);
                }
            }
            Value::Object(map) => {
                let bad_keys: Vec<String> = map
                    .keys()
                    .filter(|k| self.scan_str(k).is_some())
                    .cloned()
                    .collect();
                if !bad_keys.is_empty() {
                    for k in &bad_keys {
                        map.remove(k);
                    }
                    map.insert(REDACTED.to_owned(), Value::String(REDACTED.to_owned()));
                    restricted.insert(if path.is_empty() {
                        "key".to_owned()
                    } else {
                        format!("{path}.key")
                    });
                }
                for (k, v) in map.iter_mut() {
                    if k == REDACTED {
                        continue;
                    }
                    let child = if path.is_empty() {
                        k.clone()
                    } else {
                        format!("{path}.{k}")
                    };
                    self.redact(v, &child, restricted);
                }
            }
            Value::Bool(_) | Value::Null => {}
        }
    }

    /// Final safety net over the serialized output: true when any needle or pattern is still
    /// present (the caller then withholds the whole result with `RESULT_RESTRICTED`).
    pub fn leaks(&self, value: &Value) -> bool {
        let Ok(text) = serde_json::to_string(value) else {
            return true;
        };
        let text = Zeroizing::new(text);
        if self.needles.iter().any(|n| text.contains(n.as_str())) {
            return true;
        }
        DETECTORS
            .iter()
            .filter(|d| !d.contextual)
            .any(|d| d.re.find_iter(&text).any(|m| (d.validate)(m.as_str())))
    }
}

/// Result of [`filter_value`].
#[derive(Debug, Clone, PartialEq)]
pub struct Filtered {
    /// Projected and redacted data.
    pub data: Value,
    /// Paths of redacted values (sorted, unique).
    pub restricted_fields: Vec<String>,
}

/// Project (when `fields` is given) and redact `value`.
pub fn filter_value(filter: &OutputFilter, value: &Value, fields: Option<&FieldTree>) -> Filtered {
    let mut data = match fields {
        Some(t) => t.project(value),
        None => value.clone(),
    };
    let mut restricted = BTreeSet::new();
    filter.redact(&mut data, "", &mut restricted);
    Filtered {
        data,
        restricted_fields: restricted.into_iter().collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aipass_crypto::SecretString;
    use aipass_types::EntryId;
    use aipass_types::vault::EntryKind;
    use serde_json::json;

    fn material() -> CredentialMaterial {
        CredentialMaterial {
            entry_id: EntryId::generate(),
            version: 1,
            kind: EntryKind::Database,
            username: Some("ai_reader_role".into()),
            secret: SecretString::from("Pg-Secret-7f3a9c!"),
            database: None,
            expires_at: chrono::Utc::now() + chrono::Duration::seconds(60),
        }
    }

    #[test]
    fn projection_keeps_only_allowed_paths() {
        let t = FieldTree::from_paths(["id", "owner.login", "labels.name"]);
        let v = json!({
            "id": 1, "secret": "x",
            "owner": {"login": "octo", "email": "o@example.com"},
            "labels": [{"name": "bug", "color": "red"}, {"name": "ui"}]
        });
        assert_eq!(
            t.project(&v),
            json!({"id":1,"owner":{"login":"octo"},"labels":[{"name":"bug"},{"name":"ui"}]})
        );
        assert_eq!(t.project(&json!([{"id": 2, "x": 3}])), json!([{"id": 2}]));
        assert_eq!(t.project(&json!({"owner": "flat"})), json!({"owner": null}));
    }

    #[test]
    fn every_pattern_detector_fires() {
        let f = OutputFilter::new();
        let samples = [
            "token ghp_0123456789abcdefghijABCDEFGHIJ012345",
            "github_pat_11ABCDEFG0123456789_abcdefghijklmnopqrstuvwxyz",
            "gho_abcdefghijklmnopqrstuvwxyz0123",
            "ghs_abcdefghijklmnopqrstuvwxyz0123",
            "key sk-proj-abcdefghijklmnop1234",
            "sk-ant-api03-abcdefghijklmnopqrstuv",
            "sk_live_abcdefghijklmnop",
            "AKIAIOSFODNN7EXAMPLE",
            "xoxb-123456789012-abcdefghij",
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
            "-----BEGIN RSA PRIVATE KEY-----\nMIIE...",
            "-----BEGIN OPENSSH PRIVATE KEY-----",
            "postgres://admin:hunter2@db.internal:5432/app",
            "Authorization: Bearer abc.def-123456789xyz",
            "password=CorrectHorseBattery",
            "AIzaSyA1234567890abcdefghijklmnopqrstuv",
        ];
        for s in samples {
            assert!(f.scan_str(s).is_some(), "not detected: {s}");
        }
        let benign = [
            "a basic understanding of bearer bonds",
            "plan pro, 12 subscriptions",
            "https://github.com/octo/repo",
            "skill-based routing",
            "2026-10-30",
        ];
        for s in benign {
            assert!(f.scan_str(s).is_none(), "false positive: {s}");
        }
    }

    #[test]
    fn installed_credential_and_encodings_are_redacted() {
        let m = material();
        let f = OutputFilter::for_credential(&m);
        let b64 = base64::engine::general_purpose::STANDARD.encode("Pg-Secret-7f3a9c!");
        let pct = "Pg-Secret-7f3a9c%21";
        let mut v = json!({
            "rows": [
                {"note": "the password is Pg-Secret-7f3a9c! ok", "plan": "pro"},
                {"note": format!("b64 {b64}"), "plan": "pro"},
                {"note": format!("url {pct}"), "plan": "basic"},
                {"note": "owner ai_reader_role", "plan": "free"},
            ],
            "meta": {"Pg-Secret-7f3a9c!": 1}
        });
        let mut r = BTreeSet::new();
        f.redact(&mut v, "", &mut r);
        let s = v.to_string();
        assert!(!s.contains("Pg-Secret"), "{s}");
        assert!(!s.contains(&b64));
        assert!(!s.contains("ai_reader_role"));
        assert_eq!(
            r.into_iter().collect::<Vec<_>>(),
            vec!["meta.key".to_owned(), "rows.note".to_owned()]
        );
        assert_eq!(v["rows"][0]["plan"], "pro");
        assert!(!f.leaks(&v));
        assert!(f.leaks(&json!({"x": "Pg-Secret-7f3a9c!"})));
        let dbg = format!("{f:?}");
        assert!(!dbg.contains("Pg-Secret"));
    }

    #[test]
    fn short_username_only_matches_whole_value() {
        let mut f = OutputFilter::new();
        f.add_username("bob");
        assert!(f.scan_str("bob").is_some());
        assert!(f.scan_str("bobcat").is_none());
    }

    #[test]
    fn filter_value_combines_projection_and_redaction() {
        let f = OutputFilter::new();
        let t = FieldTree::from_paths(["name", "description"]);
        let out = filter_value(
            &f,
            &json!({"name":"r","description":"leaked ghp_0123456789abcdefghijABCDEFGHIJ012345","token":"x"}),
            Some(&t),
        );
        assert_eq!(out.data, json!({"name":"r","description":"[REDACTED]"}));
        assert_eq!(out.restricted_fields, vec!["description".to_owned()]);
    }
}
