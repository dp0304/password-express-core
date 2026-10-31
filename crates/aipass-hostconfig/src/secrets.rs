// SPDX-License-Identifier: Apache-2.0
//! Secret-looking string detection (defence in depth).
//!
//! The wizard never writes secrets: entries are validated against a strict grammar, and as a
//! second line of defence every entry is scanned for well-known credential formats. Diffs
//! shown to the user (or to an AI agent that runs the wizard) redact secret-looking values
//! found in the user's *other* settings.

use std::sync::OnceLock;

use regex::Regex;

fn patterns() -> &'static [Regex] {
    static P: OnceLock<Vec<Regex>> = OnceLock::new();
    P.get_or_init(|| {
        [
            r"ghp_[A-Za-z0-9]{20,}",
            r"github_pat_[A-Za-z0-9_]{20,}",
            r"gh[osur]_[A-Za-z0-9]{20,}",
            r"(?:^|[^A-Za-z0-9])sk-(?:ant-)?[A-Za-z0-9_\-]{16,}",
            r"AKIA[0-9A-Z]{16}",
            r"xox[abeprs]-[A-Za-z0-9\-]{10,}",
            r"[sr]k_(?:live|test)_[A-Za-z0-9]{10,}",
            r"glpat-[A-Za-z0-9_\-]{20,}",
            r"AIza[0-9A-Za-z_\-]{35}",
            r"npm_[A-Za-z0-9]{36}",
            r"eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]*",
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
            r"[A-Za-z][A-Za-z0-9+.\-]*://[^/\s:@]+:[^/\s@]+@",
            r"(?i)bearer\s+[A-Za-z0-9._~+/\-]{8,}",
            r"aip[cars]_[A-Za-z0-9_\-]{8,}",
            r#"(?i)(?:password|passwd|secret|api[_-]?key|token)["']?\s*[:=]\s*["']?[^\s"',}]{6,}"#,
        ]
        .iter()
        .filter_map(|p| Regex::new(p).ok())
        .collect()
    })
}

/// Whether `s` contains something that looks like a credential.
pub fn contains_secret(s: &str) -> bool {
    patterns().iter().any(|r| r.is_match(s))
}

/// Replace secret-looking substrings with `[REDACTED]`.
pub fn redact(s: &str) -> String {
    let mut out = s.to_owned();
    for r in patterns() {
        out = r.replace_all(&out, "[REDACTED]").into_owned();
    }
    out
}

/// Quoted string values (JSON / TOML) whose key names a credential: `"AWS_SECRET_ACCESS_KEY":
/// "…"`, `STRIPE_SECRET_KEY = "…"`, `"x-api-key": "…"`, `"SESSION_COOKIE": "…"`. Display only:
/// the value format is unknown, so the key decides.
fn credential_key_value() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(
            r#"(?i)(["']?[A-Za-z0-9_.\-]*(?:key|secret|token|passw|pwd|credential|auth|cookie|session|private|signature)[A-Za-z0-9_.\-]*["']?\s*[:=]\s*)(?:"(?:[^"\\]|\\.)*"|'[^']*')"#,
        )
        .expect("static regex")
    })
}

/// Redaction for text shown to the user (or to an AI agent driving the wizard), such as the
/// diff of a host config: everything [`redact`] catches plus the value of every quoted
/// string whose key names a credential.
pub fn redact_for_display(s: &str) -> String {
    let out = credential_key_value().replace_all(s, "${1}\"[REDACTED]\"");
    redact(&out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_and_redacts() {
        for s in [
            "ghp_abcdefghijklmnopqrstuvwxyz0123",
            "token sk-ant-api03-abcdefghijklmnopqrst",
            "AKIAABCDEFGHIJKLMNOP",
            "postgres://app:hunter22@db.internal/x",
            "Authorization: Bearer abcdefghijk",
            "aipc_abcdefghijklmnop",
            "\"API_KEY\": \"abcdef123456\"",
            "-----BEGIN OPENSSH PRIVATE KEY-----",
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.sig",
        ] {
            assert!(contains_secret(s), "{s}");
            assert!(!redact(s).contains("abcdefghijklmnop") || s.contains("BEGIN"), "{s}");
        }
        for s in [
            "/Users/desk-top/bin/aipass-mcp",
            "stdio --connection conn_01jbz3k6w8a7m2q4t5v9x0y1z4",
            "https://node.example.com/mcp",
            "\"command\": \"npx\"",
            "\"tokens_used\": 3",
        ] {
            assert!(!contains_secret(s), "{s}");
        }
        assert_eq!(redact("x ghp_abcdefghijklmnopqrstuvwxyz0123 y"), "x [REDACTED] y");
    }

    /// MNC-06: neighbouring credentials of other servers never reach a printed diff.
    #[test]
    fn display_redaction_covers_credential_keys() {
        for (line, value) in [
            ("        \"AWS_SECRET_ACCESS_KEY\": \"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\"", "wJalrXUtnFEMI"),
            ("        \"STRIPE_SECRET_KEY\": \"sk_live_51Habcdefghijklmnop\",", "sk_live_51H"),
            ("STRIPE_KEY = \"rk_test_abcdefghijklmnop\"", "rk_test_abc"),
            ("  \"x-api-key\": \"short1\"", "short1"),
            ("  \"SESSION_COOKIE\": 'abc def'", "abc def"),
            ("  \"DB_PASSWD\": \"a\\\"b\"", "a\\\"b"),
            ("  \"GITLAB\": \"glpat-abcdefghijklmnopqrst\"", "glpat-abc"),
        ] {
            let out = redact_for_display(line);
            assert!(out.contains("[REDACTED]"), "{line} -> {out}");
            assert!(!out.contains(value), "{line} -> {out}");
        }
        for line in [
            "      \"command\": \"/usr/local/bin/aipass-mcp\",",
            "      \"args\": [\"stdio\", \"--connection\", \"conn_01jbz3k6w8a7m2q4t5v9x0y1z4\"]",
            "\"tokens_used\": 3",
        ] {
            assert_eq!(redact_for_display(line), line);
        }
    }
}
