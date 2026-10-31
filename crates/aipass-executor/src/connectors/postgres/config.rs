// SPDX-License-Identifier: Apache-2.0
//! PostgreSQL resource configuration (CONTRACTS §8):
//!
//! ```json
//! {"host":"db.internal","port":5432,"dbname":"lure","sslmode":"verify-full",
//!  "allowed_views":{"analytics.subscription_daily":{"fields":["day","plan","subscriptions"],
//!                                                    "date_field":"day"}},
//!  "statement_timeout_ms":5000,"max_rows_per_operation":1000,
//!  "allow_superuser":false,"lease_mode":"static"}
//! ```
//!
//! Additive optional keys: `ssl_root_cert` (PEM CA bundle — public data), `connect_timeout_ms`,
//! per-view `row_filter` (fixed conditions always ANDed, e.g. a tenant id), and
//! `temporary_role` (`{template_role, ttl_seconds, connection_limit}`, experimental).
//! Unknown keys are rejected (fail closed).

use std::collections::BTreeMap;
use std::sync::LazyLock;
use std::time::Duration;

use regex::Regex;
use serde::Deserialize;
use serde_json::Value;

use super::query::FilterOp;
use aipass_types::ApiError;

use crate::errors;

/// Default statement timeout.
pub const DEFAULT_STATEMENT_TIMEOUT_MS: u64 = 5000;
/// Bounds of `statement_timeout_ms`.
pub const STATEMENT_TIMEOUT_RANGE: (u64, u64) = (100, 60_000);
/// Default / maximum rows per operation.
pub const DEFAULT_MAX_ROWS: u64 = 1000;
/// Hard maximum rows per operation.
pub const HARD_MAX_ROWS: u64 = 10_000;

static IDENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[A-Za-z_][A-Za-z0-9_$]{0,62}$").unwrap_or_else(|e| panic!("ident regex: {e}"))
});

/// Whether `s` is an identifier this connector accepts (letters, digits, `_`, `$`; ≤ 63 bytes).
pub fn is_ident(s: &str) -> bool {
    IDENT.is_match(s)
}

/// `"ident"` with embedded quotes doubled.
pub fn quote_ident(s: &str) -> String {
    format!("\"{}\"", s.replace('"', "\"\""))
}

/// `sslmode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SslModeCfg {
    /// Plain TCP.
    Disable,
    /// TLS when offered, no verification (libpq semantics).
    Prefer,
    /// TLS required; chain verified only when `ssl_root_cert` is set (libpq semantics).
    #[default]
    Require,
    /// TLS with chain + host-name verification (webpki roots + `ssl_root_cert`).
    VerifyFull,
}

impl SslModeCfg {
    /// Parse the wire string (as stored in vault `DatabaseInfo.sslmode`).
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "disable" => Some(Self::Disable),
            "prefer" => Some(Self::Prefer),
            "require" => Some(Self::Require),
            "verify-full" => Some(Self::VerifyFull),
            _ => None,
        }
    }
}

/// `lease_mode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LeaseMode {
    /// Use the installed credential directly.
    #[default]
    Static,
    /// Experimental: create a short-lived role per grant from the installed (issuer)
    /// credential, drop it on `revoke_upstream`.
    TemporaryRole,
}

/// A fixed condition configured by the trusted client.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FixedFilter {
    /// Column.
    pub field: String,
    /// Operator.
    pub op: FilterOp,
    /// Value (scalar, or array for `in` / `between`).
    #[serde(default)]
    pub value: Option<Value>,
}

/// One allowlisted view.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ViewConfig {
    /// Fields the AI may select / filter / sort by.
    pub fields: Vec<String>,
    /// Column used by `period_days`.
    #[serde(default)]
    pub date_field: Option<String>,
    /// Conditions always applied (e.g. tenant isolation).
    #[serde(default)]
    pub row_filter: Vec<FixedFilter>,
}

/// Experimental temporary-role lease settings.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TemporaryRoleConfig {
    /// Existing NOLOGIN role whose privileges the temporary role inherits.
    pub template_role: String,
    /// Lease lifetime (bounded by the credential expiry). Default 900 s, max 86400 s.
    #[serde(default = "default_lease_ttl")]
    pub ttl_seconds: u64,
    /// `CONNECTION LIMIT` of the temporary role. Default 4.
    #[serde(default = "default_conn_limit")]
    pub connection_limit: u32,
}

fn default_lease_ttl() -> u64 {
    900
}
fn default_conn_limit() -> u32 {
    4
}
fn default_port() -> u16 {
    5432
}
fn default_timeout() -> u64 {
    DEFAULT_STATEMENT_TIMEOUT_MS
}
fn default_rows() -> u64 {
    DEFAULT_MAX_ROWS
}

/// Raw resource config.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PgConfig {
    /// Host name, IP, or absolute Unix-socket directory.
    pub host: String,
    /// Port.
    #[serde(default = "default_port")]
    pub port: u16,
    /// Database.
    pub dbname: String,
    /// TLS mode.
    #[serde(default)]
    pub sslmode: SslModeCfg,
    /// PEM root certificate(s) for `require` (chain check) / `verify-full`.
    #[serde(default)]
    pub ssl_root_cert: Option<String>,
    /// `"schema.view"` → view config.
    pub allowed_views: BTreeMap<String, ViewConfig>,
    /// `SET LOCAL statement_timeout` (100..=60000 ms).
    #[serde(default = "default_timeout")]
    pub statement_timeout_ms: u64,
    /// Row cap per operation (1..=10000).
    #[serde(default = "default_rows")]
    pub max_rows_per_operation: u64,
    /// Permit superuser / BYPASSRLS / server-file roles (default false).
    #[serde(default)]
    pub allow_superuser: bool,
    /// Credential mode.
    #[serde(default)]
    pub lease_mode: LeaseMode,
    /// Temporary-role settings (required for `lease_mode: temporary_role`).
    #[serde(default)]
    pub temporary_role: Option<TemporaryRoleConfig>,
    /// TCP/TLS connect timeout (default 10000 ms, max 30000 ms).
    #[serde(default)]
    pub connect_timeout_ms: Option<u64>,
}

impl PgConfig {
    /// Parse and validate.
    pub fn parse(config: &Value) -> Result<Self, ApiError> {
        let cfg: PgConfig =
            serde_json::from_value(config.clone()).map_err(|_| errors::bad_config("$"))?;
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> Result<(), ApiError> {
        if self.host.is_empty()
            || self.host.len() > 255
            || self.host.chars().any(char::is_whitespace)
        {
            return Err(errors::bad_config("host"));
        }
        if self.host.starts_with('/') && self.sslmode != SslModeCfg::Disable {
            return Err(errors::bad_config("sslmode"));
        }
        if self.dbname.is_empty() || self.dbname.len() > 63 || self.dbname.contains('\0') {
            return Err(errors::bad_config("dbname"));
        }
        if self.port == 0 {
            return Err(errors::bad_config("port"));
        }
        if !(STATEMENT_TIMEOUT_RANGE.0..=STATEMENT_TIMEOUT_RANGE.1)
            .contains(&self.statement_timeout_ms)
        {
            return Err(errors::bad_config("statement_timeout_ms"));
        }
        if !(1..=HARD_MAX_ROWS).contains(&self.max_rows_per_operation) {
            return Err(errors::bad_config("max_rows_per_operation"));
        }
        if let Some(ms) = self.connect_timeout_ms
            && !(100..=30_000).contains(&ms)
        {
            return Err(errors::bad_config("connect_timeout_ms"));
        }
        if let Some(pem) = &self.ssl_root_cert {
            crate::tls::parse_pem_certs(pem).map_err(|_| errors::bad_config("ssl_root_cert"))?;
        }
        if self.allowed_views.is_empty() {
            return Err(errors::bad_config("allowed_views"));
        }
        for (name, view) in &self.allowed_views {
            let at = format!("allowed_views.{name}");
            split_view(name).ok_or_else(|| errors::bad_config(&at))?;
            if view.fields.is_empty() || view.fields.len() > 256 {
                return Err(errors::bad_config(&format!("{at}.fields")));
            }
            if !view.fields.iter().all(|f| is_ident(f)) {
                return Err(errors::bad_config(&format!("{at}.fields")));
            }
            if let Some(d) = &view.date_field
                && !is_ident(d)
            {
                return Err(errors::bad_config(&format!("{at}.date_field")));
            }
            for (i, f) in view.row_filter.iter().enumerate() {
                let fat = format!("{at}.row_filter[{i}]");
                if !is_ident(&f.field) {
                    return Err(errors::bad_config(&fat));
                }
                super::query::filter_value_text(f.op, f.value.as_ref())
                    .map_err(|_| errors::bad_config(&fat))?;
            }
        }
        match (self.lease_mode, &self.temporary_role) {
            (LeaseMode::TemporaryRole, None) => return Err(errors::bad_config("temporary_role")),
            (LeaseMode::TemporaryRole, Some(t)) => {
                if !cfg!(feature = "experimental") {
                    return Err(errors::not_supported(
                        "临时数据库角色是实验性功能，此版本未启用",
                        "Temporary database roles are experimental and not enabled in this build.",
                    ));
                }
                if !is_ident(&t.template_role) {
                    return Err(errors::bad_config("temporary_role.template_role"));
                }
                if !(60..=86_400).contains(&t.ttl_seconds) {
                    return Err(errors::bad_config("temporary_role.ttl_seconds"));
                }
                if !(1..=100).contains(&t.connection_limit) {
                    return Err(errors::bad_config("temporary_role.connection_limit"));
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// Connect timeout.
    pub fn connect_timeout(&self) -> Duration {
        Duration::from_millis(self.connect_timeout_ms.unwrap_or(10_000))
    }

    /// View config by its exact `"schema.view"` name.
    pub fn view(&self, name: &str) -> Option<&ViewConfig> {
        self.allowed_views.get(name)
    }
}

/// Split `"schema.view"`; both parts must be identifiers.
pub fn split_view(name: &str) -> Option<(&str, &str)> {
    let (s, v) = name.split_once('.')?;
    (is_ident(s) && is_ident(v)).then_some((s, v))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_contract_shape() {
        let c = PgConfig::parse(&json!({
            "host":"127.0.0.1","port":5432,"dbname":"lure","sslmode":"verify-full",
            "allowed_views":{"analytics.subscription_daily":{"fields":["day","plan","subscriptions"],"date_field":"day"}},
            "statement_timeout_ms":5000,"max_rows_per_operation":1000,"allow_superuser":false,"lease_mode":"static"
        }))
        .unwrap();
        assert_eq!(c.sslmode, SslModeCfg::VerifyFull);
        assert!(c.view("analytics.subscription_daily").is_some());
    }

    #[test]
    fn rejects_bad_configs() {
        let base = json!({"host":"h","dbname":"d","allowed_views":{"a.b":{"fields":["x"]}}});
        PgConfig::parse(&base).unwrap();
        for bad in [
            json!({"host":"h","dbname":"d","allowed_views":{"ab":{"fields":["x"]}}}),
            json!({"host":"h","dbname":"d","allowed_views":{"a.b":{"fields":["x; drop"]}}}),
            json!({"host":"h","dbname":"d","allowed_views":{"a.b\"":{"fields":["x"]}}}),
            json!({"host":"h","dbname":"d","allowed_views":{}}),
            json!({"host":"h","dbname":"d","allowed_views":{"a.b":{"fields":["x"]}},"statement_timeout_ms":0}),
            json!({"host":"h","dbname":"d","allowed_views":{"a.b":{"fields":["x"]}},"surprise":true}),
            json!({"host":"h","dbname":"d","sslmode":"verify-ca","allowed_views":{"a.b":{"fields":["x"]}}}),
        ] {
            assert!(PgConfig::parse(&bad).is_err(), "{bad}");
        }
        assert_eq!(quote_ident("a\"b"), "\"a\"\"b\"");
    }
}
