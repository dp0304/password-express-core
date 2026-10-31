// SPDX-License-Identifier: Apache-2.0
//! Declarative HTTPS API connector (CONTRACTS §8). There is **no** arbitrary HTTP forwarding:
//! the AI calls `http_api.call` with the name of an operation the trusted client declared
//! and typed parameters; method, origin, path template, auth placement and the output field
//! allowlist all come from the resource config.
//!
//! ```json
//! {"base_url": "https://api.example.com/v1",
//!  "auth": {"type": "bearer"},                    // bearer | header{name} | query{name} | basic
//!  "allow_private_network": false,
//!  "timeout_ms": 10000, "max_response_bytes": 1048576,          // optional, ≤ defaults
//!  "operations": {
//!    "list_orders": {"method": "GET", "path": "/orders",
//!                    "query": {"status": {"type": "string", "enum": ["open","closed"]},
//!                              "limit": {"type": "integer", "max": 100}},
//!                    "side_effect": "read", "retry_safe": true,
//!                    "response": {"items_path": "data", "allowed_fields": ["id","status","total"]}},
//!    "get_order":   {"method": "GET", "path": "/orders/{order_id}",
//!                    "path_params": {"order_id": {"type": "string", "max": 64}},
//!                    "side_effect": "read", "retry_safe": true,
//!                    "response": {"allowed_fields": ["id","status"]}}}}
//! ```
//!
//! Call parameters: `{"operation": "list_orders", "params": {"status": "open"}, "body"?: {…}}`.
//! Grant scope: `{operations:["http_api.call"], http_api:{operations:["list_orders"]}}`.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::LazyLock;
use std::time::Duration;

use aipass_types::exec::{ExecutionOutcome, LevelReport, NormalizedRequest, OperationSpec, Stage};
use aipass_types::models::{
    Connector, GrantScope, HttpApiScope, Resource, SideEffectClass, SideEffects,
};
use aipass_types::vault::EntryKind;
use aipass_types::{ApiError, ErrorCode, GrantId};
use async_trait::async_trait;
use base64::Engine as _;
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use regex::Regex;
use reqwest::header::{ACCEPT, AUTHORIZATION, HeaderMap, HeaderName, HeaderValue};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use url::Url;

use crate::connectors::{ConnectorDriver, ExecContext, SessionsClosed};
use crate::egress::{EgressError, EgressGuard, EgressPolicy, EgressRequest, MAX_RESPONSE_BYTES};
use crate::errors;
use crate::filter::{FieldTree, OutputFilter};
use crate::schema;

/// Operation name.
pub const CALL: &str = "http_api.call";
/// Max items returned per call.
pub const MAX_ITEMS: u64 = 1000;
/// Default max length of string parameters.
pub const DEFAULT_STRING_MAX: i64 = 256;

/// RFC 3986 unreserved characters stay; everything else in a path parameter is encoded
/// (including `/`, `?`, `#`, `%`).
const PATH_PARAM: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

static OP_NAME: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-z][a-z0-9_]{0,63}$").unwrap_or_else(|e| panic!("{e}")));
static PARAM_NAME: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[A-Za-z_][A-Za-z0-9_.\-]{0,63}$").unwrap_or_else(|e| panic!("{e}"))
});
static HEADER_NAME: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z0-9\-]{1,64}$").unwrap_or_else(|e| panic!("{e}")));
static TEMPLATE_STATIC: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z0-9\-._~/]*$").unwrap_or_else(|e| panic!("{e}")));

const FORBIDDEN_HEADERS: &[&str] = &[
    "host",
    "content-length",
    "content-type",
    "transfer-encoding",
    "connection",
    "upgrade",
    "te",
    "trailer",
    "proxy-authorization",
    "proxy-connection",
    "keep-alive",
    "expect",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum AuthType {
    Bearer,
    Header,
    Query,
    Basic,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthConfig {
    #[serde(rename = "type")]
    ty: AuthType,
    #[serde(default)]
    name: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ParamType {
    String,
    Integer,
    Boolean,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ParamSpec {
    #[serde(rename = "type")]
    ty: ParamType,
    #[serde(default, rename = "enum")]
    allowed: Option<Vec<Value>>,
    /// Strings: max length; integers: max value.
    #[serde(default)]
    max: Option<i64>,
    /// Integers: min value; strings: min length.
    #[serde(default)]
    min: Option<i64>,
    #[serde(default)]
    required: bool,
    #[serde(default)]
    pattern: Option<String>,
    #[serde(default)]
    description: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
enum OnSecret {
    #[default]
    Redact,
    Withhold,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResponseConfig {
    #[serde(default)]
    items_path: Option<String>,
    allowed_fields: Vec<String>,
    #[serde(default)]
    on_secret_detected: OnSecret,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct OpConfig {
    method: String,
    path: String,
    #[serde(default)]
    path_params: BTreeMap<String, ParamSpec>,
    #[serde(default)]
    query: BTreeMap<String, ParamSpec>,
    #[serde(default)]
    body_schema: Option<Value>,
    side_effect: SideEffectClass,
    #[serde(default)]
    retry_safe: bool,
    response: ResponseConfig,
    #[serde(default)]
    description_zh: Option<String>,
    #[serde(default)]
    description_en: Option<String>,
}

impl OpConfig {
    fn method(&self) -> reqwest::Method {
        match self.method.as_str() {
            "POST" => reqwest::Method::POST,
            "PUT" => reqwest::Method::PUT,
            "PATCH" => reqwest::Method::PATCH,
            "DELETE" => reqwest::Method::DELETE,
            _ => reqwest::Method::GET,
        }
    }
    fn writes(&self) -> bool {
        self.side_effect != SideEffectClass::Read
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct HttpApiConfig {
    base_url: String,
    auth: AuthConfig,
    #[serde(default)]
    allow_private_network: bool,
    #[serde(default)]
    timeout_ms: Option<u64>,
    #[serde(default)]
    max_response_bytes: Option<u64>,
    operations: BTreeMap<String, OpConfig>,
}

fn template_params(path: &str) -> Result<Vec<String>, ()> {
    let mut out = Vec::new();
    let mut rest = path;
    while let Some(start) = rest.find('{') {
        let (stat, tail) = rest.split_at(start);
        if !TEMPLATE_STATIC.is_match(stat) {
            return Err(());
        }
        let end = tail.find('}').ok_or(())?;
        let name = &tail[1..end];
        if !PARAM_NAME.is_match(name) {
            return Err(());
        }
        out.push(name.to_owned());
        rest = &tail[end + 1..];
    }
    if !TEMPLATE_STATIC.is_match(rest) || rest.contains('}') {
        return Err(());
    }
    Ok(out)
}

impl HttpApiConfig {
    fn parse(v: &Value) -> Result<Self, ApiError> {
        let c: HttpApiConfig =
            serde_json::from_value(v.clone()).map_err(|_| errors::bad_config("$"))?;
        let base = c.base()?;
        EgressGuard::check_url_shape(&base, false).map_err(|_| errors::bad_config("base_url"))?;
        if base.query().is_some() || base.fragment().is_some() {
            return Err(errors::bad_config("base_url"));
        }
        match c.auth.ty {
            AuthType::Header => {
                let n = c.auth.name.as_deref().unwrap_or("");
                if !HEADER_NAME.is_match(n)
                    || FORBIDDEN_HEADERS.contains(&n.to_ascii_lowercase().as_str())
                {
                    return Err(errors::bad_config("auth.name"));
                }
            }
            AuthType::Query => {
                let n = c.auth.name.as_deref().unwrap_or("");
                if !PARAM_NAME.is_match(n) {
                    return Err(errors::bad_config("auth.name"));
                }
            }
            AuthType::Bearer | AuthType::Basic => {
                if c.auth.name.is_some() {
                    return Err(errors::bad_config("auth.name"));
                }
            }
        }
        if let Some(ms) = c.timeout_ms
            && !(100..=10_000).contains(&ms)
        {
            return Err(errors::bad_config("timeout_ms"));
        }
        if let Some(b) = c.max_response_bytes
            && !(1..=MAX_RESPONSE_BYTES as u64).contains(&b)
        {
            return Err(errors::bad_config("max_response_bytes"));
        }
        if c.operations.is_empty() || c.operations.len() > 100 {
            return Err(errors::bad_config("operations"));
        }
        for (name, op) in &c.operations {
            let at = format!("operations.{name}");
            if !OP_NAME.is_match(name) {
                return Err(errors::bad_config(&at));
            }
            if !["GET", "POST", "PUT", "PATCH", "DELETE"].contains(&op.method.as_str()) {
                return Err(errors::bad_config(&format!("{at}.method")));
            }
            if !op.path.starts_with('/') || op.path.contains("..") || op.path.contains("//") {
                return Err(errors::bad_config(&format!("{at}.path")));
            }
            let placeholders =
                template_params(&op.path).map_err(|_| errors::bad_config(&format!("{at}.path")))?;
            let declared: BTreeSet<&String> = op.path_params.keys().collect();
            let used: BTreeSet<&String> = placeholders.iter().collect();
            if declared.iter().any(|d| !used.contains(d)) {
                return Err(errors::bad_config(&format!("{at}.path_params")));
            }
            for (pname, spec) in op.path_params.iter().chain(op.query.iter()) {
                if !PARAM_NAME.is_match(pname) {
                    return Err(errors::bad_config(&format!("{at}.{pname}")));
                }
                check_param_spec(spec).map_err(|_| errors::bad_config(&format!("{at}.{pname}")))?;
            }
            if op.path_params.keys().any(|k| op.query.contains_key(k)) {
                return Err(errors::bad_config(&format!("{at}.query")));
            }
            if c.auth.ty == AuthType::Query
                && op.query.contains_key(c.auth.name.as_deref().unwrap_or(""))
            {
                return Err(errors::bad_config(&format!("{at}.query")));
            }
            if let Some(s) = &op.body_schema {
                if op.method == "GET" {
                    return Err(errors::bad_config(&format!("{at}.body_schema")));
                }
                schema::check_schema(s)
                    .map_err(|_| errors::bad_config(&format!("{at}.body_schema")))?;
            }
            if op.response.allowed_fields.is_empty() || op.response.allowed_fields.len() > 200 {
                return Err(errors::bad_config(&format!("{at}.response.allowed_fields")));
            }
        }
        Ok(c)
    }

    fn base(&self) -> Result<Url, ApiError> {
        Url::parse(&self.base_url).map_err(|_| errors::bad_config("base_url"))
    }

    fn policy(&self) -> EgressPolicy {
        let mut p = EgressPolicy {
            allow_private_network: self.allow_private_network,
            ..EgressPolicy::default()
        };
        if let Some(ms) = self.timeout_ms {
            p.timeout = Duration::from_millis(ms);
        }
        if let Some(b) = self.max_response_bytes {
            p.max_response_bytes = b as usize;
        }
        p
    }
}

fn check_param_spec(spec: &ParamSpec) -> Result<(), ()> {
    if let Some(p) = &spec.pattern {
        if spec.ty != ParamType::String {
            return Err(());
        }
        Regex::new(&format!("^(?:{p})$")).map_err(|_| ())?;
    }
    if let Some(e) = &spec.allowed {
        let ok = !e.is_empty()
            && e.iter().all(|v| match spec.ty {
                ParamType::String => v.is_string(),
                ParamType::Integer => v.is_i64(),
                ParamType::Boolean => v.is_boolean(),
            });
        if !ok {
            return Err(());
        }
    }
    Ok(())
}

/// Outcome of an applied write whose result cannot be returned (secret detected under
/// `withhold`, too large, …): status only, `side_effects: applied`, flagged restricted.
fn withheld(
    filter: &OutputFilter,
    name: &str,
    status: u16,
    reason: &str,
    mut restricted: BTreeSet<String>,
    byte_cap: u64,
) -> ExecutionOutcome {
    let mut data = json!({"operation": name, "status": status, "withheld": true, "reason": reason});
    if filter.leaks(&data) {
        data = json!({"status": status, "withheld": true, "reason": reason});
    }
    if crate::connectors::json_len(&data) > byte_cap {
        data = json!({"withheld": true});
    }
    if restricted.is_empty() {
        restricted.insert("result".to_owned());
    }
    ExecutionOutcome {
        bytes: crate::connectors::json_len(&data),
        data,
        rows: Some(0),
        truncated: false,
        restricted_fields: restricted.into_iter().collect(),
        side_effects: SideEffects::Applied,
    }
}

fn bad(param: &str) -> ApiError {
    errors::invalid_param(param, "参数无效", "Invalid parameter.")
}

/// Validate one parameter value; returns its normalized JSON form.
fn check_value(name: &str, spec: &ParamSpec, v: &Value, in_path: bool) -> Result<Value, ApiError> {
    let out = match spec.ty {
        ParamType::String => {
            let s = v.as_str().ok_or_else(|| bad(name))?;
            let len = s.chars().count() as i64;
            if len > spec.max.unwrap_or(DEFAULT_STRING_MAX) || len < spec.min.unwrap_or(0) {
                return Err(bad(name));
            }
            if s.chars().any(char::is_control) {
                return Err(bad(name));
            }
            if in_path && (s.is_empty() || s == "." || s == "..") {
                return Err(bad(name));
            }
            if let Some(p) = &spec.pattern {
                let re = Regex::new(&format!("^(?:{p})$")).map_err(|_| errors::bad_config(name))?;
                if !re.is_match(s) {
                    return Err(bad(name));
                }
            }
            Value::String(s.to_owned())
        }
        ParamType::Integer => {
            let i = v
                .as_i64()
                .filter(|i| i.abs() <= schema::MAX_SAFE_INTEGER)
                .ok_or_else(|| bad(name))?;
            if spec.max.is_some_and(|m| i > m) || spec.min.is_some_and(|m| i < m) {
                return Err(bad(name));
            }
            Value::from(i)
        }
        ParamType::Boolean => Value::Bool(v.as_bool().ok_or_else(|| bad(name))?),
    };
    if let Some(allowed) = &spec.allowed
        && !allowed.contains(&out)
    {
        return Err(bad(name));
    }
    Ok(out)
}

fn value_text(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

fn get_path<'a>(v: &'a Value, path: &str) -> Option<&'a Value> {
    path.split('.')
        .filter(|s| !s.is_empty())
        .try_fold(v, |cur, seg| cur.get(seg))
}

fn param_schema(spec: &ParamSpec) -> Value {
    let mut m = Map::new();
    match spec.ty {
        ParamType::String => {
            m.insert("type".into(), "string".into());
            m.insert(
                "maxLength".into(),
                spec.max.unwrap_or(DEFAULT_STRING_MAX).into(),
            );
            if let Some(p) = &spec.pattern {
                m.insert("pattern".into(), p.clone().into());
            }
        }
        ParamType::Integer => {
            m.insert("type".into(), "integer".into());
            if let Some(x) = spec.max {
                m.insert("maximum".into(), x.into());
            }
            if let Some(x) = spec.min {
                m.insert("minimum".into(), x.into());
            }
        }
        ParamType::Boolean => {
            m.insert("type".into(), "boolean".into());
        }
    }
    if let Some(e) = &spec.allowed {
        m.insert("enum".into(), Value::Array(e.clone()));
    }
    if let Some(d) = &spec.description {
        m.insert("description".into(), d.clone().into());
    }
    Value::Object(m)
}

/// Static spec of `http_api.call`.
pub fn call_spec() -> OperationSpec {
    OperationSpec {
        name: CALL.to_owned(),
        connector: Connector::HttpApi,
        description_zh: "调用该资源声明的 API 操作（固定地址、方法和字段范围）；不能访问未声明的地址。".to_owned(),
        description_en: "Call one of the API operations declared for this resource (fixed origin, method and output fields); undeclared endpoints cannot be reached.".to_owned(),
        side_effect: SideEffectClass::Write,
        retry_safe: false,
        parameters_schema: json!({
            "type": "object", "additionalProperties": false, "required": ["operation"],
            "properties": {
                "operation": {"type": "string", "description": "declared operation name"},
                "params": {"type": "object", "description": "path and query parameters of that operation"},
                "body": {"type": "object", "description": "request body (only for operations with a body_schema)"}
            }
        }),
        stage: Stage::V1,
    }
}

/// The declarative HTTP API driver.
pub struct HttpApiDriver {
    guard: EgressGuard,
}

impl std::fmt::Debug for HttpApiDriver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HttpApiDriver")
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CallInput {
    operation: String,
    #[serde(default)]
    params: Map<String, Value>,
    #[serde(default)]
    body: Option<Value>,
}

impl HttpApiDriver {
    /// New driver using `guard` for egress.
    pub fn new(guard: EgressGuard) -> Self {
        Self { guard }
    }

    fn normalize_call(
        cfg: &HttpApiConfig,
        params: &Value,
    ) -> Result<(Value, GrantScope), ApiError> {
        let input: CallInput = serde_json::from_value(params.clone()).map_err(|_| {
            errors::invalid(
                "参数格式无效（需要 operation，可选 params、body）",
                "Invalid parameters (expected operation and optional params, body).",
            )
        })?;
        let op = cfg.operations.get(&input.operation).ok_or_else(|| {
            errors::scope_denied(
                "该资源没有声明此 API 操作",
                "That API operation is not declared for this resource.",
            )
        })?;
        let placeholders = template_params(&op.path).map_err(|_| errors::bad_config("path"))?;
        let default_path_spec = ParamSpec {
            ty: ParamType::String,
            allowed: None,
            max: None,
            min: Some(1),
            required: true,
            pattern: None,
            description: None,
        };
        let mut out = BTreeMap::new();
        for (k, v) in &input.params {
            let (spec, in_path) = match (op.path_params.get(k), op.query.get(k)) {
                (Some(s), _) => (s, true),
                (None, _) if placeholders.contains(k) => (&default_path_spec, true),
                (None, Some(s)) => (s, false),
                (None, None) => return Err(bad(k)),
            };
            out.insert(k.clone(), check_value(k, spec, v, in_path)?);
        }
        for p in &placeholders {
            if !out.contains_key(p) {
                return Err(bad(p));
            }
        }
        for (k, spec) in op.path_params.iter().chain(op.query.iter()) {
            if spec.required && !out.contains_key(k) {
                return Err(bad(k));
            }
        }
        let body = match (&op.body_schema, input.body) {
            // An omitted body is the empty object and must satisfy the schema like any
            // other body (required fields, bounds, enums); the normalized params carry it,
            // so the digest and the approval display show exactly what is sent.
            (Some(s), b) => {
                let b = b.unwrap_or_else(|| json!({}));
                schema::validate(s, &b).map_err(|_| bad("body"))?;
                Some(b)
            }
            (None, Some(_)) => return Err(bad("body")),
            (None, None) => None,
        };
        let mut normalized = json!({"operation": input.operation, "params": out});
        if let Some(b) = body {
            normalized["body"] = b;
        }
        let scope = GrantScope {
            operations: vec![CALL.to_owned()],
            http_api: Some(HttpApiScope {
                operations: vec![input.operation.clone()],
            }),
            ..Default::default()
        };
        Ok((normalized, scope))
    }

    fn build_url(
        cfg: &HttpApiConfig,
        op: &OpConfig,
        params: &Map<String, Value>,
    ) -> Result<Url, ApiError> {
        let base = cfg.base()?;
        let mut path = base.path().trim_end_matches('/').to_owned();
        let mut rest = op.path.as_str();
        while let Some(start) = rest.find('{') {
            path.push_str(&rest[..start]);
            let end = rest[start..]
                .find('}')
                .ok_or_else(|| errors::bad_config("path"))?
                + start;
            let name = &rest[start + 1..end];
            let v = params.get(name).ok_or_else(|| bad(name))?;
            path.push_str(&utf8_percent_encode(&value_text(v), PATH_PARAM).to_string());
            rest = &rest[end + 1..];
        }
        path.push_str(rest);
        let mut url = base.clone();
        url.set_path(&path);
        let query_params: Vec<(&String, &Value)> = params
            .iter()
            .filter(|(k, _)| op.query.contains_key(*k))
            .collect();
        if !query_params.is_empty() {
            let mut q = url.query_pairs_mut();
            for (k, v) in query_params {
                q.append_pair(k, &value_text(v));
            }
        }
        if url.origin() != base.origin() {
            return Err(crate::egress::EgressError::OriginMismatch.to_api(false));
        }
        Ok(url)
    }

    fn map_status(status: u16, writes: bool, retry_after: Option<u64>) -> Option<ApiError> {
        if (200..300).contains(&status) {
            return None;
        }
        let with = |e: ApiError| e.with_detail("upstream_status", status);
        Some(match status {
            401 => with(errors::interactive_auth("API")),
            403 => with(errors::scope_denied(
                "外部服务拒绝了此操作（凭证权限不足）",
                "The external service refused the operation (insufficient credential permissions).",
            )),
            404 => with(ApiError::new(ErrorCode::NotFound)),
            409 | 412 | 422 | 400 => with(errors::invalid(
                "外部服务不接受这些参数",
                "The external service rejected the parameters.",
            )),
            429 => with(errors::rate_limited(retry_after)),
            s if s >= 500 && writes => with(errors::outcome_unknown("upstream_5xx")),
            _ => with(errors::upstream(
                "upstream_status",
                "外部服务返回错误",
                "The external service returned an error.",
            )),
        })
    }
}

#[async_trait]
impl ConnectorDriver for HttpApiDriver {
    fn connector(&self) -> Connector {
        Connector::HttpApi
    }

    fn operation_specs(&self) -> Vec<OperationSpec> {
        vec![call_spec()]
    }

    fn resource_operation_specs(&self, resource: &Resource) -> Vec<OperationSpec> {
        if !resource.operations.iter().any(|o| o == CALL) {
            return Vec::new();
        }
        let Ok(cfg) = HttpApiConfig::parse(&resource.config) else {
            return Vec::new();
        };
        let mut spec = call_spec();
        let names: Vec<&String> = cfg.operations.keys().collect();
        let mut ops = Map::new();
        let mut worst = SideEffectClass::Read;
        let mut all_retry_safe = true;
        for (name, op) in &cfg.operations {
            let params: Map<String, Value> = op
                .path_params
                .iter()
                .chain(op.query.iter())
                .map(|(k, s)| (k.clone(), param_schema(s)))
                .collect();
            let required: Vec<&String> = op
                .path_params
                .iter()
                .chain(op.query.iter())
                .filter(|(_, s)| s.required)
                .map(|(k, _)| k)
                .collect();
            ops.insert(
                name.clone(),
                json!({
                    "method": op.method,
                    "side_effect": op.side_effect,
                    "description_zh": op.description_zh,
                    "description_en": op.description_en,
                    "params": {"type": "object", "additionalProperties": false, "properties": params, "required": required},
                    "body": op.body_schema,
                }),
            );
            worst = match (worst, op.side_effect) {
                (_, SideEffectClass::Irreversible) | (SideEffectClass::Irreversible, _) => {
                    SideEffectClass::Irreversible
                }
                (_, SideEffectClass::Write) | (SideEffectClass::Write, _) => SideEffectClass::Write,
                _ => SideEffectClass::Read,
            };
            all_retry_safe &= op.retry_safe;
        }
        spec.side_effect = worst;
        spec.retry_safe = all_retry_safe;
        spec.parameters_schema["properties"]["operation"]["enum"] = json!(names);
        spec.parameters_schema["x-operations"] = Value::Object(ops);
        vec![spec]
    }

    fn validate_config(&self, config: &Value) -> Result<(), ApiError> {
        HttpApiConfig::parse(config).map(|_| ())
    }

    fn normalize(
        &self,
        resource: &Resource,
        operation: &str,
        params: &Value,
    ) -> Result<NormalizedRequest, ApiError> {
        crate::connectors::require_offered(resource, operation)?;
        if operation != CALL {
            return Err(errors::scope_denied(
                "HTTP API 连接器只提供 http_api.call",
                "The HTTP API connector only offers http_api.call.",
            ));
        }
        let cfg = HttpApiConfig::parse(&resource.config)?;
        let (p, scope) = Self::normalize_call(&cfg, params)?;
        crate::connectors::normalized(operation, p, scope)
    }

    async fn execute(&self, ctx: ExecContext) -> Result<ExecutionOutcome, ApiError> {
        let cfg = HttpApiConfig::parse(&ctx.resource.config)?;
        let (norm, _) = Self::normalize_call(&cfg, &ctx.normalized.params)?;
        let name = norm["operation"].as_str().unwrap_or_default().to_owned();
        let op = cfg
            .operations
            .get(&name)
            .ok_or_else(|| errors::scope_denied("未声明的操作", "Undeclared operation."))?
            .clone();
        let params = norm["params"].as_object().cloned().unwrap_or_default();
        let m = ctx.credential.material();
        if !matches!(
            m.kind,
            EntryKind::ApiKey | EntryKind::OauthToken | EntryKind::Login
        ) {
            return Err(errors::secret_unavailable(
                "该凭证类型不能用于此 API",
                "This credential type cannot be used for this API.",
            ));
        }
        let base = cfg.base()?;
        let mut url = Self::build_url(&cfg, &op, &params)?;
        let mut headers = HeaderMap::new();
        headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
        let secret = m.secret.expose();
        let malformed = || {
            errors::secret_unavailable(
                "凭证格式无法用于该认证方式",
                "The credential cannot be used with this auth type.",
            )
        };
        match cfg.auth.ty {
            AuthType::Bearer => {
                let mut v =
                    HeaderValue::from_str(&format!("Bearer {secret}")).map_err(|_| malformed())?;
                v.set_sensitive(true);
                headers.insert(AUTHORIZATION, v);
            }
            AuthType::Basic => {
                let user = m.username.as_deref().unwrap_or("");
                let token =
                    base64::engine::general_purpose::STANDARD.encode(format!("{user}:{secret}"));
                let mut v =
                    HeaderValue::from_str(&format!("Basic {token}")).map_err(|_| malformed())?;
                v.set_sensitive(true);
                headers.insert(AUTHORIZATION, v);
            }
            AuthType::Header => {
                let n = HeaderName::from_bytes(cfg.auth.name.as_deref().unwrap_or("").as_bytes())
                    .map_err(|_| errors::bad_config("auth.name"))?;
                let mut v = HeaderValue::from_str(secret).map_err(|_| malformed())?;
                v.set_sensitive(true);
                headers.insert(n, v);
            }
            AuthType::Query => {
                url.query_pairs_mut()
                    .append_pair(cfg.auth.name.as_deref().unwrap_or(""), secret);
            }
        }
        // Only the normalized (schema-validated) body is ever sent; none is invented.
        let body = match norm.get("body") {
            Some(b) => Some(serde_json::to_vec(b).map_err(|_| ApiError::internal())?),
            None => None,
        };
        let req = EgressRequest {
            method: op.method(),
            url,
            headers,
            body,
        };
        let writes = op.writes();
        let policy = cfg.policy();
        // Budget is checked BEFORE anything is sent: once a write was accepted upstream it
        // must not turn into an error that hides the applied side effect.
        let row_cap = crate::connectors::row_cap(None, MAX_ITEMS, &ctx.remaining)?;
        let byte_cap = crate::connectors::byte_cap(&ctx.remaining);
        let fetched = tokio::select! {
            r = self.guard.fetch(&base, req, &policy) => r,
            _ = ctx.cancel.cancelled() => {
                return Err(if writes { errors::outcome_unknown("cancelled_in_flight") } else { errors::cancelled() });
            }
        };
        let resp = match fetched {
            Ok(r) => r,
            // Accepted write whose answer is too large: applied, only the result is withheld.
            Err(EgressError::TooLarge { status }) if writes && (200..300).contains(&status) => {
                return Ok(withheld(
                    &ctx.filter,
                    &name,
                    status,
                    "response_too_large",
                    BTreeSet::new(),
                    byte_cap,
                ));
            }
            Err(e) => return Err(e.to_api(writes)),
        };
        if let Some(e) = Self::map_status(resp.status, writes, resp.retry_after) {
            return Err(e);
        }
        let side_effects = if writes {
            SideEffects::Applied
        } else {
            SideEffects::None
        };
        let parsed: Value = if resp.body.is_empty() {
            Value::Null
        } else {
            match serde_json::from_slice(&resp.body) {
                Ok(v) => v,
                Err(_) if writes => {
                    // Applied, but the body is not JSON: report status only.
                    Value::Null
                }
                Err(_) => {
                    return Err(errors::upstream(
                        "invalid_json",
                        "外部服务返回了无法解析的内容",
                        "The external service returned unparseable content.",
                    ));
                }
            }
        };
        let selected = match &op.response.items_path {
            Some(p) => get_path(&parsed, p).cloned().unwrap_or(Value::Null),
            None => parsed,
        };
        let tree = FieldTree::from_paths(&op.response.allowed_fields);
        let mut restricted = BTreeSet::new();
        let status = resp.status;
        let outcome = (|| match selected {
            Value::Array(arr) => {
                let cap = row_cap;
                let mut truncated = arr.len() as u64 > cap;
                let mut items: Vec<Value> = arr
                    .iter()
                    .take(cap as usize)
                    .map(|i| tree.project(i))
                    .collect();
                for i in items.iter_mut() {
                    ctx.filter.redact(i, "", &mut restricted);
                }
                if op.response.on_secret_detected == OnSecret::Withhold && !restricted.is_empty() {
                    return Err(errors::result_restricted("secret_detected"));
                }
                let restricted = restricted.clone();
                let wrap = |xs: &[Value]| json!({"operation": name, "status": status, "items": xs});
                truncated |= crate::connectors::fit_items(&mut items, byte_cap, wrap);
                let n = items.len() as u64;
                crate::connectors::finish(
                    &ctx.filter,
                    wrap(&items),
                    Some(n),
                    truncated,
                    restricted,
                    side_effects,
                    byte_cap,
                )
            }
            Value::Object(_) => {
                let mut item = tree.project(&selected);
                ctx.filter.redact(&mut item, "", &mut restricted);
                if op.response.on_secret_detected == OnSecret::Withhold && !restricted.is_empty() {
                    return Err(errors::result_restricted("secret_detected"));
                }
                let data = json!({"operation": name, "status": status, "item": item});
                crate::connectors::finish(
                    &ctx.filter,
                    data,
                    Some(1),
                    false,
                    restricted.clone(),
                    side_effects,
                    byte_cap,
                )
            }
            _ => {
                let data = json!({"operation": name, "status": status});
                crate::connectors::finish(
                    &ctx.filter,
                    data,
                    Some(0),
                    false,
                    restricted.clone(),
                    side_effects,
                    byte_cap,
                )
            }
        })();
        match outcome {
            // The upstream already applied the change (2xx): never report a failure, which
            // the broker would record as "failed, no side effects". Withhold the result and
            // keep the applied side effect visible.
            Err(e) if writes => {
                let reason = e
                    .details
                    .get("reason")
                    .and_then(Value::as_str)
                    .unwrap_or("result_unavailable")
                    .to_owned();
                Ok(withheld(
                    &ctx.filter,
                    &name,
                    status,
                    &reason,
                    restricted,
                    byte_cap,
                ))
            }
            other => other,
        }
    }

    async fn end_sessions(&self, _grant_id: &GrantId) -> SessionsClosed {
        SessionsClosed::default()
    }

    async fn revoke_upstream(&self, _grant_id: &GrantId) -> LevelReport {
        LevelReport {
            status: aipass_types::models::LevelStatus::NotApplicable,
            detail: Some(
                "该 API 凭证由用户导入，执行器无法在上游吊销；如怀疑泄露请在服务方撤销或轮换 / The imported API credential cannot be revoked upstream by the executor; revoke or rotate it with the provider if exposure is suspected".to_owned(),
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> HttpApiConfig {
        HttpApiConfig::parse(&json!({
            "base_url": "https://api.example.com/v1/",
            "auth": {"type": "query", "name": "api_key"},
            "operations": {
                "get_order": {"method": "GET", "path": "/orders/{order_id}",
                    "path_params": {"order_id": {"type": "string", "max": 64}},
                    "query": {"expand": {"type": "boolean"}},
                    "side_effect": "read", "retry_safe": true,
                    "response": {"allowed_fields": ["id", "status"]}},
                "refund": {"method": "POST", "path": "/refunds",
                    "body_schema": {"type":"object","required":["amount"],"properties":{"amount":{"type":"integer","minimum":1}}},
                    "side_effect": "irreversible",
                    "response": {"allowed_fields": ["id"]}}
            }
        }))
        .unwrap()
    }

    #[test]
    fn path_params_are_encoded_and_origin_pinned() {
        let c = cfg();
        let (n, scope) = HttpApiDriver::normalize_call(
            &c,
            &json!({"operation":"get_order","params":{"order_id":"a/../../admin?x=1#f","expand":true}}),
        )
        .unwrap();
        assert_eq!(scope.http_api.unwrap().operations, vec!["get_order"]);
        let op = &c.operations["get_order"];
        let url = HttpApiDriver::build_url(&c, op, n["params"].as_object().unwrap()).unwrap();
        assert_eq!(url.host_str(), Some("api.example.com"));
        assert_eq!(url.path(), "/v1/orders/a%2F..%2F..%2Fadmin%3Fx%3D1%23f");
        assert_eq!(url.query(), Some("expand=true"));
    }

    #[test]
    fn invalid_params_rejected() {
        let c = cfg();
        for bad in [
            json!({"operation":"delete_everything"}),
            json!({"operation":"get_order","params":{"order_id":".."}}),
            json!({"operation":"get_order","params":{"order_id":"x","url":"https://evil"}}),
            json!({"operation":"get_order","params":{"order_id":"x","expand":"yes"}}),
            json!({"operation":"get_order","params":{"order_id":"x"},"body":{}}),
            json!({"operation":"refund","body":{"amount":0}}),
            json!({"operation":"refund"}),
            json!({"operation":"refund","body":null}),
            json!({"operation":"refund","body":{"amount":5,"to":"evil"}}),
            json!({"operation":"get_order","url":"https://evil.example/"}),
        ] {
            assert!(HttpApiDriver::normalize_call(&c, &bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn config_validation() {
        for bad in [
            json!({"base_url":"http://api.example.com","auth":{"type":"bearer"},"operations":{"a":{"method":"GET","path":"/","side_effect":"read","response":{"allowed_fields":["x"]}}}}),
            json!({"base_url":"https://api.example.com","auth":{"type":"header","name":"Host"},"operations":{"a":{"method":"GET","path":"/","side_effect":"read","response":{"allowed_fields":["x"]}}}}),
            json!({"base_url":"https://api.example.com","auth":{"type":"bearer"},"operations":{"a":{"method":"GET","path":"/../x","side_effect":"read","response":{"allowed_fields":["x"]}}}}),
            json!({"base_url":"https://api.example.com","auth":{"type":"bearer"},"operations":{"a":{"method":"TRACE","path":"/","side_effect":"read","response":{"allowed_fields":["x"]}}}}),
            json!({"base_url":"https://api.example.com?x=1","auth":{"type":"bearer"},"operations":{"a":{"method":"GET","path":"/","side_effect":"read","response":{"allowed_fields":["x"]}}}}),
            json!({"base_url":"https://api.example.com","auth":{"type":"bearer"},"operations":{"a":{"method":"GET","path":"/","side_effect":"read","response":{"allowed_fields":["x"]}}},"forward_to":"x"}),
        ] {
            assert!(HttpApiConfig::parse(&bad).is_err(), "{bad}");
        }
    }
}
