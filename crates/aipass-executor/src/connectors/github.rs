// SPDX-License-Identifier: Apache-2.0
//! GitHub connector — read operations on allowlisted repositories (CONTRACTS §8).
//!
//! Resource config:
//!
//! ```json
//! {"allowed_repos": ["octo/app", "octo/docs"],
//!  "api_base": "https://api.github.com",          // optional; GHES base set by a trusted client
//!  "allow_private_network": false,                 // optional; needed for an internal GHES
//!  "timeout_ms": 10000}                            // optional, ≤ 10000
//! ```
//!
//! * The API base is fixed (`https://api.github.com` unless a trusted client configured a
//!   GHES base, which must be `https`). All traffic goes through the [`EgressGuard`].
//! * Repositories are matched case-insensitively against `allowed_repos`.
//! * Each operation has a fixed output field allowlist; response headers are never returned.
//! * `401` → `INTERACTIVE_AUTH_REQUIRED` (re-authorise on a trusted device — never ask for a
//!   token in chat, A17); rate limits → `RATE_LIMITED`.
//! * A test-only base override exists behind the `test-util` cargo feature and can only be
//!   set through [`crate::ExecutorBuilder`], never from resource config (unknown config keys
//!   are rejected).

use std::collections::BTreeSet;

use aipass_types::exec::{ExecutionOutcome, LevelReport, NormalizedRequest, OperationSpec, Stage};
use aipass_types::models::{
    Connector, GithubScope, GrantScope, Resource, SideEffectClass, SideEffects,
};
use aipass_types::vault::EntryKind;
use aipass_types::{ApiError, ErrorCode, GrantId};
use async_trait::async_trait;
use base64::Engine as _;
use reqwest::header::{ACCEPT, AUTHORIZATION, HeaderMap, HeaderValue};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use url::Url;

use crate::connectors::{ConnectorDriver, ExecContext, SessionsClosed};
use crate::egress::{EgressGuard, EgressPolicy, EgressRequest};
use crate::errors;
use crate::filter::FieldTree;

/// Default API base.
pub const DEFAULT_API_BASE: &str = "https://api.github.com";
/// `github.repo.get`.
pub const REPO_GET: &str = "github.repo.get";
/// `github.contents.get`.
pub const CONTENTS_GET: &str = "github.contents.get";
/// `github.issues.list`.
pub const ISSUES_LIST: &str = "github.issues.list";
/// `github.pulls.list`.
pub const PULLS_LIST: &str = "github.pulls.list";
/// `github.commits.list`.
pub const COMMITS_LIST: &str = "github.commits.list";
/// Max `per_page`.
pub const MAX_PER_PAGE: u64 = 100;
/// Max `page` (pagination bound).
pub const MAX_PAGE: u64 = 100;
/// Max decoded text returned by `contents.get`.
pub const MAX_TEXT_BYTES: usize = 256 * 1024;
/// Issue / PR bodies are cut to this many characters.
pub const MAX_BODY_CHARS: usize = 4000;
/// Max labels in a filter.
pub const MAX_LABELS: usize = 10;

const REPO_FIELDS: &[&str] = &[
    "id",
    "name",
    "full_name",
    "private",
    "visibility",
    "description",
    "html_url",
    "default_branch",
    "language",
    "topics",
    "archived",
    "fork",
    "stargazers_count",
    "forks_count",
    "open_issues_count",
    "created_at",
    "updated_at",
    "pushed_at",
    "license.spdx_id",
    "owner.login",
];
const ISSUE_FIELDS: &[&str] = &[
    "number",
    "title",
    "state",
    "user.login",
    "labels.name",
    "assignees.login",
    "comments",
    "created_at",
    "updated_at",
    "closed_at",
    "html_url",
    "body",
];
const PULL_FIELDS: &[&str] = &[
    "number",
    "title",
    "state",
    "draft",
    "user.login",
    "labels.name",
    "head.ref",
    "base.ref",
    "created_at",
    "updated_at",
    "closed_at",
    "merged_at",
    "html_url",
    "body",
];
const COMMIT_FIELDS: &[&str] = &[
    "sha",
    "html_url",
    "commit.message",
    "commit.author.name",
    "commit.author.date",
    "commit.committer.date",
    "author.login",
];
const DIR_ENTRY_FIELDS: &[&str] = &["name", "path", "type", "size", "sha"];

/// Allowlisted output fields of an operation (documentation / tests).
pub fn output_fields(operation: &str) -> &'static [&'static str] {
    match operation {
        REPO_GET => REPO_FIELDS,
        ISSUES_LIST => ISSUE_FIELDS,
        PULLS_LIST => PULL_FIELDS,
        COMMITS_LIST => COMMIT_FIELDS,
        CONTENTS_GET => DIR_ENTRY_FIELDS,
        _ => &[],
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct GithubConfig {
    allowed_repos: Vec<String>,
    #[serde(default)]
    api_base: Option<String>,
    #[serde(default)]
    allow_private_network: bool,
    #[serde(default)]
    timeout_ms: Option<u64>,
}

fn valid_owner(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 39
        && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        && !s.starts_with('-')
}

fn valid_repo_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 100
        && s != "."
        && s != ".."
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c))
}

/// Parse `owner/name`, lower-cased.
fn parse_repo(s: &str) -> Option<(String, String)> {
    let (o, n) = s.split_once('/')?;
    (valid_owner(o) && valid_repo_name(n)).then(|| (o.to_ascii_lowercase(), n.to_ascii_lowercase()))
}

impl GithubConfig {
    fn parse(v: &Value) -> Result<Self, ApiError> {
        let c: GithubConfig =
            serde_json::from_value(v.clone()).map_err(|_| errors::bad_config("$"))?;
        if c.allowed_repos.is_empty() || c.allowed_repos.len() > 1000 {
            return Err(errors::bad_config("allowed_repos"));
        }
        if !c.allowed_repos.iter().all(|r| parse_repo(r).is_some()) {
            return Err(errors::bad_config("allowed_repos"));
        }
        if let Some(ms) = c.timeout_ms
            && !(100..=10_000).contains(&ms)
        {
            return Err(errors::bad_config("timeout_ms"));
        }
        let base = c.base()?;
        EgressGuard::check_url_shape(&base, false).map_err(|_| errors::bad_config("api_base"))?;
        if base.query().is_some() || base.fragment().is_some() {
            return Err(errors::bad_config("api_base"));
        }
        Ok(c)
    }

    fn base(&self) -> Result<Url, ApiError> {
        Url::parse(self.api_base.as_deref().unwrap_or(DEFAULT_API_BASE))
            .map_err(|_| errors::bad_config("api_base"))
    }

    fn allows(&self, owner: &str, name: &str) -> bool {
        self.allowed_repos
            .iter()
            .filter_map(|r| parse_repo(r))
            .any(|(o, n)| o == owner && n == name)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum IssueState {
    Open,
    Closed,
    All,
}

/// Normalized GitHub parameters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GhParams {
    repo: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    path: Option<String>,
    #[serde(default, rename = "ref", skip_serializing_if = "Option::is_none")]
    git_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    state: Option<IssueState>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    labels: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    sha: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    per_page: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    page: Option<u64>,
}

fn valid_ref(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 255
        && !s.contains("..")
        && !s.starts_with('/')
        && !s.ends_with('/')
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_./".contains(c))
}

fn valid_path(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 1024
        && !s.starts_with('/')
        && s.split('/').all(|seg| {
            !seg.is_empty() && seg != "." && seg != ".." && !seg.chars().any(|c| c.is_control())
        })
}

fn bad(param: &str) -> ApiError {
    errors::invalid_param(param, "参数无效", "Invalid parameter.")
}

fn schema_repo() -> Value {
    json!({"type": "string", "pattern": "^[A-Za-z0-9-]{1,39}/[A-Za-z0-9._-]{1,100}$", "description": "owner/name"})
}

fn page_props() -> (Value, Value) {
    (
        json!({"type": "integer", "minimum": 1, "maximum": MAX_PER_PAGE}),
        json!({"type": "integer", "minimum": 1, "maximum": MAX_PAGE}),
    )
}

fn spec(name: &str, zh: &str, en: &str, schema: Value) -> OperationSpec {
    OperationSpec {
        name: name.to_owned(),
        connector: Connector::Github,
        description_zh: zh.to_owned(),
        description_en: en.to_owned(),
        side_effect: SideEffectClass::Read,
        retry_safe: true,
        parameters_schema: schema,
        stage: Stage::V1,
    }
}

/// Specs of the five read operations.
pub fn specs() -> Vec<OperationSpec> {
    let (per_page, page) = page_props();
    let state = json!({"type": "string", "enum": ["open", "closed", "all"]});
    vec![
        spec(
            REPO_GET,
            "读取允许仓库的基本信息（名称、描述、默认分支、语言等）。",
            "Read basic information about an allowed repository (name, description, default branch, language…).",
            json!({"type":"object","additionalProperties":false,"required":["repo"],"properties":{"repo":schema_repo()}}),
        ),
        spec(
            CONTENTS_GET,
            "读取允许仓库中的文件文本（最多 256 KiB）或目录列表。",
            "Read a file's text (up to 256 KiB) or a directory listing from an allowed repository.",
            json!({"type":"object","additionalProperties":false,"required":["repo","path"],"properties":{
                "repo":schema_repo(),"path":{"type":"string","maxLength":1024},"ref":{"type":"string","maxLength":255}}}),
        ),
        spec(
            ISSUES_LIST,
            "列出允许仓库的 issue（可按状态、标签筛选，分页）。",
            "List issues of an allowed repository (filter by state and labels, paginated).",
            json!({"type":"object","additionalProperties":false,"required":["repo"],"properties":{
                "repo":schema_repo(),"state":state,"labels":{"type":"array","maxItems":MAX_LABELS,"items":{"type":"string","maxLength":50}},
                "per_page":per_page,"page":page}}),
        ),
        spec(
            PULLS_LIST,
            "列出允许仓库的拉取请求（可按状态筛选，分页）。",
            "List pull requests of an allowed repository (filter by state, paginated).",
            json!({"type":"object","additionalProperties":false,"required":["repo"],"properties":{
                "repo":schema_repo(),"state":state,"per_page":per_page,"page":page}}),
        ),
        spec(
            COMMITS_LIST,
            "列出允许仓库的提交记录（可指定分支/提交与路径，分页）。",
            "List commits of an allowed repository (optional branch/sha and path, paginated).",
            json!({"type":"object","additionalProperties":false,"required":["repo"],"properties":{
                "repo":schema_repo(),"sha":{"type":"string","maxLength":255},"path":{"type":"string","maxLength":1024},
                "per_page":per_page,"page":page}}),
        ),
    ]
}

/// The GitHub driver.
pub struct GithubDriver {
    guard: EgressGuard,
    #[cfg(feature = "test-util")]
    base_override: Option<Url>,
}

impl std::fmt::Debug for GithubDriver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("GithubDriver")
    }
}

impl GithubDriver {
    /// New driver using `guard` for egress.
    pub fn new(guard: EgressGuard) -> Self {
        Self {
            guard,
            #[cfg(feature = "test-util")]
            base_override: None,
        }
    }

    /// Test-only: send requests to `base` (may be `http://127.0.0.1:…`).
    #[cfg(feature = "test-util")]
    pub fn with_test_base_override(mut self, base: Url) -> Self {
        self.base_override = Some(base);
        self
    }

    fn effective_base(&self, cfg: &GithubConfig) -> Result<(Url, EgressPolicy), ApiError> {
        let mut policy = EgressPolicy {
            allow_private_network: cfg.allow_private_network,
            ..EgressPolicy::default()
        };
        if let Some(ms) = cfg.timeout_ms {
            policy.timeout = std::time::Duration::from_millis(ms);
        }
        #[cfg(feature = "test-util")]
        if let Some(b) = &self.base_override {
            policy.allow_http = true;
            policy.allow_private_network = true;
            return Ok((b.clone(), policy));
        }
        Ok((cfg.base()?, policy))
    }

    fn normalize_params(
        &self,
        cfg: &GithubConfig,
        operation: &str,
        params: &Value,
    ) -> Result<(GhParams, GrantScope), ApiError> {
        let mut p: GhParams = serde_json::from_value(params.clone()).map_err(|_| {
            errors::invalid(
                "参数格式无效",
                "Invalid parameters for this GitHub operation.",
            )
        })?;
        let (owner, name) = parse_repo(&p.repo).ok_or_else(|| bad("repo"))?;
        if !cfg.allows(&owner, &name) {
            return Err(errors::scope_denied(
                "该仓库不在本资源允许的范围内",
                "That repository is not allowlisted for this resource.",
            ));
        }
        p.repo = format!("{owner}/{name}");
        let allowed: &[&str] = match operation {
            REPO_GET => &[],
            CONTENTS_GET => &["path", "ref"],
            ISSUES_LIST => &["state", "labels", "per_page", "page"],
            PULLS_LIST => &["state", "per_page", "page"],
            COMMITS_LIST => &["sha", "path", "per_page", "page"],
            _ => {
                return Err(errors::scope_denied(
                    "GitHub 连接器不提供此操作",
                    "The GitHub connector does not offer this operation.",
                ));
            }
        };
        let present = [
            ("path", p.path.is_some()),
            ("ref", p.git_ref.is_some()),
            ("state", p.state.is_some()),
            ("labels", p.labels.is_some()),
            ("sha", p.sha.is_some()),
            ("per_page", p.per_page.is_some()),
            ("page", p.page.is_some()),
        ];
        for (k, set) in present {
            if set && !allowed.contains(&k) {
                return Err(bad(k));
            }
        }
        if operation == CONTENTS_GET && p.path.is_none() {
            return Err(bad("path"));
        }
        if let Some(path) = &p.path
            && !valid_path(path)
        {
            return Err(bad("path"));
        }
        if let Some(r) = &p.git_ref
            && !valid_ref(r)
        {
            return Err(bad("ref"));
        }
        if let Some(r) = &p.sha
            && !valid_ref(r)
        {
            return Err(bad("sha"));
        }
        if let Some(labels) = &mut p.labels {
            if labels.is_empty() || labels.len() > MAX_LABELS {
                return Err(bad("labels"));
            }
            for l in labels.iter() {
                if l.is_empty()
                    || l.chars().count() > 50
                    || l.contains(',')
                    || l.chars().any(char::is_control)
                {
                    return Err(bad("labels"));
                }
            }
            labels.sort();
            labels.dedup();
        }
        if let Some(pp) = p.per_page
            && !(1..=MAX_PER_PAGE).contains(&pp)
        {
            return Err(bad("per_page"));
        }
        if let Some(pg) = p.page
            && !(1..=MAX_PAGE).contains(&pg)
        {
            return Err(bad("page"));
        }
        let scope = GrantScope {
            operations: vec![operation.to_owned()],
            github: Some(GithubScope {
                repos: vec![p.repo.clone()],
            }),
            ..Default::default()
        };
        Ok((p, scope))
    }

    fn map_status(resp: &crate::egress::EgressResponse) -> Option<ApiError> {
        let s = resp.status;
        if (200..300).contains(&s) {
            return None;
        }
        let with_status = |e: ApiError| e.with_detail("upstream_status", s);
        Some(match s {
            401 => with_status(errors::interactive_auth("GitHub")),
            403 | 429
                if s == 429
                    || resp.rate_limit_remaining == Some(0)
                    || resp.retry_after.is_some() =>
            {
                let retry = resp.retry_after.or_else(|| {
                    resp.rate_limit_reset
                        .map(|r| (r as i64 - aipass_types::time::unix_now()).max(0) as u64)
                });
                with_status(errors::rate_limited(retry))
            }
            403 => with_status(errors::scope_denied(
                "GitHub 拒绝访问（令牌权限不足或组织策略限制）",
                "GitHub denied access (insufficient token permissions or organisation policy).",
            )),
            404 => with_status(ApiError::new(ErrorCode::NotFound).with_message(
                "GitHub 上未找到该仓库或路径（或令牌无权查看）",
                "Repository or path not found on GitHub (or not visible to the token).",
            )),
            422 => with_status(errors::invalid(
                "GitHub 不接受这些参数（例如不存在的分支或提交）",
                "GitHub rejected the parameters (for example an unknown branch or commit).",
            )),
            _ => with_status(errors::upstream(
                "upstream_status",
                "GitHub 返回错误",
                "GitHub returned an error.",
            )),
        })
    }

    async fn call(
        &self,
        ctx: &ExecContext,
        cfg: &GithubConfig,
        p: &GhParams,
        per_page: Option<u64>,
    ) -> Result<Value, ApiError> {
        let (base, policy) = self.effective_base(cfg)?;
        let (owner, name) = parse_repo(&p.repo).ok_or_else(|| bad("repo"))?;
        let mut url = base.clone();
        {
            let mut segs = url
                .path_segments_mut()
                .map_err(|_| errors::bad_config("api_base"))?;
            segs.pop_if_empty()
                .extend(["repos", owner.as_str(), name.as_str()]);
            match ctx.normalized.operation.as_str() {
                CONTENTS_GET => {
                    segs.push("contents");
                    if let Some(path) = &p.path {
                        segs.extend(path.split('/'));
                    }
                }
                ISSUES_LIST => {
                    segs.push("issues");
                }
                PULLS_LIST => {
                    segs.push("pulls");
                }
                COMMITS_LIST => {
                    segs.push("commits");
                }
                _ => {}
            }
        }
        {
            let mut q = url.query_pairs_mut();
            match ctx.normalized.operation.as_str() {
                CONTENTS_GET => {
                    if let Some(r) = &p.git_ref {
                        q.append_pair("ref", r);
                    }
                }
                ISSUES_LIST | PULLS_LIST => {
                    if let Some(s) = p.state {
                        q.append_pair(
                            "state",
                            match s {
                                IssueState::Open => "open",
                                IssueState::Closed => "closed",
                                IssueState::All => "all",
                            },
                        );
                    }
                    if let Some(l) = &p.labels {
                        q.append_pair("labels", &l.join(","));
                    }
                }
                COMMITS_LIST => {
                    if let Some(s) = &p.sha {
                        q.append_pair("sha", s);
                    }
                    if let Some(path) = &p.path {
                        q.append_pair("path", path);
                    }
                }
                _ => {}
            }
            if let Some(pp) = per_page {
                q.append_pair("per_page", &pp.to_string());
                q.append_pair("page", &p.page.unwrap_or(1).to_string());
            }
        }
        if url.query() == Some("") {
            url.set_query(None);
        }
        let token = ctx.credential.material().secret.expose();
        let mut headers = HeaderMap::new();
        headers.insert(
            ACCEPT,
            HeaderValue::from_static("application/vnd.github+json"),
        );
        headers.insert(
            "x-github-api-version",
            HeaderValue::from_static("2022-11-28"),
        );
        let mut auth = HeaderValue::from_str(&format!("Bearer {token}")).map_err(|_| {
            errors::secret_unavailable("GitHub 令牌格式无效", "The GitHub token is malformed.")
        })?;
        auth.set_sensitive(true);
        headers.insert(AUTHORIZATION, auth);
        let req = EgressRequest {
            method: reqwest::Method::GET,
            url,
            headers,
            body: None,
        };
        let resp = tokio::select! {
            r = self.guard.fetch(&base, req, &policy) => r.map_err(|e| e.to_api(false))?,
            _ = ctx.cancel.cancelled() => return Err(errors::cancelled()),
        };
        if let Some(e) = Self::map_status(&resp) {
            return Err(e);
        }
        serde_json::from_slice(&resp.body).map_err(|_| {
            errors::upstream(
                "invalid_json",
                "GitHub 返回了无法解析的内容",
                "GitHub returned unparseable content.",
            )
        })
    }
}

fn cut_body(item: &mut Value) {
    if let Some(Value::String(b)) = item.get_mut("body")
        && b.chars().count() > MAX_BODY_CHARS
    {
        let cut: String = b.chars().take(MAX_BODY_CHARS).collect();
        *b = cut;
        if let Some(o) = item.as_object_mut() {
            o.insert("body_truncated".into(), Value::Bool(true));
        }
    }
}

fn truncate_utf8(s: &str, max: usize) -> (&str, bool) {
    if s.len() <= max {
        return (s, false);
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    (&s[..end], true)
}

#[async_trait]
impl ConnectorDriver for GithubDriver {
    fn connector(&self) -> Connector {
        Connector::Github
    }

    fn operation_specs(&self) -> Vec<OperationSpec> {
        specs()
    }

    fn validate_config(&self, config: &Value) -> Result<(), ApiError> {
        GithubConfig::parse(config).map(|_| ())
    }

    fn normalize(
        &self,
        resource: &Resource,
        operation: &str,
        params: &Value,
    ) -> Result<NormalizedRequest, ApiError> {
        crate::connectors::require_offered(resource, operation)?;
        let cfg = GithubConfig::parse(&resource.config)?;
        let (p, scope) = self.normalize_params(&cfg, operation, params)?;
        let v = serde_json::to_value(&p).map_err(|_| ApiError::internal())?;
        crate::connectors::normalized(operation, v, scope)
    }

    async fn execute(&self, ctx: ExecContext) -> Result<ExecutionOutcome, ApiError> {
        let cfg = GithubConfig::parse(&ctx.resource.config)?;
        let m = ctx.credential.material();
        if !matches!(m.kind, EntryKind::ApiKey | EntryKind::OauthToken) {
            return Err(errors::secret_unavailable(
                "该凭证类型不能用于 GitHub",
                "This credential type cannot be used for GitHub.",
            ));
        }
        let op = ctx.normalized.operation.clone();
        let (p, _) = self.normalize_params(&cfg, &op, &ctx.normalized.params)?;
        let byte_cap = crate::connectors::byte_cap(&ctx.remaining);
        let mut restricted = BTreeSet::new();
        match op.as_str() {
            REPO_GET => {
                crate::connectors::row_cap(Some(1), 1, &ctx.remaining)?;
                let raw = self.call(&ctx, &cfg, &p, None).await?;
                let mut repo = FieldTree::from_paths(REPO_FIELDS).project(&raw);
                ctx.filter.redact(&mut repo, "", &mut restricted);
                let data = json!({"repo": repo});
                crate::connectors::finish(
                    &ctx.filter,
                    data,
                    Some(1),
                    false,
                    restricted,
                    SideEffects::None,
                    byte_cap,
                )
            }
            CONTENTS_GET => {
                crate::connectors::row_cap(Some(1), 1, &ctx.remaining)?;
                let raw = self.call(&ctx, &cfg, &p, None).await?;
                let path = p.path.clone().unwrap_or_default();
                match raw {
                    Value::Array(entries) => {
                        let tree = FieldTree::from_paths(DIR_ENTRY_FIELDS);
                        let cap = crate::connectors::row_cap(None, 1000, &ctx.remaining)?;
                        let mut items: Vec<Value> =
                            entries.iter().map(|e| tree.project(e)).collect();
                        let mut truncated = items.len() as u64 > cap;
                        items.truncate(cap as usize);
                        for i in items.iter_mut() {
                            ctx.filter.redact(i, "entries", &mut restricted);
                        }
                        let wrap = |xs: &[Value]| json!({"repo": p.repo, "path": path, "type": "dir", "entries": xs});
                        truncated |= crate::connectors::fit_items(&mut items, byte_cap, wrap);
                        let n = items.len() as u64;
                        crate::connectors::finish(
                            &ctx.filter,
                            wrap(&items),
                            Some(n),
                            truncated,
                            restricted,
                            SideEffects::None,
                            byte_cap,
                        )
                    }
                    Value::Object(obj) => {
                        let kind = obj
                            .get("type")
                            .and_then(Value::as_str)
                            .unwrap_or("")
                            .to_owned();
                        let mut out = json!({
                            "repo": p.repo,
                            "path": obj.get("path").cloned().unwrap_or(Value::String(path.clone())),
                            "type": kind,
                            "sha": obj.get("sha").cloned().unwrap_or(Value::Null),
                            "size": obj.get("size").cloned().unwrap_or(Value::Null),
                        });
                        let mut truncated = false;
                        if kind == "file" {
                            let encoded = obj.get("content").and_then(Value::as_str).unwrap_or("");
                            let encoding =
                                obj.get("encoding").and_then(Value::as_str).unwrap_or("");
                            let cleaned: String =
                                encoded.chars().filter(|c| !c.is_whitespace()).collect();
                            let decoded = if encoding == "base64" {
                                base64::engine::general_purpose::STANDARD
                                    .decode(cleaned.as_bytes())
                                    .ok()
                            } else {
                                None
                            };
                            match decoded.as_deref().map(std::str::from_utf8) {
                                Some(Ok(text)) => {
                                    let (t, cut) = truncate_utf8(text, MAX_TEXT_BYTES);
                                    truncated = cut;
                                    out["text"] = Value::String(t.to_owned());
                                }
                                Some(Err(_)) => {
                                    out["text"] = Value::Null;
                                    out["binary"] = Value::Bool(true);
                                }
                                None => {
                                    out["text"] = Value::Null;
                                    out["note"] = json!({"zh": "文件过大或编码不受支持，未返回内容", "en": "File too large or unsupported encoding; content not returned"});
                                }
                            }
                        }
                        ctx.filter.redact(&mut out, "", &mut restricted);
                        if crate::connectors::json_len(&out) > byte_cap
                            && let Some(Value::String(t)) = out.get("text").cloned()
                        {
                            let overhead = crate::connectors::json_len(&out) - t.len() as u64;
                            let room = byte_cap.saturating_sub(overhead + 16) as usize;
                            let (cut, _) = truncate_utf8(&t, room);
                            out["text"] = Value::String(cut.to_owned());
                            truncated = true;
                        }
                        if truncated {
                            out["text_truncated"] = Value::Bool(true);
                        }
                        crate::connectors::finish(
                            &ctx.filter,
                            out,
                            Some(1),
                            truncated,
                            restricted,
                            SideEffects::None,
                            byte_cap,
                        )
                    }
                    _ => Err(errors::upstream(
                        "invalid_json",
                        "GitHub 返回了意外的内容",
                        "GitHub returned unexpected content.",
                    )),
                }
            }
            ISSUES_LIST | PULLS_LIST | COMMITS_LIST => {
                let requested = p.per_page.unwrap_or(30);
                let per_page =
                    crate::connectors::row_cap(Some(requested), MAX_PER_PAGE, &ctx.remaining)?;
                let raw = self.call(&ctx, &cfg, &p, Some(per_page)).await?;
                let arr = raw.as_array().cloned().ok_or_else(|| {
                    errors::upstream(
                        "invalid_json",
                        "GitHub 返回了意外的内容",
                        "GitHub returned unexpected content.",
                    )
                })?;
                let fields = output_fields(&op);
                let tree = FieldTree::from_paths(fields);
                let mut truncated = arr.len() as u64 > per_page || per_page < requested;
                let mut items: Vec<Value> = arr
                    .iter()
                    .take(per_page as usize)
                    .map(|raw_item| {
                        let mut it = tree.project(raw_item);
                        if op == ISSUES_LIST
                            && let Some(o) = it.as_object_mut()
                        {
                            o.insert(
                                "is_pull_request".into(),
                                Value::Bool(raw_item.get("pull_request").is_some()),
                            );
                        }
                        cut_body(&mut it);
                        it
                    })
                    .collect();
                for i in items.iter_mut() {
                    ctx.filter.redact(i, "", &mut restricted);
                }
                let has_more = arr.len() as u64 >= per_page;
                let page = p.page.unwrap_or(1);
                let wrap = |xs: &[Value]| json!({"repo": p.repo, "page": page, "per_page": per_page, "has_more": has_more, "items": xs});
                truncated |= crate::connectors::fit_items(&mut items, byte_cap, wrap);
                let n = items.len() as u64;
                crate::connectors::finish(
                    &ctx.filter,
                    wrap(&items),
                    Some(n),
                    truncated,
                    restricted,
                    SideEffects::None,
                    byte_cap,
                )
            }
            _ => Err(errors::scope_denied(
                "GitHub 连接器不提供此操作",
                "The GitHub connector does not offer this operation.",
            )),
        }
    }

    async fn end_sessions(&self, _grant_id: &GrantId) -> SessionsClosed {
        // Stateless: no persistent upstream sessions (each request uses a fresh client).
        SessionsClosed::default()
    }

    async fn revoke_upstream(&self, _grant_id: &GrantId) -> LevelReport {
        // The connector holds a user-imported token; it cannot revoke it upstream.
        LevelReport {
            status: aipass_types::models::LevelStatus::NotApplicable,
            detail: Some(
                "GitHub 令牌由用户导入，执行器无法在上游吊销；如怀疑泄露请在 GitHub 中撤销或轮换 / The imported GitHub token cannot be revoked upstream by the executor; revoke or rotate it on GitHub if exposure is suspected".to_owned(),
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repo_and_path_validation() {
        assert_eq!(
            parse_repo("Octo/App.js"),
            Some(("octo".into(), "app.js".into()))
        );
        assert!(parse_repo("octo/..").is_none());
        assert!(parse_repo("octo/app/extra").is_none());
        assert!(parse_repo("-bad/x").is_none());
        assert!(valid_path("src/lib.rs"));
        assert!(!valid_path("../secrets"));
        assert!(!valid_path("src/../../x"));
        assert!(!valid_path("/etc/passwd"));
        assert!(!valid_ref("main..evil"));
        assert!(valid_ref("release/v1.2"));
    }

    #[test]
    fn config_rejects_unknown_and_http() {
        assert!(GithubConfig::parse(&json!({"allowed_repos":["o/r"]})).is_ok());
        assert!(
            GithubConfig::parse(
                &json!({"allowed_repos":["o/r"],"test_base_override":"http://127.0.0.1:1"})
            )
            .is_err()
        );
        assert!(
            GithubConfig::parse(&json!({"allowed_repos":["o/r"],"api_base":"http://ghe.internal"}))
                .is_err()
        );
        assert!(
            GithubConfig::parse(
                &json!({"allowed_repos":["o/r"],"api_base":"https://u:p@ghe.internal"})
            )
            .is_err()
        );
        assert!(GithubConfig::parse(&json!({"allowed_repos":[]})).is_err());
    }
}
