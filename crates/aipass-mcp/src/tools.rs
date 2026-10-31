// SPDX-License-Identifier: Apache-2.0
//! MCP tools (CONTRACTS §9; design doc §12.1).
//!
//! Tool names use underscores (dotted names are documentation aliases). Every tool maps to
//! one AI-facing broker call; none can return a password, key, cookie or refresh token, and
//! there is no keyed `exec` or arbitrary HTTP forwarding. `approval_required` is a normal
//! result (not an error) whose hint tells the model to ask the user to approve on a trusted
//! device and then call `operations_status` — never to ask for secrets in chat.

use aipass_client::BrokerApi;
use aipass_types::models::{
    AccessRequest, AccessRequestResponse, ApprovalStatus, CancelResponse, GrantScope,
    OperationRequest, OperationResponse, OperationStatus, ReleaseResponse, ResourcesResponse,
    SideEffects, MAX_IDEMPOTENCY_KEY_LEN,
};
use aipass_types::{
    ApiError, ApprovalRequestId, ErrorCode, GrantId, Lang, Localized, OperationId, ProjectId,
    ResourceId,
};
use serde_json::{Map, Value, json};

use crate::protocol::ProtocolVersion;

/// Maximum operations in one access request.
pub const MAX_OPERATIONS: usize = 32;
/// Maximum `reason` length (characters).
pub const MAX_REASON: usize = 500;

/// Static tool definition.
#[derive(Debug, Clone)]
pub struct ToolDef {
    /// Name (`^[a-zA-Z0-9_-]{1,64}$`).
    pub name: &'static str,
    /// Documentation alias (design doc name).
    pub alias: &'static str,
    /// Title.
    pub title: Localized,
    /// Description (zh + en in one string).
    pub description: String,
    /// Input JSON Schema.
    pub input_schema: Value,
    /// Output JSON Schema (`structuredContent`).
    pub output_schema: Value,
    /// Read-only hint.
    pub read_only: bool,
    /// Destructive hint.
    pub destructive: bool,
    /// Idempotent hint.
    pub idempotent: bool,
    /// Open-world hint (talks to external services).
    pub open_world: bool,
    /// V1.1 experimental (only listed with `--experimental`).
    pub experimental: bool,
    /// For experimental operation tools: the broker operation name.
    pub fixed_operation: Option<&'static str>,
}

impl ToolDef {
    /// The `tools/list` entry for a protocol version.
    pub fn to_json(&self, v: ProtocolVersion, lang: Lang) -> Value {
        let mut t = json!({
            "name": self.name,
            "description": self.description,
            "inputSchema": self.input_schema,
        });
        if v.has_structured_output() {
            t["title"] = json!(self.title.get(lang));
            t["outputSchema"] = self.output_schema.clone();
        }
        if v.has_tool_annotations() {
            t["annotations"] = json!({
                "title": self.title.get(lang),
                "readOnlyHint": self.read_only,
                "destructiveHint": self.destructive,
                "idempotentHint": self.idempotent,
                "openWorldHint": self.open_world,
            });
        }
        t
    }
}

fn id_schema(prefix: &str, desc: &str) -> Value {
    json!({"type": "string", "pattern": format!("^{prefix}_[0-9a-hjkmnp-tv-z]{{26}}$"), "description": desc})
}

fn idem_schema() -> Value {
    json!({
        "type": "string", "minLength": 1, "maxLength": MAX_IDEMPOTENCY_KEY_LEN,
        "description": "幂等标识：同一请求重试时使用同一个值，新请求使用新值。/ Idempotency key: reuse it when retrying the same request, use a new one for a new request."
    })
}

fn error_object_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "code": {"type": "string"},
            "message": {"type": "string"},
            "details": {"type": "object"},
            "request_id": {"type": "string"}
        },
        "required": ["code", "message"]
    })
}

fn operation_response_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "status": {"type": "string", "enum": ["received", "policy_checked", "approval_required", "authorized", "running", "succeeded", "failed", "unknown", "denied", "expired", "cancelled"]},
            "operation_id": {"type": "string"},
            "approval_request_id": {"type": "string"},
            "expires_in_seconds": {"type": "integer", "minimum": 0},
            "message": {"type": "string"},
            "result": {
                "type": "object",
                "properties": {
                    "data": {"description": "按授权范围过滤后的结果 / result filtered to the approved scope"},
                    "rows": {"type": "integer", "minimum": 0},
                    "truncated": {"type": "boolean"},
                    "restricted": {"type": "boolean"},
                    "restricted_fields": {"type": "array", "items": {"type": "string"}}
                },
                "required": ["data", "truncated", "restricted", "restricted_fields"]
            },
            "error": error_object_schema()
        },
        "required": ["status", "operation_id"]
    })
}

fn access_response_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "approval_request_id": {"type": "string"},
            "status": {"type": "string", "enum": ["pending", "approved", "denied", "expired", "cancelled"]},
            "grant_id": {"type": "string"}
        },
        "required": ["approval_request_id", "status"]
    })
}

fn op_tool_input(operation_desc: Option<&str>) -> Value {
    let mut props = Map::new();
    props.insert(
        "resource_id".into(),
        id_schema("res", "resources_list 返回的资源 ID / resource id from resources_list"),
    );
    let mut required = vec!["resource_id"];
    if operation_desc.is_none() {
        props.insert(
            "operation".into(),
            json!({"type": "string", "minLength": 1, "maxLength": 128, "pattern": "^[A-Za-z0-9_.:-]+$",
                   "description": "资源提供的操作名，例如 postgres.query_view / an operation the resource offers, e.g. postgres.query_view"}),
        );
        required.push("operation");
    }
    props.insert(
        "parameters".into(),
        json!({"type": "object", "description": operation_desc.unwrap_or("结构化参数，需符合 resources_list 中该操作的 parameters_schema；不要放入密码或 Key。/ Structured parameters matching the operation's parameters_schema from resources_list; never put passwords or keys here.")}),
    );
    required.push("parameters");
    props.insert("idempotency_key".into(), idem_schema());
    required.push("idempotency_key");
    json!({"type": "object", "properties": props, "required": required, "additionalProperties": false})
}

/// All tool definitions (experimental ones included; filter with [`ToolDef::experimental`]).
pub fn all_tools() -> Vec<ToolDef> {
    vec![
        ToolDef {
            name: "resources_list",
            alias: "resources.list",
            title: Localized::new("列出可用资源", "List resources"),
            description: "列出此 AI 连接被允许发现的资源：别名、服务、可用操作及其参数 schema、状态和执行位置的保护等级。不会返回任何密码、Key 或连接串。\nList the resources this AI connection may discover: alias, service, offered operations with parameter schemas, status and the executor's protection level. Never returns passwords, keys or connection strings.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "project_id": id_schema("proj", "只看某个项目 / only this project"),
                    "service": {"type": "string", "maxLength": 64, "description": "服务类型，例如 postgres、github / service type, e.g. postgres, github"}
                },
                "additionalProperties": false
            }),
            output_schema: json!({
                "type": "object",
                "properties": {"resources": {"type": "array", "items": {
                    "type": "object",
                    "properties": {
                        "resource_id": {"type": "string"},
                        "alias": {"type": "string"},
                        "service": {"type": "string"},
                        "project_id": {"type": "string"},
                        "environment": {"type": "string", "enum": ["test", "production"]},
                        "operations": {"type": "array", "items": {"type": "object", "properties": {
                            "name": {"type": "string"},
                            "description": {"type": "string"},
                            "side_effect": {"type": "string", "enum": ["read", "write", "irreversible"]},
                            "parameters_schema": {"type": "object"}
                        }, "required": ["name", "description", "side_effect", "parameters_schema"]}},
                        "status": {"type": "string", "enum": ["available", "needs_login", "sync_conflict", "executor_offline", "disabled"]},
                        "protection_level": {"type": "string", "enum": ["isolated", "compatible"]},
                        "executor_status": {"type": "string", "enum": ["online", "offline"]}
                    },
                    "required": ["resource_id", "alias", "service", "project_id", "environment", "operations", "status", "protection_level", "executor_status"]
                }}},
                "required": ["resources"]
            }),
            read_only: true,
            destructive: false,
            idempotent: true,
            open_world: false,
            experimental: false,
            fixed_operation: None,
        },
        ToolDef {
            name: "operations_request",
            alias: "operations.request",
            title: Localized::new("发起操作", "Request an operation"),
            description: "对资源发起一个结构化操作。若已有覆盖此请求的授权，直接返回按授权范围过滤的结果；否则返回 status=approval_required 和 operation_id——请让用户在已配对的手机或可信客户端批准，然后调用 operations_status。不要在聊天中索要密码或 Key。\nRequest a structured operation on a resource. With a covering grant it returns the result filtered to the approved scope; otherwise it returns status=approval_required with an operation_id — ask the user to approve on their paired phone or trusted client, then call operations_status. Never ask for passwords or keys in chat.".into(),
            input_schema: op_tool_input(None),
            output_schema: operation_response_schema(),
            read_only: false,
            destructive: true,
            idempotent: true,
            open_world: true,
            experimental: false,
            fixed_operation: None,
        },
        ToolDef {
            name: "operations_status",
            alias: "operations.status",
            title: Localized::new("查询操作状态", "Operation status"),
            description: "查询本连接发起的操作的状态及允许返回的结果。status=unknown 表示外部服务可能已执行，需核实后再决定是否重试。\nGet the status and permitted result of an operation this connection started. status=unknown means the external service may already have executed it — verify before retrying.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {"operation_id": id_schema("op", "operations_request 返回的 operation_id / operation_id from operations_request")},
                "required": ["operation_id"],
                "additionalProperties": false
            }),
            output_schema: operation_response_schema(),
            read_only: true,
            destructive: false,
            idempotent: true,
            open_world: false,
            experimental: false,
            fixed_operation: None,
        },
        ToolDef {
            name: "operations_cancel",
            alias: "operations.cancel",
            title: Localized::new("取消操作", "Cancel an operation"),
            description: "取消本连接发起的操作，并报告是否已对外部服务产生影响（side_effects）。已发送给外部服务的动作可能已经完成。\nCancel an operation this connection started and report whether it may already have affected the external service (side_effects). Actions already sent upstream may have completed.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {"operation_id": id_schema("op", "要取消的 operation_id / operation_id to cancel")},
                "required": ["operation_id"],
                "additionalProperties": false
            }),
            output_schema: json!({
                "type": "object",
                "properties": {
                    "operation_id": {"type": "string"},
                    "status": {"type": "string"},
                    "cancelled": {"type": "boolean"},
                    "side_effects": {"type": "string", "enum": ["none", "possible", "applied"]},
                    "message": {"type": "string"}
                },
                "required": ["operation_id", "status", "cancelled", "side_effects", "message"]
            }),
            read_only: false,
            destructive: false,
            idempotent: true,
            open_world: false,
            experimental: false,
            fixed_operation: None,
        },
        ToolDef {
            name: "access_request",
            alias: "access.request",
            title: Localized::new("申请任务授权", "Request access"),
            description: "为一段任务申请对指定资源和操作范围的授权（由用户在手机或可信客户端批准，用户可以缩小范围）。返回 approval_request_id；用 access_status 查询，批准后 operations_request 会直接执行。reason 只帮助用户理解，不会扩大权限。\nAsk for task-scoped access to a resource and operations (approved — possibly narrowed — by the user on their phone or trusted client). Returns an approval_request_id; poll with access_status; once approved, operations_request runs directly. reason only helps the user understand; it never widens permissions.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "resource_id": id_schema("res", "资源 ID / resource id"),
                    "operations": {"type": "array", "minItems": 1, "maxItems": MAX_OPERATIONS, "uniqueItems": true,
                                   "items": {"type": "string", "minLength": 1, "maxLength": 128}, "description": "操作名 / operation names"},
                    "scope": {"type": "object", "description": "可选的更小范围，例如 {\"operations\":[…],\"postgres\":{\"views\":{\"schema.view\":[\"field\"]}}} / optional narrower scope"},
                    "duration_seconds": {"type": "integer", "minimum": 60, "maximum": 86400, "description": "期望时长（默认 900 秒）/ desired duration (default 900 s)"},
                    "reason": {"type": "string", "maxLength": MAX_REASON, "description": "给用户看的用途说明 / purpose shown to the user"}
                },
                "required": ["resource_id", "operations"],
                "additionalProperties": false
            }),
            output_schema: access_response_schema(),
            read_only: false,
            destructive: false,
            idempotent: false,
            open_world: false,
            experimental: false,
            fixed_operation: None,
        },
        ToolDef {
            name: "access_status",
            alias: "access.status",
            title: Localized::new("查询授权请求", "Access request status"),
            description: "查询 access_request 发起的授权请求状态（pending / approved / denied / expired / cancelled）及批准后的 grant_id。\nGet the status of an access request (pending / approved / denied / expired / cancelled) and the grant_id once approved.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {"approval_request_id": id_schema("apr", "access_request 返回的 ID / id from access_request")},
                "required": ["approval_request_id"],
                "additionalProperties": false
            }),
            output_schema: access_response_schema(),
            read_only: true,
            destructive: false,
            idempotent: true,
            open_world: false,
            experimental: false,
            fixed_operation: None,
        },
        ToolDef {
            name: "access_release",
            alias: "access.release",
            title: Localized::new("结束授权", "Release access"),
            description: "任务完成后主动结束本连接持有的授权。\nRelease a grant this connection holds once the task is done.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {"grant_id": id_schema("grt", "要结束的授权 ID / grant id to release")},
                "required": ["grant_id"],
                "additionalProperties": false
            }),
            output_schema: json!({
                "type": "object",
                "properties": {"grant_id": {"type": "string"}, "status": {"type": "string"}},
                "required": ["grant_id", "status"]
            }),
            read_only: false,
            destructive: false,
            idempotent: true,
            open_world: false,
            experimental: false,
            fixed_operation: None,
        },
        experimental_tool(
            "accounts_create",
            "accounts.create",
            "accounts.create",
            Localized::new("创建账号（实验性）", "Create an account (experimental)"),
            "【实验性】通过已适配的指定站点创建账号：密码由执行器在本地生成并先保存再提交，不会返回给你。结果可能是 created、needs_verification 或 unknown（需核实）。参数见 resources_list 中 accounts.create 的 parameters_schema。\n[Experimental] Create an account on a specifically adapted site: the executor generates and saves the password before submitting and never returns it. Outcomes: created, needs_verification or unknown (verify). Parameters: see accounts.create in resources_list.",
        ),
        experimental_tool(
            "credentials_rotate",
            "credentials.rotate",
            "credentials.rotate",
            Localized::new("轮换凭证（实验性）", "Rotate a credential (experimental)"),
            "【实验性】对指定服务按轮换方案（例如 postgres.password）轮换凭证；新凭证只密封回批准设备，不会返回给你。需要用户批准；不保证所有服务都能轮换。\n[Experimental] Rotate a credential of a specific service with a rotation scheme (e.g. postgres.password); the new credential is sealed back to the approving device only and never returned to you. Needs user approval; rotation is not guaranteed for every service.",
        ),
        experimental_tool(
            "browser_start_task",
            "browser.start_task",
            "browser.start_task",
            Localized::new("受控浏览器任务（实验性）", "Controlled browser task (experimental)"),
            "【实验性】在已适配站点上启动受限的受控浏览器任务，只允许适配器定义的动作；登录等敏感阶段由执行器接管，你看不到凭证。\n[Experimental] Start a restricted controlled-browser task on an adapted site with adapter-defined actions only; sensitive steps such as login are handled by the executor and you never see credentials.",
        ),
    ]
}

fn experimental_tool(
    name: &'static str,
    alias: &'static str,
    operation: &'static str,
    title: Localized,
    description: &str,
) -> ToolDef {
    ToolDef {
        name,
        alias,
        title,
        description: description.to_owned(),
        input_schema: op_tool_input(Some("该操作的结构化参数（见 resources_list 的 parameters_schema）/ structured parameters (see parameters_schema in resources_list)")),
        output_schema: operation_response_schema(),
        read_only: false,
        destructive: true,
        idempotent: true,
        open_world: true,
        experimental: true,
        fixed_operation: Some(operation),
    }
}

/// Outcome of a tool call before MCP rendering.
#[derive(Debug, Clone, PartialEq)]
pub struct ToolOutput {
    /// JSON shown to the model (`structuredContent` when it conforms to the output schema).
    pub json: Value,
    /// Whether `json` conforms to the tool's output schema (errors do not).
    pub structured: bool,
    /// `isError`.
    pub is_error: bool,
    /// Short bilingual hint appended to the text block.
    pub hint: Localized,
}

impl ToolOutput {
    /// Render as an MCP `CallToolResult`.
    pub fn to_result(&self, v: ProtocolVersion) -> Value {
        let pretty = serde_json::to_string_pretty(&self.json).unwrap_or_else(|_| "{}".into());
        let text = format!("{pretty}\n\n{}\n{}", self.hint.zh, self.hint.en);
        let mut r = json!({
            "content": [{"type": "text", "text": text}],
            "isError": self.is_error,
        });
        if self.structured && v.has_structured_output() {
            r["structuredContent"] = self.json.clone();
        }
        r
    }
}

/// Error output: `{error:{code,message}}` + hint.
pub fn error_output(e: &ApiError, lang: Lang) -> ToolOutput {
    ToolOutput {
        json: json!({"error": {"code": e.code.as_str(), "message": e.message(lang)}}),
        structured: false,
        is_error: true,
        hint: error_hint(e.code),
    }
}

fn l(zh: impl Into<String>, en: impl Into<String>) -> Localized {
    Localized::new(zh, en)
}

const NO_SECRETS_ZH: &str = "不要在聊天中向用户索要密码、Key、验证码或令牌。";
const NO_SECRETS_EN: &str = "Never ask the user for passwords, keys, codes or tokens in chat.";

/// Hint for an error code.
pub fn error_hint(code: ErrorCode) -> Localized {
    let (zh, en): (&str, &str) = match code {
        ErrorCode::IdentityUnverified => ("此 AI 连接未通过身份验证（可能尚未配对、已被移除或连接密钥不可用）。请让用户在 AI 通行证的“AI 连接”中检查此连接。", "This AI connection could not be verified (not paired, removed, or its connection key is unavailable). Ask the user to check it under “AI connections” in AI Pass."),
        ErrorCode::ConnectionPaused => ("用户已暂停此 AI 连接；在用户恢复之前不要重试。", "The user paused this AI connection; do not retry until they resume it."),
        ErrorCode::ScopeDenied => ("超出授权范围或该资源不提供此操作。可以用 access_request 申请明确、较小的范围，由用户决定是否批准。", "Outside the approved scope, or the resource does not offer this operation. You may use access_request to ask for an explicit, narrower scope for the user to decide on."),
        ErrorCode::ApprovalDenied => ("用户拒绝了本次访问。不要换一种方式重试或绕过。", "The user denied this access. Do not retry another way or try to work around it."),
        ErrorCode::ApprovalExpired => ("审批已过期，未获批准（超时不会自动批准）。如仍需要，请先征得用户同意再重新发起。", "The approval expired without being approved (timeouts never approve). If still needed, ask the user before requesting again."),
        ErrorCode::GrantExpired | ErrorCode::GrantRevoked => ("授权已过期或已被撤销；如需继续，请征得用户同意后重新申请。", "The grant expired or was revoked; ask the user before requesting access again."),
        ErrorCode::BudgetExhausted => ("本次授权的额度（行数、请求数或数据量）已用完；如需继续，请征得用户同意后用 access_request 申请新的授权。", "The grant's budget (rows, requests or bytes) is used up; ask the user before requesting new access with access_request."),
        ErrorCode::ExecutorOffline => ("执行设备离线。请让用户确认执行设备（桌面 App 或自托管节点）在线后再试。", "The executor is offline. Ask the user to bring the executor (desktop app or self-hosted node) online, then retry."),
        ErrorCode::ControlChannelLost => ("执行设备与控制通道断开，已拒绝新操作；请稍后再试。", "The executor lost its control channel and refuses new operations; try again later."),
        ErrorCode::SecretUnavailable => ("凭证暂不可用（未送达执行设备或账号库已锁定）。请让用户在可信设备上处理。", "The credential is unavailable (not delivered to the executor, or the vault is locked). Ask the user to resolve it on a trusted device."),
        ErrorCode::SyncConflict => ("该账号存在同步冲突，自动使用已暂停；请让用户在可信客户端解决冲突。", "This account has a sync conflict and automatic use is paused; ask the user to resolve it in a trusted client."),
        ErrorCode::InteractiveAuthRequired => ("上游服务需要用户在可信设备上重新登录或重新授权。", "The upstream service needs the user to sign in or re-consent on a trusted device."),
        ErrorCode::ResultRestricted => ("结果受输出策略限制，未返回。", "The result was withheld by the output policy."),
        ErrorCode::UpstreamOutcomeUnknown => ("外部服务可能已经执行了此操作，结果未知。请先核实再决定是否重试，不要自动重试。", "The external service may already have executed this; the outcome is unknown. Verify before deciding to retry; do not retry automatically."),
        ErrorCode::UpstreamError => ("外部服务返回错误。", "The external service returned an error."),
        ErrorCode::IdempotencyConflict => ("相同的 idempotency_key 对应了不同参数；新的请求请使用新的 idempotency_key。", "The idempotency_key was reused with different parameters; use a new idempotency_key for a new request."),
        ErrorCode::RateLimited => ("请求过于频繁，或同类请求刚被拒绝；请稍后再试，不要反复发起。", "Too many requests, or a similar request was just denied; wait before trying again and do not repeat it."),
        ErrorCode::NotFound => ("未找到（或不属于此连接）。可先用 resources_list 查看可用资源。", "Not found (or not owned by this connection). Use resources_list to see available resources."),
        ErrorCode::InvalidRequest => ("参数无效；请对照工具与操作的 schema 修正后重试。", "Invalid arguments; fix them against the tool and operation schemas, then retry."),
        ErrorCode::NotSupported => ("暂不支持此功能。", "Not supported."),
        _ => ("请求未完成。", "The request did not complete."),
    };
    l(format!("{zh}{NO_SECRETS_ZH}"), format!("{en} {NO_SECRETS_EN}"))
}

fn operation_output(r: &OperationResponse) -> ToolOutput {
    let id = r.operation_id.as_str();
    let (hint, is_error) = match r.status {
        OperationStatus::AwaitingApproval => (
            l(
                format!(
                    "需要用户批准：请告诉用户在已配对的手机或可信客户端上批准本次访问{}，批准后调用 operations_status（operation_id={id}）查询结果。不要阻塞等待，超时不会自动批准。{NO_SECRETS_ZH}",
                    r.expires_in_seconds.map(|s| format!("（{s} 秒内有效）")).unwrap_or_default()
                ),
                format!(
                    "Approval required: tell the user to approve this access on their paired phone or trusted client{}, then call operations_status (operation_id={id}). Do not block waiting; timeouts never approve. {NO_SECRETS_EN}",
                    r.expires_in_seconds.map(|s| format!(" (valid for {s} s)")).unwrap_or_default()
                ),
            ),
            false,
        ),
        OperationStatus::Succeeded => {
            let (mut zh, mut en) = ("操作已完成，结果已按授权范围过滤。".to_owned(), "Done; the result is filtered to the approved scope.".to_owned());
            if let Some(res) = &r.result {
                if res.truncated {
                    zh.push_str("结果因额度被截断。");
                    en.push_str(" The result was truncated by limits.");
                }
                if res.restricted {
                    zh.push_str("部分字段已被隐去（[REDACTED]）。");
                    en.push_str(" Some fields were withheld ([REDACTED]).");
                }
            }
            (l(zh, en), false)
        }
        OperationStatus::Received | OperationStatus::PolicyChecked | OperationStatus::Authorized | OperationStatus::Running => (
            l(
                format!("操作仍在进行；稍后调用 operations_status（operation_id={id}）查询。"),
                format!("Still in progress; call operations_status (operation_id={id}) later."),
            ),
            false,
        ),
        OperationStatus::Cancelled => (l("操作已取消。", "The operation was cancelled."), false),
        OperationStatus::Unknown => (error_hint(ErrorCode::UpstreamOutcomeUnknown), true),
        OperationStatus::Denied => (error_hint(ErrorCode::ApprovalDenied), true),
        OperationStatus::Expired => (error_hint(ErrorCode::ApprovalExpired), true),
        OperationStatus::Failed => (
            r.error.as_ref().map(|e| error_hint(e.code)).unwrap_or_else(|| error_hint(ErrorCode::UpstreamError)),
            true,
        ),
    };
    ToolOutput {
        json: serde_json::to_value(r).unwrap_or(Value::Null),
        structured: true,
        is_error,
        hint,
    }
}

fn access_output(r: &AccessRequestResponse) -> ToolOutput {
    let id = r.approval_request_id.as_str();
    let (hint, is_error) = match r.status {
        ApprovalStatus::Pending => (
            l(
                format!("授权请求已发送：请让用户在已配对的手机或可信客户端批准，然后调用 access_status（approval_request_id={id}）查询；批准后即可用 operations_request。{NO_SECRETS_ZH}"),
                format!("Access request sent: ask the user to approve it on their paired phone or trusted client, then call access_status (approval_request_id={id}); once approved, use operations_request. {NO_SECRETS_EN}"),
            ),
            false,
        ),
        ApprovalStatus::Approved => (
            l(
                format!("已批准{}。在批准的范围和期限内调用 operations_request；完成后可用 access_release 结束授权。", r.grant_id.as_ref().map(|g| format!("（grant_id={g}）")).unwrap_or_default()),
                format!("Approved{}. Call operations_request within the approved scope and duration; release it with access_release when done.", r.grant_id.as_ref().map(|g| format!(" (grant_id={g})")).unwrap_or_default()),
            ),
            false,
        ),
        ApprovalStatus::Denied => (error_hint(ErrorCode::ApprovalDenied), true),
        ApprovalStatus::Expired => (error_hint(ErrorCode::ApprovalExpired), true),
        ApprovalStatus::Cancelled => (l("授权请求已取消。", "The access request was cancelled."), false),
    };
    ToolOutput {
        json: serde_json::to_value(r).unwrap_or(Value::Null),
        structured: true,
        is_error,
        hint,
    }
}

fn cancel_output(r: &CancelResponse) -> ToolOutput {
    let hint = match (r.cancelled, r.side_effects) {
        (true, SideEffects::None) => l("已取消，未对外部服务产生影响。", "Cancelled; nothing reached the external service."),
        (true, _) => l("已取消，但外部服务可能已执行部分动作，请核实。", "Cancelled, but the external service may already have executed part of it; verify."),
        (false, SideEffects::None) => l("操作已结束，无法取消。", "The operation already finished and cannot be cancelled."),
        (false, _) => l("操作已结束，无法取消；外部服务可能已执行，请核实。", "The operation already finished and cannot be cancelled; the external service may have executed it — verify."),
    };
    ToolOutput {
        json: serde_json::to_value(r).unwrap_or(Value::Null),
        structured: true,
        is_error: false,
        hint,
    }
}

fn resources_output(r: &ResourcesResponse) -> ToolOutput {
    let hint = if r.resources.is_empty() {
        l(
            "此连接当前没有可发现的资源。请让用户在 AI 通行证中为此连接添加资源或允许相应项目。",
            "No resources are visible to this connection. Ask the user to add a resource or allow its project for this connection in AI Pass.",
        )
    } else {
        l(
            "用 operations_request 对资源发起操作，parameters 需符合该操作的 parameters_schema。资源别名和 ID 不是凭证。",
            "Use operations_request on a resource with parameters matching the operation's parameters_schema. Resource aliases and IDs are not credentials.",
        )
    };
    ToolOutput {
        json: serde_json::to_value(r).unwrap_or(Value::Null),
        structured: true,
        is_error: false,
        hint,
    }
}

fn release_output(r: &ReleaseResponse) -> ToolOutput {
    ToolOutput {
        json: serde_json::to_value(r).unwrap_or(Value::Null),
        structured: true,
        is_error: false,
        hint: l("授权已结束。", "The grant was released."),
    }
}

// ----------------------------------------------------------------------------------------
// argument validation
// ----------------------------------------------------------------------------------------

fn bad(field: &str, zh: &str, en: &str) -> ApiError {
    ApiError::invalid_request(format!("{field}：{zh}"), format!("{field}: {en}")).with_detail("field", field.to_owned())
}

struct Args<'a> {
    map: &'a Map<String, Value>,
}

impl<'a> Args<'a> {
    fn new(v: &'a Value, allowed: &[&str]) -> Result<Self, ApiError> {
        let map = v
            .as_object()
            .ok_or_else(|| ApiError::invalid_request("arguments 必须是对象", "arguments must be an object"))?;
        if let Some(k) = map.keys().find(|k| !allowed.contains(&k.as_str())) {
            let shown: String = k.chars().take(64).collect();
            return Err(bad(&shown, "不是此工具的参数", "is not an argument of this tool"));
        }
        Ok(Self { map })
    }

    fn str_opt(&self, k: &str, max: usize) -> Result<Option<&'a str>, ApiError> {
        match self.map.get(k) {
            None | Some(Value::Null) => Ok(None),
            Some(Value::String(s)) if s.chars().count() <= max && !s.chars().any(char::is_control) => Ok(Some(s)),
            Some(Value::String(_)) => Err(bad(k, "过长或包含控制字符", "is too long or contains control characters")),
            Some(_) => Err(bad(k, "必须是字符串", "must be a string")),
        }
    }

    fn str_req(&self, k: &str, max: usize) -> Result<&'a str, ApiError> {
        self.str_opt(k, max)?.filter(|s| !s.is_empty()).ok_or_else(|| bad(k, "必填", "is required"))
    }

    fn id<T>(&self, k: &str, parse: fn(&str) -> Result<T, aipass_types::ids::IdError>) -> Result<T, ApiError> {
        let s = self.str_req(k, 64)?;
        parse(s).map_err(|_| bad(k, "标识格式无效", "is not a valid identifier"))
    }

    fn id_opt<T>(&self, k: &str, parse: fn(&str) -> Result<T, aipass_types::ids::IdError>) -> Result<Option<T>, ApiError> {
        match self.str_opt(k, 64)? {
            None => Ok(None),
            Some(s) => parse(s).map(Some).map_err(|_| bad(k, "标识格式无效", "is not a valid identifier")),
        }
    }
}

fn operation_name(s: &str) -> Result<(), ApiError> {
    if s.is_empty() || s.len() > 128 || !s.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-' | b':')) {
        return Err(bad("operation", "必须是资源提供的操作名（字母、数字、点、下划线、连字符、冒号）", "must be an operation name the resource offers (letters, digits, dots, underscores, hyphens, colons)"));
    }
    Ok(())
}

fn idempotency_key(s: &str) -> Result<(), ApiError> {
    if s.is_empty() || s.chars().count() > MAX_IDEMPOTENCY_KEY_LEN || s.chars().any(char::is_control) {
        return Err(bad("idempotency_key", "必须是 1 到 128 个可打印字符", "must be 1 to 128 printable characters"));
    }
    Ok(())
}

fn build_operation_request(args: &Value, fixed: Option<&str>) -> Result<OperationRequest, ApiError> {
    let allowed: &[&str] = if fixed.is_some() {
        &["resource_id", "parameters", "idempotency_key"]
    } else {
        &["resource_id", "operation", "parameters", "idempotency_key"]
    };
    let a = Args::new(args, allowed)?;
    let resource_id = a.id("resource_id", ResourceId::parse)?;
    let operation = match fixed {
        Some(op) => op.to_owned(),
        None => {
            let op = a.str_req("operation", 128)?;
            operation_name(op)?;
            op.to_owned()
        }
    };
    let parameters = match a.map.get("parameters") {
        Some(Value::Object(m)) => Value::Object(m.clone()),
        Some(_) => return Err(bad("parameters", "必须是对象", "must be an object")),
        None => return Err(bad("parameters", "必填（没有参数时传 {}）", "is required (pass {} when there are none)")),
    };
    let key = a.str_req("idempotency_key", MAX_IDEMPOTENCY_KEY_LEN)?;
    idempotency_key(key)?;
    // numbers must be canonicalizable (no floats / huge integers) — the broker digests them
    aipass_types::canonical::value_to_jcs(&parameters).map_err(ApiError::from)?;
    let req = OperationRequest {
        resource_id,
        operation,
        parameters,
        idempotency_key: key.to_owned(),
        task_id: None,
    };
    req.validate()?;
    Ok(req)
}

fn build_access_request(args: &Value) -> Result<AccessRequest, ApiError> {
    let a = Args::new(args, &["resource_id", "operations", "scope", "duration_seconds", "reason"])?;
    let resource_id = a.id("resource_id", ResourceId::parse)?;
    let ops = match a.map.get("operations") {
        Some(Value::Array(items)) if !items.is_empty() && items.len() <= MAX_OPERATIONS => {
            let mut out = Vec::new();
            for it in items {
                let Some(s) = it.as_str() else {
                    return Err(bad("operations", "必须是字符串数组", "must be an array of strings"));
                };
                operation_name(s)?;
                if !out.iter().any(|o: &String| o == s) {
                    out.push(s.to_owned());
                }
            }
            out
        }
        Some(Value::Array(_)) => return Err(bad("operations", &format!("需要 1 到 {MAX_OPERATIONS} 个操作"), &format!("needs 1 to {MAX_OPERATIONS} operations"))),
        Some(_) => return Err(bad("operations", "必须是字符串数组", "must be an array of strings")),
        None => return Err(bad("operations", "必填", "is required")),
    };
    let scope = match a.map.get("scope") {
        None | Some(Value::Null) => None,
        Some(v @ Value::Object(_)) => Some(
            serde_json::from_value::<GrantScope>(v.clone())
                .map_err(|_| bad("scope", "格式无效（operations、postgres.views、github.repos、http_api.operations）", "is malformed (operations, postgres.views, github.repos, http_api.operations)"))?,
        ),
        Some(_) => return Err(bad("scope", "必须是对象", "must be an object")),
    };
    let duration_seconds = match a.map.get("duration_seconds") {
        None | Some(Value::Null) => None,
        Some(v) => match v.as_u64() {
            Some(n) if (60..=aipass_types::approval::MAX_TASK_TTL_SECS).contains(&n) => Some(n),
            _ => return Err(bad("duration_seconds", "必须是 60 到 86400 之间的整数", "must be an integer between 60 and 86400")),
        },
    };
    let reason = a.str_opt("reason", MAX_REASON)?.map(str::to_owned);
    Ok(AccessRequest {
        resource_id,
        operations: ops,
        scope,
        limits: None,
        duration_seconds,
        reason,
    })
}

/// Execute a tool. `Err` → JSON-RPC error (unknown tool); `Ok` → tool result (possibly
/// `isError`).
pub async fn call_tool(
    def: &ToolDef,
    args: &Value,
    broker: &dyn BrokerApi,
    lang: Lang,
) -> ToolOutput {
    let r = run(def, args, broker).await;
    match r {
        Ok(out) => out,
        Err(e) => error_output(&e, lang),
    }
}

async fn run(def: &ToolDef, args: &Value, broker: &dyn BrokerApi) -> Result<ToolOutput, ApiError> {
    match def.name {
        "resources_list" => {
            let a = Args::new(args, &["project_id", "service"])?;
            let project = a.id_opt("project_id", ProjectId::parse)?;
            let service = a.str_opt("service", 64)?;
            Ok(resources_output(&broker.list_resources(project.as_ref(), service).await?))
        }
        "operations_request" | "accounts_create" | "credentials_rotate" | "browser_start_task" => {
            let req = build_operation_request(args, def.fixed_operation)?;
            Ok(operation_output(&broker.request_operation(&req).await?))
        }
        "operations_status" => {
            let a = Args::new(args, &["operation_id"])?;
            let id = a.id("operation_id", OperationId::parse)?;
            Ok(operation_output(&broker.get_operation(&id).await?))
        }
        "operations_cancel" => {
            let a = Args::new(args, &["operation_id"])?;
            let id = a.id("operation_id", OperationId::parse)?;
            Ok(cancel_output(&broker.cancel_operation(&id).await?))
        }
        "access_request" => {
            let req = build_access_request(args)?;
            Ok(access_output(&broker.request_access(&req).await?))
        }
        "access_status" => {
            let a = Args::new(args, &["approval_request_id"])?;
            let id = a.id("approval_request_id", ApprovalRequestId::parse)?;
            Ok(access_output(&broker.get_access_request(&id).await?))
        }
        "access_release" => {
            let a = Args::new(args, &["grant_id"])?;
            let id = a.id("grant_id", GrantId::parse)?;
            Ok(release_output(&broker.release_grant(&id).await?))
        }
        _ => Err(ApiError::new(ErrorCode::NotSupported)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_and_schemas() {
        let re = regex_lite_name;
        for t in all_tools() {
            assert!(re(t.name), "{}", t.name);
            assert_eq!(t.input_schema["type"], "object");
            assert_eq!(t.output_schema["type"], "object");
            assert!(!t.description.is_empty());
        }
    }

    fn regex_lite_name(n: &str) -> bool {
        !n.is_empty() && n.len() <= 64 && n.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    }

    #[test]
    fn op_arg_validation() {
        let ok = json!({"resource_id": "res_01jbz3k6w8a7m2q4t5v9x0y1z2", "operation": "postgres.query_view", "parameters": {"view": "a.b", "fields": ["x"]}, "idempotency_key": "k"});
        assert!(build_operation_request(&ok, None).is_ok());
        let mut extra = ok.clone();
        extra["password"] = json!("x");
        assert_eq!(build_operation_request(&extra, None).unwrap_err().code, ErrorCode::InvalidRequest);
        let mut float = ok.clone();
        float["parameters"]["limit"] = json!(1.5);
        assert!(build_operation_request(&float, None).is_err());
        let mut bad_id = ok.clone();
        bad_id["resource_id"] = json!("resource_sales_analytics");
        assert!(build_operation_request(&bad_id, None).is_err());
        let mut no_params = ok.clone();
        no_params.as_object_mut().unwrap().remove("parameters");
        assert!(build_operation_request(&no_params, None).is_err());
        let mut long_key = ok.clone();
        long_key["idempotency_key"] = json!("x".repeat(129));
        assert!(build_operation_request(&long_key, None).is_err());
        let fixed = json!({"resource_id": "res_01jbz3k6w8a7m2q4t5v9x0y1z2", "parameters": {"scheme": "postgres.password"}, "idempotency_key": "rot-1"});
        assert_eq!(build_operation_request(&fixed, Some("credentials.rotate")).unwrap().operation, "credentials.rotate");
        assert!(build_operation_request(&ok, Some("credentials.rotate")).is_err(), "operation is fixed");
    }

    #[test]
    fn access_arg_validation() {
        let ok = json!({"resource_id": "res_01jbz3k6w8a7m2q4t5v9x0y1z2", "operations": ["postgres.query_view", "postgres.query_view"], "duration_seconds": 900, "scope": {"operations": ["postgres.query_view"], "postgres": {"views": {"analytics.subscription_daily": ["day"]}}}});
        let r = build_access_request(&ok).unwrap();
        assert_eq!(r.operations.len(), 1);
        assert!(r.scope.unwrap().postgres.is_some());
        for bad in [
            json!({"resource_id": "res_01jbz3k6w8a7m2q4t5v9x0y1z2", "operations": []}),
            json!({"resource_id": "res_01jbz3k6w8a7m2q4t5v9x0y1z2", "operations": ["X Y"]}),
            json!({"resource_id": "res_01jbz3k6w8a7m2q4t5v9x0y1z2", "operations": ["a"], "duration_seconds": 10}),
            json!({"resource_id": "res_01jbz3k6w8a7m2q4t5v9x0y1z2", "operations": ["a"], "scope": {"postgres": 1}}),
            json!({"resource_id": "res_01jbz3k6w8a7m2q4t5v9x0y1z2", "operations": ["a"], "limits": {}}),
        ] {
            assert!(build_access_request(&bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn approval_required_is_not_an_error() {
        let r = OperationResponse::approval_required(
            OperationId::parse("op_01jbz5c2v7k9m3n4p5q6r7s8t9").unwrap(),
            ApprovalRequestId::parse("apr_01jbz5c2v8a1b2c3d4e5f6g7h8").unwrap(),
            120,
        );
        let out = operation_output(&r);
        assert!(!out.is_error);
        let res = out.to_result(ProtocolVersion::V2025_11_25);
        assert_eq!(res["isError"], false);
        assert_eq!(res["structuredContent"]["status"], "approval_required");
        assert_eq!(res["structuredContent"]["message"], "请在已配对的手机或可信客户端批准本次访问。");
        let text = res["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("operations_status"));
        assert!(text.contains("不要在聊天中向用户索要密码"));
        assert!(text.contains("Never ask the user for passwords"));
        // old protocol: no structuredContent, JSON still in text
        let old = out.to_result(ProtocolVersion::V2025_03_26);
        assert!(old.get("structuredContent").is_none());
        assert!(old["content"][0]["text"].as_str().unwrap().contains("\"approval_required\""));
    }

    #[test]
    fn errors_render_without_structured_content() {
        let out = error_output(&ApiError::new(ErrorCode::ScopeDenied), Lang::ZhCn);
        let res = out.to_result(ProtocolVersion::V2025_11_25);
        assert_eq!(res["isError"], true);
        assert!(res.get("structuredContent").is_none());
        let text = res["content"][0]["text"].as_str().unwrap();
        let json_part: Value = serde_json::from_str(text.split("\n\n").next().unwrap()).unwrap();
        assert_eq!(json_part, json!({"error": {"code": "SCOPE_DENIED", "message": "超出本次授权范围"}}));
    }
}
