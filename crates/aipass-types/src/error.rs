// SPDX-License-Identifier: Apache-2.0
//! Stable error codes, HTTP statuses, default zh-CN / en messages and the JSON error
//! envelope (CONTRACTS §1.5):
//!
//! ```json
//! {"error":{"code":"SCOPE_DENIED","message":"超出本次授权范围","details":{},"request_id":"req_01j..."}}
//! ```
//!
//! Error values must never contain secrets, credentials, result bodies or raw upstream
//! responses; `details` carries only structured, non-sensitive context (field names, IDs).

use core::fmt;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// UI / message language. zh-CN is the default; English when `Accept-Language` starts with `en`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub enum Lang {
    /// Simplified Chinese (default).
    #[default]
    #[serde(rename = "zh-CN")]
    ZhCn,
    /// English.
    #[serde(rename = "en")]
    En,
}

impl Lang {
    /// Pick the language from an `Accept-Language` header value.
    pub fn from_accept_language(header: Option<&str>) -> Self {
        match header {
            Some(h) if h.trim_start().to_ascii_lowercase().starts_with("en") => Lang::En,
            _ => Lang::ZhCn,
        }
    }
}

/// A short text in both supported languages.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Localized {
    /// Simplified Chinese.
    pub zh: String,
    /// English.
    pub en: String,
}

impl Localized {
    /// Construct.
    pub fn new(zh: impl Into<String>, en: impl Into<String>) -> Self {
        Self {
            zh: zh.into(),
            en: en.into(),
        }
    }

    /// Pick by language.
    pub fn get(&self, lang: Lang) -> &str {
        match lang {
            Lang::ZhCn => &self.zh,
            Lang::En => &self.en,
        }
    }
}

macro_rules! error_codes {
    ($( $(#[$m:meta])* $variant:ident = $s:literal, $status:literal, $zh:literal, $en:literal; )*) => {
        /// Stable error codes (CONTRACTS §1.5, plus client-local codes used by FFI and
        /// native messaging). Serialized as `SCREAMING_SNAKE_CASE` strings.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
        #[non_exhaustive]
        pub enum ErrorCode {
            $( $(#[$m])* #[serde(rename = $s)] $variant, )*
        }

        impl ErrorCode {
            /// Every code, in declaration order.
            pub const ALL: &'static [ErrorCode] = &[ $( ErrorCode::$variant, )* ];

            /// Wire string, e.g. `"SCOPE_DENIED"`.
            pub fn as_str(&self) -> &'static str {
                match self { $( ErrorCode::$variant => $s, )* }
            }

            /// HTTP status code for this error.
            pub fn http_status(&self) -> u16 {
                match self { $( ErrorCode::$variant => $status, )* }
            }

            /// Default human message.
            pub fn default_message(&self, lang: Lang) -> &'static str {
                match (self, lang) {
                    $( (ErrorCode::$variant, Lang::ZhCn) => $zh, (ErrorCode::$variant, Lang::En) => $en, )*
                }
            }

            /// Parse a wire string.
            pub fn parse(s: &str) -> Option<ErrorCode> {
                match s { $( $s => Some(ErrorCode::$variant), )* _ => None }
            }
        }
    };
}

error_codes! {
    /// Signature/token invalid, unknown or unpaired principal.
    IdentityUnverified = "IDENTITY_UNVERIFIED", 401, "无法验证调用方身份", "The caller's identity could not be verified.";
    /// (cloud) missing/invalid session.
    Unauthenticated = "UNAUTHENTICATED", 401, "请先登录", "Sign-in required.";
    /// Principal not allowed to call this endpoint.
    Forbidden = "FORBIDDEN", 403, "无权执行此操作", "You are not allowed to perform this action.";
    /// User paused this AI app.
    ConnectionPaused = "CONNECTION_PAUSED", 403, "此 AI 连接已被暂停", "This AI connection is paused.";
    /// Only as SDK exception when the caller disabled waiting; the API returns it as a status.
    ApprovalRequired = "APPROVAL_REQUIRED", 202, "请在已配对的手机或可信客户端批准本次访问。", "Approve this access on your paired phone or trusted client.";
    /// User denied.
    ApprovalDenied = "APPROVAL_DENIED", 403, "用户拒绝了本次访问", "The user denied this access.";
    /// Approval window passed — never auto-approved.
    ApprovalExpired = "APPROVAL_EXPIRED", 410, "审批已过期，未获批准", "The approval request expired without being approved.";
    /// Grant expired.
    GrantExpired = "GRANT_EXPIRED", 403, "授权已过期", "The grant has expired.";
    /// Grant revoked.
    GrantRevoked = "GRANT_REVOKED", 403, "授权已撤销", "The grant has been revoked.";
    /// Grant row/request/byte budget used up.
    BudgetExhausted = "BUDGET_EXHAUSTED", 403, "本次授权的额度已用完", "The grant's budget is used up.";
    /// Outside policy/grant scope, or capability not offered.
    ScopeDenied = "SCOPE_DENIED", 403, "超出本次授权范围", "Outside the approved scope.";
    /// No online executor.
    ExecutorOffline = "EXECUTOR_OFFLINE", 503, "执行设备离线", "The executor is offline.";
    /// Executor lost its control channel; new operations denied.
    ControlChannelLost = "CONTROL_CHANNEL_LOST", 503, "执行设备与控制通道断开，已拒绝新操作", "The executor lost its control channel; new operations are denied.";
    /// Credential not delivered to executor / vault locked.
    SecretUnavailable = "SECRET_UNAVAILABLE", 409, "凭证暂不可用（未送达执行设备或账号库已锁定）", "The credential is unavailable (not delivered to the executor, or the vault is locked).";
    /// Entry has an unresolved conflict; automatic use paused.
    SyncConflict = "SYNC_CONFLICT", 409, "该条目存在同步冲突，已暂停自动使用", "This entry has a sync conflict; automatic use is paused.";
    /// Conditional write failed.
    PreconditionFailed = "PRECONDITION_FAILED", 412, "条件写入失败，数据已被其他设备修改", "Conditional write failed; the object was changed elsewhere.";
    /// Storage older than known checkpoint.
    RollbackDetected = "ROLLBACK_DETECTED", 409, "检测到存储被回退到较旧版本，已停止写入", "Storage appears to have been rolled back to an older version; writes are stopped.";
    /// Signature / hash / AEAD failure.
    IntegrityFailed = "INTEGRITY_FAILED", 422, "完整性校验失败", "Integrity check failed.";
    /// Upstream needs re-login / OAuth re-consent (never ask for secrets in chat).
    InteractiveAuthRequired = "INTERACTIVE_AUTH_REQUIRED", 409, "需要重新登录或重新授权，请在可信设备上完成，不要在聊天中提供密码", "Re-login or re-consent is required. Complete it on a trusted device; never share passwords in chat.";
    /// Whole result withheld by output policy.
    ResultRestricted = "RESULT_RESTRICTED", 403, "结果受输出策略限制，未返回", "The result was withheld by the output policy.";
    /// External service may have executed; verify before retrying.
    UpstreamOutcomeUnknown = "UPSTREAM_OUTCOME_UNKNOWN", 502, "外部服务可能已执行，请先核实再重试", "The external service may already have executed this; verify before retrying.";
    /// Upstream error.
    UpstreamError = "UPSTREAM_ERROR", 502, "外部服务返回错误", "The external service returned an error.";
    /// Same idempotency key, different normalized parameters.
    IdempotencyConflict = "IDEMPOTENCY_CONFLICT", 409, "相同的幂等标识对应了不同的参数", "The idempotency key was reused with different parameters.";
    /// Includes throttling after a denial.
    RateLimited = "RATE_LIMITED", 429, "请求过于频繁，请稍后再试", "Too many requests; please try again later.";
    /// Also returned for objects owned by another principal (no existence leak).
    NotFound = "NOT_FOUND", 404, "未找到", "Not found.";
    /// Invalid request.
    InvalidRequest = "INVALID_REQUEST", 400, "请求无效", "Invalid request.";
    /// Not supported.
    NotSupported = "NOT_SUPPORTED", 501, "暂不支持此功能", "Not supported.";
    /// (cloud) entitlement missing.
    PaymentRequired = "PAYMENT_REQUIRED", 402, "当前套餐不包含此功能", "Your plan does not include this feature.";
    /// (cloud) quota exceeded.
    QuotaExceeded = "QUOTA_EXCEEDED", 429, "已超出用量配额", "Quota exceeded.";
    /// Internal error.
    Internal = "INTERNAL", 500, "内部错误", "Internal error.";
    /// (client-local, FFI / native messaging) the vault is locked.
    Locked = "LOCKED", 423, "账号库已锁定", "The vault is locked.";
    /// (client-local, FFI) no vault on this device yet.
    NoVault = "NO_VAULT", 404, "尚未创建或加入账号库", "No vault has been created or joined on this device.";
    /// (client-local, native messaging) page origin does not match the entry.
    OriginMismatch = "ORIGIN_MISMATCH", 403, "网站来源不匹配，已拒绝填充", "The site origin does not match; fill refused.";
    /// (client-local, native messaging) the extension is not paired with the desktop app.
    NotPaired = "NOT_PAIRED", 401, "尚未与桌面 App 配对", "Not paired with the desktop app.";
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The inner `error` object of the envelope.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ErrorObject {
    /// Stable code.
    pub code: ErrorCode,
    /// Human message (zh-CN default, en on request).
    pub message: String,
    /// Structured, non-sensitive context. Always an object (possibly empty).
    #[serde(default = "empty_object")]
    pub details: Value,
    /// Request id (`req_…`), when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
}

fn empty_object() -> Value {
    Value::Object(Map::new())
}

/// The HTTP error body: `{"error": {...}}`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ErrorBody {
    /// The error.
    pub error: ErrorObject,
}

/// An API error: code + optional custom message + details. Converted to an [`ErrorBody`]
/// for a given language at the HTTP edge.
#[derive(Debug, Clone, PartialEq)]
pub struct ApiError {
    /// Stable code.
    pub code: ErrorCode,
    /// Custom message; `None` uses [`ErrorCode::default_message`].
    pub message: Option<Localized>,
    /// Structured, non-sensitive details (object).
    pub details: Map<String, Value>,
    /// Request id.
    pub request_id: Option<String>,
}

impl ApiError {
    /// New error with the default message.
    pub fn new(code: ErrorCode) -> Self {
        Self {
            code,
            message: None,
            details: Map::new(),
            request_id: None,
        }
    }

    /// Replace the message (both languages). Never put secrets into messages.
    pub fn with_message(mut self, zh: impl Into<String>, en: impl Into<String>) -> Self {
        self.message = Some(Localized::new(zh, en));
        self
    }

    /// Add one detail member. Never put secrets or result bodies into details.
    pub fn with_detail(mut self, key: impl Into<String>, value: impl Into<Value>) -> Self {
        self.details.insert(key.into(), value.into());
        self
    }

    /// Set the request id.
    pub fn with_request_id(mut self, id: impl Into<String>) -> Self {
        self.request_id = Some(id.into());
        self
    }

    /// HTTP status.
    pub fn http_status(&self) -> u16 {
        self.code.http_status()
    }

    /// Message in `lang`.
    pub fn message(&self, lang: Lang) -> String {
        match &self.message {
            Some(m) => m.get(lang).to_owned(),
            None => self.code.default_message(lang).to_owned(),
        }
    }

    /// Envelope object.
    pub fn to_object(&self, lang: Lang) -> ErrorObject {
        ErrorObject {
            code: self.code,
            message: self.message(lang),
            details: Value::Object(self.details.clone()),
            request_id: self.request_id.clone(),
        }
    }

    /// Full HTTP body.
    pub fn to_body(&self, lang: Lang) -> ErrorBody {
        ErrorBody {
            error: self.to_object(lang),
        }
    }

    /// Rebuild from a received body (client side).
    pub fn from_body(body: &ErrorBody) -> Self {
        let details = match &body.error.details {
            Value::Object(m) => m.clone(),
            _ => Map::new(),
        };
        Self {
            code: body.error.code,
            message: Some(Localized::new(
                body.error.message.clone(),
                body.error.message.clone(),
            )),
            details,
            request_id: body.error.request_id.clone(),
        }
    }

    // Convenience constructors -------------------------------------------------------------

    /// `INVALID_REQUEST` with an English/Chinese reason.
    pub fn invalid_request(zh: impl Into<String>, en: impl Into<String>) -> Self {
        Self::new(ErrorCode::InvalidRequest).with_message(zh, en)
    }
    /// `NOT_FOUND`.
    pub fn not_found() -> Self {
        Self::new(ErrorCode::NotFound)
    }
    /// `SCOPE_DENIED`.
    pub fn scope_denied() -> Self {
        Self::new(ErrorCode::ScopeDenied)
    }
    /// `INTERNAL` (never include the underlying error text if it may contain secrets).
    pub fn internal() -> Self {
        Self::new(ErrorCode::Internal)
    }
    /// `IDENTITY_UNVERIFIED`.
    pub fn identity_unverified() -> Self {
        Self::new(ErrorCode::IdentityUnverified)
    }
    /// `INTEGRITY_FAILED`.
    pub fn integrity_failed() -> Self {
        Self::new(ErrorCode::IntegrityFailed)
    }
}

impl From<ErrorCode> for ApiError {
    fn from(code: ErrorCode) -> Self {
        Self::new(code)
    }
}

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code.as_str(), self.message(Lang::En))
    }
}

impl std::error::Error for ApiError {}

impl From<crate::canonical::CanonicalError> for ApiError {
    fn from(_: crate::canonical::CanonicalError) -> Self {
        ApiError::invalid_request(
            "请求包含不允许的数值（浮点数或超出范围的整数）",
            "The payload contains disallowed numbers (floats or out-of-range integers).",
        )
    }
}

impl From<crate::ids::IdError> for ApiError {
    fn from(e: crate::ids::IdError) -> Self {
        ApiError::invalid_request("标识格式无效", "Malformed identifier.")
            .with_detail("reason", e.to_string())
    }
}

impl From<aipass_crypto::CryptoError> for ApiError {
    fn from(_: aipass_crypto::CryptoError) -> Self {
        ApiError::new(ErrorCode::IntegrityFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_matches_contract_example() {
        let e =
            ApiError::new(ErrorCode::ScopeDenied).with_request_id("req_01jbz3k6w8a7m2q4t5v9x0y1z2");
        let json = serde_json::to_string(&e.to_body(Lang::ZhCn)).unwrap();
        assert_eq!(
            json,
            r#"{"error":{"code":"SCOPE_DENIED","message":"超出本次授权范围","details":{},"request_id":"req_01jbz3k6w8a7m2q4t5v9x0y1z2"}}"#
        );
        let en = e.to_body(Lang::from_accept_language(Some("en-US,en;q=0.9")));
        assert_eq!(en.error.message, "Outside the approved scope.");
        assert_eq!(Lang::from_accept_language(Some("zh-CN")), Lang::ZhCn);
        assert_eq!(Lang::from_accept_language(None), Lang::ZhCn);
        let back: ErrorBody = serde_json::from_str(&json).unwrap();
        assert_eq!(ApiError::from_body(&back).code, ErrorCode::ScopeDenied);
    }

    #[test]
    fn statuses_and_strings() {
        let table = [
            (ErrorCode::IdentityUnverified, 401),
            (ErrorCode::ApprovalRequired, 202),
            (ErrorCode::ApprovalExpired, 410),
            (ErrorCode::ExecutorOffline, 503),
            (ErrorCode::PreconditionFailed, 412),
            (ErrorCode::IntegrityFailed, 422),
            (ErrorCode::UpstreamOutcomeUnknown, 502),
            (ErrorCode::RateLimited, 429),
            (ErrorCode::NotSupported, 501),
            (ErrorCode::PaymentRequired, 402),
            (ErrorCode::Internal, 500),
        ];
        for (c, s) in table {
            assert_eq!(c.http_status(), s);
        }
        for c in ErrorCode::ALL {
            assert_eq!(ErrorCode::parse(c.as_str()), Some(*c));
            assert_eq!(
                serde_json::to_string(c).unwrap(),
                format!("\"{}\"", c.as_str())
            );
            assert!(!c.default_message(Lang::ZhCn).is_empty());
            assert!(!c.default_message(Lang::En).is_empty());
        }
        assert_eq!(
            ErrorCode::ExecutorOffline.default_message(Lang::ZhCn),
            "执行设备离线"
        );
        assert_eq!(ErrorCode::ALL.len(), 34);
    }
}
