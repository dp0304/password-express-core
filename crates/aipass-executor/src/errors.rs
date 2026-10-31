// SPDX-License-Identifier: Apache-2.0
//! Error constructors shared by the executor and its connectors.
//!
//! Every error the executor returns is an [`ApiError`] built from a stable code plus a fixed
//! zh-CN / en message and small, non-sensitive details. Upstream error texts (database
//! messages, HTTP bodies, `reqwest` errors — which embed the request URL and therefore any
//! query-string API key) are **never** copied into an error.

use aipass_types::{ApiError, ErrorCode};

/// `INVALID_REQUEST` with a reason detail.
pub fn invalid(zh: &str, en: &str) -> ApiError {
    ApiError::new(ErrorCode::InvalidRequest).with_message(zh, en)
}

/// `INVALID_REQUEST` naming the offending parameter (the name, never its value).
pub fn invalid_param(param: &str, zh: &str, en: &str) -> ApiError {
    invalid(zh, en).with_detail("parameter", param.to_owned())
}

/// `SCOPE_DENIED` with a reason.
pub fn scope_denied(zh: &str, en: &str) -> ApiError {
    ApiError::new(ErrorCode::ScopeDenied).with_message(zh, en)
}

/// `SECRET_UNAVAILABLE`.
pub fn secret_unavailable(zh: &str, en: &str) -> ApiError {
    ApiError::new(ErrorCode::SecretUnavailable).with_message(zh, en)
}

/// `UPSTREAM_ERROR` with a machine-readable reason.
pub fn upstream(reason: &str, zh: &str, en: &str) -> ApiError {
    ApiError::new(ErrorCode::UpstreamError)
        .with_message(zh, en)
        .with_detail("reason", reason.to_owned())
}

/// `UPSTREAM_OUTCOME_UNKNOWN` — the request may have been applied upstream.
pub fn outcome_unknown(reason: &str) -> ApiError {
    ApiError::new(ErrorCode::UpstreamOutcomeUnknown).with_detail("reason", reason.to_owned())
}

/// The operation was cancelled (operations.cancel / revocation end_sessions).
///
/// There is no dedicated contract code for "cancelled"; the broker owns the operation state
/// (`cancelled`), so the executor reports `UPSTREAM_ERROR` with `details.reason = "cancelled"`.
pub fn cancelled() -> ApiError {
    upstream("cancelled", "操作已取消", "The operation was cancelled.")
}

/// `INTERACTIVE_AUTH_REQUIRED` — the upstream rejected the credential. Never asks for a secret
/// in chat (A17).
pub fn interactive_auth(service: &str) -> ApiError {
    ApiError::new(ErrorCode::InteractiveAuthRequired)
        .with_message(
            format!(
                "{service} 凭证已失效或被拒绝，请在已配对的手机或可信客户端重新登录或重新授权；不要在聊天中提供密码或令牌。"
            ),
            format!(
                "The {service} credential was rejected or has expired. Re-authenticate on your paired phone or trusted client; never paste passwords or tokens into the chat."
            ),
        )
        .with_detail("service", service.to_owned())
}

/// `BUDGET_EXHAUSTED`.
pub fn budget_exhausted() -> ApiError {
    ApiError::new(ErrorCode::BudgetExhausted)
}

/// `RESULT_RESTRICTED` with a reason.
pub fn result_restricted(reason: &str) -> ApiError {
    ApiError::new(ErrorCode::ResultRestricted).with_detail("reason", reason.to_owned())
}

/// `INTERNAL` for an invalid (trusted) resource configuration. The message does not echo the
/// configuration; `path` names the offending key.
pub fn bad_config(path: &str) -> ApiError {
    ApiError::new(ErrorCode::InvalidRequest)
        .with_message(
            "资源配置无效，请在可信客户端检查该资源的设置",
            "The resource configuration is invalid; check it on a trusted client.",
        )
        .with_detail("config_path", path.to_owned())
}

/// `NOT_SUPPORTED`.
pub fn not_supported(zh: &str, en: &str) -> ApiError {
    ApiError::new(ErrorCode::NotSupported).with_message(zh, en)
}

/// `RATE_LIMITED` with an optional retry hint in seconds.
pub fn rate_limited(retry_after: Option<u64>) -> ApiError {
    let e = ApiError::new(ErrorCode::RateLimited);
    match retry_after {
        Some(s) => e.with_detail("retry_after_seconds", s),
        None => e,
    }
}
