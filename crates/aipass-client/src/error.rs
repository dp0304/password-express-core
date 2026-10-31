// SPDX-License-Identifier: Apache-2.0
//! Client-side errors.
//!
//! [`ClientError`] distinguishes errors the broker reported (an [`ApiError`] decoded from the
//! CONTRACTS §1.5 envelope) from local problems (transport, configuration, key files).
//! Messages never contain secrets: bearer tokens and key seeds are never formatted into
//! errors, and transport errors only carry the broker endpoint (which never contains
//! credentials — see [`crate::endpoint::BrokerEndpoint::parse`]).

use aipass_types::{ApiError, ErrorBody, ErrorCode};
use serde_json::Value;

/// Error returned by [`crate::BrokerClient`] and the helpers of this crate.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// The broker answered with an error envelope.
    #[error("{0}")]
    Api(ApiError),
    /// The broker could not be reached (connection refused, socket missing, timeout, TLS).
    #[error("broker unreachable at {endpoint}: {reason}")]
    Unreachable {
        /// Endpoint (no secrets).
        endpoint: String,
        /// Short reason.
        reason: String,
    },
    /// The broker answered something that is not a valid response for this endpoint.
    #[error("unexpected broker response: {0}")]
    Protocol(String),
    /// Local configuration problem (bad URL, unsupported platform feature, …).
    #[error("configuration error: {0}")]
    Config(String),
    /// Connection key file problem.
    #[error("connection key error: {0}")]
    Key(String),
    /// Local I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

impl ClientError {
    /// The broker error code, if this is an API error.
    pub fn code(&self) -> Option<ErrorCode> {
        match self {
            ClientError::Api(e) => Some(e.code),
            _ => None,
        }
    }

    /// Convert to an [`ApiError`] suitable for showing to an AI host (MCP tool error).
    ///
    /// Local failures are mapped to `INTERNAL` with a localized, actionable message and a
    /// machine `reason` detail (`broker_unreachable`, `protocol`, `config`, `key`, `io`).
    pub fn to_api_error(&self) -> ApiError {
        match self {
            ClientError::Api(e) => e.clone(),
            ClientError::Unreachable { .. } => ApiError::new(ErrorCode::Internal)
                .with_message(
                    "无法连接 AI 通行证授权代理。请确认桌面 App 或 aipass node 正在运行，然后运行 aipass-mcp doctor 检查。",
                    "Cannot reach the AI Pass access broker. Make sure the desktop app or `aipass node` is running, then run `aipass-mcp doctor`.",
                )
                .with_detail("reason", "broker_unreachable"),
            ClientError::Protocol(_) => ApiError::new(ErrorCode::Internal)
                .with_message("授权代理返回了无法识别的响应", "The access broker returned an unrecognized response.")
                .with_detail("reason", "protocol"),
            ClientError::Config(_) => ApiError::new(ErrorCode::Internal)
                .with_message("接入桥配置有误，请运行 aipass-mcp doctor 检查", "The bridge is misconfigured; run `aipass-mcp doctor`.")
                .with_detail("reason", "config"),
            ClientError::Key(_) => ApiError::new(ErrorCode::IdentityUnverified)
                .with_message(
                    "此 AI 连接尚未配对或连接密钥不可用。请运行 aipass-mcp pair，或在桌面 App 的“连接 AI”中重新连接。",
                    "This AI connection is not paired or its connection key is unavailable. Run `aipass-mcp pair` or reconnect from “Connect AI” in the desktop app.",
                )
                .with_detail("reason", "key"),
            ClientError::Io(_) => ApiError::new(ErrorCode::Internal)
                .with_message("接入桥本地读写失败", "The bridge hit a local I/O error.")
                .with_detail("reason", "io"),
        }
    }
}

impl From<ApiError> for ClientError {
    fn from(e: ApiError) -> Self {
        ClientError::Api(e)
    }
}

impl From<ClientError> for ApiError {
    fn from(e: ClientError) -> Self {
        e.to_api_error()
    }
}

/// Fallback code for an HTTP status when the body carries no (known) error code.
pub(crate) fn code_for_status(status: u16) -> ErrorCode {
    match status {
        400 => ErrorCode::InvalidRequest,
        401 => ErrorCode::IdentityUnverified,
        402 => ErrorCode::PaymentRequired,
        403 => ErrorCode::Forbidden,
        404 => ErrorCode::NotFound,
        409 => ErrorCode::PreconditionFailed,
        410 => ErrorCode::ApprovalExpired,
        412 => ErrorCode::PreconditionFailed,
        422 => ErrorCode::IntegrityFailed,
        429 => ErrorCode::RateLimited,
        501 => ErrorCode::NotSupported,
        502 | 504 => ErrorCode::UpstreamError,
        503 => ErrorCode::ExecutorOffline,
        _ => ErrorCode::Internal,
    }
}

/// Decode an error envelope leniently. Unknown codes fall back to the HTTP status mapping and
/// keep the original code string in `details.code`; non-JSON bodies produce a generic error.
pub(crate) fn decode_error_body(status: u16, body: &[u8]) -> ApiError {
    if let Ok(parsed) = serde_json::from_slice::<ErrorBody>(body) {
        return ApiError::from_body(&parsed);
    }
    let fallback = ApiError::new(code_for_status(status)).with_detail("http_status", status);
    let Ok(Value::Object(root)) = serde_json::from_slice::<Value>(body) else {
        return fallback;
    };
    let Some(Value::Object(err)) = root.get("error") else {
        return fallback;
    };
    let raw_code = err.get("code").and_then(Value::as_str);
    let code = raw_code
        .and_then(ErrorCode::parse)
        .unwrap_or_else(|| code_for_status(status));
    let mut e = ApiError::new(code);
    if let Some(m) = err.get("message").and_then(Value::as_str) {
        e = e.with_message(m, m);
    }
    if let Some(Value::Object(d)) = err.get("details") {
        for (k, v) in d {
            e = e.with_detail(k.clone(), v.clone());
        }
    }
    if let Some(raw) = raw_code
        && ErrorCode::parse(raw).is_none()
    {
        e = e.with_detail("code", raw.to_owned());
    }
    if let Some(r) = err.get("request_id").and_then(Value::as_str) {
        e = e.with_request_id(r);
    }
    e
}

#[cfg(test)]
mod tests {
    use super::*;
    use aipass_types::Lang;

    #[test]
    fn decodes_contract_envelope() {
        let body = br#"{"error":{"code":"SCOPE_DENIED","message":"x","details":{"field":"view"},"request_id":"req_01jbz3k6w8a7m2q4t5v9x0y1z2"}}"#;
        let e = decode_error_body(403, body);
        assert_eq!(e.code, ErrorCode::ScopeDenied);
        assert_eq!(e.message(Lang::ZhCn), "x");
        assert_eq!(e.details.get("field").unwrap(), "view");
        assert_eq!(
            e.request_id.as_deref(),
            Some("req_01jbz3k6w8a7m2q4t5v9x0y1z2")
        );
    }

    #[test]
    fn unknown_code_and_garbage_fall_back_to_status() {
        let e = decode_error_body(
            429,
            br#"{"error":{"code":"SOMETHING_NEW","message":"slow down"}}"#,
        );
        assert_eq!(e.code, ErrorCode::RateLimited);
        assert_eq!(e.details.get("code").unwrap(), "SOMETHING_NEW");
        assert_eq!(e.message(Lang::En), "slow down");
        let e = decode_error_body(503, b"<html>bad gateway</html>");
        assert_eq!(e.code, ErrorCode::ExecutorOffline);
        let e = decode_error_body(500, b"");
        assert_eq!(e.code, ErrorCode::Internal);
    }

    #[test]
    fn local_errors_map_to_actionable_api_errors() {
        let e = ClientError::Unreachable {
            endpoint: "unix:///tmp/x.sock".into(),
            reason: "No such file".into(),
        };
        let api = e.to_api_error();
        assert_eq!(api.code, ErrorCode::Internal);
        assert_eq!(api.details.get("reason").unwrap(), "broker_unreachable");
        assert_eq!(
            ClientError::Key("missing".into()).to_api_error().code,
            ErrorCode::IdentityUnverified
        );
    }
}
