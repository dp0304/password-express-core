// SPDX-License-Identifier: Apache-2.0
//! HTTP error envelope (CONTRACTS §1.5): `{"error":{"code","message","details","request_id"}}`
//! with the status of the code, zh-CN by default and English when `Accept-Language` starts
//! with `en`. Every error carries a fresh `req_…` id (also in `X-Request-Id`).

use aipass_types::ids::RequestId;
use aipass_types::{ApiError, ErrorCode, Lang};
use axum::Json;
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};

/// Language requested by the client.
pub fn lang_of(headers: &HeaderMap) -> Lang {
    Lang::from_accept_language(
        headers
            .get(axum::http::header::ACCEPT_LANGUAGE)
            .and_then(|v| v.to_str().ok()),
    )
}

/// An [`ApiError`] rendered for one request.
#[derive(Debug, Clone)]
pub struct HttpError {
    /// The error.
    pub err: ApiError,
    /// Response language.
    pub lang: Lang,
}

impl HttpError {
    /// Wrap.
    pub fn new(err: ApiError, lang: Lang) -> Self {
        Self { err, lang }
    }
}

impl IntoResponse for HttpError {
    fn into_response(self) -> Response {
        let mut err = self.err;
        let rid = err
            .request_id
            .clone()
            .unwrap_or_else(|| RequestId::generate().into_string());
        err.request_id = Some(rid.clone());
        let status =
            StatusCode::from_u16(err.http_status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        let mut resp = (status, Json(err.to_body(self.lang))).into_response();
        if let Ok(v) = HeaderValue::from_str(&rid) {
            resp.headers_mut().insert("x-request-id", v);
        }
        resp.headers_mut().insert(
            axum::http::header::CACHE_CONTROL,
            HeaderValue::from_static("no-store"),
        );
        resp
    }
}

/// `INVALID_REQUEST` with a machine-readable `details.reason`.
pub fn invalid(reason: &'static str) -> ApiError {
    ApiError::new(ErrorCode::InvalidRequest).with_detail("reason", reason)
}

/// Object too large.
pub fn too_large(limit: usize) -> ApiError {
    ApiError::new(ErrorCode::InvalidRequest)
        .with_message("对象过大", "Object too large.")
        .with_detail("reason", "too_large")
        .with_detail("limit", limit as u64)
}

/// Unknown / unverifiable principal (never says which part failed beyond a short reason).
pub fn unverified(reason: &'static str) -> ApiError {
    ApiError::new(ErrorCode::IdentityUnverified).with_detail("reason", reason)
}

/// Internal error with a safe log line (no secrets, no bodies).
pub fn internal(context: &'static str) -> ApiError {
    tracing::warn!(context, "internal error");
    ApiError::new(ErrorCode::Internal)
}

/// Map a storage error from the blob backend.
pub fn storage(e: aipass_storage::StorageError) -> ApiError {
    tracing::warn!(error = %e, "blob backend error");
    match e {
        aipass_storage::StorageError::InvalidKey => invalid("invalid_key"),
        aipass_storage::StorageError::TooLarge { limit } => too_large(limit as usize),
        aipass_storage::StorageError::RateLimited => ApiError::new(ErrorCode::RateLimited),
        _ => ApiError::new(ErrorCode::Internal),
    }
}
