// SPDX-License-Identifier: Apache-2.0
//! Storage errors. Messages must never contain credentials, signed URLs, authorization
//! headers or object contents — backends sanitize before constructing them.

use aipass_types::{ApiError, ErrorCode};
use thiserror::Error;

/// Error from an [`crate::ObjectStore`] operation.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum StorageError {
    /// The key is not a valid object key (see `aipass_types::vault::keys::is_valid`).
    #[error("invalid object key")]
    InvalidKey,
    /// Credentials were rejected (401/403 or equivalent).
    #[error("storage credentials were rejected")]
    Unauthorized,
    /// The bucket / container / vault does not exist.
    #[error("storage location not found")]
    LocationNotFound,
    /// Object larger than the backend or protocol allows.
    #[error("object too large (limit {limit} bytes)")]
    TooLarge {
        /// Limit in bytes.
        limit: u64,
    },
    /// The backend throttled the request.
    #[error("storage backend rate limited the request")]
    RateLimited,
    /// Network / connection failure (transient).
    #[error("storage network error: {0}")]
    Network(String),
    /// Timed out (transient).
    #[error("storage request timed out")]
    Timeout,
    /// Local I/O failure.
    #[error("storage I/O error: {0}")]
    Io(String),
    /// The backend answered with something unexpected.
    #[error("storage backend error (status {status:?}): {message}")]
    Backend {
        /// HTTP status, when relevant.
        status: Option<u16>,
        /// Sanitized message.
        message: String,
    },
    /// The operation is not supported by this backend.
    #[error("operation not supported by this storage backend: {0}")]
    Unsupported(&'static str),
}

impl StorageError {
    /// Whether retrying later may succeed.
    pub fn is_retryable(&self) -> bool {
        matches!(self, Self::RateLimited | Self::Network(_) | Self::Timeout)
            || matches!(self, Self::Backend { status: Some(s), .. } if *s >= 500)
    }
}

impl From<std::io::Error> for StorageError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e.kind().to_string())
    }
}

impl From<StorageError> for ApiError {
    fn from(e: StorageError) -> Self {
        let code = match e {
            StorageError::InvalidKey => ErrorCode::InvalidRequest,
            StorageError::Unauthorized => ErrorCode::Forbidden,
            StorageError::LocationNotFound => ErrorCode::NotFound,
            StorageError::TooLarge { .. } => ErrorCode::InvalidRequest,
            StorageError::RateLimited => ErrorCode::RateLimited,
            StorageError::Unsupported(_) => ErrorCode::NotSupported,
            StorageError::Network(_) | StorageError::Timeout | StorageError::Backend { .. } => {
                ErrorCode::UpstreamError
            }
            StorageError::Io(_) => ErrorCode::Internal,
        };
        ApiError::new(code).with_detail("storage", e.to_string())
    }
}
