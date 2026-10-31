// SPDX-License-Identifier: Apache-2.0
//! Internal error plumbing. Everything leaving the crate is an [`ApiError`]; database and
//! serialization failures become `INTERNAL` after being logged **without** any payload.

use aipass_types::error::{ApiError, ErrorCode};
use thiserror::Error;

/// Error used inside database closures; converted to [`ApiError`] at the boundary.
#[derive(Debug)]
pub(crate) enum StoreError {
    Api(ApiError),
    Sql(rusqlite::Error),
    Json(serde_json::Error),
}

pub(crate) type SResult<T> = Result<T, StoreError>;

impl From<ApiError> for StoreError {
    fn from(e: ApiError) -> Self {
        Self::Api(e)
    }
}

impl From<ErrorCode> for StoreError {
    fn from(c: ErrorCode) -> Self {
        Self::Api(ApiError::new(c))
    }
}

impl From<rusqlite::Error> for StoreError {
    fn from(e: rusqlite::Error) -> Self {
        Self::Sql(e)
    }
}

impl From<serde_json::Error> for StoreError {
    fn from(e: serde_json::Error) -> Self {
        Self::Json(e)
    }
}

impl From<aipass_types::ids::IdError> for StoreError {
    fn from(e: aipass_types::ids::IdError) -> Self {
        Self::Api(e.into())
    }
}

impl From<aipass_types::CanonicalError> for StoreError {
    fn from(e: aipass_types::CanonicalError) -> Self {
        Self::Api(e.into())
    }
}

impl StoreError {
    /// Convert to the public error. SQL / JSON details are logged (they never contain
    /// secrets: the broker database holds no credentials) and replaced by `INTERNAL`.
    pub(crate) fn into_api(self) -> ApiError {
        match self {
            Self::Api(e) => e,
            Self::Sql(e) => {
                tracing::error!(error = %e, "broker database error");
                ApiError::internal()
            }
            Self::Json(e) => {
                tracing::error!(
                    line = e.line(),
                    column = e.column(),
                    "broker record (de)serialization error"
                );
                ApiError::internal()
            }
        }
    }
}

impl From<StoreError> for ApiError {
    fn from(e: StoreError) -> Self {
        e.into_api()
    }
}

/// Failure to open a broker.
#[derive(Debug, Error)]
pub enum OpenError {
    /// Filesystem problem (data directory, admin token file).
    #[error("broker I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// Database could not be opened or migrated.
    #[error("broker database error: {0}")]
    Database(String),
}

impl From<rusqlite::Error> for OpenError {
    fn from(e: rusqlite::Error) -> Self {
        Self::Database(e.to_string())
    }
}

impl From<StoreError> for OpenError {
    fn from(e: StoreError) -> Self {
        match e {
            StoreError::Sql(e) => Self::Database(e.to_string()),
            StoreError::Json(e) => Self::Database(format!("record decode failed: {}", e.line())),
            StoreError::Api(e) => Self::Database(e.to_string()),
        }
    }
}

/// Shorthand constructors with zh/en messages.
pub(crate) fn err(code: ErrorCode, zh: &str, en: &str) -> ApiError {
    ApiError::new(code).with_message(zh, en)
}
