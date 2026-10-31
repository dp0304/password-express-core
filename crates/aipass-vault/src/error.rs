// SPDX-License-Identifier: Apache-2.0
//! Vault / sync error type.
//!
//! Errors never carry key material, plaintext, passwords, recovery keys or storage
//! credentials — only the kind of failure and short, static, non-sensitive reasons. Every
//! variant maps to a stable [`ErrorCode`] (CONTRACTS §1.5, plus the client-local `LOCKED`
//! and `NO_VAULT`) through [`VaultError::code`] and `From<VaultError> for ApiError`.

use aipass_crypto::CryptoError;
use aipass_storage::StorageError;
use aipass_types::{ApiError, CanonicalError, ErrorCode, Localized, SignatureError};
use thiserror::Error;

/// Result alias.
pub type Result<T, E = VaultError> = core::result::Result<T, E>;

/// Vault Core / sync engine error.
#[derive(Debug, Clone, PartialEq, Error)]
#[non_exhaustive]
pub enum VaultError {
    /// The vault is locked (no keys in memory).
    #[error("the vault is locked")]
    Locked,
    /// No vault exists on this device yet.
    #[error("no vault on this device")]
    NoVault,
    /// A vault already exists in this data directory / storage location.
    #[error("a vault already exists here")]
    AlreadyExists,
    /// Object not found (entry, device, version, …).
    #[error("not found: {0}")]
    NotFound(&'static str),
    /// Invalid input. The reason is a fixed, non-sensitive description.
    #[error("invalid input: {0}")]
    InvalidInput(&'static str),
    /// Invalid input with a localized user-facing explanation (never contains secrets).
    #[error("invalid input: {}", .0.en)]
    Invalid(Localized),
    /// Signature, hash, AEAD or structural verification failed.
    #[error("integrity check failed: {0}")]
    Integrity(&'static str),
    /// Storage older than (or different from) the known checkpoint.
    #[error("rollback detected: {0}")]
    Rollback(&'static str),
    /// Entry has an unresolved sync conflict; automatic use is paused.
    #[error("sync conflict: automatic use of this entry is paused")]
    SyncConflict,
    /// A conditional write failed / state changed concurrently.
    #[error("precondition failed: {0}")]
    PreconditionFailed(&'static str),
    /// This device is not allowed to perform the action (e.g. not an owner, revoked).
    #[error("forbidden: {0}")]
    Forbidden(&'static str),
    /// The device has been revoked from this vault.
    #[error("this device has been revoked from the vault")]
    Revoked,
    /// The secret needed is not available (entry has no secret, executor key unknown…).
    #[error("secret unavailable: {0}")]
    SecretUnavailable(&'static str),
    /// A time-limited object expired (pairing QR, approval window).
    #[error("expired: {0}")]
    Expired(&'static str),
    /// The pairing / approval was cancelled or rejected.
    #[error("cancelled: {0}")]
    Cancelled(&'static str),
    /// Operation not supported.
    #[error("not supported: {0}")]
    Unsupported(&'static str),
    /// Low-level crypto failure.
    #[error("cryptographic operation failed: {0}")]
    Crypto(CryptoError),
    /// Storage backend failure.
    #[error("storage error: {0}")]
    Storage(StorageError),
    /// Relay transport failure (message is sanitized by the transport).
    #[error("relay error: {0}")]
    Relay(String),
    /// Local I/O failure (kind only).
    #[error("local I/O error: {0}")]
    Io(String),
    /// Platform secret store failure (kind only).
    #[error("secret store error: {0}")]
    SecretStore(&'static str),
    /// Internal invariant violated.
    #[error("internal error: {0}")]
    Internal(&'static str),
    /// An error that already carries a stable API code (e.g. from `aipass_types::approval`).
    #[error("{}", .0.code)]
    Api(Box<ApiError>),
}

impl VaultError {
    /// Stable error code.
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::Locked => ErrorCode::Locked,
            Self::NoVault => ErrorCode::NoVault,
            Self::AlreadyExists => ErrorCode::PreconditionFailed,
            Self::NotFound(_) => ErrorCode::NotFound,
            Self::InvalidInput(_) | Self::Invalid(_) => ErrorCode::InvalidRequest,
            Self::Integrity(_) => ErrorCode::IntegrityFailed,
            Self::Rollback(_) => ErrorCode::RollbackDetected,
            Self::SyncConflict => ErrorCode::SyncConflict,
            Self::PreconditionFailed(_) => ErrorCode::PreconditionFailed,
            Self::Forbidden(_) => ErrorCode::Forbidden,
            Self::Revoked => ErrorCode::Forbidden,
            Self::SecretUnavailable(_) => ErrorCode::SecretUnavailable,
            Self::Expired(_) => ErrorCode::ApprovalExpired,
            Self::Cancelled(_) => ErrorCode::InvalidRequest,
            Self::Unsupported(_) => ErrorCode::NotSupported,
            Self::Crypto(e) => match e {
                CryptoError::Rng | CryptoError::Encrypt => ErrorCode::Internal,
                _ => ErrorCode::IntegrityFailed,
            },
            Self::Storage(e) => ApiError::from(e.clone()).code,
            Self::Relay(_) => ErrorCode::UpstreamError,
            Self::Io(_) | Self::SecretStore(_) | Self::Internal(_) => ErrorCode::Internal,
            Self::Api(e) => e.code,
        }
    }

    /// True when the failure is transient (network, rate limit, timeout) and the change can
    /// stay in the outbox for a later retry (design doc §10.6).
    pub fn is_offline(&self) -> bool {
        match self {
            Self::Storage(e) => e.is_retryable(),
            Self::Relay(_) => true,
            _ => false,
        }
    }

    /// Localized explanation for user interfaces (zh-CN, en).
    pub fn localized(&self) -> Localized {
        match self {
            Self::Invalid(l) => l.clone(),
            Self::Revoked => Localized::new(
                "此设备已被移出账号库，无法继续同步或获得新密钥",
                "This device was removed from the vault; it can no longer sync or receive new keys.",
            ),
            Self::SyncConflict => Localized::new(
                "该条目存在同步冲突，已暂停自动使用。请在可信客户端选择并确认当前有效版本。",
                "This entry has a sync conflict and automatic use is paused. Choose the current version on a trusted client.",
            ),
            Self::Rollback(_) => Localized::new(
                "检测到存储被回退到较旧版本或被替换，已停止写入。请检查存储服务，或从其他可信设备同步。",
                "Storage appears to have been rolled back or replaced; writes are stopped. Check the storage service or sync from another trusted device.",
            ),
            other => {
                let code = other.code();
                Localized::new(
                    code.default_message(aipass_types::Lang::ZhCn),
                    code.default_message(aipass_types::Lang::En),
                )
            }
        }
    }
}

impl From<VaultError> for ApiError {
    fn from(e: VaultError) -> Self {
        match e {
            VaultError::Api(api) => *api,
            other => {
                let msg = other.localized();
                let mut api = ApiError::new(other.code()).with_message(msg.zh, msg.en);
                match &other {
                    VaultError::Integrity(r)
                    | VaultError::Rollback(r)
                    | VaultError::NotFound(r)
                    | VaultError::InvalidInput(r)
                    | VaultError::PreconditionFailed(r)
                    | VaultError::Forbidden(r)
                    | VaultError::SecretUnavailable(r)
                    | VaultError::Expired(r)
                    | VaultError::Cancelled(r)
                    | VaultError::Unsupported(r) => {
                        api = api.with_detail("reason", *r);
                    }
                    VaultError::Storage(s) => {
                        api = api.with_detail("storage", s.to_string());
                    }
                    _ => {}
                }
                api
            }
        }
    }
}

impl From<ApiError> for VaultError {
    fn from(e: ApiError) -> Self {
        Self::Api(Box::new(e))
    }
}

impl From<CryptoError> for VaultError {
    fn from(e: CryptoError) -> Self {
        Self::Crypto(e)
    }
}

impl From<StorageError> for VaultError {
    fn from(e: StorageError) -> Self {
        Self::Storage(e)
    }
}

impl From<CanonicalError> for VaultError {
    fn from(_: CanonicalError) -> Self {
        Self::Internal("canonical JSON encoding failed")
    }
}

impl From<SignatureError> for VaultError {
    fn from(e: SignatureError) -> Self {
        match e {
            SignatureError::Canonical(_) => Self::Internal("canonical JSON encoding failed"),
            SignatureError::Malformed => Self::Integrity("malformed signature"),
            SignatureError::Invalid => Self::Integrity("invalid signature"),
        }
    }
}

impl From<aipass_types::IdError> for VaultError {
    fn from(_: aipass_types::IdError) -> Self {
        Self::InvalidInput("malformed identifier")
    }
}

impl From<std::io::Error> for VaultError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e.kind().to_string())
    }
}

impl From<aipass_types::relay::RelayError> for VaultError {
    fn from(e: aipass_types::relay::RelayError) -> Self {
        use aipass_types::relay::RelayError as R;
        match e {
            R::Signature => Self::Integrity("relay envelope signature invalid"),
            R::Crypto => Self::Integrity("relay envelope could not be opened"),
            R::Payload => Self::Integrity("relay payload invalid"),
            R::TooLarge => Self::InvalidInput("relay envelope too large"),
            R::Version => Self::Unsupported("relay envelope version"),
            R::Canonical(_) => Self::Internal("canonical JSON encoding failed"),
        }
    }
}

/// Parse JSON from storage/relay bytes, mapping failures to an integrity error without
/// echoing the content.
pub(crate) fn parse_json<T: serde::de::DeserializeOwned>(
    bytes: &[u8],
    what: &'static str,
) -> Result<T> {
    serde_json::from_slice(bytes).map_err(|_| VaultError::Integrity(what))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_and_api_conversion() {
        assert_eq!(VaultError::Locked.code(), ErrorCode::Locked);
        assert_eq!(VaultError::SyncConflict.code(), ErrorCode::SyncConflict);
        assert_eq!(
            VaultError::Rollback("x").code(),
            ErrorCode::RollbackDetected
        );
        assert_eq!(
            VaultError::Crypto(CryptoError::Decrypt).code(),
            ErrorCode::IntegrityFailed
        );
        let api: ApiError = VaultError::Integrity("manifest signature").into();
        assert_eq!(api.code, ErrorCode::IntegrityFailed);
        assert_eq!(api.details["reason"], "manifest signature");
        let back: VaultError = ApiError::scope_denied().into();
        assert_eq!(back.code(), ErrorCode::ScopeDenied);
        assert!(VaultError::Storage(StorageError::Timeout).is_offline());
        assert!(!VaultError::Integrity("x").is_offline());
    }
}
