// SPDX-License-Identifier: Apache-2.0
//! `CoreError { code, message }` — the only error type crossing the FFI boundary.
//!
//! Codes are the §1.5 codes plus the client-local `LOCKED` / `NO_VAULT`. Messages are
//! localized (zh-CN default, `en` via [`crate::set_locale`]) and never contain secrets:
//! they are built from static strings and error codes only.

use std::sync::atomic::{AtomicBool, Ordering};

use aipass_types::{ApiError, ErrorCode, Lang, Localized};
use aipass_vault::VaultError;

static ENGLISH: AtomicBool = AtomicBool::new(false);

/// Current UI language for error messages.
pub(crate) fn lang() -> Lang {
    if ENGLISH.load(Ordering::Relaxed) {
        Lang::En
    } else {
        Lang::ZhCn
    }
}

pub(crate) fn set_lang(english: bool) {
    ENGLISH.store(english, Ordering::Relaxed);
}

pub(crate) fn pick(l: &Localized) -> String {
    match lang() {
        Lang::En => l.en.clone(),
        Lang::ZhCn => l.zh.clone(),
    }
}

/// Error returned by every fallible core method.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, uniffi::Error)]
pub enum CoreError {
    /// `code` is a stable machine code (e.g. `LOCKED`, `NOT_FOUND`, `SYNC_CONFLICT`);
    /// `message` is a user-presentable explanation in the current locale.
    #[error("{code}: {message}")]
    Failure { code: String, message: String },
}

impl CoreError {
    pub(crate) fn new(code: ErrorCode, zh: &str, en: &str) -> Self {
        CoreError::Failure {
            code: code.as_str().to_owned(),
            message: pick(&Localized::new(zh, en)),
        }
    }

    pub(crate) fn code(code: ErrorCode) -> Self {
        CoreError::Failure {
            code: code.as_str().to_owned(),
            message: code.default_message(lang()).to_owned(),
        }
    }

    pub(crate) fn invalid(zh: &str, en: &str) -> Self {
        Self::new(ErrorCode::InvalidRequest, zh, en)
    }

    /// Machine code (convenience for Rust tests).
    pub fn code_str(&self) -> &str {
        match self {
            CoreError::Failure { code, .. } => code,
        }
    }
}

impl From<VaultError> for CoreError {
    fn from(e: VaultError) -> Self {
        CoreError::Failure {
            code: e.code().as_str().to_owned(),
            message: pick(&e.localized()),
        }
    }
}

impl From<ApiError> for CoreError {
    fn from(e: ApiError) -> Self {
        let message = match &e.message {
            Some(m) => pick(m),
            None => e.code.default_message(lang()).to_owned(),
        };
        CoreError::Failure {
            code: e.code.as_str().to_owned(),
            message,
        }
    }
}

impl From<aipass_crypto::CryptoError> for CoreError {
    fn from(e: aipass_crypto::CryptoError) -> Self {
        CoreError::from(VaultError::Crypto(e))
    }
}

pub(crate) type CoreResult<T> = Result<T, CoreError>;

/// Error a native [`crate::SecretStore`] implementation reports.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, uniffi::Error)]
pub enum SecretStoreError {
    /// The user cancelled or failed biometric / passcode authentication.
    #[error("user authentication cancelled or failed")]
    UserCancelled,
    /// Keychain / Keystore unavailable (device locked, item inaccessible, …).
    #[error("secure storage unavailable")]
    Unavailable { reason: String },
    /// An unexpected error inside the native callback.
    #[error("unexpected secure storage error")]
    Unexpected { reason: String },
}

impl From<uniffi::UnexpectedUniFFICallbackError> for SecretStoreError {
    fn from(e: uniffi::UnexpectedUniFFICallbackError) -> Self {
        SecretStoreError::Unexpected { reason: e.reason }
    }
}

impl From<SecretStoreError> for VaultError {
    fn from(e: SecretStoreError) -> Self {
        match e {
            SecretStoreError::UserCancelled => {
                VaultError::Cancelled("user authentication cancelled")
            }
            SecretStoreError::Unavailable { .. } => {
                VaultError::SecretStore("secure storage unavailable")
            }
            SecretStoreError::Unexpected { .. } => {
                VaultError::SecretStore("unexpected secure storage error")
            }
        }
    }
}
