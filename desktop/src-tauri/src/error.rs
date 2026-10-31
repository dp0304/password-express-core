// SPDX-License-Identifier: Apache-2.0
//! The one error type that crosses into the WebView. It carries a stable code (CONTRACTS
//! §1.5 plus `LOCKED` / `NO_VAULT` / `REAUTH_REQUIRED`) and a zh/en message. It is built
//! only from typed errors whose messages never contain secret values.

use aipass_types::{ApiError, ErrorCode, Lang, Localized};
use aipass_vault::VaultError;
use serde::Serialize;

/// Error returned by every Tauri command.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UiError {
    /// Stable machine code.
    pub code: String,
    /// Human message in both languages.
    pub message: Localized,
}

/// Result alias for desktop operations.
pub type UiResult<T> = Result<T, UiError>;

impl UiError {
    /// Build from a code and both messages.
    pub fn new(code: &str, zh: &str, en: &str) -> Self {
        Self { code: code.to_owned(), message: Localized::new(zh, en) }
    }

    /// Input validation failure.
    pub fn invalid(zh: &str, en: &str) -> Self {
        Self::new(ErrorCode::InvalidRequest.as_str(), zh, en)
    }

    /// Vault locked.
    pub fn locked() -> Self {
        Self::new("LOCKED", "账号库已锁定，请先解锁。", "The vault is locked. Unlock it first.")
    }

    /// The embedded node is not running yet (it starts at the first unlock).
    pub fn node_not_running() -> Self {
        Self::new(
            "EXECUTOR_OFFLINE",
            "本机执行设备尚未启动，请先解锁账号库。",
            "The local execution node is not running yet. Unlock the vault first.",
        )
    }

    /// A sensitive action needs a fresh re-authentication.
    pub fn reauth_required() -> Self {
        Self::new(
            "REAUTH_REQUIRED",
            "此操作需要重新验证本机解锁密码。",
            "This action requires re-entering the local unlock password.",
        )
    }

    /// Internal failure without details.
    pub fn internal(what: &str) -> Self {
        Self::new(
            ErrorCode::Internal.as_str(),
            &format!("内部错误：{what}"),
            &format!("Internal error: {what}"),
        )
    }

    /// Message in the requested language.
    pub fn text(&self, lang: Lang) -> &str {
        match lang {
            Lang::ZhCn => &self.message.zh,
            Lang::En => &self.message.en,
        }
    }
}

impl std::fmt::Display for UiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message.en)
    }
}

impl std::error::Error for UiError {}

impl From<VaultError> for UiError {
    fn from(e: VaultError) -> Self {
        Self { code: e.code().as_str().to_owned(), message: e.localized() }
    }
}

impl From<ApiError> for UiError {
    fn from(e: ApiError) -> Self {
        let message = e
            .message
            .clone()
            .unwrap_or_else(|| Localized::new(e.code.default_message(Lang::ZhCn), e.code.default_message(Lang::En)));
        Self { code: e.code.as_str().to_owned(), message }
    }
}

impl From<aipass_hostconfig::HostConfigError> for UiError {
    fn from(e: aipass_hostconfig::HostConfigError) -> Self {
        // HostConfigError messages never contain file contents (crate guarantee).
        let en = e.to_string();
        Self::new(ErrorCode::InvalidRequest.as_str(), &format!("AI 宿主配置失败：{en}"), &format!("Host configuration failed: {en}"))
    }
}

impl From<aipass_client::ClientError> for UiError {
    fn from(e: aipass_client::ClientError) -> Self {
        e.to_api_error().into()
    }
}

impl From<std::io::Error> for UiError {
    fn from(e: std::io::Error) -> Self {
        let kind = format!("{:?}", e.kind());
        Self::new(ErrorCode::Internal.as_str(), &format!("文件操作失败（{kind}）"), &format!("File operation failed ({kind})"))
    }
}
