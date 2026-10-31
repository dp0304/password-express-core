// SPDX-License-Identifier: Apache-2.0
//! Non-secret desktop settings (`<home>/desktop.json`).

use std::path::Path;

use aipass_types::ids::ExecutorId;
use serde::{Deserialize, Serialize};

use crate::error::{UiError, UiResult};
use crate::paths::write_private;

/// Default cloud base URL (placeholder domain, CONTRACTS §1.7).
pub const DEFAULT_CLOUD_URL: &str = "https://cloud.aipass.example";

/// Settings persisted between runs. Never contains secrets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    /// Always 1.
    pub format: u32,
    /// UI language: "zh-CN" or "en".
    pub lang: String,
    /// Executor id of the embedded node (identity lives in the secret store).
    pub executor_id: Option<ExecutorId>,
    /// Relay base URL for phone approvals (official cloud or a self-hosted node).
    pub relay_url: Option<String>,
    /// Cloud base URL.
    pub cloud_url: String,
    /// Signed-in cloud account e-mail (display only; the session token is secret-stored).
    pub cloud_email: Option<String>,
    /// Last license token (offline-verifiable; not a vault secret).
    pub license_token: Option<String>,
    /// Pinned cloud license public key (b64u), trust-on-first-use from the cloud API.
    pub license_public_key: Option<String>,
    /// Extension origins allowed to use native messaging (`chrome-extension://<id>/`).
    /// Empty = any origin that Chrome let through the host manifest.
    pub allowed_extension_origins: Vec<String>,
    /// Seconds before a copied secret is cleared from the clipboard.
    pub clipboard_clear_secs: u64,
    /// Seconds of inactivity before the vault locks (0 = never).
    pub auto_lock_secs: u64,
    /// The user finished onboarding (three first actions shown until then).
    pub onboarding_done: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            format: 1,
            lang: "zh-CN".into(),
            executor_id: None,
            relay_url: None,
            cloud_url: std::env::var("AIPASS_CLOUD_URL").unwrap_or_else(|_| DEFAULT_CLOUD_URL.into()),
            cloud_email: None,
            license_token: None,
            license_public_key: None,
            allowed_extension_origins: Vec::new(),
            clipboard_clear_secs: 30,
            auto_lock_secs: 900,
            onboarding_done: false,
        }
    }
}

impl Settings {
    /// Load, or defaults when the file does not exist.
    pub fn load(path: &Path) -> UiResult<Self> {
        match std::fs::read(path) {
            Ok(b) => serde_json::from_slice(&b)
                .map_err(|_| UiError::internal("desktop.json is not valid / 设置文件无效")),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e.into()),
        }
    }

    /// Persist atomically (0600).
    pub fn save(&self, path: &Path) -> UiResult<()> {
        let bytes = serde_json::to_vec_pretty(self).map_err(|_| UiError::internal("encode settings"))?;
        write_private(path, &bytes)?;
        Ok(())
    }

    /// Validate user-editable fields.
    pub fn validate(&self) -> UiResult<()> {
        if self.lang != "zh-CN" && self.lang != "en" {
            return Err(UiError::invalid("不支持的语言", "Unsupported language"));
        }
        for o in &self.allowed_extension_origins {
            if !aipass_nm::ipc::is_extension_origin(o) {
                return Err(UiError::invalid(
                    "扩展来源格式应为 chrome-extension://<id>/",
                    "Extension origins must look like chrome-extension://<id>/",
                ));
            }
        }
        for u in [Some(&self.cloud_url), self.relay_url.as_ref()].into_iter().flatten() {
            let parsed = url::Url::parse(u).map_err(|_| UiError::invalid("地址格式不正确", "Invalid URL"))?;
            let loopback = matches!(parsed.host_str(), Some("127.0.0.1" | "localhost" | "[::1]"));
            if parsed.scheme() != "https" && !(parsed.scheme() == "http" && loopback) {
                return Err(UiError::invalid(
                    "云端与中继地址必须使用 https（本机调试可用 http://127.0.0.1）",
                    "Cloud and relay URLs must use https (http only for 127.0.0.1 during development)",
                ));
            }
        }
        if !(10..=600).contains(&self.clipboard_clear_secs) {
            return Err(UiError::invalid("剪贴板清除时间应在 10–600 秒之间", "Clipboard clear time must be 10–600 s"));
        }
        if self.auto_lock_secs != 0 && !(60..=86_400).contains(&self.auto_lock_secs) {
            return Err(UiError::invalid("自动锁定时间应为 0 或 60–86400 秒", "Auto-lock must be 0 or 60–86400 s"));
        }
        Ok(())
    }
}
