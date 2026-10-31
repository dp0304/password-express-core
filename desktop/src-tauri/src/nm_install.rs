// SPDX-License-Identifier: Apache-2.0
//! Installs the native-messaging host manifest `com.aipass.native` for Chromium browsers
//! (Chrome, Chromium, Edge, Brave) on macOS, Linux and Windows. The manifest points at the
//! bundled `aipass-nm-host` binary and allows exactly one extension origin.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::core::AppCore;
use crate::error::{UiError, UiResult};

/// Host name (CONTRACTS §11).
pub const HOST_NAME: &str = "com.aipass.native";

/// Supported browsers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Browser {
    /// Google Chrome.
    Chrome,
    /// Chromium.
    Chromium,
    /// Microsoft Edge.
    Edge,
    /// Brave.
    Brave,
}

/// Absolute path of the bundled host binary.
pub fn nm_host_path() -> UiResult<PathBuf> {
    if let Some(p) = std::env::var_os("AIPASS_NM_HOST_PATH") {
        let p = PathBuf::from(p);
        if p.is_absolute() && p.is_file() {
            return Ok(p);
        }
    }
    let exe = std::env::current_exe()?;
    let name = if cfg!(windows) { "aipass-nm-host.exe" } else { "aipass-nm-host" };
    let p = exe.parent().ok_or_else(|| UiError::internal("exe dir"))?.join(name);
    if p.is_file() {
        Ok(p)
    } else {
        Err(UiError::new("NOT_FOUND", "找不到随附的 aipass-nm-host，请重新安装桌面 App。", "The bundled aipass-nm-host was not found. Reinstall the desktop app."))
    }
}

/// Where the manifest goes (Unix) — Windows uses a registry value instead.
#[cfg(not(windows))]
pub fn manifest_dir(browser: Browser) -> UiResult<PathBuf> {
    let home = dirs::home_dir().ok_or_else(|| UiError::internal("home"))?;
    #[cfg(target_os = "macos")]
    let base = home.join("Library/Application Support");
    #[cfg(not(target_os = "macos"))]
    let base = dirs::config_dir().unwrap_or_else(|| home.join(".config"));
    #[cfg(target_os = "macos")]
    let sub = match browser {
        Browser::Chrome => "Google/Chrome",
        Browser::Chromium => "Chromium",
        Browser::Edge => "Microsoft Edge",
        Browser::Brave => "BraveSoftware/Brave-Browser",
    };
    #[cfg(not(target_os = "macos"))]
    let sub = match browser {
        Browser::Chrome => "google-chrome",
        Browser::Chromium => "chromium",
        Browser::Edge => "microsoft-edge",
        Browser::Brave => "BraveSoftware/Brave-Browser",
    };
    Ok(base.join(sub).join("NativeMessagingHosts"))
}

/// Manifest JSON.
pub fn manifest_json(host_path: &std::path::Path, extension_origin: &str) -> serde_json::Value {
    json!({
        "name": HOST_NAME,
        "description": "AI 通行证 native messaging host / AI Pass native messaging host",
        "path": host_path.display().to_string(),
        "type": "stdio",
        "allowed_origins": [extension_origin],
    })
}

impl AppCore {
    /// Install the manifest for `browser`, allowing `extension_id`, and remember the origin.
    pub fn install_native_host(&self, browser: Browser, extension_id: &str) -> UiResult<String> {
        let origin = format!("chrome-extension://{}/", extension_id.trim());
        if !aipass_nm::ipc::is_extension_origin(&origin) {
            return Err(UiError::invalid("扩展 ID 应为 32 个 a–p 字母", "The extension id must be 32 letters a–p"));
        }
        let host = nm_host_path()?;
        let body = serde_json::to_vec_pretty(&manifest_json(&host, &origin)).map_err(|_| UiError::internal("encode"))?;
        let written = write_manifest(browser, &body)?;
        let o = origin.clone();
        self.mutate_settings(|s| {
            if !s.allowed_extension_origins.contains(&o) {
                s.allowed_extension_origins.push(o);
            }
        })?;
        crate::nm_server::ensure_token(self)?;
        Ok(written)
    }
}

#[cfg(not(windows))]
fn write_manifest(browser: Browser, body: &[u8]) -> UiResult<String> {
    let dir = manifest_dir(browser)?;
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(format!("{HOST_NAME}.json"));
    let tmp = dir.join(format!(".{HOST_NAME}.json.tmp"));
    std::fs::write(&tmp, body)?;
    std::fs::rename(&tmp, &path)?;
    Ok(path.display().to_string())
}

#[cfg(windows)]
fn write_manifest(browser: Browser, body: &[u8]) -> UiResult<String> {
    let dir = dirs::data_local_dir().ok_or_else(|| UiError::internal("LOCALAPPDATA"))?.join("AIPass");
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(format!("{HOST_NAME}.json"));
    std::fs::write(&path, body)?;
    let key = match browser {
        Browser::Chrome => r"HKCU\Software\Google\Chrome\NativeMessagingHosts\com.aipass.native",
        Browser::Chromium => r"HKCU\Software\Chromium\NativeMessagingHosts\com.aipass.native",
        Browser::Edge => r"HKCU\Software\Microsoft\Edge\NativeMessagingHosts\com.aipass.native",
        Browser::Brave => r"HKCU\Software\BraveSoftware\Brave-Browser\NativeMessagingHosts\com.aipass.native",
    };
    let status = std::process::Command::new("reg")
        .args(["add", key, "/ve", "/t", "REG_SZ", "/d"])
        .arg(&path)
        .arg("/f")
        .status()?;
    if !status.success() {
        return Err(UiError::internal("registry write failed / 注册表写入失败"));
    }
    Ok(path.display().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_shape() {
        let o = format!("chrome-extension://{}/", "b".repeat(32));
        let m = manifest_json(std::path::Path::new("/Applications/AI.app/Contents/MacOS/aipass-nm-host"), &o);
        assert_eq!(m["name"], HOST_NAME);
        assert_eq!(m["type"], "stdio");
        assert_eq!(m["allowed_origins"][0], o);
        #[cfg(target_os = "macos")]
        assert!(manifest_dir(Browser::Chrome).unwrap().ends_with("Google/Chrome/NativeMessagingHosts"));
    }
}
