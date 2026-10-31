// SPDX-License-Identifier: Apache-2.0
//! AI 通行证 desktop app (Tauri 2, one codebase for macOS / Windows / Linux).
//!
//! The Rust side owns everything sensitive: the vault ([`aipass_sync::VaultClient`]), the
//! embedded local node (broker + executor, protection level 兼容连接), the host-config
//! wizard, pairing, the optional cloud account, and the native-messaging IPC server for the
//! browser extension. The WebView receives metadata only.

pub mod clipboard;
pub mod cloud;
pub mod commands;
pub mod core;
pub mod core_ai;
pub mod core_pair;
pub mod error;
pub mod nm_install;
pub mod nm_server;
pub mod node;
pub mod paths;
pub mod relay;
pub mod secrets;
pub mod settings;
pub mod tunnel;

use std::sync::Arc;
use std::time::Duration;

use tauri::{Emitter, Manager};
use tokio_util::sync::CancellationToken;

use crate::core::{AppCore, CoreOptions, EventSink};

/// Emits core events to the main window (payloads never contain secrets).
struct TauriSink {
    handle: tauri::AppHandle,
}

impl EventSink for TauriSink {
    fn emit(&self, event: &str, payload: serde_json::Value) {
        if event == "open-app"
            && let Some(w) = self.handle.get_webview_window("main")
        {
            let _ = w.show();
            let _ = w.unminimize();
            let _ = w.set_focus();
        }
        let _ = self.handle.emit(event, payload);
    }
}

fn platform() -> aipass_types::vault::Platform {
    use aipass_types::vault::Platform;
    if cfg!(target_os = "macos") {
        Platform::Macos
    } else if cfg!(windows) {
        Platform::Windows
    } else {
        Platform::Linux
    }
}

/// Start the app.
pub fn run() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("AIPASS_LOG").unwrap_or_else(|_| "warn".into()),
        )
        .with_writer(std::io::stderr)
        .try_init();
    let shutdown = CancellationToken::new();
    let shutdown_setup = shutdown.clone();
    let app = tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .setup(move |app| {
            let paths = paths::AppPaths::from_env().ok_or("cannot determine the home directory")?;
            let core = AppCore::open(CoreOptions {
                paths,
                platform: platform(),
                app_version: app.package_info().version.to_string(),
                argon2: aipass_crypto::password::Argon2Params::CONTRACT_V1,
                serve_broker_socket: true,
                store_factory: None,
                sink: Arc::new(TauriSink { handle: app.handle().clone() }),
            })
            .map_err(|e| e.to_string())?;
            // Review CLI-02: revealed secrets, TOTP codes and the recovery key render in this
            // window, so keep it out of screenshots, screen recording and screen sharing
            // (macOS NSWindowSharingNone, Windows WDA_EXCLUDEFROMCAPTURE). tauri.conf.json
            // sets it too; this guards against a config regression. No reliable Linux
            // equivalent exists (documented in the README).
            for (_, w) in app.webview_windows() {
                if let Err(e) = w.set_content_protected(true) {
                    tracing::warn!(error = %e, "could not enable window content protection");
                }
            }
            app.manage(core.clone());
            let c = core.clone();
            let token = shutdown_setup.clone();
            tauri::async_runtime::spawn(async move {
                if let Err(e) = nm_server::serve_ipc(c, token).await {
                    tracing::error!(error = %e, "native-messaging IPC server stopped");
                }
            });
            let c = core.clone();
            let token = shutdown_setup.clone();
            tauri::async_runtime::spawn(async move {
                loop {
                    tokio::select! {
                        _ = token.cancelled() => break,
                        _ = tokio::time::sleep(Duration::from_secs(15)) => { c.auto_lock_tick().await; }
                    }
                }
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::app_status,
            commands::test_storage,
            commands::create_vault,
            commands::unlock,
            commands::lock,
            commands::reauth,
            commands::touch,
            commands::get_settings,
            commands::update_settings,
            commands::finish_onboarding,
            commands::verify_recovery_key,
            commands::save_recovery_kit,
            commands::replace_recovery_key,
            commands::list_items,
            commands::get_item,
            commands::save_item,
            commands::delete_item,
            commands::reveal_secret,
            commands::copy_secret,
            commands::totp_now,
            commands::generate_password,
            commands::copy_generated,
            commands::import_csv,
            commands::import_encrypted,
            commands::export_encrypted,
            commands::export_csv,
            commands::sync_now,
            commands::list_conflicts,
            commands::resolve_conflict,
            commands::list_devices,
            commands::revoke_device,
            commands::migrate_storage,
            commands::node_status,
            commands::list_connections,
            commands::approve_connection,
            commands::deny_connection,
            commands::control_connection,
            commands::host_detect,
            commands::host_plan,
            commands::host_apply,
            commands::host_cancel,
            commands::host_remove,
            commands::remote_instructions,
            commands::list_projects,
            commands::create_project,
            commands::list_resources,
            commands::create_resource,
            commands::delete_resource,
            commands::list_approvals,
            commands::approve_request,
            commands::deny_request,
            commands::list_operations,
            commands::list_grants,
            commands::revoke_grant,
            commands::audit_events,
            commands::verify_audit,
            commands::activity_summary,
            commands::pair_scan,
            commands::pair_confirm,
            commands::pair_cancel,
            commands::join_begin,
            commands::cloud_login,
            commands::cloud_logout,
            commands::cloud_status,
            commands::activate_license,
            commands::install_native_host,
            commands::cloud_link_node,
            commands::tunnel_start,
            commands::tunnel_stop,
            commands::tunnel_status,
        ])
        .build(tauri::generate_context!())
        .expect("failed to build the AI Pass desktop app");
    app.run(move |handle, event| {
        if let tauri::RunEvent::Exit = event {
            shutdown.cancel();
            if let Some(core) = handle.try_state::<Arc<AppCore>>() {
                let core = core.inner().clone();
                tauri::async_runtime::block_on(async move { core.shutdown().await });
            }
        }
    });
}

#[cfg(test)]
mod config_tests {
    /// Review CLI-02: every configured window is excluded from screen capture.
    #[test]
    fn windows_are_content_protected() {
        let conf: serde_json::Value = serde_json::from_str(include_str!("../tauri.conf.json")).unwrap();
        let windows = conf["app"]["windows"].as_array().expect("windows configured");
        assert!(!windows.is_empty());
        for w in windows {
            assert_eq!(w["contentProtected"], serde_json::Value::Bool(true), "window {} must set contentProtected", w["label"]);
        }
    }
}
