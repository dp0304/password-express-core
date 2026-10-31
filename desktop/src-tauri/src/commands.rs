// SPDX-License-Identifier: Apache-2.0
//! Tauri commands: thin, input-validating wrappers around [`AppCore`]. Every command
//! returns metadata only, except `reveal_secret` (fresh re-authentication required) and
//! `create_vault` (one-time recovery key). File contents (CSV, exports, recovery kit) are
//! read and written in Rust via native dialogs; the WebView never sees them.

use std::sync::Arc;

use aipass_crypto::SecretString;
use aipass_hostconfig::{Host, Scope};
use aipass_storage::CapabilityReport;
use aipass_sync::{ConflictInfo, DeviceInfo, ItemDetail, ItemSummary, MigrationReport, RevokeResult, SyncReport};
use aipass_types::ids::{ApprovalRequestId, ConnectionId, DeviceId, EntryId, GrantId, ProjectId, ResourceId};
use aipass_types::models::{AccessSpec, AllowedProjects, Resource, RevocationLevel};
use aipass_types::relay::ControlAction;
use aipass_types::vault::PasswordRules;
use aipass_vault::import::ImportReport;
use serde_json::Value;
use tauri::{AppHandle, State};
use tauri_plugin_dialog::DialogExt;

use crate::cloud::LicenseStatus;
use crate::core::{AppCore, AppStatus, CreateVaultInput, CreateVaultOutput, GeneratedPassword, ItemForm, StorageInput, TotpView};
use crate::core_ai::{HostPlanInput, PlanView, ResourceForm};
use crate::error::{UiError, UiResult};
use crate::nm_install::Browser;
use crate::settings::Settings;

type Core<'a> = State<'a, Arc<AppCore>>;

fn parse<T: std::str::FromStr>(s: &str) -> UiResult<T> {
    s.parse().map_err(|_| UiError::invalid("标识格式不正确", "Malformed identifier"))
}

async fn pick_open(app: &AppHandle, name: &str, exts: &[&str]) -> UiResult<Option<std::path::PathBuf>> {
    let mut d = app.dialog().file();
    if !exts.is_empty() {
        d = d.add_filter(name, exts);
    }
    let picked = tauri::async_runtime::spawn_blocking(move || d.blocking_pick_file())
        .await
        .map_err(|_| UiError::internal("dialog"))?;
    Ok(picked.and_then(|p| p.into_path().ok()))
}

async fn pick_save(app: &AppHandle, default_name: &str) -> UiResult<Option<std::path::PathBuf>> {
    let d = app.dialog().file().set_file_name(default_name);
    let picked = tauri::async_runtime::spawn_blocking(move || d.blocking_save_file())
        .await
        .map_err(|_| UiError::internal("dialog"))?;
    Ok(picked.and_then(|p| p.into_path().ok()))
}

// ---------------- lifecycle ----------------

#[tauri::command(rename_all = "snake_case")]
pub async fn app_status(core: Core<'_>) -> UiResult<AppStatus> {
    Ok(core.status().await)
}

#[tauri::command(rename_all = "snake_case")]
pub async fn test_storage(core: Core<'_>, storage: StorageInput) -> UiResult<CapabilityReport> {
    core.test_storage(storage).await
}

#[tauri::command(rename_all = "snake_case")]
pub async fn create_vault(core: Core<'_>, input: CreateVaultInput) -> UiResult<CreateVaultOutput> {
    core.create_vault(input).await
}

#[tauri::command(rename_all = "snake_case")]
pub async fn unlock(core: Core<'_>, password: SecretString) -> UiResult<()> {
    core.unlock(password).await
}

#[tauri::command(rename_all = "snake_case")]
pub async fn lock(core: Core<'_>) -> UiResult<()> {
    core.lock_app().await;
    Ok(())
}

#[tauri::command(rename_all = "snake_case")]
pub fn reauth(core: Core<'_>, password: SecretString) -> UiResult<()> {
    core.reauth(password)
}

#[tauri::command(rename_all = "snake_case")]
pub fn touch(core: Core<'_>) {
    if core.is_unlocked() {
        core.touch();
    }
}

#[tauri::command(rename_all = "snake_case")]
pub fn get_settings(core: Core<'_>) -> Settings {
    core.settings()
}

#[tauri::command(rename_all = "snake_case")]
pub async fn update_settings(core: Core<'_>, settings: Settings) -> UiResult<Settings> {
    let old_relay = core.settings().relay_url;
    let s = core.update_settings(settings)?;
    if s.relay_url != old_relay && core.is_unlocked() {
        core.restart_relay().await?;
    }
    Ok(s)
}

#[tauri::command(rename_all = "snake_case")]
pub fn finish_onboarding(core: Core<'_>) -> UiResult<()> {
    core.mutate_settings(|s| s.onboarding_done = true)
}

// ---------------- recovery ----------------

#[tauri::command(rename_all = "snake_case")]
pub fn verify_recovery_key(core: Core<'_>, key: String) -> UiResult<bool> {
    core.verify_recovery_key(&key)
}

#[tauri::command(rename_all = "snake_case")]
pub async fn save_recovery_kit(app: AppHandle, core: Core<'_>) -> UiResult<Option<String>> {
    core.require_unlocked()?;
    let Some(path) = pick_save(&app, "AI通行证-恢复包.txt").await? else { return Ok(None) };
    core.save_recovery_kit_to(&path)?;
    Ok(Some(path.display().to_string()))
}

#[tauri::command(rename_all = "snake_case")]
pub async fn replace_recovery_key(core: Core<'_>) -> UiResult<String> {
    core.replace_recovery_key().await
}

// ---------------- items ----------------

#[tauri::command(rename_all = "snake_case")]
pub fn list_items(core: Core<'_>, query: Option<String>, project_id: Option<String>) -> UiResult<Vec<ItemSummary>> {
    let p = project_id.filter(|s| !s.is_empty()).map(|s| parse::<ProjectId>(&s)).transpose()?;
    core.list_items(query, p)
}

#[tauri::command(rename_all = "snake_case")]
pub fn get_item(core: Core<'_>, entry_id: String) -> UiResult<ItemDetail> {
    core.get_item(&parse(&entry_id)?)
}

#[tauri::command(rename_all = "snake_case")]
pub async fn save_item(core: Core<'_>, form: ItemForm) -> UiResult<String> {
    Ok(core.save_item(form).await?.to_string())
}

#[tauri::command(rename_all = "snake_case")]
pub async fn delete_item(core: Core<'_>, entry_id: String) -> UiResult<()> {
    core.delete_item(&parse(&entry_id)?).await
}

/// Explicit "查看原始密码": fresh re-authentication required; the UI hides it after 30 s.
#[tauri::command(rename_all = "snake_case")]
pub fn reveal_secret(core: Core<'_>, entry_id: String, field: String) -> UiResult<String> {
    Ok(core.reveal_secret(&parse::<EntryId>(&entry_id)?, &field)?.expose().to_owned())
}

#[tauri::command(rename_all = "snake_case")]
pub fn copy_secret(core: Core<'_>, entry_id: String, field: String) -> UiResult<u64> {
    core.copy_secret(&parse(&entry_id)?, &field)
}

#[tauri::command(rename_all = "snake_case")]
pub fn totp_now(core: Core<'_>, entry_id: String) -> UiResult<TotpView> {
    core.totp_now(&parse(&entry_id)?)
}

#[tauri::command(rename_all = "snake_case")]
pub fn generate_password(core: Core<'_>, rules: PasswordRules) -> UiResult<GeneratedPassword> {
    core.generate_password(rules)
}

#[tauri::command(rename_all = "snake_case")]
pub fn copy_generated(core: Core<'_>, handle: String) -> UiResult<u64> {
    core.copy_generated(&handle)
}

#[tauri::command(rename_all = "snake_case")]
pub async fn import_csv(app: AppHandle, core: Core<'_>, format: String) -> UiResult<Option<ImportReport>> {
    core.require_unlocked()?;
    let Some(path) = pick_open(&app, "CSV", &["csv"]).await? else { return Ok(None) };
    Ok(Some(core.import_csv_file(&format, &path).await?))
}

#[tauri::command(rename_all = "snake_case")]
pub async fn import_encrypted(app: AppHandle, core: Core<'_>, password: SecretString) -> UiResult<Option<ImportReport>> {
    core.require_unlocked()?;
    let Some(path) = pick_open(&app, "AI Pass export", &["aipassx"]).await? else { return Ok(None) };
    Ok(Some(core.import_encrypted_file(&path, &password).await?))
}

#[tauri::command(rename_all = "snake_case")]
pub async fn export_encrypted(app: AppHandle, core: Core<'_>, password: SecretString) -> UiResult<Option<String>> {
    core.require_reauth()?;
    let Some(path) = pick_save(&app, "AI通行证-导出.aipassx").await? else { return Ok(None) };
    core.export_encrypted_to(&path, &password)?;
    Ok(Some(path.display().to_string()))
}

#[tauri::command(rename_all = "snake_case")]
pub async fn export_csv(app: AppHandle, core: Core<'_>) -> UiResult<Option<String>> {
    core.require_reauth()?;
    let Some(path) = pick_save(&app, "AI通行证-明文导出.csv").await? else { return Ok(None) };
    core.export_csv_to(&path)?;
    Ok(Some(path.display().to_string()))
}

// ---------------- sync / devices / storage ----------------

#[tauri::command(rename_all = "snake_case")]
pub async fn sync_now(core: Core<'_>) -> UiResult<SyncReport> {
    core.sync_now().await
}

#[tauri::command(rename_all = "snake_case")]
pub async fn list_conflicts(core: Core<'_>) -> UiResult<Vec<ConflictInfo>> {
    core.conflicts().await
}

#[tauri::command(rename_all = "snake_case")]
pub async fn resolve_conflict(core: Core<'_>, entry_id: String, keep_version: u64) -> UiResult<()> {
    core.resolve_conflict(&parse(&entry_id)?, keep_version).await
}

#[tauri::command(rename_all = "snake_case")]
pub fn list_devices(core: Core<'_>) -> UiResult<Vec<DeviceInfo>> {
    core.devices()
}

#[tauri::command(rename_all = "snake_case")]
pub async fn revoke_device(core: Core<'_>, device_id: String) -> UiResult<RevokeResult> {
    core.revoke_device(&parse::<DeviceId>(&device_id)?).await
}

#[tauri::command(rename_all = "snake_case")]
pub async fn migrate_storage(core: Core<'_>, storage: StorageInput) -> UiResult<MigrationReport> {
    core.migrate_storage(storage).await
}

// ---------------- AI side ----------------

#[tauri::command(rename_all = "snake_case")]
pub async fn node_status(core: Core<'_>) -> UiResult<Value> {
    core.node_status().await
}

#[tauri::command(rename_all = "snake_case")]
pub async fn list_connections(core: Core<'_>) -> UiResult<Value> {
    core.list_connections().await
}

#[tauri::command(rename_all = "snake_case")]
pub async fn approve_connection(core: Core<'_>, connection_id: String, allowed_projects: AllowedProjects, password: Option<SecretString>) -> UiResult<Value> {
    core.approve_connection(&parse::<ConnectionId>(&connection_id)?, allowed_projects, password.as_ref()).await
}

#[tauri::command(rename_all = "snake_case")]
pub async fn deny_connection(core: Core<'_>, connection_id: String) -> UiResult<Value> {
    core.deny_connection(&parse::<ConnectionId>(&connection_id)?).await
}

#[tauri::command(rename_all = "snake_case")]
pub async fn control_connection(core: Core<'_>, connection_id: String, action: ControlAction) -> UiResult<Value> {
    core.control_connection(&parse::<ConnectionId>(&connection_id)?, action).await
}

#[tauri::command(rename_all = "snake_case")]
pub fn host_detect(core: Core<'_>) -> UiResult<Value> {
    core.host_detect()
}

#[tauri::command(rename_all = "snake_case")]
pub async fn host_plan(core: Core<'_>, input: HostPlanInput) -> UiResult<PlanView> {
    core.host_plan(input).await
}

#[tauri::command(rename_all = "snake_case")]
pub fn host_apply(core: Core<'_>, plan_id: String) -> UiResult<Value> {
    core.host_apply(&plan_id)
}

#[tauri::command(rename_all = "snake_case")]
pub async fn host_cancel(core: Core<'_>, plan_id: String) -> UiResult<()> {
    core.host_cancel(&plan_id).await
}

#[tauri::command(rename_all = "snake_case")]
pub fn host_remove(core: Core<'_>, host: Host, scope: Scope, project_dir: Option<String>) -> UiResult<Value> {
    core.host_remove(host, scope, project_dir)
}

#[tauri::command(rename_all = "snake_case")]
pub fn remote_instructions(core: Core<'_>, host: Host) -> UiResult<Value> {
    core.remote_instructions(host)
}

#[tauri::command(rename_all = "snake_case")]
pub async fn list_projects(core: Core<'_>) -> UiResult<Value> {
    core.list_projects().await
}

#[tauri::command(rename_all = "snake_case")]
pub async fn create_project(core: Core<'_>, name: String) -> UiResult<Value> {
    core.create_project(&name).await
}

#[tauri::command(rename_all = "snake_case")]
pub async fn list_resources(core: Core<'_>) -> UiResult<Value> {
    core.list_resources().await
}

#[tauri::command(rename_all = "snake_case")]
pub async fn create_resource(core: Core<'_>, form: ResourceForm) -> UiResult<Resource> {
    core.create_resource(form).await
}

#[tauri::command(rename_all = "snake_case")]
pub async fn delete_resource(core: Core<'_>, resource_id: String) -> UiResult<()> {
    core.delete_resource(&parse::<ResourceId>(&resource_id)?).await
}

#[tauri::command(rename_all = "snake_case")]
pub async fn list_approvals(core: Core<'_>) -> UiResult<Value> {
    core.list_approvals().await
}

#[tauri::command(rename_all = "snake_case")]
pub async fn approve_request(core: Core<'_>, approval_request_id: String, request_digest: String, narrowed: Option<AccessSpec>, password: Option<SecretString>) -> UiResult<Value> {
    core.approve(&parse::<ApprovalRequestId>(&approval_request_id)?, &request_digest, narrowed, password.as_ref()).await
}

#[tauri::command(rename_all = "snake_case")]
pub async fn deny_request(core: Core<'_>, approval_request_id: String, request_digest: String) -> UiResult<Value> {
    core.deny(&parse::<ApprovalRequestId>(&approval_request_id)?, &request_digest).await
}

#[tauri::command(rename_all = "snake_case")]
pub async fn list_operations(core: Core<'_>, limit: Option<u64>) -> UiResult<Value> {
    core.list_operations(limit.unwrap_or(100)).await
}

#[tauri::command(rename_all = "snake_case")]
pub async fn list_grants(core: Core<'_>) -> UiResult<Value> {
    core.list_grants().await
}

#[tauri::command(rename_all = "snake_case")]
pub async fn revoke_grant(core: Core<'_>, grant_id: String, level: RevocationLevel) -> UiResult<Value> {
    core.revoke_grant(&parse::<GrantId>(&grant_id)?, level).await
}

#[tauri::command(rename_all = "snake_case")]
pub async fn audit_events(core: Core<'_>, after: Option<u64>, limit: Option<u64>) -> UiResult<Value> {
    core.audit_events(after.unwrap_or(0), limit.unwrap_or(200)).await
}

#[tauri::command(rename_all = "snake_case")]
pub async fn verify_audit(core: Core<'_>) -> UiResult<Value> {
    core.verify_audit().await
}

#[tauri::command(rename_all = "snake_case")]
pub async fn activity_summary(core: Core<'_>) -> UiResult<Value> {
    core.activity_summary().await
}

// ---------------- pairing ----------------

#[tauri::command(rename_all = "snake_case")]
pub async fn pair_scan(core: Core<'_>, uri: String) -> UiResult<Value> {
    core.inner().clone().pair_scan(&uri).await
}

#[tauri::command(rename_all = "snake_case")]
pub async fn pair_confirm(core: Core<'_>, code: Option<String>, share_storage_secret: bool) -> UiResult<Value> {
    core.pair_confirm(code, share_storage_secret).await
}

#[tauri::command(rename_all = "snake_case")]
pub async fn pair_cancel(core: Core<'_>) -> UiResult<()> {
    core.pair_cancel().await;
    Ok(())
}

#[tauri::command(rename_all = "snake_case")]
pub async fn join_begin(core: Core<'_>, device_name: String, relay_url: String, unlock_password: SecretString) -> UiResult<Value> {
    core.inner().clone().join_begin(&device_name, &relay_url, unlock_password).await
}

// ---------------- cloud & browser ----------------

#[tauri::command(rename_all = "snake_case")]
pub async fn cloud_login(core: Core<'_>, email: String, password: SecretString) -> UiResult<Value> {
    core.cloud_login(&email, password).await
}

#[tauri::command(rename_all = "snake_case")]
pub async fn cloud_logout(core: Core<'_>) -> UiResult<()> {
    core.cloud_logout().await
}

#[tauri::command(rename_all = "snake_case")]
pub async fn cloud_status(core: Core<'_>) -> UiResult<Value> {
    core.cloud_status().await
}

#[tauri::command(rename_all = "snake_case")]
pub async fn activate_license(core: Core<'_>) -> UiResult<LicenseStatus> {
    core.activate_license().await
}

#[tauri::command(rename_all = "snake_case")]
pub fn install_native_host(core: Core<'_>, browser: Browser, extension_id: String) -> UiResult<String> {
    core.install_native_host(browser, &extension_id)
}

#[tauri::command(rename_all = "snake_case")]
pub async fn cloud_link_node(core: Core<'_>) -> UiResult<Value> {
    core.cloud_link_node().await
}

/// Start the remote-MCP tunnel (the official gateway sees request/result content).
#[tauri::command(rename_all = "snake_case")]
pub async fn tunnel_start(core: Core<'_>) -> UiResult<()> {
    let mut g = core.tunnel.lock().await;
    if g.is_none() {
        *g = Some(core.start_tunnel().await?);
    }
    Ok(())
}

#[tauri::command(rename_all = "snake_case")]
pub async fn tunnel_stop(core: Core<'_>) -> UiResult<()> {
    if let Some(t) = core.tunnel.lock().await.take() {
        t.stop().await;
    }
    Ok(())
}

#[tauri::command(rename_all = "snake_case")]
pub async fn tunnel_status(core: Core<'_>) -> UiResult<Value> {
    let g = core.tunnel.lock().await;
    Ok(match g.as_ref() {
        Some(t) => serde_json::json!({"running": true, "state": format!("{:?}", t.handle.sender().state()).to_lowercase()}),
        None => serde_json::json!({"running": false}),
    })
}
