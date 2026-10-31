// SPDX-License-Identifier: Apache-2.0
// Typed wrappers around the Rust commands. Only metadata comes back, except
// `revealSecret` (after re-authentication) and the one-time recovery key.

import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";

export interface Localized { zh: string; en: string }
export interface UiError { code: string; message: Localized }

export function isUiError(e: unknown): e is UiError {
  return typeof e === "object" && e !== null && "code" in e && "message" in e;
}

export async function call<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  try {
    return await invoke<T>(cmd, args);
  } catch (e) {
    if (isUiError(e)) throw e;
    throw { code: "INTERNAL", message: { zh: "桌面核心无响应", en: "The desktop core did not respond" } } as UiError;
  }
}

export function onEvent<T>(name: string, cb: (payload: T) => void): Promise<UnlistenFn> {
  return listen<T>(name, (e) => cb(e.payload));
}

export interface CoreStatus {
  vault_id?: string; unlocked: boolean; device_id?: string; device_name?: string; storage_kind?: string;
  last_sync_at?: string; pending_changes: number; /** null while the vault is locked (unknown until unlock) */ conflicts: number | null; recovery_verified: boolean;
  rollback_detected: boolean; revoked: boolean; last_error?: string;
}
export interface AppStatus {
  has_vault: boolean; unlocked: boolean; core: CoreStatus; node_running: boolean; executor_id?: string;
  onboarding_done: boolean; lang: string; version: string; home: string; cloud_email?: string; relay_url?: string;
}
export type StorageKind = "local" | "official" | "s3" | "selfhost";
export interface StorageInput {
  kind: StorageKind; path?: string; endpoint?: string; region?: string; bucket?: string; prefix?: string;
  path_style?: boolean; access_key_id?: string; secret?: string; base_url?: string;
}
export interface CapabilityReport {
  read: boolean; write: boolean; list: boolean; conditional_create: boolean; conditional_update: boolean;
  delete: boolean; roundtrip: boolean; verdict: "sync_capable" | "backup_only"; details: string[];
}
export interface ItemSummary {
  entry_id: string; kind: string; title: string; username?: string; primary_url?: string; project_id?: string;
  lifecycle: string; has_conflict: boolean; pending_sync: boolean; tags: string[]; updated_at: string;
}
export interface ItemDetail {
  summary: ItemSummary; urls: string[]; notes?: string; has_secret: boolean; secret_masked?: string; has_totp: boolean;
  fields: { name: string; value?: string; sensitive: boolean }[]; version?: number; conflict_versions: number[]; created_at: string;
}
export interface PasswordRules {
  length: number; lower: boolean; upper: boolean; digits: boolean; symbols: boolean; symbol_set?: string;
  exclude_ambiguous: boolean; require_each_class: boolean;
}
export interface ItemForm {
  entry_id?: string; kind: string; title: string; username?: string; secret?: string; secret_ref?: string;
  clear_secret?: boolean; urls: string[]; notes?: string; totp?: string; clear_totp?: boolean; project_id?: string; tags: string[];
}
export interface Generated { handle: string; length: number; masked: string }
export interface ImportReport { imported: number; duplicates: unknown[]; skipped: unknown[]; warnings?: unknown[] }
export interface ConflictInfo {
  entry_id: string; title: string; current_version: number; conflict_versions: number[];
  versions: { version: number; is_current: boolean; author_device_id: string; author_name?: string; created_at: string; username?: string; secret_differs: boolean }[];
}
export interface DeviceInfo {
  device_id: string; name: string; platform: string; role: string; status: string; is_this_device: boolean; is_recovery_key: boolean; updated_at: string; key_epoch: number;
}
export interface Limits { max_rows_per_operation: number; max_rows_per_grant: number; max_requests_per_grant: number; max_result_bytes: number }
export interface GrantScope {
  operations: string[]; postgres?: { views: Record<string, string[]> }; github?: { repos: string[] }; http_api?: { operations: string[] };
}
export interface AccessSpec { operations: string[]; scope: GrantScope; limits: Limits; duration_seconds: number; mode: string }
export interface ApprovalRequest {
  approval_request_id: string; kind: string;
  connection: { connection_id: string; display_name: string; host_type: string; verified: boolean };
  resource: { resource_id: string; alias: string; service: string; environment: string };
  summary: Localized; requested: AccessSpec; excluded_fields?: Record<string, string[]>;
  executor: { executor_id: string; name: string; protection_level: string };
  recipients: { connection_id: string; display_name: string }[]; status: string; created_at: string; expires_at: string; operation_id?: string;
  parameters_digest?: string;
  /** Digest of exactly this request (added by the desktop core); passed back with approve/deny. */
  request_digest: string;
}
export interface Settings {
  format: number; lang: string; executor_id?: string; relay_url?: string; cloud_url: string; cloud_email?: string;
  license_token?: string; license_public_key?: string; allowed_extension_origins: string[]; clipboard_clear_secs: number;
  auto_lock_secs: number; onboarding_done: boolean;
}
export interface PlanView { plan_id: string; host: string; scope: string; path: string; action: string; unified_diff: string; connection_id: string }

export const api = {
  status: () => call<AppStatus>("app_status"),
  testStorage: (storage: StorageInput) => call<CapabilityReport>("test_storage", { storage }),
  createVault: (input: { device_name: string; unlock_password: string; storage: StorageInput }) =>
    call<{ vault_id: string; device_id: string; recovery_key: string }>("create_vault", { input }),
  unlock: (password: string) => call<void>("unlock", { password }),
  lock: () => call<void>("lock"),
  reauth: (password: string) => call<void>("reauth", { password }),
  touch: () => call<void>("touch"),
  getSettings: () => call<Settings>("get_settings"),
  updateSettings: (settings: Settings) => call<Settings>("update_settings", { settings }),
  finishOnboarding: () => call<void>("finish_onboarding"),
  verifyRecoveryKey: (key: string) => call<boolean>("verify_recovery_key", { key }),
  saveRecoveryKit: () => call<string | null>("save_recovery_kit"),
  replaceRecoveryKey: () => call<string>("replace_recovery_key"),
  listItems: (query?: string, project_id?: string) => call<ItemSummary[]>("list_items", { query, project_id }),
  getItem: (entry_id: string) => call<ItemDetail>("get_item", { entry_id }),
  saveItem: (form: ItemForm) => call<string>("save_item", { form }),
  deleteItem: (entry_id: string) => call<void>("delete_item", { entry_id }),
  revealSecret: (entry_id: string, field: string) => call<string>("reveal_secret", { entry_id, field }),
  copySecret: (entry_id: string, field: string) => call<number>("copy_secret", { entry_id, field }),
  totpNow: (entry_id: string) => call<{ code: string; remaining_seconds: number; period: number }>("totp_now", { entry_id }),
  generatePassword: (rules: PasswordRules) => call<Generated>("generate_password", { rules }),
  copyGenerated: (handle: string) => call<number>("copy_generated", { handle }),
  importCsv: (format: string) => call<ImportReport | null>("import_csv", { format }),
  importEncrypted: (password: string) => call<ImportReport | null>("import_encrypted", { password }),
  exportEncrypted: (password: string) => call<string | null>("export_encrypted", { password }),
  exportCsv: () => call<string | null>("export_csv"),
  syncNow: () => call<{ status: string; pulled: number; pushed: number; conflicts: number; message?: Localized }>("sync_now"),
  conflicts: () => call<ConflictInfo[]>("list_conflicts"),
  resolveConflict: (entry_id: string, keep_version: number) => call<void>("resolve_conflict", { entry_id, keep_version }),
  devices: () => call<DeviceInfo[]>("list_devices"),
  revokeDevice: (device_id: string) => call<{ note: Localized }>("revoke_device", { device_id }),
  migrateStorage: (storage: StorageInput) => call<{ objects_copied: number; entries_verified: number }>("migrate_storage", { storage }),
  nodeStatus: () => call<any>("node_status"),
  connections: () => call<any[]>("list_connections"),
  approveConnection: (connection_id: string, allowed_projects: string[] | ["*"], password: string) => call<any>("approve_connection", { connection_id, allowed_projects, password }),
  denyConnection: (connection_id: string) => call<any>("deny_connection", { connection_id }),
  controlConnection: (connection_id: string, action: "pause" | "resume" | "remove" | "revoke_all") => call<any>("control_connection", { connection_id, action }),
  hostDetect: () => call<any[]>("host_detect"),
  hostPlan: (input: { host: string; scope: string; project_dir?: string; allowed_projects: string[] }) => call<PlanView>("host_plan", { input }),
  hostApply: (plan_id: string) => call<any>("host_apply", { plan_id }),
  hostCancel: (plan_id: string) => call<void>("host_cancel", { plan_id }),
  hostRemove: (host: string, scope: string, project_dir?: string) => call<any>("host_remove", { host, scope, project_dir }),
  remoteInstructions: (host: string) => call<any>("remote_instructions", { host }),
  projects: () => call<{ projects: { project_id: string; name: string }[] }>("list_projects"),
  createProject: (name: string) => call<any>("create_project", { name }),
  resources: () => call<{ resources: any[] }>("list_resources"),
  createResource: (form: any) => call<any>("create_resource", { form }),
  deleteResource: (resource_id: string) => call<void>("delete_resource", { resource_id }),
  approvals: () => call<{ approvals: ApprovalRequest[] }>("list_approvals"),
  // Every approval carries the unlock password; the core verifies it for this one decision (CLI-01).
  // request_digest: the `request_digest` of the request shown (from list_approvals).
  approve: (approval_request_id: string, request_digest: string, password: string, narrowed?: AccessSpec) => call<any>("approve_request", { approval_request_id, request_digest, narrowed, password }),
  deny: (approval_request_id: string, request_digest: string) => call<any>("deny_request", { approval_request_id, request_digest }),
  operations: () => call<{ operations: any[] }>("list_operations", { limit: 100 }),
  grants: () => call<{ grants: any[] }>("list_grants"),
  revokeGrant: (grant_id: string, level: "stop_access" | "end_sessions" | "revoke_upstream") => call<any>("revoke_grant", { grant_id, level }),
  audit: () => call<{ events: any[] }>("audit_events", { after: 0, limit: 200 }),
  verifyAudit: () => call<any>("verify_audit"),
  summary: () => call<any>("activity_summary"),
  pairScan: (uri: string) => call<{ name: string; role: string }>("pair_scan", { uri }),
  pairConfirm: (code: string | undefined, share_storage_secret: boolean) => call<any>("pair_confirm", { code, share_storage_secret }),
  pairCancel: () => call<void>("pair_cancel"),
  joinBegin: (device_name: string, relay_url: string, unlock_password: string) =>
    call<{ qr_payload: string; qr_svg: string; expires_at: number }>("join_begin", { device_name, relay_url, unlock_password }),
  cloudLogin: (email: string, password: string) => call<any>("cloud_login", { email, password }),
  cloudLogout: () => call<void>("cloud_logout"),
  cloudStatus: () => call<any>("cloud_status"),
  activateLicense: () => call<any>("activate_license"),
  cloudLinkNode: () => call<any>("cloud_link_node"),
  tunnelStart: () => call<void>("tunnel_start"),
  tunnelStop: () => call<void>("tunnel_stop"),
  tunnelStatus: () => call<{ running: boolean; state?: string }>("tunnel_status"),
  installNativeHost: (browser: string, extension_id: string) => call<string>("install_native_host", { browser, extension_id }),
};
