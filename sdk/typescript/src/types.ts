// SPDX-License-Identifier: Apache-2.0
/**
 * Wire types for the connection-authenticated ("C") broker endpoints (CONTRACTS §6.1, §6.3).
 * Field names are snake_case exactly as on the wire; unknown extra fields are preserved.
 */

export type HostType = "codex" | "claude_code" | "cursor" | "chatgpt" | "claude_connector" | "sdk" | "custom";
export type ConnectionTransport = "stdio" | "http" | "sdk" | "remote_gateway";

/** Operation status as shown by the API (`awaiting_approval` is shown as `approval_required`). */
export type OperationStatus =
  | "received"
  | "policy_checked"
  | "approval_required"
  | "authorized"
  | "running"
  | "succeeded"
  | "failed"
  | "unknown"
  | "denied"
  | "expired"
  | "cancelled";

/** Terminal operation statuses (CONTRACTS §6.2). */
export const TERMINAL_OPERATION_STATUSES: readonly OperationStatus[] = Object.freeze([
  "succeeded",
  "failed",
  "unknown",
  "denied",
  "expired",
  "cancelled",
]);

export function isTerminalOperationStatus(status: string | undefined | null): boolean {
  return typeof status === "string" && (TERMINAL_OPERATION_STATUSES as readonly string[]).includes(status);
}

export type SideEffects = "none" | "possible" | "applied";

export interface ErrorBody {
  code: string;
  message: string;
  details?: Record<string, unknown>;
  request_id?: string;
}

export interface OperationResult {
  data: unknown;
  rows?: number | null;
  truncated: boolean;
  restricted: boolean;
  restricted_fields: string[];
  [extra: string]: unknown;
}

export interface OperationResponse {
  status: OperationStatus | (string & {});
  operation_id: string;
  approval_request_id?: string | null;
  expires_in_seconds?: number | null;
  message?: string | null;
  result?: OperationResult | null;
  error?: ErrorBody | null;
  [extra: string]: unknown;
}

export interface CancelResponse {
  operation_id: string;
  status: OperationStatus | (string & {});
  cancelled: boolean;
  side_effects: SideEffects | (string & {});
  message: string;
  [extra: string]: unknown;
}

export interface OperationSpecView {
  name: string;
  description: string;
  side_effect: "read" | "write" | "irreversible" | (string & {});
  parameters_schema: Record<string, unknown>;
  [extra: string]: unknown;
}

export type ResourceStatus = "available" | "needs_login" | "sync_conflict" | "executor_offline" | "disabled";

export interface ResourceView {
  resource_id: string;
  alias: string;
  service: string;
  project_id: string;
  environment: "test" | "production" | (string & {});
  operations: OperationSpecView[];
  status: ResourceStatus | (string & {});
  protection_level: "isolated" | "compatible" | (string & {});
  executor_status: "online" | "offline" | (string & {});
  [extra: string]: unknown;
}

export interface ResourceList {
  resources: ResourceView[];
  [extra: string]: unknown;
}

export interface ListResourcesParams {
  project_id?: string;
  service?: string;
}

export interface OperationRequest {
  resource_id: string;
  operation: string;
  parameters?: Record<string, unknown>;
  /** 1..128 chars. Strongly recommended: pass your own stable key so you can safely retry. */
  idempotency_key?: string;
  task_id?: string;
}

export interface GrantScope {
  operations: string[];
  postgres?: { views: Record<string, string[]> };
  github?: { repos: string[] };
  http_api?: { operations: string[] };
  [extra: string]: unknown;
}

export interface Limits {
  max_rows_per_operation: number;
  max_rows_per_grant: number;
  max_requests_per_grant: number;
  max_result_bytes: number;
}

export interface AccessRequest {
  resource_id: string;
  operations: string[];
  scope?: GrantScope;
  /** All four limits are required when given (the broker has no per-field defaults). */
  limits?: Limits;
  duration_seconds?: number;
  reason?: string;
}

export type AccessRequestStatus = "pending" | "approval_required" | "approved" | "denied" | "expired" | "cancelled";

export const TERMINAL_ACCESS_STATUSES: readonly AccessRequestStatus[] = Object.freeze(["approved", "denied", "expired", "cancelled"]);

export function isTerminalAccessStatus(status: string | undefined | null): boolean {
  return typeof status === "string" && (TERMINAL_ACCESS_STATUSES as readonly string[]).includes(status);
}

export interface AccessRequestResponse {
  approval_request_id: string;
  status: AccessRequestStatus | (string & {});
  grant_id?: string | null;
  [extra: string]: unknown;
}

export interface ReleaseResponse {
  grant_id: string;
  status: "released" | (string & {});
  [extra: string]: unknown;
}

export interface HealthResponse {
  status: string;
  version?: string;
  executor_online?: boolean;
  protection_level?: string;
  [extra: string]: unknown;
}

export interface PairRequestBody {
  host_type: HostType;
  display_name: string;
  transport: ConnectionTransport;
  public_key: string;
}

export interface PairStartResponse {
  pairing_request_id: string;
  connection_id: string;
  pairing_code: string;
  expires_at: string;
  [extra: string]: unknown;
}

export type PairStatus = "pending" | "approved" | "denied" | "expired";

export interface PairStatusResponse {
  status: PairStatus | (string & {});
  connection_id: string;
  [extra: string]: unknown;
}

export type Locale = "zh-CN" | "en";
