// SPDX-License-Identifier: Apache-2.0
/**
 * Typed errors. Every broker error body is
 * `{"error":{"code","message","details","request_id"}}` (CONTRACTS §1.5); each code maps to a
 * subclass of {@link AIPassError}. Errors never carry request headers, bodies or credentials.
 */
import type { OperationResponse } from "./types.js";

/** Error codes defined by CONTRACTS §1.5. */
export const ERROR_CODES = [
  "IDENTITY_UNVERIFIED",
  "UNAUTHENTICATED",
  "FORBIDDEN",
  "CONNECTION_PAUSED",
  "APPROVAL_REQUIRED",
  "APPROVAL_DENIED",
  "APPROVAL_EXPIRED",
  "GRANT_EXPIRED",
  "GRANT_REVOKED",
  "BUDGET_EXHAUSTED",
  "SCOPE_DENIED",
  "EXECUTOR_OFFLINE",
  "CONTROL_CHANNEL_LOST",
  "SECRET_UNAVAILABLE",
  "SYNC_CONFLICT",
  "PRECONDITION_FAILED",
  "ROLLBACK_DETECTED",
  "INTEGRITY_FAILED",
  "INTERACTIVE_AUTH_REQUIRED",
  "RESULT_RESTRICTED",
  "UPSTREAM_OUTCOME_UNKNOWN",
  "UPSTREAM_ERROR",
  "IDEMPOTENCY_CONFLICT",
  "RATE_LIMITED",
  "NOT_FOUND",
  "INVALID_REQUEST",
  "NOT_SUPPORTED",
  "PAYMENT_REQUIRED",
  "QUOTA_EXCEEDED",
  "INTERNAL",
] as const;

/** Codes raised locally by the SDK (never sent by the broker). */
export const SDK_ERROR_CODES = ["NETWORK_ERROR", "TIMEOUT", "ABORTED", "INVALID_RESPONSE", "CONFIG_ERROR", "CANCELLED"] as const;

export type ErrorCode = (typeof ERROR_CODES)[number] | (typeof SDK_ERROR_CODES)[number];

export interface AIPassErrorOptions {
  httpStatus?: number;
  requestId?: string;
  details?: Record<string, unknown>;
  cause?: unknown;
}

/** Base class for every error thrown by the SDK. */
export class AIPassError extends Error {
  /** Stable error code (CONTRACTS §1.5, or an SDK-local code). */
  readonly code: string;
  /** HTTP status of the broker response, when there was one. */
  readonly httpStatus: number | undefined;
  /** Broker request id (`req_…`), when known — quote it in bug reports. */
  readonly requestId: string | undefined;
  /** Structured details from the broker (never secrets). */
  readonly details: Record<string, unknown>;

  constructor(code: string, message: string, options: AIPassErrorOptions = {}) {
    super(message, options.cause === undefined ? undefined : { cause: options.cause });
    this.name = new.target.name;
    this.code = code;
    this.httpStatus = options.httpStatus;
    this.requestId = options.requestId;
    this.details = options.details ?? {};
  }

  /** JSON-safe representation (what tool helpers return to a model). */
  toJSON(): { code: string; message: string; http_status?: number; request_id?: string; details?: Record<string, unknown> } {
    const out: { code: string; message: string; http_status?: number; request_id?: string; details?: Record<string, unknown> } = {
      code: this.code,
      message: this.message,
    };
    if (this.httpStatus !== undefined) out.http_status = this.httpStatus;
    if (this.requestId !== undefined) out.request_id = this.requestId;
    if (Object.keys(this.details).length > 0) out.details = this.details;
    return out;
  }

  override toString(): string {
    const rid = this.requestId ? ` (request_id=${this.requestId})` : "";
    return `${this.name} [${this.code}]: ${this.message}${rid}`;
  }
}

// ---- broker error codes ---------------------------------------------------------------

export class IdentityUnverifiedError extends AIPassError {}
export class UnauthenticatedError extends AIPassError {}
export class ForbiddenError extends AIPassError {}
export class ConnectionPausedError extends AIPassError {}

/**
 * Raised only when the caller opted in (`raiseOnPending`). The API itself reports
 * `approval_required` as a normal status, never as an error.
 */
export class ApprovalRequiredError extends AIPassError {
  /** The operation that is waiting for approval, when known. */
  readonly operation: OperationResponse | undefined;
  readonly operationId: string | undefined;
  readonly approvalRequestId: string | undefined;

  constructor(code: string, message: string, options: AIPassErrorOptions & { operation?: OperationResponse; approvalRequestId?: string } = {}) {
    super(code, message, options);
    this.operation = options.operation;
    this.operationId = options.operation?.operation_id;
    this.approvalRequestId = options.approvalRequestId ?? options.operation?.approval_request_id ?? undefined;
  }
}

export class ApprovalDeniedError extends AIPassError {}
export class ApprovalExpiredError extends AIPassError {}
export class GrantExpiredError extends AIPassError {}
export class GrantRevokedError extends AIPassError {}
export class BudgetExhaustedError extends AIPassError {}
export class ScopeDeniedError extends AIPassError {}
export class ExecutorOfflineError extends AIPassError {}
export class ControlChannelLostError extends AIPassError {}
export class SecretUnavailableError extends AIPassError {}
export class SyncConflictError extends AIPassError {}
export class PreconditionFailedError extends AIPassError {}
export class RollbackDetectedError extends AIPassError {}
export class IntegrityFailedError extends AIPassError {}
/** Upstream needs re-login / OAuth re-consent — handle it in the AI Pass app, never by asking for secrets in chat. */
export class InteractiveAuthRequiredError extends AIPassError {}
export class ResultRestrictedError extends AIPassError {}
/** The external service may have executed the action. Verify before retrying. */
export class UpstreamOutcomeUnknownError extends AIPassError {}
export class UpstreamError extends AIPassError {}
export class IdempotencyConflictError extends AIPassError {}

export class RateLimitedError extends AIPassError {
  /** Parsed `Retry-After` header (seconds), when present. */
  readonly retryAfterSeconds: number | undefined;

  constructor(code: string, message: string, options: AIPassErrorOptions & { retryAfterSeconds?: number } = {}) {
    super(code, message, options);
    this.retryAfterSeconds = options.retryAfterSeconds;
  }
}

export class NotFoundError extends AIPassError {}
export class InvalidRequestError extends AIPassError {}
export class NotSupportedError extends AIPassError {}
export class PaymentRequiredError extends AIPassError {}
export class QuotaExceededError extends AIPassError {}
export class InternalError extends AIPassError {}

// ---- SDK-local codes ------------------------------------------------------------------

/** The broker could not be reached (connection refused, socket missing, TLS failure, reset…). */
export class NetworkError extends AIPassError {}

/** A request or a wait timed out. A timeout is never an approval. */
export class AIPassTimeoutError extends AIPassError {
  /** Latest known operation state (wait timeouts only). */
  readonly operation: OperationResponse | undefined;

  constructor(code: string, message: string, options: AIPassErrorOptions & { operation?: OperationResponse } = {}) {
    super(code, message, options);
    this.operation = options.operation;
  }
}

export class AbortedError extends AIPassError {}
export class InvalidResponseError extends AIPassError {}
export class ConfigError extends AIPassError {}
export class OperationCancelledError extends AIPassError {}

type ErrorCtor = new (code: string, message: string, options?: AIPassErrorOptions) => AIPassError;

const CLASS_BY_CODE: Record<string, ErrorCtor> = {
  IDENTITY_UNVERIFIED: IdentityUnverifiedError,
  UNAUTHENTICATED: UnauthenticatedError,
  FORBIDDEN: ForbiddenError,
  CONNECTION_PAUSED: ConnectionPausedError,
  APPROVAL_REQUIRED: ApprovalRequiredError,
  APPROVAL_DENIED: ApprovalDeniedError,
  APPROVAL_EXPIRED: ApprovalExpiredError,
  GRANT_EXPIRED: GrantExpiredError,
  GRANT_REVOKED: GrantRevokedError,
  BUDGET_EXHAUSTED: BudgetExhaustedError,
  SCOPE_DENIED: ScopeDeniedError,
  EXECUTOR_OFFLINE: ExecutorOfflineError,
  CONTROL_CHANNEL_LOST: ControlChannelLostError,
  SECRET_UNAVAILABLE: SecretUnavailableError,
  SYNC_CONFLICT: SyncConflictError,
  PRECONDITION_FAILED: PreconditionFailedError,
  ROLLBACK_DETECTED: RollbackDetectedError,
  INTEGRITY_FAILED: IntegrityFailedError,
  INTERACTIVE_AUTH_REQUIRED: InteractiveAuthRequiredError,
  RESULT_RESTRICTED: ResultRestrictedError,
  UPSTREAM_OUTCOME_UNKNOWN: UpstreamOutcomeUnknownError,
  UPSTREAM_ERROR: UpstreamError,
  IDEMPOTENCY_CONFLICT: IdempotencyConflictError,
  RATE_LIMITED: RateLimitedError,
  NOT_FOUND: NotFoundError,
  INVALID_REQUEST: InvalidRequestError,
  NOT_SUPPORTED: NotSupportedError,
  PAYMENT_REQUIRED: PaymentRequiredError,
  QUOTA_EXCEEDED: QuotaExceededError,
  INTERNAL: InternalError,
  NETWORK_ERROR: NetworkError,
  TIMEOUT: AIPassTimeoutError,
  ABORTED: AbortedError,
  INVALID_RESPONSE: InvalidResponseError,
  CONFIG_ERROR: ConfigError,
  CANCELLED: OperationCancelledError,
};

/** The subclass used for a code (`AIPassError` for codes unknown to this SDK version). */
export function errorClassForCode(code: string): ErrorCtor {
  return CLASS_BY_CODE[code] ?? AIPassError;
}

/** Construct the typed error for `code`. */
export function errorFromCode(code: string, message: string, options: AIPassErrorOptions & { retryAfterSeconds?: number; operation?: OperationResponse } = {}): AIPassError {
  const Ctor = errorClassForCode(code) as new (code: string, message: string, options?: object) => AIPassError;
  return new Ctor(code, message, options);
}

const FALLBACK_CODE_BY_STATUS: Record<number, string> = {
  400: "INVALID_REQUEST",
  401: "IDENTITY_UNVERIFIED",
  402: "PAYMENT_REQUIRED",
  403: "FORBIDDEN",
  404: "NOT_FOUND",
  412: "PRECONDITION_FAILED",
  429: "RATE_LIMITED",
  500: "INTERNAL",
  501: "NOT_SUPPORTED",
};

function parseRetryAfter(value: string | string[] | undefined): number | undefined {
  const v = Array.isArray(value) ? value[0] : value;
  if (!v) return undefined;
  if (/^\d+$/.test(v.trim())) return Number(v.trim());
  const date = Date.parse(v);
  if (Number.isNaN(date)) return undefined;
  return Math.max(0, Math.ceil((date - Date.now()) / 1000));
}

function header(headers: Record<string, string | string[] | undefined>, name: string): string | undefined {
  const v = headers[name];
  return Array.isArray(v) ? v[0] : v;
}

/**
 * Map a non-2xx broker response to a typed error. The body is parsed as the CONTRACTS §1.5
 * envelope; if it is not one, the HTTP status decides the code and the body is NOT echoed
 * (it could be an arbitrary proxy page).
 */
export function errorFromResponse(
  status: number,
  bodyText: string,
  headers: Record<string, string | string[] | undefined>,
  fallbackMessage: string,
): AIPassError {
  let envelope: unknown;
  try {
    envelope = bodyText ? JSON.parse(bodyText) : undefined;
  } catch {
    envelope = undefined;
  }
  const requestIdHeader = header(headers, "x-request-id");
  const retryAfterSeconds = parseRetryAfter(headers["retry-after"]);
  const err = (envelope as { error?: unknown } | undefined)?.error;
  if (err && typeof err === "object" && typeof (err as { code?: unknown }).code === "string") {
    const e = err as { code: string; message?: unknown; details?: unknown; request_id?: unknown };
    const details = e.details && typeof e.details === "object" && !Array.isArray(e.details) ? (e.details as Record<string, unknown>) : undefined;
    const opts: AIPassErrorOptions & { retryAfterSeconds?: number } = { httpStatus: status };
    const rid = typeof e.request_id === "string" ? e.request_id : requestIdHeader;
    if (rid !== undefined) opts.requestId = rid;
    if (details !== undefined) opts.details = details;
    if (retryAfterSeconds !== undefined) opts.retryAfterSeconds = retryAfterSeconds;
    return errorFromCode(e.code, typeof e.message === "string" && e.message ? e.message : fallbackMessage, opts);
  }
  const code = FALLBACK_CODE_BY_STATUS[status] ?? "INVALID_RESPONSE";
  const opts: AIPassErrorOptions & { retryAfterSeconds?: number } = { httpStatus: status };
  if (requestIdHeader !== undefined) opts.requestId = requestIdHeader;
  if (retryAfterSeconds !== undefined) opts.retryAfterSeconds = retryAfterSeconds;
  return errorFromCode(code, fallbackMessage, opts);
}
