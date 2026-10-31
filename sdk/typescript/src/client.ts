// SPDX-License-Identifier: Apache-2.0
/**
 * `AIPassClient` — the connection-authenticated ("C") side of the AI Pass broker API
 * (CONTRACTS §6.3). The client never receives, stores or returns business credentials: it only
 * holds its own connection key / token, and that is never serialised or logged.
 */
import { BearerAuthenticator, SignatureAuthenticator, type Authenticator } from "./auth.js";
import { HttpCore, pathSegment, type Logger } from "./core.js";
import { randomB64u } from "./encoding.js";
import {
  AIPassError,
  AIPassTimeoutError,
  ApprovalRequiredError,
  ConfigError,
  errorFromCode,
  InvalidRequestError,
  InvalidResponseError,
} from "./errors.js";
import { loadConnectionKey } from "./keyfile.js";
import { msg, normalizeLocale } from "./messages.js";
import type { ConnectionKey } from "./signing.js";
import { handleToolCall, type HandleToolCallOptions, type ToolCallResult } from "./tools.js";
import { NodeHttpTransport, type Transport } from "./transport.js";
import {
  isTerminalAccessStatus,
  isTerminalOperationStatus,
  type AccessRequest,
  type AccessRequestResponse,
  type CancelResponse,
  type HealthResponse,
  type ListResourcesParams,
  type Locale,
  type OperationRequest,
  type OperationResponse,
  type ReleaseResponse,
  type ResourceList,
  type ResourceView,
} from "./types.js";
import { parseBrokerUrl, resolveBrokerUrl, type BrokerEndpoint } from "./url.js";
import { poll, type BackoffOptions } from "./wait.js";

const INSPECT = Symbol.for("nodejs.util.inspect.custom");

export interface AIPassClientOptions {
  /** `http(s)://host:port[/base]` or `unix:///abs/path.sock`. Default: see {@link resolveBrokerUrl}. */
  brokerUrl?: string;
  /** Unix socket path (alternative to `brokerUrl`). */
  socketPath?: string;
  /** Paired connection key (`AIPass-Sig`). */
  connectionKey?: ConnectionKey;
  /** Path of a connection key file written by `pair()` / the MCP bridge (must be 0600). */
  keyFile?: string;
  /** `aipc_…` node-issued connection token or `aipa_…` cloud access token. */
  bearerToken?: string;
  /** `zh-CN` (default) or `en` — sent as `Accept-Language`, used for SDK messages. */
  locale?: Locale | string;
  /** Per-request timeout (ms). Default 30000. */
  timeoutMs?: number;
  /** Retries for transport failures on retry-safe requests. Default 2. */
  maxRetries?: number;
  /** Response size cap (bytes). Default 16 MiB. */
  maxResponseBytes?: number;
  /** Extra trusted CA certificate(s) (PEM) for a self-hosted node. TLS verification cannot be disabled. */
  ca?: string | Buffer | Array<string | Buffer>;
  /** Allow plaintext http to a non-loopback host. Default false. */
  allowInsecureHttp?: boolean;
  /** Skip the 0600 check when loading `keyFile`. Default false. */
  allowInsecureKeyFilePermissions?: boolean;
  /** Appended to the SDK user agent. */
  userAgent?: string;
  logger?: Logger;
  /** Custom transport (advanced; tests). */
  transport?: Transport;
  /** Environment used for broker URL resolution (default `process.env`). */
  env?: NodeJS.ProcessEnv;
}

export interface RequestOptions {
  signal?: AbortSignal;
  timeoutMs?: number;
}

export interface RequestOperationOptions extends RequestOptions {
  /** Throw {@link ApprovalRequiredError} instead of returning `status: "approval_required"`. */
  raiseOnPending?: boolean;
}

export interface WaitForOperationOptions extends BackoffOptions {
  /** Total wait (ms). Default 120000 (the broker's operation approval TTL). */
  timeoutMs?: number;
  signal?: AbortSignal;
  /** At timeout, throw instead of returning the still-pending status. Default false. */
  raiseOnPending?: boolean;
  /** Throw a typed error for terminal statuses other than `succeeded`. Default false. */
  raiseOnFailure?: boolean;
  onUpdate?: (operation: OperationResponse) => void;
}

export interface WaitForAccessOptions extends BackoffOptions {
  /** Total wait (ms). Default 600000 (the broker's access-request approval TTL). */
  timeoutMs?: number;
  signal?: AbortSignal;
  raiseOnPending?: boolean;
  raiseOnFailure?: boolean;
  onUpdate?: (request: AccessRequestResponse) => void;
}

export interface FindResourceQuery extends ListResourcesParams {
  alias?: string;
  resource_id?: string;
}

/** Generate a random idempotency key (`aipass-sdk-<b64u>`). Prefer a key derived from your task. */
export function generateIdempotencyKey(): string {
  return `aipass-sdk-${randomB64u(18)}`;
}

const LIMIT_KEYS = ["max_rows_per_operation", "max_rows_per_grant", "max_requests_per_grant", "max_result_bytes"] as const;
const CONTROL_CHARS = /[\u0000-\u001f\u007f-\u009f]/;

function invalid(locale: Locale, detail: string): InvalidRequestError {
  return new InvalidRequestError("INVALID_REQUEST", msg(locale, "invalidArgument", { detail }));
}

function requireId(locale: Locale, value: unknown, name: string): string {
  if (typeof value !== "string" || value.trim() === "" || value.length > 128) throw invalid(locale, `${name} must be a non-empty string (≤128 chars)`);
  return value;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function expectShape(locale: Locale, status: number, ok: boolean): void {
  if (!ok) throw new InvalidResponseError("INVALID_RESPONSE", msg(locale, "invalidResponse", { status }), { httpStatus: status });
}

/** Typed error for a terminal operation that did not succeed. */
export function errorForOperation(op: OperationResponse, locale: Locale = "zh-CN"): AIPassError {
  const opts = { operation: op } as { operation: OperationResponse; requestId?: string; details?: Record<string, unknown> };
  if (op.error && typeof op.error.code === "string") {
    if (op.error.request_id) opts.requestId = op.error.request_id;
    if (op.error.details) opts.details = op.error.details;
    return errorFromCode(op.error.code, op.error.message || msg(locale, "operationFailed", { status: op.status }), opts);
  }
  switch (op.status) {
    case "denied":
      return errorFromCode("APPROVAL_DENIED", msg(locale, "approvalDenied"), opts);
    case "expired":
      return errorFromCode("APPROVAL_EXPIRED", msg(locale, "approvalExpired"), opts);
    case "cancelled":
      return errorFromCode("CANCELLED", msg(locale, "operationCancelled"), opts);
    case "unknown":
      return errorFromCode("UPSTREAM_OUTCOME_UNKNOWN", msg(locale, "outcomeUnknown"), opts);
    default:
      return errorFromCode("UPSTREAM_ERROR", msg(locale, "operationFailed", { status: op.status }), opts);
  }
}

export class AIPassClient {
  readonly #core: HttpCore;
  readonly #auth: Authenticator;
  readonly #locale: Locale;

  constructor(options: AIPassClientOptions = {}) {
    const locale = normalizeLocale(options.locale);
    this.#locale = locale;
    const authSources = [options.connectionKey, options.keyFile, options.bearerToken].filter((v) => v !== undefined && v !== null && v !== "");
    if (authSources.length === 0) throw new ConfigError("CONFIG_ERROR", msg(locale, "noAuth"));
    if (authSources.length > 1) throw new ConfigError("CONFIG_ERROR", msg(locale, "multipleAuth"));

    let keyFileBrokerUrl: string | undefined;
    if (options.connectionKey) {
      this.#auth = new SignatureAuthenticator(options.connectionKey);
    } else if (options.keyFile) {
      const loaded = loadConnectionKey(options.keyFile, {
        locale,
        ...(options.allowInsecureKeyFilePermissions ? { allowInsecurePermissions: true } : {}),
      });
      keyFileBrokerUrl = loaded.metadata.broker_url;
      this.#auth = new SignatureAuthenticator(loaded.key);
    } else {
      this.#auth = new BearerAuthenticator(options.bearerToken as string, locale);
    }

    const endpoint = AIPassClient.#endpointFor(options, locale, keyFileBrokerUrl);
    this.#core = new HttpCore({
      endpoint,
      transport: options.transport ?? new NodeHttpTransport(endpoint, { locale, ...(options.ca !== undefined ? { ca: options.ca } : {}) }),
      locale,
      timeoutMs: options.timeoutMs ?? 30_000,
      maxRetries: options.maxRetries ?? 2,
      maxResponseBytes: options.maxResponseBytes ?? 16 * 1024 * 1024,
      ...(options.userAgent ? { userAgent: options.userAgent } : {}),
      ...(options.logger ? { logger: options.logger } : {}),
    });
  }

  static #endpointFor(options: AIPassClientOptions, locale: Locale, keyFileBrokerUrl: string | undefined): BrokerEndpoint {
    if (options.socketPath) return parseBrokerUrl(`unix://${options.socketPath}`, { locale });
    const env = options.env ?? process.env;
    const explicit = options.brokerUrl ?? (env.AIPASS_BROKER_URL ? undefined : keyFileBrokerUrl);
    return parseBrokerUrl(resolveBrokerUrl(explicit, env), {
      locale,
      ...(options.allowInsecureHttp ? { allowInsecureHttp: true } : {}),
    });
  }

  /** Create a client from a connection key file. */
  static fromKeyFile(keyFile: string, options: Omit<AIPassClientOptions, "keyFile" | "connectionKey" | "bearerToken"> = {}): AIPassClient {
    return new AIPassClient({ ...options, keyFile });
  }

  /** Display form of the broker endpoint (no credentials). */
  get brokerUrl(): string {
    return this.#core.endpoint.display;
  }

  /** `conn_…` when authenticated with a connection key. */
  get connectionId(): string | undefined {
    return this.#auth.principalId;
  }

  get authKind(): "connection_key" | "bearer" {
    return this.#auth.kind;
  }

  get locale(): Locale {
    return this.#locale;
  }

  /** `GET /v1/health` (public). */
  async health(options: RequestOptions = {}): Promise<HealthResponse> {
    const res = await this.#core.call<HealthResponse>("GET", "/v1/health", { auth: null, retrySafe: true, ...options });
    expectShape(this.#locale, res.status, typeof res.data.status === "string");
    return res.data;
  }

  /** `GET /v1/resources` — resources this connection may discover (never secrets). */
  async listResources(params: ListResourcesParams = {}, options: RequestOptions = {}): Promise<ResourceList> {
    const res = await this.#core.call<ResourceList>("GET", "/v1/resources", {
      auth: this.#auth,
      retrySafe: true,
      query: { project_id: params.project_id, service: params.service },
      ...options,
    });
    expectShape(this.#locale, res.status, Array.isArray(res.data.resources));
    return res.data;
  }

  /** Find a visible resource by id or alias (aliases are labels, not identity). */
  async findResource(query: FindResourceQuery, options: RequestOptions = {}): Promise<ResourceView | undefined> {
    const params: ListResourcesParams = {};
    if (query.project_id) params.project_id = query.project_id;
    if (query.service) params.service = query.service;
    const { resources } = await this.listResources(params, options);
    return resources.find(
      (r) => (query.resource_id === undefined || r.resource_id === query.resource_id) && (query.alias === undefined || r.alias === query.alias),
    );
  }

  /**
   * `POST /v1/operations`. Returns the broker's `OperationResponse`: done (`succeeded`, …) or
   * pending (`approval_required`). If `idempotency_key` is omitted a random one is generated —
   * pass your own so that *your* retries are deduplicated too.
   */
  async requestOperation(request: OperationRequest, options: RequestOperationOptions = {}): Promise<OperationResponse> {
    const locale = this.#locale;
    if (!isPlainObject(request)) throw invalid(locale, "request must be an object");
    const resourceId = requireId(locale, request.resource_id, "resource_id");
    const operation = requireId(locale, request.operation, "operation");
    const parameters = request.parameters ?? {};
    if (!isPlainObject(parameters)) throw invalid(locale, "parameters must be an object");
    const idempotencyKey = request.idempotency_key ?? generateIdempotencyKey();
    if (typeof idempotencyKey !== "string" || idempotencyKey.length < 1 || [...idempotencyKey].length > 128 || CONTROL_CHARS.test(idempotencyKey)) {
      throw invalid(locale, "idempotency_key must be 1..128 printable characters");
    }
    const body: Record<string, unknown> = { resource_id: resourceId, operation, parameters, idempotency_key: idempotencyKey };
    if (request.task_id !== undefined) body.task_id = requireId(locale, request.task_id, "task_id");
    const res = await this.#core.call<OperationResponse>("POST", "/v1/operations", {
      auth: this.#auth,
      retrySafe: true, // carries an idempotency key
      body,
      ...pickRequestOptions(options),
    });
    const op = this.#checkOperation(res.status, res.data);
    if (options.raiseOnPending && op.status === "approval_required") throw this.#approvalRequired(op);
    return op;
  }

  /** `GET /v1/operations/{id}` (own operations only; others are `NOT_FOUND`). */
  async getOperation(operationId: string, options: RequestOptions = {}): Promise<OperationResponse> {
    const id = requireId(this.#locale, operationId, "operation_id");
    const res = await this.#core.call<OperationResponse>("GET", `/v1/operations/${pathSegment(id)}`, {
      auth: this.#auth,
      retrySafe: true,
      ...pickRequestOptions(options),
    });
    return this.#checkOperation(res.status, res.data);
  }

  /** `POST /v1/operations/{id}/cancel`. Check `side_effects`: an external action may already have happened. */
  async cancelOperation(operationId: string, options: RequestOptions = {}): Promise<CancelResponse> {
    const id = requireId(this.#locale, operationId, "operation_id");
    const res = await this.#core.call<CancelResponse>("POST", `/v1/operations/${pathSegment(id)}/cancel`, {
      auth: this.#auth,
      retrySafe: true, // cancelling twice is harmless
      body: {},
      ...pickRequestOptions(options),
    });
    expectShape(this.#locale, res.status, typeof res.data.operation_id === "string" && typeof res.data.status === "string");
    return res.data;
  }

  /**
   * Poll an operation until it reaches a terminal status, the timeout passes, or `signal`
   * aborts. Returns the latest status; `approval_required` at timeout is returned as-is (never
   * treated as approval) unless `raiseOnPending` is set.
   */
  async waitForOperation(operationId: string, options: WaitForOperationOptions = {}): Promise<OperationResponse> {
    const id = requireId(this.#locale, operationId, "operation_id");
    const outcome = await poll<OperationResponse>(
      (remainingMs) =>
        this.#core
          .call<OperationResponse>("GET", `/v1/operations/${pathSegment(id)}`, {
            auth: this.#auth,
            retrySafe: false, // the poll loop retries
            timeoutMs: Math.min(this.#core.timeoutMs, Math.max(2000, remainingMs)),
            ...(options.signal ? { signal: options.signal } : {}),
          })
          .then((res) => this.#checkOperation(res.status, res.data)),
      {
        ...options,
        timeoutMs: options.timeoutMs ?? 120_000,
        locale: this.#locale,
        isTerminal: (op) => isTerminalOperationStatus(op.status),
      },
    );
    const op = outcome.value;
    if (outcome.timedOut) {
      if (options.raiseOnPending) {
        if (op.status === "approval_required") throw this.#approvalRequired(op);
        throw new AIPassTimeoutError("TIMEOUT", msg(this.#locale, "waitTimeout", { status: op.status }), { operation: op });
      }
      return op;
    }
    if (options.raiseOnFailure && op.status !== "succeeded") throw errorForOperation(op, this.#locale);
    return op;
  }

  /** `POST /v1/access/requests` — ask the user for a task-scoped grant. Not retried automatically. */
  async requestAccess(request: AccessRequest, options: RequestOptions = {}): Promise<AccessRequestResponse> {
    const locale = this.#locale;
    if (!isPlainObject(request)) throw invalid(locale, "request must be an object");
    const body: Record<string, unknown> = { resource_id: requireId(locale, request.resource_id, "resource_id") };
    if (!Array.isArray(request.operations) || request.operations.length === 0 || !request.operations.every((o) => typeof o === "string" && o !== "")) {
      throw invalid(locale, "operations must be a non-empty array of strings");
    }
    body.operations = request.operations;
    if (request.scope !== undefined) {
      if (!isPlainObject(request.scope)) throw invalid(locale, "scope must be an object");
      body.scope = request.scope;
    }
    if (request.limits !== undefined) {
      const limits = request.limits as unknown;
      if (!isPlainObject(limits) || !LIMIT_KEYS.every((k) => Number.isSafeInteger(limits[k]) && (limits[k] as number) >= 0)) {
        throw invalid(locale, `limits must contain the integers ${LIMIT_KEYS.join(", ")}`);
      }
      body.limits = Object.fromEntries(LIMIT_KEYS.map((k) => [k, limits[k]]));
    }
    if (request.duration_seconds !== undefined) {
      if (!Number.isSafeInteger(request.duration_seconds) || request.duration_seconds <= 0) throw invalid(locale, "duration_seconds must be a positive integer");
      body.duration_seconds = request.duration_seconds;
    }
    if (request.reason !== undefined) {
      if (typeof request.reason !== "string") throw invalid(locale, "reason must be a string");
      body.reason = request.reason;
    }
    const res = await this.#core.call<AccessRequestResponse>("POST", "/v1/access/requests", {
      auth: this.#auth,
      retrySafe: false, // no idempotency key: a resend could create a second approval prompt
      body,
      ...pickRequestOptions(options),
    });
    return this.#checkAccess(res.status, res.data);
  }

  /** `GET /v1/access/requests/{id}`. */
  async getAccessRequest(approvalRequestId: string, options: RequestOptions = {}): Promise<AccessRequestResponse> {
    const id = requireId(this.#locale, approvalRequestId, "approval_request_id");
    const res = await this.#core.call<AccessRequestResponse>("GET", `/v1/access/requests/${pathSegment(id)}`, {
      auth: this.#auth,
      retrySafe: true,
      ...pickRequestOptions(options),
    });
    return this.#checkAccess(res.status, res.data);
  }

  /** Poll an access request until approved / denied / expired / cancelled, timeout or abort. */
  async waitForAccessRequest(approvalRequestId: string, options: WaitForAccessOptions = {}): Promise<AccessRequestResponse> {
    const id = requireId(this.#locale, approvalRequestId, "approval_request_id");
    const outcome = await poll<AccessRequestResponse>(
      (remainingMs) =>
        this.#core
          .call<AccessRequestResponse>("GET", `/v1/access/requests/${pathSegment(id)}`, {
            auth: this.#auth,
            retrySafe: false,
            timeoutMs: Math.min(this.#core.timeoutMs, Math.max(2000, remainingMs)),
            ...(options.signal ? { signal: options.signal } : {}),
          })
          .then((res) => this.#checkAccess(res.status, res.data)),
      {
        ...options,
        timeoutMs: options.timeoutMs ?? 600_000,
        locale: this.#locale,
        isTerminal: (r) => isTerminalAccessStatus(r.status),
      },
    );
    const value = outcome.value;
    if (outcome.timedOut) {
      if (options.raiseOnPending) {
        throw new ApprovalRequiredError("APPROVAL_REQUIRED", msg(this.#locale, "approvalRequired"), { approvalRequestId: value.approval_request_id });
      }
      return value;
    }
    if (options.raiseOnFailure && value.status !== "approved") {
      const code = value.status === "denied" ? "APPROVAL_DENIED" : value.status === "expired" ? "APPROVAL_EXPIRED" : "CANCELLED";
      const key = value.status === "denied" ? "approvalDenied" : value.status === "expired" ? "approvalExpired" : "operationCancelled";
      throw errorFromCode(code, msg(this.#locale, key));
    }
    return value;
  }

  /** `POST /v1/access/grants/{id}/release` — end a grant early. */
  async releaseGrant(grantId: string, options: RequestOptions = {}): Promise<ReleaseResponse> {
    const id = requireId(this.#locale, grantId, "grant_id");
    const res = await this.#core.call<ReleaseResponse>("POST", `/v1/access/grants/${pathSegment(id)}/release`, {
      auth: this.#auth,
      retrySafe: true, // releasing twice is harmless
      body: {},
      ...pickRequestOptions(options),
    });
    expectShape(this.#locale, res.status, typeof res.data.grant_id === "string" && typeof res.data.status === "string");
    return res.data;
  }

  /** Dispatch a model tool call (CONTRACTS §9 names). Never throws for broker errors. */
  handleToolCall(name: string, args: unknown, options: HandleToolCallOptions = {}): Promise<ToolCallResult> {
    return handleToolCall(this, name, args, { locale: this.#locale, ...options });
  }

  /** Release pooled sockets. */
  close(): void {
    this.#core.close();
  }

  #checkOperation(status: number, data: OperationResponse): OperationResponse {
    expectShape(this.#locale, status, typeof data.status === "string" && typeof data.operation_id === "string");
    return data;
  }

  #checkAccess(status: number, data: AccessRequestResponse): AccessRequestResponse {
    expectShape(this.#locale, status, typeof data.approval_request_id === "string" && typeof data.status === "string");
    return data;
  }

  #approvalRequired(op: OperationResponse): ApprovalRequiredError {
    return new ApprovalRequiredError("APPROVAL_REQUIRED", op.message || msg(this.#locale, "approvalRequired"), { operation: op });
  }

  toJSON(): Record<string, unknown> {
    return { broker_url: this.brokerUrl, auth: this.#auth.kind, connection_id: this.connectionId ?? null };
  }

  toString(): string {
    return `AIPassClient(${this.brokerUrl}, auth=${this.#auth.kind}${this.connectionId ? `, ${this.connectionId}` : ""})`;
  }

  [INSPECT](): string {
    return this.toString();
  }
}

function pickRequestOptions(options: RequestOptions): Pick<RequestOptions, "signal" | "timeoutMs"> {
  const out: RequestOptions = {};
  if (options.signal) out.signal = options.signal;
  if (options.timeoutMs !== undefined) out.timeoutMs = options.timeoutMs;
  return out;
}
