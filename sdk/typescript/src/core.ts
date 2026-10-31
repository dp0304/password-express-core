// SPDX-License-Identifier: Apache-2.0
/**
 * Shared request pipeline: serialise → sign (fresh nonce per attempt) → send → map errors.
 * Retries only transport failures, and only for requests the caller marked retry-safe.
 */
import type { Authenticator } from "./auth.js";
import { AbortedError, AIPassError, AIPassTimeoutError, errorFromResponse, InvalidResponseError, NetworkError } from "./errors.js";
import { msg } from "./messages.js";
import type { Transport } from "./transport.js";
import type { Locale } from "./types.js";
import type { BrokerEndpoint } from "./url.js";
import { jittered, sleep } from "./wait.js";
import { VERSION } from "./version.js";

/** Optional diagnostics sink. Receives method, path (no query), status, request id, timing — never headers or bodies. */
export interface Logger {
  debug?(event: string, fields: Record<string, unknown>): void;
  warn?(event: string, fields: Record<string, unknown>): void;
}

export interface CoreOptions {
  endpoint: BrokerEndpoint;
  transport: Transport;
  locale: Locale;
  timeoutMs: number;
  maxRetries: number;
  maxResponseBytes: number;
  userAgent?: string;
  logger?: Logger;
}

export interface CallOptions {
  query?: Record<string, string | undefined | null>;
  body?: unknown;
  auth: Authenticator | null;
  /** Safe to resend after a transport failure (GET, or POST carrying an idempotency key). */
  retrySafe: boolean;
  signal?: AbortSignal;
  timeoutMs?: number;
}

export interface CallResult<T> {
  status: number;
  data: T;
  requestId: string | undefined;
}

/** RFC 3986 query encoding; the exact string is both signed and sent. */
export function encodeQuery(query: Record<string, string | undefined | null> | undefined): string {
  if (!query) return "";
  const parts: string[] = [];
  for (const [k, v] of Object.entries(query)) {
    if (v === undefined || v === null) continue;
    parts.push(`${encodeURIComponent(k)}=${encodeURIComponent(v)}`);
  }
  return parts.length > 0 ? `?${parts.join("&")}` : "";
}

/** Encode one path segment (ids are opaque strings to the SDK). */
export function pathSegment(value: string): string {
  return encodeURIComponent(value);
}

export class HttpCore {
  readonly endpoint: BrokerEndpoint;
  readonly locale: Locale;
  readonly timeoutMs: number;
  readonly #transport: Transport;
  readonly #maxRetries: number;
  readonly #maxResponseBytes: number;
  readonly #userAgent: string;
  readonly #logger: Logger | undefined;

  constructor(options: CoreOptions) {
    this.endpoint = options.endpoint;
    this.locale = options.locale;
    this.timeoutMs = options.timeoutMs;
    this.#transport = options.transport;
    this.#maxRetries = Math.max(0, Math.floor(options.maxRetries));
    this.#maxResponseBytes = options.maxResponseBytes;
    const base = `aipass-sdk-typescript/${VERSION} node/${process.versions.node}`;
    this.#userAgent = options.userAgent ? `${base} ${options.userAgent}` : base;
    this.#logger = options.logger;
  }

  async call<T>(method: string, path: string, options: CallOptions): Promise<CallResult<T>> {
    const fullPath = `${this.endpoint.basePath}${path}${encodeQuery(options.query)}`;
    const body = options.body === undefined ? undefined : Buffer.from(JSON.stringify(options.body), "utf8");
    const attempts = options.retrySafe ? this.#maxRetries + 1 : 1;
    const logPath = `${this.endpoint.basePath}${path}`;
    let lastError: unknown;
    for (let attempt = 1; attempt <= attempts; attempt += 1) {
      const headers: Record<string, string> = {
        accept: "application/json",
        "accept-language": this.locale === "en" ? "en" : "zh-CN",
        "user-agent": this.#userAgent,
      };
      if (body !== undefined) headers["content-type"] = "application/json";
      if (options.auth) headers.authorization = options.auth.authorize(method, fullPath, body);
      const started = Date.now();
      try {
        const res = await this.#transport.request({
          method,
          path: fullPath,
          headers,
          ...(body !== undefined ? { body } : {}),
          timeoutMs: options.timeoutMs ?? this.timeoutMs,
          maxResponseBytes: this.#maxResponseBytes,
          ...(options.signal ? { signal: options.signal } : {}),
        });
        const requestIdHeader = res.headers["x-request-id"];
        const requestId = Array.isArray(requestIdHeader) ? requestIdHeader[0] : requestIdHeader;
        this.#logger?.debug?.("aipass.http", {
          method,
          path: logPath,
          status: res.status,
          request_id: requestId,
          duration_ms: Date.now() - started,
          attempt,
        });
        const text = res.body.toString("utf8");
        if (res.status < 200 || res.status >= 300) {
          throw errorFromResponse(res.status, text, res.headers, msg(this.locale, "invalidResponse", { status: res.status }));
        }
        let data: unknown;
        try {
          data = text.trim() === "" ? {} : JSON.parse(text);
        } catch {
          throw new InvalidResponseError("INVALID_RESPONSE", msg(this.locale, "invalidResponse", { status: res.status }), {
            httpStatus: res.status,
            ...(requestId !== undefined ? { requestId } : {}),
          });
        }
        if (data === null || typeof data !== "object" || Array.isArray(data)) {
          throw new InvalidResponseError("INVALID_RESPONSE", msg(this.locale, "invalidResponse", { status: res.status }), {
            httpStatus: res.status,
            ...(requestId !== undefined ? { requestId } : {}),
          });
        }
        return { status: res.status, data: data as T, requestId };
      } catch (err) {
        if (err instanceof AbortedError) throw err;
        const transportFailure = err instanceof NetworkError || (err instanceof AIPassTimeoutError && err.httpStatus === undefined);
        if (!transportFailure || attempt >= attempts) {
          if (err instanceof AIPassError) {
            this.#logger?.debug?.("aipass.http.error", { method, path: logPath, code: err.code, request_id: err.requestId, attempt });
          }
          throw err;
        }
        lastError = err;
        this.#logger?.warn?.("aipass.http.retry", { method, path: logPath, code: (err as AIPassError).code, attempt });
        await sleep(jittered(Math.min(2000, 250 * 2 ** (attempt - 1)), 0.3), options.signal, this.locale);
      }
    }
    throw lastError;
  }

  close(): void {
    this.#transport.close();
  }
}
