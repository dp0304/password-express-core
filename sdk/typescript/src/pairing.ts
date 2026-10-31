// SPDX-License-Identifier: Apache-2.0
/**
 * Connection pairing (CONTRACTS §6.3):
 *
 * 1. Generate an Ed25519 key from the OS CSPRNG (the seed never leaves this process except into
 *    the 0600 key file you choose).
 * 2. `POST /v1/connections/pair {host_type, display_name, transport, public_key}` →
 *    `{pairing_request_id, connection_id, pairing_code, expires_at}`.
 * 3. Show the pairing code to the user; they confirm it on their phone / trusted client.
 * 4. Poll `GET /v1/connections/pair/{pairing_request_id}` — signed with the pending key
 *    (`kid = connection_id`) — until `approved | denied | expired`.
 *
 * Nothing here can approve a connection: only the user's trusted device can.
 */
import { SignatureAuthenticator } from "./auth.js";
import { AIPassClient, type AIPassClientOptions } from "./client.js";
import { HttpCore, pathSegment, type Logger } from "./core.js";
import { ConfigError, InvalidRequestError, InvalidResponseError } from "./errors.js";
import { saveConnectionKey } from "./keyfile.js";
import { msg, normalizeLocale } from "./messages.js";
import { ConnectionKey, SigningKey } from "./signing.js";
import { NodeHttpTransport, type Transport } from "./transport.js";
import type { ConnectionTransport, HostType, Locale, PairStartResponse, PairStatus, PairStatusResponse } from "./types.js";
import { parseBrokerUrl, resolveBrokerUrl } from "./url.js";
import { poll, type BackoffOptions } from "./wait.js";

const HOST_TYPES: readonly HostType[] = ["codex", "claude_code", "cursor", "chatgpt", "claude_connector", "sdk", "custom"];

export interface PairingConnectionOptions {
  brokerUrl?: string;
  socketPath?: string;
  locale?: Locale | string;
  timeoutMs?: number;
  maxRetries?: number;
  ca?: string | Buffer | Array<string | Buffer>;
  allowInsecureHttp?: boolean;
  userAgent?: string;
  logger?: Logger;
  transport?: Transport;
  env?: NodeJS.ProcessEnv;
}

export interface StartPairingOptions extends PairingConnectionOptions {
  /** Shown to the user on the approval screen — a label, never identity. */
  displayName: string;
  /** Default `sdk`. */
  hostType?: HostType;
  /** Default `sdk`. */
  connectionTransport?: ConnectionTransport;
}

export interface PairingInfo {
  pairing_request_id: string;
  connection_id: string;
  pairing_code: string;
  expires_at: string;
}

export interface WaitForPairingOptions extends BackoffOptions {
  /** Default: until `expires_at` (+5 s), capped at 15 minutes. */
  timeoutMs?: number;
  signal?: AbortSignal;
  onUpdate?: (status: PairStatusResponse) => void;
}

export interface PairingResult {
  status: PairStatus;
  /** True when the local wait ended before the broker reported a final status. */
  timedOut: boolean;
  connectionId: string;
  pairingRequestId: string;
  pairingCode: string;
  expiresAt: string;
  /** Present only when approved. */
  connectionKey?: ConnectionKey;
  /** Where the key was saved (approved + `keyPath` given). */
  keyPath?: string;
}

export interface PairOptions extends StartPairingOptions, WaitForPairingOptions {
  /** Persist the key here (mode 0600) once approved. */
  keyPath?: string;
  /** Overwrite an existing key file. Default false. */
  overwrite?: boolean;
  /** Called with the pairing code as soon as it is known — display it to the user. */
  onPairingCode?: (info: PairingInfo) => void | Promise<void>;
}

/** An in-progress pairing: holds the pending key and the code to show the user. */
export class PairingSession {
  readonly info: PairingInfo;
  readonly connectionKey: ConnectionKey;
  readonly #core: HttpCore;
  readonly #auth: SignatureAuthenticator;
  readonly #options: StartPairingOptions;

  /** @internal */
  constructor(core: HttpCore, info: PairingInfo, key: ConnectionKey, options: StartPairingOptions) {
    this.#core = core;
    this.info = Object.freeze({ ...info });
    this.connectionKey = key;
    this.#auth = new SignatureAuthenticator(key);
    this.#options = options;
  }

  get pairingCode(): string {
    return this.info.pairing_code;
  }

  get connectionId(): string {
    return this.info.connection_id;
  }

  /** One status check. */
  async poll(options: { signal?: AbortSignal; timeoutMs?: number } = {}): Promise<PairStatusResponse> {
    const locale = this.#core.locale;
    const res = await this.#core.call<PairStatusResponse>("GET", `/v1/connections/pair/${pathSegment(this.info.pairing_request_id)}`, {
      auth: this.#auth,
      retrySafe: true,
      ...(options.signal ? { signal: options.signal } : {}),
      ...(options.timeoutMs !== undefined ? { timeoutMs: options.timeoutMs } : {}),
    });
    if (typeof res.data.status !== "string") {
      throw new InvalidResponseError("INVALID_RESPONSE", msg(locale, "invalidResponse", { status: res.status }), { httpStatus: res.status });
    }
    if (typeof res.data.connection_id === "string" && res.data.connection_id !== this.info.connection_id) {
      throw new InvalidResponseError("INVALID_RESPONSE", msg(locale, "pairingMismatch"), { httpStatus: res.status });
    }
    return res.data;
  }

  /** Poll until the user approves or denies on a trusted device, the request expires, or the wait ends. */
  async wait(options: WaitForPairingOptions = {}): Promise<PairingResult> {
    const expiresMs = Date.parse(this.info.expires_at);
    const untilExpiry = Number.isNaN(expiresMs) ? 10 * 60_000 : expiresMs - Date.now() + 5_000;
    const timeoutMs = options.timeoutMs ?? Math.min(15 * 60_000, Math.max(0, untilExpiry));
    const outcome = await poll<PairStatusResponse>(
      (remainingMs) =>
        this.poll({
          ...(options.signal ? { signal: options.signal } : {}),
          timeoutMs: Math.min(this.#core.timeoutMs, Math.max(2000, remainingMs)),
        }),
      {
        intervalMs: 2000,
        maxIntervalMs: 5000,
        ...options,
        timeoutMs,
        locale: this.#core.locale,
        isTerminal: (s) => s.status === "approved" || s.status === "denied" || s.status === "expired",
      },
    );
    const status = (["approved", "denied", "expired"].includes(outcome.value.status) ? outcome.value.status : "pending") as PairStatus;
    const result: PairingResult = {
      status,
      timedOut: outcome.timedOut,
      connectionId: this.info.connection_id,
      pairingRequestId: this.info.pairing_request_id,
      pairingCode: this.info.pairing_code,
      expiresAt: this.info.expires_at,
    };
    if (status === "approved") result.connectionKey = this.connectionKey;
    return result;
  }

  /** Save the key (0600). Usually called after approval; `pair()` does it for you. */
  saveKey(path: string, options: { overwrite?: boolean } = {}): string {
    return saveConnectionKey(
      path,
      this.connectionKey,
      {
        broker_url: this.#core.endpoint.display,
        host_type: this.#options.hostType ?? "sdk",
        display_name: this.#options.displayName,
      },
      { locale: this.#core.locale, ...(options.overwrite ? { overwrite: true } : {}) },
    );
  }

  /** A client authenticated with this (approved) connection key. */
  createClient(options: Omit<AIPassClientOptions, "connectionKey" | "keyFile" | "bearerToken" | "brokerUrl" | "socketPath"> = {}): AIPassClient {
    const endpoint = this.#core.endpoint;
    const base = this.#options;
    return new AIPassClient({
      ...(base.locale !== undefined ? { locale: base.locale } : {}),
      ...(base.ca !== undefined ? { ca: base.ca } : {}),
      ...(base.allowInsecureHttp ? { allowInsecureHttp: true } : {}),
      ...(base.logger ? { logger: base.logger } : {}),
      ...(base.transport ? { transport: base.transport } : {}),
      ...options,
      ...(endpoint.kind === "unix" ? { socketPath: endpoint.socketPath } : { brokerUrl: endpoint.display }),
      connectionKey: this.connectionKey,
    });
  }

  /** Release the pairing session's pooled sockets (clients created from it are unaffected). */
  close(): void {
    if (!this.#options.transport) this.#core.close();
  }

  toJSON(): PairingInfo {
    return { ...this.info };
  }
}

function coreFor(options: PairingConnectionOptions, locale: Locale): HttpCore {
  const env = options.env ?? process.env;
  const endpoint = options.socketPath
    ? parseBrokerUrl(`unix://${options.socketPath}`, { locale })
    : parseBrokerUrl(resolveBrokerUrl(options.brokerUrl, env), { locale, ...(options.allowInsecureHttp ? { allowInsecureHttp: true } : {}) });
  return new HttpCore({
    endpoint,
    transport: options.transport ?? new NodeHttpTransport(endpoint, { locale, ...(options.ca !== undefined ? { ca: options.ca } : {}) }),
    locale,
    timeoutMs: options.timeoutMs ?? 30_000,
    maxRetries: options.maxRetries ?? 2,
    maxResponseBytes: 1024 * 1024,
    ...(options.userAgent ? { userAgent: options.userAgent } : {}),
    ...(options.logger ? { logger: options.logger } : {}),
  });
}

/** Start pairing: creates the key and asks the broker for a pairing code. */
export async function startPairing(options: StartPairingOptions, requestOptions: { signal?: AbortSignal } = {}): Promise<PairingSession> {
  const locale = normalizeLocale(options.locale);
  const displayName = typeof options.displayName === "string" ? options.displayName.trim() : "";
  if (!displayName || displayName.length > 100) {
    throw new InvalidRequestError("INVALID_REQUEST", msg(locale, "invalidArgument", { detail: "displayName must be 1..100 characters" }));
  }
  const hostType = options.hostType ?? "sdk";
  if (!HOST_TYPES.includes(hostType)) {
    throw new InvalidRequestError("INVALID_REQUEST", msg(locale, "invalidArgument", { detail: `hostType must be one of ${HOST_TYPES.join(", ")}` }));
  }
  const core = coreFor(options, locale);
  const signingKey = SigningKey.generate();
  const res = await core.call<PairStartResponse>("POST", "/v1/connections/pair", {
    auth: null,
    retrySafe: false,
    body: { host_type: hostType, display_name: displayName, transport: options.connectionTransport ?? "sdk", public_key: signingKey.publicKey },
    ...(requestOptions.signal ? { signal: requestOptions.signal } : {}),
  });
  const d = res.data;
  if (
    typeof d.pairing_request_id !== "string" ||
    typeof d.connection_id !== "string" ||
    typeof d.pairing_code !== "string" ||
    typeof d.expires_at !== "string"
  ) {
    throw new InvalidResponseError("INVALID_RESPONSE", msg(locale, "invalidResponse", { status: res.status }), { httpStatus: res.status });
  }
  let key: ConnectionKey;
  try {
    key = new ConnectionKey(d.connection_id, signingKey);
  } catch {
    throw new InvalidResponseError("INVALID_RESPONSE", msg(locale, "invalidResponse", { status: res.status }), { httpStatus: res.status });
  }
  return new PairingSession(
    core,
    { pairing_request_id: d.pairing_request_id, connection_id: d.connection_id, pairing_code: d.pairing_code, expires_at: d.expires_at },
    key,
    { ...options, displayName, hostType },
  );
}

/**
 * Full pairing flow: start, report the code via `onPairingCode`, wait for the user's decision on
 * a trusted device, and — only if approved — save the key to `keyPath` (0600).
 * Check `result.status === "approved"` before using `result.client`.
 */
export async function pair(options: PairOptions): Promise<PairingResult & { client?: AIPassClient }> {
  const locale = normalizeLocale(options.locale);
  if (options.keyPath !== undefined && (typeof options.keyPath !== "string" || options.keyPath.trim() === "")) {
    throw new ConfigError("CONFIG_ERROR", msg(locale, "invalidArgument", { detail: "keyPath must be a non-empty path" }));
  }
  const session = await startPairing(options, options.signal ? { signal: options.signal } : {});
  try {
    if (options.onPairingCode) await options.onPairingCode({ ...session.info });
    const waitOptions: WaitForPairingOptions = {};
    for (const k of ["timeoutMs", "signal", "onUpdate", "intervalMs", "maxIntervalMs", "backoff", "jitter"] as const) {
      if (options[k] !== undefined) (waitOptions as Record<string, unknown>)[k] = options[k];
    }
    const result: PairingResult & { client?: AIPassClient } = await session.wait(waitOptions);
    if (result.status === "approved") {
      if (options.keyPath) result.keyPath = session.saveKey(options.keyPath, options.overwrite ? { overwrite: true } : {});
      result.client = session.createClient();
    }
    return result;
  } finally {
    session.close();
  }
}
