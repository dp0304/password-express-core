// SPDX-License-Identifier: Apache-2.0
/**
 * Request authenticators for connection-authenticated ("C") endpoints: an `AIPass-Sig`
 * connection key, or a bearer token (`aipc_…` node-issued connection token, `aipa_…` cloud
 * OAuth access token). Credentials are held in private fields and never serialised.
 */
import { ConfigError } from "./errors.js";
import { msg } from "./messages.js";
import type { ConnectionKey } from "./signing.js";
import type { Locale } from "./types.js";

const INSPECT = Symbol.for("nodejs.util.inspect.custom");

export interface Authenticator {
  readonly kind: "connection_key" | "bearer";
  /** Principal id when known (`conn_…`). */
  readonly principalId: string | undefined;
  /** `Authorization` header value for one request (fresh nonce every call). */
  authorize(method: string, path: string, body: Buffer | undefined): string;
}

export class SignatureAuthenticator implements Authenticator {
  readonly kind = "connection_key" as const;
  readonly #key: ConnectionKey;

  constructor(key: ConnectionKey) {
    this.#key = key;
  }

  get principalId(): string {
    return this.#key.connectionId;
  }

  authorize(method: string, path: string, body: Buffer | undefined): string {
    return this.#key.signRequest({ method, path, body: body ?? Buffer.alloc(0) }).authorization;
  }

  toJSON(): Record<string, string> {
    return { kind: this.kind, connection_id: this.#key.connectionId };
  }

  [INSPECT](): string {
    return `SignatureAuthenticator(${this.#key.connectionId})`;
  }
}

const TOKEN_RE = /^(aipc|aipa)_[A-Za-z0-9_-]{16,512}$/;

export class BearerAuthenticator implements Authenticator {
  readonly kind = "bearer" as const;
  readonly principalId = undefined;
  readonly #token: string;

  constructor(token: string, locale?: Locale) {
    if (typeof token !== "string" || !TOKEN_RE.test(token.trim())) {
      throw new ConfigError("CONFIG_ERROR", msg(locale, "badToken"));
    }
    this.#token = token.trim();
  }

  authorize(): string {
    return `Bearer ${this.#token}`;
  }

  /** Token family only — never the token. */
  get tokenKind(): "aipc" | "aipa" {
    return this.#token.startsWith("aipc_") ? "aipc" : "aipa";
  }

  toJSON(): Record<string, string> {
    return { kind: this.kind, token: `${this.tokenKind}_[REDACTED]` };
  }

  [INSPECT](): string {
    return `BearerAuthenticator(${this.tokenKind}_[REDACTED])`;
  }
}
