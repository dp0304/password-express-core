// SPDX-License-Identifier: Apache-2.0
/**
 * `AIPass-Sig` request signing (CONTRACTS §1.6).
 *
 * ```
 * Authorization: AIPass-Sig kid=<principal id>, ts=<unix seconds>, nonce=<b64u 16 bytes>, sig=<b64u 64 bytes>
 * ```
 * String to sign (UTF-8, joined by "\n", no trailing newline):
 * `AIPASS-SIG-V1`, METHOD, path+query exactly as sent, ts, nonce, b64u(SHA-256(raw body)).
 *
 * Ed25519 comes from `node:crypto` (OpenSSL). Private key material lives only inside a
 * `KeyObject`; it is never exposed through `toString`, `toJSON` or `util.inspect`.
 */
import { createPrivateKey, createPublicKey, sign as cryptoSign, verify as cryptoVerify, randomBytes, type KeyObject } from "node:crypto";
import { b64uDecode, b64uEncode, randomB64u, sha256B64u } from "./encoding.js";

export const SIGNATURE_SCHEME = "AIPass-Sig";
export const STRING_TO_SIGN_VERSION = "AIPASS-SIG-V1";
/** Nonce length in bytes (CONTRACTS §1.6). */
export const NONCE_BYTES = 16;

const INSPECT = Symbol.for("nodejs.util.inspect.custom");
// PKCS#8 DER prefix for a raw 32-byte Ed25519 seed (RFC 8410).
const PKCS8_ED25519_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
// SPKI DER prefix for a raw 32-byte Ed25519 public key.
const SPKI_ED25519_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

function toBytes(value: Uint8Array | string): Buffer {
  return typeof value === "string" ? Buffer.from(value, "utf8") : Buffer.from(value.buffer, value.byteOffset, value.byteLength);
}

/** An Ed25519 signing key. The seed is held only inside an opaque `KeyObject`. */
export class SigningKey {
  readonly #key: KeyObject;
  /** Raw 32-byte public key, b64u. */
  readonly publicKey: string;

  private constructor(key: KeyObject) {
    this.#key = key;
    const jwk = createPublicKey(key).export({ format: "jwk" }) as { x?: string };
    if (typeof jwk.x !== "string") throw new TypeError("failed to derive Ed25519 public key");
    this.publicKey = jwk.x;
  }

  /** Generate a fresh key from the OS CSPRNG. */
  static generate(): SigningKey {
    const seed = randomBytes(32);
    try {
      return SigningKey.fromSeed(seed);
    } finally {
      seed.fill(0);
    }
  }

  /** Build from a 32-byte Ed25519 seed (raw bytes or b64u). */
  static fromSeed(seed: Uint8Array | string): SigningKey {
    const raw = typeof seed === "string" ? b64uDecode(seed) : Buffer.from(seed);
    try {
      if (raw.length !== 32) throw new TypeError("Ed25519 seed must be exactly 32 bytes");
      const der = Buffer.concat([PKCS8_ED25519_PREFIX, raw]);
      try {
        return new SigningKey(createPrivateKey({ key: der, format: "der", type: "pkcs8" }));
      } finally {
        der.fill(0);
      }
    } finally {
      raw.fill(0);
    }
  }

  /** Ed25519 signature (64 bytes). */
  sign(message: Uint8Array | string): Buffer {
    return cryptoSign(null, toBytes(message), this.#key);
  }

  /**
   * Export the raw 32-byte seed. Only used to persist a connection key file (0600);
   * callers must wipe the returned buffer (`buf.fill(0)`) once written.
   */
  exportSeed(): Buffer {
    const der = this.#key.export({ format: "der", type: "pkcs8" });
    try {
      return Buffer.from(der.subarray(der.length - 32));
    } finally {
      der.fill(0);
    }
  }

  toJSON(): Record<string, string> {
    return { type: "ed25519", public_key: this.publicKey };
  }

  toString(): string {
    return `SigningKey(ed25519, public_key=${this.publicKey})`;
  }

  [INSPECT](): string {
    return this.toString();
  }
}

/** Verify an Ed25519 signature against a raw b64u public key. */
export function verifySignature(publicKeyB64u: string, message: Uint8Array | string, signatureB64u: string): boolean {
  let pub: Buffer;
  let sig: Buffer;
  try {
    pub = b64uDecode(publicKeyB64u);
    sig = b64uDecode(signatureB64u);
  } catch {
    return false;
  }
  if (pub.length !== 32 || sig.length !== 64) return false;
  const key = createPublicKey({ key: Buffer.concat([SPKI_ED25519_PREFIX, pub]), format: "der", type: "spki" });
  return cryptoVerify(null, toBytes(message), key, sig);
}

/** A paired app connection: `conn_…` id + its Ed25519 key. */
export class ConnectionKey {
  readonly connectionId: string;
  readonly signingKey: SigningKey;

  constructor(connectionId: string, signingKey: SigningKey) {
    if (typeof connectionId !== "string" || !/^conn_[0-9a-z]{1,64}$/.test(connectionId)) {
      throw new TypeError("connection id must look like conn_<ulid>");
    }
    this.connectionId = connectionId;
    this.signingKey = signingKey;
  }

  static fromSeed(connectionId: string, seed: Uint8Array | string): ConnectionKey {
    return new ConnectionKey(connectionId, SigningKey.fromSeed(seed));
  }

  get publicKey(): string {
    return this.signingKey.publicKey;
  }

  /** Produce the `Authorization` header for one request. */
  signRequest(request: SignRequestInput): SignedRequest {
    return signRequest(this.connectionId, this.signingKey, request);
  }

  toJSON(): Record<string, string> {
    return { connection_id: this.connectionId, public_key: this.publicKey };
  }

  toString(): string {
    return `ConnectionKey(${this.connectionId}, public_key=${this.publicKey})`;
  }

  [INSPECT](): string {
    return this.toString();
  }
}

export interface SignRequestInput {
  method: string;
  /** Path + query exactly as sent on the wire, e.g. `/v1/resources?project_id=proj_…`. */
  path: string;
  /** Raw body bytes (empty / undefined → hash of the empty string). */
  body?: Uint8Array | string;
  /** Unix seconds; defaults to now. */
  ts?: number;
  /** b64u of 16 random bytes; defaults to a fresh CSPRNG nonce. Never reuse a nonce. */
  nonce?: string;
}

export interface SignedRequest {
  authorization: string;
  kid: string;
  ts: number;
  nonce: string;
  signature: string;
  bodySha256: string;
  stringToSign: string;
}

/** Build the canonical string to sign (CONTRACTS §1.6). */
export function buildStringToSign(input: { method: string; path: string; ts: number; nonce: string; bodySha256: string }): string {
  if (!Number.isSafeInteger(input.ts) || input.ts < 0) throw new TypeError("ts must be a non-negative integer (unix seconds)");
  if (!input.path.startsWith("/")) throw new TypeError("path must start with '/'");
  if (/[\r\n]/.test(input.path) || /[\r\n]/.test(input.nonce)) throw new TypeError("path/nonce must not contain newlines");
  return [STRING_TO_SIGN_VERSION, input.method.toUpperCase(), input.path, String(input.ts), input.nonce, input.bodySha256].join("\n");
}

/** Format the `Authorization` header value. */
export function formatAuthorization(parts: { kid: string; ts: number; nonce: string; sig: string }): string {
  return `${SIGNATURE_SCHEME} kid=${parts.kid}, ts=${parts.ts}, nonce=${parts.nonce}, sig=${parts.sig}`;
}

/** Parse an `AIPass-Sig` header (returns `null` if it is not one). Useful for servers and tests. */
export function parseAuthorization(header: string | undefined | null): { kid: string; ts: number; nonce: string; sig: string } | null {
  if (!header) return null;
  const prefix = `${SIGNATURE_SCHEME} `;
  if (!header.startsWith(prefix)) return null;
  const fields: Record<string, string> = {};
  for (const part of header.slice(prefix.length).split(",")) {
    const eq = part.indexOf("=");
    if (eq <= 0) return null;
    const name = part.slice(0, eq).trim();
    if (name in fields) return null;
    fields[name] = part.slice(eq + 1).trim();
  }
  const { kid, ts, nonce, sig } = fields;
  if (!kid || !ts || !nonce || !sig || !/^\d{1,15}$/.test(ts)) return null;
  return { kid, ts: Number(ts), nonce, sig };
}

/** Sign one request with `kid` + key. Low-level; most callers use `ConnectionKey.signRequest`. */
export function signRequest(kid: string, key: SigningKey, input: SignRequestInput): SignedRequest {
  const ts = input.ts ?? Math.floor(Date.now() / 1000);
  const nonce = input.nonce ?? randomB64u(NONCE_BYTES);
  const bodySha256 = sha256B64u(input.body === undefined ? Buffer.alloc(0) : toBytes(input.body));
  const stringToSign = buildStringToSign({ method: input.method, path: input.path, ts, nonce, bodySha256 });
  const signature = b64uEncode(key.sign(stringToSign));
  return {
    authorization: formatAuthorization({ kid, ts, nonce, sig: signature }),
    kid,
    ts,
    nonce,
    signature,
    bodySha256,
    stringToSign,
  };
}
