// SPDX-License-Identifier: Apache-2.0
/**
 * Encoding helpers. Binary values on the AI Pass wire are base64url without padding
 * ("b64u", CONTRACTS §1.2). Hashes are SHA-256.
 */
import { createHash, randomBytes } from "node:crypto";

const B64U_RE = /^[A-Za-z0-9_-]*$/;

/** Encode bytes as base64url without padding. */
export function b64uEncode(bytes: Uint8Array): string {
  return Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength).toString("base64url");
}

/**
 * Decode a base64url string (padding tolerated, but no other characters).
 * Throws `TypeError` on malformed input.
 */
export function b64uDecode(text: string): Buffer {
  const trimmed = text.trim().replace(/=+$/, "");
  if (!B64U_RE.test(trimmed) || trimmed.length % 4 === 1) {
    throw new TypeError("invalid base64url value");
  }
  return Buffer.from(trimmed, "base64url");
}

/** b64u(SHA-256(bytes)). */
export function sha256B64u(bytes: Uint8Array | string): string {
  return createHash("sha256").update(bytes).digest("base64url");
}

/** Random bytes from the OS CSPRNG, b64u-encoded. */
export function randomB64u(byteLength: number): string {
  return randomBytes(byteLength).toString("base64url");
}

/** Uniform float in [0, 1) from the OS CSPRNG (used for retry/poll jitter). */
export function randomUnit(): number {
  return randomBytes(4).readUInt32BE(0) / 0x1_0000_0000;
}
