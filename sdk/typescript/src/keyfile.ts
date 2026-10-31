// SPDX-License-Identifier: Apache-2.0
/**
 * Connection key files. Written atomically with mode 0600 (parent directory created 0700);
 * loading refuses group/world-readable files on POSIX.
 *
 * Format written by this SDK (JSON, UTF-8):
 * ```json
 * {"format":"aipass-connection-key-1","connection_id":"conn_…","seed":"<b64u 32B>",
 *  "public_key":"<b64u 32B>","broker_url":"…","host_type":"sdk","display_name":"…","created_at":"…Z"}
 * ```
 * The loader also accepts JSON using `private_key` / `secret_key` instead of `seed` (32-byte seed,
 * or 64-byte seed‖public key), or a plain-text file holding only the b64u seed whose file name is
 * `<conn_id>.key` (the MCP bridge layout `<AIPASS_HOME>/connections/<conn_id>.key`).
 */
import { randomBytes } from "node:crypto";
import { chmodSync, closeSync, fsyncSync, linkSync, mkdirSync, openSync, readFileSync, renameSync, statSync, unlinkSync, writeSync } from "node:fs";
import { basename, dirname } from "node:path";
import { b64uDecode, b64uEncode } from "./encoding.js";
import { ConfigError, IntegrityFailedError } from "./errors.js";
import { msg } from "./messages.js";
import { ConnectionKey, SigningKey } from "./signing.js";
import type { Locale } from "./types.js";

export const KEY_FILE_FORMAT = "aipass-connection-key-1";

export interface KeyFileMetadata {
  broker_url?: string;
  host_type?: string;
  display_name?: string;
}

export interface SaveKeyOptions {
  /** Replace an existing file (default false: refuse). */
  overwrite?: boolean;
  locale?: Locale;
}

export interface LoadKeyOptions {
  /** Skip the 0600 permission check (not recommended). */
  allowInsecurePermissions?: boolean;
  /** Override / supply the connection id (e.g. for raw seed files). */
  connectionId?: string;
  locale?: Locale;
}

export interface LoadedKeyFile {
  key: ConnectionKey;
  metadata: KeyFileMetadata & { created_at?: string };
}

/** Persist a connection key; returns the path written. */
export function saveConnectionKey(path: string, key: ConnectionKey, metadata: KeyFileMetadata = {}, options: SaveKeyOptions = {}): string {
  const seed = key.signingKey.exportSeed();
  const doc: Record<string, string> = {
    format: KEY_FILE_FORMAT,
    connection_id: key.connectionId,
    seed: b64uEncode(seed),
    public_key: key.publicKey,
    created_at: new Date().toISOString().replace(/\.\d{3}Z$/, "Z"),
  };
  seed.fill(0);
  if (metadata.broker_url) doc.broker_url = metadata.broker_url;
  if (metadata.host_type) doc.host_type = metadata.host_type;
  if (metadata.display_name) doc.display_name = metadata.display_name;
  const payload = Buffer.from(`${JSON.stringify(doc, null, 2)}\n`, "utf8");

  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const tmp = `${path}.tmp-${randomBytes(6).toString("hex")}`;
  const fd = openSync(tmp, "wx", 0o600);
  try {
    writeSync(fd, payload);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
    payload.fill(0);
  }
  try {
    chmodSync(tmp, 0o600);
    if (options.overwrite) {
      renameSync(tmp, path);
    } else {
      try {
        // link() fails with EEXIST instead of silently replacing: atomic no-clobber publish.
        linkSync(tmp, path);
      } catch (err) {
        if ((err as NodeJS.ErrnoException).code === "EEXIST") {
          throw new ConfigError("CONFIG_ERROR", msg(options.locale, "keyFileExists", { path }));
        }
        throw err;
      } finally {
        unlinkSync(tmp);
      }
    }
  } catch (err) {
    try {
      unlinkSync(tmp);
    } catch {
      // already gone
    }
    throw err;
  }
  return path;
}

function decodeKeyMaterial(value: string, locale: Locale | undefined): { seed: Buffer; embeddedPublic?: string } {
  let raw: Buffer;
  try {
    raw = b64uDecode(value);
  } catch {
    throw new ConfigError("CONFIG_ERROR", msg(locale, "keyFileInvalid", { detail: "key is not base64url" }));
  }
  if (raw.length === 32) return { seed: raw };
  if (raw.length === 64) {
    const seed = Buffer.from(raw.subarray(0, 32));
    const embeddedPublic = b64uEncode(raw.subarray(32));
    raw.fill(0);
    return { seed, embeddedPublic };
  }
  raw.fill(0);
  throw new ConfigError("CONFIG_ERROR", msg(locale, "keyFileInvalid", { detail: "key must be a 32-byte Ed25519 seed" }));
}

/** Load a connection key file (see module docs for accepted formats). */
export function loadConnectionKey(path: string, options: LoadKeyOptions = {}): LoadedKeyFile {
  const { locale } = options;
  let st;
  try {
    st = statSync(path);
  } catch {
    throw new ConfigError("CONFIG_ERROR", msg(locale, "keyFileMissing", { path }));
  }
  if (process.platform !== "win32" && !options.allowInsecurePermissions && (st.mode & 0o077) !== 0) {
    throw new ConfigError("CONFIG_ERROR", msg(locale, "keyFilePerms", { path, mode: `0${(st.mode & 0o777).toString(8)}` }));
  }
  const text = readFileSync(path, "utf8").trim();
  let connectionId = options.connectionId;
  let material: string | undefined;
  let declaredPublic: string | undefined;
  const metadata: LoadedKeyFile["metadata"] = {};
  if (text.startsWith("{")) {
    let doc: Record<string, unknown>;
    try {
      doc = JSON.parse(text) as Record<string, unknown>;
    } catch {
      throw new ConfigError("CONFIG_ERROR", msg(locale, "keyFileInvalid", { detail: "malformed JSON" }));
    }
    const pick = (...names: string[]) => {
      for (const n of names) if (typeof doc[n] === "string" && doc[n] !== "") return doc[n] as string;
      return undefined;
    };
    connectionId ??= pick("connection_id", "kid", "id");
    material = pick("seed", "private_key", "secret_key", "ed25519_seed");
    declaredPublic = pick("public_key");
    const brokerUrl = pick("broker_url");
    const hostType = pick("host_type");
    const displayName = pick("display_name");
    const createdAt = pick("created_at");
    if (brokerUrl) metadata.broker_url = brokerUrl;
    if (hostType) metadata.host_type = hostType;
    if (displayName) metadata.display_name = displayName;
    if (createdAt) metadata.created_at = createdAt;
  } else {
    material = text;
  }
  if (!connectionId) {
    const stem = basename(path).replace(/\.(key|json)$/, "");
    if (stem.startsWith("conn_")) connectionId = stem;
  }
  if (!material) throw new ConfigError("CONFIG_ERROR", msg(locale, "keyFileInvalid", { detail: "missing seed" }));
  if (!connectionId) throw new ConfigError("CONFIG_ERROR", msg(locale, "keyFileInvalid", { detail: "missing connection_id" }));
  const { seed, embeddedPublic } = decodeKeyMaterial(material, locale);
  let signingKey: SigningKey;
  try {
    signingKey = SigningKey.fromSeed(seed);
  } finally {
    seed.fill(0);
  }
  for (const expected of [declaredPublic, embeddedPublic]) {
    if (expected !== undefined && expected.replace(/=+$/, "") !== signingKey.publicKey) {
      throw new IntegrityFailedError("INTEGRITY_FAILED", msg(locale, "keyMismatch"));
    }
  }
  let key: ConnectionKey;
  try {
    key = new ConnectionKey(connectionId, signingKey);
  } catch {
    throw new ConfigError("CONFIG_ERROR", msg(locale, "keyFileInvalid", { detail: "connection_id must look like conn_<ulid>" }));
  }
  return { key, metadata };
}
