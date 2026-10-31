// SPDX-License-Identifier: Apache-2.0
import { chmodSync, mkdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  AIPassClient,
  ConfigError,
  ConnectionKey,
  IntegrityFailedError,
  isLoopbackHost,
  loadConnectionKey,
  parseBrokerUrl,
  resolveBrokerUrl,
  saveConnectionKey,
  SigningKey,
} from "../src/index.js";
import { shortTempDir } from "./helpers.js";

const SEED = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
const PUB = "A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg";
const KID = "conn_01jbz3k6w8a7m2q4t5v9x0y1z4";

describe("connection key files", () => {
  let tmp: { dir: string; remove: () => void };
  beforeEach(() => {
    tmp = shortTempDir();
  });
  afterEach(() => tmp.remove());

  it("save → load round-trips with 0600 and metadata", () => {
    const path = join(tmp.dir, "a", "b", "k.json");
    saveConnectionKey(path, ConnectionKey.fromSeed(KID, SEED), { broker_url: "http://127.0.0.1:7878", display_name: "x" });
    expect(statSync(path).mode & 0o777).toBe(0o600);
    const loaded = loadConnectionKey(path);
    expect(loaded.key.connectionId).toBe(KID);
    expect(loaded.key.publicKey).toBe(PUB);
    expect(loaded.metadata.broker_url).toBe("http://127.0.0.1:7878");
    expect(loaded.metadata.created_at).toMatch(/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/);
  });

  it("refuses group/world-readable key files unless explicitly allowed", () => {
    const path = join(tmp.dir, "k.json");
    saveConnectionKey(path, ConnectionKey.fromSeed(KID, SEED));
    chmodSync(path, 0o644);
    expect(() => loadConnectionKey(path)).toThrow(ConfigError);
    expect(() => loadConnectionKey(path)).toThrow(/chmod 600/);
    expect(() => new AIPassClient({ brokerUrl: "http://127.0.0.1:1", keyFile: path })).toThrow(ConfigError);
    expect(loadConnectionKey(path, { allowInsecurePermissions: true }).key.publicKey).toBe(PUB);
  });

  it("accepts a raw b64u seed file named <conn_id>.key (MCP bridge layout)", () => {
    const dir = join(tmp.dir, "connections");
    mkdirSync(dir);
    const path = join(dir, `${KID}.key`);
    writeFileSync(path, `${SEED}\n`, { mode: 0o600 });
    const loaded = loadConnectionKey(path);
    expect(loaded.key.connectionId).toBe(KID);
    expect(loaded.key.publicKey).toBe(PUB);
  });

  it("accepts JSON with private_key as 64-byte seed‖public and verifies the embedded public key", () => {
    const path = join(tmp.dir, "k64.json");
    const both = Buffer.concat([Buffer.from(SEED, "base64url"), Buffer.from(PUB, "base64url")]).toString("base64url");
    writeFileSync(path, JSON.stringify({ kid: KID, private_key: both }), { mode: 0o600 });
    expect(loadConnectionKey(path).key.publicKey).toBe(PUB);
    const wrong = Buffer.concat([Buffer.from(SEED, "base64url"), Buffer.alloc(32, 7)]).toString("base64url");
    writeFileSync(path, JSON.stringify({ kid: KID, private_key: wrong }), { mode: 0o600 });
    expect(() => loadConnectionKey(path)).toThrow(IntegrityFailedError);
  });

  it("detects a public_key that does not match the seed", () => {
    const path = join(tmp.dir, "bad.json");
    writeFileSync(path, JSON.stringify({ connection_id: KID, seed: SEED, public_key: SigningKey.generate().publicKey }), { mode: 0o600 });
    expect(() => loadConnectionKey(path)).toThrow(IntegrityFailedError);
  });

  it("rejects malformed files with ConfigError", () => {
    const cases: Array<[string, string]> = [
      ["nojson.json", "{not json"],
      ["noseed.json", JSON.stringify({ connection_id: KID })],
      ["noid.json", JSON.stringify({ seed: SEED })],
      ["badid.json", JSON.stringify({ connection_id: "dev_123", seed: SEED })],
      ["short.json", JSON.stringify({ connection_id: KID, seed: "AAEC" })],
    ];
    for (const [name, content] of cases) {
      const path = join(tmp.dir, name);
      writeFileSync(path, content, { mode: 0o600 });
      expect(() => loadConnectionKey(path), name).toThrow(ConfigError);
    }
    expect(() => loadConnectionKey(join(tmp.dir, "missing.key"))).toThrow(ConfigError);
  });

  it("never overwrites unless asked", () => {
    const path = join(tmp.dir, "k.json");
    saveConnectionKey(path, ConnectionKey.fromSeed(KID, SEED));
    expect(() => saveConnectionKey(path, new ConnectionKey(KID, SigningKey.generate()))).toThrow(ConfigError);
    expect(JSON.parse(readFileSync(path, "utf8")).public_key).toBe(PUB);
    saveConnectionKey(path, new ConnectionKey(KID, SigningKey.generate()), {}, { overwrite: true });
    expect(JSON.parse(readFileSync(path, "utf8")).public_key).not.toBe(PUB);
  });
});

describe("broker URLs", () => {
  it("parses http, https with base path, and unix forms", () => {
    expect(parseBrokerUrl("http://127.0.0.1:7878")).toMatchObject({ kind: "tcp", protocol: "http:", hostname: "127.0.0.1", port: 7878, basePath: "" });
    expect(parseBrokerUrl("https://node.example.com/aipass/")).toMatchObject({ kind: "tcp", port: 443, basePath: "/aipass", display: "https://node.example.com/aipass" });
    expect(parseBrokerUrl("unix:///tmp/x/broker.sock")).toMatchObject({ kind: "unix", socketPath: "/tmp/x/broker.sock" });
    expect(parseBrokerUrl("unix:/tmp/y.sock")).toMatchObject({ kind: "unix", socketPath: "/tmp/y.sock" });
    expect(parseBrokerUrl("http://[::1]:7878")).toMatchObject({ hostname: "::1" });
  });

  it("refuses credentials in URLs, odd schemes, relative sockets and remote plaintext http", () => {
    for (const bad of ["ftp://x", "http://user:pass@127.0.0.1", "http://127.0.0.1/?q=1", "unix://relative.sock", "", "not a url"]) {
      expect(() => parseBrokerUrl(bad), bad).toThrow(ConfigError);
    }
    expect(() => parseBrokerUrl("http://node.example.com:7878")).toThrow(/https/);
    expect(parseBrokerUrl("http://node.example.com:7878", { allowInsecureHttp: true })).toMatchObject({ hostname: "node.example.com" });
    expect(isLoopbackHost("localhost") && isLoopbackHost("127.9.0.1") && isLoopbackHost("[::1]") && isLoopbackHost("a.localhost")).toBe(true);
    expect(isLoopbackHost("10.0.0.1")).toBe(false);
  });

  it("resolution order: explicit > AIPASS_BROKER_URL > broker.json > default socket", () => {
    const tmp = shortTempDir();
    try {
      const home = join(tmp.dir, "home");
      expect(resolveBrokerUrl(undefined, { AIPASS_HOME: home })).toBe(`unix://${join(home, "run", "broker.sock")}`);
      mkdirSync(home);
      writeFileSync(join(home, "broker.json"), JSON.stringify({ broker_url: "http://127.0.0.1:9999" }));
      expect(resolveBrokerUrl(undefined, { AIPASS_HOME: home })).toBe("http://127.0.0.1:9999");
      expect(resolveBrokerUrl(undefined, { AIPASS_HOME: home, AIPASS_BROKER_URL: "unix:///s.sock" })).toBe("unix:///s.sock");
      expect(resolveBrokerUrl("https://x.example", { AIPASS_HOME: home, AIPASS_BROKER_URL: "unix:///s.sock" })).toBe("https://x.example");
      writeFileSync(join(home, "broker.json"), "garbage");
      expect(resolveBrokerUrl(undefined, { AIPASS_HOME: home })).toBe(`unix://${join(home, "run", "broker.sock")}`);
    } finally {
      tmp.remove();
    }
  });
});
