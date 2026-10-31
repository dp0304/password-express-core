// SPDX-License-Identifier: Apache-2.0
import { existsSync, readFileSync } from "node:fs";
import { inspect } from "node:util";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  AIPassClient,
  buildStringToSign,
  ConnectionKey,
  formatAuthorization,
  parseAuthorization,
  sha256B64u,
  signRequest,
  SigningKey,
  verifySignature,
} from "../src/index.js";
import { MockBroker } from "./mock-broker.js";

/** CONTRACTS §1.6 test vector (verbatim). */
const VECTOR = {
  seed: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
  public_key: "A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg",
  kid: "conn_01jbz3k6w8a7m2q4t5v9x0y1z4",
  ts: 1793318400,
  nonce: "qqqqqqqqqqqqqqqqqqqqqg",
  cases: [
    {
      method: "POST",
      path: "/v1/operations",
      body: '{"resource_id":"res_01jbz3k6w8a7m2q4t5v9x0y1z2","operation":"postgres.query_view","parameters":{"view":"analytics.subscription_daily","fields":["day","plan","subscriptions"],"period_days":30},"idempotency_key":"subscription-summary-request-001"}',
      body_sha256: "xR8hGf1lWFHmtsMZF81X1VBrAPQQyuFe2wpLmxcaLjE",
      string_to_sign:
        "AIPASS-SIG-V1\nPOST\n/v1/operations\n1793318400\nqqqqqqqqqqqqqqqqqqqqqg\nxR8hGf1lWFHmtsMZF81X1VBrAPQQyuFe2wpLmxcaLjE",
      signature: "bkY5XhOuTqE-0g0GA_J5SPOZgk67xYrVj77Koc0EBsWGH-APHWHBuGx1MojhxBSiYyV4Cj2Llu1xmAyRITt1Aw",
    },
    {
      method: "GET",
      path: "/v1/resources?project_id=proj_01jbz3k6w8a7m2q4t5v9x0y1z3",
      body: "",
      body_sha256: "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU",
      string_to_sign:
        "AIPASS-SIG-V1\nGET\n/v1/resources?project_id=proj_01jbz3k6w8a7m2q4t5v9x0y1z3\n1793318400\nqqqqqqqqqqqqqqqqqqqqqg\n47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU",
      signature: "z-FXrTabpsAztih0b7vQ-r9wqLCSnkTZtGHBrGgL9U5aT6Nt4usP6qgRQb_FBzyl_DQ0xrNb0oSuphvOvmOjDg",
    },
  ],
};

type Vector = typeof VECTOR;

function checkVector(v: Vector): void {
  const key = SigningKey.fromSeed(v.seed);
  expect(key.publicKey).toBe(v.public_key);
  for (const c of v.cases) {
    expect(sha256B64u(Buffer.from(c.body, "utf8"))).toBe(c.body_sha256);
    expect(buildStringToSign({ method: c.method, path: c.path, ts: v.ts, nonce: v.nonce, bodySha256: c.body_sha256 })).toBe(c.string_to_sign);
    const signed = signRequest(v.kid, key, { method: c.method, path: c.path, body: c.body, ts: v.ts, nonce: v.nonce });
    expect(signed.stringToSign).toBe(c.string_to_sign);
    expect(signed.bodySha256).toBe(c.body_sha256);
    expect(signed.signature).toBe(c.signature);
    expect(signed.authorization).toBe(`AIPass-Sig kid=${v.kid}, ts=${v.ts}, nonce=${v.nonce}, sig=${c.signature}`);
    expect(verifySignature(v.public_key, c.string_to_sign, c.signature)).toBe(true);
  }
}

describe("AIPass-Sig test vector (CONTRACTS §1.6)", () => {
  it("reproduces public key, body hashes, strings to sign and signatures exactly", () => {
    checkVector(VECTOR);
  });

  it("matches open-source/test-vectors/request-signing.json when present", () => {
    const shared = join(__dirname, "..", "..", "..", "test-vectors", "request-signing.json");
    if (!existsSync(shared)) {
      // The shared file is produced by the foundation/types crate; the inline copy above is authoritative here.
      return;
    }
    const doc = JSON.parse(readFileSync(shared, "utf8")) as Vector;
    checkVector(doc);
  });

  it("ConnectionKey signs the same way and verifies; tampering fails", () => {
    const key = ConnectionKey.fromSeed(VECTOR.kid, VECTOR.seed);
    const c = VECTOR.cases[0]!;
    const signed = key.signRequest({ method: "post", path: c.path, body: Buffer.from(c.body), ts: VECTOR.ts, nonce: VECTOR.nonce });
    expect(signed.signature).toBe(c.signature);
    expect(verifySignature(key.publicKey, c.string_to_sign.replace("POST", "GET"), c.signature)).toBe(false);
    expect(verifySignature(key.publicKey, c.string_to_sign, `${c.signature.slice(0, -2)}AA`)).toBe(false);
    expect(verifySignature("short", c.string_to_sign, c.signature)).toBe(false);
  });

  it("fresh nonces are 16 CSPRNG bytes and never repeat", () => {
    const key = SigningKey.generate();
    const seen = new Set<string>();
    for (let i = 0; i < 200; i += 1) {
      const s = signRequest("conn_x", key, { method: "GET", path: "/v1/resources" });
      expect(Buffer.from(s.nonce, "base64url")).toHaveLength(16);
      seen.add(s.nonce);
    }
    expect(seen.size).toBe(200);
  });

  it("parses and formats the header", () => {
    const header = formatAuthorization({ kid: VECTOR.kid, ts: VECTOR.ts, nonce: VECTOR.nonce, sig: "abc" });
    expect(parseAuthorization(header)).toEqual({ kid: VECTOR.kid, ts: VECTOR.ts, nonce: VECTOR.nonce, sig: "abc" });
    expect(parseAuthorization("Bearer aipc_x")).toBeNull();
    expect(parseAuthorization("AIPass-Sig kid=a, kid=b, ts=1, nonce=n, sig=s")).toBeNull();
    expect(parseAuthorization("AIPass-Sig kid=a, ts=notanumber, nonce=n, sig=s")).toBeNull();
  });

  it("rejects malformed inputs", () => {
    expect(() => SigningKey.fromSeed("AAEC")).toThrow(TypeError);
    expect(() => SigningKey.fromSeed("not base64url!")).toThrow(TypeError);
    expect(() => buildStringToSign({ method: "GET", path: "no-slash", ts: 1, nonce: "n", bodySha256: "h" })).toThrow(TypeError);
    expect(() => buildStringToSign({ method: "GET", path: "/a\nb", ts: 1, nonce: "n", bodySha256: "h" })).toThrow(TypeError);
    expect(() => buildStringToSign({ method: "GET", path: "/a", ts: 1.5, nonce: "n", bodySha256: "h" })).toThrow(TypeError);
    expect(() => new ConnectionKey("dev_123", SigningKey.generate())).toThrow(TypeError);
  });

  it("never exposes the seed through inspect / JSON / toString", () => {
    const key = ConnectionKey.fromSeed(VECTOR.kid, VECTOR.seed);
    const seedHex = Buffer.from(VECTOR.seed, "base64url").toString("hex");
    for (const text of [inspect(key, { depth: 10, showHidden: true }), JSON.stringify(key), String(key), inspect(key.signingKey, { showHidden: true })]) {
      expect(text).not.toContain(VECTOR.seed);
      expect(text).not.toContain(seedHex);
    }
    expect(JSON.stringify(key)).toContain(VECTOR.public_key);
  });

  it("exportSeed round-trips (used only for the 0600 key file)", () => {
    const key = SigningKey.fromSeed(VECTOR.seed);
    const seed = key.exportSeed();
    expect(seed.toString("base64url")).toBe(VECTOR.seed);
    seed.fill(0);
  });
});

describe("end-to-end: client body bytes + signature match the vector", () => {
  let broker: MockBroker | undefined;
  afterEach(async () => {
    await broker?.close();
    broker = undefined;
  });

  it("requestOperation sends exactly the vector body and a signature the broker accepts", async () => {
    broker = new MockBroker();
    const url = await broker.listenTcp();
    const key = ConnectionKey.fromSeed(VECTOR.kid, VECTOR.seed);
    broker.addConnection(key.publicKey, VECTOR.kid);
    const client = new AIPassClient({ brokerUrl: url, connectionKey: key });
    try {
      const op = await client.requestOperation({
        resource_id: "res_01jbz3k6w8a7m2q4t5v9x0y1z2",
        operation: "postgres.query_view",
        parameters: { view: "analytics.subscription_daily", fields: ["day", "plan", "subscriptions"], period_days: 30 },
        idempotency_key: "subscription-summary-request-001",
      });
      expect(op.status).toBe("approval_required");
      const sent = broker.requests.at(-1)!;
      const c = VECTOR.cases[0]!;
      expect(sent.url).toBe(c.path);
      expect(sent.body.toString("utf8")).toBe(c.body);
      // Re-signing the bytes we actually sent at the vector's ts/nonce reproduces the vector signature.
      const resigned = key.signRequest({ method: sent.method, path: sent.url, body: sent.body, ts: VECTOR.ts, nonce: VECTOR.nonce });
      expect(resigned.signature).toBe(c.signature);

      await client.listResources({ project_id: "proj_01jbz3k6w8a7m2q4t5v9x0y1z3" });
      expect(broker.requests.at(-1)!.url).toBe(VECTOR.cases[1]!.path);
    } finally {
      client.close();
    }
  });
});
