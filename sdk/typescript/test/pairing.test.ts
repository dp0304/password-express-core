// SPDX-License-Identifier: Apache-2.0
import { existsSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { AbortedError, AIPassClient, ConfigError, InvalidRequestError, pair, parseAuthorization, startPairing, type PairingInfo } from "../src/index.js";
import { MockBroker } from "./mock-broker.js";
import { shortTempDir } from "./helpers.js";

const FAST = { intervalMs: 5, maxIntervalMs: 10, jitter: 0 };

describe("pairing (host_type=sdk)", () => {
  let broker: MockBroker;
  let tmp: { dir: string; remove: () => void };
  beforeEach(async () => {
    broker = new MockBroker();
    await broker.listenTcp();
    tmp = shortTempDir();
  });
  afterEach(async () => {
    await broker.close();
    tmp.remove();
  });

  it("returns the pairing code, polls until approved, saves the key 0600, and the key works", async () => {
    broker.pairingDecisionAfterPolls = 3;
    const keyPath = join(tmp.dir, "keys", "lure-agent.key");
    const codes: PairingInfo[] = [];
    const result = await pair({ brokerUrl: broker.url, displayName: "路亚站分析 Agent", keyPath, onPairingCode: (i) => void codes.push(i), ...FAST });
    try {
      expect(codes).toHaveLength(1);
      expect(codes[0]!.pairing_code).toMatch(/^\d{6}$/);
      expect(result).toMatchObject({ status: "approved", timedOut: false, pairingCode: codes[0]!.pairing_code, keyPath });
      expect(result.connectionId).toMatch(/^conn_/);

      // Pairing request body.
      const start = broker.requests.find((r) => r.url === "/v1/connections/pair")!;
      const body = JSON.parse(start.body.toString("utf8"));
      expect(body).toEqual({ host_type: "sdk", display_name: "路亚站分析 Agent", transport: "sdk", public_key: result.connectionKey!.publicKey });
      expect(start.headers.authorization).toBeUndefined();

      // Status polls are signed by the pending key with kid = connection_id.
      const polls = broker.requests.filter((r) => r.url.startsWith("/v1/connections/pair/"));
      expect(polls).toHaveLength(3);
      for (const p of polls) expect(parseAuthorization(p.headers.authorization as string)?.kid).toBe(result.connectionId);

      // Key file: 0600, JSON format, contains the seed (and nothing pretends otherwise).
      expect(statSync(keyPath).mode & 0o777).toBe(0o600);
      expect(statSync(join(tmp.dir, "keys")).mode & 0o777).toBe(0o700);
      const doc = JSON.parse(readFileSync(keyPath, "utf8"));
      expect(doc).toMatchObject({
        format: "aipass-connection-key-1",
        connection_id: result.connectionId,
        public_key: result.connectionKey!.publicKey,
        broker_url: broker.url,
        host_type: "sdk",
        display_name: "路亚站分析 Agent",
      });
      expect(Buffer.from(doc.seed, "base64url")).toHaveLength(32);

      // The returned client and a client loaded from the file both work.
      expect((await result.client!.listResources()).resources.length).toBe(3);
      const fromFile = AIPassClient.fromKeyFile(keyPath);
      try {
        expect(fromFile.connectionId).toBe(result.connectionId);
        expect(fromFile.brokerUrl).toBe(broker.url); // broker_url from the key file
        expect((await fromFile.listResources()).resources.length).toBe(3);
      } finally {
        fromFile.close();
      }
    } finally {
      result.client?.close();
    }
  });

  it("denied: no key file is written and no client is returned", async () => {
    broker.pairingDecisionAfterPolls = 1;
    broker.pairingDecision = "denied";
    const keyPath = join(tmp.dir, "denied.key");
    const result = await pair({ brokerUrl: broker.url, displayName: "agent", keyPath, ...FAST });
    expect(result.status).toBe("denied");
    expect(result.client).toBeUndefined();
    expect(result.connectionKey).toBeUndefined();
    expect(existsSync(keyPath)).toBe(false);
  });

  it("expired: reported as expired, never approved", async () => {
    broker.pairingDecisionAfterPolls = 2;
    broker.pairingDecision = "expired";
    const result = await pair({ brokerUrl: broker.url, displayName: "agent", keyPath: join(tmp.dir, "e.key"), ...FAST });
    expect(result.status).toBe("expired");
    expect(existsSync(join(tmp.dir, "e.key"))).toBe(false);
  });

  it("local wait timeout leaves the status pending (timedOut) — never approved", async () => {
    const result = await pair({ brokerUrl: broker.url, displayName: "agent", keyPath: join(tmp.dir, "t.key"), timeoutMs: 60, ...FAST });
    expect(result).toMatchObject({ status: "pending", timedOut: true });
    expect(existsSync(join(tmp.dir, "t.key"))).toBe(false);
  });

  it("two-step API: startPairing → show code → session.wait → saveKey refuses to clobber", async () => {
    const session = await startPairing({ brokerUrl: broker.url, displayName: "two-step", hostType: "custom" });
    try {
      expect(session.pairingCode).toMatch(/^\d{6}$/);
      expect((await session.poll()).status).toBe("pending");
      broker.pairingDecisionAfterPolls = 2;
      const result = await session.wait(FAST);
      expect(result.status).toBe("approved");
      const keyPath = join(tmp.dir, "two.key");
      writeFileSync(keyPath, "existing", { mode: 0o600 });
      expect(() => session.saveKey(keyPath)).toThrow(ConfigError);
      expect(readFileSync(keyPath, "utf8")).toBe("existing");
      session.saveKey(keyPath, { overwrite: true });
      expect(JSON.parse(readFileSync(keyPath, "utf8")).connection_id).toBe(session.connectionId);
      expect(statSync(keyPath).mode & 0o777).toBe(0o600);
      const body = JSON.parse(broker.requests.find((r) => r.url === "/v1/connections/pair")!.body.toString("utf8"));
      expect(body.host_type).toBe("custom");
    } finally {
      session.close();
    }
  });

  it("abort during the wait", async () => {
    const controller = new AbortController();
    setTimeout(() => controller.abort(), 50);
    await expect(pair({ brokerUrl: broker.url, displayName: "agent", signal: controller.signal, intervalMs: 1000 })).rejects.toBeInstanceOf(AbortedError);
  });

  it("validates displayName / hostType", async () => {
    await expect(startPairing({ brokerUrl: broker.url, displayName: "  " })).rejects.toBeInstanceOf(InvalidRequestError);
    await expect(startPairing({ brokerUrl: broker.url, displayName: "x", hostType: "evil" as never })).rejects.toBeInstanceOf(InvalidRequestError);
  });
});
