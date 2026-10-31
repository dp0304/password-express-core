// SPDX-License-Identifier: Apache-2.0
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { AIPassClient, ConnectionKey, NetworkError, pair, SigningKey } from "../src/index.js";
import { LURE_RESOURCE, MockBroker } from "./mock-broker.js";
import { shortTempDir } from "./helpers.js";

describe("unix domain socket transport", () => {
  let broker: MockBroker;
  let tmp: { dir: string; remove: () => void };
  let socketPath: string;

  beforeEach(async () => {
    tmp = shortTempDir();
    socketPath = join(tmp.dir, "broker.sock");
    broker = new MockBroker();
    await broker.listenUnix(socketPath);
  });
  afterEach(async () => {
    await broker.close();
    tmp.remove();
  });

  it("works with unix:///abs/path.sock and with socketPath, signatures verified by the broker", async () => {
    const signingKey = SigningKey.generate();
    const id = broker.addConnection(signingKey.publicKey);
    const key = new ConnectionKey(id, signingKey);
    for (const client of [new AIPassClient({ brokerUrl: `unix://${socketPath}`, connectionKey: key }), new AIPassClient({ socketPath, connectionKey: key })]) {
      try {
        expect(client.brokerUrl).toBe(`unix://${socketPath}`);
        const res = await client.listResources({ service: "postgres" });
        expect(res.resources[0]?.alias).toBe("路亚站测试库");
        const op = await client.requestOperation({
          resource_id: LURE_RESOURCE.resource_id,
          operation: "postgres.query_view",
          parameters: { view: "analytics.subscription_daily", fields: ["day"] },
          idempotency_key: `uds-${Math.random()}`,
        });
        expect(op.status).toBe("approval_required");
        broker.decideOperation(op.operation_id, "succeeded");
        const done = await client.waitForOperation(op.operation_id, { intervalMs: 5, timeoutMs: 2000 });
        expect(done.status).toBe("succeeded");
        const sent = broker.requests.at(-1)!;
        expect(sent.principal).toBe(id);
        expect(sent.headers.host).toBe("localhost");
      } finally {
        client.close();
      }
    }
  });

  it("resolves AIPASS_BROKER_URL from the environment", async () => {
    const signingKey = SigningKey.generate();
    const id = broker.addConnection(signingKey.publicKey);
    const client = new AIPassClient({ connectionKey: new ConnectionKey(id, signingKey), env: { AIPASS_BROKER_URL: `unix://${socketPath}` } });
    try {
      expect((await client.health()).status).toBe("ok");
    } finally {
      client.close();
    }
  });

  it("pairs over the unix socket", async () => {
    broker.pairingDecisionAfterPolls = 1;
    const result = await pair({ socketPath, displayName: "uds agent", intervalMs: 5, maxIntervalMs: 10, jitter: 0 });
    expect(result.status).toBe("approved");
    try {
      expect((await result.client!.listResources()).resources.length).toBeGreaterThan(0);
    } finally {
      result.client?.close();
    }
  });

  it("a missing socket is a NetworkError (default socket path when nothing is configured)", async () => {
    const client = new AIPassClient({
      connectionKey: new ConnectionKey("conn_01jbz3k6w8a7m2q4t5v9x0y1z4", SigningKey.generate()),
      env: { AIPASS_HOME: join(tmp.dir, "home") },
      maxRetries: 0,
    });
    try {
      expect(client.brokerUrl).toBe(`unix://${join(tmp.dir, "home", "run", "broker.sock")}`);
      const err = await client.listResources().catch((e: unknown) => e);
      expect(err).toBeInstanceOf(NetworkError);
      expect((err as NetworkError).message).toContain("broker.sock");
    } finally {
      client.close();
    }
  });
});
