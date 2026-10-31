// SPDX-License-Identifier: Apache-2.0
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AIPassClient, ConnectionKey, SigningKey, type AIPassClientOptions } from "../src/index.js";
import { MockBroker } from "./mock-broker.js";

export interface Harness {
  broker: MockBroker;
  key: ConnectionKey;
  client: AIPassClient;
  cleanup: () => Promise<void>;
}

/** A mock broker on TCP plus a client paired to it with a fresh connection key. */
export async function tcpHarness(options: Partial<AIPassClientOptions> = {}): Promise<Harness> {
  const broker = new MockBroker();
  const url = await broker.listenTcp();
  const signingKey = SigningKey.generate();
  const connectionId = broker.addConnection(signingKey.publicKey);
  const key = new ConnectionKey(connectionId, signingKey);
  const client = new AIPassClient({ brokerUrl: url, connectionKey: key, ...options });
  return {
    broker,
    key,
    client,
    cleanup: async () => {
      client.close();
      await broker.close();
    },
  };
}

/** Short temp dir (unix socket paths must stay under ~104 bytes on macOS). */
export function shortTempDir(prefix = "aps-"): { dir: string; remove: () => void } {
  let base = tmpdir();
  if (base.length > 60) base = "/tmp";
  const dir = mkdtempSync(join(base, prefix));
  return { dir, remove: () => rmSync(dir, { recursive: true, force: true }) };
}
