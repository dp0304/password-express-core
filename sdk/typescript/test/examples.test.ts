// SPDX-License-Identifier: Apache-2.0
// Runs the example scripts as real child processes against the mock broker (requires `pnpm build`).
import { execFile } from "node:child_process";
import { existsSync, statSync } from "node:fs";
import { join } from "node:path";
import { promisify } from "node:util";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { ConnectionKey, saveConnectionKey, SigningKey } from "../src/index.js";
import { MockBroker } from "./mock-broker.js";
import { shortTempDir } from "./helpers.js";

const run = promisify(execFile);
const ROOT = join(__dirname, "..");
const built = existsSync(join(ROOT, "dist", "index.js"));

describe.skipIf(!built)("examples (node scripts)", () => {
  let broker: MockBroker;
  let tmp: { dir: string; remove: () => void };
  let keyFile: string;

  beforeEach(async () => {
    broker = new MockBroker();
    await broker.listenTcp();
    tmp = shortTempDir();
    const sk = SigningKey.generate();
    keyFile = join(tmp.dir, "lure-agent.key");
    saveConnectionKey(keyFile, new ConnectionKey(broker.addConnection(sk.publicKey), sk), { broker_url: broker.url });
  });
  afterEach(async () => {
    await broker.close();
    tmp.remove();
  });

  const env = (extra: Record<string, string> = {}) => ({ PATH: process.env.PATH ?? "", HOME: tmp.dir, AIPASS_HOME: join(tmp.dir, "home"), ...extra });

  it("lure-store.mjs: approval_required → user approves → summary per plan", async () => {
    broker.approveOperationsAfterPolls = 1;
    const { stdout } = await run(process.execPath, [join(ROOT, "examples", "lure-store.mjs")], {
      env: env({ AIPASS_BROKER_URL: broker.url, AIPASS_KEY_FILE: keyFile }),
      timeout: 30_000,
    });
    expect(stdout).toContain("路亚站测试库");
    expect(stdout).toContain("请在已配对的手机或可信客户端批准本次访问。");
    expect(stdout).toMatch(/monthly: 21/);
    expect(stdout).toMatch(/yearly: 3/);
    const op = JSON.parse(broker.requests.find((r) => r.url === "/v1/operations")!.body.toString("utf8"));
    expect(op).toMatchObject({ operation: "postgres.query_view", parameters: { view: "analytics.subscription_daily", period_days: 30 } });
    expect(op.idempotency_key).toMatch(/^lure-subscription-summary-\d{4}-\d\d-\d\d$/);
  });

  it("lure-store.mjs in English", async () => {
    broker.granted.add(`${[...broker.connections.keys()][0]}:res_01jbz3k6w8a7m2q4t5v9x0y1z2`);
    const { stdout } = await run(process.execPath, [join(ROOT, "examples", "lure-store.mjs")], {
      env: env({ AIPASS_BROKER_URL: broker.url, AIPASS_KEY_FILE: keyFile, AIPASS_LOCALE: "en" }),
      timeout: 30_000,
    });
    expect(stdout).toContain("New subscriptions, last 30 days (3 rows):");
  });

  it("pair.mjs writes a 0600 key only after approval", async () => {
    broker.pairingDecisionAfterPolls = 1;
    const out = join(tmp.dir, "paired.key");
    const { stdout } = await run(process.execPath, [join(ROOT, "examples", "pair.mjs"), out, "路亚站分析 Agent"], {
      env: env({ AIPASS_BROKER_URL: broker.url }),
      timeout: 30_000,
    });
    expect(stdout).toMatch(/配对码：\d{6}/);
    expect(stdout).toContain("已批准");
    expect(statSync(out).mode & 0o777).toBe(0o600);
  });

  it("tool-calling.mjs dispatches tool calls and prints provider payloads", async () => {
    const { stdout } = await run(process.execPath, [join(ROOT, "examples", "tool-calling.mjs")], {
      env: env({ AIPASS_BROKER_URL: broker.url, AIPASS_KEY_FILE: keyFile }),
      timeout: 30_000,
    });
    expect(stdout).toContain("resources_list, operations_request, operations_status, operations_cancel, access_request, access_release");
    expect(stdout).toContain('"type":"tool_result"');
    expect(stdout).toContain("approval_required");
  });
});
