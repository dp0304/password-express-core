// SPDX-License-Identifier: Apache-2.0
// TypeScript-SDK step of the e2e test, against the real aipass-node: pair a connection
// (host_type sdk), check that another connection's operation id is invisible (A04), then run
// one approved operation. Prints markers the driver waits for.
// argv: broker_url key_path resource_id foreign_op_id sdk_dist_dir
import path from "node:path";
import { pathToFileURL } from "node:url";

const [broker, keyPath, resourceId, foreignOp, dist] = process.argv.slice(2);
const { pair, AIPassClient } = await import(pathToFileURL(path.join(dist, "index.js")).href);

const res = await pair({
  displayName: "e2e-ts-sdk",
  keyPath,
  brokerUrl: broker,
  locale: "en",
  timeoutMs: 120_000,
  onPairingCode: (info) => console.log("PAIRING_CODE", info.pairing_code),
});
res.client?.close?.();
if (res.status !== "approved") {
  console.log("PAIR_STATUS", res.status);
  process.exit(1);
}

const c = AIPassClient.fromKeyFile(keyPath, { brokerUrl: broker, locale: "en" });
try {
  await c.getOperation(foreignOp);
  console.log("FOREIGN VISIBLE");
} catch (e) {
  console.log("FOREIGN", e?.code ?? "");
}
let op = await c.requestOperation({
  resource_id: resourceId,
  operation: "postgres.query_view",
  parameters: { view: "analytics.subscription_daily", fields: ["day", "plan"], limit: 5 },
  idempotency_key: "ts-sdk-1",
});
if (op.status === "approval_required") {
  console.log("APPROVAL", op.approval_request_id);
  op = await c.waitForOperation(op.operation_id, { timeoutMs: 90_000 });
}
const rows = op.result?.data?.rows ?? [];
c.close?.();
if (op.status !== "succeeded" || rows.length === 0 || !rows.every((r) => Object.keys(r).sort().join(",") === "day,plan")) {
  console.log("BAD", JSON.stringify(op).slice(0, 400));
  process.exit(1);
}
console.log("TS_SDK_OK", rows.length);
