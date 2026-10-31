#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
//
// 路亚站订阅分析示例 / Lure-store subscription report.
//
// The agent asks AI Pass to run `postgres.query_view` on `analytics.subscription_daily` of the
// resource aliased "路亚站测试库". It never sees the database password: the executor connects,
// the user approves on their phone / trusted client, and only the allowed fields come back.
//
// Run (after `pnpm build`):
//   AIPASS_KEY_FILE=~/.aipass/connections/lure-agent.key node examples/lure-store.mjs
//   # or: AIPASS_TOKEN=aipc_… AIPASS_BROKER_URL=https://node.example.com node examples/lure-store.mjs
// Broker URL resolution: AIPASS_BROKER_URL > ~/.aipass/broker.json > unix://~/.aipass/run/broker.sock
// (AIPASS_KEY_FILE / AIPASS_TOKEN are read by this example only.)
import { AIPassClient, AIPassError } from "@aipass/sdk";

const ALIAS = "路亚站测试库";
const VIEW = "analytics.subscription_daily";
const en = (process.env.AIPASS_LOCALE ?? "").startsWith("en");
const t = (zh, english) => (en ? english : zh);

function makeClient() {
  const locale = en ? "en" : "zh-CN";
  if (process.env.AIPASS_TOKEN) return new AIPassClient({ bearerToken: process.env.AIPASS_TOKEN, locale });
  const keyFile = process.env.AIPASS_KEY_FILE;
  if (!keyFile) {
    console.error(t("请设置 AIPASS_KEY_FILE（先运行 examples/pair.mjs 配对）或 AIPASS_TOKEN。", "Set AIPASS_KEY_FILE (pair first with examples/pair.mjs) or AIPASS_TOKEN."));
    process.exit(2);
  }
  return AIPassClient.fromKeyFile(keyFile.replace(/^~(?=\/)/, process.env.HOME ?? "~"), { locale });
}

async function main() {
  const client = makeClient();
  try {
    const resource = await client.findResource({ alias: ALIAS });
    if (!resource) {
      console.error(t(`当前连接看不到资源「${ALIAS}」。请在 AI 通行证中把它加入允许的项目。`, `This connection cannot see the resource "${ALIAS}". Allow its project for this connection in AI Pass.`));
      process.exitCode = 1;
      return;
    }
    console.log(t(`资源：${resource.alias}（${resource.resource_id}，${resource.environment}，执行设备${resource.executor_status === "online" ? "在线" : "离线"}）`,
      `Resource: ${resource.alias} (${resource.resource_id}, ${resource.environment}, executor ${resource.executor_status})`));

    // A stable, task-derived idempotency key: re-running today reuses the same operation.
    const today = new Date().toISOString().slice(0, 10);
    let op = await client.requestOperation({
      resource_id: resource.resource_id,
      operation: "postgres.query_view",
      parameters: { view: VIEW, fields: ["day", "plan", "subscriptions"], period_days: 30 },
      idempotency_key: `lure-subscription-summary-${today}`,
    });

    if (op.status === "approval_required") {
      console.log(op.message ?? t("请在已配对的手机或可信客户端批准本次访问。", "Please approve on your paired phone or trusted client."));
      console.log(t(`等待批准（最多 ${op.expires_in_seconds ?? 120} 秒；超时不会被视为批准）…`, `Waiting for approval (up to ${op.expires_in_seconds ?? 120}s; a timeout is never an approval)…`));
      op = await client.waitForOperation(op.operation_id, { timeoutMs: ((op.expires_in_seconds ?? 120) + 10) * 1000 });
    }

    switch (op.status) {
      case "succeeded": {
        const rows = Array.isArray(op.result?.data) ? op.result.data : [];
        const byPlan = new Map();
        for (const row of rows) byPlan.set(row.plan, (byPlan.get(row.plan) ?? 0) + Number(row.subscriptions ?? 0));
        console.log(t(`近 30 天新增订阅（${rows.length} 行）：`, `New subscriptions, last 30 days (${rows.length} rows):`));
        for (const [plan, total] of [...byPlan.entries()].sort((a, b) => b[1] - a[1])) console.log(`  ${plan}: ${total}`);
        if (op.result?.truncated) console.log(t("（结果已按授权上限截断）", "(truncated at the approved limit)"));
        if (op.result?.restricted_fields?.length) console.log(t(`（已隐藏字段：${op.result.restricted_fields.join(", ")}）`, `(withheld fields: ${op.result.restricted_fields.join(", ")})`));
        break;
      }
      case "approval_required":
        console.log(t("仍在等待批准，稍后可用相同的 idempotency_key 重新运行。", "Still waiting for approval; re-run later with the same idempotency_key."));
        process.exitCode = 3;
        break;
      case "unknown":
        console.log(t("结果未知：外部服务可能已执行，请先核实。", "Outcome unknown: the external service may have executed; verify first."));
        process.exitCode = 4;
        break;
      default:
        console.log(t(`操作结束：${op.status}${op.error ? ` — ${op.error.code}: ${op.error.message}` : ""}`, `Operation ended: ${op.status}${op.error ? ` — ${op.error.code}: ${op.error.message}` : ""}`));
        process.exitCode = 1;
    }
  } catch (err) {
    if (err instanceof AIPassError) {
      console.error(`${err.code}: ${err.message}${err.requestId ? ` (request_id=${err.requestId})` : ""}`);
      process.exitCode = 1;
      return;
    }
    throw err;
  } finally {
    client.close();
  }
}

await main();
