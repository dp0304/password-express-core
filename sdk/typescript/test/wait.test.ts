// SPDX-License-Identifier: Apache-2.0
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  AbortedError,
  AIPassTimeoutError,
  ApprovalDeniedError,
  ApprovalExpiredError,
  ApprovalRequiredError,
  backoffDelay,
  errorForOperation,
  jittered,
  NotFoundError,
  OperationCancelledError,
  poll,
  resolveBackoff,
  UpstreamOutcomeUnknownError,
  type OperationResponse,
} from "../src/index.js";
import { LURE_RESOURCE } from "./mock-broker.js";
import { tcpHarness, type Harness } from "./helpers.js";

const FAST = { intervalMs: 5, maxIntervalMs: 20, jitter: 0 };

async function pendingOp(h: Harness, key: string): Promise<OperationResponse> {
  return h.client.requestOperation({
    resource_id: LURE_RESOURCE.resource_id,
    operation: "postgres.query_view",
    parameters: { view: "analytics.subscription_daily", fields: ["day", "plan", "subscriptions"], period_days: 30 },
    idempotency_key: key,
  });
}

describe("backoff math", () => {
  it("grows geometrically and caps", () => {
    const b = resolveBackoff({ intervalMs: 100, maxIntervalMs: 1000, backoff: 2, jitter: 0 });
    expect([0, 1, 2, 3, 4, 5].map((i) => backoffDelay(i, b))).toEqual([100, 200, 400, 800, 1000, 1000]);
  });

  it("applies bounded jitter", () => {
    expect(jittered(1000, 0.2, () => 0)).toBe(800);
    expect(jittered(1000, 0.2, () => 0.999999)).toBe(1200);
    expect(jittered(1000, 0, () => 0.5)).toBe(1000);
    for (let i = 0; i < 500; i += 1) {
      const v = jittered(1000, 0.25);
      expect(v).toBeGreaterThanOrEqual(750);
      expect(v).toBeLessThanOrEqual(1250);
    }
  });

  it("sanitises bad options", () => {
    expect(resolveBackoff({ intervalMs: -5, maxIntervalMs: 1, backoff: 0.1, jitter: 7 })).toEqual({ intervalMs: 1000, maxIntervalMs: 1000, backoff: 1.5, jitter: 1 });
  });

  it("poll() with an injected clock times out after the final poll at the deadline", async () => {
    let t = 0;
    let calls = 0;
    const out = await poll(
      async () => {
        calls += 1;
        t += 400;
        return { status: "approval_required" };
      },
      { timeoutMs: 1000, intervalMs: 1, jitter: 0, isTerminal: (v) => v.status !== "approval_required", now: () => t },
    );
    expect(out.timedOut).toBe(true);
    expect(out.value.status).toBe("approval_required");
    expect(calls).toBe(3);
  });
});

describe("waitForOperation", () => {
  let h: Harness;
  beforeEach(async () => {
    h = await tcpHarness();
  });
  afterEach(async () => {
    await h.cleanup();
  });

  it("returns the final result once the user approves on a trusted device", async () => {
    const op = await pendingOp(h, "w-approve");
    h.broker.approveOperationsAfterPolls = 3;
    const updates: string[] = [];
    const done = await h.client.waitForOperation(op.operation_id, { ...FAST, timeoutMs: 5000, onUpdate: (o) => updates.push(o.status) });
    expect(done.status).toBe("succeeded");
    expect(done.result?.rows).toBe(3);
    expect(updates).toEqual(["approval_required", "approval_required", "succeeded"]);
  });

  it("timeout returns the still-pending status — a timeout is NEVER an approval", async () => {
    const op = await pendingOp(h, "w-timeout");
    const started = Date.now();
    const res = await h.client.waitForOperation(op.operation_id, { ...FAST, timeoutMs: 150 });
    expect(res.status).toBe("approval_required");
    expect(res.result).toBeUndefined();
    expect(Date.now() - started).toBeGreaterThanOrEqual(140);
    expect(h.broker.operations.get(op.operation_id)!.response.status).toBe("approval_required");
  });

  it("raiseOnPending: timeout while approval_required → ApprovalRequiredError", async () => {
    const op = await pendingOp(h, "w-raise");
    const err = await h.client.waitForOperation(op.operation_id, { ...FAST, timeoutMs: 60, raiseOnPending: true }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ApprovalRequiredError);
    expect((err as ApprovalRequiredError).operationId).toBe(op.operation_id);
  });

  it("raiseOnPending: timeout while running → AIPassTimeoutError with the latest operation", async () => {
    const op = await pendingOp(h, "w-running");
    h.broker.decideOperation(op.operation_id, "running");
    const err = await h.client.waitForOperation(op.operation_id, { ...FAST, timeoutMs: 60, raiseOnPending: true }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(AIPassTimeoutError);
    expect((err as AIPassTimeoutError).operation?.status).toBe("running");
    expect((err as AIPassTimeoutError).message).toContain("绝不会被视为批准");
  });

  it("denied / expired are returned as statuses, or thrown as typed errors with raiseOnFailure", async () => {
    const a = await pendingOp(h, "w-denied");
    h.broker.operationDecision = "denied";
    h.broker.approveOperationsAfterPolls = 1;
    expect((await h.client.waitForOperation(a.operation_id, { ...FAST, timeoutMs: 2000 })).status).toBe("denied");
    const b = await pendingOp(h, "w-denied-raise");
    await expect(h.client.waitForOperation(b.operation_id, { ...FAST, timeoutMs: 2000, raiseOnFailure: true })).rejects.toBeInstanceOf(ApprovalDeniedError);
    h.broker.operationDecision = "expired";
    const c = await pendingOp(h, "w-expired");
    const expired = await h.client.waitForOperation(c.operation_id, { ...FAST, timeoutMs: 2000 });
    expect(expired.status).toBe("expired");
    expect(expired.result).toBeUndefined();
    const d = await pendingOp(h, "w-expired-raise");
    await expect(h.client.waitForOperation(d.operation_id, { ...FAST, timeoutMs: 2000, raiseOnFailure: true })).rejects.toBeInstanceOf(ApprovalExpiredError);
  });

  it("errorForOperation maps statuses without an error body", () => {
    expect(errorForOperation({ status: "unknown", operation_id: "op_1" })).toBeInstanceOf(UpstreamOutcomeUnknownError);
    expect(errorForOperation({ status: "cancelled", operation_id: "op_1" })).toBeInstanceOf(OperationCancelledError);
    expect(errorForOperation({ status: "denied", operation_id: "op_1" }, "en").message).toBe("The request was denied.");
  });

  it("abort stops the wait promptly", async () => {
    const op = await pendingOp(h, "w-abort");
    const controller = new AbortController();
    setTimeout(() => controller.abort(), 80);
    const started = Date.now();
    const err = await h.client.waitForOperation(op.operation_id, { intervalMs: 1000, timeoutMs: 30_000, signal: controller.signal }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(AbortedError);
    expect(Date.now() - started).toBeLessThan(1000);
  });

  it("transient broker errors are retried within the deadline", async () => {
    const op = await pendingOp(h, "w-transient");
    h.broker.failNext({ status: 503, rawBody: "<html>upstream reset</html>", pathPrefix: "/v1/operations/" });
    h.broker.failNext({ status: 500, code: "INTERNAL", pathPrefix: "/v1/operations/" });
    h.broker.failNext({ status: 429, code: "RATE_LIMITED", pathPrefix: "/v1/operations/" });
    h.broker.approveOperationsAfterPolls = 1;
    const done = await h.client.waitForOperation(op.operation_id, { ...FAST, timeoutMs: 5000 });
    expect(done.status).toBe("succeeded");
  });

  it("if the final attempt failed, the error is thrown instead of a stale status", async () => {
    const op = await pendingOp(h, "w-stale");
    for (let i = 0; i < 50; i += 1) h.broker.failNext({ status: 500, code: "INTERNAL", pathPrefix: "/v1/operations/" });
    await expect(h.client.waitForOperation(op.operation_id, { ...FAST, timeoutMs: 80 })).rejects.toMatchObject({ code: "INTERNAL" });
  });

  it("permanent errors (NOT_FOUND) are thrown immediately", async () => {
    const started = Date.now();
    await expect(h.client.waitForOperation("op_01jbz3k6w8a7m2q4t5v9xnone0", { intervalMs: 1000, timeoutMs: 10_000 })).rejects.toBeInstanceOf(NotFoundError);
    expect(Date.now() - started).toBeLessThan(500);
  });

  it("honours Retry-After on RATE_LIMITED while polling", async () => {
    const op = await pendingOp(h, "w-retry-after");
    h.broker.failNext({ status: 429, code: "RATE_LIMITED", headers: { "retry-after": "1" }, pathPrefix: "/v1/operations/" });
    h.broker.approveOperationsAfterPolls = 1;
    const started = Date.now();
    const done = await h.client.waitForOperation(op.operation_id, { ...FAST, timeoutMs: 5000 });
    expect(done.status).toBe("succeeded");
    expect(Date.now() - started).toBeGreaterThanOrEqual(950);
  });
});
