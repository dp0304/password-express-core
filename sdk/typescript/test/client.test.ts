// SPDX-License-Identifier: Apache-2.0
import { inspect } from "node:util";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  AIPassClient,
  ApprovalRequiredError,
  ConfigError,
  ConnectionKey,
  ExecutorOfflineError,
  IdempotencyConflictError,
  IdentityUnverifiedError,
  InvalidRequestError,
  NotFoundError,
  SigningKey,
  type Logger,
} from "../src/index.js";
import { APPROVAL_MESSAGE_EN, APPROVAL_MESSAGE_ZH, GITHUB_RESOURCE, LURE_RESOURCE, OFFLINE_RESOURCE } from "./mock-broker.js";
import { tcpHarness, type Harness } from "./helpers.js";

const QUERY = {
  resource_id: LURE_RESOURCE.resource_id,
  operation: "postgres.query_view",
  parameters: { view: "analytics.subscription_daily", fields: ["day", "plan", "subscriptions"], period_days: 30 },
};

describe("AIPassClient against the mock broker", () => {
  let h: Harness;
  beforeEach(async () => {
    h = await tcpHarness();
  });
  afterEach(async () => {
    await h.cleanup();
  });

  it("health() is public and unauthenticated", async () => {
    const health = await h.client.health();
    expect(health.status).toBe("ok");
    expect(h.broker.requests.at(-1)!.headers.authorization).toBeUndefined();
  });

  it("listResources() signs path+query and filters", async () => {
    const all = await h.client.listResources();
    expect(all.resources.map((r) => r.resource_id)).toEqual([LURE_RESOURCE.resource_id, OFFLINE_RESOURCE.resource_id, GITHUB_RESOURCE.resource_id]);
    const filtered = await h.client.listResources({ project_id: LURE_RESOURCE.project_id, service: "postgres" });
    expect(filtered.resources.map((r) => r.alias)).toEqual(["路亚站测试库", "离线库"]);
    const sent = h.broker.requests.at(-1)!;
    expect(sent.url).toBe(`/v1/resources?project_id=${LURE_RESOURCE.project_id}&service=postgres`);
    expect(sent.headers.authorization).toMatch(/^AIPass-Sig kid=conn_[0-9a-z]+, ts=\d+, nonce=[A-Za-z0-9_-]{22}, sig=[A-Za-z0-9_-]{86}$/);
    expect(sent.principal).toBe(h.key.connectionId);
    expect(sent.headers["accept-language"]).toBe("zh-CN");
    expect(sent.headers["user-agent"]).toMatch(/^aipass-sdk-typescript\/0\.1\.0 node\//);
  });

  it("query values with spaces/unicode are encoded identically in the signature and the request line", async () => {
    const res = await h.client.listResources({ service: "postgres 测试&x=1" });
    expect(res.resources).toEqual([]);
    expect(h.broker.requests.at(-1)!.url).toBe("/v1/resources?service=postgres%20%E6%B5%8B%E8%AF%95%26x%3D1");
  });

  it("findResource() finds the lure-store test DB by alias", async () => {
    const r = await h.client.findResource({ alias: "路亚站测试库" });
    expect(r?.resource_id).toBe(LURE_RESOURCE.resource_id);
    expect(await h.client.findResource({ alias: "nope" })).toBeUndefined();
  });

  it("requestOperation() returns approval_required as a normal 202 status (never an exception by default)", async () => {
    const op = await h.client.requestOperation({ ...QUERY, idempotency_key: "k-approval-1" });
    expect(op.status).toBe("approval_required");
    expect(op.message).toBe(APPROVAL_MESSAGE_ZH);
    expect(op.expires_in_seconds).toBe(120);
    expect(op.approval_request_id).toMatch(/^apr_/);
    expect(op.operation_id).toMatch(/^op_/);
  });

  it("requestOperation({raiseOnPending}) throws ApprovalRequiredError carrying the operation", async () => {
    const err = await h.client.requestOperation({ ...QUERY, idempotency_key: "k-raise" }, { raiseOnPending: true }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ApprovalRequiredError);
    const e = err as ApprovalRequiredError;
    expect(e.code).toBe("APPROVAL_REQUIRED");
    expect(e.operationId).toMatch(/^op_/);
    expect(e.approvalRequestId).toMatch(/^apr_/);
    expect(e.message).toBe(APPROVAL_MESSAGE_ZH);
  });

  it("requestOperation() succeeds immediately when a grant exists", async () => {
    h.broker.granted.add(`${h.key.connectionId}:${LURE_RESOURCE.resource_id}`);
    const op = await h.client.requestOperation({ ...QUERY, idempotency_key: "k-granted" });
    expect(op.status).toBe("succeeded");
    expect(op.result?.rows).toBe(3);
  });

  it("generates an idempotency key when omitted, and replays are deduplicated by the broker", async () => {
    const op = await h.client.requestOperation(QUERY);
    const body = JSON.parse(h.broker.requests.at(-1)!.body.toString("utf8")) as { idempotency_key: string };
    expect(body.idempotency_key).toMatch(/^aipass-sdk-[A-Za-z0-9_-]{24}$/);
    const again = await h.client.requestOperation({ ...QUERY, idempotency_key: body.idempotency_key });
    expect(again.operation_id).toBe(op.operation_id);
  });

  it("same idempotency key with different parameters → IdempotencyConflictError", async () => {
    await h.client.requestOperation({ ...QUERY, idempotency_key: "k-conflict" });
    const err = await h.client
      .requestOperation({ ...QUERY, parameters: { ...QUERY.parameters, period_days: 7 }, idempotency_key: "k-conflict" })
      .catch((e: unknown) => e);
    expect(err).toBeInstanceOf(IdempotencyConflictError);
    expect((err as IdempotencyConflictError).httpStatus).toBe(409);
    expect((err as IdempotencyConflictError).requestId).toMatch(/^req_/);
  });

  it("executor offline → ExecutorOfflineError (503)", async () => {
    const err = await h.client.requestOperation({ ...QUERY, resource_id: OFFLINE_RESOURCE.resource_id, idempotency_key: "k-off" }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ExecutorOfflineError);
    expect((err as ExecutorOfflineError).message).toBe("执行设备离线");
  });

  it("getOperation() / cancelOperation()", async () => {
    const op = await h.client.requestOperation({ ...QUERY, idempotency_key: "k-cancel" });
    const fetched = await h.client.getOperation(op.operation_id);
    expect(fetched.status).toBe("approval_required");
    const cancelled = await h.client.cancelOperation(op.operation_id);
    expect(cancelled).toMatchObject({ operation_id: op.operation_id, status: "cancelled", cancelled: true, side_effects: "none" });
    expect((await h.client.getOperation(op.operation_id)).status).toBe("cancelled");
  });

  it("IDs are not capabilities: another connection's operation is NOT_FOUND", async () => {
    const op = await h.client.requestOperation({ ...QUERY, idempotency_key: "k-owner" });
    const otherKey = SigningKey.generate();
    const otherId = h.broker.addConnection(otherKey.publicKey);
    const other = new AIPassClient({ brokerUrl: h.broker.url, connectionKey: new ConnectionKey(otherId, otherKey) });
    try {
      await expect(other.getOperation(op.operation_id)).rejects.toBeInstanceOf(NotFoundError);
      await expect(other.cancelOperation(op.operation_id)).rejects.toBeInstanceOf(NotFoundError);
    } finally {
      other.close();
    }
  });

  it("requestAccess() / getAccessRequest() / waitForAccessRequest() / releaseGrant()", async () => {
    const acc = await h.client.requestAccess({
      resource_id: LURE_RESOURCE.resource_id,
      operations: ["postgres.query_view"],
      scope: { operations: ["postgres.query_view"], postgres: { views: { "analytics.subscription_daily": ["day", "plan", "subscriptions"] } } },
      limits: { max_rows_per_operation: 1000, max_rows_per_grant: 5000, max_requests_per_grant: 20, max_result_bytes: 262144 },
      duration_seconds: 900,
      reason: "订阅转化分析",
    });
    expect(acc.status).toBe("pending");
    const sentBody = JSON.parse(h.broker.requests.at(-1)!.body.toString("utf8"));
    expect(sentBody).toEqual({
      resource_id: LURE_RESOURCE.resource_id,
      operations: ["postgres.query_view"],
      scope: { operations: ["postgres.query_view"], postgres: { views: { "analytics.subscription_daily": ["day", "plan", "subscriptions"] } } },
      limits: { max_rows_per_operation: 1000, max_rows_per_grant: 5000, max_requests_per_grant: 20, max_result_bytes: 262144 },
      duration_seconds: 900,
      reason: "订阅转化分析",
    });
    expect((await h.client.getAccessRequest(acc.approval_request_id)).status).toBe("pending");
    h.broker.approveAccessAfterPolls = 3;
    const approved = await h.client.waitForAccessRequest(acc.approval_request_id, { intervalMs: 5, maxIntervalMs: 10, timeoutMs: 5000 });
    expect(approved.status).toBe("approved");
    expect(approved.grant_id).toMatch(/^grt_/);
    const released = await h.client.releaseGrant(approved.grant_id!);
    expect(released).toEqual({ grant_id: approved.grant_id, status: "released" });
  });

  it("validates arguments locally before calling the broker", async () => {
    const before = h.broker.requests.length;
    await expect(h.client.requestOperation({ ...QUERY, resource_id: "" })).rejects.toBeInstanceOf(InvalidRequestError);
    await expect(h.client.requestOperation({ ...QUERY, idempotency_key: "x".repeat(129) })).rejects.toBeInstanceOf(InvalidRequestError);
    await expect(h.client.requestOperation({ ...QUERY, parameters: [] as unknown as Record<string, unknown> })).rejects.toBeInstanceOf(InvalidRequestError);
    await expect(h.client.requestAccess({ resource_id: LURE_RESOURCE.resource_id, operations: [] })).rejects.toBeInstanceOf(InvalidRequestError);
    await expect(h.client.requestAccess({ resource_id: LURE_RESOURCE.resource_id, operations: ["x"], duration_seconds: 1.5 })).rejects.toBeInstanceOf(
      InvalidRequestError,
    );
    await expect(h.client.getOperation("")).rejects.toBeInstanceOf(InvalidRequestError);
    await expect(h.client.requestOperation({ ...QUERY, idempotency_key: "bad\nkey" })).rejects.toBeInstanceOf(InvalidRequestError);
    await expect(
      h.client.requestAccess({ resource_id: LURE_RESOURCE.resource_id, operations: ["x"], limits: { max_rows_per_grant: 5 } as never }),
    ).rejects.toBeInstanceOf(InvalidRequestError);
    expect(h.broker.requests.length).toBe(before);
  });

  it("an unknown / revoked key is IDENTITY_UNVERIFIED", async () => {
    const stranger = new AIPassClient({ brokerUrl: h.broker.url, connectionKey: new ConnectionKey("conn_01jbz3k6w8a7m2q4t5v9xzzzzz", SigningKey.generate()) });
    try {
      await expect(stranger.listResources()).rejects.toBeInstanceOf(IdentityUnverifiedError);
    } finally {
      stranger.close();
    }
  });

  it("a key that signs for another kid is rejected (signature binds the principal)", async () => {
    const forged = new AIPassClient({ brokerUrl: h.broker.url, connectionKey: new ConnectionKey(h.key.connectionId, SigningKey.generate()) });
    try {
      await expect(forged.listResources()).rejects.toBeInstanceOf(IdentityUnverifiedError);
    } finally {
      forged.close();
    }
  });

  it("paused connection → CONNECTION_PAUSED", async () => {
    h.broker.connections.get(h.key.connectionId)!.status = "paused";
    await expect(h.client.listResources()).rejects.toMatchObject({ code: "CONNECTION_PAUSED", httpStatus: 403 });
  });
});

describe("client configuration", () => {
  let h: Harness | undefined;
  afterEach(async () => {
    await h?.cleanup();
    h = undefined;
  });

  it("bearer token auth (aipc_) sends Authorization: Bearer and works end to end", async () => {
    h = await tcpHarness();
    const token = h.broker.addToken(h.key.connectionId);
    const client = new AIPassClient({ brokerUrl: h.broker.url, bearerToken: token });
    try {
      const res = await client.listResources();
      expect(res.resources.length).toBe(3);
      expect(h.broker.requests.at(-1)!.headers.authorization).toBe(`Bearer ${token}`);
      expect(client.authKind).toBe("bearer");
      // The token never appears in inspect / JSON / toString.
      for (const text of [inspect(client, { depth: 10, showHidden: true }), JSON.stringify(client), String(client)]) {
        expect(text).not.toContain(token.slice(5));
      }
    } finally {
      client.close();
    }
  });

  it("rejects unsupported bearer prefixes (refresh / session tokens are never API credentials)", () => {
    for (const bad of ["aipr_abcdefghijklmnopqrstu", "aips_abcdefghijklmnopqrstu", "ghp_abcdefghijklmnopqrstu", "aipc_short"]) {
      expect(() => new AIPassClient({ brokerUrl: "http://127.0.0.1:1", bearerToken: bad })).toThrow(ConfigError);
    }
  });

  it("requires exactly one auth source", () => {
    expect(() => new AIPassClient({ brokerUrl: "http://127.0.0.1:1" })).toThrow(ConfigError);
    expect(
      () =>
        new AIPassClient({
          brokerUrl: "http://127.0.0.1:1",
          bearerToken: "aipc_abcdefghijklmnopqrstuvwxyz",
          connectionKey: new ConnectionKey("conn_abc", SigningKey.generate()),
        }),
    ).toThrow(ConfigError);
  });

  it("Accept-Language: en yields English broker messages", async () => {
    h = await tcpHarness({ locale: "en" });
    const op = await h.client.requestOperation({ ...QUERY, idempotency_key: "k-en" });
    expect(op.message).toBe(APPROVAL_MESSAGE_EN);
    expect(h.broker.requests.at(-1)!.headers["accept-language"]).toBe("en");
  });

  it("logger receives metadata only — never Authorization, bodies or secrets", async () => {
    const events: Array<[string, Record<string, unknown>]> = [];
    const logger: Logger = { debug: (e, f) => events.push([e, f]), warn: (e, f) => events.push([e, f]) };
    h = await tcpHarness({ logger });
    await h.client.listResources({ project_id: LURE_RESOURCE.project_id });
    await h.client.requestOperation({ ...QUERY, idempotency_key: "k-log" });
    await h.client.getOperation("op_missing").catch(() => undefined);
    const dump = JSON.stringify(events);
    expect(events.length).toBeGreaterThanOrEqual(3);
    expect(dump).not.toMatch(/AIPass-Sig|authorization|sig=|analytics\.subscription_daily|project_id=/i);
    expect(events[0]![1]).toMatchObject({ method: "GET", path: "/v1/resources", status: 200 });
  });

  it("toString / inspect identify the client without secrets", async () => {
    h = await tcpHarness();
    const seed = h.key.signingKey.exportSeed().toString("base64url");
    const text = inspect(h.client, { depth: 10, showHidden: true });
    expect(text).toContain(h.key.connectionId);
    expect(text).not.toContain(seed);
    expect(JSON.stringify(h.client)).not.toContain(seed);
  });
});
