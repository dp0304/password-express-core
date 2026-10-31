// SPDX-License-Identifier: Apache-2.0
import http from "node:http";
import type { AddressInfo } from "node:net";
import { afterEach, describe, expect, it } from "vitest";
import {
  AbortedError,
  AIPassClient,
  AIPassError,
  AIPassTimeoutError,
  ApprovalDeniedError,
  ApprovalExpiredError,
  ApprovalRequiredError,
  BudgetExhaustedError,
  ConnectionKey,
  ConnectionPausedError,
  ControlChannelLostError,
  ERROR_CODES,
  errorClassForCode,
  errorFromResponse,
  ExecutorOfflineError,
  ForbiddenError,
  GrantExpiredError,
  GrantRevokedError,
  IdempotencyConflictError,
  IdentityUnverifiedError,
  IntegrityFailedError,
  InteractiveAuthRequiredError,
  InternalError,
  InvalidRequestError,
  InvalidResponseError,
  NetworkError,
  NotFoundError,
  NotSupportedError,
  PaymentRequiredError,
  PreconditionFailedError,
  QuotaExceededError,
  RateLimitedError,
  ResultRestrictedError,
  RollbackDetectedError,
  ScopeDeniedError,
  SecretUnavailableError,
  SigningKey,
  SyncConflictError,
  UnauthenticatedError,
  UpstreamError,
  UpstreamOutcomeUnknownError,
} from "../src/index.js";
import { LURE_RESOURCE } from "./mock-broker.js";
import { tcpHarness, type Harness } from "./helpers.js";

const STATUS_BY_CODE: Record<string, [number, new (...a: never[]) => AIPassError]> = {
  IDENTITY_UNVERIFIED: [401, IdentityUnverifiedError],
  UNAUTHENTICATED: [401, UnauthenticatedError],
  FORBIDDEN: [403, ForbiddenError],
  CONNECTION_PAUSED: [403, ConnectionPausedError],
  APPROVAL_REQUIRED: [202, ApprovalRequiredError],
  APPROVAL_DENIED: [403, ApprovalDeniedError],
  APPROVAL_EXPIRED: [410, ApprovalExpiredError],
  GRANT_EXPIRED: [403, GrantExpiredError],
  GRANT_REVOKED: [403, GrantRevokedError],
  BUDGET_EXHAUSTED: [403, BudgetExhaustedError],
  SCOPE_DENIED: [403, ScopeDeniedError],
  EXECUTOR_OFFLINE: [503, ExecutorOfflineError],
  CONTROL_CHANNEL_LOST: [503, ControlChannelLostError],
  SECRET_UNAVAILABLE: [409, SecretUnavailableError],
  SYNC_CONFLICT: [409, SyncConflictError],
  PRECONDITION_FAILED: [412, PreconditionFailedError],
  ROLLBACK_DETECTED: [409, RollbackDetectedError],
  INTEGRITY_FAILED: [422, IntegrityFailedError],
  INTERACTIVE_AUTH_REQUIRED: [409, InteractiveAuthRequiredError],
  RESULT_RESTRICTED: [403, ResultRestrictedError],
  UPSTREAM_OUTCOME_UNKNOWN: [502, UpstreamOutcomeUnknownError],
  UPSTREAM_ERROR: [502, UpstreamError],
  IDEMPOTENCY_CONFLICT: [409, IdempotencyConflictError],
  RATE_LIMITED: [429, RateLimitedError],
  NOT_FOUND: [404, NotFoundError],
  INVALID_REQUEST: [400, InvalidRequestError],
  NOT_SUPPORTED: [501, NotSupportedError],
  PAYMENT_REQUIRED: [402, PaymentRequiredError],
  QUOTA_EXCEEDED: [429, QuotaExceededError],
  INTERNAL: [500, InternalError],
};

describe("error mapping (CONTRACTS §1.5)", () => {
  let h: Harness;
  afterEach(async () => {
    await h?.cleanup();
  });

  it("covers every contract code", () => {
    expect(Object.keys(STATUS_BY_CODE).sort()).toEqual([...ERROR_CODES].sort());
    for (const code of ERROR_CODES) expect(errorClassForCode(code)).toBe(STATUS_BY_CODE[code]![1]);
    expect(errorClassForCode("SOMETHING_NEW")).toBe(AIPassError);
  });

  it("maps every broker error envelope to its typed subclass with code, message, status, request_id and details", async () => {
    h = await tcpHarness({ maxRetries: 0 });
    for (const [code, [status, Cls]] of Object.entries(STATUS_BY_CODE)) {
      if (status < 400) continue; // APPROVAL_REQUIRED is a status, not an HTTP error
      h.broker.failNext({ status, code, message: `消息 ${code}`, details: { field: "plan" } });
      const err = await h.client.listResources().catch((e: unknown) => e);
      expect(err, code).toBeInstanceOf(Cls);
      expect(err).toBeInstanceOf(AIPassError);
      const e = err as AIPassError;
      expect(e.code).toBe(code);
      expect(e.message).toBe(`消息 ${code}`);
      expect(e.httpStatus).toBe(status);
      expect(e.requestId).toMatch(/^req_/);
      expect(e.details).toEqual({ field: "plan" });
      expect(e.toJSON()).toMatchObject({ code, message: `消息 ${code}`, http_status: status });
      expect(String(e)).toContain(`[${code}]`);
    }
  });

  it("unknown future codes become a base AIPassError with the code preserved", async () => {
    h = await tcpHarness({ maxRetries: 0 });
    h.broker.failNext({ status: 418, code: "BRAND_NEW_CODE", message: "new" });
    const err = (await h.client.listResources().catch((e: unknown) => e)) as AIPassError;
    expect(err.constructor).toBe(AIPassError);
    expect(err.code).toBe("BRAND_NEW_CODE");
  });

  it("parses Retry-After on RATE_LIMITED", async () => {
    h = await tcpHarness({ maxRetries: 0 });
    h.broker.failNext({ status: 429, code: "RATE_LIMITED", headers: { "retry-after": "7" } });
    const err = (await h.client.listResources().catch((e: unknown) => e)) as RateLimitedError;
    expect(err).toBeInstanceOf(RateLimitedError);
    expect(err.retryAfterSeconds).toBe(7);
  });

  it("a non-envelope body (proxy page) never leaks into the message; status decides the code", async () => {
    h = await tcpHarness({ maxRetries: 0 });
    h.broker.failNext({ status: 502, rawBody: "<html>Bad gateway secret-ish proxy text</html>" });
    const err = (await h.client.listResources().catch((e: unknown) => e)) as AIPassError;
    expect(err).toBeInstanceOf(InvalidResponseError);
    expect(err.httpStatus).toBe(502);
    expect(err.message).not.toContain("proxy");
    h.broker.failNext({ status: 404, rawBody: "nope" });
    expect(await h.client.listResources().catch((e: unknown) => e)).toBeInstanceOf(NotFoundError);
  });

  it("a 200 with non-JSON or wrong shape is INVALID_RESPONSE", async () => {
    expect(errorFromResponse(500, "", {}, "fallback")).toBeInstanceOf(InternalError);
    h = await tcpHarness({ maxRetries: 0 });
    h.broker.failNext({ status: 200, rawBody: "not json" });
    expect(await h.client.listResources().catch((e: unknown) => e)).toBeInstanceOf(InvalidResponseError);
    h.broker.failNext({ status: 200, rawBody: '{"unexpected":true}' });
    expect(await h.client.listResources().catch((e: unknown) => e)).toBeInstanceOf(InvalidResponseError);
    h.broker.failNext({ status: 200, rawBody: "[1,2]" });
    expect(await h.client.getOperation("op_x").catch((e: unknown) => e)).toBeInstanceOf(InvalidResponseError);
  });

  it("response size is capped", async () => {
    h = await tcpHarness({ maxRetries: 0, maxResponseBytes: 64 });
    const err = (await h.client.listResources().catch((e: unknown) => e)) as AIPassError;
    expect(err).toBeInstanceOf(InvalidResponseError);
    expect(err.message).toContain("64");
  });
});

describe("transport failures", () => {
  let server: http.Server | undefined;
  afterEach(async () => {
    if (server) {
      server.closeAllConnections?.();
      await new Promise<void>((r) => server!.close(() => r()));
      server = undefined;
    }
  });

  function key(): ConnectionKey {
    return new ConnectionKey("conn_01jbz3k6w8a7m2q4t5v9x0y1z4", SigningKey.generate());
  }

  it("connection refused → NetworkError after bounded retries (zh message names the broker)", async () => {
    const probe = http.createServer();
    await new Promise<void>((r) => probe.listen(0, "127.0.0.1", r));
    const { port } = probe.address() as AddressInfo;
    await new Promise<void>((r) => probe.close(() => r()));
    const client = new AIPassClient({ brokerUrl: `http://127.0.0.1:${port}`, connectionKey: key(), maxRetries: 1 });
    const started = Date.now();
    const err = (await client.listResources().catch((e: unknown) => e)) as AIPassError;
    expect(err).toBeInstanceOf(NetworkError);
    expect(err.code).toBe("NETWORK_ERROR");
    expect(err.message).toContain(`127.0.0.1:${port}`);
    expect(err.message).toContain("无法连接");
    expect(Date.now() - started).toBeGreaterThanOrEqual(150); // one backoff sleep happened
    client.close();
  });

  it("retries transport failures on retry-safe requests, re-signing each attempt with a fresh nonce", async () => {
    let calls = 0;
    const auths: string[] = [];
    server = http.createServer((req, res) => {
      calls += 1;
      auths.push(String(req.headers.authorization));
      if (calls === 1) {
        req.socket.destroy(); // drop the connection mid-request
        return;
      }
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ resources: [] }));
    });
    await new Promise<void>((r) => server!.listen(0, "127.0.0.1", r));
    const { port } = server.address() as AddressInfo;
    const client = new AIPassClient({ brokerUrl: `http://127.0.0.1:${port}`, connectionKey: key(), maxRetries: 2 });
    const res = await client.listResources();
    expect(res.resources).toEqual([]);
    expect(calls).toBe(2);
    expect(auths[0]).not.toBe(auths[1]);
    client.close();
  });

  it("does not resend non-idempotent POST /v1/access/requests after a transport failure", async () => {
    let calls = 0;
    server = http.createServer((req) => {
      calls += 1;
      req.socket.destroy();
    });
    await new Promise<void>((r) => server!.listen(0, "127.0.0.1", r));
    const { port } = server.address() as AddressInfo;
    const client = new AIPassClient({ brokerUrl: `http://127.0.0.1:${port}`, connectionKey: key(), maxRetries: 3 });
    await expect(client.requestAccess({ resource_id: LURE_RESOURCE.resource_id, operations: ["postgres.query_view"] })).rejects.toBeInstanceOf(NetworkError);
    expect(calls).toBe(1);
    client.close();
  });

  it("request timeout → AIPassTimeoutError (TIMEOUT) whose message warns a timeout is not proof nothing happened", async () => {
    server = http.createServer(() => {
      /* never answer */
    });
    await new Promise<void>((r) => server!.listen(0, "127.0.0.1", r));
    const { port } = server.address() as AddressInfo;
    const client = new AIPassClient({ brokerUrl: `http://127.0.0.1:${port}`, connectionKey: key(), timeoutMs: 100, maxRetries: 0 });
    const err = (await client
      .requestOperation({ resource_id: LURE_RESOURCE.resource_id, operation: "postgres.query_view", parameters: {}, idempotency_key: "k" })
      .catch((e: unknown) => e)) as AIPassError;
    expect(err).toBeInstanceOf(AIPassTimeoutError);
    expect(err.code).toBe("TIMEOUT");
    expect(err.message).toContain("idempotency_key");
    client.close();
  });

  it("abort signal → AbortedError immediately, without retries", async () => {
    let calls = 0;
    server = http.createServer(() => {
      calls += 1;
    });
    await new Promise<void>((r) => server!.listen(0, "127.0.0.1", r));
    const { port } = server.address() as AddressInfo;
    const client = new AIPassClient({ brokerUrl: `http://127.0.0.1:${port}`, connectionKey: key(), maxRetries: 3 });
    const controller = new AbortController();
    const pending = client.listResources({}, { signal: controller.signal });
    setTimeout(() => controller.abort(), 50);
    const err = await pending.catch((e: unknown) => e);
    expect(err).toBeInstanceOf(AbortedError);
    expect(calls).toBe(1);
    const pre = new AbortController();
    pre.abort();
    await expect(client.listResources({}, { signal: pre.signal })).rejects.toBeInstanceOf(AbortedError);
    client.close();
  });
});
