// SPDX-License-Identifier: Apache-2.0
/**
 * In-process mock of the AI Pass broker's connection-facing API (CONTRACTS §6.3), served over
 * real node:http on TCP or a unix socket. It verifies AIPass-Sig signatures exactly as the
 * contract specifies (raw path+query, body hash, ±300 s, nonce uniqueness), enforces ownership
 * (other connections' objects → NOT_FOUND) and idempotency, and lets tests script approvals.
 */
import { createHash, randomBytes } from "node:crypto";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { buildStringToSign, parseAuthorization, verifySignature } from "../src/signing.js";
import type { OperationResponse, ResourceView } from "../src/types.js";

export const APPROVAL_MESSAGE_ZH = "请在已配对的手机或可信客户端批准本次访问。";
export const APPROVAL_MESSAGE_EN = "Please approve this access on your paired phone or trusted client.";

export interface RecordedRequest {
  method: string;
  url: string;
  headers: http.IncomingHttpHeaders;
  body: Buffer;
  principal?: string;
}

interface Connection {
  connectionId: string;
  publicKey: string;
  status: "pending" | "active" | "paused" | "denied";
}

interface StoredOperation {
  owner: string;
  paramsDigest: string;
  response: OperationResponse;
  polls: number;
}

interface StoredAccess {
  owner: string;
  response: { approval_request_id: string; status: string; grant_id?: string | null };
  polls: number;
}

interface Pairing {
  pairingRequestId: string;
  connectionId: string;
  code: string;
  expiresAt: number;
  status: "pending" | "approved" | "denied" | "expired";
  polls: number;
}

export interface ScriptedFailure {
  status: number;
  code?: string;
  message?: string;
  details?: Record<string, unknown>;
  headers?: Record<string, string>;
  /** Raw body instead of the error envelope (e.g. a proxy HTML page). */
  rawBody?: string;
  /** Only apply to requests whose path starts with this prefix. */
  pathPrefix?: string;
}

let idCounter = 0;
function ulid(): string {
  idCounter += 1;
  return `01jbz3k6w8a7m2q4t5v9x${String(idCounter).padStart(5, "0")}`.slice(0, 26);
}

export const LURE_RESOURCE: ResourceView = {
  resource_id: "res_01jbz3k6w8a7m2q4t5v9x0y1z2",
  alias: "路亚站测试库",
  service: "postgres",
  project_id: "proj_01jbz3k6w8a7m2q4t5v9x0y1z3",
  environment: "test",
  operations: [
    {
      name: "postgres.query_view",
      description: "Query an allowlisted view",
      side_effect: "read",
      parameters_schema: { type: "object", properties: { view: { type: "string" } }, required: ["view", "fields"] },
    },
  ],
  status: "available",
  protection_level: "compatible",
  executor_status: "online",
};

export const OFFLINE_RESOURCE: ResourceView = {
  ...LURE_RESOURCE,
  resource_id: "res_01jbz3k6w8a7m2q4t5v9x0off1",
  alias: "离线库",
  status: "executor_offline",
  executor_status: "offline",
};

export const GITHUB_RESOURCE: ResourceView = {
  ...LURE_RESOURCE,
  resource_id: "res_01jbz3k6w8a7m2q4t5v9x0gh01",
  alias: "lure-site repo",
  service: "github",
  project_id: "proj_01jbz3k6w8a7m2q4t5v9x0zzzz",
  operations: [{ name: "github.repo.get", description: "Get repo", side_effect: "read", parameters_schema: { type: "object" } }],
};

export const SAMPLE_RESULT = {
  data: [
    { day: "2026-10-01", plan: "monthly", subscriptions: 12 },
    { day: "2026-10-01", plan: "yearly", subscriptions: 3 },
    { day: "2026-10-02", plan: "monthly", subscriptions: 9 },
  ],
  rows: 3,
  truncated: false,
  restricted: false,
  restricted_fields: [],
};

export class MockBroker {
  readonly server: http.Server;
  url = "";
  readonly connections = new Map<string, Connection>();
  readonly tokens = new Map<string, string>();
  readonly pairings = new Map<string, Pairing>();
  readonly operations = new Map<string, StoredOperation>();
  readonly idempotency = new Map<string, string>();
  readonly access = new Map<string, StoredAccess>();
  readonly grants = new Map<string, { owner: string; status: string }>();
  readonly requests: RecordedRequest[] = [];
  readonly nonces = new Set<string>();
  readonly failures: ScriptedFailure[] = [];
  resources: ResourceView[] = [LURE_RESOURCE, OFFLINE_RESOURCE, GITHUB_RESOURCE];
  /** Connections that already hold a grant (operations succeed immediately). */
  readonly granted = new Set<string>();
  /** Auto-decide pending operations after N status polls (undefined = never). */
  approveOperationsAfterPolls: number | undefined;
  operationDecision: "succeeded" | "denied" | "expired" = "succeeded";
  approveAccessAfterPolls: number | undefined;
  /** Pairing decision after N polls (undefined = stays pending). */
  pairingDecisionAfterPolls: number | undefined;
  pairingDecision: "approved" | "denied" | "expired" = "approved";
  pairingTtlSeconds = 600;
  /** Clock used for signature freshness (seconds). */
  now: () => number = () => Math.floor(Date.now() / 1000);
  /** Artificial latency (ms) for every response. */
  delayMs = 0;
  #reqCounter = 0;

  constructor() {
    this.server = http.createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on("data", (c: Buffer) => chunks.push(c));
      req.on("end", () => {
        const body = Buffer.concat(chunks);
        const send = () => {
          try {
            this.#handle(req, res, body);
          } catch (err) {
            this.#error(res, 500, "INTERNAL", `mock broker bug: ${(err as Error).message}`);
          }
        };
        if (this.delayMs > 0) setTimeout(send, this.delayMs);
        else send();
      });
    });
  }

  async listenTcp(): Promise<string> {
    await new Promise<void>((resolve) => this.server.listen(0, "127.0.0.1", resolve));
    const { port } = this.server.address() as AddressInfo;
    this.url = `http://127.0.0.1:${port}`;
    return this.url;
  }

  async listenUnix(socketPath: string): Promise<string> {
    await new Promise<void>((resolve) => this.server.listen(socketPath, resolve));
    this.url = `unix://${socketPath}`;
    return this.url;
  }

  async close(): Promise<void> {
    this.server.closeAllConnections?.();
    await new Promise<void>((resolve) => this.server.close(() => resolve()));
  }

  /** Register an active connection with a raw b64u Ed25519 public key. */
  addConnection(publicKey: string, connectionId = `conn_${ulid()}`): string {
    this.connections.set(connectionId, { connectionId, publicKey, status: "active" });
    return connectionId;
  }

  /** Issue an `aipc_` bearer token for a connection. */
  addToken(connectionId: string): string {
    const token = `aipc_${randomBytes(32).toString("base64url")}`;
    this.tokens.set(token, connectionId);
    return token;
  }

  failNext(failure: ScriptedFailure): void {
    this.failures.push(failure);
  }

  decideOperation(operationId: string, status: "succeeded" | "denied" | "expired" | "failed" | "unknown" | "running"): void {
    const op = this.operations.get(operationId);
    if (!op) throw new Error(`no op ${operationId}`);
    this.#applyDecision(op, status);
  }

  #applyDecision(op: StoredOperation, status: string): void {
    const r = op.response;
    r.status = status;
    delete r.expires_in_seconds;
    if (status === "succeeded") {
      r.result = structuredClone(SAMPLE_RESULT);
      r.message = null;
    } else if (status === "denied") {
      r.error = { code: "APPROVAL_DENIED", message: "用户拒绝了本次访问" };
    } else if (status === "expired") {
      r.error = { code: "APPROVAL_EXPIRED", message: "审批已过期" };
    } else if (status === "unknown") {
      r.error = { code: "UPSTREAM_OUTCOME_UNKNOWN", message: "外部服务可能已执行" };
    } else if (status === "failed") {
      r.error = { code: "UPSTREAM_ERROR", message: "上游错误" };
    }
  }

  #requestId(): string {
    this.#reqCounter += 1;
    return `req_01jbz3k6w8a7m2q4t5v9x${String(this.#reqCounter).padStart(5, "0")}`.slice(0, 30);
  }

  #json(res: http.ServerResponse, status: number, payload: unknown, headers: Record<string, string> = {}): void {
    const body = Buffer.from(JSON.stringify(payload));
    res.writeHead(status, { "content-type": "application/json", "content-length": body.length, "x-request-id": this.#requestId(), ...headers });
    res.end(body);
  }

  #error(res: http.ServerResponse, status: number, code: string, message: string, details: Record<string, unknown> = {}, headers: Record<string, string> = {}): void {
    const requestId = this.#requestId();
    const body = Buffer.from(JSON.stringify({ error: { code, message, details, request_id: requestId } }));
    res.writeHead(status, { "content-type": "application/json", "content-length": body.length, "x-request-id": requestId, ...headers });
    res.end(body);
  }

  #authenticate(req: http.IncomingMessage, body: Buffer, allowPending: (kid: string) => boolean = () => false): { principal: string } | { status: number; code: string } {
    const header = req.headers.authorization;
    if (!header) return { status: 401, code: "IDENTITY_UNVERIFIED" };
    if (header.startsWith("Bearer ")) {
      const conn = this.tokens.get(header.slice("Bearer ".length));
      if (!conn) return { status: 401, code: "IDENTITY_UNVERIFIED" };
      const c = this.connections.get(conn);
      if (!c) return { status: 401, code: "IDENTITY_UNVERIFIED" };
      if (c.status === "paused") return { status: 403, code: "CONNECTION_PAUSED" };
      return { principal: conn };
    }
    const parsed = parseAuthorization(header);
    if (!parsed) return { status: 401, code: "IDENTITY_UNVERIFIED" };
    if (Math.abs(this.now() - parsed.ts) > 300) return { status: 401, code: "IDENTITY_UNVERIFIED" };
    const nonceKey = `${parsed.kid}:${parsed.nonce}`;
    if (this.nonces.has(nonceKey)) return { status: 401, code: "IDENTITY_UNVERIFIED" };
    if (Buffer.from(parsed.nonce, "base64url").length !== 16) return { status: 401, code: "IDENTITY_UNVERIFIED" };
    const conn = this.connections.get(parsed.kid);
    if (!conn) return { status: 401, code: "IDENTITY_UNVERIFIED" };
    if (conn.status === "pending" && !allowPending(parsed.kid)) return { status: 401, code: "IDENTITY_UNVERIFIED" };
    if (conn.status === "denied") return { status: 401, code: "IDENTITY_UNVERIFIED" };
    const stringToSign = buildStringToSign({
      method: req.method ?? "GET",
      path: req.url ?? "/",
      ts: parsed.ts,
      nonce: parsed.nonce,
      bodySha256: createHash("sha256").update(body).digest("base64url"),
    });
    if (!verifySignature(conn.publicKey, stringToSign, parsed.sig)) return { status: 401, code: "IDENTITY_UNVERIFIED" };
    this.nonces.add(nonceKey);
    if (conn.status === "paused") return { status: 403, code: "CONNECTION_PAUSED" };
    return { principal: parsed.kid };
  }

  #handle(req: http.IncomingMessage, res: http.ServerResponse, body: Buffer): void {
    const method = req.method ?? "GET";
    const rawUrl = req.url ?? "/";
    const record: RecordedRequest = { method, url: rawUrl, headers: req.headers, body };
    this.requests.push(record);
    const en = (req.headers["accept-language"] ?? "").toString().startsWith("en");
    const url = new URL(rawUrl, "http://mock");
    const path = url.pathname;

    const failureIdx = this.failures.findIndex((f) => !f.pathPrefix || path.startsWith(f.pathPrefix));
    if (failureIdx >= 0) {
      const [f] = this.failures.splice(failureIdx, 1);
      if (f!.rawBody !== undefined) {
        res.writeHead(f!.status, { "content-type": "text/html", ...(f!.headers ?? {}) });
        res.end(f!.rawBody);
      } else {
        this.#error(res, f!.status, f!.code ?? "INTERNAL", f!.message ?? (en ? "scripted failure" : "预设错误"), f!.details ?? {}, f!.headers ?? {});
      }
      return;
    }

    let json: Record<string, unknown> = {};
    if (body.length > 0) {
      try {
        json = JSON.parse(body.toString("utf8")) as Record<string, unknown>;
      } catch {
        this.#error(res, 400, "INVALID_REQUEST", "invalid JSON");
        return;
      }
    }

    if (method === "GET" && path === "/v1/health") {
      this.#json(res, 200, { status: "ok", version: "mock-1", executor_online: true, protection_level: "compatible" });
      return;
    }

    if (method === "POST" && path === "/v1/connections/pair") {
      const { host_type, display_name, transport, public_key } = json as Record<string, string>;
      if (!host_type || !display_name || !transport || !public_key || Buffer.from(public_key, "base64url").length !== 32) {
        this.#error(res, 400, "INVALID_REQUEST", "bad pairing request");
        return;
      }
      const connectionId = `conn_${ulid()}`;
      const pairingRequestId = `pair_${ulid()}`;
      this.connections.set(connectionId, { connectionId, publicKey: public_key, status: "pending" });
      const code = String(100000 + (randomBytes(4).readUInt32BE(0) % 900000));
      const expiresAt = this.now() + this.pairingTtlSeconds;
      this.pairings.set(pairingRequestId, { pairingRequestId, connectionId, code, expiresAt, status: "pending", polls: 0 });
      this.#json(res, 201, {
        pairing_request_id: pairingRequestId,
        connection_id: connectionId,
        pairing_code: code,
        expires_at: new Date(expiresAt * 1000).toISOString().replace(/\.\d{3}Z$/, "Z"),
      });
      return;
    }

    const pairMatch = /^\/v1\/connections\/pair\/([^/]+)$/.exec(path);
    if (method === "GET" && pairMatch) {
      const pairing = this.pairings.get(decodeURIComponent(pairMatch[1]!));
      if (!pairing) {
        this.#error(res, 404, "NOT_FOUND", "not found");
        return;
      }
      const auth = this.#authenticate(req, body, (kid) => kid === pairing.connectionId);
      if ("code" in auth || auth.principal !== pairing.connectionId) {
        this.#error(res, 401, "IDENTITY_UNVERIFIED", "signature required");
        return;
      }
      record.principal = auth.principal;
      pairing.polls += 1;
      if (pairing.status === "pending" && this.pairingDecisionAfterPolls !== undefined && pairing.polls >= this.pairingDecisionAfterPolls) {
        pairing.status = this.pairingDecision;
        const conn = this.connections.get(pairing.connectionId)!;
        conn.status = this.pairingDecision === "approved" ? "active" : "denied";
      }
      this.#json(res, 200, { status: pairing.status, connection_id: pairing.connectionId });
      return;
    }

    // Everything below is connection-authenticated ("C").
    const auth = this.#authenticate(req, body);
    if ("code" in auth) {
      this.#error(res, auth.status, auth.code, en ? "authentication failed" : "身份验证失败");
      return;
    }
    const principal = auth.principal;
    record.principal = principal;

    if (method === "GET" && path === "/v1/resources") {
      const projectId = url.searchParams.get("project_id");
      const service = url.searchParams.get("service");
      const resources = this.resources.filter((r) => (!projectId || r.project_id === projectId) && (!service || r.service === service));
      this.#json(res, 200, { resources });
      return;
    }

    if (method === "POST" && path === "/v1/operations") {
      const { resource_id, operation, parameters, idempotency_key } = json as {
        resource_id?: string;
        operation?: string;
        parameters?: unknown;
        idempotency_key?: string;
      };
      if (!resource_id || !operation || typeof parameters !== "object" || !idempotency_key || idempotency_key.length > 128) {
        this.#error(res, 400, "INVALID_REQUEST", "bad operation request");
        return;
      }
      const resource = this.resources.find((r) => r.resource_id === resource_id);
      if (!resource) {
        this.#error(res, 404, "NOT_FOUND", en ? "not found" : "未找到");
        return;
      }
      const digest = createHash("sha256").update(JSON.stringify({ resource_id, operation, parameters })).digest("base64url");
      const idemKey = `${principal}:${idempotency_key}`;
      const existingId = this.idempotency.get(idemKey);
      if (existingId) {
        const existing = this.operations.get(existingId)!;
        if (existing.paramsDigest !== digest) {
          this.#error(res, 409, "IDEMPOTENCY_CONFLICT", en ? "idempotency conflict" : "幂等键冲突");
          return;
        }
        this.#json(res, existing.response.status === "approval_required" ? 202 : 200, existing.response);
        return;
      }
      if (resource.executor_status === "offline") {
        this.#error(res, 503, "EXECUTOR_OFFLINE", en ? "executor offline" : "执行设备离线");
        return;
      }
      const operationId = `op_${ulid()}`;
      let response: OperationResponse;
      if (this.granted.has(`${principal}:${resource_id}`)) {
        response = { status: "succeeded", operation_id: operationId, result: structuredClone(SAMPLE_RESULT) };
      } else {
        response = {
          status: "approval_required",
          operation_id: operationId,
          approval_request_id: `apr_${ulid()}`,
          expires_in_seconds: 120,
          message: en ? APPROVAL_MESSAGE_EN : APPROVAL_MESSAGE_ZH,
        };
      }
      this.operations.set(operationId, { owner: principal, paramsDigest: digest, response, polls: 0 });
      this.idempotency.set(idemKey, operationId);
      this.#json(res, response.status === "approval_required" ? 202 : 200, response);
      return;
    }

    const opMatch = /^\/v1\/operations\/([^/]+)(\/cancel)?$/.exec(path);
    if (opMatch) {
      const op = this.operations.get(decodeURIComponent(opMatch[1]!));
      if (!op || op.owner !== principal) {
        this.#error(res, 404, "NOT_FOUND", en ? "not found" : "未找到");
        return;
      }
      if (method === "GET" && !opMatch[2]) {
        op.polls += 1;
        if (op.response.status === "approval_required" && this.approveOperationsAfterPolls !== undefined && op.polls >= this.approveOperationsAfterPolls) {
          this.#applyDecision(op, this.operationDecision);
        }
        this.#json(res, 200, op.response);
        return;
      }
      if (method === "POST" && opMatch[2]) {
        const terminal = ["succeeded", "failed", "unknown", "denied", "expired", "cancelled"].includes(op.response.status);
        if (!terminal) op.response.status = "cancelled";
        this.#json(res, 200, {
          operation_id: op.response.operation_id,
          status: op.response.status,
          cancelled: !terminal,
          side_effects: "none",
          message: terminal ? "already finished" : "cancelled",
        });
        return;
      }
    }

    if (method === "POST" && path === "/v1/access/requests") {
      const { resource_id, operations } = json as { resource_id?: string; operations?: unknown };
      if (!resource_id || !Array.isArray(operations) || operations.length === 0) {
        this.#error(res, 400, "INVALID_REQUEST", "bad access request");
        return;
      }
      if (!this.resources.some((r) => r.resource_id === resource_id)) {
        this.#error(res, 404, "NOT_FOUND", "not found");
        return;
      }
      const id = `apr_${ulid()}`;
      const stored: StoredAccess = { owner: principal, response: { approval_request_id: id, status: "pending" }, polls: 0 };
      this.access.set(id, stored);
      this.#json(res, 202, stored.response);
      return;
    }

    const accMatch = /^\/v1\/access\/requests\/([^/]+)$/.exec(path);
    if (method === "GET" && accMatch) {
      const acc = this.access.get(decodeURIComponent(accMatch[1]!));
      if (!acc || acc.owner !== principal) {
        this.#error(res, 404, "NOT_FOUND", "not found");
        return;
      }
      acc.polls += 1;
      if (acc.response.status === "pending" && this.approveAccessAfterPolls !== undefined && acc.polls >= this.approveAccessAfterPolls) {
        const grantId = `grt_${ulid()}`;
        acc.response = { ...acc.response, status: "approved", grant_id: grantId };
        this.grants.set(grantId, { owner: principal, status: "active" });
      }
      this.#json(res, 200, acc.response);
      return;
    }

    const grantMatch = /^\/v1\/access\/grants\/([^/]+)\/release$/.exec(path);
    if (method === "POST" && grantMatch) {
      const grantId = decodeURIComponent(grantMatch[1]!);
      const grant = this.grants.get(grantId);
      if (!grant || grant.owner !== principal) {
        this.#error(res, 404, "NOT_FOUND", "not found");
        return;
      }
      grant.status = "released";
      this.#json(res, 200, { grant_id: grantId, status: "released" });
      return;
    }

    this.#error(res, 404, "NOT_FOUND", "no route");
  }
}
