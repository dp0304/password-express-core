// SPDX-License-Identifier: Apache-2.0
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  anthropicTools,
  canonicalToolName,
  handleToolCall,
  jsonSchemaTools,
  openAIResponsesTools,
  openAITools,
  systemPrompt,
  toAnthropicToolResult,
  TOOL_NAMES,
  toolDefinitions,
  toOpenAIResponsesOutput,
  toOpenAIToolMessage,
} from "../src/index.js";
import { LURE_RESOURCE } from "./mock-broker.js";
import { tcpHarness, type Harness } from "./helpers.js";

const CONTRACT_TOOLS = ["resources_list", "operations_request", "operations_status", "operations_cancel", "access_request", "access_release"];
const FORBIDDEN_TOOLS = /get_password|export_vault|get_cookie|get_refresh_token|exec|http_forward/;

describe("tool definitions (CONTRACTS §9)", () => {
  it("use exactly the contract names, valid for OpenAI/Anthropic name rules", () => {
    expect([...TOOL_NAMES]).toEqual(CONTRACT_TOOLS);
    for (const d of toolDefinitions()) {
      expect(d.name).toMatch(/^[a-zA-Z0-9_-]{1,64}$/);
      expect(d.name).not.toMatch(FORBIDDEN_TOOLS);
      expect(d.input_schema.type).toBe("object");
      expect(d.input_schema.additionalProperties).toBe(false);
      expect(d.description.length).toBeGreaterThan(10);
    }
  });

  it("operations_request requires the §9 inputs", () => {
    const def = toolDefinitions().find((d) => d.name === "operations_request")!;
    expect(def.input_schema.required).toEqual(["resource_id", "operation", "parameters", "idempotency_key"]);
    const access = toolDefinitions().find((d) => d.name === "access_request")!;
    expect(Object.keys(access.input_schema.properties as object)).toEqual(["resource_id", "operations", "scope", "duration_seconds", "reason"]);
  });

  it("zh-CN by default, complete English on request", () => {
    const zh = toolDefinitions();
    const en = toolDefinitions({ locale: "en" });
    expect(zh[0]!.description).toMatch(/[一-鿿]/);
    for (const d of en) {
      expect(d.description).not.toMatch(/[一-鿿]/);
      expect(JSON.stringify(d.input_schema)).not.toMatch(/[一-鿿]/);
    }
    expect(JSON.stringify(zh[1]!.input_schema)).toMatch(/[一-鿿]/);
  });

  it("provider shapes: OpenAI chat, OpenAI responses, Anthropic, generic", () => {
    const oa = openAITools({ locale: "en" });
    expect(oa[0]).toEqual({ type: "function", function: { name: "resources_list", description: expect.any(String), parameters: expect.any(Object) } });
    const resp = openAIResponsesTools();
    expect(resp[1]).toMatchObject({ type: "function", name: "operations_request", strict: false });
    const an = anthropicTools();
    expect(Object.keys(an[2]!).sort()).toEqual(["description", "input_schema", "name"]);
    expect(jsonSchemaTools()).toEqual(toolDefinitions());
    // Everything is plain JSON.
    expect(JSON.parse(JSON.stringify(an))).toEqual(an);
  });

  it("system prompt explains approval_required and forbids asking for secrets (zh + en)", () => {
    const zh = systemPrompt();
    expect(zh).toContain("approval_required");
    expect(zh).toContain("operations_status");
    expect(zh).toContain("绝不要求用户在对话中粘贴密码");
    const en = systemPrompt({ locale: "en" });
    expect(en).toContain("approval_required");
    expect(en).toMatch(/Never ask the user to paste passwords/);
    expect(en).not.toMatch(/[一-鿿]/);
  });

  it("accepts the design-doc dotted aliases", () => {
    expect(canonicalToolName("operations.request")).toBe("operations_request");
    expect(canonicalToolName("resources_list")).toBe("resources_list");
    expect(canonicalToolName("get_password")).toBeUndefined();
  });
});

describe("handleToolCall", () => {
  let h: Harness;
  beforeEach(async () => {
    h = await tcpHarness();
  });
  afterEach(async () => {
    await h.cleanup();
  });

  it("resources_list → {resources}", async () => {
    const r = await handleToolCall(h.client, "resources_list", { service: "postgres" });
    expect(r.isError).toBe(false);
    expect((r.structuredContent.resources as unknown[]).length).toBe(2);
    expect(JSON.parse(r.text)).toEqual(r.structuredContent);
  });

  it("operations_request (JSON string args, as OpenAI sends them) → approval_required is not an error and carries the hint", async () => {
    const args = JSON.stringify({
      resource_id: LURE_RESOURCE.resource_id,
      operation: "postgres.query_view",
      parameters: { view: "analytics.subscription_daily", fields: ["day", "plan", "subscriptions"], period_days: 30 },
      idempotency_key: "tool-1",
    });
    const r = await h.client.handleToolCall("operations_request", args);
    expect(r.isError).toBe(false);
    expect(r.structuredContent.status).toBe("approval_required");
    expect(r.text).toContain("已配对的手机或可信客户端");
    expect(r.text).toContain("不要要求用户在对话中提供密码");
    const [json] = r.text.split("\n\n");
    expect(JSON.parse(json!)).toEqual(r.structuredContent);

    // Then operations_status after the user approves.
    h.broker.decideOperation(r.structuredContent.operation_id as string, "succeeded");
    const s = await handleToolCall(h.client, "operations.status", { operation_id: r.structuredContent.operation_id }, { locale: "en" });
    expect(s).toMatchObject({ tool: "operations_status", isError: false });
    expect((s.structuredContent.result as { rows: number }).rows).toBe(3);
  });

  it("settleMs waits briefly for running operations but never for approval", async () => {
    h.broker.granted.add(`${h.key.connectionId}:${LURE_RESOURCE.resource_id}`);
    const r = await handleToolCall(
      h.client,
      "operations_request",
      { resource_id: LURE_RESOURCE.resource_id, operation: "postgres.query_view", parameters: {}, idempotency_key: "tool-settle" },
      { settleMs: 500 },
    );
    expect(r.structuredContent.status).toBe("succeeded");
    h.broker.granted.clear();
    const started = Date.now();
    const p = await handleToolCall(
      h.client,
      "operations_request",
      { resource_id: LURE_RESOURCE.resource_id, operation: "postgres.query_view", parameters: {}, idempotency_key: "tool-settle-2" },
      { settleMs: 5000 },
    );
    expect(p.structuredContent.status).toBe("approval_required");
    expect(Date.now() - started).toBeLessThan(1000);
  });

  it("operations_cancel, access_request, access_release", async () => {
    const op = await h.client.requestOperation({ resource_id: LURE_RESOURCE.resource_id, operation: "postgres.query_view", parameters: {}, idempotency_key: "tool-c" });
    const c = await handleToolCall(h.client, "operations_cancel", { operation_id: op.operation_id });
    expect(c.structuredContent).toMatchObject({ cancelled: true, side_effects: "none" });

    const a = await handleToolCall(h.client, "access_request", {
      resource_id: LURE_RESOURCE.resource_id,
      operations: ["postgres.query_view"],
      scope: { operations: ["postgres.query_view"], postgres: { views: { "analytics.subscription_daily": ["day", "plan", "subscriptions"] } } },
      duration_seconds: 900,
      reason: "订阅分析",
    });
    expect(a.isError).toBe(false);
    expect(a.structuredContent.status).toBe("pending");
    expect(a.text).toContain("等待用户在可信设备上批准");

    h.broker.approveAccessAfterPolls = 1;
    const approved = await h.client.getAccessRequest(a.structuredContent.approval_request_id as string);
    const rel = await handleToolCall(h.client, "access_release", { grant_id: approved.grant_id });
    expect(rel.structuredContent).toEqual({ grant_id: approved.grant_id, status: "released" });
  });

  it("broker errors become isError results with {error:{code,message}} and a safe hint", async () => {
    h.broker.failNext({ status: 409, code: "INTERACTIVE_AUTH_REQUIRED", message: "需要重新登录 GitHub" });
    const r = await handleToolCall(h.client, "resources_list", {});
    expect(r.isError).toBe(true);
    expect(r.structuredContent).toEqual({ error: { code: "INTERACTIVE_AUTH_REQUIRED", message: "需要重新登录 GitHub" } });
    expect(r.text).toContain("不要在对话中索要密码");
    expect(toAnthropicToolResult("toolu_1", r)).toEqual({ type: "tool_result", tool_use_id: "toolu_1", content: r.text, is_error: true });

    const nf = await handleToolCall(h.client, "operations_status", { operation_id: "op_01jbz3k6w8a7m2q4t5v9xnone0" });
    expect(nf.structuredContent).toMatchObject({ error: { code: "NOT_FOUND" } });
  });

  it("invalid arguments are rejected locally (INVALID_REQUEST), unknown tools too", async () => {
    const before = h.broker.requests.length;
    const cases: Array<[string, unknown]> = [
      ["operations_request", { resource_id: LURE_RESOURCE.resource_id, operation: "x", parameters: {} }], // no idempotency_key
      ["operations_request", "{not json"],
      ["operations_request", [1, 2]],
      ["operations_status", {}],
      ["access_request", { resource_id: LURE_RESOURCE.resource_id, operations: [] }],
      ["access_request", { resource_id: LURE_RESOURCE.resource_id, operations: ["x"], duration_seconds: 999999 }],
      ["access_release", { grant_id: 5 }],
    ];
    for (const [name, args] of cases) {
      const r = await handleToolCall(h.client, name, args);
      expect(r.isError, `${name} ${JSON.stringify(args)}`).toBe(true);
      expect((r.structuredContent.error as { code: string }).code).toBe("INVALID_REQUEST");
    }
    const unknown = await handleToolCall(h.client, "get_password", { entry: "x" });
    expect(unknown).toMatchObject({ isError: true, tool: "get_password" });
    expect(h.broker.requests.length).toBe(before);
  });

  it("tool output never contains the connection key or Authorization material", async () => {
    const seed = h.key.signingKey.exportSeed().toString("base64url");
    const outputs = [
      await handleToolCall(h.client, "resources_list", {}),
      await handleToolCall(h.client, "operations_request", {
        resource_id: LURE_RESOURCE.resource_id,
        operation: "postgres.query_view",
        parameters: {},
        idempotency_key: "tool-leak",
      }),
      await handleToolCall(h.client, "operations_status", { operation_id: "op_missing0000" }),
    ];
    for (const o of outputs) {
      const text = JSON.stringify(o);
      expect(text).not.toContain(seed);
      expect(text).not.toMatch(/AIPass-Sig|sig=|Bearer /);
    }
  });

  it("provider result envelopes", async () => {
    const r = await handleToolCall(h.client, "resources_list", {});
    expect(toOpenAIToolMessage("call_1", r)).toEqual({ role: "tool", tool_call_id: "call_1", content: r.text });
    expect(toOpenAIResponsesOutput("call_2", r)).toEqual({ type: "function_call_output", call_id: "call_2", output: r.text });
    expect(toAnthropicToolResult("toolu_2", r)).toEqual({ type: "tool_result", tool_use_id: "toolu_2", content: r.text });
  });
});
