// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from "vitest";
import type { ApprovalRequest, AppStatus, ItemSummary } from "./api";
import { approvalRows, detectExceptions, diffLineClass, exceptionForError, groupItems, isNarrower, narrowSpec, secondsLeft, validateStorage, ALL_EXCEPTIONS } from "./logic";

const req: ApprovalRequest = {
  approval_request_id: "apr_1", kind: "operation",
  connection: { connection_id: "conn_1", display_name: "Claude Code", host_type: "claude_code", verified: true },
  resource: { resource_id: "res_1", alias: "路亚站测试库", service: "PostgreSQL", environment: "test" },
  summary: { zh: "查询订阅统计视图", en: "Query the subscription stats view" },
  requested: {
    operations: ["postgres.query_view"],
    scope: { operations: ["postgres.query_view"], postgres: { views: { "public.subscription_stats": ["date", "tier", "count"] } } },
    limits: { max_rows_per_operation: 1000, max_rows_per_grant: 5000, max_requests_per_grant: 20, max_result_bytes: 262144 },
    duration_seconds: 900, mode: "task",
  },
  excluded_fields: { "public.subscription_stats": ["customer_email"] },
  executor: { executor_id: "exe_1", name: "我的服务器", protection_level: "isolated" },
  recipients: [{ connection_id: "conn_1", display_name: "Claude Code" }],
  status: "pending", created_at: "2026-10-30T12:00:00Z", expires_at: "2026-10-30T12:02:00Z", request_digest: "ETyiwt52XTTK_nZIOdGnn_F9K1AjXYlqIsHny39NlQY",
};

describe("approval screen", () => {
  it("lists fields in the §5.3 order", () => {
    const rows = approvalRows(req, "zh-CN").map((r) => r.label);
    expect(rows).toEqual(["请求方", "资源", "操作", "数据", "不含", "范围", "额度", "期限", "执行位置", "结果接收方"]);
    const en = approvalRows(req, "en");
    expect(en.find((r) => r.label === "Excludes")?.value).toBe("customer_email");
    expect(en.find((r) => r.label === "Duration")?.value).toContain("15 minutes");
    expect(en.find((r) => r.label === "Runs on")?.value).toContain("Isolated");
  });
  it("marks unverified requesters", () => {
    const r = approvalRows({ ...req, connection: { ...req.connection, verified: false } }, "zh-CN")[0];
    expect(r.tone).toBe("warn");
  });
  it("narrowing never widens", () => {
    const n = narrowSpec(req.requested, { removeFields: { "public.subscription_stats": ["tier"] }, maxRows: 100, durationSeconds: 300 });
    expect(n.scope.postgres!.views["public.subscription_stats"]).toEqual(["date", "count"]);
    expect(n.limits.max_rows_per_operation).toBe(100);
    expect(n.duration_seconds).toBe(300);
    expect(isNarrower(n, req.requested)).toBe(true);
    const wider = narrowSpec(req.requested, { maxRows: 10_000, durationSeconds: 99_999 });
    expect(wider.limits.max_rows_per_operation).toBe(1000);
    expect(wider.duration_seconds).toBe(900);
    const forged = { ...n, scope: { ...n.scope, postgres: { views: { "public.subscription_stats": ["customer_email"] } } } };
    expect(isNarrower(forged, req.requested)).toBe(false);
    expect(req.requested.scope.postgres!.views["public.subscription_stats"]).toHaveLength(3); // original untouched
  });
  it("counts down without going negative", () => {
    expect(secondsLeft("2026-10-30T12:02:00Z", Date.parse("2026-10-30T12:01:30Z"))).toBe(30);
    expect(secondsLeft("2026-10-30T12:02:00Z", Date.parse("2026-10-30T12:05:00Z"))).toBe(0);
  });
});

describe("storage form", () => {
  it("validates", () => {
    expect(validateStorage({ kind: "local" })).toBeNull();
    expect(validateStorage({ kind: "local", path: "relative/dir" })).toBe("folder");
    expect(validateStorage({ kind: "s3", endpoint: "http://x", bucket: "b", access_key_id: "a", secret: "s" })).toBe("endpoint");
    expect(validateStorage({ kind: "s3", endpoint: "https://x", bucket: "b", access_key_id: "a", secret: "s" })).toBeNull();
    expect(validateStorage({ kind: "selfhost", base_url: "https://node" })).toBeNull();
  });
});

const item = (id: string, title: string, project?: string, url?: string): ItemSummary => ({
  entry_id: id, kind: "login", title, project_id: project, primary_url: url, lifecycle: "active", has_conflict: false, pending_sync: false, tags: [], updated_at: "2026-10-30T12:00:00Z",
});

describe("grouping and exceptions", () => {
  it("groups by project with the unassigned group last", () => {
    const g = groupItems([item("a", "GitHub", undefined, "https://github.com"), item("b", "DB", "proj_1"), item("c", "Admin", "proj_1")], { proj_1: "路亚站" }, "未归入项目");
    expect(g.map((x) => x.title)).toEqual(["路亚站", "未归入项目"]);
    expect(g[0].items.map((i) => i.title)).toEqual(["Admin", "DB"]);
  });
  it("detects exceptions and maps errors", () => {
    const st = { has_vault: true, unlocked: true, node_running: false, core: { recovery_verified: false, conflicts: 2 } } as unknown as AppStatus;
    expect(detectExceptions(st, { partialRevokes: 1 })).toEqual(["recovery", "conflict", "revoke", "executor"]);
    expect(exceptionForError("EXECUTOR_OFFLINE")).toBe("executor");
    expect(exceptionForError("UPSTREAM_OUTCOME_UNKNOWN")).toBe("signup");
    expect(exceptionForError("NOT_FOUND")).toBeNull();
    expect(ALL_EXCEPTIONS).toHaveLength(8);
  });
  it("classifies diff lines", () => {
    expect(diffLineClass("+  \"aipass\": {")).toBe("add");
    expect(diffLineClass("-old")).toBe("del");
    expect(diffLineClass("+++ b/file")).toBe("");
  });
});
