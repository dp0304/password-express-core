// SPDX-License-Identifier: Apache-2.0
// Pure UI logic (unit-tested with vitest): approval screen rows in design-doc §5.3 order,
// narrowing an access request, storage form validation, item grouping and the
// exception (§11.5) detector.

import type { AccessSpec, ApprovalRequest, AppStatus, ItemSummary, StorageInput } from "./api";
import { type Lang, translate, type Key } from "./i18n";

export interface Row { label: string; value: string; tone?: "ok" | "warn" }

/** Rows of the approval screen in the fixed §5.3 order. */
export function approvalRows(req: ApprovalRequest, lang: Lang): Row[] {
  const t = (k: Key, v?: Record<string, string | number>) => translate(lang, k, v);
  const spec = req.requested;
  const rows: Row[] = [];
  rows.push({
    label: t("apRequester"),
    value: `${req.connection.display_name} · ${req.connection.verified ? t("apVerified") : t("apUnverified")}`,
    tone: req.connection.verified ? "ok" : "warn",
  });
  rows.push({ label: t("apResource"), value: `${req.resource.alias}（${req.resource.service} · ${req.resource.environment === "production" ? t("rProd") : t("rTest")}）` });
  rows.push({ label: t("apOperation"), value: spec.operations.join("、") });
  const data = dataFields(spec);
  if (data.length) rows.push({ label: t("apData"), value: data.join("；") });
  const excluded = Object.entries(req.excluded_fields ?? {}).flatMap(([, f]) => f);
  if (excluded.length) rows.push({ label: t("apExcluded"), value: excluded.join("、"), tone: "ok" });
  rows.push({ label: t("apScope"), value: scopeText(spec, lang) });
  rows.push({ label: t("apLimits"), value: t("apRows", { n: spec.limits.max_rows_per_operation.toLocaleString() }) });
  rows.push({ label: t("apDuration"), value: `${spec.mode === "task" ? t("apTask") + "，" : ""}${t("apMinutes", { n: Math.max(1, Math.round(spec.duration_seconds / 60)) })}` });
  rows.push({ label: t("apLocation"), value: `${req.executor.name} · ${req.executor.protection_level === "isolated" ? t("exIsolated") : t("exCompatible")}` });
  const recips = req.recipients.length ? req.recipients.map((r) => r.display_name).join("、") + " · " + t("apRecipientsDefault") : t("apRecipientsDefault");
  rows.push({ label: t("apRecipients"), value: recips });
  return rows;
}

export function dataFields(spec: AccessSpec): string[] {
  const out: string[] = [];
  for (const [view, fields] of Object.entries(spec.scope.postgres?.views ?? {})) out.push(`${view}: ${fields.join(", ")}`);
  for (const repo of spec.scope.github?.repos ?? []) out.push(repo);
  for (const op of spec.scope.http_api?.operations ?? []) out.push(op);
  return out;
}

function scopeText(spec: AccessSpec, lang: Lang): string {
  const parts = [...spec.scope.operations];
  return parts.length ? parts.join(", ") : translate(lang, "none");
}

/** Build a narrowed spec: fewer fields / repos / operations, fewer rows, shorter duration. Never wider. */
export function narrowSpec(
  spec: AccessSpec,
  changes: { removeFields?: Record<string, string[]>; removeRepos?: string[]; removeHttpOps?: string[]; maxRows?: number; durationSeconds?: number },
): AccessSpec {
  const next: AccessSpec = JSON.parse(JSON.stringify(spec));
  if (next.scope.postgres && changes.removeFields) {
    for (const [view, fields] of Object.entries(changes.removeFields)) {
      const cur = next.scope.postgres.views[view];
      if (!cur) continue;
      const kept = cur.filter((f) => !fields.includes(f));
      if (kept.length) next.scope.postgres.views[view] = kept;
      else delete next.scope.postgres.views[view];
    }
  }
  if (next.scope.github && changes.removeRepos) next.scope.github.repos = next.scope.github.repos.filter((r) => !changes.removeRepos!.includes(r));
  if (next.scope.http_api && changes.removeHttpOps) next.scope.http_api.operations = next.scope.http_api.operations.filter((o) => !changes.removeHttpOps!.includes(o));
  if (changes.maxRows !== undefined) {
    const n = Math.max(1, Math.min(Math.floor(changes.maxRows), spec.limits.max_rows_per_operation));
    next.limits.max_rows_per_operation = n;
    next.limits.max_rows_per_grant = Math.min(next.limits.max_rows_per_grant, Math.max(n, 1) * Math.max(1, Math.floor(spec.limits.max_rows_per_grant / Math.max(1, spec.limits.max_rows_per_operation))));
  }
  if (changes.durationSeconds !== undefined) next.duration_seconds = Math.max(60, Math.min(Math.floor(changes.durationSeconds), spec.duration_seconds));
  return next;
}

/** True when `narrow` is within `orig` (mirrors the Rust subset check closely enough for UI gating). */
export function isNarrower(narrow: AccessSpec, orig: AccessSpec): boolean {
  if (narrow.duration_seconds > orig.duration_seconds) return false;
  const l = narrow.limits, o = orig.limits;
  if (l.max_rows_per_operation > o.max_rows_per_operation || l.max_rows_per_grant > o.max_rows_per_grant || l.max_requests_per_grant > o.max_requests_per_grant || l.max_result_bytes > o.max_result_bytes) return false;
  for (const [v, fs] of Object.entries(narrow.scope.postgres?.views ?? {})) {
    const of = orig.scope.postgres?.views[v];
    if (!of || fs.some((f) => !of.includes(f))) return false;
  }
  if ((narrow.scope.github?.repos ?? []).some((r) => !(orig.scope.github?.repos ?? []).includes(r))) return false;
  if ((narrow.scope.http_api?.operations ?? []).some((r) => !(orig.scope.http_api?.operations ?? []).includes(r))) return false;
  return narrow.operations.every((op) => orig.operations.includes(op));
}

export function secondsLeft(expiresAt: string, now = Date.now()): number {
  return Math.max(0, Math.floor((Date.parse(expiresAt) - now) / 1000));
}

/** Client-side checks before sending a storage selection to Rust (Rust validates again). */
export function validateStorage(s: StorageInput): Key | null {
  switch (s.kind) {
    case "local":
      return s.path && !s.path.startsWith("/") && !/^[A-Za-z]:\\/.test(s.path) ? "folder" : null;
    case "s3":
      if (!s.endpoint?.startsWith("https://")) return "endpoint";
      if (!s.bucket) return "bucket";
      if (!s.access_key_id) return "accessKey";
      if (!s.secret) return "secretKey";
      return null;
    case "selfhost":
      return s.base_url?.startsWith("https://") ? null : "nodeUrl";
    default:
      return null;
  }
}

export interface Group { key: string; title: string; items: ItemSummary[] }

/** Group items by project, then by service (registrable host of the primary URL). */
export function groupItems(items: ItemSummary[], projectNames: Record<string, string>, noProject: string): Group[] {
  const groups = new Map<string, Group>();
  for (const it of items) {
    const key = it.project_id ?? "_";
    const title = it.project_id ? projectNames[it.project_id] ?? it.project_id : noProject;
    if (!groups.has(key)) groups.set(key, { key, title, items: [] });
    groups.get(key)!.items.push(it);
  }
  const list = [...groups.values()];
  for (const g of list) g.items.sort((a, b) => serviceOf(a).localeCompare(serviceOf(b)) || a.title.localeCompare(b.title));
  return list.sort((a, b) => (a.key === "_" ? 1 : b.key === "_" ? -1 : a.title.localeCompare(b.title)));
}

export function serviceOf(it: ItemSummary): string {
  if (!it.primary_url) return it.title.toLowerCase();
  try {
    const h = new URL(it.primary_url).hostname;
    return h.split(".").slice(-2).join(".");
  } catch {
    return it.title.toLowerCase();
  }
}

export type ExceptionKind = "push" | "executor" | "site" | "signup" | "revoke" | "conflict" | "recovery" | "host";
export const ALL_EXCEPTIONS: ExceptionKind[] = ["push", "executor", "site", "signup", "revoke", "conflict", "recovery", "host"];

/** Exceptions derived from app state (others are raised by specific flows). */
export function detectExceptions(st: AppStatus, extra: { partialRevokes?: number; executorOffline?: boolean } = {}): ExceptionKind[] {
  const out: ExceptionKind[] = [];
  if (st.has_vault && !st.core.recovery_verified) out.push("recovery");
  if ((st.core.conflicts ?? 0) > 0) out.push("conflict");
  if (extra.partialRevokes) out.push("revoke");
  if (extra.executorOffline || (st.unlocked && !st.node_running)) out.push("executor");
  return out;
}

/** Map an error code from Rust to the exception page that explains it. */
export function exceptionForError(code: string): ExceptionKind | null {
  switch (code) {
    case "EXECUTOR_OFFLINE":
    case "CONTROL_CHANNEL_LOST":
      return "executor";
    case "SYNC_CONFLICT":
      return "conflict";
    case "UPSTREAM_OUTCOME_UNKNOWN":
      return "signup";
    case "INTERACTIVE_AUTH_REQUIRED":
      return "site";
    default:
      return null;
  }
}

export function diffLineClass(line: string): "add" | "del" | "" {
  if (line.startsWith("+") && !line.startsWith("+++")) return "add";
  if (line.startsWith("-") && !line.startsWith("---")) return "del";
  return "";
}
