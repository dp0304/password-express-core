// SPDX-License-Identifier: Apache-2.0
import { useCallback, useEffect, useMemo, useState } from "react";
import { api, onEvent, type ApprovalRequest, type AppStatus } from "./api";
import type { Lang } from "./i18n";
import { AppCtx, type Ctx, type Page, Toast, errorText, makeT } from "./ui";
import { Onboarding } from "./screens/Onboarding";
import { Unlock } from "./screens/Unlock";
import { Overview } from "./screens/Overview";
import { Accounts } from "./screens/Accounts";
import { Connections } from "./screens/Connections";
import { Executors } from "./screens/Executors";
import { Activity } from "./screens/Activity";
import { SettingsPage } from "./screens/Settings";
import { PairPhone } from "./screens/PairPhone";
import { ApprovalModal } from "./screens/ApprovalModal";

const NAV: { page: Page; key: "navOverview" | "navAccounts" | "navConnections" | "navExecutors" | "navActivity" | "navSettings" }[] = [
  { page: "overview", key: "navOverview" },
  { page: "accounts", key: "navAccounts" },
  { page: "connections", key: "navConnections" },
  { page: "executors", key: "navExecutors" },
  { page: "activity", key: "navActivity" },
  { page: "settings", key: "navSettings" },
];

export function App() {
  const [lang, setLangState] = useState<Lang>("zh-CN");
  const [status, setStatus] = useState<AppStatus | null>(null);
  const [page, setPage] = useState<Page>("overview");
  const [toastMsg, setToastMsg] = useState<string | null>(null);
  const [approvals, setApprovals] = useState<ApprovalRequest[]>([]);
  const [deferred, setDeferred] = useState<Set<string>>(new Set());

  const refresh = useCallback(async () => {
    try {
      const s = await api.status();
      setStatus(s);
      if (s.lang === "en" || s.lang === "zh-CN") setLangState(s.lang);
    } catch {
      /* core not ready yet */
    }
  }, []);
  const loadApprovals = useCallback(async () => {
    try {
      const r = await api.approvals();
      setApprovals(r.approvals ?? []);
    } catch {
      setApprovals([]);
    }
  }, []);

  useEffect(() => {
    refresh();
    const subs = [
      onEvent("app-status", () => refresh()),
      onEvent("sync", () => refresh()),
      onEvent<{ type: string }>("broker-event", (e) => {
        if (e.type === "approval_requested" || e.type === "approval_resolved") loadApprovals();
      }),
    ];
    const timer = window.setInterval(loadApprovals, 5000);
    const activity = () => api.touch().catch(() => undefined);
    window.addEventListener("keydown", activity);
    window.addEventListener("mousedown", activity);
    return () => {
      subs.forEach((p) => p.then((u) => u()));
      window.clearInterval(timer);
      window.removeEventListener("keydown", activity);
      window.removeEventListener("mousedown", activity);
    };
  }, [refresh, loadApprovals]);

  useEffect(() => {
    if (status?.node_running) loadApprovals();
  }, [status?.node_running, loadApprovals]);

  useEffect(() => {
    document.documentElement.lang = lang;
  }, [lang]);

  const toast = useCallback((m: string) => {
    setToastMsg(m);
    window.setTimeout(() => setToastMsg((cur) => (cur === m ? null : cur)), 4000);
  }, []);

  const ctx: Ctx = useMemo(
    () => ({
      lang,
      t: makeT(lang),
      status,
      refresh,
      toast,
      errText: (e: unknown) => errorText(lang, e),
      go: setPage,
      setLang: setLangState,
    }),
    [lang, status, refresh, toast],
  );

  const t = ctx.t;
  if (!status) {
    return <div className="center-screen muted">{t("loading")}</div>;
  }
  const showOnboarding = !status.has_vault || (status.unlocked && !status.onboarding_done);
  const pending = approvals.filter((a) => a.status === "pending");
  const current = pending.find((a) => !deferred.has(a.approval_request_id));

  return (
    <AppCtx.Provider value={ctx}>
      {showOnboarding ? (
        <Onboarding />
      ) : !status.unlocked ? (
        <Unlock />
      ) : (
        <div className="shell">
          <nav className="nav" aria-label={t("appName")}>
            <div className="brand"><span className="brand-mark" aria-hidden>AP</span>{t("appName")}</div>
            {NAV.map((n) => (
              <button key={n.page} aria-current={page === n.page ? "page" : undefined} onClick={() => setPage(n.page)}>
                <span>{t(n.key)}</span>
                {n.page === "activity" && pending.length > 0 && <span className="count" aria-label={t("pendingApprovals")}>{pending.length}</span>}
              </button>
            ))}
            <div className="bottom">
              <button className="btn small" onClick={async () => { await api.lock(); refresh(); }}>{t("lockNow")}</button>
              <span className="muted small">{t("notAudited")}</span>
            </div>
          </nav>
          <main className="main">
            {page === "overview" && <Overview pending={pending.length} />}
            {page === "accounts" && <Accounts />}
            {page === "connections" && <Connections />}
            {page === "executors" && <Executors />}
            {page === "activity" && <Activity approvals={pending} onOpenApproval={(id) => setDeferred((d) => { const n = new Set(d); n.delete(id); return n; })} />}
            {page === "settings" && <SettingsPage />}
            {page === "pair" && <PairPhone />}
          </main>
        </div>
      )}
      {current && status.has_vault && (
        <ApprovalModal
          key={current.approval_request_id}
          request={current}
          unlocked={status.unlocked}
          onDone={() => loadApprovals()}
          onDefer={() => setDeferred((d) => new Set(d).add(current.approval_request_id))}
        />
      )}
      <Toast msg={toastMsg} />
    </AppCtx.Provider>
  );
}
