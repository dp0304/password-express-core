// SPDX-License-Identifier: Apache-2.0
import { api } from "../api";
import { detectExceptions } from "../logic";
import { loc } from "../i18n";
import { Badge, fmtTime, useAction, useApp, useLoad } from "../ui";
import { ExceptionCard } from "./Exceptions";

export function Overview({ pending }: { pending: number }) {
  const { t, lang, status, refresh, toast, go } = useApp();
  const summary = useLoad(() => api.summary(), [status?.node_running]);
  const items = useLoad(() => api.listItems(), []);
  const { busy, run } = useAction();
  if (!status) return null;
  const partial = (summary.data?.anomalies ?? []).filter((a: any) => a.kind === "partial_revocation").length;
  const exceptions = detectExceptions(status, { partialRevokes: partial });
  const firstRun = (items.data?.length ?? 0) === 0;
  return (
    <div>
      <div className="page-head">
        <div><h1>{t("ovTitle")}</h1><p className="muted">{t("tagline")}</p></div>
        <button className="btn" disabled={busy} onClick={async () => {
          const r = await run(() => api.syncNow());
          if (r) toast(`${r.status} · ↓${r.pulled} ↑${r.pushed}`);
          refresh();
        }}>{t("ovSyncNow")}</button>
      </div>
      {firstRun && (
        <div className="card">
          <h2>{t("obFirstActions")}</h2>
          <div className="grid2">
            <button className="choice" onClick={() => go("accounts")}><strong>{t("actImport")}</strong><div className="muted small">{t("actImportDesc")}</div></button>
            <button className="choice" onClick={() => go("connections")}><strong>{t("actConnect")}</strong><div className="muted small">{t("actConnectDesc")}</div></button>
            <button className="choice" onClick={() => go("pair")}><strong>{t("actPhone")}</strong><div className="muted small">{t("actPhoneDesc")}</div></button>
          </div>
        </div>
      )}
      <div className="card">
        <h2>{t("ovExceptions")}</h2>
        {pending > 0 && <div className="notice info row"><span className="grow">{t("pendingApprovals")}: {pending}</span><button className="btn small primary" onClick={() => go("activity")}>{t("goHandle")}</button></div>}
        {exceptions.length === 0 && pending === 0 ? <p className="muted">{t("ovAllGood")}</p> : <div className="col">{exceptions.map((k) => <ExceptionCard key={k} kind={k} />)}</div>}
        {(summary.data?.anomalies ?? []).filter((a: any) => a.kind !== "partial_revocation").map((a: any, i: number) => (
          <div key={i} className="notice warn small">{loc(lang, a.summary)}</div>
        ))}
      </div>
      <div className="grid2" style={{ marginTop: 12 }}>
        <div className="card">
          <h3>{t("ovVault")}</h3>
          <dl className="kv">
            <dt>{t("ovItems")}</dt><dd>{items.data?.length ?? "—"}</dd>
            <dt>{t("ovLastSync")}</dt><dd>{status.core.last_sync_at ? fmtTime(lang, status.core.last_sync_at) : t("ovNever")}</dd>
            <dt>{t("status")}</dt><dd>{(status.core.conflicts ?? 0) > 0 ? <Badge tone="warn">{t("stConflict")}</Badge> : status.core.last_error ? <Badge tone="warn">{t("stDeviceOffline")}</Badge> : <Badge tone="ok">{t("stAvailable")}</Badge>}</dd>
            <dt>{t("sRecovery")}</dt><dd>{status.core.recovery_verified ? <Badge tone="ok">{t("stVerified")}</Badge> : <Badge tone="warn">{t("stNeedsAction")}</Badge>}</dd>
          </dl>
        </div>
        <div className="card">
          <h3>{t("ovNode")}</h3>
          <dl className="kv">
            <dt>{t("status")}</dt><dd>{status.node_running ? <Badge tone="ok">{t("ovNodeRunning")}</Badge> : <Badge tone="warn">{t("ovNodeStopped")}</Badge>}</dd>
            <dt>{t("exProtection")}</dt><dd>{t("exCompatible")}</dd>
          </dl>
          {summary.data && (
            <p className="small muted">{t("ovRecentActivity")}: {JSON.stringify(Object.fromEntries(Object.entries(summary.data).filter(([, v]) => typeof v === "number")))}</p>
          )}
        </div>
      </div>
    </div>
  );
}
