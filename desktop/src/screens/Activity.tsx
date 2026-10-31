// SPDX-License-Identifier: Apache-2.0
import { useState } from "react";
import { api, type ApprovalRequest } from "../api";
import { loc } from "../i18n";
import { Badge, ErrorText, Modal, fmtTime, useAction, useApp, useLoad } from "../ui";
import { ExceptionCard } from "./Exceptions";

type Tab = "approvals" | "operations" | "grants" | "audit";
const LEVELS = [["stop_access", "lvStop"], ["end_sessions", "lvEnd"], ["revoke_upstream", "lvUpstream"]] as const;

export function Activity(props: { approvals: ApprovalRequest[]; onOpenApproval: (id: string) => void }) {
  const { t, lang } = useApp();
  const [tab, setTab] = useState<Tab>("approvals");
  const ops = useLoad(() => api.operations(), [tab]);
  const grants = useLoad(() => api.grants(), [tab]);
  const audit = useLoad(() => api.audit(), [tab]);
  const [verify, setVerify] = useState<any | null>(null);
  const [report, setReport] = useState<any | null>(null);
  const [revoking, setRevoking] = useState<any | null>(null);
  const { busy, error, run } = useAction();
  const tabs: [Tab, "avApprovals" | "avOperations" | "avGrants" | "avAudit"][] = [["approvals", "avApprovals"], ["operations", "avOperations"], ["grants", "avGrants"], ["audit", "avAudit"]];
  return (
    <div>
      <div className="page-head"><h1>{t("avTitle")}</h1></div>
      <div className="row" role="tablist" style={{ marginBottom: 12 }}>
        {tabs.map(([k, l]) => (
          <button key={k} role="tab" aria-selected={tab === k} className={`btn small ${tab === k ? "primary" : ""}`} onClick={() => setTab(k)}>
            {t(l)}{k === "approvals" && props.approvals.length > 0 ? ` (${props.approvals.length})` : ""}
          </button>
        ))}
      </div>
      <ErrorText error={error} />
      {tab === "approvals" && (
        <div className="col">
          <ExceptionCard kind="push" />
          <div className="list">
            {props.approvals.length === 0 && <div className="list-item muted">{t("none")}</div>}
            {props.approvals.map((a) => (
              <button key={a.approval_request_id} className="list-item" onClick={() => props.onOpenApproval(a.approval_request_id)}>
                <div className="grow"><strong>{a.connection.display_name}</strong> → {a.resource.alias}<div className="muted small">{loc(lang, a.summary)}</div></div>
                <Badge tone="warn">{t("stPending")}</Badge>
              </button>
            ))}
          </div>
        </div>
      )}
      {tab === "operations" && (
        <table>
          <thead><tr><th>ID</th><th>{t("apOperation")}</th><th>{t("apResource")}</th><th>{t("status")}</th><th>{t("details")}</th></tr></thead>
          <tbody>
            {(ops.data?.operations ?? []).map((o: any) => (
              <tr key={o.operation_id}>
                <td><code className="small">{o.operation_id}</code></td><td>{o.operation}</td><td>{o.resource_id}</td>
                <td><Badge tone={o.status === "succeeded" ? "ok" : o.status === "failed" || o.status === "unknown" ? "danger" : "warn"}>{o.status}</Badge></td>
                <td className="small muted">{o.error ? `${o.error.code}` : ""} {fmtTime(lang, o.updated_at ?? o.created_at)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {tab === "grants" && (
        <table>
          <thead><tr><th>ID</th><th>{t("apResource")}</th><th>{t("apScope")}</th><th>{t("status")}</th><th>{t("apDuration")}</th><th /></tr></thead>
          <tbody>
            {(grants.data?.grants ?? []).map((g: any) => (
              <tr key={g.grant_id}>
                <td><code className="small">{g.grant_id}</code></td><td>{g.resource_id}</td><td className="small">{(g.scope?.operations ?? []).join(", ")}</td>
                <td><Badge tone={g.status === "active" ? "ok" : g.status === "revoked" ? "danger" : undefined}>{g.status === "revoked" ? t("stRevoked") : g.status}</Badge></td>
                <td className="small">{fmtTime(lang, g.expires_at)}</td>
                <td>{g.status === "active" && <button className="btn small danger" onClick={() => setRevoking(g)}>{t("avRevoke")}</button>}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {tab === "audit" && (
        <div className="col">
          <div className="row">
            <button className="btn" disabled={busy} onClick={async () => { const r = await run(() => api.verifyAudit()); if (r) setVerify(r); }}>{t("avVerify")}</button>
            {verify && (verify.valid ? <Badge tone="ok">{t("avAuditOk", { n: verify.events_checked })}</Badge> : <Badge tone="danger">{t("avAuditBad", { r: verify.reason ?? "" })}</Badge>)}
          </div>
          <table>
            <thead><tr><th>#</th><th>{t("details")}</th><th>{t("status")}</th></tr></thead>
            <tbody>
              {(audit.data?.events ?? []).slice().reverse().map((e: any) => (
                <tr key={e.seq ?? e.event_id}><td>{e.seq}</td><td className="small">{e.kind ?? e.type} {e.connection_id ? `· ${e.connection_id}` : ""}</td><td className="small muted">{fmtTime(lang, e.at ?? e.created_at)}</td></tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {revoking && (
        <Modal title={`${t("avRevoke")} · ${revoking.grant_id}`} onClose={() => setRevoking(null)}>
          <p className="muted small">{t("avLevels")}</p>
          <div className="col">
            {LEVELS.map(([lv, label]) => (
              <button key={lv} className="btn" disabled={busy} onClick={async () => {
                const r = await run(() => api.revokeGrant(revoking.grant_id, lv));
                if (r) { setReport(r); setRevoking(null); grants.reload(); }
              }}>{t(label)}</button>
            ))}
          </div>
        </Modal>
      )}
      {report && (
        <Modal title={t("avReport")} onClose={() => setReport(null)}>
          {!report.fully_revoked && <ExceptionCard kind="revoke" />}
          <p><Badge tone={report.fully_revoked ? "ok" : "warn"}>{report.fully_revoked ? t("stRevoked") : t("stPartialRevoke")}</Badge> {report.label ? loc(lang, report.label) : ""}</p>
          <table>
            <tbody>
              {Object.entries(report.report ?? {}).filter(([, v]) => typeof v === "object" && v && "status" in (v as any)).map(([k, v]: [string, any]) => (
                <tr key={k}><td>{k}</td><td><Badge tone={v.status === "done" ? "ok" : v.status === "failed" ? "danger" : v.status === "pending" ? "warn" : undefined}>{v.status}</Badge></td><td className="small muted">{v.detail ?? ""}</td></tr>
              ))}
            </tbody>
          </table>
          <div className="modal-actions"><button className="btn" onClick={() => setReport(null)}>{t("close")}</button></div>
        </Modal>
      )}
    </div>
  );
}
