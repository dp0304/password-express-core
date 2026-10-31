// SPDX-License-Identifier: Apache-2.0
// Approval screen (design doc §5.3): requester, resource, operation, data fields (and
// excluded fields), scope/limits/duration, execution location, result recipients, then
// 允许本次 / 选择较小权限 / 拒绝 and 转到手机处理. Nothing is ever approved on timeout.
import { useEffect, useState } from "react";
import { api, type ApprovalRequest } from "../api";
import { approvalRows, isNarrower, narrowSpec, secondsLeft } from "../logic";
import { loc } from "../i18n";
import { ErrorText, Field, Modal, useAction, useApp } from "../ui";

export function ApprovalModal(props: { request: ApprovalRequest; unlocked: boolean; onDone: () => void; onDefer: () => void }) {
  const { t, lang, toast } = useApp();
  const req = props.request;
  const [left, setLeft] = useState(secondsLeft(req.expires_at));
  const [narrowing, setNarrowing] = useState(false);
  const [removeFields, setRemoveFields] = useState<Record<string, string[]>>({});
  const [removeRepos, setRemoveRepos] = useState<string[]>([]);
  const [maxRows, setMaxRows] = useState(req.requested.limits.max_rows_per_operation);
  const [minutes, setMinutes] = useState(Math.max(1, Math.round(req.requested.duration_seconds / 60)));
  const { busy, error, run } = useAction();
  // Fresh presence for this one decision (CLI-01): the core refuses approvals without it.
  const [pw, setPw] = useState("");
  const approve = async (spec: typeof narrowed | undefined, msg: string) => {
    const r = await run(() => api.approve(req.approval_request_id, req.request_digest, pw, spec));
    setPw("");
    if (r) finish(msg);
  };

  useEffect(() => {
    const h = window.setInterval(() => setLeft(secondsLeft(req.expires_at)), 1000);
    return () => window.clearInterval(h);
  }, [req.expires_at]);

  const expired = left <= 0;
  const narrowed = narrowSpec(req.requested, { removeFields, removeRepos, maxRows, durationSeconds: minutes * 60 });
  const valid = isNarrower(narrowed, req.requested);
  const finish = (msg: string) => { toast(msg); props.onDone(); };

  return (
    <Modal title={`${t("apTitle")} · ${req.connection.display_name}`} onClose={props.onDefer} wide>
      <p><strong>{loc(lang, req.summary)}</strong></p>
      <dl className="kv" aria-label={t("apTitle")}>
        {approvalRows(req, lang).map((r) => (
          <div key={r.label} style={{ display: "contents" }}>
            <dt>{r.label}</dt>
            <dd className={r.tone === "warn" ? "badge warn" : undefined}>{r.value}</dd>
          </div>
        ))}
      </dl>
      <p className={`small ${expired ? "badge danger" : "muted"}`}>{expired ? t("apExpired") : t("apExpiresIn", { s: left })} · {t("apNoAutoApprove")}</p>

      {narrowing && (
        <fieldset className="card col">
          <legend>{t("apNarrow")}</legend>
          {Object.entries(req.requested.scope.postgres?.views ?? {}).map(([view, fields]) => (
            <div key={view}>
              <div className="small muted">{view}</div>
              <div className="row">
                {fields.map((f) => {
                  const off = (removeFields[view] ?? []).includes(f);
                  return (
                    <label key={f} className="row small">
                      <input type="checkbox" checked={!off} onChange={(e) => setRemoveFields({ ...removeFields, [view]: e.target.checked ? (removeFields[view] ?? []).filter((x) => x !== f) : [...(removeFields[view] ?? []), f] })} />
                      {f}
                    </label>
                  );
                })}
              </div>
            </div>
          ))}
          {(req.requested.scope.github?.repos ?? []).map((r) => (
            <label key={r} className="row small"><input type="checkbox" checked={!removeRepos.includes(r)} onChange={(e) => setRemoveRepos(e.target.checked ? removeRepos.filter((x) => x !== r) : [...removeRepos, r])} />{r}</label>
          ))}
          <div className="grid2">
            <Field label={t("apLimits")}><input type="number" min={1} max={req.requested.limits.max_rows_per_operation} value={maxRows} onChange={(e) => setMaxRows(Number(e.target.value))} /></Field>
            <Field label={t("apDuration")}><input type="number" min={1} max={Math.round(req.requested.duration_seconds / 60)} value={minutes} onChange={(e) => setMinutes(Number(e.target.value))} /></Field>
          </div>
        </fieldset>
      )}

      {!props.unlocked && <div className="notice warn small">{t("apUnlockFirst")}</div>}
      {props.unlocked && !expired && (
        <Field label={t("apConfirmPw")}>
          <input type="password" autoComplete="current-password" value={pw} onChange={(e) => setPw(e.target.value)} aria-describedby="ap-confirm-desc" />
        </Field>
      )}
      {props.unlocked && !expired && <p id="ap-confirm-desc" className="small muted">{t("apConfirmPwDesc")}</p>}
      <div className="notice info small">{t("apToPhoneDesc")}</div>
      <ErrorText error={error} />
      <div className="modal-actions">
        <button className="btn" onClick={props.onDefer}>{t("apToPhone")}</button>
        <button className="btn danger" disabled={busy || expired} onClick={async () => { const r = await run(() => api.deny(req.approval_request_id, req.request_digest)); if (r) finish(t("apDeny")); }}>{t("apDeny")}</button>
        {narrowing ? (
          <button className="btn primary" disabled={busy || expired || !props.unlocked || !valid || !pw} onClick={() => approve(narrowed, t("apNarrow"))}>{t("confirm")}</button>
        ) : (
          <>
            <button className="btn" disabled={busy || expired} onClick={() => setNarrowing(true)}>{t("apNarrow")}</button>
            <button className="btn primary" disabled={busy || expired || !props.unlocked || !pw} onClick={() => approve(undefined, t("apAllowOnce"))}>{t("apAllowOnce")}</button>
          </>
        )}
      </div>
    </Modal>
  );
}
