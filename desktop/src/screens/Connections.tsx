// SPDX-License-Identifier: Apache-2.0
import { useState } from "react";
import { api, type PlanView } from "../api";
import { diffLineClass } from "../logic";
import { loc } from "../i18n";
import { Badge, ErrorText, Field, Modal, useAction, useApp, useLoad } from "../ui";
import { ExceptionCard } from "./Exceptions";

function ProjectPicker(props: { value: string[]; onChange: (v: string[]) => void }) {
  const { t } = useApp();
  const projects = useLoad(() => api.projects(), []);
  const all = props.value.length === 1 && props.value[0] === "*";
  return (
    <fieldset className="col">
      <legend>{t("cnAllowed")}</legend>
      <label className="row small"><input type="checkbox" checked={all} onChange={(e) => props.onChange(e.target.checked ? ["*"] : [])} />{t("cnAllProjects")}</label>
      {!all && (projects.data?.projects ?? []).map((p) => (
        <label key={p.project_id} className="row small">
          <input type="checkbox" checked={props.value.includes(p.project_id)} onChange={(e) => props.onChange(e.target.checked ? [...props.value, p.project_id] : props.value.filter((x) => x !== p.project_id))} />
          {p.name}
        </label>
      ))}
    </fieldset>
  );
}

export function Connections() {
  const { t, lang } = useApp();
  const hosts = useLoad(() => api.hostDetect(), []);
  const conns = useLoad(() => api.connections(), []);
  const [connectHost, setConnectHost] = useState<any | null>(null);
  const [remote, setRemote] = useState<any | null>(null);
  const [approving, setApproving] = useState<any | null>(null);
  const { busy, error, run } = useAction();
  const pendingConns = (conns.data ?? []).filter((c) => c.status === "pending");
  const activeConns = (conns.data ?? []).filter((c) => c.status !== "pending" && c.status !== "removed");

  return (
    <div>
      <div className="page-head"><h1>{t("cnTitle")}</h1><button className="btn" onClick={() => { hosts.reload(); conns.reload(); }}>{t("cnDetect")}</button></div>
      <ErrorText error={error} />
      {pendingConns.length > 0 && (
        <div className="card">
          <h2>{t("cnPairPending")}</h2>
          {pendingConns.map((c) => (
            <div key={c.connection_id} className="row list-item">
              <div className="grow"><strong>{c.display_name}</strong> <span className="muted small">{c.host_type}</span></div>
              {c.pairing && <span className="mono">{t("cnPairCode")}: <strong>{c.pairing.code}</strong></span>}
              <button className="btn small primary" onClick={() => setApproving(c)}>{t("cnApprove")}</button>
              <button className="btn small danger" disabled={busy} onClick={async () => { await run(() => api.denyConnection(c.connection_id)); conns.reload(); }}>{t("cnDeny")}</button>
            </div>
          ))}
        </div>
      )}
      <div className="card">
        <h2>{t("cnHosts")}</h2>
        <div className="list">
          {(hosts.data ?? []).map((h, i) => (
            <div key={`${h.host}-${h.scope ?? i}`} className="list-item">
              <div className="grow">
                <div><strong>{h.display_name}</strong> {h.scope && <span className="muted small">· {h.scope === "project" ? t("cnProject") : t("cnUser")}</span>}</div>
                <div className="muted small">{h.config_path ?? ""} {h.version ? `· ${h.version}` : ""}</div>
              </div>
              <Badge tone={h.label === "unsupported" ? "danger" : "accent"}>{loc(lang, h.label_text)}</Badge>
              {h.installed ? <Badge tone="ok">{t("cnInstalled")}</Badge> : <Badge>{t("cnNotInstalled")}</Badge>}
              {h.has_aipass_entry && <Badge tone="ok">{t("cnHasEntry")}</Badge>}
              {h.is_remote ? (
                <button className="btn small" onClick={async () => { const r = await run(() => api.remoteInstructions(h.host)); if (r) setRemote(r); }}>{t("details")}</button>
              ) : h.label === "unsupported" ? null : (
                <>
                  <button className="btn small primary" onClick={() => setConnectHost(h)}>{t("cnConnect")}</button>
                  {h.has_aipass_entry && <button className="btn small" disabled={busy} onClick={async () => { await run(() => api.hostRemove(h.host, h.scope ?? "user")); hosts.reload(); }}>{t("cnRemove")}</button>}
                </>
              )}
            </div>
          ))}
        </div>
        {(hosts.data ?? []).some((h) => h.label === "unsupported") && <div className="spacer" />}
        {(hosts.data ?? []).some((h) => h.label === "unsupported") && <ExceptionCard kind="host" />}
      </div>
      <div className="card">
        <h2>{t("cnConnections")}</h2>
        {activeConns.length === 0 && <p className="muted">{t("none")}</p>}
        <div className="list">
          {activeConns.map((c) => (
            <div key={c.connection_id} className="list-item">
              <div className="grow"><strong>{c.display_name}</strong><div className="muted small">{c.host_type} · {c.transport} · <code>{c.connection_id}</code></div></div>
              <Badge tone={c.status === "active" ? "ok" : c.status === "paused" ? "warn" : undefined}>{c.status}</Badge>
              {c.status === "active" && <button className="btn small" disabled={busy} onClick={async () => { await run(() => api.controlConnection(c.connection_id, "pause")); conns.reload(); }}>{t("cnPause")}</button>}
              {c.status === "paused" && <button className="btn small" disabled={busy} onClick={async () => { await run(() => api.controlConnection(c.connection_id, "resume")); conns.reload(); }}>{t("cnResume")}</button>}
              <button className="btn small danger" disabled={busy} onClick={async () => { await run(() => api.controlConnection(c.connection_id, "revoke_all")); conns.reload(); }}>{t("cnRevokeAll")}</button>
              <button className="btn small danger" disabled={busy} onClick={async () => { await run(() => api.controlConnection(c.connection_id, "remove")); conns.reload(); }}>{t("cnRemoveConn")}</button>
            </div>
          ))}
        </div>
      </div>
      <div className="card">
        <h2>{t("cnRemote")}</h2>
        <p className="muted small">{t("cnRemoteNote")}</p>
      </div>
      {connectHost && <ConnectWizard host={connectHost} onClose={() => { setConnectHost(null); hosts.reload(); conns.reload(); }} />}
      {approving && <ApproveConnection conn={approving} onClose={() => { setApproving(null); conns.reload(); }} />}
      {remote && (
        <Modal title={t("cnRemote")} onClose={() => setRemote(null)}>
          <p className="notice warn small">{t("cnRemoteNote")}</p>
          <dl className="kv"><dt>URL</dt><dd><code>{remote.server_url}</code></dd><dt>OAuth</dt><dd>{remote.auth} · {remote.oauth_scope}</dd></dl>
          <ol>{(remote.steps ?? []).map((s: any, i: number) => <li key={i} className="small">{typeof s === "string" ? s : loc(lang, s)}</li>)}</ol>
          <div className="modal-actions"><button className="btn" onClick={() => setRemote(null)}>{t("close")}</button></div>
        </Modal>
      )}
    </div>
  );
}

function ApproveConnection(props: { conn: any; onClose: () => void }) {
  const { t } = useApp();
  const [allowed, setAllowed] = useState<string[]>(["*"]);
  const [pw, setPw] = useState("");
  const { busy, error, run } = useAction();
  return (
    <Modal title={t("cnApprove")} onClose={props.onClose}>
      <p><strong>{props.conn.display_name}</strong> · {props.conn.host_type}</p>
      <p className="muted small">{t("cnPairCompare")}</p>
      <div className="sas">{props.conn.pairing?.code ?? "------"}</div>
      <ProjectPicker value={allowed} onChange={setAllowed} />
      <Field label={t("apConfirmPw")}>
        <input type="password" autoComplete="current-password" value={pw} onChange={(e) => setPw(e.target.value)} />
      </Field>
      <p className="small muted">{t("apConfirmPwDesc")}</p>
      <ErrorText error={error} />
      <div className="modal-actions">
        <button className="btn" onClick={props.onClose}>{t("cancel")}</button>
        <button className="btn primary" disabled={busy || allowed.length === 0 || !pw} onClick={async () => { const r = await run(() => api.approveConnection(props.conn.connection_id, allowed, pw)); setPw(""); if (r) props.onClose(); }}>{t("cnApprove")}</button>
      </div>
    </Modal>
  );
}

function ConnectWizard(props: { host: any; onClose: () => void }) {
  const { t } = useApp();
  const [scope, setScope] = useState<string>(props.host.scope ?? "user");
  const [dir, setDir] = useState("");
  const [allowed, setAllowed] = useState<string[]>(["*"]);
  const [plan, setPlan] = useState<PlanView | null>(null);
  const [applied, setApplied] = useState<string | null>(null);
  const { busy, error, run } = useAction();
  const close = async () => { if (plan && !applied) await api.hostCancel(plan.plan_id).catch(() => undefined); props.onClose(); };
  return (
    <Modal title={`${t("cnConnect")} · ${props.host.display_name}`} onClose={close} wide>
      {!plan && (
        <div className="col">
          <Field label={t("cnScope")}>
            <select value={scope} onChange={(e) => setScope(e.target.value)}>
              <option value="user">{t("cnUser")}</option>
              <option value="project">{t("cnProject")}</option>
            </select>
          </Field>
          {scope === "project" && <Field label={t("cnProjectDir")}><input value={dir} onChange={(e) => setDir(e.target.value)} placeholder="/Users/me/code/app" /></Field>}
          <ProjectPicker value={allowed} onChange={setAllowed} />
        </div>
      )}
      {plan && (
        <div className="col">
          <h3>{t("cnPreview")}</h3>
          <p className="muted small">{t("cnPreviewDesc")}</p>
          <code className="small">{plan.path}</code>
          <div className="diff mono" aria-label={t("cnPreview")}>
            {plan.unified_diff.split("\n").map((l, i) => <div key={i} className={diffLineClass(l)}>{l || " "}</div>)}
          </div>
          {applied && <div className="notice ok" role="status">{applied}</div>}
        </div>
      )}
      <ErrorText error={error} />
      <div className="modal-actions">
        <button className="btn" onClick={close}>{applied ? t("done") : t("cancel")}</button>
        {!plan && <button className="btn primary" disabled={busy || allowed.length === 0} onClick={async () => {
          const p = await run(() => api.hostPlan({ host: props.host.host, scope, project_dir: dir || undefined, allowed_projects: allowed }));
          if (p) setPlan(p);
        }}>{t("next")}</button>}
        {plan && !applied && <button className="btn primary" disabled={busy || plan.action === "unchanged"} onClick={async () => {
          const r = await run(() => api.hostApply(plan.plan_id));
          if (r) setApplied(t("cnApplied", { b: r.outcome?.backup_path ?? "—" }));
        }}>{t("cnApply")}</button>}
      </div>
    </Modal>
  );
}
