// SPDX-License-Identifier: Apache-2.0
import { useState } from "react";
import { api } from "../api";
import { Badge, ErrorText, Field, Modal, useAction, useApp, useLoad } from "../ui";
import { ExceptionCard } from "./Exceptions";

const EXAMPLES: Record<string, string> = {
  postgres: JSON.stringify({ host: "db.example.com", port: 5432, dbname: "app", sslmode: "verify-full", allowed_views: { "public.subscription_stats": { fields: ["date", "tier", "count"] } } }, null, 2),
  github: JSON.stringify({ allowed_repos: ["owner/repo"] }, null, 2),
  http_api: JSON.stringify({ base_url: "https://api.example.com", auth: { type: "bearer" }, operations: { list_items: { method: "GET", path: "/items", side_effect: "read", response: { allowed_fields: ["id", "name"] } } } }, null, 2),
};

export function Executors() {
  const { t, go } = useApp();
  const node = useLoad(() => api.nodeStatus(), []);
  const resources = useLoad(() => api.resources(), []);
  const [adding, setAdding] = useState(false);
  const { busy, error, run } = useAction();
  const n = node.data;
  return (
    <div>
      <div className="page-head"><h1>{t("exTitle")}</h1><button className="btn" onClick={() => { node.reload(); resources.reload(); }}>{t("refresh")}</button></div>
      {n && !n.running && <ExceptionCard kind="executor" />}
      <div className="card">
        <h2>{t("exLocal")}</h2>
        <dl className="kv">
          <dt>{t("status")}</dt><dd>{n?.running ? <Badge tone="ok">{t("ovNodeRunning")}</Badge> : <Badge tone="warn">{t("stExecutorOffline")}</Badge>}</dd>
          <dt>{t("exProtection")}</dt><dd><Badge tone="warn">{t("exCompatible")}</Badge></dd>
          {n?.executor_id && (<><dt>ID</dt><dd><code>{n.executor_id}</code></dd></>)}
          {n?.broker_socket && (<><dt>{t("exSocket")}</dt><dd><code>unix://{n.broker_socket}</code></dd></>)}
        </dl>
        <div className="spacer" />
        <div className="notice warn small"><strong>{t("exCompatible")}</strong> — {t("exCompatibleDesc")}</div>
        <div className="spacer" />
        <div className="notice info small"><strong>{t("exIsolated")}</strong> — {t("exIsolatedDesc")}</div>
      </div>
      <div className="card">
        <div className="row"><h2 className="grow">{t("exResources")}</h2><button className="btn primary small" onClick={() => setAdding(true)}>{t("exAddResource")}</button></div>
        <ErrorText error={error} />
        <table>
          <thead><tr><th>{t("rAlias")}</th><th>{t("rService")}</th><th>{t("rConnector")}</th><th>{t("rEnv")}</th><th>{t("status")}</th><th /></tr></thead>
          <tbody>
            {(resources.data?.resources ?? []).map((r: any) => (
              <tr key={r.resource_id}>
                <td>{r.alias}</td><td>{r.service}</td><td>{r.connector}</td>
                <td>{r.environment === "production" ? <Badge tone="danger">{t("rProd")}</Badge> : <Badge>{t("rTest")}</Badge>}</td>
                <td>{r.status}</td>
                <td><button className="btn small danger" disabled={busy} onClick={async () => { await run(() => api.deleteResource(r.resource_id)); resources.reload(); }}>{t("delete")}</button></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="card">
        <h2>{t("exPaired")}</h2>
        <p className="muted small">{t("pPasteDesc")}</p>
        <button className="btn" onClick={() => go("pair")}>{t("exPairServer")}</button>
      </div>
      {adding && <AddResource onClose={() => { setAdding(false); resources.reload(); }} />}
    </div>
  );
}

function AddResource(props: { onClose: () => void }) {
  const { t } = useApp();
  const projects = useLoad(() => api.projects(), []);
  const items = useLoad(() => api.listItems(), []);
  const [connector, setConnector] = useState("http_api");
  const [form, setForm] = useState({ alias: "", service: "", project_id: "", environment: "test", credential_entry_id: "", config: EXAMPLES.http_api });
  const [newProject, setNewProject] = useState("");
  const { busy, error, setError, run } = useAction();
  return (
    <Modal title={t("exAddResource")} onClose={props.onClose} wide>
      <form className="col" onSubmit={async (e) => {
        e.preventDefault();
        let config: unknown;
        try { config = JSON.parse(form.config); } catch { return setError("JSON"); }
        let project_id = form.project_id;
        if (!project_id && newProject) {
          const p = await run(() => api.createProject(newProject));
          if (!p) return;
          project_id = p.project_id;
        }
        const r = await run(() => api.createResource({ ...form, project_id, connector, config }));
        if (r) props.onClose();
      }}>
        <div className="grid2">
          <Field label={t("rAlias")}><input value={form.alias} onChange={(e) => setForm({ ...form, alias: e.target.value })} required /></Field>
          <Field label={t("rService")}><input value={form.service} onChange={(e) => setForm({ ...form, service: e.target.value })} required /></Field>
          <Field label={t("rConnector")}>
            <select value={connector} onChange={(e) => { setConnector(e.target.value); setForm({ ...form, config: EXAMPLES[e.target.value] }); }}>
              <option value="postgres">PostgreSQL</option><option value="github">GitHub</option><option value="http_api">HTTP API</option>
            </select>
          </Field>
          <Field label={t("rEnv")}>
            <select value={form.environment} onChange={(e) => setForm({ ...form, environment: e.target.value })}>
              <option value="test">{t("rTest")}</option><option value="production">{t("rProd")}</option>
            </select>
          </Field>
          <Field label={t("fProject")}>
            <select value={form.project_id} onChange={(e) => setForm({ ...form, project_id: e.target.value })}>
              <option value="">+ {t("add")}</option>
              {(projects.data?.projects ?? []).map((p) => <option key={p.project_id} value={p.project_id}>{p.name}</option>)}
            </select>
          </Field>
          {!form.project_id && <Field label={t("fProject")}><input value={newProject} onChange={(e) => setNewProject(e.target.value)} required /></Field>}
          <Field label={t("rEntry")}>
            <select value={form.credential_entry_id} onChange={(e) => setForm({ ...form, credential_entry_id: e.target.value })} required>
              <option value="" disabled>—</option>
              {(items.data ?? []).map((i) => <option key={i.entry_id} value={i.entry_id}>{i.title}</option>)}
            </select>
          </Field>
        </div>
        <Field label={t("rConfig")}><textarea className="mono" rows={10} value={form.config} onChange={(e) => setForm({ ...form, config: e.target.value })} spellCheck={false} /></Field>
        <ErrorText error={error} />
        <div className="modal-actions">
          <button type="button" className="btn" onClick={props.onClose}>{t("cancel")}</button>
          <button className="btn primary" disabled={busy}>{t("save")}</button>
        </div>
      </form>
    </Modal>
  );
}
