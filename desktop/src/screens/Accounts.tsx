// SPDX-License-Identifier: Apache-2.0
import { useEffect, useMemo, useState } from "react";
import { api, type Generated, type ItemDetail, type ItemForm, type ItemSummary, type PasswordRules } from "../api";
import { groupItems } from "../logic";
import type { Key } from "../i18n";
import { Badge, ErrorText, Field, Modal, fmtTime, useAction, useApp, useLoad, useReauth } from "../ui";

const KINDS: [string, Key][] = [["login", "kLogin"], ["api_key", "kApiKey"], ["database", "kDatabase"], ["oauth_token", "kOauth"], ["ssh_key", "kSsh"], ["secure_note", "kNote"]];
const REVEAL_SECS = 30;

export function Accounts() {
  const { t } = useApp();
  const [q, setQ] = useState("");
  const [sel, setSel] = useState<string | null>(null);
  const [editing, setEditing] = useState<ItemDetail | "new" | null>(null);
  const [importing, setImporting] = useState(false);
  const [conflictsOpen, setConflictsOpen] = useState(false);
  const items = useLoad(() => api.listItems(q || undefined), [q]);
  const projects = useLoad(() => api.projects().catch(() => ({ projects: [] })), []);
  const names = useMemo(() => Object.fromEntries((projects.data?.projects ?? []).map((p) => [p.project_id, p.name])), [projects.data]);
  const groups = groupItems(items.data ?? [], names, t("acNoProject"));
  const conflicts = (items.data ?? []).filter((i) => i.has_conflict).length;

  return (
    <div>
      <div className="page-head">
        <h1>{t("acTitle")}</h1>
        <div className="row">
          {conflicts > 0 && <button className="btn" onClick={() => setConflictsOpen(true)}>{t("acConflicts")} <Badge tone="warn">{conflicts}</Badge></button>}
          <button className="btn" onClick={() => setImporting(true)}>{t("acImport")}</button>
          <button className="btn primary" onClick={() => setEditing("new")}>{t("acAdd")}</button>
        </div>
      </div>
      <div className="row" style={{ marginBottom: 12 }}>
        <input className="grow" type="search" aria-label={t("search")} placeholder={t("search")} value={q} onChange={(e) => setQ(e.target.value)} />
      </div>
      <div className="grid2" style={{ gridTemplateColumns: "minmax(280px, 1fr) minmax(320px, 1.3fr)" }}>
        <div>
          {groups.length === 0 && <p className="muted">{t("acEmpty")}</p>}
          {groups.map((g) => (
            <section key={g.key} aria-label={g.title}>
              <div className="group-title">{g.title}</div>
              <div className="list" role="listbox" aria-label={g.title}>
                {g.items.map((it) => (
                  <button key={it.entry_id} className="list-item" role="option" aria-selected={sel === it.entry_id} onClick={() => setSel(it.entry_id)}>
                    <div className="grow">
                      <div>{it.title}</div>
                      <div className="muted small">{it.username ?? it.primary_url ?? ""}</div>
                    </div>
                    {it.has_conflict && <Badge tone="warn">{t("stConflict")}</Badge>}
                    {it.pending_sync && <Badge>{t("stPending")}</Badge>}
                  </button>
                ))}
              </div>
            </section>
          ))}
        </div>
        <div>{sel && <ItemPanel key={sel} id={sel} onEdit={(d) => setEditing(d)} onDeleted={() => { setSel(null); items.reload(); }} />}</div>
      </div>
      {editing && <ItemEditor item={editing === "new" ? null : editing} projects={projects.data?.projects ?? []} onClose={() => setEditing(null)} onSaved={(id) => { setEditing(null); setSel(id); items.reload(); }} />}
      {importing && <ImportWizard onClose={() => { setImporting(false); items.reload(); }} />}
      {conflictsOpen && <ConflictDialog onClose={() => { setConflictsOpen(false); items.reload(); }} />}
    </div>
  );
}

function ItemPanel(props: { id: string; onEdit: (d: ItemDetail) => void; onDeleted: () => void }) {
  const { t, lang, toast } = useApp();
  const item = useLoad(() => api.getItem(props.id), [props.id]);
  const [revealed, setRevealed] = useState<{ value: string; left: number } | null>(null);
  const [totp, setTotp] = useState<{ code: string; remaining_seconds: number } | null>(null);
  const { guard, dialog } = useReauth();
  const { error, run } = useAction();

  useEffect(() => {
    if (!revealed) return;
    if (revealed.left <= 0) { setRevealed(null); return; }
    const h = window.setTimeout(() => setRevealed((r) => (r ? { ...r, left: r.left - 1 } : null)), 1000);
    return () => window.clearTimeout(h);
  }, [revealed]);
  useEffect(() => {
    if (!item.data?.has_totp) return;
    let alive = true;
    const tick = () => api.totpNow(props.id).then((c) => alive && setTotp(c), () => undefined);
    tick();
    const h = window.setInterval(tick, 5000);
    return () => { alive = false; window.clearInterval(h); };
  }, [item.data?.has_totp, props.id]);
  useEffect(() => () => setRevealed(null), []);

  const d = item.data;
  if (!d) return <div className="card muted">{t("loading")}</div>;
  const copy = async (field: string) => {
    const s = await run(() => api.copySecret(props.id, field));
    if (s) toast(t("copied", { s }));
  };
  return (
    <div className="card col">
      <div className="row"><h2 className="grow">{d.summary.title}</h2><button className="btn small" onClick={() => props.onEdit(d)}>{t("edit")}</button></div>
      {d.summary.has_conflict && <div className="notice warn small">{t("exc_conflict_body")} {t("exc_conflict_next")}</div>}
      <dl className="kv">
        {d.summary.username && (<><dt>{t("fUsername")}</dt><dd className="row"><span className="grow">{d.summary.username}</span><button className="btn small" onClick={() => copy("username")}>{t("copy")}</button></dd></>)}
        {d.has_secret && (
          <>
            <dt>{t("fPassword")}</dt>
            <dd className="col">
              <span className="mono">{revealed ? revealed.value : d.secret_masked ?? "••••••••"}</span>
              {revealed && <span className="muted small">{t("autoHide", { s: revealed.left })}</span>}
              <div className="row">
                <button className="btn small" onClick={() => copy("secret")}>{t("copyPassword")}</button>
                {revealed ? <button className="btn small ghost" onClick={() => setRevealed(null)}>{t("hide")}</button> : (
                  <button className="btn small ghost" onClick={() => run(async () => { const v = await guard(() => api.revealSecret(props.id, "secret")); setRevealed({ value: v, left: REVEAL_SECS }); })}>{t("reveal")}</button>
                )}
              </div>
            </dd>
          </>
        )}
        {d.has_totp && (<><dt>{t("totpCode")}</dt><dd className="row"><span className="mono grow">{totp ? `${totp.code} · ${totp.remaining_seconds}s` : "…"}</span><button className="btn small" onClick={() => copy("totp_code")}>{t("copyTotp")}</button></dd></>)}
        {d.urls.length > 0 && (<><dt>{t("fUrls")}</dt><dd>{d.urls.map((u) => <div key={u} className="small">{u}</div>)}</dd></>)}
        {d.notes && (<><dt>{t("fNotes")}</dt><dd className="small" style={{ whiteSpace: "pre-wrap" }}>{d.notes}</dd></>)}
        <dt>{t("status")}</dt><dd>{fmtTime(lang, d.summary.updated_at)}</dd>
      </dl>
      <ErrorText error={error} />
      <div className="row">
        <button className="btn danger small" onClick={async () => {
          if (!window.confirm(t("deleteConfirm", { t: d.summary.title }))) return;
          const r = await run(() => api.deleteItem(props.id));
          if (r !== undefined) props.onDeleted();
        }}>{t("delete")}</button>
      </div>
      {dialog}
    </div>
  );
}

export function GeneratorBox(props: { onGenerated: (g: Generated) => void }) {
  const { t, toast } = useApp();
  const [rules, setRules] = useState<PasswordRules>({ length: 20, lower: true, upper: true, digits: true, symbols: true, exclude_ambiguous: false, require_each_class: true });
  const [gen, setGen] = useState<Generated | null>(null);
  const { error, run } = useAction();
  const flag = (k: keyof PasswordRules, label: Key) => (
    <label className="row small"><input type="checkbox" checked={Boolean(rules[k])} onChange={(e) => setRules({ ...rules, [k]: e.target.checked })} />{t(label)}</label>
  );
  return (
    <fieldset className="card col">
      <legend>{t("genTitle")}</legend>
      <Field label={`${t("genLength")}: ${rules.length}`}><input type="range" min={8} max={64} value={rules.length} onChange={(e) => setRules({ ...rules, length: Number(e.target.value) })} /></Field>
      <div className="row">{flag("lower", "genLower")}{flag("upper", "genUpper")}{flag("digits", "genDigits")}{flag("symbols", "genSymbols")}{flag("exclude_ambiguous", "genAmbiguous")}{flag("require_each_class", "genEach")}</div>
      <div className="row">
        <button type="button" className="btn" onClick={async () => { const g = await run(() => api.generatePassword(rules)); if (g) setGen(g); }}>{t("genGenerate")}</button>
        {gen && <>
          <span className="mono">{gen.masked}</span>
          <button type="button" className="btn small" onClick={async () => { const s = await run(() => api.copyGenerated(gen.handle)); if (s) toast(t("copied", { s })); }}>{t("copy")}</button>
          <button type="button" className="btn small primary" onClick={() => props.onGenerated(gen)}>{t("genUse")}</button>
        </>}
      </div>
      {gen && <span className="muted small">{t("genReady", { n: gen.length })}</span>}
      <ErrorText error={error} />
    </fieldset>
  );
}

function ItemEditor(props: { item: ItemDetail | null; projects: { project_id: string; name: string }[]; onClose: () => void; onSaved: (id: string) => void }) {
  const { t } = useApp();
  const it = props.item;
  const [form, setForm] = useState<ItemForm>({
    entry_id: it?.summary.entry_id, kind: it?.summary.kind ?? "login", title: it?.summary.title ?? "", username: it?.summary.username ?? "",
    urls: it?.urls ?? [], notes: it?.notes ?? "", project_id: it?.summary.project_id, tags: it?.summary.tags ?? [],
  });
  const [secret, setSecret] = useState("");
  const [genRef, setGenRef] = useState<Generated | null>(null);
  const [totp, setTotp] = useState("");
  const [showGen, setShowGen] = useState(false);
  const { busy, error, run } = useAction();
  const set = (p: Partial<ItemForm>) => setForm({ ...form, ...p });
  return (
    <Modal title={it ? t("edit") : t("acAdd")} onClose={props.onClose} wide>
      <form className="col" onSubmit={async (e) => {
        e.preventDefault();
        const payload: ItemForm = { ...form, secret: genRef ? undefined : secret || undefined, secret_ref: genRef?.handle, totp: totp || undefined };
        const id = await run(() => api.saveItem(payload));
        setSecret("");
        if (id) props.onSaved(id);
      }}>
        <div className="grid2">
          <Field label={t("fKind")}><select value={form.kind} onChange={(e) => set({ kind: e.target.value })}>{KINDS.map(([k, l]) => <option key={k} value={k}>{t(l)}</option>)}</select></Field>
          <Field label={t("fTitle")}><input value={form.title} onChange={(e) => set({ title: e.target.value })} required maxLength={200} /></Field>
          <Field label={t("fUsername")}><input value={form.username ?? ""} onChange={(e) => set({ username: e.target.value })} autoComplete="off" /></Field>
          <Field label={t("fPassword")} hint={it ? t("keepSecret") : undefined}>
            {genRef ? <div className="row"><span className="mono">{genRef.masked}</span><button type="button" className="btn small ghost" onClick={() => setGenRef(null)}>{t("cancel")}</button></div>
              : <input type="password" value={secret} onChange={(e) => setSecret(e.target.value)} autoComplete="new-password" />}
          </Field>
          <Field label={t("fProject")}>
            <select value={form.project_id ?? ""} onChange={(e) => set({ project_id: e.target.value || undefined })}>
              <option value="">{t("acNoProject")}</option>
              {props.projects.map((p) => <option key={p.project_id} value={p.project_id}>{p.name}</option>)}
            </select>
          </Field>
          <Field label={t("fTotp")}><input value={totp} onChange={(e) => setTotp(e.target.value)} autoComplete="off" placeholder={it?.has_totp ? t("keepSecret") : ""} /></Field>
        </div>
        <button type="button" className="btn small ghost" onClick={() => setShowGen(!showGen)}>{t("genTitle")}</button>
        {showGen && <GeneratorBox onGenerated={(g) => { setGenRef(g); setShowGen(false); }} />}
        <Field label={t("fUrls")}><textarea value={form.urls.join("\n")} onChange={(e) => set({ urls: e.target.value.split("\n") })} /></Field>
        <Field label={t("fNotes")}><textarea value={form.notes ?? ""} onChange={(e) => set({ notes: e.target.value })} /></Field>
        <Field label={t("fTags")}><input value={form.tags.join(", ")} onChange={(e) => set({ tags: e.target.value.split(",").map((s) => s.trim()).filter(Boolean) })} /></Field>
        {it && (
          <div className="row small">
            {it.has_secret && <label className="row"><input type="checkbox" checked={!!form.clear_secret} onChange={(e) => set({ clear_secret: e.target.checked })} />{t("clearSecret")}</label>}
            {it.has_totp && <label className="row"><input type="checkbox" checked={!!form.clear_totp} onChange={(e) => set({ clear_totp: e.target.checked })} />{t("clearTotp")}</label>}
          </div>
        )}
        <ErrorText error={error} />
        <div className="modal-actions">
          <button type="button" className="btn" onClick={props.onClose}>{t("cancel")}</button>
          <button className="btn primary" disabled={busy}>{t("save")}</button>
        </div>
      </form>
    </Modal>
  );
}

function ImportWizard(props: { onClose: () => void }) {
  const { t } = useApp();
  const [format, setFormat] = useState("chrome");
  const [ack, setAck] = useState(false);
  const [result, setResult] = useState<string | null>(null);
  const { busy, error, run } = useAction();
  return (
    <Modal title={t("impTitle")} onClose={props.onClose}>
      <div className="notice warn small">{t("impRisk")}</div>
      <div className="spacer" />
      <Field label={t("impFormat")}>
        <select value={format} onChange={(e) => setFormat(e.target.value)}>
          {["chrome", "firefox", "safari", "bitwarden", "1password", "lastpass", "generic"].map((f) => <option key={f} value={f}>{f}</option>)}
        </select>
      </Field>
      <label className="row small"><input type="checkbox" checked={ack} onChange={(e) => setAck(e.target.checked)} />{t("impRisk").split("。")[0]}</label>
      {result && <div className="notice ok" role="status">{result}</div>}
      <ErrorText error={error} />
      <div className="modal-actions">
        <button className="btn" onClick={props.onClose}>{t("close")}</button>
        <button className="btn primary" disabled={!ack || busy} onClick={async () => {
          const r = await run(() => api.importCsv(format));
          if (r) setResult(t("impResult", { i: r.imported, d: r.duplicates.length, s: r.skipped.length }));
        }}>{t("impPick")}</button>
      </div>
    </Modal>
  );
}

function ConflictDialog(props: { onClose: () => void }) {
  const { t, lang } = useApp();
  const list = useLoad(() => api.conflicts(), []);
  const { busy, error, run } = useAction();
  return (
    <Modal title={t("cfTitle")} onClose={props.onClose} wide>
      <p className="muted">{t("cfDesc")}</p>
      {(list.data ?? []).map((c) => (
        <div key={c.entry_id} className="card">
          <h3>{c.title}</h3>
          <table>
            <thead><tr><th>#</th><th>{t("sDevices")}</th><th>{t("fUsername")}</th><th>{t("details")}</th><th /></tr></thead>
            <tbody>
              {c.versions.map((v) => (
                <tr key={v.version}>
                  <td>{v.version} {v.is_current && <Badge>{t("cfCurrent")}</Badge>}</td>
                  <td>{v.author_name ?? v.author_device_id}<div className="muted small">{fmtTime(lang, v.created_at)}</div></td>
                  <td>{v.username ?? "—"}</td>
                  <td>{v.secret_differs && <Badge tone="warn">{t("cfSecretDiffers")}</Badge>}</td>
                  <td><button className="btn small" disabled={busy} onClick={async () => { await run(() => api.resolveConflict(c.entry_id, v.version)); list.reload(); }}>{t("cfKeep")}</button></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ))}
      {list.data?.length === 0 && <p className="muted">{t("ovAllGood")}</p>}
      <ErrorText error={error} />
      <div className="modal-actions"><button className="btn" onClick={props.onClose}>{t("close")}</button></div>
    </Modal>
  );
}

export type { ItemSummary };
