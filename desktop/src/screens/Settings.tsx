// SPDX-License-Identifier: Apache-2.0
import { useEffect, useState } from "react";
import { api, type CapabilityReport, type Settings, type StorageInput } from "../api";
import { loc, type Lang } from "../i18n";
import { validateStorage } from "../logic";
import { Badge, ErrorText, Field, useAction, useApp, useLoad, useReauth } from "../ui";
import { CapabilityResult, StorageForm } from "./Onboarding";
import { ExceptionCard } from "./Exceptions";

export function SettingsPage() {
  const { t, lang, status, refresh, toast, setLang } = useApp();
  const settings = useLoad(() => api.getSettings(), []);
  const devices = useLoad(() => api.devices(), []);
  const cloud = useLoad(() => api.cloudStatus(), []);
  const tunnel = useLoad(() => api.tunnelStatus(), []);
  const [draft, setDraft] = useState<Settings | null>(null);
  const [storage, setStorage] = useState<StorageInput>({ kind: "local" });
  const [report, setReport] = useState<CapabilityReport | null>(null);
  const [email, setEmail] = useState("");
  const [cpw, setCpw] = useState("");
  const [exportPw, setExportPw] = useState("");
  const [extId, setExtId] = useState("");
  const [browser, setBrowser] = useState("chrome");
  const [newKey, setNewKey] = useState<string | null>(null);
  const { guard, dialog } = useReauth();
  const { busy, error, setError, run } = useAction();

  useEffect(() => { if (settings.data) setDraft(settings.data); }, [settings.data]);
  if (!draft || !status) return <p className="muted">{t("loading")}</p>;
  const lic = cloud.data?.license;
  const sub = cloud.data?.subscription;

  return (
    <div className="col">
      <div className="page-head"><h1>{t("sTitle")}</h1></div>
      <ErrorText error={error} />
      {!status.core.recovery_verified && <ExceptionCard kind="recovery" />}

      <section className="card col" aria-labelledby="s-general">
        <h2 id="s-general">{t("sLanguage")}</h2>
        <div className="grid2">
          <Field label={t("sLanguage")}>
            <select value={draft.lang} onChange={(e) => setDraft({ ...draft, lang: e.target.value })}><option value="zh-CN">简体中文</option><option value="en">English</option></select>
          </Field>
          <Field label={t("sAutoLock")}><input type="number" value={draft.auto_lock_secs} onChange={(e) => setDraft({ ...draft, auto_lock_secs: Number(e.target.value) })} /></Field>
          <Field label={t("sClipboard")}><input type="number" value={draft.clipboard_clear_secs} onChange={(e) => setDraft({ ...draft, clipboard_clear_secs: Number(e.target.value) })} /></Field>
          <Field label={t("sRelay")} hint={t("relayHint")}><input value={draft.relay_url ?? ""} onChange={(e) => setDraft({ ...draft, relay_url: e.target.value || undefined })} /></Field>
          <Field label={t("sCloudUrl")}><input value={draft.cloud_url} onChange={(e) => setDraft({ ...draft, cloud_url: e.target.value })} /></Field>
        </div>
        <div className="row"><button className="btn primary" disabled={busy} onClick={async () => {
          const s = await run(() => api.updateSettings(draft));
          if (s) { setLang(s.lang as Lang); toast(t("sSaved")); refresh(); }
        }}>{t("save")}</button></div>
      </section>

      <section className="card col">
        <h2>{t("sStorage")}</h2>
        <p className="muted small">{status.core.storage_kind ?? ""} · {t("sMigrateDesc")}</p>
        <StorageForm value={storage} onChange={(s) => { setStorage(s); setReport(null); }} signedIn={!!cloud.data?.signed_in} />
        <CapabilityResult report={report} />
        <div className="row">
          <button className="btn" disabled={busy} onClick={async () => { const bad = validateStorage(storage); if (bad) return setError(t(bad)); const r = await run(() => api.testStorage(storage)); if (r) setReport(r); }}>{t("runTest")}</button>
          <button className="btn primary" disabled={busy || report?.verdict !== "sync_capable"} onClick={async () => {
            const r = await run(() => guard(() => api.migrateStorage(storage)));
            if (r) { toast(`${t("sMigrate")} ✓ ${r.entries_verified}`); refresh(); }
          }}>{t("sMigrate")}</button>
        </div>
      </section>

      <section className="card col">
        <h2>{t("sCloud")}</h2>
        <p className="muted small">{t("sCloudNote")}</p>
        {cloud.data?.signed_in ? (
          <>
            <dl className="kv">
              <dt>{t("sEmail")}</dt><dd>{cloud.data.email}</dd>
              <dt>{t("sPlan")}</dt><dd>{sub ? `${sub.plan_id} · ${sub.status}` : cloud.data.subscription_error ? loc(lang, cloud.data.subscription_error.message) : "—"}</dd>
              <dt>{t("sLicense")}</dt><dd>{lic?.valid ? <Badge tone="ok">{t("sLicValid")} · {lic.plan_id}</Badge> : <Badge>{t("sLicInvalid")}</Badge>}</dd>
            </dl>
            <div className="row">
              <button className="btn" disabled={busy} onClick={async () => { const r = await run(() => api.activateLicense()); if (r) cloud.reload(); }}>{t("sActivate")}</button>
              <button className="btn" disabled={busy} onClick={async () => { await run(() => api.cloudLogout()); cloud.reload(); refresh(); }}>{t("sLogout")}</button>
            </div>
            <h3>{t("cnRemote")}</h3>
            <p className="notice warn small">{t("cnRemoteNote")}</p>
            <div className="row">
              <button className="btn" disabled={busy} onClick={async () => { const r = await run(() => api.cloudLinkNode()); if (r) toast(t("sLinked")); }}>{t("sLinkNode")}</button>
              {tunnel.data?.running
                ? <button className="btn" disabled={busy} onClick={async () => { await run(() => api.tunnelStop()); tunnel.reload(); }}>{t("sTunnelStop")}</button>
                : <button className="btn" disabled={busy} onClick={async () => { await run(() => api.tunnelStart()); tunnel.reload(); }}>{t("sTunnelStart")}</button>}
              <span className="muted small">{t("sTunnelState")}: {tunnel.data?.running ? tunnel.data.state : "—"}</span>
            </div>
          </>
        ) : (
          <form className="grid2" onSubmit={async (e) => { e.preventDefault(); const r = await run(() => api.cloudLogin(email, cpw)); setCpw(""); if (r) { cloud.reload(); refresh(); } }}>
            <Field label={t("sEmail")}><input type="email" value={email} onChange={(e) => setEmail(e.target.value)} autoComplete="username" required /></Field>
            <Field label={t("sPassword")}><input type="password" value={cpw} onChange={(e) => setCpw(e.target.value)} autoComplete="current-password" required /></Field>
            <div className="row"><button className="btn primary" disabled={busy}>{t("sLogin")}</button></div>
          </form>
        )}
      </section>

      <section className="card col">
        <h2>{t("sRecovery")}</h2>
        <p>{status.core.recovery_verified ? <Badge tone="ok">{t("sRecoveryVerified")}</Badge> : <Badge tone="warn">{t("sRecoveryNotVerified")}</Badge>}</p>
        <div className="row">
          <button className="btn" disabled={busy} onClick={async () => { const p = await run(() => api.saveRecoveryKit()); if (p) toast(t("kitSaved", { p })); }}>{t("saveKit")}</button>
          <button className="btn" disabled={busy} onClick={async () => { const k = await run(() => guard(() => api.replaceRecoveryKey())); if (k) setNewKey(k); }}>{t("sReplaceKey")}</button>
        </div>
        {newKey && <><div className="recovery">{newKey}</div><p className="muted small">{t("obRecoveryOnce")}</p><button className="btn small" onClick={() => { setNewKey(null); refresh(); }}>{t("done")}</button></>}
      </section>

      <section className="card col">
        <h2>{t("sExport")}</h2>
        <Field label={t("sExportPassword")}><input type="password" value={exportPw} minLength={10} onChange={(e) => setExportPw(e.target.value)} autoComplete="new-password" /></Field>
        <div className="row">
          <button className="btn" disabled={busy || exportPw.length < 10} onClick={async () => { const p = await run(() => guard(() => api.exportEncrypted(exportPw))); setExportPw(""); if (p) toast(p); }}>{t("sExportEnc")}</button>
          <button className="btn danger" disabled={busy} onClick={async () => { if (!window.confirm(t("sCsvWarn"))) return; const p = await run(() => guard(() => api.exportCsv())); if (p) toast(p); }}>{t("sExportCsv")}</button>
        </div>
        <p className="muted small">{t("sCsvWarn")}</p>
      </section>

      <section className="card col">
        <h2>{t("sDevices")}</h2>
        <p className="muted small">{t("sRevokeNote")}</p>
        <div className="list">
          {(devices.data ?? []).filter((d) => !d.is_recovery_key).map((d) => (
            <div key={d.device_id} className="list-item">
              <div className="grow"><strong>{d.name}</strong> {d.is_this_device && <Badge>{t("sThisDevice")}</Badge>}<div className="muted small">{d.platform} · {d.role} · epoch {d.key_epoch}</div></div>
              <Badge tone={d.status === "active" ? "ok" : "danger"}>{d.status === "revoked" ? t("stRevoked") : d.status}</Badge>
              {!d.is_this_device && d.status === "active" && <button className="btn small danger" disabled={busy} onClick={async () => { const r = await run(() => guard(() => api.revokeDevice(d.device_id))); if (r) { toast(loc(lang, r.note)); devices.reload(); } }}>{t("sRevokeDevice")}</button>}
            </div>
          ))}
        </div>
      </section>

      <section className="card col">
        <h2>{t("sBrowser")}</h2>
        <div className="grid2">
          <Field label="Browser"><select value={browser} onChange={(e) => setBrowser(e.target.value)}><option value="chrome">Chrome</option><option value="chromium">Chromium</option><option value="edge">Edge</option><option value="brave">Brave</option></select></Field>
          <Field label={t("sExtId")}><input className="mono" value={extId} onChange={(e) => setExtId(e.target.value.trim())} maxLength={32} /></Field>
        </div>
        <div className="row"><button className="btn" disabled={busy || extId.length !== 32} onClick={async () => { const p = await run(() => api.installNativeHost(browser, extId)); if (p) toast(p); }}>{t("sInstallHost")}</button></div>
        <p className="muted small">{(draft.allowed_extension_origins ?? []).join(", ")}</p>
      </section>

      <section className="card">
        <h2>{t("sAbout")}</h2>
        <dl className="kv"><dt>{t("sVersion")}</dt><dd>{status.version}</dd><dt>Data</dt><dd><code>{status.home}</code></dd></dl>
        <p className="muted small">{t("notAudited")}</p>
      </section>
      {dialog}
    </div>
  );
}
