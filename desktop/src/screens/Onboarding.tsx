// SPDX-License-Identifier: Apache-2.0
import { useEffect, useState } from "react";
import { api, onEvent, type CapabilityReport, type StorageInput, type StorageKind } from "../api";
import { validateStorage } from "../logic";
import { ErrorText, Field, useAction, useApp } from "../ui";

type Step = "choose" | "device" | "storage" | "recovery" | "verify" | "first" | "join";

export function StorageForm(props: { value: StorageInput; onChange: (s: StorageInput) => void; signedIn: boolean }) {
  const { t } = useApp();
  const s = props.value;
  const kinds: { k: StorageKind; title: string; desc: string }[] = [
    { k: "local", title: t("stLocal"), desc: t("stLocalDesc") },
    { k: "official", title: t("stOfficial"), desc: t("stOfficialDesc") },
    { k: "s3", title: t("stS3"), desc: t("stS3Desc") },
    { k: "selfhost", title: t("stSelfhost"), desc: t("stSelfhostDesc") },
  ];
  const set = (patch: Partial<StorageInput>) => props.onChange({ ...s, ...patch });
  return (
    <div className="col">
      <div className="grid2" role="radiogroup" aria-label={t("obStorage")}>
        {kinds.map((k) => (
          <button key={k.k} type="button" className="choice" aria-pressed={s.kind === k.k} onClick={() => props.onChange({ kind: k.k })}>
            <strong>{k.title}</strong>
            <div className="muted small">{k.desc}</div>
          </button>
        ))}
      </div>
      {s.kind === "local" && (
        <Field label={`${t("folder")}（${t("optional")}）`} hint="~/.aipass/storage">
          <input value={s.path ?? ""} onChange={(e) => set({ path: e.target.value })} placeholder="/Users/me/Sync/AIPass" />
        </Field>
      )}
      {s.kind === "official" && !props.signedIn && <div className="notice warn small">{t("sCloudNote")}</div>}
      {s.kind === "s3" && (
        <div className="grid2">
          <Field label={t("endpoint")}><input value={s.endpoint ?? ""} onChange={(e) => set({ endpoint: e.target.value })} placeholder="https://s3.amazonaws.com" /></Field>
          <Field label={t("region")}><input value={s.region ?? ""} onChange={(e) => set({ region: e.target.value })} placeholder="us-east-1" /></Field>
          <Field label={t("bucket")}><input value={s.bucket ?? ""} onChange={(e) => set({ bucket: e.target.value })} /></Field>
          <Field label={`${t("prefix")}（${t("optional")}）`}><input value={s.prefix ?? ""} onChange={(e) => set({ prefix: e.target.value })} /></Field>
          <Field label={t("accessKey")}><input value={s.access_key_id ?? ""} onChange={(e) => set({ access_key_id: e.target.value })} autoComplete="off" /></Field>
          <Field label={t("secretKey")}><input type="password" value={s.secret ?? ""} onChange={(e) => set({ secret: e.target.value })} autoComplete="off" /></Field>
          <label className="row small"><input type="checkbox" checked={s.path_style ?? true} onChange={(e) => set({ path_style: e.target.checked })} />{t("pathStyle")}</label>
        </div>
      )}
      {s.kind === "selfhost" && (
        <div className="grid2">
          <Field label={t("nodeUrl")}><input value={s.base_url ?? ""} onChange={(e) => set({ base_url: e.target.value })} placeholder="https://node.example.com" /></Field>
          <Field label={t("enrollToken")}><input type="password" value={s.secret ?? ""} onChange={(e) => set({ secret: e.target.value })} autoComplete="off" /></Field>
        </div>
      )}
    </div>
  );
}

export function CapabilityResult({ report }: { report: CapabilityReport | null }) {
  const { t } = useApp();
  if (!report) return null;
  return <div className={`notice ${report.verdict === "sync_capable" ? "ok" : "warn"}`} role="status">{report.verdict === "sync_capable" ? t("capOk") : t("capBackup")}</div>;
}

export function Onboarding() {
  const { t, status, refresh, toast, go } = useApp();
  const [step, setStep] = useState<Step>(status?.has_vault ? (status.core.recovery_verified ? "first" : "verify") : "choose");
  const [name, setName] = useState("我的电脑");
  const [pw, setPw] = useState("");
  const [pw2, setPw2] = useState("");
  const [storage, setStorage] = useState<StorageInput>({ kind: "local" });
  const [report, setReport] = useState<CapabilityReport | null>(null);
  const [recoveryKey, setRecoveryKey] = useState<string | null>(null);
  const [typedKey, setTypedKey] = useState("");
  const [relay, setRelay] = useState("https://cloud.aipass.example");
  const [qr, setQr] = useState<{ svg: string; payload: string } | null>(null);
  const [sas, setSas] = useState<string | null>(null);
  const { busy, error, setError, run } = useAction();
  const order: Step[] = ["device", "storage", "recovery", "verify", "first"];

  useEffect(() => {
    const sub = onEvent<{ stage: string; sas?: string; error?: { message: { zh: string; en: string } } }>("pairing", (e) => {
      if (e.stage === "sas") setSas(e.sas ?? null);
      if (e.stage === "done") { refresh(); setStep("first"); }
      if (e.stage === "failed") setError(t("pFailed", { e: e.error?.message.zh ?? "" }));
    });
    return () => { sub.then((u) => u()); };
  }, [refresh, setError, t]);

  const stepBar = order.includes(step) && (
    <div className="steps" aria-hidden>{order.map((s, i) => <span key={s} className={order.indexOf(step) >= i ? "on" : ""} />)}</div>
  );

  return (
    <div className="center-screen">
      <div className="card panel">
        {stepBar}
        {step === "choose" && (
          <div className="col">
            <h1>{t("obWelcome")}</h1>
            <p className="muted">{t("tagline")}</p>
            <p>{t("obChoose")}</p>
            <div className="grid2">
              <button className="choice" onClick={() => setStep("device")}><strong>{t("obCreate")}</strong><div className="muted small">{t("obCreateDesc")}</div></button>
              <button className="choice" onClick={() => setStep("join")}><strong>{t("obJoin")}</strong><div className="muted small">{t("obJoinDesc")}</div></button>
            </div>
            <p className="muted small">{t("notAudited")}</p>
          </div>
        )}

        {(step === "device" || step === "join") && (
          <form
            className="col"
            onSubmit={async (e) => {
              e.preventDefault();
              if (pw !== pw2) return setError(t("obPasswordMismatch"));
              if (step === "device") return setStep("storage");
              const r = await run(() => api.joinBegin(name, relay, pw));
              if (r) setQr({ svg: r.qr_svg, payload: r.qr_payload });
            }}
          >
            <h2>{step === "join" ? t("obJoin") : t("obCreate")}</h2>
            <Field label={t("obDeviceName")}><input value={name} onChange={(e) => setName(e.target.value)} maxLength={64} required /></Field>
            <Field label={t("obPassword")} hint={t("obPasswordNote")}><input type="password" value={pw} minLength={8} onChange={(e) => setPw(e.target.value)} autoComplete="new-password" required /></Field>
            <Field label={t("obPassword2")}><input type="password" value={pw2} onChange={(e) => setPw2(e.target.value)} autoComplete="new-password" required /></Field>
            {step === "join" && <Field label={t("relayUrl")} hint={t("relayHint")}><input value={relay} onChange={(e) => setRelay(e.target.value)} required /></Field>}
            <ErrorText error={error} />
            {qr && (
              <div className="col" aria-live="polite">
                <div className="qr"><img alt={t("pLink")} src={`data:image/svg+xml;base64,${btoa(qr.svg)}`} /></div>
                <code className="small" style={{ wordBreak: "break-all" }}>{qr.payload}</code>
                <p className="muted">{sas ? t("pSas") : t("pWaiting")}</p>
                {sas && <div className="sas" aria-label={t("pSas")}>{sas}</div>}
                <p className="muted small">{t("pNoVaultNote")}</p>
              </div>
            )}
            <div className="modal-actions">
              <button type="button" className="btn" onClick={() => { api.pairCancel(); setQr(null); setStep("choose"); }}>{t("back")}</button>
              {!qr && <button className="btn primary" disabled={busy}>{step === "join" ? t("pStart") : t("next")}</button>}
            </div>
          </form>
        )}

        {step === "storage" && (
          <div className="col">
            <h2>{t("obStorage")}</h2>
            <p className="muted small">{t("obStorageNote")}</p>
            <StorageForm value={storage} onChange={(s) => { setStorage(s); setReport(null); }} signedIn={!!status?.cloud_email} />
            <CapabilityResult report={report} />
            <ErrorText error={error} />
            <div className="modal-actions">
              <button className="btn" onClick={() => setStep("device")}>{t("back")}</button>
              <button className="btn" disabled={busy} onClick={async () => {
                const bad = validateStorage(storage);
                if (bad) return setError(t(bad));
                const r = await run(() => api.testStorage(storage));
                if (r) setReport(r);
              }}>{busy && !recoveryKey ? t("testing") : t("runTest")}</button>
              <button className="btn primary" disabled={busy || report?.verdict !== "sync_capable"} onClick={async () => {
                const r = await run(() => api.createVault({ device_name: name, unlock_password: pw, storage }));
                if (r) { setPw(""); setPw2(""); setRecoveryKey(r.recovery_key); setStep("recovery"); }
              }}>{busy ? t("obCreating") : t("obCreate")}</button>
            </div>
          </div>
        )}

        {step === "recovery" && recoveryKey && (
          <div className="col">
            <h2>{t("obRecoveryTitle")}</h2>
            <p>{t("obRecoveryDesc")}</p>
            <div className="recovery" aria-label={t("obRecoveryTitle")}>{recoveryKey}</div>
            <p className="muted small">{t("obRecoveryOnce")}</p>
            <ErrorText error={error} />
            <div className="modal-actions">
              <button className="btn" onClick={async () => { const p = await run(() => api.saveRecoveryKit()); if (p) toast(t("kitSaved", { p })); }}>{t("saveKit")}</button>
              <button className="btn primary" onClick={() => { setRecoveryKey(null); setStep("verify"); }}>{t("next")}</button>
            </div>
          </div>
        )}

        {step === "verify" && (
          <form className="col" onSubmit={async (e) => {
            e.preventDefault();
            const ok = await run(() => api.verifyRecoveryKey(typedKey.trim()));
            if (ok === false) setError(t("verifyFail"));
            if (ok) { setTypedKey(""); await refresh(); setStep("first"); }
          }}>
            <h2>{t("obVerifyTitle")}</h2>
            <p className="muted">{t("obVerifyDesc")}</p>
            <Field label="AIPR-…"><input className="mono" value={typedKey} onChange={(e) => setTypedKey(e.target.value)} autoComplete="off" spellCheck={false} required /></Field>
            <ErrorText error={error} />
            <div className="modal-actions"><button className="btn primary" disabled={busy || !typedKey}>{t("verify")}</button></div>
          </form>
        )}

        {step === "first" && (
          <div className="col">
            <h2>{t("obFirstActions")}</h2>
            <div className="grid2">
              {([["actImport", "actImportDesc", "accounts"], ["actConnect", "actConnectDesc", "connections"], ["actPhone", "actPhoneDesc", "pair"]] as const).map(([k, d, page]) => (
                <button key={k} className="choice" onClick={async () => { await api.finishOnboarding(); await refresh(); go(page); }}>
                  <strong>{t(k)}</strong><div className="muted small">{t(d)}</div>
                </button>
              ))}
            </div>
            <div className="modal-actions">
              <button className="btn primary" onClick={async () => { await api.finishOnboarding(); await refresh(); }}>{t("done")}</button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
