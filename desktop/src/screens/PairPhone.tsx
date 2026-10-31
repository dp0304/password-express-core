// SPDX-License-Identifier: Apache-2.0
// 绑定手机: this desktop already holds the vault, so it acts as the trusted device — paste
// the aipass://pair link shown by the phone, compare the 6-digit code, confirm here.
// (Desktop-as-new-device is offered in onboarding, "加入已有账号库".)
import { useEffect, useState } from "react";
import { api, onEvent } from "../api";
import { loc } from "../i18n";
import { ErrorText, Field, useAction, useApp } from "../ui";

export function PairPhone() {
  const { t, lang, toast } = useApp();
  const [uri, setUri] = useState("");
  const [peer, setPeer] = useState<{ name: string; role: string } | null>(null);
  const [sas, setSas] = useState<string | null>(null);
  const [code, setCode] = useState("");
  const [share, setShare] = useState(false);
  const [done, setDone] = useState(false);
  const { busy, error, setError, run } = useAction();

  useEffect(() => {
    const sub = onEvent<{ stage: string; side?: string; sas?: string; error?: { message: { zh: string; en: string } } }>("pairing", (e) => {
      if (e.side && e.side !== "trusted") return;
      if (e.stage === "sas") setSas(e.sas ?? null);
      if (e.stage === "failed") setError(t("pFailed", { e: loc(lang, e.error?.message) }));
    });
    return () => { sub.then((u) => u()); api.pairCancel().catch(() => undefined); };
  }, [lang, setError, t]);

  const reset = () => { setPeer(null); setSas(null); setCode(""); setUri(""); setDone(false); api.pairCancel(); };

  return (
    <div>
      <div className="page-head"><h1>{t("pTitle")}</h1></div>
      <div className="card col">
        <h2>{t("pModePaste")}</h2>
        <p className="muted small">{t("pPasteDesc")}</p>
        <p className="muted small">{t("pShowDesc")} → {t("obJoin")}</p>
        {!peer && (
          <form className="col" onSubmit={async (e) => {
            e.preventDefault();
            const r = await run(() => api.pairScan(uri));
            if (r) setPeer(r);
          }}>
            <Field label={t("pLink")}><textarea className="mono" value={uri} onChange={(e) => setUri(e.target.value)} placeholder="aipass://pair?v=1&p=…" required spellCheck={false} /></Field>
            <div className="row"><button className="btn primary" disabled={busy || !uri.startsWith("aipass://pair")}>{t("pStart")}</button></div>
          </form>
        )}
        {peer && !done && (
          <div className="col" aria-live="polite">
            <p><strong>{peer.name}</strong> · {peer.role}</p>
            {!sas ? <p className="muted">{t("pWaiting")}</p> : (
              <>
                <p>{t("pSas")}</p>
                <div className="sas">{sas}</div>
                <Field label={`${t("pCodeOnOther")}（${t("optional")}）`}><input className="mono" inputMode="numeric" maxLength={6} value={code} onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))} /></Field>
                <label className="row small"><input type="checkbox" checked={share} onChange={(e) => setShare(e.target.checked)} />{t("pShareStorage")}</label>
                <div className="row">
                  <button className="btn danger" onClick={reset}>{t("pSasMismatch")}</button>
                  <button className="btn primary" disabled={busy} onClick={async () => {
                    const r = await run(() => api.pairConfirm(code || undefined, share));
                    if (r) { setDone(true); toast(t("pDone")); }
                  }}>{t("pSasMatch")}</button>
                </div>
              </>
            )}
          </div>
        )}
        {done && <div className="notice ok">{t("pDone")} <button className="btn small" onClick={reset}>{t("add")}</button></div>}
        <ErrorText error={error} />
        <p className="muted small">{t("pNoVaultNote")}</p>
      </div>
    </div>
  );
}
