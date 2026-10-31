// SPDX-License-Identifier: Apache-2.0
import { useState } from "react";
import { api } from "../api";
import { ErrorText, Field, useAction, useApp } from "../ui";

export function Unlock() {
  const { t, refresh, status } = useApp();
  const [pw, setPw] = useState("");
  const { busy, error, run } = useAction();
  return (
    <div className="center-screen">
      <form
        className="card panel col"
        onSubmit={async (e) => {
          e.preventDefault();
          const r = await run(() => api.unlock(pw));
          setPw("");
          if (r !== undefined) await refresh();
        }}
      >
        <div className="brand"><span className="brand-mark" aria-hidden>AP</span>{t("appName")}</div>
        <h1>{t("unlockTitle")}</h1>
        <p className="muted">{t("unlockHint")}</p>
        {status?.core.device_name && <p className="small muted">{status.core.device_name}</p>}
        <Field label={t("unlockPassword")}>
          <input type="password" autoFocus autoComplete="current-password" value={pw} onChange={(e) => setPw(e.target.value)} required />
        </Field>
        <ErrorText error={error} />
        <div className="row">
          <button className="btn primary" disabled={busy || !pw}>{t("unlock")}</button>
        </div>
        <p className="muted small">{t("forgotPassword")}</p>
        <p className="muted small">{t("notAudited")}</p>
      </form>
    </div>
  );
}
