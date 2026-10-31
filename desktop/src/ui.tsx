// SPDX-License-Identifier: Apache-2.0
import { createContext, useCallback, useContext, useEffect, useRef, useState, type ReactNode } from "react";
import { api, isUiError, type AppStatus, type UiError } from "./api";
import { type Key, type Lang, loc, translate } from "./i18n";

export interface Ctx {
  lang: Lang;
  t: (k: Key, v?: Record<string, string | number>) => string;
  status: AppStatus | null;
  refresh: () => Promise<void>;
  toast: (msg: string) => void;
  errText: (e: unknown) => string;
  go: (page: Page) => void;
  setLang: (l: Lang) => void;
}
export type Page = "overview" | "accounts" | "connections" | "executors" | "activity" | "settings" | "pair";

export const AppCtx = createContext<Ctx | null>(null);
export function useApp(): Ctx {
  const c = useContext(AppCtx);
  if (!c) throw new Error("AppCtx missing");
  return c;
}

export function makeT(lang: Lang) {
  return (k: Key, v?: Record<string, string | number>) => translate(lang, k, v);
}

export function errorText(lang: Lang, e: unknown): string {
  if (isUiError(e)) return loc(lang, (e as UiError).message) || (e as UiError).code;
  return lang === "en" ? "Something went wrong." : "出现错误。";
}

/** Run an async action with busy + error state. */
export function useAction() {
  const { errText } = useApp();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const run = useCallback(
    async <T,>(fn: () => Promise<T>): Promise<T | undefined> => {
      setBusy(true);
      setError(null);
      try {
        return await fn();
      } catch (e) {
        setError(errText(e));
        return undefined;
      } finally {
        setBusy(false);
      }
    },
    [errText],
  );
  return { busy, error, setError, run };
}

/** Load data on mount / when deps change. */
export function useLoad<T>(fn: () => Promise<T>, deps: unknown[] = []) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<UiError | null>(null);
  const [tick, setTick] = useState(0);
  useEffect(() => {
    let alive = true;
    fn().then(
      (d) => alive && (setData(d), setError(null)),
      (e) => alive && setError(isUiError(e) ? e : { code: "INTERNAL", message: { zh: "加载失败", en: "Failed to load" } }),
    );
    return () => {
      alive = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, tick]);
  return { data, error, reload: () => setTick((x) => x + 1) };
}

export function Modal(props: { title: string; onClose: () => void; children: ReactNode; wide?: boolean; labelledBy?: string }) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const prev = document.activeElement as HTMLElement | null;
    const first = ref.current?.querySelector<HTMLElement>("input, button, select, textarea, [tabindex]");
    first?.focus();
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") props.onClose();
      if (e.key === "Tab" && ref.current) {
        const f = [...ref.current.querySelectorAll<HTMLElement>("input, button, select, textarea, a[href]")].filter((x) => !x.hasAttribute("disabled"));
        if (!f.length) return;
        const [a, b] = [f[0], f[f.length - 1]];
        if (e.shiftKey && document.activeElement === a) { b.focus(); e.preventDefault(); }
        else if (!e.shiftKey && document.activeElement === b) { a.focus(); e.preventDefault(); }
      }
    };
    window.addEventListener("keydown", onKey);
    return () => { window.removeEventListener("keydown", onKey); prev?.focus(); };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
  return (
    <div className="backdrop" role="presentation" onMouseDown={(e) => e.target === e.currentTarget && props.onClose()}>
      <div className={`modal${props.wide ? " wide" : ""}`} role="dialog" aria-modal="true" aria-label={props.title} ref={ref}>
        <h2>{props.title}</h2>
        {props.children}
      </div>
    </div>
  );
}

export function Field(props: { label: string; children: ReactNode; hint?: string }) {
  return (
    <label className="field">
      <span>{props.label}</span>
      {props.children}
      {props.hint && <span className="muted small">{props.hint}</span>}
    </label>
  );
}

export function Badge(props: { tone?: "ok" | "warn" | "danger" | "accent"; children: ReactNode }) {
  return <span className={`badge ${props.tone ?? ""}`}>{props.children}</span>;
}

export function ErrorText({ error }: { error: string | null | undefined }) {
  if (!error) return null;
  return <div className="notice danger" role="alert">{error}</div>;
}

/** Re-authentication dialog for 查看原始密码 / 导出. */
export function ReauthDialog(props: { onDone: () => void; onClose: () => void }) {
  const { t } = useApp();
  const [pw, setPw] = useState("");
  const { busy, error, run } = useAction();
  return (
    <Modal title={t("reauthTitle")} onClose={props.onClose}>
      <p className="muted">{t("reauthDesc")}</p>
      <div className="notice warn small">{t("reauthAgentWarn")}</div>
      <div className="spacer" />
      <form
        onSubmit={async (e) => {
          e.preventDefault();
          const ok = await run(() => api.reauth(pw));
          setPw("");
          if (ok !== undefined) props.onDone();
        }}
      >
        <Field label={t("unlockPassword")}>
          <input type="password" autoComplete="current-password" value={pw} onChange={(e) => setPw(e.target.value)} required />
        </Field>
        <ErrorText error={error} />
        <div className="modal-actions">
          <button type="button" className="btn" onClick={props.onClose}>{t("cancel")}</button>
          <button className="btn primary" disabled={busy || !pw}>{t("confirm")}</button>
        </div>
      </form>
    </Modal>
  );
}

/** Ask for re-auth only when Rust says it is required, then retry once. */
export function useReauth() {
  const [pending, setPending] = useState<null | (() => void)>(null);
  const guard = useCallback(async <T,>(fn: () => Promise<T>): Promise<T> => {
    try {
      return await fn();
    } catch (e) {
      if (isUiError(e) && e.code === "REAUTH_REQUIRED") {
        return await new Promise<T>((resolve, reject) => {
          setPending(() => () => {
            setPending(null);
            fn().then(resolve, reject);
          });
        });
      }
      throw e;
    }
  }, []);
  const dialog = pending ? <ReauthDialog onDone={pending} onClose={() => setPending(null)} /> : null;
  return { guard, dialog };
}

export function Toast({ msg }: { msg: string | null }) {
  if (!msg) return null;
  return <div className="toast" role="status" aria-live="polite">{msg}</div>;
}

export function fmtTime(lang: Lang, iso?: string | null): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "—";
  return d.toLocaleString(lang === "en" ? "en-US" : "zh-CN", { hour12: false });
}
