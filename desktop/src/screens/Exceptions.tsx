// SPDX-License-Identifier: Apache-2.0
// The eight exception pages of design doc §11.5: explanation + next step.
import type { ExceptionKind } from "../logic";
import type { Key } from "../i18n";
import { type Page, useApp } from "../ui";

const TARGET: Record<ExceptionKind, Page> = {
  push: "activity", executor: "executors", site: "accounts", signup: "accounts",
  revoke: "activity", conflict: "accounts", recovery: "settings", host: "connections",
};

export function ExceptionCard({ kind }: { kind: ExceptionKind }) {
  const { t, go } = useApp();
  const k = (s: "title" | "body" | "next") => `exc_${kind}_${s}` as Key;
  return (
    <div className="notice warn" role="region" aria-label={t(k("title"))}>
      <div className="row"><strong className="grow">{t(k("title"))}</strong>
        <button className="btn small" onClick={() => go(TARGET[kind])}>{t("goHandle")}</button>
      </div>
      <p className="small">{t(k("body"))}</p>
      <p className="small muted">{t(k("next"))}</p>
    </div>
  );
}
