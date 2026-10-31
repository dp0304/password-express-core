// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from "vitest";
import { dictionaries, translate } from "./i18n";
import { ALL_EXCEPTIONS } from "./logic";

describe("i18n", () => {
  it("en is complete and non-empty for every zh key", () => {
    const zh = dictionaries["zh-CN"], en = dictionaries.en;
    expect(Object.keys(en).sort()).toEqual(Object.keys(zh).sort());
    for (const [k, v] of Object.entries(en)) expect(v.trim(), k).not.toBe("");
  });
  it("interpolates", () => {
    expect(translate("en", "copied", { s: 30 })).toBe(
      "Copied; the clipboard is cleared in 30 s and the value is marked to stay out of clipboard history and cloud sync (some clipboard tools may ignore this)",
    );
    expect(translate("zh-CN", "copied", { s: 30 })).toMatch(/^已复制，30 秒后自动清除剪贴板；/);
    expect(translate("zh-CN", "apRows", { n: "1,000" })).toBe("最多 1,000 行");
  });
  it("has all eight exception pages in both languages", () => {
    for (const k of ALL_EXCEPTIONS)
      for (const part of ["title", "body", "next"]) {
        expect(translate("zh-CN", `exc_${k}_${part}` as never)).not.toContain("exc_");
        expect(translate("en", `exc_${k}_${part}` as never)).not.toContain("exc_");
      }
  });
  it("follows the honesty rules", () => {
    const all = [...Object.values(dictionaries["zh-CN"]), ...Object.values(dictionaries.en)].join("\n");
    expect(all).not.toMatch(/已验证兼容|verified compatib|首个|the first /i);
    expect(dictionaries.en.cnRemoteNote).toContain("not an end-to-end blind relay");
    expect(dictionaries["zh-CN"].notAudited).toContain("尚未经过独立安全审计");
    expect(dictionaries["zh-CN"].navOverview + dictionaries["zh-CN"].navAccounts + dictionaries["zh-CN"].navConnections + dictionaries["zh-CN"].navExecutors + dictionaries["zh-CN"].navActivity + dictionaries["zh-CN"].navSettings).toBe("总览账号AI 连接执行设备活动设置");
  });
});
