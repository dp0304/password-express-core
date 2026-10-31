#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
//
// 配对一个自研 Agent / Pair a custom agent (host_type = "sdk").
//
//   node examples/pair.mjs ./lure-agent.key "路亚站分析 Agent"
//
// Shows a pairing code; confirm it on your phone or trusted AI Pass client. The key file is written
// with mode 0600 only after approval. Broker URL: AIPASS_BROKER_URL > ~/.aipass/broker.json >
// unix://~/.aipass/run/broker.sock.
import { pair } from "@aipass/sdk";

const [keyPath = "./aipass-agent.key", displayName = "Custom agent"] = process.argv.slice(2);
const en = (process.env.AIPASS_LOCALE ?? "").startsWith("en");

const result = await pair({
  displayName,
  keyPath,
  locale: en ? "en" : "zh-CN",
  onPairingCode: ({ pairing_code, expires_at }) => {
    console.log(en ? `Pairing code: ${pairing_code}` : `配对码：${pairing_code}`);
    console.log(
      en
        ? `Confirm this code on your paired phone or trusted client before ${expires_at}. Scanning or seeing the code alone grants nothing.`
        : `请在 ${expires_at} 前于已配对的手机或可信客户端核对并确认此配对码。仅看到配对码不会授予任何权限。`,
    );
  },
});

switch (result.status) {
  case "approved":
    console.log(en ? `Approved: ${result.connectionId}; key saved to ${result.keyPath} (0600).` : `已批准：${result.connectionId}；密钥已保存到 ${result.keyPath}（权限 0600）。`);
    result.client?.close();
    break;
  case "denied":
    console.log(en ? "The connection was denied." : "连接请求被拒绝。");
    process.exitCode = 1;
    break;
  case "expired":
    console.log(en ? "The pairing request expired; run again." : "配对请求已过期，请重新运行。");
    process.exitCode = 1;
    break;
  default:
    console.log(en ? "Still pending (stopped waiting). Nothing was approved." : "仍在等待（已停止等待），未获批准。");
    process.exitCode = 1;
}
