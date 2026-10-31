# SPDX-License-Identifier: Apache-2.0
"""配对一个自研 Agent / Pair a custom agent (host_type = "sdk").

    uv run python examples/pair.py ./lure-agent.key "路亚站分析 Agent"

Shows a pairing code; confirm it on your phone or trusted AI Pass client. The key file is written
with mode 0600 only after approval. Broker URL: AIPASS_BROKER_URL > ~/.aipass/broker.json >
unix://~/.aipass/run/broker.sock.
"""

from __future__ import annotations

import os
import sys
from typing import Dict

from aipass import AIPassError, pair

EN = os.environ.get("AIPASS_LOCALE", "").startswith("en")


def show_code(info: Dict[str, str]) -> None:
    if EN:
        print(f"Pairing code: {info['pairing_code']}")
        print(
            f"Confirm this code on your paired phone or trusted client before {info['expires_at']}. Seeing the code alone grants nothing."
        )
    else:
        print(f"配对码：{info['pairing_code']}")
        print(
            f"请在 {info['expires_at']} 前于已配对的手机或可信客户端核对并确认此配对码。仅看到配对码不会授予任何权限。"
        )
    sys.stdout.flush()


def main() -> int:
    key_path = sys.argv[1] if len(sys.argv) > 1 else "./aipass-agent.key"
    display_name = sys.argv[2] if len(sys.argv) > 2 else "Custom agent"
    try:
        result = pair(display_name, key_path=key_path, on_pairing_code=show_code, locale="en" if EN else "zh-CN")
    except AIPassError as err:
        print(f"{err.code}: {err.message}", file=sys.stderr)
        return 1
    if result.status == "approved":
        print(
            f"Approved: {result.connection_id}; key saved to {result.key_path} (0600)."
            if EN
            else f"已批准：{result.connection_id}；密钥已保存到 {result.key_path}（权限 0600）。"
        )
        result.client.close()
        return 0
    messages = {
        "denied": ("连接请求被拒绝。", "The connection was denied."),
        "expired": ("配对请求已过期，请重新运行。", "The pairing request expired; run again."),
        "pending": ("仍在等待（已停止等待），未获批准。", "Still pending (stopped waiting). Nothing was approved."),
    }
    zh, en = messages[result.status]
    print(en if EN else zh)
    return 1


if __name__ == "__main__":
    sys.exit(main())
