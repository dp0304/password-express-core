# SPDX-License-Identifier: Apache-2.0
"""路亚站订阅分析示例 / Lure-store subscription report.

The agent asks AI Pass to run ``postgres.query_view`` on ``analytics.subscription_daily`` of the
resource aliased "路亚站测试库". It never sees the database password: the executor connects, the
user approves on their phone / trusted client, and only the allowed fields come back.

Run::

    AIPASS_KEY_FILE=~/.aipass/connections/lure-agent.key uv run python examples/lure_store.py
    # or: AIPASS_TOKEN=aipc_… AIPASS_BROKER_URL=https://node.example.com uv run python examples/lure_store.py

Broker URL resolution: AIPASS_BROKER_URL > ~/.aipass/broker.json > unix://~/.aipass/run/broker.sock
(AIPASS_KEY_FILE / AIPASS_TOKEN are read by this example only.)
"""

from __future__ import annotations

import os
import sys
from collections import Counter
from datetime import date

from aipass import AIPassError, Client

ALIAS = "路亚站测试库"
VIEW = "analytics.subscription_daily"
EN = os.environ.get("AIPASS_LOCALE", "").startswith("en")


def t(zh: str, en: str) -> str:
    return en if EN else zh


def make_client() -> Client:
    locale = "en" if EN else "zh-CN"
    if os.environ.get("AIPASS_TOKEN"):
        return Client(bearer_token=os.environ["AIPASS_TOKEN"], locale=locale)
    key_file = os.environ.get("AIPASS_KEY_FILE")
    if not key_file:
        print(
            t(
                "请设置 AIPASS_KEY_FILE（先运行 examples/pair.py 配对）或 AIPASS_TOKEN。",
                "Set AIPASS_KEY_FILE (pair first with examples/pair.py) or AIPASS_TOKEN.",
            ),
            file=sys.stderr,
        )
        sys.exit(2)
    return Client.from_key_file(key_file, locale=locale)


def main() -> int:
    with make_client() as client:
        try:
            resource = client.find_resource(alias=ALIAS)
            if resource is None:
                print(
                    t(
                        f"当前连接看不到资源「{ALIAS}」。请在 AI 通行证中把它加入允许的项目。",
                        f'This connection cannot see the resource "{ALIAS}". Allow its project in AI Pass.',
                    )
                )
                return 1
            print(
                t(
                    f"资源：{resource['alias']}（{resource['resource_id']}，{resource['environment']}）",
                    f"Resource: {resource['alias']} ({resource['resource_id']}, {resource['environment']})",
                )
            )

            # A stable, task-derived idempotency key: re-running today reuses the same operation.
            op = client.request_operation(
                resource["resource_id"],
                "postgres.query_view",
                {"view": VIEW, "fields": ["day", "plan", "subscriptions"], "period_days": 30},
                idempotency_key=f"lure-subscription-summary-{date.today().isoformat()}",
            )
            if op["status"] == "approval_required":
                expires = op.get("expires_in_seconds") or 120
                print(
                    op.get("message")
                    or t(
                        "请在已配对的手机或可信客户端批准本次访问。",
                        "Please approve on your paired phone or trusted client.",
                    )
                )
                print(
                    t(
                        f"等待批准（最多 {expires} 秒；超时不会被视为批准）…",
                        f"Waiting for approval (up to {expires}s; a timeout is never an approval)…",
                    )
                )
                op = client.wait_for_operation(op["operation_id"], timeout=expires + 10)
        except AIPassError as err:
            rid = f" (request_id={err.request_id})" if err.request_id else ""
            print(f"{err.code}: {err.message}{rid}", file=sys.stderr)
            return 1

    status = op["status"]
    if status == "succeeded":
        result = op.get("result") or {}
        rows = result.get("data") or []
        totals: Counter = Counter()
        for row in rows:
            totals[row.get("plan")] += int(row.get("subscriptions") or 0)
        print(t(f"近 30 天新增订阅（{len(rows)} 行）：", f"New subscriptions, last 30 days ({len(rows)} rows):"))
        for plan, total in totals.most_common():
            print(f"  {plan}: {total}")
        if result.get("truncated"):
            print(t("（结果已按授权上限截断）", "(truncated at the approved limit)"))
        if result.get("restricted_fields"):
            print(
                t(
                    f"（已隐藏字段：{', '.join(result['restricted_fields'])}）",
                    f"(withheld fields: {', '.join(result['restricted_fields'])})",
                )
            )
        return 0
    if status == "approval_required":
        print(
            t(
                "仍在等待批准，稍后可用相同的 idempotency_key 重新运行。",
                "Still waiting for approval; re-run later with the same idempotency_key.",
            )
        )
        return 3
    if status == "unknown":
        print(
            t(
                "结果未知：外部服务可能已执行，请先核实。",
                "Outcome unknown: the external service may have executed; verify first.",
            )
        )
        return 4
    error = op.get("error") or {}
    print(
        t(
            f"操作结束：{status} {error.get('code', '')} {error.get('message', '')}",
            f"Operation ended: {status} {error.get('code', '')} {error.get('message', '')}",
        ).rstrip()
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
