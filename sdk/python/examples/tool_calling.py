# SPDX-License-Identifier: Apache-2.0
"""把 AI 通行证工具接入任意模型的函数调用循环 / Plug AI Pass tools into any model's tool loop.

This example does not call a model API. It prints the tool definitions and the system-prompt
snippet, then dispatches the tool calls a model would emit and shows the exact tool-result payloads
you would send back (OpenAI and Anthropic formats). Replace ``model_tool_calls`` with the tool calls
from your model's response.

    AIPASS_KEY_FILE=./lure-agent.key uv run python examples/tool_calling.py
"""

from __future__ import annotations

import json
import os
import sys

from aipass import (
    Client,
    anthropic_tools,
    openai_tools,
    system_prompt,
    to_anthropic_tool_result,
    to_openai_tool_message,
)

LOCALE = "en" if os.environ.get("AIPASS_LOCALE", "").startswith("en") else "zh-CN"


def main() -> int:
    # 1) Give these to your model.
    print("system prompt:\n" + system_prompt(LOCALE) + "\n")
    print("tools: " + ", ".join(t["function"]["name"] for t in openai_tools(LOCALE)) + "\n")
    assert [t["name"] for t in anthropic_tools(LOCALE)] == [t["function"]["name"] for t in openai_tools(LOCALE)]

    if not os.environ.get("AIPASS_KEY_FILE") and not os.environ.get("AIPASS_TOKEN"):
        print("Set AIPASS_KEY_FILE or AIPASS_TOKEN to also dispatch sample tool calls against your broker.")
        return 0
    client = (
        Client(bearer_token=os.environ["AIPASS_TOKEN"], locale=LOCALE)
        if os.environ.get("AIPASS_TOKEN")
        else Client.from_key_file(os.environ["AIPASS_KEY_FILE"], locale=LOCALE)
    )
    with client:
        # 2) Tool calls as your model would emit them (OpenAI sends `arguments` as a JSON string).
        listed = client.handle_tool_call("resources_list", "{}")
        print("resources_list →", listed.text[:300], "\n")
        resource = next(
            (r for r in listed.structured_content.get("resources", []) if r.get("alias") == "路亚站测试库"), None
        )
        if resource is None:
            print("路亚站测试库 not visible to this connection.")
            return 0
        call = client.handle_tool_call(
            "operations_request",
            {
                "resource_id": resource["resource_id"],
                "operation": "postgres.query_view",
                "parameters": {
                    "view": "analytics.subscription_daily",
                    "fields": ["day", "plan", "subscriptions"],
                    "period_days": 30,
                },
                "idempotency_key": "tool-loop-demo-1",
            },
        )
        # 3) Send this back to the model. `approval_required` is NOT an error: the hint tells the
        #    model to ask the user to approve on their phone and then call operations_status.
        print("OpenAI tool message:", json.dumps(to_openai_tool_message("call_1", call), ensure_ascii=False))
        print("Anthropic tool_result:", json.dumps(to_anthropic_tool_result("toolu_1", call), ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
