# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import json
import re
import time

import pytest

from aipass import (
    TOOL_NAMES,
    AsyncClient,
    Client,
    ConnectionKey,
    anthropic_tools,
    canonical_tool_name,
    handle_tool_call,
    json_schema_tools,
    openai_responses_tools,
    openai_tools,
    system_prompt,
    to_anthropic_tool_result,
    to_openai_responses_output,
    to_openai_tool_message,
    tool_definitions,
)
from aipass._encoding import b64u_encode

from mock_broker import LURE_RESOURCE, MockBroker

CONTRACT = [
    "resources_list",
    "operations_request",
    "operations_status",
    "operations_cancel",
    "access_request",
    "access_release",
]
CJK = re.compile(r"[一-鿿]")
RID = LURE_RESOURCE["resource_id"]


def test_definitions_use_contract_names() -> None:
    assert list(TOOL_NAMES) == CONTRACT
    for d in tool_definitions():
        assert re.match(r"^[a-zA-Z0-9_-]{1,64}$", d["name"])
        assert not re.search(r"get_password|export_vault|get_cookie|get_refresh_token|exec|http_forward", d["name"])
        assert d["input_schema"]["type"] == "object"
        assert d["input_schema"]["additionalProperties"] is False
    req = next(d for d in tool_definitions() if d["name"] == "operations_request")
    assert req["input_schema"]["required"] == ["resource_id", "operation", "parameters", "idempotency_key"]


def test_locales() -> None:
    assert CJK.search(tool_definitions()[0]["description"])
    for d in tool_definitions("en"):
        assert not CJK.search(json.dumps(d, ensure_ascii=False))


def test_provider_shapes() -> None:
    oa = openai_tools("en")[0]
    assert oa["type"] == "function" and set(oa["function"]) == {"name", "description", "parameters"}
    assert openai_responses_tools()[1]["strict"] is False
    assert set(anthropic_tools()[2]) == {"name", "description", "input_schema"}
    assert json_schema_tools() == tool_definitions()
    assert json.loads(json.dumps(anthropic_tools())) == anthropic_tools()


def test_matches_typescript_definitions_byte_for_byte() -> None:
    """Both SDKs ship identical tool definitions (compared against the TS build when available)."""
    import os
    import subprocess

    ts_dist = os.path.join(os.path.dirname(__file__), "..", "..", "typescript", "dist", "index.cjs")
    if not os.path.exists(ts_dist):
        pytest.skip("TypeScript SDK not built")
    try:
        out = subprocess.run(
            [
                "node",
                "-e",
                f"const m=require({json.dumps(os.path.abspath(ts_dist))});"
                "process.stdout.write(JSON.stringify({zh:m.toolDefinitions(),en:m.toolDefinitions({locale:'en'}),"
                "pz:m.systemPrompt(),pe:m.systemPrompt({locale:'en'})}))",
            ],
            capture_output=True,
            check=True,
            timeout=30,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        pytest.skip("node not available")
    ts = json.loads(out)
    assert ts["zh"] == tool_definitions()
    assert ts["en"] == tool_definitions("en")
    assert ts["pz"] == system_prompt()
    assert ts["pe"] == system_prompt("en")


def test_system_prompt() -> None:
    zh = system_prompt()
    assert "approval_required" in zh and "operations_status" in zh and "绝不要求用户在对话中粘贴密码" in zh
    en = system_prompt("en")
    assert "approval_required" in en and "Never ask the user to paste passwords" in en and not CJK.search(en)


def test_aliases() -> None:
    assert canonical_tool_name("operations.request") == "operations_request"
    assert canonical_tool_name("get_password") is None


def test_dispatch_every_tool(client: Client, broker: MockBroker) -> None:
    r = handle_tool_call(client, "resources_list", {"service": "postgres"})
    assert not r.is_error and len(r.structured_content["resources"]) == 2
    assert json.loads(r.text) == r.structured_content

    args = json.dumps(
        {
            "resource_id": RID,
            "operation": "postgres.query_view",
            "parameters": {"view": "analytics.subscription_daily", "fields": ["day"]},
            "idempotency_key": "tool-1",
        }
    )
    r = client.handle_tool_call("operations_request", args)
    assert not r.is_error and r.structured_content["status"] == "approval_required"
    assert "已配对的手机或可信客户端" in r.text and "不要要求用户在对话中提供密码" in r.text
    assert json.loads(r.text.split("\n\n")[0]) == r.structured_content
    oid = r.structured_content["operation_id"]

    broker.decide_operation(oid, "succeeded")
    s = handle_tool_call(client, "operations.status", {"operation_id": oid}, locale="en")
    assert s.tool == "operations_status" and s.structured_content["result"]["rows"] == 3

    op2 = client.request_operation(RID, "postgres.query_view", {}, idempotency_key="tool-c")
    c = handle_tool_call(client, "operations_cancel", {"operation_id": op2["operation_id"]})
    assert c.structured_content["cancelled"] is True

    a = handle_tool_call(
        client,
        "access_request",
        {
            "resource_id": RID,
            "operations": ["postgres.query_view"],
            "scope": {"operations": ["postgres.query_view"]},
            "duration_seconds": 900,
            "reason": "订阅分析",
        },
    )
    assert not a.is_error and a.structured_content["status"] == "pending" and "等待用户在可信设备上批准" in a.text
    broker.approve_access_after_polls = 1
    grant = client.get_access_request(a.structured_content["approval_request_id"])["grant_id"]
    rel = handle_tool_call(client, "access_release", {"grant_id": grant})
    assert rel.structured_content == {"grant_id": grant, "status": "released"}
    assert json.loads(json.dumps(rel.to_dict()))["tool"] == "access_release"


def test_settle_waits_for_running_not_for_approval(client: Client, broker: MockBroker, key: ConnectionKey) -> None:
    started = time.monotonic()
    p = handle_tool_call(
        client,
        "operations_request",
        {"resource_id": RID, "operation": "postgres.query_view", "parameters": {}, "idempotency_key": "s1"},
        settle=5,
    )
    assert p.structured_content["status"] == "approval_required"
    assert time.monotonic() - started < 1


def test_errors_become_results(client: Client, broker: MockBroker) -> None:
    broker.fail_next(status=409, code="INTERACTIVE_AUTH_REQUIRED", message="需要重新登录 GitHub")
    r = handle_tool_call(client, "resources_list", {})
    assert r.is_error
    assert r.structured_content == {"error": {"code": "INTERACTIVE_AUTH_REQUIRED", "message": "需要重新登录 GitHub"}}
    assert "不要在对话中索要密码" in r.text
    assert to_anthropic_tool_result("toolu_1", r) == {
        "type": "tool_result",
        "tool_use_id": "toolu_1",
        "content": r.text,
        "is_error": True,
    }
    nf = handle_tool_call(client, "operations_status", {"operation_id": "op_01jbz3k6w8a7m2q4t5v9xnone0"})
    assert nf.structured_content["error"]["code"] == "NOT_FOUND"


@pytest.mark.parametrize(
    "name,args",
    [
        ("operations_request", {"resource_id": RID, "operation": "x", "parameters": {}}),
        ("operations_request", "{not json"),
        ("operations_request", [1, 2]),
        ("operations_status", {}),
        ("access_request", {"resource_id": RID, "operations": []}),
        ("access_request", {"resource_id": RID, "operations": ["x"], "duration_seconds": 999999}),
        ("access_release", {"grant_id": 5}),
    ],
)
def test_invalid_args_rejected_locally(client: Client, broker: MockBroker, name: str, args: object) -> None:
    before = len(broker.requests)
    r = handle_tool_call(client, name, args)
    assert r.is_error and r.structured_content["error"]["code"] == "INVALID_REQUEST"
    assert len(broker.requests) == before


def test_unknown_tool(client: Client, broker: MockBroker) -> None:
    r = handle_tool_call(client, "get_password", {"entry": "x"})
    assert r.is_error and r.tool == "get_password"
    assert broker.requests == []


def test_no_secret_material_in_tool_output(client: Client, key: ConnectionKey) -> None:
    seed = b64u_encode(key.signing_key.export_seed())
    outs = [
        handle_tool_call(client, "resources_list", {}),
        handle_tool_call(
            client,
            "operations_request",
            {"resource_id": RID, "operation": "postgres.query_view", "parameters": {}, "idempotency_key": "leak"},
        ),
        handle_tool_call(client, "operations_status", {"operation_id": "op_missing0000"}),
    ]
    for o in outs:
        text = json.dumps(o.to_dict(), ensure_ascii=False)
        assert seed not in text
        assert not re.search(r"AIPass-Sig|sig=|Bearer ", text)


def test_envelopes(client: Client) -> None:
    r = handle_tool_call(client, "resources_list", {})
    assert to_openai_tool_message("call_1", r) == {"role": "tool", "tool_call_id": "call_1", "content": r.text}
    assert to_openai_responses_output("call_2", r) == {
        "type": "function_call_output",
        "call_id": "call_2",
        "output": r.text,
    }
    assert to_anthropic_tool_result("toolu_2", r) == {
        "type": "tool_result",
        "tool_use_id": "toolu_2",
        "content": r.text,
    }


@pytest.mark.anyio
async def test_async_dispatch(aclient: AsyncClient, broker: MockBroker) -> None:
    async with aclient as c:
        r = await c.handle_tool_call("resources_list", "{}")
        assert not r.is_error
        r = await c.handle_tool_call(
            "operations_request",
            {"resource_id": RID, "operation": "postgres.query_view", "parameters": {}, "idempotency_key": "a1"},
        )
        assert r.structured_content["status"] == "approval_required"
        broker.fail_next(status=503, code="EXECUTOR_OFFLINE", message="执行设备离线")
        e = await c.handle_tool_call("operations_status", {"operation_id": r.structured_content["operation_id"]})
        assert e.is_error and "执行设备离线" in e.text
