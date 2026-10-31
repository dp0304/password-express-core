# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import json
import logging
import re

import pytest

from aipass import (
    ApprovalRequiredError,
    AsyncClient,
    Client,
    ConfigError,
    ConnectionKey,
    ExecutorOfflineError,
    IdempotencyConflictError,
    IdentityUnverifiedError,
    InvalidRequestError,
    NotFoundError,
    SigningKey,
)

from conftest import BROKER_URL
from mock_broker import (
    APPROVAL_MESSAGE_EN,
    APPROVAL_MESSAGE_ZH,
    GITHUB_RESOURCE,
    LURE_RESOURCE,
    OFFLINE_RESOURCE,
    MockBroker,
)

PARAMS = {"view": "analytics.subscription_daily", "fields": ["day", "plan", "subscriptions"], "period_days": 30}
RID = LURE_RESOURCE["resource_id"]


def test_health_is_public(client: Client, broker: MockBroker) -> None:
    assert client.health()["status"] == "ok"
    assert "authorization" not in broker.requests[-1].headers


def test_list_resources_signs_query(client: Client, broker: MockBroker, key: ConnectionKey) -> None:
    assert [r["resource_id"] for r in client.list_resources()["resources"]] == [
        RID,
        OFFLINE_RESOURCE["resource_id"],
        GITHUB_RESOURCE["resource_id"],
    ]
    res = client.list_resources(project_id=LURE_RESOURCE["project_id"], service="postgres")
    assert [r["alias"] for r in res["resources"]] == ["路亚站测试库", "离线库"]
    sent = broker.requests[-1]
    assert sent.target == f"/v1/resources?project_id={LURE_RESOURCE['project_id']}&service=postgres"
    assert re.match(
        r"^AIPass-Sig kid=conn_[0-9a-z]+, ts=\d+, nonce=[A-Za-z0-9_-]{22}, sig=[A-Za-z0-9_-]{86}$",
        sent.headers["authorization"],
    )
    assert sent.principal == key.connection_id
    assert sent.headers["accept-language"] == "zh-CN"
    assert sent.headers["user-agent"].startswith("aipass-sdk-python/0.1.0 python/")


def test_query_with_spaces_and_unicode_is_signed_as_sent(client: Client, broker: MockBroker) -> None:
    assert client.list_resources(service="postgres 测试&x=1")["resources"] == []
    assert broker.requests[-1].principal is not None  # signature verified against the raw target


def test_find_resource_by_alias(client: Client) -> None:
    found = client.find_resource(alias="路亚站测试库")
    assert found is not None and found["resource_id"] == RID
    assert client.find_resource(alias="nope") is None


def test_request_operation_approval_required_is_a_status(client: Client) -> None:
    op = client.request_operation(RID, "postgres.query_view", PARAMS, idempotency_key="k-approval")
    assert op["status"] == "approval_required"
    assert op["message"] == APPROVAL_MESSAGE_ZH
    assert op["expires_in_seconds"] == 120
    assert op["approval_request_id"].startswith("apr_")


def test_raise_on_pending(client: Client) -> None:
    with pytest.raises(ApprovalRequiredError) as ei:
        client.request_operation(RID, "postgres.query_view", PARAMS, idempotency_key="k-raise", raise_on_pending=True)
    assert ei.value.code == "APPROVAL_REQUIRED"
    assert ei.value.operation_id and ei.value.operation_id.startswith("op_")
    assert ei.value.approval_request_id and ei.value.approval_request_id.startswith("apr_")


def test_granted_operation_succeeds_immediately(client: Client, broker: MockBroker, key: ConnectionKey) -> None:
    broker.granted.add(f"{key.connection_id}:{RID}")
    op = client.request_operation(RID, "postgres.query_view", PARAMS, idempotency_key="k-granted")
    assert op["status"] == "succeeded"
    assert op["result"]["rows"] == 3


def test_auto_idempotency_key_and_replay(client: Client, broker: MockBroker) -> None:
    op = client.request_operation(RID, "postgres.query_view", PARAMS)
    body = json.loads(broker.requests[-1].body)
    assert re.match(r"^aipass-sdk-[A-Za-z0-9_-]{24}$", body["idempotency_key"])
    again = client.request_operation(RID, "postgres.query_view", PARAMS, idempotency_key=body["idempotency_key"])
    assert again["operation_id"] == op["operation_id"]


def test_idempotency_conflict(client: Client) -> None:
    client.request_operation(RID, "postgres.query_view", PARAMS, idempotency_key="k-conflict")
    with pytest.raises(IdempotencyConflictError) as ei:
        client.request_operation(RID, "postgres.query_view", {**PARAMS, "period_days": 7}, idempotency_key="k-conflict")
    assert ei.value.http_status == 409
    assert ei.value.request_id and ei.value.request_id.startswith("req_")


def test_executor_offline(client: Client) -> None:
    with pytest.raises(ExecutorOfflineError) as ei:
        client.request_operation(
            OFFLINE_RESOURCE["resource_id"], "postgres.query_view", PARAMS, idempotency_key="k-off"
        )
    assert ei.value.message == "执行设备离线"


def test_get_and_cancel_operation(client: Client) -> None:
    op = client.request_operation(RID, "postgres.query_view", PARAMS, idempotency_key="k-cancel")
    assert client.get_operation(op["operation_id"])["status"] == "approval_required"
    cancelled = client.cancel_operation(op["operation_id"])
    assert cancelled == {
        "operation_id": op["operation_id"],
        "status": "cancelled",
        "cancelled": True,
        "side_effects": "none",
        "message": "cancelled",
    }
    assert client.get_operation(op["operation_id"])["status"] == "cancelled"


def test_ids_are_not_capabilities(client: Client, broker: MockBroker) -> None:
    op = client.request_operation(RID, "postgres.query_view", PARAMS, idempotency_key="k-owner")
    sk = SigningKey.generate()
    other_id = broker.add_connection(sk.public_key)
    with Client(BROKER_URL, connection_key=ConnectionKey(other_id, sk), transport=broker.mock_transport()) as other:
        with pytest.raises(NotFoundError):
            other.get_operation(op["operation_id"])
        with pytest.raises(NotFoundError):
            other.cancel_operation(op["operation_id"])


def test_access_request_flow(client: Client, broker: MockBroker) -> None:
    scope = {
        "operations": ["postgres.query_view"],
        "postgres": {"views": {"analytics.subscription_daily": ["day", "plan", "subscriptions"]}},
    }
    acc = client.request_access(
        RID,
        ["postgres.query_view"],
        scope=scope,
        limits={
            "max_rows_per_operation": 1000,
            "max_rows_per_grant": 5000,
            "max_requests_per_grant": 20,
            "max_result_bytes": 262144,
        },
        duration_seconds=900,
        reason="订阅转化分析",
    )
    assert acc["status"] == "pending"
    assert json.loads(broker.requests[-1].body) == {
        "resource_id": RID,
        "operations": ["postgres.query_view"],
        "scope": scope,
        "limits": {
            "max_rows_per_operation": 1000,
            "max_rows_per_grant": 5000,
            "max_requests_per_grant": 20,
            "max_result_bytes": 262144,
        },
        "duration_seconds": 900,
        "reason": "订阅转化分析",
    }
    assert client.get_access_request(acc["approval_request_id"])["status"] == "pending"
    broker.approve_access_after_polls = 3
    approved = client.wait_for_access_request(acc["approval_request_id"], interval=0.005, max_interval=0.01, timeout=5)
    assert approved["status"] == "approved"
    assert approved["grant_id"].startswith("grt_")
    assert client.release_grant(approved["grant_id"]) == {"grant_id": approved["grant_id"], "status": "released"}


def test_local_validation_before_any_request(client: Client, broker: MockBroker) -> None:
    before = len(broker.requests)
    with pytest.raises(InvalidRequestError):
        client.request_operation("", "postgres.query_view", PARAMS)
    with pytest.raises(InvalidRequestError):
        client.request_operation(RID, "postgres.query_view", PARAMS, idempotency_key="x" * 129)
    with pytest.raises(InvalidRequestError):
        client.request_operation(RID, "postgres.query_view", [1, 2])  # type: ignore[arg-type]
    with pytest.raises(InvalidRequestError):
        client.request_access(RID, [])
    with pytest.raises(InvalidRequestError):
        client.request_access(RID, ["x"], duration_seconds=True)  # type: ignore[arg-type]
    with pytest.raises(InvalidRequestError):
        client.get_operation("")
    with pytest.raises(InvalidRequestError):
        client.request_operation(RID, "postgres.query_view", PARAMS, idempotency_key="bad\nkey")
    with pytest.raises(InvalidRequestError):
        client.request_access(RID, ["x"], limits={"max_rows_per_grant": 5})
    assert len(broker.requests) == before


def test_unknown_and_forged_keys_are_rejected(broker: MockBroker, key: ConnectionKey) -> None:
    for k in (
        ConnectionKey("conn_01jbz3k6w8a7m2q4t5v9xzzzzz", SigningKey.generate()),
        ConnectionKey(key.connection_id, SigningKey.generate()),
    ):
        with Client(BROKER_URL, connection_key=k, transport=broker.mock_transport()) as c:
            with pytest.raises(IdentityUnverifiedError):
                c.list_resources()


def test_paused_connection(client: Client, broker: MockBroker, key: ConnectionKey) -> None:
    broker.connections[key.connection_id]["status"] = "paused"
    with pytest.raises(Exception) as ei:
        client.list_resources()
    assert getattr(ei.value, "code", None) == "CONNECTION_PAUSED"


def test_bearer_token(broker: MockBroker, key: ConnectionKey) -> None:
    token = broker.add_token(key.connection_id)
    with Client(BROKER_URL, bearer_token=token, transport=broker.mock_transport()) as c:
        assert len(c.list_resources()["resources"]) == 3
        assert broker.requests[-1].headers["authorization"] == f"Bearer {token}"
        assert c.auth_kind == "bearer"
        assert token[5:] not in repr(c)
        assert token[5:] not in repr(c._auth)


@pytest.mark.parametrize(
    "bad", ["aipr_abcdefghijklmnopqrstu", "aips_abcdefghijklmnopqrstu", "ghp_abcdefghijklmnopqrstu", "aipc_short"]
)
def test_rejects_unsupported_bearer_prefixes(bad: str) -> None:
    with pytest.raises(ConfigError):
        Client(BROKER_URL, bearer_token=bad)


def test_requires_exactly_one_auth_source() -> None:
    with pytest.raises(ConfigError):
        Client(BROKER_URL)
    with pytest.raises(ConfigError):
        Client(
            BROKER_URL,
            bearer_token="aipc_abcdefghijklmnopqrstuvwxyz",
            connection_key=ConnectionKey("conn_abc", SigningKey.generate()),
        )


def test_english_locale(broker: MockBroker, key: ConnectionKey) -> None:
    with Client(BROKER_URL, connection_key=key, transport=broker.mock_transport(), locale="en") as c:
        assert (
            c.request_operation(RID, "postgres.query_view", PARAMS, idempotency_key="k-en")["message"]
            == APPROVAL_MESSAGE_EN
        )
        assert broker.requests[-1].headers["accept-language"] == "en"


def test_logs_carry_metadata_only(client: Client, caplog: pytest.LogCaptureFixture, key: ConnectionKey) -> None:
    caplog.set_level(logging.DEBUG, logger="aipass")
    client.list_resources(project_id=LURE_RESOURCE["project_id"])
    client.request_operation(RID, "postgres.query_view", PARAMS, idempotency_key="k-log")
    with pytest.raises(NotFoundError):
        client.get_operation("op_missing")
    records = [r for r in caplog.records if r.name == "aipass"]
    assert len(records) >= 3
    dump = "\n".join(r.getMessage() for r in records)
    assert "path=/v1/resources " in dump
    for forbidden in (
        "AIPass-Sig",
        "sig=",
        "Authorization",
        "analytics.subscription_daily",
        "project_id=",
        key.signing_key.export_seed().hex(),
    ):
        assert forbidden not in dump


def test_repr_without_secrets(client: Client, key: ConnectionKey) -> None:
    from aipass._encoding import b64u_encode

    seed = b64u_encode(key.signing_key.export_seed())
    assert key.connection_id in repr(client)
    assert seed not in repr(client)
    assert seed not in repr(client._auth)


# ---- async ----------------------------------------------------------------------------------


@pytest.mark.anyio
async def test_async_client_every_method(aclient: AsyncClient, broker: MockBroker, key: ConnectionKey) -> None:
    async with aclient as c:
        assert (await c.health())["status"] == "ok"
        assert len((await c.list_resources(service="postgres"))["resources"]) == 2
        assert (await c.find_resource(alias="路亚站测试库")) is not None
        op = await c.request_operation(RID, "postgres.query_view", PARAMS, idempotency_key="a-1")
        assert op["status"] == "approval_required"
        with pytest.raises(ApprovalRequiredError):
            await c.request_operation(RID, "postgres.query_view", PARAMS, idempotency_key="a-1", raise_on_pending=True)
        broker.approve_operations_after_polls = 2
        done = await c.wait_for_operation(op["operation_id"], interval=0.005, max_interval=0.01, jitter=0, timeout=5)
        assert done["status"] == "succeeded"
        assert (await c.get_operation(op["operation_id"]))["result"]["rows"] == 3
        op2 = await c.request_operation(RID, "postgres.query_view", PARAMS, idempotency_key="a-2")
        assert (await c.cancel_operation(op2["operation_id"]))["cancelled"] is True
        acc = await c.request_access(RID, ["postgres.query_view"], duration_seconds=600)
        assert (await c.get_access_request(acc["approval_request_id"]))["status"] == "pending"
        broker.approve_access_after_polls = 1
        approved = await c.wait_for_access_request(acc["approval_request_id"], interval=0.005, timeout=5)
        assert (await c.release_grant(approved["grant_id"]))["status"] == "released"
        with pytest.raises(IdempotencyConflictError):
            await c.request_operation(RID, "postgres.query_view", {"view": "x"}, idempotency_key="a-1")
        assert all(r.principal == key.connection_id for r in broker.requests if r.target != "/v1/health")
