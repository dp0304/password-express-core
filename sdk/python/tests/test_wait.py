# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import asyncio
import threading
import time
from typing import Any, Dict, List

import pytest

from aipass import (
    AbortedError,
    AIPassTimeoutError,
    ApprovalDeniedError,
    ApprovalExpiredError,
    ApprovalRequiredError,
    AsyncClient,
    Backoff,
    Client,
    NotFoundError,
    OperationCancelledError,
    UpstreamOutcomeUnknownError,
    backoff_delay,
    error_for_operation,
    jittered,
    resolve_backoff,
)
from aipass.wait import poll_sync

from mock_broker import LURE_RESOURCE, MockBroker

FAST: Dict[str, Any] = {"interval": 0.005, "max_interval": 0.02, "jitter": 0}
PARAMS = {"view": "analytics.subscription_daily", "fields": ["day", "plan", "subscriptions"], "period_days": 30}


def pending(client: Client, key: str) -> str:
    return client.request_operation(LURE_RESOURCE["resource_id"], "postgres.query_view", PARAMS, idempotency_key=key)[
        "operation_id"
    ]


def test_backoff_math() -> None:
    b = resolve_backoff(0.1, 1.0, 2.0, 0.0)
    assert [round(backoff_delay(i, b), 6) for i in range(6)] == [0.1, 0.2, 0.4, 0.8, 1.0, 1.0]
    assert jittered(1.0, 0.2, lambda: 0.0) == pytest.approx(0.8)
    assert jittered(1.0, 0.2, lambda: 0.999999) == pytest.approx(1.2, abs=1e-5)
    for _ in range(500):
        assert 0.75 <= jittered(1.0, 0.25) <= 1.25
    # Invalid values fall back to the defaults; jitter is clamped to [0, 1].
    assert resolve_backoff(-5, 0.0001, 0.1, 7) == Backoff(interval=1.0, max_interval=10.0, backoff=1.5, jitter=1.0)
    assert resolve_backoff(5, 1, 2, 0) == Backoff(interval=5.0, max_interval=5.0, backoff=2.0, jitter=0.0)


def test_poll_with_fake_clock_does_final_poll_at_deadline() -> None:
    t = [0.0]
    calls = [0]

    def fetch(_remaining: float) -> Dict[str, str]:
        calls[0] += 1
        t[0] += 0.4
        return {"status": "approval_required"}

    out = poll_sync(
        fetch,
        lambda v: v["status"] != "approval_required",
        timeout=1.0,
        backoff=Backoff(0.001, 0.001, 1, 0),
        clock=lambda: t[0],
    )
    assert out.timed_out and out.value["status"] == "approval_required" and calls[0] == 3


def test_approval_then_result(client: Client, broker: MockBroker) -> None:
    oid = pending(client, "w-approve")
    broker.approve_operations_after_polls = 3
    updates: List[str] = []
    done = client.wait_for_operation(oid, timeout=5, on_update=lambda o: updates.append(o["status"]), **FAST)
    assert done["status"] == "succeeded"
    assert done["result"]["rows"] == 3
    assert updates == ["approval_required", "approval_required", "succeeded"]


def test_timeout_is_never_approval(client: Client, broker: MockBroker) -> None:
    oid = pending(client, "w-timeout")
    started = time.monotonic()
    res = client.wait_for_operation(oid, timeout=0.15, **FAST)
    assert res["status"] == "approval_required"
    assert "result" not in res
    assert time.monotonic() - started >= 0.14
    assert broker.operations[oid]["response"]["status"] == "approval_required"


def test_raise_on_pending_at_timeout(client: Client, broker: MockBroker) -> None:
    oid = pending(client, "w-raise")
    with pytest.raises(ApprovalRequiredError) as ei:
        client.wait_for_operation(oid, timeout=0.06, raise_on_pending=True, **FAST)
    assert ei.value.operation_id == oid
    oid2 = pending(client, "w-running")
    broker.decide_operation(oid2, "running")
    with pytest.raises(AIPassTimeoutError) as et:
        client.wait_for_operation(oid2, timeout=0.06, raise_on_pending=True, **FAST)
    assert et.value.operation is not None and et.value.operation["status"] == "running"
    assert "绝不会被视为批准" in et.value.message


def test_denied_and_expired(client: Client, broker: MockBroker) -> None:
    broker.approve_operations_after_polls = 1
    broker.operation_decision = "denied"
    assert client.wait_for_operation(pending(client, "d1"), timeout=2, **FAST)["status"] == "denied"
    with pytest.raises(ApprovalDeniedError):
        client.wait_for_operation(pending(client, "d2"), timeout=2, raise_on_failure=True, **FAST)
    broker.operation_decision = "expired"
    expired = client.wait_for_operation(pending(client, "e1"), timeout=2, **FAST)
    assert expired["status"] == "expired" and "result" not in expired
    with pytest.raises(ApprovalExpiredError):
        client.wait_for_operation(pending(client, "e2"), timeout=2, raise_on_failure=True, **FAST)


def test_error_for_operation_without_error_body() -> None:
    assert isinstance(error_for_operation({"status": "unknown", "operation_id": "op_1"}), UpstreamOutcomeUnknownError)
    assert isinstance(error_for_operation({"status": "cancelled", "operation_id": "op_1"}), OperationCancelledError)
    assert error_for_operation({"status": "denied", "operation_id": "op_1"}, "en").message == "The request was denied."


def test_cancel_event_aborts_promptly(client: Client) -> None:
    oid = pending(client, "w-abort")
    event = threading.Event()
    threading.Timer(0.08, event.set).start()
    started = time.monotonic()
    with pytest.raises(AbortedError):
        client.wait_for_operation(oid, interval=1.0, timeout=30, cancel_event=event)
    assert time.monotonic() - started < 1.0


def test_transient_errors_retried(client: Client, broker: MockBroker) -> None:
    oid = pending(client, "w-transient")
    broker.fail_next(status=503, raw_body="<html>reset</html>", path_prefix="/v1/operations/")
    broker.fail_next(status=500, code="INTERNAL", path_prefix="/v1/operations/")
    broker.fail_next(status=429, code="RATE_LIMITED", path_prefix="/v1/operations/")
    broker.approve_operations_after_polls = 1
    assert client.wait_for_operation(oid, timeout=5, **FAST)["status"] == "succeeded"


def test_final_failure_is_raised_not_stale_status(client: Client, broker: MockBroker) -> None:
    oid = pending(client, "w-stale")
    for _ in range(200):
        broker.fail_next(status=500, code="INTERNAL", path_prefix="/v1/operations/")
    with pytest.raises(Exception) as ei:
        client.wait_for_operation(oid, timeout=0.08, **FAST)
    assert getattr(ei.value, "code", None) == "INTERNAL"


def test_permanent_error_immediate(client: Client) -> None:
    started = time.monotonic()
    with pytest.raises(NotFoundError):
        client.wait_for_operation("op_01jbz3k6w8a7m2q4t5v9xnone0", interval=1.0, timeout=10)
    assert time.monotonic() - started < 0.5


def test_retry_after_honoured(client: Client, broker: MockBroker) -> None:
    oid = pending(client, "w-retry-after")
    broker.fail_next(status=429, code="RATE_LIMITED", headers={"retry-after": "1"}, path_prefix="/v1/operations/")
    broker.approve_operations_after_polls = 1
    started = time.monotonic()
    assert client.wait_for_operation(oid, timeout=5, **FAST)["status"] == "succeeded"
    assert time.monotonic() - started >= 0.95


@pytest.mark.anyio
async def test_async_wait_timeout_cancel_and_task_cancellation(aclient: AsyncClient, broker: MockBroker) -> None:
    async with aclient as c:
        op = await c.request_operation(
            LURE_RESOURCE["resource_id"], "postgres.query_view", PARAMS, idempotency_key="aw-1"
        )
        res = await c.wait_for_operation(op["operation_id"], timeout=0.1, **FAST)
        assert res["status"] == "approval_required"
        with pytest.raises(ApprovalRequiredError):
            await c.wait_for_operation(op["operation_id"], timeout=0.05, raise_on_pending=True, **FAST)

        event = asyncio.Event()
        asyncio.get_running_loop().call_later(0.05, event.set)
        started = time.monotonic()
        with pytest.raises(AbortedError):
            await c.wait_for_operation(op["operation_id"], interval=1.0, timeout=30, cancel_event=event)
        assert time.monotonic() - started < 1.0

        task = asyncio.ensure_future(c.wait_for_operation(op["operation_id"], interval=1.0, timeout=30))
        await asyncio.sleep(0.05)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

        broker.approve_operations_after_polls = broker.operations[op["operation_id"]]["polls"] + 1
        assert (await c.wait_for_operation(op["operation_id"], timeout=5, **FAST))["status"] == "succeeded"
