# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import socket
import time
from typing import Dict, List, Tuple, Type

import httpx
import pytest

import aipass
from aipass import (
    ERROR_CODES,
    AIPassError,
    AIPassTimeoutError,
    Client,
    ConnectionKey,
    InternalError,
    InvalidResponseError,
    NetworkError,
    NotFoundError,
    RateLimitedError,
    SigningKey,
    error_class_for_code,
    error_from_response,
)

from conftest import BROKER_URL
from mock_broker import LURE_RESOURCE, MockBroker

STATUS_BY_CODE: Dict[str, Tuple[int, Type[AIPassError]]] = {
    "IDENTITY_UNVERIFIED": (401, aipass.IdentityUnverifiedError),
    "UNAUTHENTICATED": (401, aipass.UnauthenticatedError),
    "FORBIDDEN": (403, aipass.ForbiddenError),
    "CONNECTION_PAUSED": (403, aipass.ConnectionPausedError),
    "APPROVAL_REQUIRED": (202, aipass.ApprovalRequiredError),
    "APPROVAL_DENIED": (403, aipass.ApprovalDeniedError),
    "APPROVAL_EXPIRED": (410, aipass.ApprovalExpiredError),
    "GRANT_EXPIRED": (403, aipass.GrantExpiredError),
    "GRANT_REVOKED": (403, aipass.GrantRevokedError),
    "BUDGET_EXHAUSTED": (403, aipass.BudgetExhaustedError),
    "SCOPE_DENIED": (403, aipass.ScopeDeniedError),
    "EXECUTOR_OFFLINE": (503, aipass.ExecutorOfflineError),
    "CONTROL_CHANNEL_LOST": (503, aipass.ControlChannelLostError),
    "SECRET_UNAVAILABLE": (409, aipass.SecretUnavailableError),
    "SYNC_CONFLICT": (409, aipass.SyncConflictError),
    "PRECONDITION_FAILED": (412, aipass.PreconditionFailedError),
    "ROLLBACK_DETECTED": (409, aipass.RollbackDetectedError),
    "INTEGRITY_FAILED": (422, aipass.IntegrityFailedError),
    "INTERACTIVE_AUTH_REQUIRED": (409, aipass.InteractiveAuthRequiredError),
    "RESULT_RESTRICTED": (403, aipass.ResultRestrictedError),
    "UPSTREAM_OUTCOME_UNKNOWN": (502, aipass.UpstreamOutcomeUnknownError),
    "UPSTREAM_ERROR": (502, aipass.UpstreamError),
    "IDEMPOTENCY_CONFLICT": (409, aipass.IdempotencyConflictError),
    "RATE_LIMITED": (429, aipass.RateLimitedError),
    "NOT_FOUND": (404, aipass.NotFoundError),
    "INVALID_REQUEST": (400, aipass.InvalidRequestError),
    "NOT_SUPPORTED": (501, aipass.NotSupportedError),
    "PAYMENT_REQUIRED": (402, aipass.PaymentRequiredError),
    "QUOTA_EXCEEDED": (429, aipass.QuotaExceededError),
    "INTERNAL": (500, aipass.InternalError),
}


def test_every_contract_code_has_a_class() -> None:
    assert sorted(STATUS_BY_CODE) == sorted(ERROR_CODES)
    for code, (_, cls) in STATUS_BY_CODE.items():
        assert error_class_for_code(code) is cls
        assert issubclass(cls, AIPassError)
    assert error_class_for_code("SOMETHING_NEW") is AIPassError


def test_envelopes_map_to_typed_errors(broker: MockBroker, key: ConnectionKey) -> None:
    with Client(BROKER_URL, connection_key=key, transport=broker.mock_transport(), max_retries=0) as client:
        for code, (status, cls) in STATUS_BY_CODE.items():
            if status < 400:
                continue
            broker.fail_next(status=status, code=code, message=f"消息 {code}", details={"field": "plan"})
            with pytest.raises(cls) as ei:
                client.list_resources()
            e = ei.value
            assert e.code == code
            assert e.message == f"消息 {code}"
            assert e.http_status == status
            assert e.request_id and e.request_id.startswith("req_")
            assert e.details == {"field": "plan"}
            assert e.to_dict()["code"] == code
            assert f"[{code}]" in str(e)


def test_unknown_code_preserved(client: Client, broker: MockBroker) -> None:
    broker.fail_next(status=418, code="BRAND_NEW_CODE", message="new")
    with pytest.raises(AIPassError) as ei:
        client.list_resources()
    assert type(ei.value) is AIPassError
    assert ei.value.code == "BRAND_NEW_CODE"


def test_retry_after(client: Client, broker: MockBroker) -> None:
    broker.fail_next(status=429, code="RATE_LIMITED", headers={"retry-after": "7"})
    with pytest.raises(RateLimitedError) as ei:
        client.list_resources()
    assert ei.value.retry_after_seconds == 7


def test_non_envelope_bodies_never_leak(client: Client, broker: MockBroker) -> None:
    broker.fail_next(status=502, raw_body="<html>Bad gateway proxy text</html>")
    with pytest.raises(InvalidResponseError) as ei:
        client.list_resources()
    assert ei.value.http_status == 502
    assert "proxy" not in ei.value.message
    broker.fail_next(status=404, raw_body="nope")
    with pytest.raises(NotFoundError):
        client.list_resources()
    assert isinstance(error_from_response(500, b"", {}, "fallback"), InternalError)


def test_bad_success_bodies(client: Client, broker: MockBroker) -> None:
    for raw in ("not json", '{"unexpected": true}'):
        broker.fail_next(status=200, raw_body=raw)
        with pytest.raises(InvalidResponseError):
            client.list_resources()
    broker.fail_next(status=200, raw_body="[1,2]")
    with pytest.raises(InvalidResponseError):
        client.get_operation("op_x")


def test_response_size_cap(broker: MockBroker, key: ConnectionKey) -> None:
    with Client(BROKER_URL, connection_key=key, transport=broker.mock_transport(), max_response_bytes=64) as c:
        with pytest.raises(InvalidResponseError) as ei:
            c.list_resources()
        assert "64" in ei.value.message


def _key() -> ConnectionKey:
    return ConnectionKey("conn_01jbz3k6w8a7m2q4t5v9x0y1z4", SigningKey.generate())


def test_connection_refused_is_network_error_after_retries() -> None:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    with Client(f"http://127.0.0.1:{port}", connection_key=_key(), max_retries=1) as c:
        started = time.monotonic()
        with pytest.raises(NetworkError) as ei:
            c.list_resources()
        assert ei.value.code == "NETWORK_ERROR"
        assert f"127.0.0.1:{port}" in ei.value.message
        assert "无法连接" in ei.value.message
        assert time.monotonic() - started >= 0.15


def test_transport_failures_retried_with_fresh_signatures() -> None:
    auths: List[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        auths.append(request.headers["authorization"])
        if len(auths) == 1:
            raise httpx.ReadError("connection reset", request=request)
        return httpx.Response(200, json={"resources": []})

    with Client(BROKER_URL, connection_key=_key(), transport=httpx.MockTransport(handler), max_retries=2) as c:
        assert c.list_resources() == {"resources": []}
    assert len(auths) == 2 and auths[0] != auths[1]


def test_access_requests_are_not_resent() -> None:
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(1)
        raise httpx.ConnectError("refused", request=request)

    with Client(BROKER_URL, connection_key=_key(), transport=httpx.MockTransport(handler), max_retries=3) as c:
        with pytest.raises(NetworkError):
            c.request_access(LURE_RESOURCE["resource_id"], ["postgres.query_view"])
    assert len(calls) == 1


def test_timeout_message_warns_not_proof_of_nothing() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("timed out", request=request)

    with Client(
        BROKER_URL, connection_key=_key(), transport=httpx.MockTransport(handler), max_retries=0, timeout=0.1
    ) as c:
        with pytest.raises(AIPassTimeoutError) as ei:
            c.request_operation(LURE_RESOURCE["resource_id"], "postgres.query_view", {}, idempotency_key="k")
    assert ei.value.code == "TIMEOUT"
    assert "idempotency_key" in ei.value.message


def test_real_timeout_against_silent_server() -> None:
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    try:
        with Client(f"http://127.0.0.1:{port}", connection_key=_key(), max_retries=0, timeout=0.2) as c:
            with pytest.raises(AIPassTimeoutError):
                c.list_resources()
    finally:
        srv.close()
