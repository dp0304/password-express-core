# SPDX-License-Identifier: Apache-2.0
"""Real HTTP/1.1 server on a unix domain socket (httpx ``uds`` transport, sync and async)."""

from __future__ import annotations

import os
import uuid
from typing import Iterator, Tuple

import pytest

from aipass import AsyncClient, Client, ConnectionKey, NetworkError, SigningKey, apair, pair

from mock_broker import LURE_RESOURCE, MockBroker, serve_unix

PARAMS = {"view": "analytics.subscription_daily", "fields": ["day"]}


@pytest.fixture
def uds(short_tmp: str) -> Iterator[Tuple[MockBroker, str]]:
    broker = MockBroker()
    path = os.path.join(short_tmp, "broker.sock")
    server, thread = serve_unix(broker, path)
    try:
        yield broker, path
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _key(broker: MockBroker) -> ConnectionKey:
    sk = SigningKey.generate()
    return ConnectionKey(broker.add_connection(sk.public_key), sk)


def test_sync_client_over_unix_socket(uds: Tuple[MockBroker, str]) -> None:
    broker, path = uds
    key = _key(broker)
    for client in (Client(f"unix://{path}", connection_key=key), Client(socket_path=path, connection_key=key)):
        with client:
            assert client.broker_url == f"unix://{path}"
            assert client.list_resources(service="postgres")["resources"][0]["alias"] == "路亚站测试库"
            # Query with spaces/unicode: the server verifies the signature against the raw request target.
            assert client.list_resources(service="postgres 测试&x=1")["resources"] == []
            op = client.request_operation(
                LURE_RESOURCE["resource_id"], "postgres.query_view", PARAMS, idempotency_key=f"uds-{uuid.uuid4()}"
            )
            assert op["status"] == "approval_required"
            broker.decide_operation(op["operation_id"], "succeeded")
            assert client.wait_for_operation(op["operation_id"], interval=0.005, timeout=2)["status"] == "succeeded"
            assert broker.requests[-1].principal == key.connection_id
            assert broker.requests[-1].headers["host"] == "localhost"


@pytest.mark.anyio
async def test_async_client_over_unix_socket(uds: Tuple[MockBroker, str]) -> None:
    broker, path = uds
    key = _key(broker)
    async with AsyncClient(socket_path=path, connection_key=key) as client:
        assert (await client.health())["status"] == "ok"
        op = await client.request_operation(
            LURE_RESOURCE["resource_id"], "postgres.query_view", PARAMS, idempotency_key="uds-async"
        )
        broker.approve_operations_after_polls = 1
        done = await client.wait_for_operation(op["operation_id"], interval=0.005, timeout=2)
        assert done["status"] == "succeeded"
        assert broker.requests[-1].principal == key.connection_id


def test_env_resolution_over_unix_socket(uds: Tuple[MockBroker, str]) -> None:
    broker, path = uds
    with Client(connection_key=_key(broker), env={"AIPASS_BROKER_URL": f"unix://{path}"}) as client:
        assert client.health()["status"] == "ok"


def test_pairing_over_unix_socket(uds: Tuple[MockBroker, str], short_tmp: str) -> None:
    broker, path = uds
    broker.pairing_decision_after_polls = 1
    result = pair("uds agent", socket_path=path, key_path=os.path.join(short_tmp, "k.key"), interval=0.005, jitter=0)
    assert result.status == "approved"
    with result.client as c:
        assert len(c.list_resources()["resources"]) == 3
    with Client(key_file=os.path.join(short_tmp, "k.key")) as from_file:  # broker_url from the key file
        assert from_file.broker_url == f"unix://{path}"
        assert len(from_file.list_resources()["resources"]) == 3


@pytest.mark.anyio
async def test_async_pairing_over_unix_socket(uds: Tuple[MockBroker, str]) -> None:
    broker, path = uds
    broker.pairing_decision_after_polls = 2
    result = await apair("uds async agent", socket_path=path, interval=0.005, jitter=0)
    assert result.status == "approved"
    async with result.client as c:
        assert len((await c.list_resources())["resources"]) == 3


def test_missing_socket_is_network_error(short_tmp: str) -> None:
    home = os.path.join(short_tmp, "home")
    with Client(
        connection_key=ConnectionKey("conn_01jbz3k6w8a7m2q4t5v9x0y1z4", SigningKey.generate()),
        env={"AIPASS_HOME": home},
        max_retries=0,
    ) as c:
        assert c.broker_url == f"unix://{os.path.join(home, 'run', 'broker.sock')}"
        with pytest.raises(NetworkError) as ei:
            c.list_resources()
        assert "broker.sock" in ei.value.message
