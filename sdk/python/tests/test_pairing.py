# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import json
import os
import stat
import threading
from typing import Any, Dict, List

import pytest

from aipass import (
    AbortedError,
    Client,
    ConfigError,
    InvalidRequestError,
    apair,
    pair,
    parse_authorization,
    start_pairing,
)

from conftest import BROKER_URL
from mock_broker import MockBroker

FAST: Dict[str, Any] = {"interval": 0.005, "max_interval": 0.01, "jitter": 0}


def test_pair_approved_saves_key_0600_and_works(broker: MockBroker, short_tmp: str) -> None:
    broker.pairing_decision_after_polls = 3
    key_path = os.path.join(short_tmp, "keys", "lure-agent.key")
    codes: List[Dict[str, str]] = []
    result = pair(
        "路亚站分析 Agent",
        broker_url=BROKER_URL,
        transport=broker.mock_transport(),
        key_path=key_path,
        on_pairing_code=codes.append,
        **FAST,
    )
    assert len(codes) == 1 and len(codes[0]["pairing_code"]) == 6
    assert result.status == "approved" and not result.timed_out
    assert result.pairing_code == codes[0]["pairing_code"]
    assert result.key_path == key_path
    assert result.connection_key is not None
    start = next(r for r in broker.requests if r.target == "/v1/connections/pair")
    assert json.loads(start.body) == {
        "host_type": "sdk",
        "display_name": "路亚站分析 Agent",
        "transport": "sdk",
        "public_key": result.connection_key.public_key,
    }
    assert "authorization" not in start.headers
    polls = [r for r in broker.requests if r.target.startswith("/v1/connections/pair/")]
    assert len(polls) == 3
    for p in polls:
        parsed = parse_authorization(p.headers["authorization"])
        assert parsed is not None and parsed["kid"] == result.connection_id
    assert stat.S_IMODE(os.stat(key_path).st_mode) == 0o600
    assert stat.S_IMODE(os.stat(os.path.dirname(key_path)).st_mode) == 0o700
    with open(key_path, encoding="utf-8") as fh:
        doc = json.load(fh)
    assert doc["format"] == "aipass-connection-key-1"
    assert doc["connection_id"] == result.connection_id
    assert doc["broker_url"] == BROKER_URL
    assert doc["display_name"] == "路亚站分析 Agent"
    with result.client as c:
        assert len(c.list_resources()["resources"]) == 3
    with Client.from_key_file(key_path, transport=broker.mock_transport()) as c2:
        assert c2.connection_id == result.connection_id
        assert c2.broker_url == BROKER_URL
        assert len(c2.list_resources()["resources"]) == 3


@pytest.mark.parametrize("decision", ["denied", "expired"])
def test_pair_denied_or_expired_writes_nothing(broker: MockBroker, short_tmp: str, decision: str) -> None:
    broker.pairing_decision_after_polls = 1
    broker.pairing_decision = decision
    key_path = os.path.join(short_tmp, "x.key")
    result = pair("agent", broker_url=BROKER_URL, transport=broker.mock_transport(), key_path=key_path, **FAST)
    assert result.status == decision
    assert result.client is None and result.connection_key is None
    assert not os.path.exists(key_path)


def test_local_wait_timeout_stays_pending(broker: MockBroker, short_tmp: str) -> None:
    result = pair(
        "agent",
        broker_url=BROKER_URL,
        transport=broker.mock_transport(),
        key_path=os.path.join(short_tmp, "t.key"),
        wait_timeout=0.06,
        **FAST,
    )
    assert result.status == "pending" and result.timed_out
    assert not os.path.exists(os.path.join(short_tmp, "t.key"))


def test_two_step_and_no_clobber(broker: MockBroker, short_tmp: str) -> None:
    session = start_pairing("two-step", broker_url=BROKER_URL, transport=broker.mock_transport(), host_type="custom")
    try:
        assert len(session.pairing_code) == 6
        assert session.poll()["status"] == "pending"
        broker.pairing_decision_after_polls = 2
        assert session.wait(**FAST).status == "approved"
        key_path = os.path.join(short_tmp, "two.key")
        fd = os.open(key_path, os.O_WRONLY | os.O_CREAT, 0o600)
        os.write(fd, b"existing")
        os.close(fd)
        with pytest.raises(ConfigError):
            session.save_key(key_path)
        with open(key_path, "rb") as fh:
            assert fh.read() == b"existing"
        session.save_key(key_path, overwrite=True)
        with open(key_path, encoding="utf-8") as fh:
            assert json.load(fh)["connection_id"] == session.connection_id
        assert stat.S_IMODE(os.stat(key_path).st_mode) == 0o600
        body = json.loads(next(r for r in broker.requests if r.target == "/v1/connections/pair").body)
        assert body["host_type"] == "custom"
        assert session.pairing_code in repr(session)
    finally:
        session.close()


def test_cancel_event_aborts(broker: MockBroker) -> None:
    event = threading.Event()
    threading.Timer(0.05, event.set).start()
    with pytest.raises(AbortedError):
        pair("agent", broker_url=BROKER_URL, transport=broker.mock_transport(), cancel_event=event, interval=1.0)


def test_validation(broker: MockBroker) -> None:
    with pytest.raises(InvalidRequestError):
        start_pairing("  ", broker_url=BROKER_URL, transport=broker.mock_transport())
    with pytest.raises(InvalidRequestError):
        start_pairing("x", broker_url=BROKER_URL, transport=broker.mock_transport(), host_type="evil")
    with pytest.raises(ConfigError):
        pair("x", broker_url=BROKER_URL, transport=broker.mock_transport(), key_path="  ")


@pytest.mark.anyio
async def test_async_pair(broker: MockBroker, short_tmp: str) -> None:
    broker.pairing_decision_after_polls = 2
    seen: List[str] = []

    async def on_code(info: Dict[str, str]) -> None:
        seen.append(info["pairing_code"])

    key_path = os.path.join(short_tmp, "async.key")
    result = await apair(
        "async agent",
        broker_url=BROKER_URL,
        transport=broker.mock_transport(),
        key_path=key_path,
        on_pairing_code=on_code,
        **FAST,
    )
    assert result.status == "approved" and seen == [result.pairing_code]
    assert stat.S_IMODE(os.stat(key_path).st_mode) == 0o600
    async with result.client as c:
        assert len((await c.list_resources())["resources"]) == 3
