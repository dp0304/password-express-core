# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import os
import shutil
import sys
import tempfile
from typing import Iterator

import pytest

sys.path.insert(0, os.path.dirname(__file__))

from aipass import AsyncClient, Client, ConnectionKey, SigningKey

from mock_broker import MockBroker

BROKER_URL = "http://127.0.0.1:7878"


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def broker() -> MockBroker:
    return MockBroker()


@pytest.fixture
def key(broker: MockBroker) -> ConnectionKey:
    sk = SigningKey.generate()
    return ConnectionKey(broker.add_connection(sk.public_key), sk)


@pytest.fixture
def client(broker: MockBroker, key: ConnectionKey) -> Iterator[Client]:
    c = Client(BROKER_URL, connection_key=key, transport=broker.mock_transport())
    yield c
    c.close()


@pytest.fixture
async def aclient(broker: MockBroker, key: ConnectionKey) -> AsyncClient:
    return AsyncClient(BROKER_URL, connection_key=key, transport=broker.mock_transport())


@pytest.fixture
def short_tmp() -> Iterator[str]:
    """Short temp dir (unix socket paths must stay under ~104 bytes on macOS)."""
    base = tempfile.gettempdir()
    if len(base) > 60:
        base = "/tmp"
    d = tempfile.mkdtemp(prefix="apy-", dir=base)
    yield d
    shutil.rmtree(d, ignore_errors=True)
