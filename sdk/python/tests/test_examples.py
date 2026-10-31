# SPDX-License-Identifier: Apache-2.0
"""Run the example scripts as real subprocesses against the mock broker on a unix socket."""

from __future__ import annotations

import json
import os
import re
import stat
import subprocess
import sys
from typing import Dict, Iterator, Tuple

import pytest

from aipass import ConnectionKey, SigningKey, save_connection_key

from mock_broker import LURE_RESOURCE, MockBroker, serve_unix

EXAMPLES = os.path.join(os.path.dirname(__file__), "..", "examples")


@pytest.fixture
def env_broker(short_tmp: str) -> Iterator[Tuple[MockBroker, Dict[str, str], str]]:
    broker = MockBroker()
    sock = os.path.join(short_tmp, "b.sock")
    server, thread = serve_unix(broker, sock)
    sk = SigningKey.generate()
    key_file = os.path.join(short_tmp, "lure-agent.key")
    save_connection_key(key_file, ConnectionKey(broker.add_connection(sk.public_key), sk))
    env = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": short_tmp,
        "AIPASS_HOME": os.path.join(short_tmp, "home"),
        "AIPASS_BROKER_URL": f"unix://{sock}",
        "AIPASS_KEY_FILE": key_file,
    }
    try:
        yield broker, env, short_tmp
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _run(script: str, env: Dict[str, str], *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, os.path.join(EXAMPLES, script), *args],
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )


def test_lure_store_example(env_broker: Tuple[MockBroker, Dict[str, str], str]) -> None:
    broker, env, _ = env_broker
    broker.approve_operations_after_polls = 1
    proc = _run("lure_store.py", env)
    assert proc.returncode == 0, proc.stderr
    assert "路亚站测试库" in proc.stdout
    assert "请在已配对的手机或可信客户端批准本次访问。" in proc.stdout
    assert re.search(r"monthly: 21", proc.stdout) and re.search(r"yearly: 3", proc.stdout)
    body = json.loads(next(r for r in broker.requests if r.target == "/v1/operations").body)
    assert body["parameters"] == {
        "view": "analytics.subscription_daily",
        "fields": ["day", "plan", "subscriptions"],
        "period_days": 30,
    }
    assert re.match(r"^lure-subscription-summary-\d{4}-\d\d-\d\d$", body["idempotency_key"])


def test_lure_store_example_english(env_broker: Tuple[MockBroker, Dict[str, str], str]) -> None:
    broker, env, _ = env_broker
    broker.granted.add(f"{next(iter(broker.connections))}:{LURE_RESOURCE['resource_id']}")
    proc = _run("lure_store.py", {**env, "AIPASS_LOCALE": "en"})
    assert proc.returncode == 0, proc.stderr
    assert "New subscriptions, last 30 days (3 rows):" in proc.stdout


def test_pair_example(env_broker: Tuple[MockBroker, Dict[str, str], str]) -> None:
    broker, env, tmp = env_broker
    broker.pairing_decision_after_polls = 1
    out = os.path.join(tmp, "paired.key")
    env = {k: v for k, v in env.items() if k != "AIPASS_KEY_FILE"}
    proc = _run("pair.py", env, out, "路亚站分析 Agent")
    assert proc.returncode == 0, proc.stderr
    assert re.search(r"配对码：\d{6}", proc.stdout) and "已批准" in proc.stdout
    assert stat.S_IMODE(os.stat(out).st_mode) == 0o600


def test_tool_calling_example(env_broker: Tuple[MockBroker, Dict[str, str], str]) -> None:
    _, env, _ = env_broker
    proc = _run("tool_calling.py", env)
    assert proc.returncode == 0, proc.stderr
    assert (
        "resources_list, operations_request, operations_status, operations_cancel, access_request, access_release"
        in proc.stdout
    )
    assert '"type": "tool_result"' in proc.stdout and "approval_required" in proc.stdout
