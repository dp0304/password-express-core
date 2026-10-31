# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import json
import os
import re
import stat

import pytest

import aipass
from aipass import (
    Client,
    ConfigError,
    ConnectionKey,
    IntegrityFailedError,
    SigningKey,
    is_loopback_host,
    load_connection_key,
    parse_broker_url,
    resolve_broker_url,
    save_connection_key,
)
from aipass._encoding import b64u_decode, b64u_encode

SEED = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
PUB = "A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg"
KID = "conn_01jbz3k6w8a7m2q4t5v9x0y1z4"


def _write(path: str, content: str, mode: int = 0o600) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    os.write(fd, content.encode())
    os.close(fd)
    os.chmod(path, mode)


def test_save_load_roundtrip(short_tmp: str) -> None:
    path = os.path.join(short_tmp, "a", "b", "k.json")
    save_connection_key(path, ConnectionKey.from_seed(KID, SEED), broker_url="http://127.0.0.1:7878", display_name="x")
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    loaded = load_connection_key(path)
    assert loaded.key.connection_id == KID and loaded.key.public_key == PUB
    assert loaded.metadata["broker_url"] == "http://127.0.0.1:7878"
    assert re.match(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$", loaded.metadata["created_at"])
    assert not [f for f in os.listdir(os.path.dirname(path)) if ".tmp-" in f]


def test_permissions_enforced(short_tmp: str) -> None:
    path = os.path.join(short_tmp, "k.json")
    save_connection_key(path, ConnectionKey.from_seed(KID, SEED))
    os.chmod(path, 0o644)
    with pytest.raises(ConfigError, match="chmod 600"):
        load_connection_key(path)
    with pytest.raises(ConfigError):
        Client("http://127.0.0.1:1", key_file=path)
    assert load_connection_key(path, allow_insecure_permissions=True).key.public_key == PUB


def test_typescript_sdk_format_and_mcp_layout(short_tmp: str) -> None:
    os.mkdir(os.path.join(short_tmp, "connections"))
    raw = os.path.join(short_tmp, "connections", f"{KID}.key")
    _write(raw, SEED + "\n")
    assert load_connection_key(raw).key.connection_id == KID
    ts_doc = {
        "format": "aipass-connection-key-1",
        "connection_id": KID,
        "seed": SEED,
        "public_key": PUB,
        "created_at": "2026-10-30T00:00:00Z",
    }
    ts_path = os.path.join(short_tmp, "ts.json")
    _write(ts_path, json.dumps(ts_doc, indent=2))
    assert load_connection_key(ts_path).key.public_key == PUB


def test_64_byte_private_key_and_mismatch(short_tmp: str) -> None:
    path = os.path.join(short_tmp, "k64.json")
    _write(path, json.dumps({"kid": KID, "private_key": b64u_encode(b64u_decode(SEED) + b64u_decode(PUB))}))
    assert load_connection_key(path).key.public_key == PUB
    _write(path, json.dumps({"kid": KID, "private_key": b64u_encode(b64u_decode(SEED) + bytes(32))}))
    with pytest.raises(IntegrityFailedError):
        load_connection_key(path)
    _write(path, json.dumps({"connection_id": KID, "seed": SEED, "public_key": SigningKey.generate().public_key}))
    with pytest.raises(IntegrityFailedError):
        load_connection_key(path)


@pytest.mark.parametrize(
    "content",
    [
        "{not json",
        json.dumps({"connection_id": KID}),
        json.dumps({"seed": SEED}),
        json.dumps({"connection_id": "dev_1", "seed": SEED}),
        json.dumps({"connection_id": KID, "seed": "AAEC"}),
        "[]",
    ],
)
def test_malformed_key_files(short_tmp: str, content: str) -> None:
    path = os.path.join(short_tmp, "bad.json")
    _write(path, content)
    with pytest.raises(ConfigError):
        load_connection_key(path)


def test_missing_key_file(short_tmp: str) -> None:
    with pytest.raises(ConfigError):
        load_connection_key(os.path.join(short_tmp, "missing.key"))


def test_no_clobber(short_tmp: str) -> None:
    path = os.path.join(short_tmp, "k.json")
    save_connection_key(path, ConnectionKey.from_seed(KID, SEED))
    with pytest.raises(ConfigError):
        save_connection_key(path, ConnectionKey(KID, SigningKey.generate()))
    assert load_connection_key(path).key.public_key == PUB
    save_connection_key(path, ConnectionKey(KID, SigningKey.generate()), overwrite=True)
    assert load_connection_key(path).key.public_key != PUB


def test_broker_url_parsing() -> None:
    ep = parse_broker_url("http://127.0.0.1:7878")
    assert (ep.kind, ep.scheme, ep.hostname, ep.port, ep.base_path) == ("tcp", "http", "127.0.0.1", 7878, "")
    ep = parse_broker_url("https://node.example.com/aipass/")
    assert (ep.port, ep.base_path, ep.display, ep.base_url) == (
        443,
        "/aipass",
        "https://node.example.com/aipass",
        "https://node.example.com:443/aipass",
    )
    assert parse_broker_url("unix:///tmp/x/broker.sock").socket_path == "/tmp/x/broker.sock"
    assert parse_broker_url("unix:/tmp/y.sock").socket_path == "/tmp/y.sock"
    assert parse_broker_url("http://[::1]:7878").base_url == "http://[::1]:7878"
    for bad in (
        "ftp://x",
        "http://user:pass@127.0.0.1",
        "http://127.0.0.1/?q=1",
        "unix://relative.sock",
        "",
        "http://",
    ):
        with pytest.raises(ConfigError):
            parse_broker_url(bad)
    with pytest.raises(ConfigError, match="https"):
        parse_broker_url("http://node.example.com:7878")
    assert parse_broker_url("http://node.example.com:7878", allow_insecure_http=True).hostname == "node.example.com"
    assert all(is_loopback_host(h) for h in ("localhost", "127.9.0.1", "[::1]", "a.localhost"))
    assert not is_loopback_host("10.0.0.1")


def test_resolution_order(short_tmp: str) -> None:
    home = os.path.join(short_tmp, "home")
    assert resolve_broker_url(None, {"AIPASS_HOME": home}) == f"unix://{home}/run/broker.sock"
    os.mkdir(home)
    with open(os.path.join(home, "broker.json"), "w", encoding="utf-8") as fh:
        json.dump({"broker_url": "http://127.0.0.1:9999"}, fh)
    assert resolve_broker_url(None, {"AIPASS_HOME": home}) == "http://127.0.0.1:9999"
    assert resolve_broker_url(None, {"AIPASS_HOME": home, "AIPASS_BROKER_URL": "unix:///s.sock"}) == "unix:///s.sock"
    assert (
        resolve_broker_url("https://x.example", {"AIPASS_HOME": home, "AIPASS_BROKER_URL": "unix:///s.sock"})
        == "https://x.example"
    )
    with open(os.path.join(home, "broker.json"), "w", encoding="utf-8") as fh:
        fh.write("garbage")
    assert resolve_broker_url(None, {"AIPASS_HOME": home}) == f"unix://{home}/run/broker.sock"


def test_version_matches_pyproject() -> None:
    root = os.path.join(os.path.dirname(__file__), "..")
    with open(os.path.join(root, "pyproject.toml"), encoding="utf-8") as fh:
        m = re.search(r'^version = "([^"]+)"', fh.read(), re.M)
    assert m and m.group(1) == aipass.__version__
    assert os.path.exists(os.path.join(root, "src", "aipass", "py.typed"))
