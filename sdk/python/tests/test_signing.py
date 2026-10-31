# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import json
import os
import pickle
from typing import Any, Dict

import pytest

from aipass import (
    Client,
    ConnectionKey,
    SigningKey,
    build_string_to_sign,
    format_authorization,
    parse_authorization,
    sha256_b64u,
    sign_request,
    verify_signature,
)
from aipass._encoding import b64u_decode

from conftest import BROKER_URL
from mock_broker import MockBroker

#: CONTRACTS §1.6 test vector (verbatim).
VECTOR: Dict[str, Any] = {
    "seed": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
    "public_key": "A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg",
    "kid": "conn_01jbz3k6w8a7m2q4t5v9x0y1z4",
    "ts": 1793318400,
    "nonce": "qqqqqqqqqqqqqqqqqqqqqg",
    "cases": [
        {
            "method": "POST",
            "path": "/v1/operations",
            "body": '{"resource_id":"res_01jbz3k6w8a7m2q4t5v9x0y1z2","operation":"postgres.query_view","parameters":{"view":"analytics.subscription_daily","fields":["day","plan","subscriptions"],"period_days":30},"idempotency_key":"subscription-summary-request-001"}',
            "body_sha256": "xR8hGf1lWFHmtsMZF81X1VBrAPQQyuFe2wpLmxcaLjE",
            "string_to_sign": "AIPASS-SIG-V1\nPOST\n/v1/operations\n1793318400\nqqqqqqqqqqqqqqqqqqqqqg\nxR8hGf1lWFHmtsMZF81X1VBrAPQQyuFe2wpLmxcaLjE",
            "signature": "bkY5XhOuTqE-0g0GA_J5SPOZgk67xYrVj77Koc0EBsWGH-APHWHBuGx1MojhxBSiYyV4Cj2Llu1xmAyRITt1Aw",
        },
        {
            "method": "GET",
            "path": "/v1/resources?project_id=proj_01jbz3k6w8a7m2q4t5v9x0y1z3",
            "body": "",
            "body_sha256": "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU",
            "string_to_sign": "AIPASS-SIG-V1\nGET\n/v1/resources?project_id=proj_01jbz3k6w8a7m2q4t5v9x0y1z3\n1793318400\nqqqqqqqqqqqqqqqqqqqqqg\n47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU",
            "signature": "z-FXrTabpsAztih0b7vQ-r9wqLCSnkTZtGHBrGgL9U5aT6Nt4usP6qgRQb_FBzyl_DQ0xrNb0oSuphvOvmOjDg",
        },
    ],
}


def check_vector(v: Dict[str, Any]) -> None:
    key = SigningKey.from_seed(v["seed"])
    assert key.public_key == v["public_key"]
    for c in v["cases"]:
        assert sha256_b64u(c["body"].encode()) == c["body_sha256"]
        assert (
            build_string_to_sign(c["method"], c["path"], v["ts"], v["nonce"], c["body_sha256"]) == c["string_to_sign"]
        )
        signed = sign_request(v["kid"], key, c["method"], c["path"], c["body"], ts=v["ts"], nonce=v["nonce"])
        assert signed.string_to_sign == c["string_to_sign"]
        assert signed.body_sha256 == c["body_sha256"]
        assert signed.signature == c["signature"]
        assert (
            signed.authorization == f"AIPass-Sig kid={v['kid']}, ts={v['ts']}, nonce={v['nonce']}, sig={c['signature']}"
        )
        assert verify_signature(v["public_key"], c["string_to_sign"], c["signature"])


def test_vector_reproduced_exactly() -> None:
    check_vector(VECTOR)


def test_shared_vector_file_when_present() -> None:
    path = os.path.join(os.path.dirname(__file__), "..", "..", "..", "test-vectors", "request-signing.json")
    if not os.path.exists(path):
        pytest.skip("open-source/test-vectors/request-signing.json not present (inline copy is authoritative)")
    with open(path, encoding="utf-8") as fh:
        check_vector(json.load(fh))


def test_connection_key_and_tampering() -> None:
    key = ConnectionKey.from_seed(VECTOR["kid"], VECTOR["seed"])
    c = VECTOR["cases"][0]
    assert (
        key.sign_request("post", c["path"], c["body"].encode(), ts=VECTOR["ts"], nonce=VECTOR["nonce"]).signature
        == c["signature"]
    )
    assert not verify_signature(key.public_key, c["string_to_sign"].replace("POST", "GET"), c["signature"])
    assert not verify_signature(key.public_key, c["string_to_sign"], c["signature"][:-2] + "AA")
    assert not verify_signature("short", c["string_to_sign"], c["signature"])


def test_nonces_are_fresh_16_byte_values() -> None:
    key = SigningKey.generate()
    seen = set()
    for _ in range(200):
        s = sign_request("conn_x", key, "GET", "/v1/resources")
        assert len(b64u_decode(s.nonce)) == 16
        seen.add(s.nonce)
    assert len(seen) == 200


def test_header_parse_and_format() -> None:
    header = format_authorization(VECTOR["kid"], VECTOR["ts"], VECTOR["nonce"], "abc")
    assert parse_authorization(header) == {
        "kid": VECTOR["kid"],
        "ts": VECTOR["ts"],
        "nonce": VECTOR["nonce"],
        "sig": "abc",
    }
    assert parse_authorization("Bearer aipc_x") is None
    assert parse_authorization("AIPass-Sig kid=a, kid=b, ts=1, nonce=n, sig=s") is None
    assert parse_authorization("AIPass-Sig kid=a, ts=x, nonce=n, sig=s") is None


def test_rejects_malformed_inputs() -> None:
    with pytest.raises(ValueError):
        SigningKey.from_seed("AAEC")
    with pytest.raises(ValueError):
        SigningKey.from_seed("not base64url!")
    with pytest.raises(ValueError):
        build_string_to_sign("GET", "no-slash", 1, "n", "h")
    with pytest.raises(ValueError):
        build_string_to_sign("GET", "/a\nb", 1, "n", "h")
    with pytest.raises(ValueError):
        build_string_to_sign("GET", "/a", True, "n", "h")  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        ConnectionKey("dev_123", SigningKey.generate())


def test_seed_never_in_repr_and_not_picklable() -> None:
    key = ConnectionKey.from_seed(VECTOR["kid"], VECTOR["seed"])
    seed_hex = b64u_decode(VECTOR["seed"]).hex()
    for text in (repr(key), str(key), repr(key.signing_key)):
        assert VECTOR["seed"] not in text
        assert seed_hex not in text
    assert VECTOR["public_key"] in repr(key)
    with pytest.raises(TypeError):
        pickle.dumps(key)
    with pytest.raises(TypeError):
        pickle.dumps(key.signing_key)
    assert key.signing_key.export_seed() == b64u_decode(VECTOR["seed"])


def test_client_body_bytes_and_signature_match_vector() -> None:
    broker = MockBroker()
    key = ConnectionKey.from_seed(VECTOR["kid"], VECTOR["seed"])
    broker.add_connection(key.public_key, VECTOR["kid"])
    with Client(BROKER_URL, connection_key=key, transport=broker.mock_transport()) as client:
        op = client.request_operation(
            "res_01jbz3k6w8a7m2q4t5v9x0y1z2",
            "postgres.query_view",
            {"view": "analytics.subscription_daily", "fields": ["day", "plan", "subscriptions"], "period_days": 30},
            idempotency_key="subscription-summary-request-001",
        )
        assert op["status"] == "approval_required"
        sent = broker.requests[-1]
        c = VECTOR["cases"][0]
        assert sent.target == c["path"]
        assert sent.body.decode() == c["body"]  # byte-identical to the TypeScript SDK and the vector
        resigned = key.sign_request(sent.method, sent.target, sent.body, ts=VECTOR["ts"], nonce=VECTOR["nonce"])
        assert resigned.signature == c["signature"]
        client.list_resources(project_id="proj_01jbz3k6w8a7m2q4t5v9x0y1z3")
        assert broker.requests[-1].target == VECTOR["cases"][1]["path"]
