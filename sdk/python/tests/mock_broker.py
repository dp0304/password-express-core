# SPDX-License-Identifier: Apache-2.0
"""Mock of the AI Pass broker's connection-facing API (CONTRACTS §6.3).

The same request handler is exposed through ``httpx.MockTransport`` (sync + async) and through a
real HTTP server on a unix domain socket. It verifies AIPass-Sig signatures exactly as the contract
specifies (raw path+query, body hash, ±300 s, nonce uniqueness), enforces ownership (other
connections' objects → NOT_FOUND) and idempotency, and lets tests script approvals.
"""

from __future__ import annotations

import copy
import hashlib
import http.server
import itertools
import json
import secrets
import socketserver
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Mapping, Optional, Set, Tuple
from urllib.parse import parse_qs, unquote, urlsplit

import httpx

from aipass import build_string_to_sign, parse_authorization, verify_signature
from aipass._encoding import b64u_decode, b64u_encode

APPROVAL_MESSAGE_ZH = "请在已配对的手机或可信客户端批准本次访问。"
APPROVAL_MESSAGE_EN = "Please approve this access on your paired phone or trusted client."

LURE_RESOURCE: Dict[str, Any] = {
    "resource_id": "res_01jbz3k6w8a7m2q4t5v9x0y1z2",
    "alias": "路亚站测试库",
    "service": "postgres",
    "project_id": "proj_01jbz3k6w8a7m2q4t5v9x0y1z3",
    "environment": "test",
    "operations": [
        {
            "name": "postgres.query_view",
            "description": "Query an allowlisted view",
            "side_effect": "read",
            "parameters_schema": {"type": "object", "required": ["view", "fields"]},
        }
    ],
    "status": "available",
    "protection_level": "compatible",
    "executor_status": "online",
}
OFFLINE_RESOURCE = {
    **LURE_RESOURCE,
    "resource_id": "res_01jbz3k6w8a7m2q4t5v9x0off1",
    "alias": "离线库",
    "status": "executor_offline",
    "executor_status": "offline",
}
GITHUB_RESOURCE = {
    **LURE_RESOURCE,
    "resource_id": "res_01jbz3k6w8a7m2q4t5v9x0gh01",
    "alias": "lure-site repo",
    "service": "github",
    "project_id": "proj_01jbz3k6w8a7m2q4t5v9x0zzzz",
}

SAMPLE_RESULT = {
    "data": [
        {"day": "2026-10-01", "plan": "monthly", "subscriptions": 12},
        {"day": "2026-10-01", "plan": "yearly", "subscriptions": 3},
        {"day": "2026-10-02", "plan": "monthly", "subscriptions": 9},
    ],
    "rows": 3,
    "truncated": False,
    "restricted": False,
    "restricted_fields": [],
}

_counter = itertools.count(1)


def ulid() -> str:
    return f"01jbz3k6w8a7m2q4t5v9x{next(_counter):05d}"[:26]


@dataclass
class Recorded:
    method: str
    target: str
    headers: Dict[str, str]
    body: bytes
    principal: Optional[str] = None


@dataclass
class ScriptedFailure:
    status: int
    code: Optional[str] = None
    message: Optional[str] = None
    details: Optional[Dict[str, Any]] = None
    headers: Dict[str, str] = field(default_factory=dict)
    raw_body: Optional[str] = None
    path_prefix: Optional[str] = None


Response = Tuple[int, Dict[str, str], bytes]


class MockBroker:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.connections: Dict[str, Dict[str, str]] = {}
        self.tokens: Dict[str, str] = {}
        self.pairings: Dict[str, Dict[str, Any]] = {}
        self.operations: Dict[str, Dict[str, Any]] = {}
        self.idempotency: Dict[str, str] = {}
        self.access: Dict[str, Dict[str, Any]] = {}
        self.grants: Dict[str, Dict[str, str]] = {}
        self.requests: List[Recorded] = []
        self.nonces: Set[str] = set()
        self.failures: List[ScriptedFailure] = []
        self.resources: List[Dict[str, Any]] = [LURE_RESOURCE, OFFLINE_RESOURCE, GITHUB_RESOURCE]
        self.granted: Set[str] = set()
        self.approve_operations_after_polls: Optional[int] = None
        self.operation_decision = "succeeded"
        self.approve_access_after_polls: Optional[int] = None
        self.pairing_decision_after_polls: Optional[int] = None
        self.pairing_decision = "approved"
        self.pairing_ttl = 600
        self.now = lambda: int(time.time())
        self._req = itertools.count(1)

    # ---- setup helpers -------------------------------------------------------------------

    def add_connection(self, public_key: str, connection_id: Optional[str] = None) -> str:
        cid = connection_id or f"conn_{ulid()}"
        self.connections[cid] = {"public_key": public_key, "status": "active"}
        return cid

    def add_token(self, connection_id: str) -> str:
        token = "aipc_" + b64u_encode(secrets.token_bytes(32))
        self.tokens[token] = connection_id
        return token

    def fail_next(self, **kwargs: Any) -> None:
        self.failures.append(ScriptedFailure(**kwargs))

    def decide_operation(self, operation_id: str, status: str) -> None:
        self._apply(self.operations[operation_id], status)

    def _apply(self, op: Dict[str, Any], status: str) -> None:
        r = op["response"]
        r["status"] = status
        r.pop("expires_in_seconds", None)
        errors = {
            "denied": ("APPROVAL_DENIED", "用户拒绝了本次访问"),
            "expired": ("APPROVAL_EXPIRED", "审批已过期"),
            "unknown": ("UPSTREAM_OUTCOME_UNKNOWN", "外部服务可能已执行"),
            "failed": ("UPSTREAM_ERROR", "上游错误"),
        }
        if status == "succeeded":
            r["result"] = copy.deepcopy(SAMPLE_RESULT)
            r["message"] = None
        elif status in errors:
            code, message = errors[status]
            r["error"] = {"code": code, "message": message}

    # ---- transports ----------------------------------------------------------------------

    def mock_transport(self) -> httpx.MockTransport:
        def handler(request: httpx.Request) -> httpx.Response:
            status, headers, body = self.handle(
                request.method, request.url.raw_path.decode("ascii"), dict(request.headers), request.read()
            )
            return httpx.Response(status, headers=headers, content=body)

        return httpx.MockTransport(handler)

    # ---- request handling ----------------------------------------------------------------

    def _rid(self) -> str:
        return f"req_01jbz3k6w8a7m2q4t5v9x{next(self._req):05d}"

    def _json(self, status: int, payload: Any, headers: Optional[Mapping[str, str]] = None) -> Response:
        return (
            status,
            {"content-type": "application/json", "x-request-id": self._rid(), **(headers or {})},
            json.dumps(payload).encode(),
        )

    def _error(
        self,
        status: int,
        code: str,
        message: str,
        details: Optional[Dict[str, Any]] = None,
        headers: Optional[Mapping[str, str]] = None,
    ) -> Response:
        rid = self._rid()
        body = {"error": {"code": code, "message": message, "details": details or {}, "request_id": rid}}
        return (
            status,
            {"content-type": "application/json", "x-request-id": rid, **(headers or {})},
            json.dumps(body, ensure_ascii=False).encode(),
        )

    def _authenticate(
        self, method: str, target: str, headers: Mapping[str, str], body: bytes, allow_pending: Optional[str] = None
    ) -> Tuple[Optional[str], Optional[Response]]:
        header = headers.get("authorization")
        en = headers.get("accept-language", "").startswith("en")
        fail = self._error(401, "IDENTITY_UNVERIFIED", "authentication failed" if en else "身份验证失败")
        if not header:
            return None, fail
        if header.startswith("Bearer "):
            cid = self.tokens.get(header[len("Bearer ") :])
            conn = self.connections.get(cid or "")
            if not cid or not conn:
                return None, fail
            if conn["status"] == "paused":
                return None, self._error(403, "CONNECTION_PAUSED", "paused")
            return cid, None
        parsed = parse_authorization(header)
        if not parsed:
            return None, fail
        kid, ts, nonce, sig = str(parsed["kid"]), int(parsed["ts"]), str(parsed["nonce"]), str(parsed["sig"])
        if abs(self.now() - ts) > 300:
            return None, fail
        try:
            if len(b64u_decode(nonce)) != 16:
                return None, fail
        except ValueError:
            return None, fail
        if f"{kid}:{nonce}" in self.nonces:
            return None, fail
        conn = self.connections.get(kid)
        if not conn or conn["status"] == "denied" or (conn["status"] == "pending" and allow_pending != kid):
            return None, fail
        sts = build_string_to_sign(method, target, ts, nonce, b64u_encode(hashlib.sha256(body).digest()))
        if not verify_signature(conn["public_key"], sts, sig):
            return None, fail
        self.nonces.add(f"{kid}:{nonce}")
        if conn["status"] == "paused":
            return None, self._error(403, "CONNECTION_PAUSED", "paused")
        return kid, None

    def handle(self, method: str, target: str, headers: Mapping[str, str], body: bytes) -> Response:
        headers = {k.lower(): v for k, v in headers.items()}
        with self.lock:
            rec = Recorded(method, target, dict(headers), body)
            self.requests.append(rec)
            try:
                return self._route(rec, method, target, headers, body)
            except Exception as exc:  # pragma: no cover - a bug in the mock
                return self._error(500, "INTERNAL", f"mock broker bug: {exc}")

    def _route(self, rec: Recorded, method: str, target: str, headers: Mapping[str, str], body: bytes) -> Response:
        en = headers.get("accept-language", "").startswith("en")
        parts = urlsplit(target)
        path = parts.path
        query = {k: v[0] for k, v in parse_qs(parts.query).items()}

        for i, f in enumerate(self.failures):
            if not f.path_prefix or path.startswith(f.path_prefix):
                del self.failures[i]
                if f.raw_body is not None:
                    return f.status, {"content-type": "text/html", **f.headers}, f.raw_body.encode()
                return self._error(
                    f.status,
                    f.code or "INTERNAL",
                    f.message or ("scripted failure" if en else "预设错误"),
                    f.details,
                    f.headers,
                )

        try:
            data = json.loads(body.decode()) if body else {}
        except ValueError:
            return self._error(400, "INVALID_REQUEST", "invalid JSON")

        if method == "GET" and path == "/v1/health":
            return self._json(
                200, {"status": "ok", "version": "mock-1", "executor_online": True, "protection_level": "compatible"}
            )

        if method == "POST" and path == "/v1/connections/pair":
            try:
                ok = all(
                    isinstance(data.get(k), str) and data[k]
                    for k in ("host_type", "display_name", "transport", "public_key")
                )
                ok = ok and len(b64u_decode(data["public_key"])) == 32
            except ValueError:
                ok = False
            if not ok:
                return self._error(400, "INVALID_REQUEST", "bad pairing request")
            cid, pid = f"conn_{ulid()}", f"pair_{ulid()}"
            self.connections[cid] = {"public_key": data["public_key"], "status": "pending"}
            expires = self.now() + self.pairing_ttl
            code = f"{100000 + secrets.randbelow(900000)}"
            self.pairings[pid] = {
                "connection_id": cid,
                "code": code,
                "expires": expires,
                "status": "pending",
                "polls": 0,
                "request": data,
            }
            exp = datetime.fromtimestamp(expires, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            return self._json(
                201, {"pairing_request_id": pid, "connection_id": cid, "pairing_code": code, "expires_at": exp}
            )

        if method == "GET" and path.startswith("/v1/connections/pair/"):
            pairing = self.pairings.get(unquote(path[len("/v1/connections/pair/") :]))
            if not pairing:
                return self._error(404, "NOT_FOUND", "not found")
            principal, err = self._authenticate(method, target, headers, body, allow_pending=pairing["connection_id"])
            if err or principal != pairing["connection_id"]:
                return self._error(401, "IDENTITY_UNVERIFIED", "signature required")
            rec.principal = principal
            pairing["polls"] += 1
            if (
                pairing["status"] == "pending"
                and self.pairing_decision_after_polls is not None
                and pairing["polls"] >= self.pairing_decision_after_polls
            ):
                pairing["status"] = self.pairing_decision
                self.connections[pairing["connection_id"]]["status"] = (
                    "active" if self.pairing_decision == "approved" else "denied"
                )
            return self._json(200, {"status": pairing["status"], "connection_id": pairing["connection_id"]})

        principal, err = self._authenticate(method, target, headers, body)
        if err:
            return err
        assert principal is not None
        rec.principal = principal

        if method == "GET" and path == "/v1/resources":
            pid, svc = query.get("project_id"), query.get("service")
            res = [
                r for r in self.resources if (not pid or r["project_id"] == pid) and (not svc or r["service"] == svc)
            ]
            return self._json(200, {"resources": res})

        if method == "POST" and path == "/v1/operations":
            rid, op_name, params, key = (
                data.get("resource_id"),
                data.get("operation"),
                data.get("parameters"),
                data.get("idempotency_key"),
            )
            if not rid or not op_name or not isinstance(params, dict) or not key or len(key) > 128:
                return self._error(400, "INVALID_REQUEST", "bad operation request")
            resource = next((r for r in self.resources if r["resource_id"] == rid), None)
            if not resource:
                return self._error(404, "NOT_FOUND", "not found" if en else "未找到")
            digest = hashlib.sha256(json.dumps([rid, op_name, params], sort_keys=True).encode()).hexdigest()
            existing_id = self.idempotency.get(f"{principal}:{key}")
            if existing_id:
                existing = self.operations[existing_id]
                if existing["digest"] != digest:
                    return self._error(409, "IDEMPOTENCY_CONFLICT", "idempotency conflict" if en else "幂等键冲突")
                r = existing["response"]
                return self._json(202 if r["status"] == "approval_required" else 200, r)
            if resource["executor_status"] == "offline":
                return self._error(503, "EXECUTOR_OFFLINE", "executor offline" if en else "执行设备离线")
            oid = f"op_{ulid()}"
            if f"{principal}:{rid}" in self.granted:
                response: Dict[str, Any] = {
                    "status": "succeeded",
                    "operation_id": oid,
                    "result": copy.deepcopy(SAMPLE_RESULT),
                }
            else:
                response = {
                    "status": "approval_required",
                    "operation_id": oid,
                    "approval_request_id": f"apr_{ulid()}",
                    "expires_in_seconds": 120,
                    "message": APPROVAL_MESSAGE_EN if en else APPROVAL_MESSAGE_ZH,
                }
            self.operations[oid] = {"owner": principal, "digest": digest, "response": response, "polls": 0}
            self.idempotency[f"{principal}:{key}"] = oid
            return self._json(202 if response["status"] == "approval_required" else 200, response)

        if path.startswith("/v1/operations/"):
            rest = path[len("/v1/operations/") :]
            cancel = rest.endswith("/cancel")
            oid = unquote(rest[: -len("/cancel")] if cancel else rest)
            op = self.operations.get(oid)
            if not op or op["owner"] != principal:
                return self._error(404, "NOT_FOUND", "not found" if en else "未找到")
            if method == "GET" and not cancel:
                op["polls"] += 1
                if (
                    op["response"]["status"] == "approval_required"
                    and self.approve_operations_after_polls is not None
                    and op["polls"] >= self.approve_operations_after_polls
                ):
                    self._apply(op, self.operation_decision)
                return self._json(200, op["response"])
            if method == "POST" and cancel:
                terminal = op["response"]["status"] in (
                    "succeeded",
                    "failed",
                    "unknown",
                    "denied",
                    "expired",
                    "cancelled",
                )
                if not terminal:
                    op["response"]["status"] = "cancelled"
                return self._json(
                    200,
                    {
                        "operation_id": oid,
                        "status": op["response"]["status"],
                        "cancelled": not terminal,
                        "side_effects": "none",
                        "message": "already finished" if terminal else "cancelled",
                    },
                )

        if method == "POST" and path == "/v1/access/requests":
            if not data.get("resource_id") or not isinstance(data.get("operations"), list) or not data["operations"]:
                return self._error(400, "INVALID_REQUEST", "bad access request")
            if not any(r["resource_id"] == data["resource_id"] for r in self.resources):
                return self._error(404, "NOT_FOUND", "not found")
            aid = f"apr_{ulid()}"
            self.access[aid] = {
                "owner": principal,
                "response": {"approval_request_id": aid, "status": "pending"},
                "polls": 0,
                "request": data,
            }
            return self._json(202, self.access[aid]["response"])

        if method == "GET" and path.startswith("/v1/access/requests/"):
            acc = self.access.get(unquote(path[len("/v1/access/requests/") :]))
            if not acc or acc["owner"] != principal:
                return self._error(404, "NOT_FOUND", "not found")
            acc["polls"] += 1
            if (
                acc["response"]["status"] == "pending"
                and self.approve_access_after_polls is not None
                and acc["polls"] >= self.approve_access_after_polls
            ):
                gid = f"grt_{ulid()}"
                acc["response"] = {**acc["response"], "status": "approved", "grant_id": gid}
                self.grants[gid] = {"owner": principal, "status": "active"}
            return self._json(200, acc["response"])

        if method == "POST" and path.startswith("/v1/access/grants/") and path.endswith("/release"):
            gid = unquote(path[len("/v1/access/grants/") : -len("/release")])
            grant = self.grants.get(gid)
            if not grant or grant["owner"] != principal:
                return self._error(404, "NOT_FOUND", "not found")
            grant["status"] = "released"
            return self._json(200, {"grant_id": gid, "status": "released"})

        return self._error(404, "NOT_FOUND", "no route")


class _UnixHTTPServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
    allow_reuse_address = True


def serve_unix(broker: MockBroker, socket_path: str) -> Tuple[_UnixHTTPServer, threading.Thread]:
    """Run ``broker`` as a real HTTP/1.1 server on a unix socket (background thread)."""

    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def _serve(self) -> None:
            length = int(self.headers.get("content-length") or 0)
            body = self.rfile.read(length) if length else b""
            status, headers, payload = broker.handle(self.command, self.path, dict(self.headers.items()), body)
            self.send_response(status)
            for k, v in headers.items():
                self.send_header(k, v)
            self.send_header("content-length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        do_GET = _serve
        do_POST = _serve

        def address_string(self) -> str:  # unix sockets have no peer address
            return "uds"

        def log_message(self, format: str, *args: Any) -> None:
            pass

    server = _UnixHTTPServer(socket_path, Handler)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
    thread.start()
    return server, thread
