# SPDX-License-Identifier: Apache-2.0
"""Shared request pipeline for the sync and async clients:
serialise → sign (fresh nonce per attempt, via httpx auth flow) → send → map errors.
Retries only transport failures, and only for requests marked retry-safe."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import platform
import ssl
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Tuple, Union

import httpx

from ._encoding import random_b64u
from ._messages import msg
from ._version import __version__
from .errors import (
    AbortedError,
    AIPassError,
    AIPassTimeoutError,
    InvalidRequestError,
    InvalidResponseError,
    NetworkError,
    error_from_code,
    error_from_response,
)
from .models import OperationResponse
from .urls import BrokerEndpoint

DEFAULT_LOGGER = logging.getLogger("aipass")
DEFAULT_MAX_RESPONSE_BYTES = 16 * 1024 * 1024

JsonDict = Dict[str, Any]


@dataclass(frozen=True)
class CoreConfig:
    endpoint: BrokerEndpoint
    locale: str
    timeout: float = 30.0
    max_retries: int = 2
    max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES
    user_agent: Optional[str] = None
    ca_file: Optional[str] = None
    trust_env: Optional[bool] = None
    logger: logging.Logger = DEFAULT_LOGGER


def user_agent(extra: Optional[str]) -> str:
    base = f"aipass-sdk-python/{__version__} python/{platform.python_version()} httpx/{httpx.__version__}"
    return f"{base} {extra}" if extra else base


def encode_body(body: Any) -> bytes:
    """Compact UTF-8 JSON (same bytes as JavaScript's ``JSON.stringify`` for the same input)."""
    return json.dumps(body, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _verify(config: CoreConfig) -> Union[bool, ssl.SSLContext]:
    if config.ca_file:
        return ssl.create_default_context(cafile=config.ca_file)
    return True


def _trust_env(config: CoreConfig) -> bool:
    # Never route a local broker (unix socket / loopback) through an environment proxy.
    if config.trust_env is not None:
        return config.trust_env
    return not config.endpoint.is_local


def _headers(config: CoreConfig, has_body: bool) -> Dict[str, str]:
    headers = {
        "Accept": "application/json",
        "Accept-Language": "en" if config.locale == "en" else "zh-CN",
        "User-Agent": user_agent(config.user_agent),
    }
    if has_body:
        headers["Content-Type"] = "application/json"
    return headers


def _parse_success(config: CoreConfig, status: int, headers: Mapping[str, str], body: bytes) -> JsonDict:
    rid = headers.get("x-request-id")
    if status < 200 or status >= 300:
        raise error_from_response(status, body, headers, msg(config.locale, "invalid_response", status=status))
    try:
        data = json.loads(body.decode("utf-8")) if body.strip() else {}
    except (UnicodeDecodeError, ValueError):
        raise InvalidResponseError(
            "INVALID_RESPONSE",
            msg(config.locale, "invalid_response", status=status),
            http_status=status,
            request_id=rid,
        ) from None
    if not isinstance(data, dict):
        raise InvalidResponseError(
            "INVALID_RESPONSE",
            msg(config.locale, "invalid_response", status=status),
            http_status=status,
            request_id=rid,
        )
    return data


def _transport_error(config: CoreConfig, exc: Exception, timeout: float) -> AIPassError:
    if isinstance(exc, httpx.TimeoutException):
        return AIPassTimeoutError("TIMEOUT", msg(config.locale, "request_timeout", seconds=f"{timeout:g}"))
    detail = str(exc) or type(exc).__name__
    return NetworkError("NETWORK_ERROR", msg(config.locale, "network", target=config.endpoint.display, detail=detail))


def _too_large(config: CoreConfig, status: int) -> InvalidResponseError:
    return InvalidResponseError(
        "INVALID_RESPONSE",
        msg(config.locale, "response_too_large", limit=config.max_response_bytes),
        http_status=status,
    )


def _retry_delay(attempt: int) -> float:
    from .wait import jittered

    return jittered(min(2.0, 0.25 * (2 ** (attempt - 1))), 0.3)


def _clean_params(params: Optional[Mapping[str, Optional[str]]]) -> Optional[Dict[str, str]]:
    if not params:
        return None
    out = {k: v for k, v in params.items() if v is not None}
    return out or None


def _precheck_socket(config: CoreConfig) -> None:
    """Fail fast (as a retryable connect error) when the unix socket file does not exist.

    httpcore 1.0.x does not close its socket when a unix ``connect()`` fails, so checking first
    avoids leaking a descriptor until GC in the common "broker not running" case."""
    ep = config.endpoint
    if ep.kind == "unix" and ep.socket_path and not os.path.exists(ep.socket_path):
        raise httpx.ConnectError(f"[Errno 2] No such file or directory: {ep.socket_path!r}")


class SyncHTTP:
    """Blocking transport around ``httpx.Client``."""

    def __init__(self, config: CoreConfig, transport: Optional[httpx.BaseTransport] = None) -> None:
        self.config = config
        ep = config.endpoint
        if transport is None:
            transport = (
                httpx.HTTPTransport(uds=ep.socket_path)
                if ep.kind == "unix"
                else httpx.HTTPTransport(verify=_verify(config))
            )
        self._client = httpx.Client(
            base_url=ep.base_url,
            transport=transport,
            timeout=config.timeout,
            trust_env=_trust_env(config),
            follow_redirects=False,
        )

    def call(
        self,
        method: str,
        path: str,
        *,
        auth: Optional[httpx.Auth],
        retry_safe: bool,
        params: Optional[Mapping[str, Optional[str]]] = None,
        body: Any = None,
        timeout: Optional[float] = None,
    ) -> Tuple[int, JsonDict]:
        config = self.config
        content = None if body is None else encode_body(body)
        attempts = config.max_retries + 1 if retry_safe else 1
        effective_timeout = config.timeout if timeout is None else timeout
        log_path = config.endpoint.base_path + path
        for attempt in range(1, attempts + 1):
            started = time.monotonic()
            try:
                _precheck_socket(config)
                with self._client.stream(
                    method,
                    path.lstrip("/"),
                    params=_clean_params(params),
                    content=content,
                    headers=_headers(config, content is not None),
                    auth=auth if auth is not None else httpx.USE_CLIENT_DEFAULT,
                    timeout=effective_timeout,
                ) as resp:
                    chunks: List[bytes] = []
                    size = 0
                    for chunk in resp.iter_bytes():
                        size += len(chunk)
                        if size > config.max_response_bytes:
                            raise _too_large(config, resp.status_code)
                        chunks.append(chunk)
                    status, headers, raw = resp.status_code, resp.headers, b"".join(chunks)
            except AIPassError:
                raise
            except (httpx.TransportError, httpx.TimeoutException) as exc:
                err = _transport_error(config, exc, effective_timeout)
                if attempt >= attempts:
                    config.logger.debug(
                        "aipass.http.error method=%s path=%s code=%s attempt=%d", method, log_path, err.code, attempt
                    )
                    raise err from None
                config.logger.warning(
                    "aipass.http.retry method=%s path=%s code=%s attempt=%d", method, log_path, err.code, attempt
                )
                time.sleep(_retry_delay(attempt))
                continue
            config.logger.debug(
                "aipass.http method=%s path=%s status=%d request_id=%s duration_ms=%d attempt=%d",
                method,
                log_path,
                status,
                headers.get("x-request-id"),
                int((time.monotonic() - started) * 1000),
                attempt,
            )
            return status, _parse_success(config, status, headers, raw)
        raise AssertionError("unreachable")  # pragma: no cover

    def close(self) -> None:
        self._client.close()


class AsyncHTTP:
    """Async transport around ``httpx.AsyncClient``."""

    def __init__(self, config: CoreConfig, transport: Optional[httpx.AsyncBaseTransport] = None) -> None:
        self.config = config
        ep = config.endpoint
        if transport is None:
            transport = (
                httpx.AsyncHTTPTransport(uds=ep.socket_path)
                if ep.kind == "unix"
                else httpx.AsyncHTTPTransport(verify=_verify(config))
            )
        self._client = httpx.AsyncClient(
            base_url=ep.base_url,
            transport=transport,
            timeout=config.timeout,
            trust_env=_trust_env(config),
            follow_redirects=False,
        )

    async def call(
        self,
        method: str,
        path: str,
        *,
        auth: Optional[httpx.Auth],
        retry_safe: bool,
        params: Optional[Mapping[str, Optional[str]]] = None,
        body: Any = None,
        timeout: Optional[float] = None,
    ) -> Tuple[int, JsonDict]:
        config = self.config
        content = None if body is None else encode_body(body)
        attempts = config.max_retries + 1 if retry_safe else 1
        effective_timeout = config.timeout if timeout is None else timeout
        log_path = config.endpoint.base_path + path
        for attempt in range(1, attempts + 1):
            started = time.monotonic()
            try:
                _precheck_socket(config)
                async with self._client.stream(
                    method,
                    path.lstrip("/"),
                    params=_clean_params(params),
                    content=content,
                    headers=_headers(config, content is not None),
                    auth=auth if auth is not None else httpx.USE_CLIENT_DEFAULT,
                    timeout=effective_timeout,
                ) as resp:
                    chunks: List[bytes] = []
                    size = 0
                    async for chunk in resp.aiter_bytes():
                        size += len(chunk)
                        if size > config.max_response_bytes:
                            raise _too_large(config, resp.status_code)
                        chunks.append(chunk)
                    status, headers, raw = resp.status_code, resp.headers, b"".join(chunks)
            except AIPassError:
                raise
            except (httpx.TransportError, httpx.TimeoutException) as exc:
                err = _transport_error(config, exc, effective_timeout)
                if attempt >= attempts:
                    config.logger.debug(
                        "aipass.http.error method=%s path=%s code=%s attempt=%d", method, log_path, err.code, attempt
                    )
                    raise err from None
                config.logger.warning(
                    "aipass.http.retry method=%s path=%s code=%s attempt=%d", method, log_path, err.code, attempt
                )
                await asyncio.sleep(_retry_delay(attempt))
                continue
            config.logger.debug(
                "aipass.http method=%s path=%s status=%d request_id=%s duration_ms=%d attempt=%d",
                method,
                log_path,
                status,
                headers.get("x-request-id"),
                int((time.monotonic() - started) * 1000),
                attempt,
            )
            return status, _parse_success(config, status, headers, raw)
        raise AssertionError("unreachable")  # pragma: no cover

    async def aclose(self) -> None:
        await self._client.aclose()


# ---- request builders / validators shared by both clients ---------------------------------


#: All four limits are required when given (the broker has no per-field defaults).
LIMIT_KEYS = ("max_rows_per_operation", "max_rows_per_grant", "max_requests_per_grant", "max_result_bytes")


def _printable(value: str) -> bool:
    return not any(ord(c) < 0x20 or 0x7F <= ord(c) <= 0x9F for c in value)


def generate_idempotency_key() -> str:
    """Random idempotency key (``aipass-sdk-<b64u>``). Prefer a key derived from your task."""
    return f"aipass-sdk-{random_b64u(18)}"


def invalid(locale: str, detail: str) -> InvalidRequestError:
    return InvalidRequestError("INVALID_REQUEST", msg(locale, "invalid_argument", detail=detail))


def require_id(locale: str, value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > 128:
        raise invalid(locale, f"{name} must be a non-empty string (≤128 chars)")
    return value


def path_segment(value: str) -> str:
    from urllib.parse import quote

    return quote(value, safe="")


def build_operation_body(
    locale: str,
    resource_id: Any,
    operation: Any,
    parameters: Any,
    idempotency_key: Optional[str],
    task_id: Optional[str],
) -> JsonDict:
    params = {} if parameters is None else parameters
    if not isinstance(params, dict):
        raise invalid(locale, "parameters must be an object")
    key = generate_idempotency_key() if idempotency_key is None else idempotency_key
    if not isinstance(key, str) or not (1 <= len(key) <= 128) or not _printable(key):
        raise invalid(locale, "idempotency_key must be 1..128 printable characters")
    body: JsonDict = {
        "resource_id": require_id(locale, resource_id, "resource_id"),
        "operation": require_id(locale, operation, "operation"),
        "parameters": params,
        "idempotency_key": key,
    }
    if task_id is not None:
        body["task_id"] = require_id(locale, task_id, "task_id")
    return body


def build_access_body(
    locale: str,
    resource_id: Any,
    operations: Any,
    scope: Any,
    limits: Any,
    duration_seconds: Any,
    reason: Any,
) -> JsonDict:
    body: JsonDict = {"resource_id": require_id(locale, resource_id, "resource_id")}
    if (
        not isinstance(operations, (list, tuple))
        or not operations
        or not all(isinstance(o, str) and o for o in operations)
    ):
        raise invalid(locale, "operations must be a non-empty list of strings")
    body["operations"] = list(operations)
    if scope is not None:
        if not isinstance(scope, dict):
            raise invalid(locale, "scope must be an object")
        body["scope"] = scope
    if limits is not None:
        if not isinstance(limits, dict) or not all(
            isinstance(limits.get(k), int) and not isinstance(limits.get(k), bool) and limits[k] >= 0
            for k in LIMIT_KEYS
        ):
            raise invalid(locale, "limits must contain the integers " + ", ".join(LIMIT_KEYS))
        body["limits"] = {k: limits[k] for k in LIMIT_KEYS}
    if duration_seconds is not None:
        if isinstance(duration_seconds, bool) or not isinstance(duration_seconds, int) or duration_seconds <= 0:
            raise invalid(locale, "duration_seconds must be a positive integer")
        body["duration_seconds"] = duration_seconds
    if reason is not None:
        if not isinstance(reason, str):
            raise invalid(locale, "reason must be a string")
        body["reason"] = reason
    return body


def expect_shape(locale: str, status: int, ok: bool) -> None:
    if not ok:
        raise InvalidResponseError(
            "INVALID_RESPONSE", msg(locale, "invalid_response", status=status), http_status=status
        )


def check_operation(locale: str, status: int, data: JsonDict) -> OperationResponse:
    expect_shape(locale, status, isinstance(data.get("status"), str) and isinstance(data.get("operation_id"), str))
    return data  # type: ignore[return-value]


def check_access(locale: str, status: int, data: JsonDict) -> JsonDict:
    expect_shape(
        locale, status, isinstance(data.get("approval_request_id"), str) and isinstance(data.get("status"), str)
    )
    return data


def error_for_operation(op: Mapping[str, Any], locale: str = "zh-CN") -> AIPassError:
    """Typed error for a terminal operation that did not succeed."""
    operation: Any = dict(op)
    err = op.get("error")
    if isinstance(err, dict) and isinstance(err.get("code"), str):
        details = err.get("details")
        return error_from_code(
            err["code"],
            err.get("message") or msg(locale, "operation_failed", status=op.get("status")),
            request_id=err.get("request_id"),
            details=details if isinstance(details, dict) else None,
            operation=operation,
        )
    status = op.get("status")
    mapping = {
        "denied": ("APPROVAL_DENIED", "approval_denied"),
        "expired": ("APPROVAL_EXPIRED", "approval_expired"),
        "cancelled": ("CANCELLED", "operation_cancelled"),
        "unknown": ("UPSTREAM_OUTCOME_UNKNOWN", "outcome_unknown"),
    }
    code, key = mapping.get(str(status), ("UPSTREAM_ERROR", "operation_failed"))
    return error_from_code(code, msg(locale, key, status=status), operation=operation)


def access_failure(status: str, locale: str) -> AIPassError:
    if status == "denied":
        return error_from_code("APPROVAL_DENIED", msg(locale, "approval_denied"))
    if status == "expired":
        return error_from_code("APPROVAL_EXPIRED", msg(locale, "approval_expired"))
    return error_from_code("CANCELLED", msg(locale, "operation_cancelled"))


def aborted(locale: str) -> AbortedError:
    return AbortedError("ABORTED", msg(locale, "aborted"))
