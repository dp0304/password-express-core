# SPDX-License-Identifier: Apache-2.0
"""Synchronous client for the connection-authenticated ("C") broker API (CONTRACTS §6.3).

The client never receives, stores or returns business credentials. It holds only its own
connection key / token, which is never serialised or logged.
"""

from __future__ import annotations

import logging
import threading
from typing import TYPE_CHECKING, Any, Callable, Dict, List, Mapping, NoReturn, Optional, Sequence, Tuple, Union

import httpx

from . import _core
from ._messages import msg, normalize_locale
from .auth import BearerAuth, SignatureAuth
from .errors import AIPassTimeoutError, ApprovalRequiredError, ConfigError
from .keyfile import load_connection_key
from .models import (
    AccessRequestResponse,
    CancelResponse,
    HealthResponse,
    OperationResponse,
    ReleaseResponse,
    ResourceList,
    ResourceView,
    is_terminal_access_status,
    is_terminal_operation_status,
)
from .signing import ConnectionKey
from .urls import BrokerEndpoint, parse_broker_url, resolve_broker_url
from .wait import Backoff, poll_sync, resolve_backoff

if TYPE_CHECKING:  # pragma: no cover
    from .tools import ToolCallResult

Auth = Union[SignatureAuth, BearerAuth]


def _resolve_auth(
    locale: str,
    connection_key: Optional[ConnectionKey],
    key_file: Optional[str],
    bearer_token: Optional[str],
    allow_insecure_key_file_permissions: bool,
) -> Tuple[Auth, Optional[str]]:
    sources = [s for s in (connection_key, key_file, bearer_token) if s]
    if not sources:
        raise ConfigError("CONFIG_ERROR", msg(locale, "no_auth"))
    if len(sources) > 1:
        raise ConfigError("CONFIG_ERROR", msg(locale, "multiple_auth"))
    if connection_key is not None:
        return SignatureAuth(connection_key), None
    if key_file:
        loaded = load_connection_key(
            key_file, allow_insecure_permissions=allow_insecure_key_file_permissions, locale=locale
        )
        return SignatureAuth(loaded.key), loaded.metadata.get("broker_url")
    return BearerAuth(bearer_token or "", locale), None


def _resolve_endpoint(
    locale: str,
    broker_url: Optional[str],
    socket_path: Optional[str],
    env: Optional[Mapping[str, str]],
    key_file_broker_url: Optional[str],
    allow_insecure_http: bool,
) -> BrokerEndpoint:
    if socket_path:
        return parse_broker_url(f"unix://{socket_path}", locale=locale)
    import os

    environ = os.environ if env is None else env
    explicit = broker_url or (None if environ.get("AIPASS_BROKER_URL") else key_file_broker_url)
    return parse_broker_url(
        resolve_broker_url(explicit, environ), locale=locale, allow_insecure_http=allow_insecure_http
    )


class _ClientBase:
    """Configuration shared by :class:`Client` and :class:`~aipass.AsyncClient`."""

    def __init__(
        self,
        broker_url: Optional[str] = None,
        *,
        socket_path: Optional[str] = None,
        connection_key: Optional[ConnectionKey] = None,
        key_file: Optional[str] = None,
        bearer_token: Optional[str] = None,
        locale: str = "zh-CN",
        timeout: float = 30.0,
        max_retries: int = 2,
        max_response_bytes: int = _core.DEFAULT_MAX_RESPONSE_BYTES,
        ca_file: Optional[str] = None,
        allow_insecure_http: bool = False,
        allow_insecure_key_file_permissions: bool = False,
        trust_env: Optional[bool] = None,
        user_agent: Optional[str] = None,
        env: Optional[Mapping[str, str]] = None,
        logger: Optional[logging.Logger] = None,
    ) -> None:
        self._locale = normalize_locale(locale)
        self._auth, key_file_url = _resolve_auth(
            self._locale, connection_key, key_file, bearer_token, allow_insecure_key_file_permissions
        )
        endpoint = _resolve_endpoint(self._locale, broker_url, socket_path, env, key_file_url, allow_insecure_http)
        self._config = _core.CoreConfig(
            endpoint=endpoint,
            locale=self._locale,
            timeout=float(timeout),
            max_retries=max(0, int(max_retries)),
            max_response_bytes=int(max_response_bytes),
            user_agent=user_agent,
            ca_file=ca_file,
            trust_env=trust_env,
            logger=logger or _core.DEFAULT_LOGGER,
        )

    @property
    def broker_url(self) -> str:
        """Display form of the broker endpoint (no credentials)."""
        return self._config.endpoint.display

    @property
    def connection_id(self) -> Optional[str]:
        """``conn_…`` when authenticated with a connection key."""
        return self._auth.principal_id

    @property
    def auth_kind(self) -> str:
        return self._auth.kind

    @property
    def locale(self) -> str:
        return self._locale

    def _poll_timeout(self, remaining: float) -> float:
        return min(self._config.timeout, max(2.0, remaining))

    def __repr__(self) -> str:
        conn = f", {self.connection_id}" if self.connection_id else ""
        return f"{type(self).__name__}({self.broker_url}, auth={self.auth_kind}{conn})"

    __str__ = __repr__

    def __reduce__(self) -> NoReturn:
        raise TypeError(f"{type(self).__name__} cannot be pickled")


class Client(_ClientBase):
    """Blocking AI Pass client. Use as a context manager or call :meth:`close`.

    Exactly one of ``connection_key``, ``key_file`` (written by :func:`aipass.pair` or the MCP
    bridge, must be 0600) or ``bearer_token`` (``aipc_…`` / ``aipa_…``) is required.
    """

    def __init__(
        self, broker_url: Optional[str] = None, *, transport: Optional[httpx.BaseTransport] = None, **kwargs: Any
    ) -> None:
        super().__init__(broker_url, **kwargs)
        self._http = _core.SyncHTTP(self._config, transport)

    @classmethod
    def from_key_file(cls, key_file: str, **kwargs: Any) -> Client:
        return cls(key_file=key_file, **kwargs)

    def __enter__(self) -> Client:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def close(self) -> None:
        self._http.close()

    # ---- API -----------------------------------------------------------------------------

    def health(self) -> HealthResponse:
        """``GET /v1/health`` (public)."""
        status, data = self._http.call("GET", "/v1/health", auth=None, retry_safe=True)
        _core.expect_shape(self._locale, status, isinstance(data.get("status"), str))
        return data  # type: ignore[return-value]

    def list_resources(
        self, project_id: Optional[str] = None, service: Optional[str] = None, *, timeout: Optional[float] = None
    ) -> ResourceList:
        """``GET /v1/resources`` — resources this connection may discover (never secrets)."""
        status, data = self._http.call(
            "GET",
            "/v1/resources",
            auth=self._auth,
            retry_safe=True,
            params={"project_id": project_id, "service": service},
            timeout=timeout,
        )
        _core.expect_shape(self._locale, status, isinstance(data.get("resources"), list))
        return data  # type: ignore[return-value]

    def find_resource(
        self,
        *,
        alias: Optional[str] = None,
        resource_id: Optional[str] = None,
        project_id: Optional[str] = None,
        service: Optional[str] = None,
    ) -> Optional[ResourceView]:
        """Find a visible resource by id or alias (aliases are labels, not identity)."""
        for r in self.list_resources(project_id, service)["resources"]:
            if (resource_id is None or r.get("resource_id") == resource_id) and (
                alias is None or r.get("alias") == alias
            ):
                return r
        return None

    def request_operation(
        self,
        resource_id: str,
        operation: str,
        parameters: Optional[Dict[str, Any]] = None,
        *,
        idempotency_key: Optional[str] = None,
        task_id: Optional[str] = None,
        raise_on_pending: bool = False,
        timeout: Optional[float] = None,
    ) -> OperationResponse:
        """``POST /v1/operations``. Returns the broker's ``OperationResponse``: done, or
        ``status == "approval_required"`` (a normal status). If ``idempotency_key`` is omitted a random
        one is generated — pass your own so that *your* retries are deduplicated too."""
        body = _core.build_operation_body(self._locale, resource_id, operation, parameters, idempotency_key, task_id)
        status, data = self._http.call(
            "POST", "/v1/operations", auth=self._auth, retry_safe=True, body=body, timeout=timeout
        )
        op = _core.check_operation(self._locale, status, data)
        if raise_on_pending and op["status"] == "approval_required":
            raise self._approval_required(op)
        return op

    def get_operation(self, operation_id: str, *, timeout: Optional[float] = None) -> OperationResponse:
        """``GET /v1/operations/{id}`` (own operations only; others are ``NOT_FOUND``)."""
        oid = _core.require_id(self._locale, operation_id, "operation_id")
        status, data = self._http.call(
            "GET", f"/v1/operations/{_core.path_segment(oid)}", auth=self._auth, retry_safe=True, timeout=timeout
        )
        return _core.check_operation(self._locale, status, data)

    def cancel_operation(self, operation_id: str, *, timeout: Optional[float] = None) -> CancelResponse:
        """``POST /v1/operations/{id}/cancel``. Check ``side_effects``: an external action may already have happened."""
        oid = _core.require_id(self._locale, operation_id, "operation_id")
        status, data = self._http.call(
            "POST",
            f"/v1/operations/{_core.path_segment(oid)}/cancel",
            auth=self._auth,
            retry_safe=True,
            body={},
            timeout=timeout,
        )
        _core.expect_shape(
            self._locale, status, isinstance(data.get("operation_id"), str) and isinstance(data.get("status"), str)
        )
        return data  # type: ignore[return-value]

    def wait_for_operation(
        self,
        operation_id: str,
        *,
        timeout: float = 120.0,
        interval: float = 1.0,
        max_interval: float = 10.0,
        backoff: float = 1.5,
        jitter: float = 0.2,
        cancel_event: Optional[threading.Event] = None,
        raise_on_pending: bool = False,
        raise_on_failure: bool = False,
        on_update: Optional[Callable[[OperationResponse], None]] = None,
    ) -> OperationResponse:
        """Poll until a terminal status, ``timeout`` seconds, or ``cancel_event``. Returns the latest
        status; ``approval_required`` at timeout is returned as-is (never treated as approval) unless
        ``raise_on_pending``."""
        oid = _core.require_id(self._locale, operation_id, "operation_id")
        path = f"/v1/operations/{_core.path_segment(oid)}"

        def fetch(remaining: float) -> OperationResponse:
            status, data = self._http.call(
                "GET", path, auth=self._auth, retry_safe=False, timeout=self._poll_timeout(remaining)
            )
            return _core.check_operation(self._locale, status, data)

        outcome = poll_sync(
            fetch,
            lambda op: is_terminal_operation_status(op.get("status")),
            timeout=timeout,
            backoff=resolve_backoff(interval, max_interval, backoff, jitter),
            cancel_event=cancel_event,
            on_update=on_update,
            locale=self._locale,
        )
        return self._finish_operation_wait(outcome.value, outcome.timed_out, raise_on_pending, raise_on_failure)

    def request_access(
        self,
        resource_id: str,
        operations: Sequence[str],
        *,
        scope: Optional[Dict[str, Any]] = None,
        limits: Optional[Dict[str, int]] = None,
        duration_seconds: Optional[int] = None,
        reason: Optional[str] = None,
        timeout: Optional[float] = None,
    ) -> AccessRequestResponse:
        """``POST /v1/access/requests`` — ask the user for a task-scoped grant. Not retried automatically
        (a resend could create a second approval prompt)."""
        body = _core.build_access_body(self._locale, resource_id, operations, scope, limits, duration_seconds, reason)
        status, data = self._http.call(
            "POST", "/v1/access/requests", auth=self._auth, retry_safe=False, body=body, timeout=timeout
        )
        return _core.check_access(self._locale, status, data)  # type: ignore[return-value]

    def get_access_request(self, approval_request_id: str, *, timeout: Optional[float] = None) -> AccessRequestResponse:
        """``GET /v1/access/requests/{id}``."""
        aid = _core.require_id(self._locale, approval_request_id, "approval_request_id")
        status, data = self._http.call(
            "GET", f"/v1/access/requests/{_core.path_segment(aid)}", auth=self._auth, retry_safe=True, timeout=timeout
        )
        return _core.check_access(self._locale, status, data)  # type: ignore[return-value]

    def wait_for_access_request(
        self,
        approval_request_id: str,
        *,
        timeout: float = 600.0,
        interval: float = 1.0,
        max_interval: float = 10.0,
        backoff: float = 1.5,
        jitter: float = 0.2,
        cancel_event: Optional[threading.Event] = None,
        raise_on_pending: bool = False,
        raise_on_failure: bool = False,
        on_update: Optional[Callable[[AccessRequestResponse], None]] = None,
    ) -> AccessRequestResponse:
        """Poll an access request until approved / denied / expired / cancelled, timeout or cancel."""
        aid = _core.require_id(self._locale, approval_request_id, "approval_request_id")
        path = f"/v1/access/requests/{_core.path_segment(aid)}"

        def fetch(remaining: float) -> AccessRequestResponse:
            status, data = self._http.call(
                "GET", path, auth=self._auth, retry_safe=False, timeout=self._poll_timeout(remaining)
            )
            return _core.check_access(self._locale, status, data)  # type: ignore[return-value]

        outcome = poll_sync(
            fetch,
            lambda r: is_terminal_access_status(r.get("status")),
            timeout=timeout,
            backoff=resolve_backoff(interval, max_interval, backoff, jitter),
            cancel_event=cancel_event,
            on_update=on_update,
            locale=self._locale,
        )
        return _finish_access_wait(self._locale, outcome.value, outcome.timed_out, raise_on_pending, raise_on_failure)

    def release_grant(self, grant_id: str, *, timeout: Optional[float] = None) -> ReleaseResponse:
        """``POST /v1/access/grants/{id}/release`` — end a grant early."""
        gid = _core.require_id(self._locale, grant_id, "grant_id")
        status, data = self._http.call(
            "POST",
            f"/v1/access/grants/{_core.path_segment(gid)}/release",
            auth=self._auth,
            retry_safe=True,
            body={},
            timeout=timeout,
        )
        _core.expect_shape(
            self._locale, status, isinstance(data.get("grant_id"), str) and isinstance(data.get("status"), str)
        )
        return data  # type: ignore[return-value]

    def handle_tool_call(self, name: str, args: Any, *, settle: float = 0.0) -> ToolCallResult:
        """Dispatch a model tool call (CONTRACTS §9 names). Never raises for broker errors."""
        from .tools import handle_tool_call

        return handle_tool_call(self, name, args, settle=settle)

    # ---- helpers -------------------------------------------------------------------------

    def _approval_required(self, op: OperationResponse) -> ApprovalRequiredError:
        return ApprovalRequiredError(
            "APPROVAL_REQUIRED", op.get("message") or msg(self._locale, "approval_required"), operation=op
        )

    def _finish_operation_wait(
        self, op: OperationResponse, timed_out: bool, raise_on_pending: bool, raise_on_failure: bool
    ) -> OperationResponse:
        return _finish_operation_wait(self._locale, op, timed_out, raise_on_pending, raise_on_failure)


def _finish_operation_wait(
    locale: str, op: OperationResponse, timed_out: bool, raise_on_pending: bool, raise_on_failure: bool
) -> OperationResponse:
    if timed_out:
        if raise_on_pending:
            if op.get("status") == "approval_required":
                raise ApprovalRequiredError(
                    "APPROVAL_REQUIRED", op.get("message") or msg(locale, "approval_required"), operation=op
                )
            raise AIPassTimeoutError("TIMEOUT", msg(locale, "wait_timeout", status=op.get("status")), operation=op)
        return op
    if raise_on_failure and op.get("status") != "succeeded":
        raise _core.error_for_operation(op, locale)
    return op


def _finish_access_wait(
    locale: str, value: AccessRequestResponse, timed_out: bool, raise_on_pending: bool, raise_on_failure: bool
) -> AccessRequestResponse:
    if timed_out:
        if raise_on_pending:
            raise ApprovalRequiredError(
                "APPROVAL_REQUIRED",
                msg(locale, "approval_required"),
                approval_request_id=value.get("approval_request_id"),
            )
        return value
    if raise_on_failure and value.get("status") != "approved":
        raise _core.access_failure(str(value.get("status")), locale)
    return value


#: Default backoff used by the wait helpers (seconds).
DEFAULT_BACKOFF = Backoff()

__all__: List[str] = ["DEFAULT_BACKOFF", "Client"]
