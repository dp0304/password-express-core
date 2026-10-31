# SPDX-License-Identifier: Apache-2.0
"""Asynchronous client (``httpx.AsyncClient``). Same API as :class:`aipass.Client`, with ``await``.
Cancel the awaiting task (or set ``cancel_event``) to stop a wait."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any, Callable, Dict, Optional, Sequence

import httpx

from . import _core
from ._messages import msg
from .client import _ClientBase, _finish_access_wait, _finish_operation_wait
from .errors import ApprovalRequiredError
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
from .wait import poll_async, resolve_backoff

if TYPE_CHECKING:  # pragma: no cover
    from .tools import ToolCallResult


class AsyncClient(_ClientBase):
    """Async AI Pass client. Use ``async with`` or call :meth:`aclose`."""

    def __init__(
        self, broker_url: Optional[str] = None, *, transport: Optional[httpx.AsyncBaseTransport] = None, **kwargs: Any
    ) -> None:
        super().__init__(broker_url, **kwargs)
        self._http = _core.AsyncHTTP(self._config, transport)

    @classmethod
    def from_key_file(cls, key_file: str, **kwargs: Any) -> AsyncClient:
        return cls(key_file=key_file, **kwargs)

    async def __aenter__(self) -> AsyncClient:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self._http.aclose()

    async def health(self) -> HealthResponse:
        status, data = await self._http.call("GET", "/v1/health", auth=None, retry_safe=True)
        _core.expect_shape(self._locale, status, isinstance(data.get("status"), str))
        return data  # type: ignore[return-value]

    async def list_resources(
        self, project_id: Optional[str] = None, service: Optional[str] = None, *, timeout: Optional[float] = None
    ) -> ResourceList:
        status, data = await self._http.call(
            "GET",
            "/v1/resources",
            auth=self._auth,
            retry_safe=True,
            params={"project_id": project_id, "service": service},
            timeout=timeout,
        )
        _core.expect_shape(self._locale, status, isinstance(data.get("resources"), list))
        return data  # type: ignore[return-value]

    async def find_resource(
        self,
        *,
        alias: Optional[str] = None,
        resource_id: Optional[str] = None,
        project_id: Optional[str] = None,
        service: Optional[str] = None,
    ) -> Optional[ResourceView]:
        for r in (await self.list_resources(project_id, service))["resources"]:
            if (resource_id is None or r.get("resource_id") == resource_id) and (
                alias is None or r.get("alias") == alias
            ):
                return r
        return None

    async def request_operation(
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
        body = _core.build_operation_body(self._locale, resource_id, operation, parameters, idempotency_key, task_id)
        status, data = await self._http.call(
            "POST", "/v1/operations", auth=self._auth, retry_safe=True, body=body, timeout=timeout
        )
        op = _core.check_operation(self._locale, status, data)
        if raise_on_pending and op["status"] == "approval_required":
            raise ApprovalRequiredError(
                "APPROVAL_REQUIRED", op.get("message") or msg(self._locale, "approval_required"), operation=op
            )
        return op

    async def get_operation(self, operation_id: str, *, timeout: Optional[float] = None) -> OperationResponse:
        oid = _core.require_id(self._locale, operation_id, "operation_id")
        status, data = await self._http.call(
            "GET", f"/v1/operations/{_core.path_segment(oid)}", auth=self._auth, retry_safe=True, timeout=timeout
        )
        return _core.check_operation(self._locale, status, data)

    async def cancel_operation(self, operation_id: str, *, timeout: Optional[float] = None) -> CancelResponse:
        oid = _core.require_id(self._locale, operation_id, "operation_id")
        status, data = await self._http.call(
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

    async def wait_for_operation(
        self,
        operation_id: str,
        *,
        timeout: float = 120.0,
        interval: float = 1.0,
        max_interval: float = 10.0,
        backoff: float = 1.5,
        jitter: float = 0.2,
        cancel_event: Optional[asyncio.Event] = None,
        raise_on_pending: bool = False,
        raise_on_failure: bool = False,
        on_update: Optional[Callable[[OperationResponse], None]] = None,
    ) -> OperationResponse:
        oid = _core.require_id(self._locale, operation_id, "operation_id")
        path = f"/v1/operations/{_core.path_segment(oid)}"

        async def fetch(remaining: float) -> OperationResponse:
            status, data = await self._http.call(
                "GET", path, auth=self._auth, retry_safe=False, timeout=self._poll_timeout(remaining)
            )
            return _core.check_operation(self._locale, status, data)

        outcome = await poll_async(
            fetch,
            lambda op: is_terminal_operation_status(op.get("status")),
            timeout=timeout,
            backoff=resolve_backoff(interval, max_interval, backoff, jitter),
            cancel_event=cancel_event,
            on_update=on_update,
            locale=self._locale,
        )
        return _finish_operation_wait(
            self._locale, outcome.value, outcome.timed_out, raise_on_pending, raise_on_failure
        )

    async def request_access(
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
        body = _core.build_access_body(self._locale, resource_id, operations, scope, limits, duration_seconds, reason)
        status, data = await self._http.call(
            "POST", "/v1/access/requests", auth=self._auth, retry_safe=False, body=body, timeout=timeout
        )
        return _core.check_access(self._locale, status, data)  # type: ignore[return-value]

    async def get_access_request(
        self, approval_request_id: str, *, timeout: Optional[float] = None
    ) -> AccessRequestResponse:
        aid = _core.require_id(self._locale, approval_request_id, "approval_request_id")
        status, data = await self._http.call(
            "GET", f"/v1/access/requests/{_core.path_segment(aid)}", auth=self._auth, retry_safe=True, timeout=timeout
        )
        return _core.check_access(self._locale, status, data)  # type: ignore[return-value]

    async def wait_for_access_request(
        self,
        approval_request_id: str,
        *,
        timeout: float = 600.0,
        interval: float = 1.0,
        max_interval: float = 10.0,
        backoff: float = 1.5,
        jitter: float = 0.2,
        cancel_event: Optional[asyncio.Event] = None,
        raise_on_pending: bool = False,
        raise_on_failure: bool = False,
        on_update: Optional[Callable[[AccessRequestResponse], None]] = None,
    ) -> AccessRequestResponse:
        aid = _core.require_id(self._locale, approval_request_id, "approval_request_id")
        path = f"/v1/access/requests/{_core.path_segment(aid)}"

        async def fetch(remaining: float) -> AccessRequestResponse:
            status, data = await self._http.call(
                "GET", path, auth=self._auth, retry_safe=False, timeout=self._poll_timeout(remaining)
            )
            return _core.check_access(self._locale, status, data)  # type: ignore[return-value]

        outcome = await poll_async(
            fetch,
            lambda r: is_terminal_access_status(r.get("status")),
            timeout=timeout,
            backoff=resolve_backoff(interval, max_interval, backoff, jitter),
            cancel_event=cancel_event,
            on_update=on_update,
            locale=self._locale,
        )
        return _finish_access_wait(self._locale, outcome.value, outcome.timed_out, raise_on_pending, raise_on_failure)

    async def release_grant(self, grant_id: str, *, timeout: Optional[float] = None) -> ReleaseResponse:
        gid = _core.require_id(self._locale, grant_id, "grant_id")
        status, data = await self._http.call(
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

    async def handle_tool_call(self, name: str, args: Any, *, settle: float = 0.0) -> ToolCallResult:
        """Dispatch a model tool call (CONTRACTS §9 names). Never raises for broker errors."""
        from .tools import ahandle_tool_call

        return await ahandle_tool_call(self, name, args, settle=settle)


__all__ = ["AsyncClient"]
