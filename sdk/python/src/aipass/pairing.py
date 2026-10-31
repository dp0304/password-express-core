# SPDX-License-Identifier: Apache-2.0
"""Connection pairing (CONTRACTS §6.3).

1. Generate an Ed25519 key from the OS CSPRNG (the seed only ever leaves this process into the
   0600 key file you choose).
2. ``POST /v1/connections/pair {host_type, display_name, transport, public_key}`` →
   ``{pairing_request_id, connection_id, pairing_code, expires_at}``.
3. Show the pairing code; the user confirms it on their phone / trusted client.
4. Poll ``GET /v1/connections/pair/{pairing_request_id}`` — signed with the pending key
   (``kid = connection_id``) — until ``approved | denied | expired``.

Nothing here can approve a connection: only the user's trusted device can.
"""

from __future__ import annotations

import asyncio
import inspect
import logging
import os
import threading
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Awaitable, Callable, Dict, Mapping, Optional, Tuple, Union

import httpx

from . import _core
from ._messages import msg, normalize_locale
from .async_client import AsyncClient
from .auth import SignatureAuth
from .client import Client
from .errors import ConfigError, InvalidRequestError, InvalidResponseError
from .keyfile import save_connection_key
from .models import PairStatusResponse
from .signing import ConnectionKey, SigningKey
from .urls import BrokerEndpoint, parse_broker_url, resolve_broker_url
from .wait import Backoff, poll_async, poll_sync, resolve_backoff

HOST_TYPES = ("codex", "claude_code", "cursor", "chatgpt", "claude_connector", "sdk", "custom")
_FINAL = ("approved", "denied", "expired")
_PAIR_BACKOFF = Backoff(interval=2.0, max_interval=5.0, backoff=1.5, jitter=0.2)


@dataclass
class PairingResult:
    #: ``approved`` | ``denied`` | ``expired`` | ``pending`` (local wait ended first).
    status: str
    #: True when the local wait ended before the broker reported a final status.
    timed_out: bool
    connection_id: str
    pairing_request_id: str
    pairing_code: str
    expires_at: str
    #: Present only when approved.
    connection_key: Optional[ConnectionKey] = None
    #: Where the key was saved (approved + ``key_path`` given).
    key_path: Optional[str] = None
    #: Client using the new key (approved only; ``Client`` or ``AsyncClient``).
    client: Any = None


def _endpoint(
    locale: str,
    broker_url: Optional[str],
    socket_path: Optional[str],
    env: Optional[Mapping[str, str]],
    allow_insecure_http: bool,
) -> BrokerEndpoint:
    if socket_path:
        return parse_broker_url(f"unix://{socket_path}", locale=locale)
    return parse_broker_url(
        resolve_broker_url(broker_url, os.environ if env is None else env),
        locale=locale,
        allow_insecure_http=allow_insecure_http,
    )


def _validate(locale: str, display_name: Any, host_type: str) -> str:
    name = display_name.strip() if isinstance(display_name, str) else ""
    if not name or len(name) > 100:
        raise InvalidRequestError(
            "INVALID_REQUEST", msg(locale, "invalid_argument", detail="display_name must be 1..100 characters")
        )
    if host_type not in HOST_TYPES:
        raise InvalidRequestError(
            "INVALID_REQUEST",
            msg(locale, "invalid_argument", detail=f"host_type must be one of {', '.join(HOST_TYPES)}"),
        )
    return name


def _parse_start(
    locale: str, status: int, data: Dict[str, Any], signing_key: SigningKey
) -> Tuple[Dict[str, str], ConnectionKey]:
    keys = ("pairing_request_id", "connection_id", "pairing_code", "expires_at")
    if not all(isinstance(data.get(k), str) for k in keys):
        raise InvalidResponseError(
            "INVALID_RESPONSE", msg(locale, "invalid_response", status=status), http_status=status
        )
    try:
        key = ConnectionKey(data["connection_id"], signing_key)
    except ValueError:
        raise InvalidResponseError(
            "INVALID_RESPONSE", msg(locale, "invalid_response", status=status), http_status=status
        ) from None
    return {k: data[k] for k in keys}, key


def _check_status(locale: str, status: int, data: Dict[str, Any], connection_id: str) -> PairStatusResponse:
    if not isinstance(data.get("status"), str):
        raise InvalidResponseError(
            "INVALID_RESPONSE", msg(locale, "invalid_response", status=status), http_status=status
        )
    if isinstance(data.get("connection_id"), str) and data["connection_id"] != connection_id:
        raise InvalidResponseError("INVALID_RESPONSE", msg(locale, "pairing_mismatch"), http_status=status)
    return data  # type: ignore[return-value]


def _default_wait(expires_at: str) -> float:
    try:
        expires = datetime.fromisoformat(expires_at.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return 600.0
    return min(15 * 60.0, max(0.0, expires - time.time() + 5.0))


def _result(info: Dict[str, str], key: ConnectionKey, value: PairStatusResponse, timed_out: bool) -> PairingResult:
    status = value["status"] if value["status"] in _FINAL else "pending"
    return PairingResult(
        status=status,
        timed_out=timed_out,
        connection_id=info["connection_id"],
        pairing_request_id=info["pairing_request_id"],
        pairing_code=info["pairing_code"],
        expires_at=info["expires_at"],
        connection_key=key if status == "approved" else None,
    )


class _SessionBase:
    def __init__(
        self, config: _core.CoreConfig, info: Dict[str, str], key: ConnectionKey, options: Dict[str, Any]
    ) -> None:
        self._config = config
        self.info: Dict[str, str] = dict(info)
        self.connection_key = key
        self._auth = SignatureAuth(key)
        self._options = options

    @property
    def pairing_code(self) -> str:
        return self.info["pairing_code"]

    @property
    def connection_id(self) -> str:
        return self.info["connection_id"]

    @property
    def expires_at(self) -> str:
        return self.info["expires_at"]

    def save_key(self, path: str, *, overwrite: bool = False) -> str:
        """Save the key (mode 0600). ``pair()`` does this for you after approval."""
        return save_connection_key(
            path,
            self.connection_key,
            broker_url=self._config.endpoint.display,
            host_type=self._options.get("host_type", "sdk"),
            display_name=self._options.get("display_name"),
            overwrite=overwrite,
            locale=self._config.locale,
        )

    def _client_kwargs(self, overrides: Dict[str, Any]) -> Dict[str, Any]:
        ep = self._config.endpoint
        kwargs: Dict[str, Any] = {
            "locale": self._config.locale,
            "timeout": self._config.timeout,
            "max_retries": self._config.max_retries,
            "ca_file": self._config.ca_file,
            "allow_insecure_http": self._options.get("allow_insecure_http", False),
            "logger": self._config.logger,
        }
        kwargs.update(overrides)
        if ep.kind == "unix":
            kwargs["socket_path"] = ep.socket_path
        else:
            kwargs["broker_url"] = ep.display
        kwargs["connection_key"] = self.connection_key
        return kwargs

    def __repr__(self) -> str:
        return f"{type(self).__name__}({self.connection_id}, code={self.pairing_code})"


class PairingSession(_SessionBase):
    """An in-progress (blocking) pairing."""

    def __init__(self, http: _core.SyncHTTP, info: Dict[str, str], key: ConnectionKey, options: Dict[str, Any]) -> None:
        super().__init__(http.config, info, key, options)
        self._http = http

    def poll(self) -> PairStatusResponse:
        """One status check."""
        status, data = self._http.call(
            "GET",
            f"/v1/connections/pair/{_core.path_segment(self.info['pairing_request_id'])}",
            auth=self._auth,
            retry_safe=True,
        )
        return _check_status(self._config.locale, status, data, self.connection_id)

    def wait(
        self,
        *,
        timeout: Optional[float] = None,
        interval: Optional[float] = None,
        max_interval: Optional[float] = None,
        backoff: Optional[float] = None,
        jitter: Optional[float] = None,
        cancel_event: Optional[threading.Event] = None,
        on_update: Optional[Callable[[PairStatusResponse], None]] = None,
    ) -> PairingResult:
        """Poll until approved / denied / expired, or the wait ends (default: until ``expires_at``)."""
        outcome = poll_sync(
            lambda _remaining: self.poll(),
            lambda s: s["status"] in _FINAL,
            timeout=_default_wait(self.expires_at) if timeout is None else timeout,
            backoff=resolve_backoff(interval, max_interval, backoff, jitter, defaults=_PAIR_BACKOFF),
            cancel_event=cancel_event,
            on_update=on_update,
            locale=self._config.locale,
        )
        return _result(self.info, self.connection_key, outcome.value, outcome.timed_out)

    def create_client(self, **overrides: Any) -> Client:
        """A client authenticated with this (approved) connection key."""
        transport = self._options.get("transport")
        if transport is not None:
            overrides.setdefault("transport", transport)
        return Client(**self._client_kwargs(overrides))

    def close(self) -> None:
        self._http.close()


class AsyncPairingSession(_SessionBase):
    """An in-progress (async) pairing."""

    def __init__(
        self, http: _core.AsyncHTTP, info: Dict[str, str], key: ConnectionKey, options: Dict[str, Any]
    ) -> None:
        super().__init__(http.config, info, key, options)
        self._http = http

    async def poll(self) -> PairStatusResponse:
        status, data = await self._http.call(
            "GET",
            f"/v1/connections/pair/{_core.path_segment(self.info['pairing_request_id'])}",
            auth=self._auth,
            retry_safe=True,
        )
        return _check_status(self._config.locale, status, data, self.connection_id)

    async def wait(
        self,
        *,
        timeout: Optional[float] = None,
        interval: Optional[float] = None,
        max_interval: Optional[float] = None,
        backoff: Optional[float] = None,
        jitter: Optional[float] = None,
        cancel_event: Optional[asyncio.Event] = None,
        on_update: Optional[Callable[[PairStatusResponse], None]] = None,
    ) -> PairingResult:
        async def fetch(_remaining: float) -> PairStatusResponse:
            return await self.poll()

        outcome = await poll_async(
            fetch,
            lambda s: s["status"] in _FINAL,
            timeout=_default_wait(self.expires_at) if timeout is None else timeout,
            backoff=resolve_backoff(interval, max_interval, backoff, jitter, defaults=_PAIR_BACKOFF),
            cancel_event=cancel_event,
            on_update=on_update,
            locale=self._config.locale,
        )
        return _result(self.info, self.connection_key, outcome.value, outcome.timed_out)

    def create_client(self, **overrides: Any) -> AsyncClient:
        transport = self._options.get("transport")
        if transport is not None:
            overrides.setdefault("transport", transport)
        return AsyncClient(**self._client_kwargs(overrides))

    async def aclose(self) -> None:
        await self._http.aclose()


def _config(
    locale: str,
    endpoint: BrokerEndpoint,
    timeout: float,
    max_retries: int,
    ca_file: Optional[str],
    user_agent: Optional[str],
    logger: Optional[logging.Logger],
) -> _core.CoreConfig:
    return _core.CoreConfig(
        endpoint=endpoint,
        locale=locale,
        timeout=float(timeout),
        max_retries=max(0, int(max_retries)),
        max_response_bytes=1024 * 1024,
        user_agent=user_agent,
        ca_file=ca_file,
        logger=logger or _core.DEFAULT_LOGGER,
    )


def start_pairing(
    display_name: str,
    *,
    broker_url: Optional[str] = None,
    socket_path: Optional[str] = None,
    host_type: str = "sdk",
    connection_transport: str = "sdk",
    locale: str = "zh-CN",
    timeout: float = 30.0,
    max_retries: int = 2,
    ca_file: Optional[str] = None,
    allow_insecure_http: bool = False,
    user_agent: Optional[str] = None,
    env: Optional[Mapping[str, str]] = None,
    logger: Optional[logging.Logger] = None,
    transport: Optional[httpx.BaseTransport] = None,
) -> PairingSession:
    """Start pairing: create a key and ask the broker for a pairing code."""
    loc = normalize_locale(locale)
    name = _validate(loc, display_name, host_type)
    config = _config(
        loc,
        _endpoint(loc, broker_url, socket_path, env, allow_insecure_http),
        timeout,
        max_retries,
        ca_file,
        user_agent,
        logger,
    )
    http = _core.SyncHTTP(config, transport)
    signing_key = SigningKey.generate()
    try:
        status, data = http.call(
            "POST",
            "/v1/connections/pair",
            auth=None,
            retry_safe=False,
            body={
                "host_type": host_type,
                "display_name": name,
                "transport": connection_transport,
                "public_key": signing_key.public_key,
            },
        )
        info, key = _parse_start(loc, status, data, signing_key)
    except BaseException:
        http.close()
        raise
    options = {
        "host_type": host_type,
        "display_name": name,
        "allow_insecure_http": allow_insecure_http,
        "transport": transport,
    }
    return PairingSession(http, info, key, options)


async def astart_pairing(
    display_name: str,
    *,
    broker_url: Optional[str] = None,
    socket_path: Optional[str] = None,
    host_type: str = "sdk",
    connection_transport: str = "sdk",
    locale: str = "zh-CN",
    timeout: float = 30.0,
    max_retries: int = 2,
    ca_file: Optional[str] = None,
    allow_insecure_http: bool = False,
    user_agent: Optional[str] = None,
    env: Optional[Mapping[str, str]] = None,
    logger: Optional[logging.Logger] = None,
    transport: Optional[httpx.AsyncBaseTransport] = None,
) -> AsyncPairingSession:
    """Async :func:`start_pairing`."""
    loc = normalize_locale(locale)
    name = _validate(loc, display_name, host_type)
    config = _config(
        loc,
        _endpoint(loc, broker_url, socket_path, env, allow_insecure_http),
        timeout,
        max_retries,
        ca_file,
        user_agent,
        logger,
    )
    http = _core.AsyncHTTP(config, transport)
    signing_key = SigningKey.generate()
    try:
        status, data = await http.call(
            "POST",
            "/v1/connections/pair",
            auth=None,
            retry_safe=False,
            body={
                "host_type": host_type,
                "display_name": name,
                "transport": connection_transport,
                "public_key": signing_key.public_key,
            },
        )
        info, key = _parse_start(loc, status, data, signing_key)
    except BaseException:
        await http.aclose()
        raise
    options = {
        "host_type": host_type,
        "display_name": name,
        "allow_insecure_http": allow_insecure_http,
        "transport": transport,
    }
    return AsyncPairingSession(http, info, key, options)


OnPairingCode = Callable[[Dict[str, str]], Union[Awaitable[None], None]]


def _check_key_path(locale: str, key_path: Optional[str]) -> None:
    if key_path is not None and (not isinstance(key_path, str) or not key_path.strip()):
        raise ConfigError("CONFIG_ERROR", msg(locale, "invalid_argument", detail="key_path must be a non-empty path"))


def pair(
    display_name: str,
    *,
    key_path: Optional[str] = None,
    overwrite: bool = False,
    on_pairing_code: Optional[Callable[[Dict[str, str]], None]] = None,
    wait_timeout: Optional[float] = None,
    interval: Optional[float] = None,
    max_interval: Optional[float] = None,
    backoff: Optional[float] = None,
    jitter: Optional[float] = None,
    cancel_event: Optional[threading.Event] = None,
    **start_kwargs: Any,
) -> PairingResult:
    """Full pairing flow: start, report the code via ``on_pairing_code``, wait for the user's
    decision on a trusted device, and — only if approved — save the key to ``key_path`` (0600).
    Check ``result.status == "approved"`` before using ``result.client``."""
    _check_key_path(normalize_locale(start_kwargs.get("locale")), key_path)
    session = start_pairing(display_name, **start_kwargs)
    try:
        if on_pairing_code is not None:
            on_pairing_code(dict(session.info))
        result = session.wait(
            timeout=wait_timeout,
            interval=interval,
            max_interval=max_interval,
            backoff=backoff,
            jitter=jitter,
            cancel_event=cancel_event,
        )
        if result.status == "approved":
            if key_path:
                result.key_path = session.save_key(key_path, overwrite=overwrite)
            result.client = session.create_client()
        return result
    finally:
        session.close()


async def apair(
    display_name: str,
    *,
    key_path: Optional[str] = None,
    overwrite: bool = False,
    on_pairing_code: Optional[OnPairingCode] = None,
    wait_timeout: Optional[float] = None,
    interval: Optional[float] = None,
    max_interval: Optional[float] = None,
    backoff: Optional[float] = None,
    jitter: Optional[float] = None,
    cancel_event: Optional[asyncio.Event] = None,
    **start_kwargs: Any,
) -> PairingResult:
    """Async :func:`pair`; ``result.client`` is an :class:`~aipass.AsyncClient`."""
    _check_key_path(normalize_locale(start_kwargs.get("locale")), key_path)
    session = await astart_pairing(display_name, **start_kwargs)
    try:
        if on_pairing_code is not None:
            maybe = on_pairing_code(dict(session.info))
            if inspect.isawaitable(maybe):
                await maybe
        result = await session.wait(
            timeout=wait_timeout,
            interval=interval,
            max_interval=max_interval,
            backoff=backoff,
            jitter=jitter,
            cancel_event=cancel_event,
        )
        if result.status == "approved":
            if key_path:
                result.key_path = session.save_key(key_path, overwrite=overwrite)
            result.client = session.create_client()
        return result
    finally:
        await session.aclose()


__all__ = [
    "HOST_TYPES",
    "AsyncPairingSession",
    "PairingResult",
    "PairingSession",
    "apair",
    "astart_pairing",
    "pair",
    "start_pairing",
]
