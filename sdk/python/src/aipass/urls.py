# SPDX-License-Identifier: Apache-2.0
"""Broker endpoint parsing and resolution.

Accepted forms: ``http://host:port[/base]``, ``https://host:port[/base]``, ``unix:///abs/path.sock``
(also ``unix:/abs/path.sock``). Resolution when nothing is passed (same order as the MCP bridge,
CONTRACTS §9): ``AIPASS_BROKER_URL`` > ``<AIPASS_HOME>/broker.json`` > ``unix://<AIPASS_HOME>/run/broker.sock``;
``AIPASS_HOME`` defaults to ``~/.aipass``.
"""

from __future__ import annotations

import ipaddress
import json
import os
from dataclasses import dataclass
from typing import Mapping, Optional
from urllib.parse import unquote, urlsplit

from ._messages import msg
from .errors import ConfigError


@dataclass(frozen=True)
class BrokerEndpoint:
    kind: str  # "tcp" | "unix"
    #: Display form (never contains credentials).
    display: str
    #: Base URL handed to httpx (``http://localhost`` for unix sockets).
    base_url: str
    socket_path: Optional[str] = None
    scheme: Optional[str] = None
    hostname: Optional[str] = None
    port: Optional[int] = None
    base_path: str = ""

    @property
    def is_local(self) -> bool:
        return self.kind == "unix" or is_loopback_host(self.hostname or "")


def is_loopback_host(hostname: str) -> bool:
    """True for hosts where plaintext http stays on this machine."""
    h = hostname.strip("[]").lower()
    if h == "localhost" or h.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(h).is_loopback
    except ValueError:
        return False


def _bad(locale: Optional[str], detail: str) -> ConfigError:
    return ConfigError("CONFIG_ERROR", msg(locale, "bad_url", detail=detail))


def parse_broker_url(url: str, *, locale: Optional[str] = None, allow_insecure_http: bool = False) -> BrokerEndpoint:
    """Parse a broker URL into an endpoint."""
    if not isinstance(url, str) or not url.strip():
        raise _bad(locale, "empty")
    text = url.strip()
    if text.startswith("unix:"):
        path = text[len("unix:") :]
        if path.startswith("//"):
            path = path[2:]
        path = unquote(path)
        if not path.startswith("/"):
            raise _bad(locale, "unix socket path must be absolute (unix:///abs/path.sock)")
        return BrokerEndpoint(kind="unix", display=f"unix://{path}", base_url="http://localhost", socket_path=path)
    try:
        parts = urlsplit(text)
        port = parts.port
    except ValueError as exc:
        raise _bad(locale, "not a URL") from exc
    scheme = parts.scheme.lower()
    if scheme not in ("http", "https"):
        raise _bad(locale, f"unsupported scheme {scheme or '(none)'}:")
    if parts.username or parts.password:
        raise _bad(locale, "URLs must not embed credentials")
    if parts.query or parts.fragment:
        raise _bad(locale, "URLs must not contain a query or fragment")
    hostname = parts.hostname
    if not hostname:
        raise _bad(locale, "missing host")
    if scheme == "http" and not is_loopback_host(hostname) and not allow_insecure_http:
        raise ConfigError("CONFIG_ERROR", msg(locale, "insecure_http", host=hostname))
    port = port or (443 if scheme == "https" else 80)
    base_path = parts.path.rstrip("/")
    host_part = f"[{hostname}]" if ":" in hostname else hostname
    netloc = parts.netloc.split("@")[-1]
    base_url = f"{scheme}://{host_part}:{port}{base_path}"
    return BrokerEndpoint(
        kind="tcp",
        display=f"{scheme}://{netloc}{base_path}",
        base_url=base_url,
        scheme=scheme,
        hostname=hostname,
        port=port,
        base_path=base_path,
    )


def aipass_home(env: Optional[Mapping[str, str]] = None) -> str:
    """``AIPASS_HOME`` (default ``~/.aipass``)."""
    env = os.environ if env is None else env
    home = env.get("AIPASS_HOME", "")
    return home if home.strip() else os.path.join(os.path.expanduser("~"), ".aipass")


def resolve_broker_url(explicit: Optional[str] = None, env: Optional[Mapping[str, str]] = None) -> str:
    """explicit > ``AIPASS_BROKER_URL`` > ``<AIPASS_HOME>/broker.json`` (``{"broker_url"}`` or
    ``{"url"}``) > ``unix://<AIPASS_HOME>/run/broker.sock``."""
    if explicit and explicit.strip():
        return explicit.strip()
    env = os.environ if env is None else env
    from_env = env.get("AIPASS_BROKER_URL", "")
    if from_env.strip():
        return from_env.strip()
    home = aipass_home(env)
    broker_json = os.path.join(home, "broker.json")
    if os.path.isfile(broker_json):
        try:
            with open(broker_json, encoding="utf-8") as fh:
                doc = json.load(fh)
            value = doc.get("broker_url") or doc.get("url") if isinstance(doc, dict) else None
            if isinstance(value, str) and value.strip():
                return value.strip()
        except (OSError, ValueError):
            pass  # malformed broker.json → fall through to the default socket
    return "unix://" + os.path.abspath(os.path.join(home, "run", "broker.sock"))
