# SPDX-License-Identifier: Apache-2.0
"""httpx authenticators for connection-authenticated ("C") endpoints.

* :class:`SignatureAuth` — ``AIPass-Sig`` with a paired connection key. It signs
  ``request.url.raw_path`` (path + query exactly as httpx puts it on the request line) and the
  exact body bytes, with a fresh CSPRNG nonce on every send (including retries).
* :class:`BearerAuth` — ``aipc_…`` node-issued connection token or ``aipa_…`` cloud access token.

Credentials are never included in ``repr``/``str``.
"""

from __future__ import annotations

import re
from typing import Generator, Optional

import httpx

from ._messages import msg
from .errors import ConfigError
from .signing import ConnectionKey

_TOKEN_RE = re.compile(r"^(aipc|aipa)_[A-Za-z0-9_-]{16,512}$")


class SignatureAuth(httpx.Auth):
    requires_request_body = True
    kind = "connection_key"

    def __init__(self, key: ConnectionKey) -> None:
        self._key = key

    @property
    def principal_id(self) -> Optional[str]:
        return self._key.connection_id

    def auth_flow(self, request: httpx.Request) -> Generator[httpx.Request, httpx.Response, None]:
        path = request.url.raw_path.decode("ascii")
        signed = self._key.sign_request(request.method, path, request.content)
        request.headers["Authorization"] = signed.authorization
        yield request

    def __repr__(self) -> str:
        return f"SignatureAuth({self._key.connection_id})"


class BearerAuth(httpx.Auth):
    kind = "bearer"
    principal_id: Optional[str] = None

    def __init__(self, token: str, locale: Optional[str] = None) -> None:
        if not isinstance(token, str) or not _TOKEN_RE.match(token.strip()):
            raise ConfigError("CONFIG_ERROR", msg(locale, "bad_token"))
        self._token = token.strip()

    @property
    def token_kind(self) -> str:
        """Token family only — never the token."""
        return "aipc" if self._token.startswith("aipc_") else "aipa"

    def auth_flow(self, request: httpx.Request) -> Generator[httpx.Request, httpx.Response, None]:
        request.headers["Authorization"] = f"Bearer {self._token}"
        yield request

    def __repr__(self) -> str:
        return f"BearerAuth({self.token_kind}_[REDACTED])"
