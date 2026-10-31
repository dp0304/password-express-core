# SPDX-License-Identifier: Apache-2.0
"""Encoding helpers: base64url without padding ("b64u", CONTRACTS §1.2), SHA-256, CSPRNG."""

from __future__ import annotations

import base64
import hashlib
import re
import secrets

_B64U_RE = re.compile(r"^[A-Za-z0-9_-]*$")


def b64u_encode(data: bytes) -> str:
    """Encode bytes as base64url without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64u_decode(text: str) -> bytes:
    """Decode base64url (padding tolerated, nothing else). Raises ``ValueError`` on bad input."""
    if not isinstance(text, str):
        raise ValueError("invalid base64url value")
    trimmed = text.strip().rstrip("=")
    if not _B64U_RE.match(trimmed) or len(trimmed) % 4 == 1:
        raise ValueError("invalid base64url value")
    return base64.urlsafe_b64decode(trimmed + "=" * (-len(trimmed) % 4))


def sha256_b64u(data: bytes) -> str:
    """b64u(SHA-256(data))."""
    return b64u_encode(hashlib.sha256(data).digest())


def random_b64u(n: int) -> str:
    """``n`` random bytes from the OS CSPRNG, b64u-encoded."""
    return b64u_encode(secrets.token_bytes(n))


_SYSRAND = secrets.SystemRandom()


def random_unit() -> float:
    """Uniform float in [0, 1) from the OS CSPRNG (used for retry/poll jitter)."""
    return _SYSRAND.random()
