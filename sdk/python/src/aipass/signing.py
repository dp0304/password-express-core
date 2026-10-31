# SPDX-License-Identifier: Apache-2.0
"""``AIPass-Sig`` request signing (CONTRACTS §1.6).

``Authorization: AIPass-Sig kid=<principal id>, ts=<unix seconds>, nonce=<b64u 16 bytes>, sig=<b64u 64 bytes>``

String to sign (UTF-8, joined by ``\\n``, no trailing newline): ``AIPASS-SIG-V1``, METHOD,
path+query exactly as sent, ts, nonce, b64u(SHA-256(raw body)).

Ed25519 comes from the ``cryptography`` package (OpenSSL). Private key material is held only in
the library's key object; ``repr``/``str`` never show it.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass
from typing import Dict, NoReturn, Optional, Union

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from ._encoding import b64u_decode, b64u_encode, random_b64u, sha256_b64u

SIGNATURE_SCHEME = "AIPass-Sig"
STRING_TO_SIGN_VERSION = "AIPASS-SIG-V1"
NONCE_BYTES = 16

_CONN_ID_RE = re.compile(r"^conn_[0-9a-z]{1,64}$")
BytesLike = Union[bytes, bytearray, memoryview]


def _to_bytes(value: Union[str, BytesLike]) -> bytes:
    return value.encode("utf-8") if isinstance(value, str) else bytes(value)


class SigningKey:
    """An Ed25519 signing key. ``repr`` shows only the public key."""

    __slots__ = ("_key", "public_key")

    def __init__(self, private_key: Ed25519PrivateKey) -> None:
        self._key = private_key
        raw_pub = private_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        #: Raw 32-byte public key, b64u.
        self.public_key: str = b64u_encode(raw_pub)

    @classmethod
    def generate(cls) -> SigningKey:
        """Generate a fresh key from the OS CSPRNG."""
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def from_seed(cls, seed: Union[str, BytesLike]) -> SigningKey:
        """Build from a 32-byte Ed25519 seed (raw bytes or b64u string)."""
        raw = b64u_decode(seed) if isinstance(seed, str) else bytes(seed)
        if len(raw) != 32:
            raise ValueError("Ed25519 seed must be exactly 32 bytes")
        return cls(Ed25519PrivateKey.from_private_bytes(raw))

    def sign(self, message: Union[str, BytesLike]) -> bytes:
        """Ed25519 signature (64 bytes)."""
        return self._key.sign(_to_bytes(message))

    def export_seed(self) -> bytes:
        """Raw 32-byte seed. Only used to persist a 0600 connection key file."""
        return self._key.private_bytes(
            serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
        )

    def __repr__(self) -> str:
        return f"SigningKey(ed25519, public_key={self.public_key!r})"

    __str__ = __repr__

    def __reduce__(self) -> NoReturn:
        raise TypeError("SigningKey cannot be pickled")


def verify_signature(public_key_b64u: str, message: Union[str, BytesLike], signature_b64u: str) -> bool:
    """Verify an Ed25519 signature against a raw b64u public key."""
    try:
        pub = b64u_decode(public_key_b64u)
        sig = b64u_decode(signature_b64u)
    except ValueError:
        return False
    if len(pub) != 32 or len(sig) != 64:
        return False
    try:
        Ed25519PublicKey.from_public_bytes(pub).verify(sig, _to_bytes(message))
    except InvalidSignature:
        return False
    return True


@dataclass(frozen=True)
class SignedRequest:
    authorization: str
    kid: str
    ts: int
    nonce: str
    signature: str
    body_sha256: str
    string_to_sign: str


def build_string_to_sign(method: str, path: str, ts: int, nonce: str, body_sha256: str) -> str:
    """Canonical string to sign (CONTRACTS §1.6)."""
    if isinstance(ts, bool) or not isinstance(ts, int) or ts < 0:
        raise ValueError("ts must be a non-negative integer (unix seconds)")
    if not path.startswith("/"):
        raise ValueError("path must start with '/'")
    if any(c in path or c in nonce for c in "\r\n"):
        raise ValueError("path/nonce must not contain newlines")
    return "\n".join([STRING_TO_SIGN_VERSION, method.upper(), path, str(ts), nonce, body_sha256])


def format_authorization(kid: str, ts: int, nonce: str, sig: str) -> str:
    return f"{SIGNATURE_SCHEME} kid={kid}, ts={ts}, nonce={nonce}, sig={sig}"


def parse_authorization(header: Optional[str]) -> Optional[Dict[str, Union[str, int]]]:
    """Parse an ``AIPass-Sig`` header; ``None`` if it is not one. Useful for servers and tests."""
    if not header or not header.startswith(SIGNATURE_SCHEME + " "):
        return None
    fields: Dict[str, str] = {}
    for part in header[len(SIGNATURE_SCHEME) + 1 :].split(","):
        name, sep, value = part.partition("=")
        name = name.strip()
        if not sep or not name or name in fields:
            return None
        fields[name] = value.strip()
    kid, ts, nonce, sig = (fields.get(k) for k in ("kid", "ts", "nonce", "sig"))
    if not kid or not ts or not nonce or not sig or not re.fullmatch(r"\d{1,15}", ts):
        return None
    return {"kid": kid, "ts": int(ts), "nonce": nonce, "sig": sig}


def sign_request(
    kid: str,
    key: SigningKey,
    method: str,
    path: str,
    body: Union[str, BytesLike, None] = None,
    *,
    ts: Optional[int] = None,
    nonce: Optional[str] = None,
) -> SignedRequest:
    """Sign one request. ``nonce`` defaults to 16 fresh CSPRNG bytes — never reuse one."""
    ts = int(time.time()) if ts is None else ts
    nonce = random_b64u(NONCE_BYTES) if nonce is None else nonce
    body_sha256 = sha256_b64u(b"" if body is None else _to_bytes(body))
    sts = build_string_to_sign(method, path, ts, nonce, body_sha256)
    signature = b64u_encode(key.sign(sts))
    return SignedRequest(
        authorization=format_authorization(kid, ts, nonce, signature),
        kid=kid,
        ts=ts,
        nonce=nonce,
        signature=signature,
        body_sha256=body_sha256,
        string_to_sign=sts,
    )


class ConnectionKey:
    """A paired app connection: ``conn_…`` id plus its Ed25519 key."""

    __slots__ = ("connection_id", "signing_key")

    def __init__(self, connection_id: str, signing_key: SigningKey) -> None:
        if not isinstance(connection_id, str) or not _CONN_ID_RE.match(connection_id):
            raise ValueError("connection id must look like conn_<ulid>")
        self.connection_id = connection_id
        self.signing_key = signing_key

    @classmethod
    def from_seed(cls, connection_id: str, seed: Union[str, BytesLike]) -> ConnectionKey:
        return cls(connection_id, SigningKey.from_seed(seed))

    @property
    def public_key(self) -> str:
        return self.signing_key.public_key

    def sign_request(
        self,
        method: str,
        path: str,
        body: Union[str, BytesLike, None] = None,
        *,
        ts: Optional[int] = None,
        nonce: Optional[str] = None,
    ) -> SignedRequest:
        return sign_request(self.connection_id, self.signing_key, method, path, body, ts=ts, nonce=nonce)

    def __repr__(self) -> str:
        return f"ConnectionKey({self.connection_id!r}, public_key={self.public_key!r})"

    __str__ = __repr__

    def __reduce__(self) -> NoReturn:
        raise TypeError("ConnectionKey cannot be pickled")
