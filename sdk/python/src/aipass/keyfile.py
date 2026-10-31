# SPDX-License-Identifier: Apache-2.0
"""Connection key files.

Written atomically with mode 0600 (parent directory created 0700); loading refuses group/world
readable files on POSIX. Format written by this SDK (identical to the TypeScript SDK)::

    {"format": "aipass-connection-key-1", "connection_id": "conn_…", "seed": "<b64u 32B>",
     "public_key": "<b64u 32B>", "broker_url": "…", "host_type": "sdk", "display_name": "…",
     "created_at": "…Z"}

The loader also accepts JSON using ``private_key`` / ``secret_key`` instead of ``seed`` (32-byte seed,
or 64-byte seed‖public key), or a plain-text file holding only the b64u seed whose file name is
``<conn_id>.key`` (the MCP bridge layout ``<AIPASS_HOME>/connections/<conn_id>.key``).
"""

from __future__ import annotations

import json
import os
import secrets
import stat
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, Optional, Tuple

from ._encoding import b64u_decode, b64u_encode
from ._messages import msg
from .errors import ConfigError, IntegrityFailedError
from .signing import ConnectionKey, SigningKey

KEY_FILE_FORMAT = "aipass-connection-key-1"


@dataclass
class LoadedKeyFile:
    key: ConnectionKey
    metadata: Dict[str, str] = field(default_factory=dict)


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def save_connection_key(
    path: str,
    key: ConnectionKey,
    *,
    broker_url: Optional[str] = None,
    host_type: Optional[str] = None,
    display_name: Optional[str] = None,
    overwrite: bool = False,
    locale: Optional[str] = None,
) -> str:
    """Persist a connection key (mode 0600); returns the path written."""
    path = os.path.abspath(os.path.expanduser(path))
    doc: Dict[str, str] = {
        "format": KEY_FILE_FORMAT,
        "connection_id": key.connection_id,
        "seed": b64u_encode(key.signing_key.export_seed()),
        "public_key": key.public_key,
        "created_at": _utc_now(),
    }
    if broker_url:
        doc["broker_url"] = broker_url
    if host_type:
        doc["host_type"] = host_type
    if display_name:
        doc["display_name"] = display_name
    payload = bytearray((json.dumps(doc, indent=2, ensure_ascii=False) + "\n").encode("utf-8"))
    doc.clear()

    parent = os.path.dirname(path)
    os.makedirs(parent, mode=0o700, exist_ok=True)
    tmp = f"{path}.tmp-{secrets.token_hex(6)}"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(tmp, flags, 0o600)
    try:
        os.write(fd, bytes(payload))
        os.fsync(fd)
    finally:
        os.close(fd)
        for i in range(len(payload)):
            payload[i] = 0
    try:
        os.chmod(tmp, 0o600)
        if overwrite:
            os.replace(tmp, path)
        else:
            try:
                # link() fails with EEXIST instead of silently replacing: atomic no-clobber publish.
                os.link(tmp, path)
            except FileExistsError:
                raise ConfigError("CONFIG_ERROR", msg(locale, "key_file_exists", path=path)) from None
            finally:
                os.unlink(tmp)
    except BaseException:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise
    return path


def _decode_material(value: str, locale: Optional[str]) -> Tuple[bytes, Optional[str]]:
    try:
        raw = b64u_decode(value)
    except ValueError:
        raise ConfigError("CONFIG_ERROR", msg(locale, "key_file_invalid", detail="key is not base64url")) from None
    if len(raw) == 32:
        return raw, None
    if len(raw) == 64:
        return raw[:32], b64u_encode(raw[32:])
    raise ConfigError("CONFIG_ERROR", msg(locale, "key_file_invalid", detail="key must be a 32-byte Ed25519 seed"))


def load_connection_key(
    path: str,
    *,
    allow_insecure_permissions: bool = False,
    connection_id: Optional[str] = None,
    locale: Optional[str] = None,
) -> LoadedKeyFile:
    """Load a connection key file (see module docs for accepted formats)."""
    path = os.path.expanduser(path)
    try:
        st = os.stat(path)
    except OSError:
        raise ConfigError("CONFIG_ERROR", msg(locale, "key_file_missing", path=path)) from None
    if sys.platform != "win32" and not allow_insecure_permissions and st.st_mode & 0o077:
        raise ConfigError(
            "CONFIG_ERROR",
            msg(locale, "key_file_perms", path=path, mode=oct(stat.S_IMODE(st.st_mode)).replace("0o", "0")),
        )
    with open(path, encoding="utf-8") as fh:
        text = fh.read().strip()
    material: Optional[str] = None
    declared_public: Optional[str] = None
    metadata: Dict[str, str] = {}
    if text.startswith("{"):
        try:
            doc = json.loads(text)
        except ValueError:
            raise ConfigError("CONFIG_ERROR", msg(locale, "key_file_invalid", detail="malformed JSON")) from None
        if not isinstance(doc, dict):
            raise ConfigError("CONFIG_ERROR", msg(locale, "key_file_invalid", detail="malformed JSON"))

        def pick(*names: str) -> Optional[str]:
            for n in names:
                v = doc.get(n)
                if isinstance(v, str) and v:
                    return v
            return None

        connection_id = connection_id or pick("connection_id", "kid", "id")
        material = pick("seed", "private_key", "secret_key", "ed25519_seed")
        declared_public = pick("public_key")
        for name in ("broker_url", "host_type", "display_name", "created_at"):
            value = pick(name)
            if value:
                metadata[name] = value
    else:
        material = text
    if not connection_id:
        stem = os.path.basename(path)
        for suffix in (".key", ".json"):
            if stem.endswith(suffix):
                stem = stem[: -len(suffix)]
        if stem.startswith("conn_"):
            connection_id = stem
    if not material:
        raise ConfigError("CONFIG_ERROR", msg(locale, "key_file_invalid", detail="missing seed"))
    if not connection_id:
        raise ConfigError("CONFIG_ERROR", msg(locale, "key_file_invalid", detail="missing connection_id"))
    seed, embedded_public = _decode_material(material, locale)
    signing_key = SigningKey.from_seed(seed)
    for expected in (declared_public, embedded_public):
        if expected is not None and expected.rstrip("=") != signing_key.public_key:
            raise IntegrityFailedError("INTEGRITY_FAILED", msg(locale, "key_mismatch"))
    try:
        key = ConnectionKey(connection_id, signing_key)
    except ValueError:
        raise ConfigError(
            "CONFIG_ERROR", msg(locale, "key_file_invalid", detail="connection_id must look like conn_<ulid>")
        ) from None
    return LoadedKeyFile(key=key, metadata=metadata)
