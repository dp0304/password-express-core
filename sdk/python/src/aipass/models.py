# SPDX-License-Identifier: Apache-2.0
"""Wire types for the connection-authenticated ("C") broker endpoints (CONTRACTS §6.1, §6.3).

All responses are plain ``dict`` objects (JSON-serialisable) typed with ``TypedDict``; field names
are snake_case exactly as on the wire, and unknown extra fields are preserved.
"""

from __future__ import annotations

from typing import Any, Dict, FrozenSet, List, Literal, Optional, TypedDict

HostType = Literal["codex", "claude_code", "cursor", "chatgpt", "claude_connector", "sdk", "custom"]
ConnectionTransport = Literal["stdio", "http", "sdk", "remote_gateway"]
Locale = Literal["zh-CN", "en"]

#: Operation statuses as shown by the API (``awaiting_approval`` is shown as ``approval_required``).
OperationStatus = Literal[
    "received",
    "policy_checked",
    "approval_required",
    "authorized",
    "running",
    "succeeded",
    "failed",
    "unknown",
    "denied",
    "expired",
    "cancelled",
]

TERMINAL_OPERATION_STATUSES: FrozenSet[str] = frozenset(
    {"succeeded", "failed", "unknown", "denied", "expired", "cancelled"}
)
TERMINAL_ACCESS_STATUSES: FrozenSet[str] = frozenset({"approved", "denied", "expired", "cancelled"})


def is_terminal_operation_status(status: Optional[str]) -> bool:
    return isinstance(status, str) and status in TERMINAL_OPERATION_STATUSES


def is_terminal_access_status(status: Optional[str]) -> bool:
    return isinstance(status, str) and status in TERMINAL_ACCESS_STATUSES


class _ErrorBodyRequired(TypedDict):
    code: str
    message: str


class ErrorBody(_ErrorBodyRequired, total=False):
    details: Dict[str, Any]
    request_id: str


class OperationResult(TypedDict, total=False):
    data: Any
    rows: Optional[int]
    truncated: bool
    restricted: bool
    restricted_fields: List[str]


class _OperationResponseRequired(TypedDict):
    status: str
    operation_id: str


class OperationResponse(_OperationResponseRequired, total=False):
    approval_request_id: Optional[str]
    expires_in_seconds: Optional[int]
    message: Optional[str]
    result: Optional[OperationResult]
    error: Optional[ErrorBody]


class CancelResponse(TypedDict):
    operation_id: str
    status: str
    cancelled: bool
    side_effects: str
    message: str


class OperationSpecView(TypedDict, total=False):
    name: str
    description: str
    side_effect: str
    parameters_schema: Dict[str, Any]


class ResourceView(TypedDict, total=False):
    resource_id: str
    alias: str
    service: str
    project_id: str
    environment: str
    operations: List[OperationSpecView]
    status: str
    protection_level: str
    executor_status: str


class ResourceList(TypedDict):
    resources: List[ResourceView]


class GrantScope(TypedDict, total=False):
    operations: List[str]
    postgres: Dict[str, Dict[str, List[str]]]
    github: Dict[str, List[str]]
    http_api: Dict[str, List[str]]


class Limits(TypedDict, total=False):
    max_rows_per_operation: int
    max_rows_per_grant: int
    max_requests_per_grant: int
    max_result_bytes: int


class _AccessRequestResponseRequired(TypedDict):
    approval_request_id: str
    status: str


class AccessRequestResponse(_AccessRequestResponseRequired, total=False):
    grant_id: Optional[str]


class ReleaseResponse(TypedDict):
    grant_id: str
    status: str


class HealthResponse(TypedDict, total=False):
    status: str
    version: str
    executor_online: bool
    protection_level: str


class PairStartResponse(TypedDict):
    pairing_request_id: str
    connection_id: str
    pairing_code: str
    expires_at: str


class PairStatusResponse(TypedDict):
    status: str
    connection_id: str


__all__ = [
    "TERMINAL_ACCESS_STATUSES",
    "TERMINAL_OPERATION_STATUSES",
    "AccessRequestResponse",
    "CancelResponse",
    "ConnectionTransport",
    "ErrorBody",
    "GrantScope",
    "HealthResponse",
    "HostType",
    "Limits",
    "Locale",
    "OperationResponse",
    "OperationResult",
    "OperationSpecView",
    "OperationStatus",
    "PairStartResponse",
    "PairStatusResponse",
    "ReleaseResponse",
    "ResourceList",
    "ResourceView",
    "is_terminal_access_status",
    "is_terminal_operation_status",
]
