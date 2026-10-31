# SPDX-License-Identifier: Apache-2.0
"""Typed errors.

Every broker error body is ``{"error":{"code","message","details","request_id"}}`` (CONTRACTS §1.5);
each code maps to a subclass of :class:`AIPassError`. Errors never carry request headers, bodies
or credentials.
"""

from __future__ import annotations

import email.utils
import json
import time
from typing import Any, Dict, Mapping, Optional, Tuple, Type

from .models import OperationResponse

#: Error codes defined by CONTRACTS §1.5.
ERROR_CODES: Tuple[str, ...] = (
    "IDENTITY_UNVERIFIED",
    "UNAUTHENTICATED",
    "FORBIDDEN",
    "CONNECTION_PAUSED",
    "APPROVAL_REQUIRED",
    "APPROVAL_DENIED",
    "APPROVAL_EXPIRED",
    "GRANT_EXPIRED",
    "GRANT_REVOKED",
    "BUDGET_EXHAUSTED",
    "SCOPE_DENIED",
    "EXECUTOR_OFFLINE",
    "CONTROL_CHANNEL_LOST",
    "SECRET_UNAVAILABLE",
    "SYNC_CONFLICT",
    "PRECONDITION_FAILED",
    "ROLLBACK_DETECTED",
    "INTEGRITY_FAILED",
    "INTERACTIVE_AUTH_REQUIRED",
    "RESULT_RESTRICTED",
    "UPSTREAM_OUTCOME_UNKNOWN",
    "UPSTREAM_ERROR",
    "IDEMPOTENCY_CONFLICT",
    "RATE_LIMITED",
    "NOT_FOUND",
    "INVALID_REQUEST",
    "NOT_SUPPORTED",
    "PAYMENT_REQUIRED",
    "QUOTA_EXCEEDED",
    "INTERNAL",
)

#: Codes raised locally by the SDK (never sent by the broker).
SDK_ERROR_CODES: Tuple[str, ...] = (
    "NETWORK_ERROR",
    "TIMEOUT",
    "ABORTED",
    "INVALID_RESPONSE",
    "CONFIG_ERROR",
    "CANCELLED",
)


class AIPassError(Exception):
    """Base class for every error raised by the SDK."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        http_status: Optional[int] = None,
        request_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message)
        #: Stable error code (CONTRACTS §1.5, or an SDK-local code).
        self.code = code
        self.message = message
        #: HTTP status of the broker response, when there was one.
        self.http_status = http_status
        #: Broker request id (``req_…``) — quote it in bug reports.
        self.request_id = request_id
        #: Structured details from the broker (never secrets).
        self.details: Dict[str, Any] = dict(details or {})

    def to_dict(self) -> Dict[str, Any]:
        """JSON-safe representation."""
        out: Dict[str, Any] = {"code": self.code, "message": self.message}
        if self.http_status is not None:
            out["http_status"] = self.http_status
        if self.request_id is not None:
            out["request_id"] = self.request_id
        if self.details:
            out["details"] = self.details
        return out

    def __str__(self) -> str:
        rid = f" (request_id={self.request_id})" if self.request_id else ""
        return f"[{self.code}] {self.message}{rid}"

    def __repr__(self) -> str:
        return f"{type(self).__name__}(code={self.code!r}, message={self.message!r}, http_status={self.http_status!r}, request_id={self.request_id!r})"


# ---- broker error codes -----------------------------------------------------------------


class IdentityUnverifiedError(AIPassError):
    pass


class UnauthenticatedError(AIPassError):
    pass


class ForbiddenError(AIPassError):
    pass


class ConnectionPausedError(AIPassError):
    pass


class ApprovalRequiredError(AIPassError):
    """Raised only when the caller opted in (``raise_on_pending``); the API reports
    ``approval_required`` as a normal status."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        operation: Optional[OperationResponse] = None,
        approval_request_id: Optional[str] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(code, message, **kwargs)
        self.operation = operation
        self.operation_id = operation.get("operation_id") if operation else None
        self.approval_request_id = approval_request_id or (operation.get("approval_request_id") if operation else None)


class ApprovalDeniedError(AIPassError):
    pass


class ApprovalExpiredError(AIPassError):
    pass


class GrantExpiredError(AIPassError):
    pass


class GrantRevokedError(AIPassError):
    pass


class BudgetExhaustedError(AIPassError):
    pass


class ScopeDeniedError(AIPassError):
    pass


class ExecutorOfflineError(AIPassError):
    pass


class ControlChannelLostError(AIPassError):
    pass


class SecretUnavailableError(AIPassError):
    pass


class SyncConflictError(AIPassError):
    pass


class PreconditionFailedError(AIPassError):
    pass


class RollbackDetectedError(AIPassError):
    pass


class IntegrityFailedError(AIPassError):
    pass


class InteractiveAuthRequiredError(AIPassError):
    """Upstream needs re-login / OAuth re-consent — handle it in the AI Pass app, never by asking
    for secrets in chat."""


class ResultRestrictedError(AIPassError):
    pass


class UpstreamOutcomeUnknownError(AIPassError):
    """The external service may have executed the action. Verify before retrying."""


class UpstreamError(AIPassError):
    pass


class IdempotencyConflictError(AIPassError):
    pass


class RateLimitedError(AIPassError):
    def __init__(self, code: str, message: str, *, retry_after_seconds: Optional[float] = None, **kwargs: Any) -> None:
        super().__init__(code, message, **kwargs)
        #: Parsed ``Retry-After`` header (seconds), when present.
        self.retry_after_seconds = retry_after_seconds


class NotFoundError(AIPassError):
    pass


class InvalidRequestError(AIPassError):
    pass


class NotSupportedError(AIPassError):
    pass


class PaymentRequiredError(AIPassError):
    pass


class QuotaExceededError(AIPassError):
    pass


class InternalError(AIPassError):
    pass


# ---- SDK-local codes ---------------------------------------------------------------------


class NetworkError(AIPassError):
    """The broker could not be reached (connection refused, socket missing, TLS failure, reset…)."""


class AIPassTimeoutError(AIPassError):
    """A request or a wait timed out. A timeout is never an approval."""

    def __init__(
        self, code: str, message: str, *, operation: Optional[OperationResponse] = None, **kwargs: Any
    ) -> None:
        super().__init__(code, message, **kwargs)
        #: Latest known operation state (wait timeouts only).
        self.operation = operation


class AbortedError(AIPassError):
    pass


class InvalidResponseError(AIPassError):
    pass


class ConfigError(AIPassError):
    pass


class OperationCancelledError(AIPassError):
    pass


_CLASS_BY_CODE: Dict[str, Type[AIPassError]] = {
    "IDENTITY_UNVERIFIED": IdentityUnverifiedError,
    "UNAUTHENTICATED": UnauthenticatedError,
    "FORBIDDEN": ForbiddenError,
    "CONNECTION_PAUSED": ConnectionPausedError,
    "APPROVAL_REQUIRED": ApprovalRequiredError,
    "APPROVAL_DENIED": ApprovalDeniedError,
    "APPROVAL_EXPIRED": ApprovalExpiredError,
    "GRANT_EXPIRED": GrantExpiredError,
    "GRANT_REVOKED": GrantRevokedError,
    "BUDGET_EXHAUSTED": BudgetExhaustedError,
    "SCOPE_DENIED": ScopeDeniedError,
    "EXECUTOR_OFFLINE": ExecutorOfflineError,
    "CONTROL_CHANNEL_LOST": ControlChannelLostError,
    "SECRET_UNAVAILABLE": SecretUnavailableError,
    "SYNC_CONFLICT": SyncConflictError,
    "PRECONDITION_FAILED": PreconditionFailedError,
    "ROLLBACK_DETECTED": RollbackDetectedError,
    "INTEGRITY_FAILED": IntegrityFailedError,
    "INTERACTIVE_AUTH_REQUIRED": InteractiveAuthRequiredError,
    "RESULT_RESTRICTED": ResultRestrictedError,
    "UPSTREAM_OUTCOME_UNKNOWN": UpstreamOutcomeUnknownError,
    "UPSTREAM_ERROR": UpstreamError,
    "IDEMPOTENCY_CONFLICT": IdempotencyConflictError,
    "RATE_LIMITED": RateLimitedError,
    "NOT_FOUND": NotFoundError,
    "INVALID_REQUEST": InvalidRequestError,
    "NOT_SUPPORTED": NotSupportedError,
    "PAYMENT_REQUIRED": PaymentRequiredError,
    "QUOTA_EXCEEDED": QuotaExceededError,
    "INTERNAL": InternalError,
    "NETWORK_ERROR": NetworkError,
    "TIMEOUT": AIPassTimeoutError,
    "ABORTED": AbortedError,
    "INVALID_RESPONSE": InvalidResponseError,
    "CONFIG_ERROR": ConfigError,
    "CANCELLED": OperationCancelledError,
}


def error_class_for_code(code: str) -> Type[AIPassError]:
    """The subclass used for ``code`` (``AIPassError`` for codes unknown to this SDK version)."""
    return _CLASS_BY_CODE.get(code, AIPassError)


def error_from_code(code: str, message: str, **kwargs: Any) -> AIPassError:
    """Construct the typed error for ``code``. Subclass-specific keyword arguments
    (``retry_after_seconds``, ``operation``) are dropped for classes that do not take them."""
    cls = error_class_for_code(code)
    if cls is not RateLimitedError:
        kwargs.pop("retry_after_seconds", None)
    if cls not in (ApprovalRequiredError, AIPassTimeoutError):
        kwargs.pop("operation", None)
    return cls(code, message, **kwargs)


_FALLBACK_CODE_BY_STATUS = {
    400: "INVALID_REQUEST",
    401: "IDENTITY_UNVERIFIED",
    402: "PAYMENT_REQUIRED",
    403: "FORBIDDEN",
    404: "NOT_FOUND",
    412: "PRECONDITION_FAILED",
    429: "RATE_LIMITED",
    500: "INTERNAL",
    501: "NOT_SUPPORTED",
}


def _parse_retry_after(value: Optional[str]) -> Optional[float]:
    if not value:
        return None
    value = value.strip()
    if value.isdigit():
        return float(value)
    try:
        parsed = email.utils.parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
    if parsed is None:  # pragma: no cover - py<3.10 returns None on failure
        return None
    return max(0.0, parsed.timestamp() - time.time())


def error_from_response(status: int, body: bytes, headers: Mapping[str, str], fallback_message: str) -> AIPassError:
    """Map a non-2xx broker response to a typed error. If the body is not the CONTRACTS §1.5
    envelope, the HTTP status decides the code and the body is NOT echoed."""
    request_id_header = headers.get("x-request-id")
    retry_after = _parse_retry_after(headers.get("retry-after"))
    envelope: Any = None
    try:
        envelope = json.loads(body.decode("utf-8")) if body else None
    except (UnicodeDecodeError, ValueError):
        envelope = None
    err = envelope.get("error") if isinstance(envelope, dict) else None
    if isinstance(err, dict) and isinstance(err.get("code"), str):
        message = err.get("message")
        details = err.get("details")
        rid = err.get("request_id")
        return error_from_code(
            err["code"],
            message if isinstance(message, str) and message else fallback_message,
            http_status=status,
            request_id=rid if isinstance(rid, str) else request_id_header,
            details=details if isinstance(details, dict) else None,
            retry_after_seconds=retry_after,
        )
    return error_from_code(
        _FALLBACK_CODE_BY_STATUS.get(status, "INVALID_RESPONSE"),
        fallback_message,
        http_status=status,
        request_id=request_id_header,
        retry_after_seconds=retry_after,
    )


__all__ = [
    "ERROR_CODES",
    "SDK_ERROR_CODES",
    "AIPassError",
    "AIPassTimeoutError",
    "AbortedError",
    "ApprovalDeniedError",
    "ApprovalExpiredError",
    "ApprovalRequiredError",
    "BudgetExhaustedError",
    "ConfigError",
    "ConnectionPausedError",
    "ControlChannelLostError",
    "ExecutorOfflineError",
    "ForbiddenError",
    "GrantExpiredError",
    "GrantRevokedError",
    "IdempotencyConflictError",
    "IdentityUnverifiedError",
    "IntegrityFailedError",
    "InteractiveAuthRequiredError",
    "InternalError",
    "InvalidRequestError",
    "InvalidResponseError",
    "NetworkError",
    "NotFoundError",
    "NotSupportedError",
    "OperationCancelledError",
    "PaymentRequiredError",
    "PreconditionFailedError",
    "QuotaExceededError",
    "RateLimitedError",
    "ResultRestrictedError",
    "RollbackDetectedError",
    "ScopeDeniedError",
    "SecretUnavailableError",
    "SyncConflictError",
    "UnauthenticatedError",
    "UpstreamError",
    "UpstreamOutcomeUnknownError",
    "error_class_for_code",
    "error_from_code",
    "error_from_response",
]
