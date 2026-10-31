# SPDX-License-Identifier: Apache-2.0
"""Polling with exponential backoff + jitter, deadline and cancellation.

A timeout ends the wait and reports the latest status — it is never an approval. If the final
attempt failed with a transient error, that error is raised rather than reporting a stale status.
"""

from __future__ import annotations

import asyncio
import math
import threading
import time
from dataclasses import dataclass
from typing import Awaitable, Callable, Generic, Optional, TypeVar

from ._encoding import random_unit
from ._messages import msg
from .errors import AbortedError, AIPassError

T = TypeVar("T")


@dataclass(frozen=True)
class Backoff:
    #: First delay between polls (seconds).
    interval: float = 1.0
    #: Upper bound for the delay (seconds).
    max_interval: float = 10.0
    #: Multiplier applied after each poll.
    backoff: float = 1.5
    #: Relative jitter in [0, 1]: each delay is scaled by a CSPRNG factor in [1 - j, 1 + j].
    jitter: float = 0.2


def _finite_or(value: Optional[float], fallback: float, minimum: float) -> float:
    if isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value) and value >= minimum:
        return float(value)
    return fallback


def resolve_backoff(
    interval: Optional[float] = None,
    max_interval: Optional[float] = None,
    backoff: Optional[float] = None,
    jitter: Optional[float] = None,
    *,
    defaults: Backoff = Backoff(),  # noqa: B008 - immutable dataclass
) -> Backoff:
    i = _finite_or(interval, defaults.interval, 0.001)
    m = max(i, _finite_or(max_interval, defaults.max_interval, 0.001))
    b = max(1.0, _finite_or(backoff, defaults.backoff, 1.0))
    j = min(1.0, max(0.0, _finite_or(jitter, defaults.jitter, 0.0)))
    return Backoff(interval=i, max_interval=m, backoff=b, jitter=j)


def backoff_delay(attempt: int, b: Backoff) -> float:
    """Delay before poll number ``attempt`` (0-based), before jitter."""
    return min(b.max_interval, b.interval * (b.backoff ** max(0, attempt)))


def jittered(base: float, jitter: float, rand: Callable[[], float] = random_unit) -> float:
    if jitter <= 0:
        return base
    return max(0.0, base * (1 - jitter + 2 * jitter * rand()))


def is_transient_poll_error(err: BaseException) -> bool:
    """Errors worth another poll before the deadline (the broker or network blipped)."""
    if not isinstance(err, AIPassError):
        return False
    if err.code in ("NETWORK_ERROR", "TIMEOUT", "RATE_LIMITED", "INTERNAL"):
        return True
    return err.code == "INVALID_RESPONSE" and (err.http_status or 0) >= 500


@dataclass
class PollOutcome(Generic[T]):
    value: T
    #: True when the deadline passed before a terminal state was reached.
    timed_out: bool
    polls: int


def _retry_after(err: BaseException) -> float:
    value = getattr(err, "retry_after_seconds", None)
    return float(value) if isinstance(value, (int, float)) and value > 0 else 0.0


def poll_sync(
    fetch: Callable[[float], T],
    is_terminal: Callable[[T], bool],
    *,
    timeout: float,
    backoff: Backoff,
    cancel_event: Optional[threading.Event] = None,
    on_update: Optional[Callable[[T], None]] = None,
    locale: Optional[str] = None,
    clock: Callable[[], float] = time.monotonic,
) -> PollOutcome[T]:
    """Blocking poll loop. ``cancel_event.set()`` aborts it (raises :class:`AbortedError`)."""
    deadline = clock() + max(0.0, timeout)
    attempt = 0
    have_value = False
    last: Optional[T] = None
    last_error: Optional[BaseException] = None
    while True:
        if cancel_event is not None and cancel_event.is_set():
            raise AbortedError("ABORTED", msg(locale, "aborted"))
        extra = 0.0
        try:
            value = fetch(max(0.0, deadline - clock()))
            last, have_value, last_error = value, True, None
            if on_update is not None:
                on_update(value)
            if is_terminal(value):
                return PollOutcome(value=value, timed_out=False, polls=attempt + 1)
        except AbortedError:
            raise
        except AIPassError as err:
            if not is_transient_poll_error(err):
                raise
            last_error = err
            extra = _retry_after(err)
        remaining = deadline - clock()
        if remaining <= 0:
            break
        delay = min(max(jittered(backoff_delay(attempt, backoff), backoff.jitter), extra), remaining)
        if cancel_event is not None:
            if cancel_event.wait(delay):
                raise AbortedError("ABORTED", msg(locale, "aborted"))
        else:
            time.sleep(delay)
        attempt += 1
    if last_error is not None or not have_value:
        assert last_error is not None
        raise last_error
    return PollOutcome(value=last, timed_out=True, polls=attempt + 1)  # type: ignore[arg-type]


async def poll_async(
    fetch: Callable[[float], Awaitable[T]],
    is_terminal: Callable[[T], bool],
    *,
    timeout: float,
    backoff: Backoff,
    cancel_event: Optional[asyncio.Event] = None,
    on_update: Optional[Callable[[T], None]] = None,
    locale: Optional[str] = None,
    clock: Callable[[], float] = time.monotonic,
) -> PollOutcome[T]:
    """Async poll loop. Cancel the task, or set ``cancel_event``, to abort."""
    deadline = clock() + max(0.0, timeout)
    attempt = 0
    have_value = False
    last: Optional[T] = None
    last_error: Optional[BaseException] = None
    while True:
        if cancel_event is not None and cancel_event.is_set():
            raise AbortedError("ABORTED", msg(locale, "aborted"))
        extra = 0.0
        try:
            value = await fetch(max(0.0, deadline - clock()))
            last, have_value, last_error = value, True, None
            if on_update is not None:
                on_update(value)
            if is_terminal(value):
                return PollOutcome(value=value, timed_out=False, polls=attempt + 1)
        except AbortedError:
            raise
        except AIPassError as err:
            if not is_transient_poll_error(err):
                raise
            last_error = err
            extra = _retry_after(err)
        remaining = deadline - clock()
        if remaining <= 0:
            break
        delay = min(max(jittered(backoff_delay(attempt, backoff), backoff.jitter), extra), remaining)
        if cancel_event is not None:
            try:
                await asyncio.wait_for(cancel_event.wait(), timeout=delay)
            except asyncio.TimeoutError:
                pass
            else:
                raise AbortedError("ABORTED", msg(locale, "aborted"))
        else:
            await asyncio.sleep(delay)
        attempt += 1
    if last_error is not None or not have_value:
        assert last_error is not None
        raise last_error
    return PollOutcome(value=last, timed_out=True, polls=attempt + 1)  # type: ignore[arg-type]
