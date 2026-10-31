// SPDX-License-Identifier: Apache-2.0
//! Time source used by the broker.
//!
//! Every timestamp the broker writes (approval windows, grant expiry, audit events) and the
//! `AIPass-Sig` skew check come from one [`Clock`], so tests can move time forward
//! deterministically ([`ManualClock`]) and prove, for example, that an expired approval is
//! never auto-approved (A10).

use std::sync::atomic::{AtomicI64, Ordering};

use aipass_types::Timestamp;
use aipass_types::time::{from_unix, truncate};

/// A source of "now" (second precision, UTC).
pub trait Clock: Send + Sync + 'static {
    /// Current time, truncated to whole seconds.
    fn now(&self) -> Timestamp;

    /// Current unix time in seconds.
    fn unix(&self) -> i64 {
        self.now().timestamp()
    }
}

/// The operating-system clock.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Timestamp {
        aipass_types::time::now()
    }
}

/// A clock that only moves when told to (tests, simulations).
#[derive(Debug)]
pub struct ManualClock {
    secs: AtomicI64,
}

impl ManualClock {
    /// Start at `start`.
    pub fn new(start: Timestamp) -> Self {
        Self {
            secs: AtomicI64::new(truncate(start).timestamp()),
        }
    }

    /// Start at unix second `secs`.
    pub fn at_unix(secs: i64) -> Self {
        Self {
            secs: AtomicI64::new(secs),
        }
    }

    /// Move forward (or backward, with a negative value) by `secs` seconds.
    pub fn advance(&self, secs: i64) {
        self.secs.fetch_add(secs, Ordering::SeqCst);
    }

    /// Jump to `t`.
    pub fn set(&self, t: Timestamp) {
        self.secs.store(truncate(t).timestamp(), Ordering::SeqCst);
    }
}

impl Clock for ManualClock {
    fn now(&self) -> Timestamp {
        from_unix(self.secs.load(Ordering::SeqCst)).unwrap_or_default()
    }

    fn unix(&self) -> i64 {
        self.secs.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manual_clock_moves_only_when_told() {
        let c = ManualClock::at_unix(1_793_318_400);
        assert_eq!(c.unix(), 1_793_318_400);
        c.advance(121);
        assert_eq!(c.unix(), 1_793_318_521);
        assert_eq!(
            aipass_types::time::format_rfc3339(&c.now()),
            "2026-10-30T00:02:01Z"
        );
    }
}
