// SPDX-License-Identifier: Apache-2.0
//! Injectable wall clock (signature skew windows, relay TTLs). [`ManualClock`] lets tests
//! and simulations move time without sleeping.

use std::sync::Mutex;

use aipass_types::Timestamp;

/// Source of the current time (second precision).
pub trait Clock: Send + Sync {
    /// Now.
    fn now(&self) -> Timestamp;
    /// Now as unix seconds.
    fn unix(&self) -> i64 {
        self.now().timestamp()
    }
}

/// The system clock.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Timestamp {
        aipass_types::time::now()
    }
}

/// A clock that only moves when told to.
#[derive(Debug)]
pub struct ManualClock {
    now: Mutex<Timestamp>,
}

impl ManualClock {
    /// Start at `t`.
    pub fn new(t: Timestamp) -> Self {
        Self {
            now: Mutex::new(aipass_types::time::truncate(t)),
        }
    }

    /// Start at the current system time.
    pub fn starting_now() -> Self {
        Self::new(aipass_types::time::now())
    }

    /// Move forward by `secs`.
    pub fn advance(&self, secs: i64) {
        let mut g = self.now.lock().unwrap_or_else(|p| p.into_inner());
        *g = aipass_types::time::add_secs(&g, secs);
    }

    /// Set the time.
    pub fn set(&self, t: Timestamp) {
        *self.now.lock().unwrap_or_else(|p| p.into_inner()) = aipass_types::time::truncate(t);
    }
}

impl Clock for ManualClock {
    fn now(&self) -> Timestamp {
        *self.now.lock().unwrap_or_else(|p| p.into_inner())
    }
}
