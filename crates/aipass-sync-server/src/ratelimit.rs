// SPDX-License-Identifier: Apache-2.0
//! Token-bucket rate limiter keyed by principal (or by client address before
//! authentication). Buckets idle for longer than the refill time are pruned, and the map
//! is bounded: when full, unknown keys share one overflow bucket (fail towards limiting,
//! never towards unlimited).

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

/// Limits of one limiter.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RateLimitConfig {
    /// Sustained requests per second.
    pub per_second: f64,
    /// Burst size.
    pub burst: f64,
}

impl RateLimitConfig {
    /// Construct.
    pub const fn new(per_second: f64, burst: f64) -> Self {
        Self { per_second, burst }
    }

    /// Effectively unlimited (tests, trusted in-process embedding).
    pub const fn unlimited() -> Self {
        Self {
            per_second: 1.0e9,
            burst: 1.0e9,
        }
    }
}

const MAX_KEYS: usize = 100_000;
const OVERFLOW_KEY: &str = "\u{0}overflow";

#[derive(Debug)]
struct Bucket {
    tokens: f64,
    last: Instant,
}

/// A keyed token-bucket limiter.
#[derive(Debug)]
pub struct RateLimiter {
    cfg: RateLimitConfig,
    buckets: Mutex<HashMap<String, Bucket>>,
}

impl RateLimiter {
    /// New limiter.
    pub fn new(cfg: RateLimitConfig) -> Self {
        Self {
            cfg,
            buckets: Mutex::new(HashMap::new()),
        }
    }

    /// Take one token for `key`; `false` = limited.
    pub fn check(&self, key: &str) -> bool {
        let now = Instant::now();
        let mut map = self.buckets.lock().unwrap_or_else(|p| p.into_inner());
        let k = if map.contains_key(key) || map.len() < MAX_KEYS {
            key
        } else {
            OVERFLOW_KEY
        };
        let b = map.entry(k.to_owned()).or_insert(Bucket {
            tokens: self.cfg.burst,
            last: now,
        });
        let elapsed = now.duration_since(b.last).as_secs_f64();
        b.tokens = (b.tokens + elapsed * self.cfg.per_second).min(self.cfg.burst);
        b.last = now;
        if b.tokens >= 1.0 {
            b.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Drop buckets that are full again (idle long enough to have refilled).
    pub fn prune(&self) {
        let now = Instant::now();
        let refill = if self.cfg.per_second > 0.0 {
            self.cfg.burst / self.cfg.per_second
        } else {
            f64::INFINITY
        };
        let mut map = self.buckets.lock().unwrap_or_else(|p| p.into_inner());
        map.retain(|_, b| now.duration_since(b.last).as_secs_f64() < refill);
    }

    /// Number of tracked keys.
    pub fn len(&self) -> usize {
        self.buckets.lock().map(|m| m.len()).unwrap_or(0)
    }

    /// True when no key is tracked.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn burst_then_limited() {
        let l = RateLimiter::new(RateLimitConfig::new(0.001, 3.0));
        assert!(l.check("a"));
        assert!(l.check("a"));
        assert!(l.check("a"));
        assert!(!l.check("a"));
        assert!(l.check("b"), "keys are independent");
    }
}
