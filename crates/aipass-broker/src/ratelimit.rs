// SPDX-License-Identifier: Apache-2.0
//! Token-bucket limiter for public (`P`) endpoints, keyed by peer.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

const MAX_KEYS: usize = 10_000;

#[derive(Debug)]
pub(crate) struct RateLimiter {
    per_minute: f64,
    burst: f64,
    buckets: Mutex<HashMap<String, (f64, Instant)>>,
}

impl RateLimiter {
    pub(crate) fn new(per_minute: u32) -> Self {
        let per_minute = f64::from(per_minute.max(1));
        Self {
            per_minute,
            burst: per_minute.clamp(1.0, 60.0),
            buckets: Mutex::new(HashMap::new()),
        }
    }

    /// Take one token for `key`; false when the bucket is empty.
    pub(crate) fn check(&self, key: &str) -> bool {
        let now = Instant::now();
        let mut map = match self.buckets.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        if map.len() >= MAX_KEYS && !map.contains_key(key) {
            // prune buckets that are full again
            let burst = self.burst;
            let rate = self.per_minute / 60.0;
            map.retain(|_, (tokens, at)| {
                *tokens + now.duration_since(*at).as_secs_f64() * rate < burst
            });
            if map.len() >= MAX_KEYS {
                return false;
            }
        }
        let rate = self.per_minute / 60.0;
        let entry = map.entry(key.to_owned()).or_insert((self.burst, now));
        let elapsed = now.duration_since(entry.1).min(Duration::from_secs(3600));
        entry.0 = (entry.0 + elapsed.as_secs_f64() * rate).min(self.burst);
        entry.1 = now;
        if entry.0 >= 1.0 {
            entry.0 -= 1.0;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_empties() {
        let r = RateLimiter::new(3);
        assert!(r.check("a"));
        assert!(r.check("a"));
        assert!(r.check("a"));
        assert!(!r.check("a"));
        assert!(r.check("b"));
    }
}
