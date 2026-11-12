//! Small in-memory sliding-window rate limiter used for login, registration and
//! password-verification throttling. It is per-process; per-account lockout in the
//! database (see `users.failed_login_count`) is what protects a multi-replica deployment.
use std::{
    collections::{HashMap, VecDeque},
    sync::Mutex,
    time::{Duration, Instant},
};

#[derive(Default)]
pub struct RateLimiter {
    hits: Mutex<HashMap<String, VecDeque<Instant>>>,
}

impl RateLimiter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an attempt for `key`. `Err(retry_after_secs)` if over `max` within `window`.
    pub fn hit(&self, key: &str, max: usize, window: Duration) -> Result<(), u64> {
        self.hit_at(key, max, window, Instant::now())
    }

    fn hit_at(&self, key: &str, max: usize, window: Duration, now: Instant) -> Result<(), u64> {
        let mut map = self.hits.lock().unwrap_or_else(|e| e.into_inner());

        // Bound memory: drop idle keys once the table gets large.
        if map.len() > 10_000 {
            map.retain(|_, q| q.back().is_some_and(|t| now.duration_since(*t) < window));
        }

        let q = map.entry(key.to_string()).or_default();
        while q.front().is_some_and(|t| now.duration_since(*t) >= window) {
            q.pop_front();
        }
        if q.len() >= max {
            let oldest = *q.front().expect("non-empty when len >= max >= 1");
            let wait = window.saturating_sub(now.duration_since(oldest));
            return Err(wait.as_secs().max(1));
        }
        q.push_back(now);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_after_max_and_recovers() {
        let l = RateLimiter::new();
        let w = Duration::from_secs(60);
        let t0 = Instant::now();
        for _ in 0..3 {
            assert!(l.hit_at("k", 3, w, t0).is_ok());
        }
        let retry = l.hit_at("k", 3, w, t0).unwrap_err();
        assert!((1..=60).contains(&retry));
        assert!(l.hit_at("k", 3, w, t0 + Duration::from_secs(61)).is_ok());
    }

    #[test]
    fn keys_are_independent() {
        let l = RateLimiter::new();
        let w = Duration::from_secs(60);
        assert!(l.hit("a", 1, w).is_ok());
        assert!(l.hit("a", 1, w).is_err());
        assert!(l.hit("b", 1, w).is_ok());
    }
}
