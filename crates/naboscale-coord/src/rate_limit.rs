//! Per-IP rate limiting for the coord server.
//!
//! Sliding-window counter: for each (peer IP, bucket name) we keep a list
//! of timestamps within the last `window`. Each request pops timestamps
//! older than `window` then checks whether the remaining count is below
//! the limit. Cheap; accurate; no external dep.
//!
//! Buckets (limits / window):
//!   - `register`:    5 req / 60s — registration is heavy (DB write + IP
//!     allocation) and should be a once-per-identity operation.
//!   - `heartbeat`:  30 req / 60s — normal mesh clients heartbeat every
//!     20 s, so 30/min allows ~3 nodes per IP without throttling.
//!   - `token`:      10 req / 60s — refresh / de-register are infrequent.
//!   - `default`:   120 req / 60s — generic safety net for everything else.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy)]
pub struct Limit {
    pub max_requests: usize,
    pub window: Duration,
}

#[derive(Debug, Clone, Copy)]
pub enum Bucket {
    Register,
    Heartbeat,
    Token,
    Default,
}

impl Bucket {
    pub fn limit(self) -> Limit {
        match self {
            Bucket::Register => Limit {
                max_requests: 5,
                window: Duration::from_secs(60),
            },
            Bucket::Heartbeat => Limit {
                max_requests: 30,
                window: Duration::from_secs(60),
            },
            Bucket::Token => Limit {
                max_requests: 10,
                window: Duration::from_secs(60),
            },
            Bucket::Default => Limit {
                max_requests: 120,
                window: Duration::from_secs(60),
            },
        }
    }
}

#[derive(Default)]
struct BucketState {
    /// Sliding window of request timestamps.
    timestamps: VecDeque<Instant>,
}

pub struct RateLimiter {
    /// (peer_ip, bucket_name) → sliding-window state.
    state: Mutex<HashMap<(IpAddr, &'static str), BucketState>>,
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self {
            state: Mutex::new(HashMap::new()),
        }
    }
}

impl RateLimiter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Try to admit a single request from `peer` into `bucket`. Returns
    /// `Ok(())` if admitted, `Err(retry_after)` if the bucket is full.
    pub fn check(&self, peer: IpAddr, bucket: Bucket) -> Result<(), Duration> {
        let limit = bucket.limit();
        let name: &'static str = match bucket {
            Bucket::Register => "register",
            Bucket::Heartbeat => "heartbeat",
            Bucket::Token => "token",
            Bucket::Default => "default",
        };
        let now = Instant::now();
        let mut map = self.state.lock().expect("rate-limiter poisoned");
        let entry = map.entry((peer, name)).or_default();
        // Pop stale timestamps.
        while let Some(&front) = entry.timestamps.front() {
            if now.duration_since(front) >= limit.window {
                entry.timestamps.pop_front();
            } else {
                break;
            }
        }
        if entry.timestamps.len() >= limit.max_requests {
            // Retry-after: how long until the OLDEST in-window timestamp
            // expires, plus a tiny grace so callers don't hammer at the
            // exact boundary.
            let oldest = *entry.timestamps.front().expect("non-empty checked");
            let retry =
                limit.window.saturating_sub(now.duration_since(oldest)) + Duration::from_millis(50);
            return Err(retry);
        }
        entry.timestamps.push_back(now);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn admits_up_to_limit_then_rejects() {
        let rl = RateLimiter::new();
        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        for _ in 0..5 {
            assert!(rl.check(ip, Bucket::Register).is_ok());
        }
        let err = rl.check(ip, Bucket::Register).unwrap_err();
        assert!(err > Duration::from_secs(0));
    }

    #[test]
    fn separate_ips_have_separate_buckets() {
        let rl = RateLimiter::new();
        let ip1 = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        let ip2 = IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8));
        for _ in 0..5 {
            assert!(rl.check(ip1, Bucket::Register).is_ok());
        }
        // ip2 unaffected.
        for _ in 0..5 {
            assert!(rl.check(ip2, Bucket::Register).is_ok());
        }
        assert!(rl.check(ip1, Bucket::Register).is_err());
    }

    #[test]
    fn separate_buckets_for_same_ip() {
        let rl = RateLimiter::new();
        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        for _ in 0..5 {
            assert!(rl.check(ip, Bucket::Register).is_ok());
        }
        // Heartbeat bucket independent.
        for _ in 0..30 {
            assert!(rl.check(ip, Bucket::Heartbeat).is_ok());
        }
        assert!(rl.check(ip, Bucket::Heartbeat).is_err());
    }
}
