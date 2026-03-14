// firewallx/src/modules/rate_limiter.rs
// Per-IP Connection Rate Limiting (Fail2Ban style)

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

/// A simple sliding window token bucket for connection rate limiting.
pub struct RateLimiter {
    /// Max packets allowed per window.
    pub threshold: u32,
    /// The time window to measure against.
    pub window: Duration,
    /// Storage of connection attempts per IP.
    records: HashMap<Ipv4Addr, RateRecord>,
}

struct RateRecord {
    count: u32,
    window_start: Instant,
    /// If an IP trips the breaker, they are temporarily banned.
    banned_until: Option<Instant>,
}

impl RateRecord {
    fn new() -> Self {
        Self {
            count: 0,
            window_start: Instant::now(),
            banned_until: None,
        }
    }
}

impl RateLimiter {
    pub fn new(threshold: u32, window: Duration) -> Self {
        Self {
            threshold,
            window,
            records: HashMap::new(),
        }
    }

    /// Checks if a packet from `src_ip` should be rate-limited.
    /// Returns `true` if the packet should be DROPPED due to rate limits.
    pub fn check(&mut self, src_ip: Ipv4Addr) -> bool {
        let now = Instant::now();
        let record = self.records.entry(src_ip).or_insert_with(RateRecord::new);

        // Check if currently serving a ban
        if let Some(ban_end) = record.banned_until {
            if now < ban_end {
                return true; // Still banned
            } else {
                // Ban expired, reset the record
                record.banned_until = None;
                record.count = 0;
                record.window_start = now;
            }
        }

        // Reset sliding window if elapsed
        if now.duration_since(record.window_start) > self.window {
            record.count = 0;
            record.window_start = now;
        }

        record.count += 1;

        if record.count > self.threshold {
            // Apply a strict 60 second ban on tripping the limit
            record.banned_until = Some(now + Duration::from_secs(60));
            return true;
        }

        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limiter_allows_under_threshold() {
        let mut rl = RateLimiter::new(5, Duration::from_secs(1));
        let ip = Ipv4Addr::new(10, 0, 0, 1);
        
        for _ in 0..5 {
            assert!(!rl.check(ip));
        }
    }

    #[test]
    fn test_rate_limiter_blocks_over_threshold() {
        let mut rl = RateLimiter::new(5, Duration::from_secs(1));
        let ip = Ipv4Addr::new(10, 0, 0, 2);
        
        // 5 allowed
        for _ in 0..5 {
            assert!(!rl.check(ip));
        }
        // 6th should be blocked and trigger a ban
        assert!(rl.check(ip));
    }
}
