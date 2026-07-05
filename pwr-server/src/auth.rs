//! Authentication rate limiting for pwr-server.
//!
//! Tracks failed authentication attempts per IP address and rejects
//! connections that exceed the configured threshold within a time window.
//! Uses a simple in-memory map with periodic cleanup.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Instant;

/// Maximum failed authentication attempts per IP before temporary ban.
const MAX_ATTEMPTS: usize = 5;

/// Time window for counting failed attempts (seconds).
const WINDOW_SECS: u64 = 60;

/// Ban duration after exceeding the attempt limit (seconds).
const BAN_DURATION_SECS: u64 = 300;

/// Entry in the rate limiting table.
#[derive(Debug, Clone)]
struct RateLimitEntry {
    /// Number of failed attempts in the current window.
    attempts: usize,
    /// When the first attempt in this window occurred.
    window_start: Instant,
    /// If banned, the time when the ban expires.
    banned_until: Option<Instant>,
}

/// Tracks authentication attempts per source IP address.
#[derive(Debug, Default)]
pub struct RateLimiter {
    entries: HashMap<IpAddr, RateLimitEntry>,
}

impl RateLimiter {
    /// Create a new rate limiter.
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// Check whether an authentication attempt from this IP should be allowed.
    ///
    /// Returns `true` if the attempt is permitted, `false` if the
    /// IP is currently banned or has exceeded the attempt limit.
    pub fn check_attempt(&mut self, ip: IpAddr) -> bool {
        let now = Instant::now();
        self.cleanup_expired(now);

        let entry = self.entries.entry(ip).or_insert(RateLimitEntry {
            attempts: 0,
            window_start: now,
            banned_until: None,
        });

        // Check if banned
        if let Some(banned_until) = entry.banned_until {
            if now < banned_until {
                log::warn!("Rejected auth attempt from banned IP: {}", ip);
                return false;
            }
            // Ban expired, reset
            entry.banned_until = None;
            entry.attempts = 0;
            entry.window_start = now;
        }

        // Reset window if expired
        if now.duration_since(entry.window_start).as_secs() > WINDOW_SECS {
            entry.attempts = 0;
            entry.window_start = now;
        }

        entry.attempts += 1;

        // Check if this attempt exceeds the limit
        if entry.attempts > MAX_ATTEMPTS {
            entry.banned_until = Some(now + std::time::Duration::from_secs(BAN_DURATION_SECS));
            log::warn!(
                "IP {} banned for {} seconds after {} failed attempts",
                ip,
                BAN_DURATION_SECS,
                entry.attempts
            );
            return false;
        }

        // Reset attempts on successful auth (called externally)
        true
    }

    /// Reset the counter for an IP after a successful authentication.
    pub fn record_success(&mut self, ip: IpAddr) {
        if let Some(entry) = self.entries.get_mut(&ip) {
            entry.attempts = 0;
            entry.banned_until = None;
        }
    }

    /// Remove expired entries to prevent unbounded memory growth.
    fn cleanup_expired(&mut self, now: Instant) {
        self.entries.retain(|_ip, entry| {
            let expired = now.duration_since(entry.window_start).as_secs() > WINDOW_SECS + BAN_DURATION_SECS;
            if let Some(banned_until) = entry.banned_until {
                !expired || now < banned_until
            } else {
                !expired
            }
        });
    }

    /// Return the number of tracked IPs (for monitoring).
    pub fn tracked_count(&self) -> usize {
        self.entries.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_ip() -> IpAddr {
        "192.168.1.100".parse().unwrap()
    }

    #[test]
    fn test_allows_first_five_attempts() {
        let mut limiter = RateLimiter::new();
        let ip = test_ip();

        for _ in 0..5 {
            assert!(limiter.check_attempt(ip));
        }
    }

    #[test]
    fn test_blocks_sixth_attempt() {
        let mut limiter = RateLimiter::new();
        let ip = test_ip();

        for _ in 0..5 {
            assert!(limiter.check_attempt(ip));
        }
        // Sixth attempt should be blocked
        assert!(!limiter.check_attempt(ip));
    }

    #[test]
    fn test_success_resets_counter() {
        let mut limiter = RateLimiter::new();
        let ip = test_ip();

        // Three failed
        for _ in 0..3 {
            limiter.check_attempt(ip);
        }
        // Success resets
        limiter.record_success(ip);

        // Should have a fresh window of 5
        for _ in 0..5 {
            assert!(limiter.check_attempt(ip));
        }
    }

    #[test]
    fn test_different_ips_independent() {
        let mut limiter = RateLimiter::new();
        let ip1: IpAddr = "10.0.0.1".parse().unwrap();
        let ip2: IpAddr = "10.0.0.2".parse().unwrap();

        // Exhaust ip1
        for _ in 0..5 {
            limiter.check_attempt(ip1);
        }
        assert!(!limiter.check_attempt(ip1));

        // ip2 should still be fine
        assert!(limiter.check_attempt(ip2));
    }
}
