use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Simple rate limiter for password attempts
#[derive(Clone)]
pub struct RateLimiter {
    attempts: Arc<Mutex<HashMap<String, AttemptRecord>>>,
    max_attempts: u32,
    window_duration: Duration,
    lockout_duration: Duration,
}

#[derive(Debug)]
struct AttemptRecord {
    count: u32,
    first_attempt: Instant,
    locked_until: Option<Instant>,
}

impl RateLimiter {
    /// Create a new rate limiter
    pub fn new(max_attempts: u32, window_minutes: u64, lockout_minutes: u64) -> Self {
        Self {
            attempts: Arc::new(Mutex::new(HashMap::new())),
            max_attempts,
            window_duration: Duration::from_secs(window_minutes * 60),
            lockout_duration: Duration::from_secs(lockout_minutes * 60),
        }
    }

    /// Check if an identifier is allowed to make an attempt
    pub fn check_attempt(&self, identifier: &str) -> Result<(), String> {
        let mut attempts = self.attempts.lock().unwrap();
        let now = Instant::now();

        // Clean up old entries
        attempts.retain(|_, record| {
            if let Some(locked_until) = record.locked_until {
                now < locked_until
            } else {
                now.duration_since(record.first_attempt) < self.window_duration
            }
        });

        // Check current record
        if let Some(record) = attempts.get(identifier) {
            // Check if locked out
            if let Some(locked_until) = record.locked_until {
                if now < locked_until {
                    let remaining = locked_until.duration_since(now);
                    return Err(format!(
                        "Too many failed attempts. Try again in {} minutes.",
                        remaining.as_secs() / 60 + 1
                    ));
                }
            }

            // Check if within rate limit
            if record.count >= self.max_attempts {
                let elapsed = now.duration_since(record.first_attempt);
                if elapsed < self.window_duration {
                    return Err(format!(
                        "Too many attempts ({}). Try again in {} minutes.",
                        record.count,
                        (self.window_duration.as_secs() - elapsed.as_secs()) / 60 + 1
                    ));
                }
            }
        }

        Ok(())
    }

    /// Record a failed attempt
    pub fn record_failure(&self, identifier: &str) {
        let mut attempts = self.attempts.lock().unwrap();
        let now = Instant::now();

        let record = attempts.entry(identifier.to_string()).or_insert(AttemptRecord {
            count: 0,
            first_attempt: now,
            locked_until: None,
        });

        // Reset if outside window
        if now.duration_since(record.first_attempt) >= self.window_duration {
            record.count = 1;
            record.first_attempt = now;
            record.locked_until = None;
        } else {
            record.count += 1;
        }

        // Lock out if too many attempts
        if record.count >= self.max_attempts {
            record.locked_until = Some(now + self.lockout_duration);
        }
    }

    /// Record a successful attempt (clears the record)
    pub fn record_success(&self, identifier: &str) {
        let mut attempts = self.attempts.lock().unwrap();
        attempts.remove(identifier);
    }
}

/// Global rate limiter instance for password attempts
static GLOBAL_RATE_LIMITER: Lazy<RateLimiter> = Lazy::new(|| {
    RateLimiter::new(
        5,  // max 5 attempts
        15, // per 15 minutes
        30, // lockout for 30 minutes
    )
});

/// Get the global rate limiter instance
pub fn get_password_rate_limiter() -> &'static RateLimiter {
    &GLOBAL_RATE_LIMITER
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limiter_basic() {
        let limiter = RateLimiter::new(3, 1, 2); // 3 attempts per minute, 2 min lockout

        // Should allow initial attempts
        assert!(limiter.check_attempt("user1").is_ok());
        limiter.record_failure("user1");

        assert!(limiter.check_attempt("user1").is_ok());
        limiter.record_failure("user1");

        assert!(limiter.check_attempt("user1").is_ok());
        limiter.record_failure("user1");

        // Should block after max attempts
        assert!(limiter.check_attempt("user1").is_err());

        // Different user should not be affected
        assert!(limiter.check_attempt("user2").is_ok());
    }

    #[test]
    fn test_rate_limiter_success_clears() {
        let limiter = RateLimiter::new(3, 1, 2);

        limiter.record_failure("user1");
        limiter.record_failure("user1");

        // Success should clear the record
        limiter.record_success("user1");

        // Should be able to attempt again
        assert!(limiter.check_attempt("user1").is_ok());
    }

    #[test]
    fn test_rate_limiter_cleanup() {
        let limiter = RateLimiter::new(3, 1, 1);

        // Fill up attempts for different users
        limiter.record_failure("user1");
        limiter.record_failure("user2");

        // Both should still be allowed
        assert!(limiter.check_attempt("user1").is_ok());
        assert!(limiter.check_attempt("user2").is_ok());

        // Test that the limiter works for independent users
        assert!(limiter.check_attempt("user3").is_ok());
    }
}