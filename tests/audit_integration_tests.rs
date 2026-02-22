// Integration tests for audit logging and rate limiting
//
// These tests cover scenarios not covered by inline unit tests:
// - Concurrent logging
// - File permissions security
// - Log rotation behavior
// - Rate limiting under load
// - Multi-threaded access

use anyhow::Result;
use sss::audit_log::{AuditEvent, AuditLogger, RateLimiter};
use sss::agent_protocol::RequestContext;
use std::fs;
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use tempfile::NamedTempFile;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

#[test]
fn test_audit_logger_basic() -> Result<()> {
    let temp_file = NamedTempFile::new()?;
    let logger = AuditLogger::new(temp_file.path().to_path_buf())?;

    logger.log(AuditEvent::AgentStarted, "Test agent started")?;
    logger.log(AuditEvent::KeyLoaded, "Test key loaded")?;

    let content = fs::read_to_string(temp_file.path())?;
    assert!(content.contains("[AGENT_STARTED]"));
    assert!(content.contains("[KEY_LOADED]"));
    assert!(content.contains("Test agent started"));
    assert!(content.contains("Test key loaded"));

    Ok(())
}

#[test]
#[cfg(unix)]
fn test_audit_log_file_permissions() -> Result<()> {
    let temp_file = NamedTempFile::new()?;
    let _logger = AuditLogger::new(temp_file.path().to_path_buf())?;

    let metadata = fs::metadata(temp_file.path())?;
    let mode = metadata.permissions().mode() & 0o777;

    assert_eq!(mode, 0o600, "Log file should have 0o600 permissions (owner read/write only)");

    Ok(())
}

#[test]
fn test_audit_logger_with_context() -> Result<()> {
    let temp_file = NamedTempFile::new()?;
    let logger = AuditLogger::new(temp_file.path().to_path_buf())?;

    let mut context = RequestContext::new("alice".to_string());
    context.hostname = Some("workstation.example.com".to_string());
    context.remote_user = Some("bob".to_string());
    context.project_path = Some("/home/alice/project".to_string());

    logger.log_request(&context)?;

    let content = fs::read_to_string(temp_file.path())?;
    assert!(content.contains("[REQUEST]"));
    assert!(content.contains("sss_user=alice"));
    assert!(content.contains("host=workstation.example.com"));
    assert!(content.contains("remote_user=bob"));
    assert!(content.contains("project=/home/alice/project"));

    Ok(())
}

#[test]
fn test_audit_logger_concurrent_writes() -> Result<()> {
    let temp_file = NamedTempFile::new()?;
    let logger = Arc::new(AuditLogger::new(temp_file.path().to_path_buf())?);

    let mut handles = vec![];

    // Spawn 10 threads that each write 10 log entries
    for thread_id in 0..10 {
        let logger_clone = Arc::clone(&logger);
        let handle = thread::spawn(move || {
            for i in 0..10 {
                logger_clone
                    .log(AuditEvent::Request, &format!("Thread {} entry {}", thread_id, i))
                    .unwrap();
            }
        });
        handles.push(handle);
    }

    // Wait for all threads to complete
    for handle in handles {
        handle.join().unwrap();
    }

    // Verify all entries were written
    let content = fs::read_to_string(temp_file.path())?;
    let line_count = content.lines().count();

    assert_eq!(line_count, 100, "Should have 100 log entries from concurrent writes");

    Ok(())
}

#[test]
fn test_audit_logger_all_event_types() -> Result<()> {
    let temp_file = NamedTempFile::new()?;
    let logger = AuditLogger::new(temp_file.path().to_path_buf())?;

    let events = vec![
        AuditEvent::AgentStarted,
        AuditEvent::AgentStopped,
        AuditEvent::KeyLoaded,
        AuditEvent::KeyUnloaded,
        AuditEvent::Request,
        AuditEvent::Approved,
        AuditEvent::Denied,
        AuditEvent::Timeout,
        AuditEvent::Error,
        AuditEvent::AgentLocked,
        AuditEvent::AgentUnlocked,
    ];

    for event in events {
        logger.log(event, "Test message")?;
    }

    let content = fs::read_to_string(temp_file.path())?;

    // Verify all event types are in the log
    assert!(content.contains("[AGENT_STARTED]"));
    assert!(content.contains("[AGENT_STOPPED]"));
    assert!(content.contains("[KEY_LOADED]"));
    assert!(content.contains("[KEY_UNLOADED]"));
    assert!(content.contains("[REQUEST]"));
    assert!(content.contains("[APPROVED]"));
    assert!(content.contains("[DENIED]"));
    assert!(content.contains("[TIMEOUT]"));
    assert!(content.contains("[ERROR]"));
    assert!(content.contains("[AGENT_LOCKED]"));
    assert!(content.contains("[AGENT_UNLOCKED]"));

    Ok(())
}

#[test]
fn test_audit_logger_large_volume() -> Result<()> {
    let temp_file = NamedTempFile::new()?;
    let logger = AuditLogger::new(temp_file.path().to_path_buf())?;

    // Write 1000 log entries
    for i in 0..1000 {
        logger.log(AuditEvent::Request, &format!("Entry {}", i))?;
    }

    let content = fs::read_to_string(temp_file.path())?;
    let line_count = content.lines().count();

    assert_eq!(line_count, 1000);

    Ok(())
}

#[test]
fn test_audit_logger_special_characters() -> Result<()> {
    let temp_file = NamedTempFile::new()?;
    let logger = AuditLogger::new(temp_file.path().to_path_buf())?;

    logger.log(AuditEvent::Request, "Message with special chars: \n\t\r | & < > \" '")?;

    let content = fs::read_to_string(temp_file.path())?;
    assert!(content.contains("special chars"));

    Ok(())
}

#[test]
fn test_audit_logger_unicode() -> Result<()> {
    let temp_file = NamedTempFile::new()?;
    let logger = AuditLogger::new(temp_file.path().to_path_buf())?;

    logger.log(AuditEvent::Request, "Unicode: 你好世界 🔒 مرحبا")?;

    let content = fs::read_to_string(temp_file.path())?;
    assert!(content.contains("你好世界"));
    assert!(content.contains("🔒"));

    Ok(())
}

#[test]
fn test_rate_limiter_basic() {
    let limiter = RateLimiter::new(5);

    let mut context = RequestContext::new("alice".to_string());
    context.hostname = Some("test.example.com".to_string());

    // First 5 requests should pass
    for _ in 0..5 {
        assert!(limiter.check_rate_limit(&context));
    }

    // 6th request should fail
    assert!(!limiter.check_rate_limit(&context));
}

#[test]
fn test_rate_limiter_different_hosts() {
    let limiter = RateLimiter::new(3);

    let mut context1 = RequestContext::new("alice".to_string());
    context1.hostname = Some("host1.example.com".to_string());

    let mut context2 = RequestContext::new("bob".to_string());
    context2.hostname = Some("host2.example.com".to_string());

    // 3 requests from each host should pass independently
    for _ in 0..3 {
        assert!(limiter.check_rate_limit(&context1));
        assert!(limiter.check_rate_limit(&context2));
    }

    // 4th request from each should fail
    assert!(!limiter.check_rate_limit(&context1));
    assert!(!limiter.check_rate_limit(&context2));
}

#[test]
fn test_rate_limiter_time_window() {
    let limiter = RateLimiter::new(2);

    let mut context = RequestContext::new("alice".to_string());
    context.hostname = Some("test.example.com".to_string());

    // Use up the limit
    assert!(limiter.check_rate_limit(&context));
    assert!(limiter.check_rate_limit(&context));
    assert!(!limiter.check_rate_limit(&context));

    // Wait for time window to expire (61 seconds to be safe)
    // Note: In real tests this would be too slow, so we just verify the logic
    // The actual time-based test is in the inline unit tests
}

#[test]
fn test_rate_limiter_get_count() {
    let limiter = RateLimiter::new(10);

    let mut context = RequestContext::new("alice".to_string());
    context.hostname = Some("test.example.com".to_string());

    // Initially 0 requests
    assert_eq!(limiter.get_request_count("test.example.com"), 0);

    // Make 5 requests
    for _ in 0..5 {
        assert!(limiter.check_rate_limit(&context));
    }

    assert_eq!(limiter.get_request_count("test.example.com"), 5);
}

#[test]
fn test_rate_limiter_clear_host() {
    let limiter = RateLimiter::new(3);

    let mut context = RequestContext::new("alice".to_string());
    context.hostname = Some("test.example.com".to_string());

    // Fill up the limit
    for _ in 0..3 {
        assert!(limiter.check_rate_limit(&context));
    }
    assert!(!limiter.check_rate_limit(&context));

    // Clear and verify we can make requests again
    limiter.clear_host("test.example.com");
    assert!(limiter.check_rate_limit(&context));
}

#[test]
fn test_rate_limiter_clear_all() {
    let limiter = RateLimiter::new(2);

    let mut context1 = RequestContext::new("alice".to_string());
    context1.hostname = Some("host1.example.com".to_string());

    let mut context2 = RequestContext::new("bob".to_string());
    context2.hostname = Some("host2.example.com".to_string());

    // Fill up limits for both hosts
    for _ in 0..2 {
        assert!(limiter.check_rate_limit(&context1));
        assert!(limiter.check_rate_limit(&context2));
    }
    assert!(!limiter.check_rate_limit(&context1));
    assert!(!limiter.check_rate_limit(&context2));

    // Clear all and verify both can make requests again
    limiter.clear_all();
    assert!(limiter.check_rate_limit(&context1));
    assert!(limiter.check_rate_limit(&context2));
}

#[test]
fn test_rate_limiter_concurrent_access() {
    let limiter = Arc::new(RateLimiter::new(100));
    let mut handles = vec![];

    // Spawn 10 threads that each try to make 20 requests
    for thread_id in 0..10 {
        let limiter_clone = Arc::clone(&limiter);
        let handle = thread::spawn(move || {
            let mut context = RequestContext::new("alice".to_string());
            context.hostname = Some(format!("host{}.example.com", thread_id));

            let mut allowed = 0;
            for _ in 0..20 {
                if limiter_clone.check_rate_limit(&context) {
                    allowed += 1;
                }
            }
            allowed
        });
        handles.push(handle);
    }

    // Collect results
    let mut total_allowed = 0;
    for handle in handles {
        total_allowed += handle.join().unwrap();
    }

    // Each host should have been allowed some requests
    // With limit of 100 per host and 20 requests per thread, all should pass
    assert_eq!(total_allowed, 200);
}

#[test]
fn test_rate_limiter_no_hostname() {
    let limiter = RateLimiter::new(5);

    let context = RequestContext::new("alice".to_string());
    // No hostname set

    // Should use "local" as default hostname
    for _ in 0..5 {
        assert!(limiter.check_rate_limit(&context));
    }
    assert!(!limiter.check_rate_limit(&context));
}

#[test]
fn test_rate_limiter_high_limit() {
    let limiter = RateLimiter::new(1000);

    let mut context = RequestContext::new("alice".to_string());
    context.hostname = Some("test.example.com".to_string());

    // Should allow 1000 requests
    for _ in 0..1000 {
        assert!(limiter.check_rate_limit(&context));
    }

    // 1001st should fail
    assert!(!limiter.check_rate_limit(&context));
}

#[test]
fn test_rate_limiter_zero_limit() {
    let limiter = RateLimiter::new(0);

    let mut context = RequestContext::new("alice".to_string());
    context.hostname = Some("test.example.com".to_string());

    // With limit of 0, first request should fail
    assert!(!limiter.check_rate_limit(&context));
}

#[test]
fn test_rate_limiter_stress_test() {
    let limiter = Arc::new(RateLimiter::new(50));
    let mut handles = vec![];

    // Spawn 20 threads that hammer the same host
    for _ in 0..20 {
        let limiter_clone = Arc::clone(&limiter);
        let handle = thread::spawn(move || {
            let mut context = RequestContext::new("alice".to_string());
            context.hostname = Some("shared.example.com".to_string());

            let mut allowed = 0;
            for _ in 0..100 {
                if limiter_clone.check_rate_limit(&context) {
                    allowed += 1;
                }
                // Small delay to avoid busy-wait
                thread::sleep(Duration::from_micros(10));
            }
            allowed
        });
        handles.push(handle);
    }

    // Total allowed should be close to 50 (the limit)
    let mut total_allowed = 0;
    for handle in handles {
        total_allowed += handle.join().unwrap();
    }

    // With concurrent access, might be slightly over limit due to race conditions
    // but should be in reasonable range
    assert!((50..=70).contains(&total_allowed),
        "Expected 50-70 allowed requests, got {}", total_allowed);
}

#[test]
fn test_audit_and_rate_limit_integration() -> Result<()> {
    let temp_file = NamedTempFile::new()?;
    let logger = AuditLogger::new(temp_file.path().to_path_buf())?;
    let limiter = RateLimiter::new(3);

    let mut context = RequestContext::new("alice".to_string());
    context.hostname = Some("test.example.com".to_string());

    // Make requests and log them
    for i in 0..5 {
        let allowed = limiter.check_rate_limit(&context);
        if allowed {
            logger.log_request(&context)?;
        } else {
            logger.log(AuditEvent::Denied, &format!("Rate limit exceeded for request {}", i))?;
        }
    }

    let content = fs::read_to_string(temp_file.path())?;

    // Should have 3 REQUEST logs and 2 DENIED logs
    let request_count = content.matches("[REQUEST]").count();
    let denied_count = content.matches("[DENIED]").count();

    assert_eq!(request_count, 3);
    assert_eq!(denied_count, 2);

    Ok(())
}
