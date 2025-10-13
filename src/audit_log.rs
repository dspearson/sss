use anyhow::Result;
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::agent_policy::UserDecision;
use crate::agent_protocol::{RequestContext, ResponseStatus};

/// Audit event types
#[derive(Debug, Clone, Copy)]
pub enum AuditEvent {
    AgentStarted,
    AgentStopped,
    KeyLoaded,
    KeyUnloaded,
    Request,
    Approved,
    Denied,
    Timeout,
    Error,
    AgentLocked,
    AgentUnlocked,
}

impl AuditEvent {
    fn as_str(&self) -> &str {
        match self {
            AuditEvent::AgentStarted => "AGENT_STARTED",
            AuditEvent::AgentStopped => "AGENT_STOPPED",
            AuditEvent::KeyLoaded => "KEY_LOADED",
            AuditEvent::KeyUnloaded => "KEY_UNLOADED",
            AuditEvent::Request => "REQUEST",
            AuditEvent::Approved => "APPROVED",
            AuditEvent::Denied => "DENIED",
            AuditEvent::Timeout => "TIMEOUT",
            AuditEvent::Error => "ERROR",
            AuditEvent::AgentLocked => "AGENT_LOCKED",
            AuditEvent::AgentUnlocked => "AGENT_UNLOCKED",
        }
    }
}

/// Audit logger
pub struct AuditLogger {
    log_file: PathBuf,
    file_handle: Arc<Mutex<File>>,
}

impl AuditLogger {
    /// Create a new audit logger
    pub fn new(log_file: PathBuf) -> Result<Self> {
        // Ensure parent directory exists
        if let Some(parent) = log_file.parent() {
            std::fs::create_dir_all(parent)?;
        }

        // Open or create log file in append mode
        let file_handle = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_file)?;

        // Set secure permissions on the log file
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let metadata = std::fs::metadata(&log_file)?;
            let mut perms = metadata.permissions();
            perms.set_mode(0o600); // Owner read/write only
            std::fs::set_permissions(&log_file, perms)?;
        }

        Ok(Self {
            log_file,
            file_handle: Arc::new(Mutex::new(file_handle)),
        })
    }

    /// Log an event
    pub fn log(&self, event: AuditEvent, message: &str) -> Result<()> {
        self.log_with_context(event, message, None)
    }

    /// Log an event with context
    pub fn log_with_context(
        &self,
        event: AuditEvent,
        message: &str,
        context: Option<&RequestContext>,
    ) -> Result<()> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();

        let mut log_line = format!("{} [{}] {}", timestamp, event.as_str(), message);

        // Add context details if available
        if let Some(ctx) = context {
            if let Some(ref hostname) = ctx.hostname {
                log_line.push_str(&format!(" | host={}", hostname));
            }
            if let Some(ref user) = ctx.remote_user {
                log_line.push_str(&format!(" | remote_user={}", user));
            }
            if let Some(ref project) = ctx.project_path {
                log_line.push_str(&format!(" | project={}", project));
            }
            log_line.push_str(&format!(" | sss_user={}", ctx.sss_username));
        }

        log_line.push('\n');

        // Write to log file
        let mut file = self.file_handle.lock().unwrap();
        file.write_all(log_line.as_bytes())?;
        file.flush()?;

        Ok(())
    }

    /// Log a request
    pub fn log_request(&self, context: &RequestContext) -> Result<()> {
        self.log_with_context(
            AuditEvent::Request,
            "Unsealing request received",
            Some(context),
        )
    }

    /// Log a user decision
    pub fn log_decision(&self, decision: UserDecision, context: &RequestContext) -> Result<()> {
        let (event, message) = match decision {
            UserDecision::DenyOnce => (AuditEvent::Denied, "User denied request"),
            UserDecision::DenyAll => (AuditEvent::Denied, "User blocked host for this project"),
            UserDecision::AllowOnce => (AuditEvent::Approved, "User allowed request once"),
            UserDecision::AllowAlways => (AuditEvent::Approved, "User allowed request always"),
        };

        self.log_with_context(event, message, Some(context))
    }

    /// Log a response
    pub fn log_response(&self, status: ResponseStatus, context: &RequestContext) -> Result<()> {
        let (event, message) = match status {
            ResponseStatus::Success => (AuditEvent::Approved, "Repository key unsealed"),
            ResponseStatus::Denied => (AuditEvent::Denied, "Request denied by policy"),
            ResponseStatus::Timeout => (AuditEvent::Timeout, "User confirmation timeout"),
            ResponseStatus::Error => (AuditEvent::Error, "Error processing request"),
            ResponseStatus::AgentLocked => (AuditEvent::AgentLocked, "Agent is locked"),
        };

        self.log_with_context(event, message, Some(context))
    }

    /// Get the log file path
    pub fn path(&self) -> &PathBuf {
        &self.log_file
    }
}

/// Rate limiter for preventing abuse
pub struct RateLimiter {
    /// Maximum requests per minute per host
    max_requests_per_minute: usize,
    /// Map of hostname -> list of request timestamps
    request_history: Arc<Mutex<HashMap<String, Vec<SystemTime>>>>,
}

impl RateLimiter {
    /// Create a new rate limiter
    pub fn new(max_requests_per_minute: usize) -> Self {
        Self {
            max_requests_per_minute,
            request_history: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Check if a request should be allowed based on rate limits
    pub fn check_rate_limit(&self, context: &RequestContext) -> bool {
        let hostname = match &context.hostname {
            Some(h) => h.clone(),
            None => "local".to_string(),
        };

        let mut history = self.request_history.lock().unwrap();
        let now = SystemTime::now();
        let one_minute_ago = now - Duration::from_secs(60);

        // Get or create entry for this host
        let requests = history.entry(hostname).or_default();

        // Remove old requests (older than 1 minute)
        requests.retain(|&timestamp| timestamp > one_minute_ago);

        // Check if we're at the limit
        if requests.len() >= self.max_requests_per_minute {
            return false;
        }

        // Add this request
        requests.push(now);

        true
    }

    /// Get the number of recent requests from a host
    pub fn get_request_count(&self, hostname: &str) -> usize {
        let history = self.request_history.lock().unwrap();
        let now = SystemTime::now();
        let one_minute_ago = now - Duration::from_secs(60);

        history
            .get(hostname)
            .map(|requests| {
                requests
                    .iter()
                    .filter(|&&timestamp| timestamp > one_minute_ago)
                    .count()
            })
            .unwrap_or(0)
    }

    /// Clear rate limit history for a host
    pub fn clear_host(&self, hostname: &str) {
        let mut history = self.request_history.lock().unwrap();
        history.remove(hostname);
    }

    /// Clear all rate limit history
    pub fn clear_all(&self) {
        let mut history = self.request_history.lock().unwrap();
        history.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_audit_logger() {
        let temp_file = NamedTempFile::new().unwrap();
        let logger = AuditLogger::new(temp_file.path().to_path_buf()).unwrap();

        logger
            .log(AuditEvent::AgentStarted, "Test message")
            .unwrap();

        // Read the log file
        let content = std::fs::read_to_string(temp_file.path()).unwrap();
        assert!(content.contains("[AGENT_STARTED]"));
        assert!(content.contains("Test message"));
    }

    #[test]
    fn test_audit_logger_with_context() {
        let temp_file = NamedTempFile::new().unwrap();
        let logger = AuditLogger::new(temp_file.path().to_path_buf()).unwrap();

        let mut context = RequestContext::new("alice".to_string());
        context.hostname = Some("test.example.com".to_string());

        logger.log_request(&context).unwrap();

        // Read the log file
        let content = std::fs::read_to_string(temp_file.path()).unwrap();
        assert!(content.contains("[REQUEST]"));
        assert!(content.contains("host=test.example.com"));
        assert!(content.contains("sss_user=alice"));
    }

    #[test]
    fn test_rate_limiter() {
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
        let limiter = RateLimiter::new(5);

        let mut context1 = RequestContext::new("alice".to_string());
        context1.hostname = Some("host1.example.com".to_string());

        let mut context2 = RequestContext::new("bob".to_string());
        context2.hostname = Some("host2.example.com".to_string());

        // 5 requests from each host should pass
        for _ in 0..5 {
            assert!(limiter.check_rate_limit(&context1));
            assert!(limiter.check_rate_limit(&context2));
        }

        // 6th request from each should fail
        assert!(!limiter.check_rate_limit(&context1));
        assert!(!limiter.check_rate_limit(&context2));
    }

    #[test]
    fn test_rate_limiter_clear() {
        let limiter = RateLimiter::new(5);

        let mut context = RequestContext::new("alice".to_string());
        context.hostname = Some("test.example.com".to_string());

        // Fill up the rate limit
        for _ in 0..5 {
            assert!(limiter.check_rate_limit(&context));
        }
        assert!(!limiter.check_rate_limit(&context));

        // Clear and try again
        limiter.clear_host("test.example.com");
        assert!(limiter.check_rate_limit(&context));
    }
}
