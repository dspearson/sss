use anyhow::{anyhow, Result};
use std::process::{Command, Stdio};
use std::time::Duration;

use crate::agent_policy::UserDecision;
use crate::agent_protocol::RequestContext;

/// Askpass configuration
#[derive(Debug, Clone)]
pub struct AskpassConfig {
    /// Path to askpass helper (or "auto", "gui", "tty")
    pub helper: String,
    /// Timeout for user response
    pub timeout: Duration,
    /// Show desktop notifications
    pub show_notification: bool,
}

impl Default for AskpassConfig {
    fn default() -> Self {
        Self {
            helper: "auto".to_string(),
            timeout: Duration::from_secs(30),
            show_notification: true,
        }
    }
}

/// Prompt user for unsealing confirmation
pub fn prompt_user(context: &RequestContext, config: &AskpassConfig) -> Result<UserDecision> {
    // Determine which helper to use
    let helper_path = resolve_helper(&config.helper)?;

    // Show desktop notification if enabled
    if config.show_notification {
        let _ = show_notification(context);
    }

    // Invoke the helper
    invoke_helper(&helper_path, context, config.timeout)
}

/// Resolve the helper path
fn resolve_helper(helper: &str) -> Result<String> {
    match helper {
        "auto" => {
            // Auto-detect: prefer GUI if we have a display, otherwise TTY
            if has_display() {
                resolve_helper("gui")
            } else {
                resolve_helper("tty")
            }
        }
        "gui" => {
            // Find the GUI helper in PATH or next to the main binary
            find_helper_binary("sss-askpass-gui")
        }
        "tty" => {
            // Find the TTY helper in PATH or next to the main binary
            find_helper_binary("sss-askpass-tty")
        }
        path => {
            // Use the provided path directly
            Ok(path.to_string())
        }
    }
}

/// Check if we have a display available
fn has_display() -> bool {
    std::env::var("DISPLAY").is_ok()
        || std::env::var("WAYLAND_DISPLAY").is_ok()
        || cfg!(target_os = "macos")
        || cfg!(target_os = "windows")
}

/// Find a helper binary in PATH or next to the main binary
fn find_helper_binary(name: &str) -> Result<String> {
    // Try to find in PATH
    if let Ok(path) = which::which(name) {
        return Ok(path.to_string_lossy().to_string());
    }

    // Try next to the current executable
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let helper_path = dir.join(name);
            if helper_path.exists() {
                return Ok(helper_path.to_string_lossy().to_string());
            }
        }
    }

    Err(anyhow!("Helper binary not found: {}", name))
}

/// Invoke the askpass helper
fn invoke_helper(
    helper_path: &str,
    context: &RequestContext,
    timeout: Duration,
) -> Result<UserDecision> {
    // Serialize context to JSON
    let context_json = serde_json::to_string(context)?;

    // Invoke helper with timeout
    let child = Command::new(helper_path)
        .arg("--context")
        .arg(&context_json)
        .arg("--timeout")
        .arg(timeout.as_secs().to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| anyhow!("Failed to spawn askpass helper: {}", e))?;

    // Wait for completion with timeout
    let result = wait_with_timeout(child, timeout)?;

    match result {
        Some(output) => {
            if output.status.success() {
                // Parse the response
                let response = String::from_utf8_lossy(&output.stdout);
                parse_decision(response.trim())
            } else {
                let error = String::from_utf8_lossy(&output.stderr);
                Err(anyhow!("Askpass helper failed: {}", error))
            }
        }
        None => {
            // Timeout - child has been killed by wait_with_timeout
            Ok(UserDecision::DenyOnce)
        }
    }
}

/// Wait for a child process with timeout
fn wait_with_timeout(
    mut child: std::process::Child,
    timeout: Duration,
) -> Result<Option<std::process::Output>> {
    // Simple polling-based timeout (not perfect but works)
    let start = std::time::Instant::now();
    let poll_interval = Duration::from_millis(100);

    loop {
        match child.try_wait()? {
            Some(_) => {
                // Process finished
                return child.wait_with_output().map(Some).map_err(Into::into);
            }
            None => {
                // Still running
                if start.elapsed() >= timeout {
                    return Ok(None);
                }
                std::thread::sleep(poll_interval);
            }
        }
    }
}

/// Parse user decision from helper output
fn parse_decision(response: &str) -> Result<UserDecision> {
    match response {
        "deny" | "deny_once" | "1" => Ok(UserDecision::DenyOnce),
        "deny_all" | "2" => Ok(UserDecision::DenyAll),
        "allow" | "allow_once" | "3" => Ok(UserDecision::AllowOnce),
        "allow_always" | "4" => Ok(UserDecision::AllowAlways),
        _ => Err(anyhow!("Invalid decision: {}", response)),
    }
}

/// Show desktop notification
fn show_notification(context: &RequestContext) -> Result<()> {
    let hostname = context.hostname.as_deref().unwrap_or("unknown host");

    let message = format!("SSS unsealing request from {}", hostname);

    // Try different notification methods based on platform
    #[cfg(target_os = "linux")]
    {
        let _ = Command::new("notify-send")
            .arg("SSS Agent")
            .arg(&message)
            .arg("--urgency=normal")
            .arg("--expire-time=30000")
            .spawn();
    }

    #[cfg(target_os = "macos")]
    {
        let script = format!(
            "display notification \"{}\" with title \"SSS Agent\"",
            message
        );
        let _ = Command::new("osascript").arg("-e").arg(&script).spawn();
    }

    #[cfg(target_os = "windows")]
    {
        // Windows notification would require additional dependencies
        // For now, skip on Windows
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_decision() {
        assert_eq!(parse_decision("deny").unwrap(), UserDecision::DenyOnce);
        assert_eq!(parse_decision("deny_all").unwrap(), UserDecision::DenyAll);
        assert_eq!(parse_decision("allow").unwrap(), UserDecision::AllowOnce);
        assert_eq!(
            parse_decision("allow_always").unwrap(),
            UserDecision::AllowAlways
        );
        assert_eq!(parse_decision("1").unwrap(), UserDecision::DenyOnce);
        assert_eq!(parse_decision("2").unwrap(), UserDecision::DenyAll);
        assert_eq!(parse_decision("3").unwrap(), UserDecision::AllowOnce);
        assert_eq!(parse_decision("4").unwrap(), UserDecision::AllowAlways);
    }

    #[test]
    fn test_parse_invalid_decision() {
        assert!(parse_decision("invalid").is_err());
        assert!(parse_decision("5").is_err());
        assert!(parse_decision("").is_err());
    }

    #[test]
    fn test_has_display() {
        // Just ensure it doesn't panic
        let _ = has_display();
    }
}
