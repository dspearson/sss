use anyhow::{anyhow, Result};
use clap::Parser;
use std::io::{self, Write};
use std::time::{Duration, SystemTime};

/// SSS Agent TTY Confirmation Helper
#[derive(Parser)]
#[command(name = "sss-askpass-tty")]
#[command(about = "Terminal-based confirmation helper for SSS agent")]
struct Args {
    /// Request context as JSON
    #[arg(long)]
    context: String,

    /// Timeout in seconds
    #[arg(long, default_value = "30")]
    timeout: u64,
}

#[derive(serde::Deserialize)]
struct RequestContext {
    hostname: Option<String>,
    remote_user: Option<String>,
    project_path: Option<String>,
    sss_username: String,
}

fn main() -> Result<()> {
    let args = Args::parse();

    // Parse context
    let context: RequestContext = serde_json::from_str(&args.context)
        .map_err(|e| anyhow!("Failed to parse context: {}", e))?;

    // Show the prompt
    show_prompt(&context, args.timeout)?;

    // Get user input with timeout
    let decision = get_user_input(Duration::from_secs(args.timeout))?;

    // Output decision to stdout
    println!("{}", decision);

    Ok(())
}

fn show_prompt(context: &RequestContext, timeout: u64) -> Result<()> {
    let mut stderr = io::stderr();

    // Use ANSI box-drawing characters for a nice-looking prompt
    writeln!(stderr)?;
    writeln!(
        stderr,
        "╔═══════════════════════════════════════════════════════════╗"
    )?;
    writeln!(
        stderr,
        "║ SSS Agent Authorization Request                           ║"
    )?;
    writeln!(
        stderr,
        "╠═══════════════════════════════════════════════════════════╣"
    )?;
    writeln!(
        stderr,
        "║                                                           ║"
    )?;

    // Host information
    if let Some(ref hostname) = context.hostname {
        if let Some(ref user) = context.remote_user {
            writeln!(stderr, "║ Host: {:<51} ║", format!("{}@{}", user, hostname))?;
        } else {
            writeln!(stderr, "║ Host: {:<51} ║", hostname)?;
        }
    } else {
        writeln!(stderr, "║ Host: {:<51} ║", "local")?;
    }

    // Project path
    if let Some(ref path) = context.project_path {
        let display_path = if path.len() > 51 {
            format!("...{}", &path[path.len() - 48..])
        } else {
            path.clone()
        };
        writeln!(stderr, "║ Project: {:<48} ║", display_path)?;
    }

    // SSS username
    writeln!(stderr, "║ User: {:<51} ║", context.sss_username)?;

    writeln!(
        stderr,
        "║                                                           ║"
    )?;
    writeln!(
        stderr,
        "║ Allow unsealing repository key?                           ║"
    )?;
    writeln!(
        stderr,
        "║                                                           ║"
    )?;
    writeln!(
        stderr,
        "║ [1] Deny this request                                     ║"
    )?;

    if context.hostname.is_some() {
        writeln!(
            stderr,
            "║ [2] Deny all from this host for this project             ║"
        )?;
    }

    writeln!(
        stderr,
        "║ [3] Allow this request once                               ║"
    )?;

    if context.hostname.is_some() {
        writeln!(
            stderr,
            "║ [4] Allow always for this host                            ║"
        )?;
    }

    writeln!(
        stderr,
        "║                                                           ║"
    )?;
    writeln!(
        stderr,
        "║ Choice (1-{}, timeout in {}s): {:<27} ║",
        if context.hostname.is_some() { "4" } else { "3" },
        timeout,
        ""
    )?;
    writeln!(
        stderr,
        "╚═══════════════════════════════════════════════════════════╝"
    )?;

    stderr.flush()?;

    Ok(())
}

fn get_user_input(timeout: Duration) -> Result<String> {
    use std::sync::mpsc;
    use std::thread;

    let (tx, rx) = mpsc::channel();

    // Spawn a thread to read from stdin
    thread::spawn(move || {
        let stdin = io::stdin();
        let mut line = String::new();
        if stdin.read_line(&mut line).is_ok() {
            let _ = tx.send(line.trim().to_string());
        }
    });

    // Wait for input or timeout
    let start = SystemTime::now();
    loop {
        match rx.try_recv() {
            Ok(input) => {
                // Got input, parse it
                return parse_input(&input);
            }
            Err(mpsc::TryRecvError::Empty) => {
                // No input yet, check timeout
                if start.elapsed().unwrap_or(Duration::ZERO) >= timeout {
                    return Err(anyhow!("Timeout waiting for user input"));
                }
                thread::sleep(Duration::from_millis(100));
            }
            Err(mpsc::TryRecvError::Disconnected) => {
                return Err(anyhow!("Input channel disconnected"));
            }
        }
    }
}

fn parse_input(input: &str) -> Result<String> {
    match input {
        "1" => Ok("deny_once".to_string()),
        "2" => Ok("deny_all".to_string()),
        "3" => Ok("allow_once".to_string()),
        "4" => Ok("allow_always".to_string()),
        "" => Ok("deny_once".to_string()), // Default to deny on empty input
        _ => Err(anyhow!("Invalid choice: {}", input)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_input_deny_once() {
        let result = parse_input("1");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "deny_once");
    }

    #[test]
    fn test_parse_input_deny_all() {
        let result = parse_input("2");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "deny_all");
    }

    #[test]
    fn test_parse_input_allow_once() {
        let result = parse_input("3");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "allow_once");
    }

    #[test]
    fn test_parse_input_allow_always() {
        let result = parse_input("4");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "allow_always");
    }

    #[test]
    fn test_parse_input_empty_defaults_to_deny() {
        let result = parse_input("");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "deny_once");
    }

    #[test]
    fn test_parse_input_invalid() {
        let result = parse_input("5");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid choice"));
    }

    #[test]
    fn test_parse_input_invalid_text() {
        let result = parse_input("invalid");
        assert!(result.is_err());
    }

    #[test]
    fn test_request_context_deserialization() {
        // Test that RequestContext can deserialize from valid JSON
        let json = r#"{
            "hostname": "example.com",
            "remote_user": "alice",
            "project_path": "/home/alice/project",
            "sss_username": "alice"
        }"#;

        let context: Result<RequestContext, _> = serde_json::from_str(json);
        assert!(context.is_ok());

        let context = context.unwrap();
        assert_eq!(context.hostname, Some("example.com".to_string()));
        assert_eq!(context.remote_user, Some("alice".to_string()));
        assert_eq!(context.project_path, Some("/home/alice/project".to_string()));
        assert_eq!(context.sss_username, "alice");
    }

    #[test]
    fn test_request_context_minimal() {
        // Test that RequestContext can deserialize with only required fields
        let json = r#"{
            "sss_username": "bob"
        }"#;

        let context: Result<RequestContext, _> = serde_json::from_str(json);
        assert!(context.is_ok());

        let context = context.unwrap();
        assert_eq!(context.hostname, None);
        assert_eq!(context.remote_user, None);
        assert_eq!(context.project_path, None);
        assert_eq!(context.sss_username, "bob");
    }

    // Note: show_prompt() and get_user_input() are not easily unit testable
    // as they interact with stderr/stdin and system time. These are better
    // tested manually or via integration tests.
}
