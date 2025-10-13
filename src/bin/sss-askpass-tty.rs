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
