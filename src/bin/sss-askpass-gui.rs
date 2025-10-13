use anyhow::{anyhow, Result};
use clap::Parser;
use std::process::Command;

/// SSS Agent GUI Confirmation Helper
#[derive(Parser)]
#[command(name = "sss-askpass-gui")]
#[command(about = "GUI-based confirmation helper for SSS agent")]
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

    // Show GUI dialog based on platform
    let decision = show_gui_dialog(&context, args.timeout)?;

    // Output decision to stdout
    println!("{}", decision);

    Ok(())
}

fn show_gui_dialog(context: &RequestContext, timeout: u64) -> Result<String> {
    // Try different GUI tools based on platform
    #[cfg(target_os = "linux")]
    {
        // Try zenity first, then kdialog
        if which::which("zenity").is_ok() {
            return show_zenity_dialog(context, timeout);
        } else if which::which("kdialog").is_ok() {
            return show_kdialog_dialog(context, timeout);
        }
    }

    #[cfg(target_os = "macos")]
    {
        return show_macos_dialog(context, timeout);
    }

    #[cfg(target_os = "windows")]
    {
        // On Windows, fall back to console prompt
        return show_console_dialog(context, timeout);
    }

    Err(anyhow!("No GUI dialog tool available on this platform"))
}

#[cfg(target_os = "linux")]
fn show_zenity_dialog(context: &RequestContext, timeout: u64) -> Result<String> {
    let host_info = format_host_info(context);
    let project_info = context.project_path.as_deref().unwrap_or("(unknown)");

    let text = format!(
        "SSS Agent Authorization Request\n\n\
         Host: {}\n\
         Project: {}\n\
         User: {}\n\n\
         Allow unsealing repository key?\n\n\
         Timeout in {} seconds",
        host_info, project_info, context.sss_username, timeout
    );

    let output = Command::new("zenity")
        .arg("--question")
        .arg("--title=SSS Agent")
        .arg(format!("--text={}", text))
        .arg("--ok-label=Allow Once")
        .arg("--cancel-label=Deny")
        .arg("--extra-button=Allow Always")
        .arg("--extra-button=Deny All")
        .arg(format!("--timeout={}", timeout))
        .output()?;

    // Zenity return codes:
    // 0 = OK (Allow Once)
    // 1 = Cancel (Deny)
    // 5 = Timeout
    // 1 with stdout = Extra button
    match output.status.code() {
        Some(0) => Ok("allow_once".to_string()),
        Some(1) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if stdout.contains("Allow Always") {
                Ok("allow_always".to_string())
            } else if stdout.contains("Deny All") {
                Ok("deny_all".to_string())
            } else {
                Ok("deny_once".to_string())
            }
        }
        Some(5) => Ok("deny_once".to_string()), // Timeout = deny
        _ => Ok("deny_once".to_string()),
    }
}

#[cfg(target_os = "linux")]
fn show_kdialog_dialog(context: &RequestContext, timeout: u64) -> Result<String> {
    let host_info = format_host_info(context);
    let project_info = context.project_path.as_deref().unwrap_or("(unknown)");

    let text = format!(
        "SSS Agent Authorization Request\n\n\
         Host: {}\n\
         Project: {}\n\
         User: {}\n\n\
         Allow unsealing repository key?\n\n\
         Timeout in {} seconds",
        host_info, project_info, context.sss_username, timeout
    );

    let output = Command::new("kdialog")
        .arg("--yesnocancel")
        .arg(text)
        .arg("--title")
        .arg("SSS Agent")
        .arg("--yes-label")
        .arg("Allow Once")
        .arg("--no-label")
        .arg("Deny")
        .arg("--cancel-label")
        .arg("Deny All")
        .output()?;

    // kdialog return codes:
    // 0 = Yes (Allow Once)
    // 1 = No (Deny)
    // 2 = Cancel (Deny All)
    match output.status.code() {
        Some(0) => Ok("allow_once".to_string()),
        Some(1) => Ok("deny_once".to_string()),
        Some(2) => Ok("deny_all".to_string()),
        _ => Ok("deny_once".to_string()),
    }
}

#[cfg(target_os = "macos")]
fn show_macos_dialog(context: &RequestContext, _timeout: u64) -> Result<String> {
    let host_info = format_host_info(context);
    let project_info = context.project_path.as_deref().unwrap_or("(unknown)");

    let script = format!(
        r#"display dialog "SSS Agent Authorization Request

Host: {}
Project: {}
User: {}

Allow unsealing repository key?" buttons {{"Deny", "Allow Once", "Allow Always"}} default button "Deny""#,
        host_info, project_info, context.sss_username
    );

    let output = Command::new("osascript").arg("-e").arg(&script).output()?;

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        if stdout.contains("Allow Always") {
            Ok("allow_always".to_string())
        } else if stdout.contains("Allow Once") {
            Ok("allow_once".to_string())
        } else {
            Ok("deny_once".to_string())
        }
    } else {
        // User closed dialog or error occurred
        Ok("deny_once".to_string())
    }
}

#[cfg(target_os = "windows")]
fn show_console_dialog(context: &RequestContext, timeout: u64) -> Result<String> {
    // On Windows, we'd ideally use a message box, but that requires additional dependencies
    // For now, fall back to console output
    use std::io::{self, Write};

    let mut stderr = io::stderr();
    let host_info = format_host_info(context);
    let project_info = context.project_path.as_deref().unwrap_or("(unknown)");

    writeln!(stderr, "\n=== SSS Agent Authorization Request ===")?;
    writeln!(stderr, "\nHost: {}", host_info)?;
    writeln!(stderr, "Project: {}", project_info)?;
    writeln!(stderr, "User: {}", context.sss_username)?;
    writeln!(stderr, "\nAllow unsealing repository key?")?;
    writeln!(stderr, "\n[1] Deny")?;
    writeln!(stderr, "[2] Allow Once")?;
    if context.hostname.is_some() {
        writeln!(stderr, "[3] Allow Always")?;
    }
    writeln!(stderr, "\nTimeout in {} seconds", timeout)?;
    write!(stderr, "Choice: ")?;
    stderr.flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;

    match input.trim() {
        "2" => Ok("allow_once".to_string()),
        "3" if context.hostname.is_some() => Ok("allow_always".to_string()),
        _ => Ok("deny_once".to_string()),
    }
}

fn format_host_info(context: &RequestContext) -> String {
    match (&context.hostname, &context.remote_user) {
        (Some(hostname), Some(user)) => format!("{}@{}", user, hostname),
        (Some(hostname), None) => hostname.clone(),
        (None, Some(user)) => format!("{}@local", user),
        (None, None) => "local".to_string(),
    }
}
