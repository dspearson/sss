use anyhow::{anyhow, Result};
use clap::ArgMatches;
use std::path::PathBuf;
use std::process::Command;

use crate::agent::AgentClient;
use crate::agent_policy::PolicyManager;

/// Handle agent subcommands
pub fn handle_agent(matches: &ArgMatches) -> Result<()> {
    match matches.subcommand() {
        Some(("start", sub_m)) => handle_start(sub_m),
        Some(("stop", _sub_m)) => handle_stop(),
        Some(("status", _sub_m)) => handle_status(),
        Some(("lock", _sub_m)) => handle_lock(),
        Some(("unlock", _sub_m)) => handle_unlock(),
        Some(("policies", sub_m)) => handle_policies(sub_m),
        _ => Err(anyhow!(
            "Unknown agent subcommand. Use 'sss agent --help' for usage."
        )),
    }
}

fn handle_start(matches: &ArgMatches) -> Result<()> {
    let foreground = matches.get_flag("foreground");
    let key_id = matches.get_one::<String>("key-id");

    println!("Starting SSS agent...");

    // Build command
    let mut cmd = Command::new("sss-agent");

    if foreground {
        cmd.arg("--foreground");
    }

    if let Some(id) = key_id {
        cmd.arg("--key-id").arg(id);
    }

    // If not foreground, spawn in background
    if foreground {
        let status = cmd.status()?;
        if !status.success() {
            return Err(anyhow!("Agent failed to start"));
        }
    } else {
        // Spawn and detach
        #[cfg(unix)]
        {
            use std::process::Stdio;

            cmd.stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null());

            // For now, just spawn without daemonizing
            // Full daemonization would require more complex handling
            cmd.spawn()?;
        }

        #[cfg(not(unix))]
        {
            cmd.spawn()?;
        }

        println!("Agent started in background");
        println!("Set SSS_AUTH_SOCK environment variable to use the agent");
    }

    Ok(())
}

fn handle_stop() -> Result<()> {
    println!("Stopping SSS agent...");

    // Try to find and kill sss-agent process
    #[cfg(unix)]
    {
        let output = Command::new("pkill")
            .arg("-TERM")
            .arg("sss-agent")
            .output()?;

        if output.status.success() {
            println!("Agent stopped");
            Ok(())
        } else {
            Err(anyhow!("Failed to stop agent. Is it running?"))
        }
    }

    #[cfg(not(unix))]
    {
        Err(anyhow!(
            "Stopping agent is not yet supported on this platform"
        ))
    }
}

fn handle_status() -> Result<()> {
    let client = AgentClient::new()?;

    if client.is_available() {
        println!("Agent is running and responsive");

        // Try to ping
        match client.ping() {
            Ok(_) => println!("Agent ping: OK"),
            Err(e) => println!("Agent ping failed: {}", e),
        }

        Ok(())
    } else {
        println!("Agent is not available");
        Err(anyhow!("Agent is not running or not accessible"))
    }
}

fn handle_lock() -> Result<()> {
    println!("Locking agent (will deny all requests until unlocked)...");

    // Load policy manager and lock it
    let policy_path = get_policy_path()?;
    let mut policy_manager = PolicyManager::new(policy_path)?;
    policy_manager.lock();
    policy_manager.save()?;

    println!("Agent locked. Use 'sss agent unlock' to unlock.");
    Ok(())
}

fn handle_unlock() -> Result<()> {
    println!("Unlocking agent...");

    // Load policy manager and unlock it
    let policy_path = get_policy_path()?;
    let mut policy_manager = PolicyManager::new(policy_path)?;
    policy_manager.unlock();
    policy_manager.save()?;

    println!("Agent unlocked");
    Ok(())
}

fn handle_policies(matches: &ArgMatches) -> Result<()> {
    match matches.subcommand() {
        Some(("list", _sub_m)) => handle_policies_list(),
        Some(("add", sub_m)) => handle_policies_add(sub_m),
        Some(("remove", sub_m)) => handle_policies_remove(sub_m),
        Some(("clear", _sub_m)) => handle_policies_clear(),
        _ => Err(anyhow!(
            "Unknown policies subcommand. Use 'sss agent policies --help' for usage."
        )),
    }
}

fn handle_policies_list() -> Result<()> {
    let policy_path = get_policy_path()?;
    let policy_manager = PolicyManager::new(policy_path)?;

    println!("Allowed hosts:");
    let allowed = policy_manager.list_allowed_hosts();
    if allowed.is_empty() {
        println!("  (none)");
    } else {
        for host in allowed {
            println!("  - {} (added: {:?})", host.hostname, host.added_at);
            if let Some(ref projects) = host.projects {
                for project in projects {
                    println!("    Project: {}", project);
                }
            }
        }
    }

    println!("\nBlocked hosts:");
    let blocked = policy_manager.list_blocked_hosts();
    if blocked.is_empty() {
        println!("  (none)");
    } else {
        for host in blocked {
            println!("  - {} (blocked: {:?})", host.hostname, host.blocked_at);
            println!("    Reason: {}", host.reason);
        }
    }

    Ok(())
}

fn handle_policies_add(matches: &ArgMatches) -> Result<()> {
    let hostname = matches
        .get_one::<String>("hostname")
        .ok_or_else(|| anyhow!("Hostname required"))?;

    let project = matches.get_one::<String>("project").cloned();

    let policy_path = get_policy_path()?;
    let mut policy_manager = PolicyManager::new(policy_path)?;

    policy_manager.add_allowed_host(hostname.clone(), project)?;
    policy_manager.save()?;

    println!("Added {} to allowed hosts", hostname);
    Ok(())
}

fn handle_policies_remove(matches: &ArgMatches) -> Result<()> {
    let hostname = matches
        .get_one::<String>("hostname")
        .ok_or_else(|| anyhow!("Hostname required"))?;

    let policy_path = get_policy_path()?;
    let mut policy_manager = PolicyManager::new(policy_path)?;

    // Try to remove from both allowed and blocked lists
    let mut removed = false;

    if policy_manager.remove_allowed_host(hostname).is_ok() {
        removed = true;
    }

    if policy_manager.remove_blocked_host(hostname).is_ok() {
        removed = true;
    }

    if removed {
        policy_manager.save()?;
        println!("Removed {} from policies", hostname);
        Ok(())
    } else {
        Err(anyhow!("Host {} not found in policies", hostname))
    }
}

fn handle_policies_clear() -> Result<()> {
    let policy_path = get_policy_path()?;
    let mut policy_manager = PolicyManager::new(policy_path)?;

    policy_manager.clear_all()?;

    println!("All policies cleared");
    Ok(())
}

fn get_policy_path() -> Result<PathBuf> {
    let home = std::env::var("HOME").map_err(|_| anyhow!("HOME environment variable not set"))?;

    #[cfg(target_os = "macos")]
    let config_dir = PathBuf::from(home)
        .join("Library")
        .join("Application Support")
        .join("sss");

    #[cfg(not(target_os = "macos"))]
    let config_dir = std::env::var("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(home).join(".config"))
        .join("sss");

    Ok(config_dir.join("agent-policy.toml"))
}
