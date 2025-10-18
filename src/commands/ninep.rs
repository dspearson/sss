//! 9P server command handler
//!
//! Implements the `serve9p` command for starting a 9P filesystem server that
//! exposes an sss project with transparent encryption/decryption.

use anyhow::{anyhow, Result};
use clap::ArgMatches;
use std::path::PathBuf;

/// Handle the serve9p command
///
/// Starts a 9P2000.L server that exports the specified sss project directory
/// with transparent rendering of encrypted content.
///
/// # Arguments
///
/// * `matches` - Command-line arguments including:
///   - `address`: Listen address (tcp:host:port or unix:path)
///   - `directory`: Project directory to export (defaults to current directory)
///   - `user`: Username for authentication (optional)
///
/// # Example Usage
///
/// ```bash
/// # TCP server
/// sss serve9p tcp:0.0.0.0:564
///
/// # Unix socket server
/// sss serve9p unix:/tmp/sss-9p.sock
///
/// # Specify directory and user
/// sss serve9p tcp:localhost:5640 --directory /path/to/project --user alice
/// ```
pub fn handle_serve9p(matches: &ArgMatches) -> Result<()> {
    // Get listen address
    let address = matches
        .get_one::<String>("address")
        .ok_or_else(|| anyhow!("Address is required"))?;

    // Get directory (default to current directory)
    let directory = matches
        .get_one::<String>("directory")
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::current_dir().expect("Failed to get current directory"));

    // Get optional username
    let username = matches.get_one::<String>("user").cloned();

    // Check if directory exists
    if !directory.exists() {
        return Err(anyhow!("Directory does not exist: {:?}", directory));
    }

    if !directory.is_dir() {
        return Err(anyhow!("Path is not a directory: {:?}", directory));
    }

    // Canonicalize path
    let directory = directory.canonicalize()?;

    // Find and load project config
    let config_path = directory.join(".sss.toml");
    if !config_path.exists() {
        return Err(anyhow!("Not an sss project (no .sss.toml found)"));
    }
    let project_config = crate::project::ProjectConfig::load_from_file(&config_path)?;

    // Load user key
    let repo_key = if let Some(ref user) = username {
        crate::config::load_key_for_user(user)?
    } else {
        crate::config::load_key()?
    };

    // Create processor with project timestamp and root
    let processor = crate::Processor::new_with_context(
        repo_key,
        directory.clone(),
        project_config.created.clone(),
    )?;

    // Print startup info
    println!("sss 9P Server");
    println!("=============");
    println!("Export directory: {}", directory.display());
    println!("Listen address: {}", address);
    println!("Protocol: 9P2000.L");
    println!();
    println!("File access modes:");
    println!("  file         - Rendered view (fully decrypted, no markers)");
    println!("  file.open    - Opened view (with ⊕{{}} markers for editing)");
    println!("  file.sealed  - Sealed view (with ⊠{{}} markers as stored)");
    println!();
    println!("Mount with standard 9p clients:");
    println!("  # Linux (v9fs)");
    println!("  mount -t 9p -o trans=tcp,port=<port> <host> /mnt/project");
    println!();
    println!("  # Using 9pfuse (macOS/Linux)");
    println!("  9pfuse 'tcp!<host>!<port>' /mnt/project");
    println!();
    println!("Starting server...");

    // Start async runtime and serve
    serve_blocking(directory, processor, address)?;

    Ok(())
}

/// Blocking wrapper for async serve function
///
/// Creates a tokio runtime and runs the async 9P server to completion.
fn serve_blocking(directory: PathBuf, processor: crate::Processor, address: &str) -> Result<()> {
    use crate::SssNinepFS;
    use rs9p::srv::srv_async;

    // Create filesystem
    let fs = SssNinepFS::new(directory, processor)?;

    // Create tokio runtime
    let runtime = tokio::runtime::Runtime::new()?;

    // Run server
    runtime.block_on(async {
        srv_async(fs, address)
            .await
            .map_err(|e| anyhow!("Server error: {}", e))
    })?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serve_blocking_requires_ninep_feature() {
        // This module is only compiled when ninep feature is enabled
        // The 9P server functionality requires:
        // - Valid sss project directory with .sss.toml
        // - Network address (tcp:host:port or unix:path)
        // - User keypair for encryption/decryption
        // Full integration testing requires a running 9P server which is
        // handled in integration tests.
    }
}
