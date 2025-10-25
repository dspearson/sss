use anyhow::{anyhow, Result};
use std::path::{Path, PathBuf};

/// Detect if we're in a FUSE mount and get the underlying directory path
/// Returns None if not in a FUSE mount, or Some(path) with the /proc/PID/fd/FD path
fn detect_fuse_underlying_path() -> Result<Option<PathBuf>> {
    let cwd = std::env::current_dir()?;

    // Try to read .git/fd from cwd or ancestor directories
    for ancestor in cwd.ancestors() {
        let fd_file = ancestor.join(".git/fd");

        match std::fs::read_to_string(&fd_file) {
            Ok(content) => {
                // Got the fd number!
                let fd: i32 = content.trim().parse()
                    .map_err(|_| anyhow!("Invalid fd number in .git/fd: {}", content.trim()))?;

                // Find the FUSE server PID
                let pid = find_fuse_server_pid(fd, ancestor)?;

                // Calculate relative path from mount root to cwd
                let relative = cwd.strip_prefix(ancestor)
                    .unwrap_or(Path::new("."));

                // Construct underlying path: /proc/PID/fd/FD/relative/path
                let underlying = if relative == Path::new("") || relative == Path::new(".") {
                    PathBuf::from(format!("/proc/{}/fd/{}", pid, fd))
                } else {
                    PathBuf::from(format!("/proc/{}/fd/{}", pid, fd)).join(relative)
                };

                return Ok(Some(underlying));
            }
            Err(_) => continue, // Try next ancestor
        }
    }

    Ok(None) // Not in a FUSE mount
}

/// Find the FUSE server PID by checking which process has the given fd open
fn find_fuse_server_pid(fd: i32, _mount_root: &Path) -> Result<u32> {
    // Scan /proc/*/fd/{fd} to find which process has this fd open
    // This is the FUSE server process

    let proc_dir = std::fs::read_dir("/proc")
        .map_err(|e| anyhow!("Cannot read /proc: {}", e))?;

    for entry in proc_dir {
        let entry = entry?;
        let name = entry.file_name();
        let name_str = name.to_string_lossy();

        // Check if this is a numeric PID directory
        if let Ok(pid) = name_str.parse::<u32>() {
            // Check if this process has /proc/{pid}/fd/{fd}
            let fd_path = format!("/proc/{}/fd/{}", pid, fd);
            if Path::new(&fd_path).exists() {
                // Verify this is indeed a FUSE process by checking if it's holding
                // a directory fd (the mount point)
                if let Ok(metadata) = std::fs::metadata(&fd_path) {
                    if metadata.is_dir() {
                        return Ok(pid);
                    }
                }
            }
        }
    }

    Err(anyhow!("Could not find FUSE server PID for fd {}", fd))
}

/// Handle git command - runs git in underlying directory if in FUSE mount
pub fn handle_git(args: &[String]) -> Result<()> {
    // Check if we're in a FUSE mount
    let underlying_path = detect_fuse_underlying_path()?;

    let status = if let Some(underlying) = underlying_path {
        // We're in a FUSE mount - run git in the underlying directory
        eprintln!("sss: Running git in underlying directory");
        eprintln!("sss: Underlying path: {}", underlying.display());

        std::process::Command::new("git")
            .arg("-C")
            .arg(&underlying)
            .args(args)
            .status()
            .map_err(|e| anyhow!("Failed to execute git: {}", e))?
    } else {
        // Not in a FUSE mount - run git normally (passthrough)
        std::process::Command::new("git")
            .args(args)
            .status()
            .map_err(|e| anyhow!("Failed to execute git: {}", e))?
    };

    // Exit with git's exit code
    std::process::exit(status.code().unwrap_or(1));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_not_in_fuse() {
        // When not in a FUSE mount, should return None
        let result = detect_fuse_underlying_path();
        // This test passes if we're not in a FUSE mount
        // Can't assert much without setting up a real FUSE mount
        assert!(result.is_ok());
    }
}
