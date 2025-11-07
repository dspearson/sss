use anyhow::{anyhow, Result};
use std::path::{Path, PathBuf};

/// Detect if we're in a FUSE mount and get the underlying directory path
/// Returns None if not in a FUSE mount, or Some(path) with the underlying path
fn detect_fuse_underlying_path() -> Result<Option<PathBuf>> {
    let cwd = std::env::current_dir()?;

    // Try to find .overlay/ from cwd or ancestor directories
    for ancestor in cwd.ancestors() {
        let overlay_dir = ancestor.join(".overlay");

        // Check if .overlay exists and is a directory
        if overlay_dir.exists() && overlay_dir.is_dir() {
            // Calculate relative path from mount root to cwd
            let relative = cwd.strip_prefix(ancestor)
                .unwrap_or(Path::new("."));

            // Construct underlying path: .overlay/relative/path
            let underlying = if relative == Path::new("") || relative == Path::new(".") {
                overlay_dir
            } else {
                overlay_dir.join(relative)
            };

            return Ok(Some(underlying));
        }
    }

    Ok(None) // Not in a FUSE mount
}

/// Handle git command - runs git in underlying directory if in FUSE mount
pub fn handle_git(args: &[String]) -> Result<()> {
    // Check if we're in a FUSE mount
    let underlying_path = detect_fuse_underlying_path()?;

    let status = if let Some(underlying) = underlying_path {
        // We're in a FUSE mount - run git in .overlay/ directory
        // .overlay/ provides raw passthrough access with no SSS processing
        eprintln!("sss: Running git in .overlay/ (raw passthrough directory)");
        eprintln!("sss: Directory: {}", underlying.display());

        std::process::Command::new("git")
            .current_dir(&underlying)
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
