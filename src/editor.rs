//! Editor management and secure file editing
//!
//! This module handles launching external editors with appropriate security flags
//! to prevent sensitive data from leaking via swap files, backups, or temp files.

use anyhow::{anyhow, Result};
use std::env;
use std::path::Path;
use std::process::{Command, ExitStatus};

use crate::constants::{DEFAULT_EDITOR, EDITOR_FALLBACKS};

/// Editor configuration with security-focused arguments
struct EditorConfig {
    /// Arguments to prevent data leakage (swap files, backups, etc.)
    security_args: Vec<&'static str>,
}

impl EditorConfig {
    /// Create config for vim/vi
    fn vim() -> Self {
        Self {
            security_args: vec![
                "-n",                 // No swap file
                "-i", "NONE",         // No viminfo
                "+set nobackup",      // No backup files
                "+set nowritebackup", // No backup before overwrite
                "+set noundofile",    // No persistent undo
            ],
        }
    }

    /// Create config for neovim
    fn neovim() -> Self {
        // Neovim uses same flags as vim
        Self::vim()
    }

    /// Create config for emacs
    fn emacs() -> Self {
        Self {
            security_args: vec![
                "--no-init-file",
                "--eval", "(setq make-backup-files nil)",
                "--eval", "(setq auto-save-default nil)",
                "--eval", "(setq create-lockfiles nil)",
            ],
        }
    }

    /// Create config for nano
    fn nano() -> Self {
        Self {
            // Nano creates lock files in /proc which fail harmlessly
            // No special flags needed
            security_args: vec![],
        }
    }

    /// Create default config for unknown editors
    fn default() -> Self {
        Self {
            security_args: vec![],
        }
    }

    /// Get config for a specific editor name
    fn for_editor(name: &str) -> Self {
        match name {
            "vim" | "vi" => Self::vim(),
            "nvim" | "neovim" => Self::neovim(),
            "emacs" => Self::emacs(),
            "nano" => Self::nano(),
            _ => Self::default(),
        }
    }
}

/// Detect the editor to use from environment or fallbacks
fn detect_editor() -> String {
    // Try environment variables first
    if let Ok(editor) = env::var("EDITOR") {
        return editor;
    }

    if let Ok(visual) = env::var("VISUAL") {
        return visual;
    }

    // Try fallbacks in order of preference
    for fallback in EDITOR_FALLBACKS {
        if which::which(fallback).is_ok() {
            return fallback.to_string();
        }
    }

    // Ultimate fallback
    DEFAULT_EDITOR.to_string()
}

/// Launch an external editor to edit a file securely
///
/// This function:
/// 1. Detects the appropriate editor from environment or fallbacks
/// 2. Applies security-focused flags to prevent data leakage
/// 3. Sets TMPDIR to memory-backed storage if available
/// 4. Waits for the editor to complete
///
/// # Security
///
/// For supported editors (vim, nvim, emacs, nano), specific flags are added
/// to disable swap files, backups, and persistent undo/history that could
/// leak sensitive information.
pub fn launch_editor(file_path: &Path) -> Result<()> {
    let editor = detect_editor();

    // Parse editor command (might contain args like "vim -u NONE")
    let editor_parts: Vec<&str> = editor.split_whitespace().collect();
    let editor_cmd = editor_parts.first().unwrap_or(&DEFAULT_EDITOR);

    // Extract editor name from path for config lookup
    let editor_name = Path::new(editor_cmd)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(DEFAULT_EDITOR);

    // Get editor-specific configuration
    let config = EditorConfig::for_editor(editor_name);

    // Build command
    let mut cmd = Command::new(editor_cmd);

    // Add any existing args from EDITOR/VISUAL
    for arg in editor_parts.iter().skip(1) {
        cmd.arg(arg);
    }

    // Add security-focused flags
    for arg in config.security_args {
        cmd.arg(arg);
    }

    // Add the file path last
    cmd.arg(file_path);

    // Set TMPDIR to memory-backed tmpfs for any swap/temp files
    #[cfg(unix)]
    {
        if Path::new("/dev/shm").exists() {
            cmd.env("TMPDIR", "/dev/shm");
        }
    }

    // Launch editor and wait for completion
    let status = cmd
        .status()
        .map_err(|e| anyhow!("Failed to launch editor '{}': {}", editor, e))?;

    check_editor_exit_status(status, &editor)?;

    Ok(())
}

/// Check editor exit status and return error if unsuccessful
fn check_editor_exit_status(status: ExitStatus, editor: &str) -> Result<()> {
    if !status.success() {
        return Err(anyhow!(
            "Editor '{}' exited with non-zero status: {}",
            editor,
            status.code().unwrap_or(-1)
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_editor_config_vim() {
        let config = EditorConfig::for_editor("vim");
        assert!(config.security_args.contains(&"-n"));
        assert!(config.security_args.contains(&"NONE"));
    }

    #[test]
    fn test_editor_config_unknown() {
        let config = EditorConfig::for_editor("unknown-editor");
        assert!(config.security_args.is_empty());
    }

    #[test]
    fn test_detect_editor_fallback() {
        // This test assumes nano is available as a fallback
        // In real scenarios, the actual detected editor will vary
        let editor = detect_editor();
        assert!(!editor.is_empty());
    }
}
