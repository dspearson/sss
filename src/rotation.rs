use anyhow::{anyhow, Result};
use chrono::Utc;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

use crate::{
    crypto::{seal_repository_key, PublicKey, RepositoryKey},
    processor::Processor,
    project::{ProjectConfig, UserConfig},
    scanner::{FileScanner, ScanResult},
};

/// Reason for key rotation
#[derive(Debug, Clone)]
pub enum RotationReason {
    UserRemoved(String),
    ManualRotation,
    SecurityIncident,
    ScheduledRotation,
}

impl std::fmt::Display for RotationReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UserRemoved(user) => write!(f, "User '{}' removed", user),
            Self::ManualRotation => write!(f, "Manual rotation"),
            Self::SecurityIncident => write!(f, "Security incident"),
            Self::ScheduledRotation => write!(f, "Scheduled rotation"),
        }
    }
}

/// Options for key rotation
#[derive(Debug, Default)]
pub struct RotationOptions {
    /// Skip creating backup before rotation
    pub no_backup: bool,
    /// Force rotation without confirmation
    pub force: bool,
    /// Dry run - show what would be done without making changes
    pub dry_run: bool,
    /// Show progress during rotation
    pub show_progress: bool,
}

/// Result of a key rotation operation
#[derive(Debug)]
pub struct RotationResult {
    pub reason: RotationReason,
    pub files_processed: usize,
    pub files_failed: usize,
    pub backup_path: Option<PathBuf>,
    pub duration: std::time::Duration,
    pub new_key_id: String,
}

impl RotationResult {
    pub fn print_summary(&self) {
        println!("✓ Key rotation completed successfully");
        println!("  Reason: {}", self.reason);
        println!("  Files processed: {}", self.files_processed);
        if self.files_failed > 0 {
            println!("  Files failed: {}", self.files_failed);
        }
        if let Some(ref backup_path) = self.backup_path {
            println!("  Backup created: {}", backup_path.display());
        }
        println!("  Duration: {:.2}s", self.duration.as_secs_f64());
        println!("  New key ID: {}...", &self.new_key_id[..16]);
    }
}

/// Key rotation orchestrator
pub struct RotationManager {
    options: RotationOptions,
}

impl RotationManager {
    pub fn new(options: RotationOptions) -> Self {
        Self { options }
    }

    /// Rotate repository key and re-encrypt all files
    pub fn rotate_repository_key(
        &self,
        config_path: &Path,
        current_repository_key: &RepositoryKey,
        reason: RotationReason,
    ) -> Result<RotationResult> {
        let start_time = Instant::now();

        if self.options.dry_run {
            return self.dry_run_rotation(config_path, reason);
        }

        println!("🔄 Starting key rotation...");
        println!("   Reason: {}", reason);

        // Step 1: Find all files with SSS patterns
        let scan_result =
            self.scan_repository_files(config_path.parent().unwrap_or(Path::new(".")))?;

        if scan_result.files_count() == 0 {
            println!("ℹ️  No files with SSS patterns found");
            return self.create_empty_rotation_result(reason, start_time);
        }

        println!(
            "📁 Found {} files with SSS patterns",
            scan_result.files_count()
        );

        // Step 2: Create backup if requested
        let backup_path = if !self.options.no_backup {
            Some(self.create_backup(&scan_result.files_with_patterns)?)
        } else {
            None
        };

        // Step 3: Generate new repository key
        let (old_key, new_key) = current_repository_key.rotate();
        let new_key_id = new_key.to_base64();

        println!("🔑 Generated new repository key");

        // Step 4: Re-encrypt all files
        let (files_processed, files_failed) =
            self.reencrypt_files(&scan_result.files_with_patterns, &old_key, &new_key)?;

        // Step 5: Update project configuration with new sealed keys
        self.update_project_config(config_path, &new_key, &reason)?;

        let duration = start_time.elapsed();

        let result = RotationResult {
            reason,
            files_processed,
            files_failed,
            backup_path: backup_path.clone(),
            duration,
            new_key_id,
        };

        if files_failed > 0 {
            println!("⚠️  {} files failed to re-encrypt", files_failed);
            if let Some(ref backup_path) = backup_path {
                println!(
                    "   Consider restoring from backup: {}",
                    backup_path.display()
                );
            }
        } else {
            println!("✅ All files successfully re-encrypted");
        }

        Ok(result)
    }

    /// Perform a dry run to show what would be done
    fn dry_run_rotation(
        &self,
        config_path: &Path,
        reason: RotationReason,
    ) -> Result<RotationResult> {
        let start_time = Instant::now();

        println!("🔍 Dry run: Scanning for files to rotate...");
        let scan_result =
            self.scan_repository_files(config_path.parent().unwrap_or(Path::new(".")))?;

        println!("📋 Dry run results:");
        println!("   Would rotate key due to: {}", reason);
        println!("   Would process {} files", scan_result.files_count());

        if !self.options.no_backup {
            println!(
                "   Would create backup of {} files",
                scan_result.files_count()
            );
        }

        // Load config to show users that would be updated
        let config = ProjectConfig::load_from_file(config_path)?;
        let user_count = config.users.len();
        println!("   Would update sealed keys for {} users", user_count);

        for username in config.list_users() {
            println!("     - {}", username);
        }

        Ok(RotationResult {
            reason,
            files_processed: scan_result.files_count(),
            files_failed: 0,
            backup_path: None,
            duration: start_time.elapsed(),
            new_key_id: "dry-run".to_string(),
        })
    }

    /// Scan repository for files containing SSS patterns
    fn scan_repository_files(&self, root_dir: &Path) -> Result<ScanResult> {
        if self.options.show_progress {
            println!("🔍 Scanning repository for encrypted files...");
        }

        let scanner = FileScanner::new();
        let scan_result = scanner.scan_with_stats(root_dir)?;

        if self.options.show_progress {
            scan_result.print_summary();
        }

        Ok(scan_result)
    }

    /// Create backup of files before rotation
    fn create_backup(&self, files: &[PathBuf]) -> Result<PathBuf> {
        if self.options.show_progress {
            println!("💾 Creating backup of {} files...", files.len());
        }

        let timestamp = Utc::now().format("%Y%m%d_%H%M%S").to_string();
        let backup_dir = PathBuf::from(format!(".sss_backup_{}", timestamp));

        fs::create_dir_all(&backup_dir)
            .map_err(|e| anyhow!("Failed to create backup directory: {}", e))?;

        for file_path in files {
            if let Some(file_name) = file_path.file_name() {
                let backup_file = backup_dir.join(file_name);
                fs::copy(file_path, &backup_file)
                    .map_err(|e| anyhow!("Failed to backup file {}: {}", file_path.display(), e))?;
            }
        }

        if self.options.show_progress {
            println!("💾 Backup created: {}", backup_dir.display());
        }

        Ok(backup_dir)
    }

    /// Re-encrypt files with new repository key
    fn reencrypt_files(
        &self,
        files: &[PathBuf],
        old_key: &RepositoryKey,
        new_key: &RepositoryKey,
    ) -> Result<(usize, usize)> {
        let mut files_processed = 0;
        let mut files_failed = 0;

        let old_processor = Processor::new((*old_key).clone())?;
        let new_processor = Processor::new((*new_key).clone())?;

        if self.options.show_progress {
            println!("🔄 Re-encrypting {} files...", files.len());
        }

        for (i, file_path) in files.iter().enumerate() {
            if self.options.show_progress {
                print!(
                    "\r🔄 Processing file {}/{}: {}",
                    i + 1,
                    files.len(),
                    file_path.display()
                );
                std::io::Write::flush(&mut std::io::stdout()).ok();
            }

            match self.reencrypt_single_file(file_path, &old_processor, &new_processor) {
                Ok(()) => files_processed += 1,
                Err(e) => {
                    eprintln!("\n❌ Failed to re-encrypt {}: {}", file_path.display(), e);
                    files_failed += 1;
                }
            }
        }

        if self.options.show_progress {
            println!(); // New line after progress
        }

        Ok((files_processed, files_failed))
    }

    /// Re-encrypt a single file
    fn reencrypt_single_file(
        &self,
        file_path: &Path,
        old_processor: &Processor,
        new_processor: &Processor,
    ) -> Result<()> {
        // Read and decrypt with old key
        let decrypted_content = old_processor.process_file(file_path)?;

        // Re-encrypt with new key
        let reencrypted_content = new_processor.process_content(&decrypted_content)?;

        // Write back to file
        fs::write(file_path, reencrypted_content).map_err(|e| {
            anyhow!(
                "Failed to write re-encrypted file {}: {}",
                file_path.display(),
                e
            )
        })?;

        Ok(())
    }

    /// Update project configuration with new sealed keys for all users
    fn update_project_config(
        &self,
        config_path: &Path,
        new_key: &RepositoryKey,
        reason: &RotationReason,
    ) -> Result<()> {
        if self.options.show_progress {
            println!("📝 Updating project configuration...");
        }

        let mut config = ProjectConfig::load_from_file(config_path)?;

        // Update rotation metadata
        config.update_rotation_metadata(reason.to_string());

        // Re-seal the new repository key for all users
        let mut updated_users = HashMap::new();

        for (username, user_config) in &config.users {
            let public_key = PublicKey::from_base64(&user_config.public)?;
            let sealed_key = seal_repository_key(new_key, &public_key)?;

            let updated_user_config = UserConfig {
                public: user_config.public.clone(),
                sealed_key,
                added: user_config.added.clone(),
            };

            updated_users.insert(username.clone(), updated_user_config);
        }

        config.users = updated_users;
        config.save_to_file(config_path)?;

        if self.options.show_progress {
            println!("📝 Updated sealed keys for {} users", config.users.len());
        }

        Ok(())
    }

    /// Create an empty rotation result (for when no files need processing)
    fn create_empty_rotation_result(
        &self,
        reason: RotationReason,
        start_time: Instant,
    ) -> Result<RotationResult> {
        Ok(RotationResult {
            reason,
            files_processed: 0,
            files_failed: 0,
            backup_path: None,
            duration: start_time.elapsed(),
            new_key_id: "no-files".to_string(),
        })
    }
}

/// Utility function to confirm rotation with user
pub fn confirm_rotation(reason: &RotationReason, force: bool) -> Result<bool> {
    if force {
        return Ok(true);
    }

    println!("⚠️  This will rotate the repository encryption key");
    println!("   Reason: {}", reason);
    println!("   All secrets will be re-encrypted with a new key");
    println!("   This operation cannot be undone without a backup");
    println!();

    print!("Continue? [y/N]: ");
    std::io::Write::flush(&mut std::io::stdout())?;

    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;

    let input = input.trim().to_lowercase();
    Ok(input == "y" || input == "yes")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rotation_reason_display() {
        let reason = RotationReason::UserRemoved("alice".to_string());
        assert_eq!(reason.to_string(), "User 'alice' removed");

        let reason = RotationReason::ManualRotation;
        assert_eq!(reason.to_string(), "Manual rotation");
    }

    #[test]
    fn test_rotation_options_default() {
        let options = RotationOptions::default();
        assert!(!options.no_backup);
        assert!(!options.force);
        assert!(!options.dry_run);
        assert!(!options.show_progress);
    }
}
