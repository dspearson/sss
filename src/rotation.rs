#![allow(
    clippy::missing_errors_doc,
    clippy::struct_excessive_bools, // RotationOptions bools match distinct orthogonal flags
    clippy::unused_self,            // self kept for future extensibility in rotation methods
    clippy::unnecessary_wraps,      // create_empty_rotation_result may error in future
)]

use anyhow::{anyhow, Result};
use chrono::Utc;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

use crate::{
    crypto::{ClassicSuite, CryptoSuite, PublicKey, RepositoryKey},
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
            Self::UserRemoved(user) => write!(f, "User '{user}' removed"),
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
    #[must_use] 
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
        println!("   Reason: {reason}");

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
        let backup_path = if self.options.no_backup {
            None
        } else {
            Some(self.create_backup(&scan_result.files_with_patterns)?)
        };

        // Step 3: Load project config for timestamp
        let project_config = ProjectConfig::load_from_file(config_path)?;
        let project_root = config_path.parent()
            .ok_or_else(|| anyhow!("Config path has no parent"))?
            .to_path_buf();

        // Step 4: Generate new repository key
        let (old_key, new_key) = current_repository_key.rotate();
        let new_key_id = new_key.to_base64();

        println!("🔑 Generated new repository key");

        // Step 5: Re-encrypt all files
        let (files_processed, files_failed) =
            self.reencrypt_files(
                &scan_result.files_with_patterns,
                &old_key,
                &new_key,
                &project_config.created,
                &project_root,
            )?;

        // Step 6: Update project configuration with new sealed keys
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
            println!("⚠️  {files_failed} files failed to re-encrypt");
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
        println!("   Would rotate key due to: {reason}");
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
        println!("   Would update sealed keys for {user_count} users");

        for username in config.list_users() {
            println!("     - {username}");
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

        let scanner = FileScanner::new().with_project_boundaries(true);
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
        let backup_dir = PathBuf::from(format!(".sss_backup_{timestamp}"));

        fs::create_dir_all(&backup_dir)
            .map_err(|e| anyhow!("Failed to create backup directory: {e}"))?;

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
        project_timestamp: &str,
        project_root: &Path,
    ) -> Result<(usize, usize)> {
        let old_processor = Processor::new_with_context(
            (*old_key).clone(),
            project_root.to_path_buf(),
            project_timestamp.to_string(),
        )?;
        let new_processor = Processor::new_with_context(
            (*new_key).clone(),
            project_root.to_path_buf(),
            project_timestamp.to_string(),
        )?;

        if self.options.show_progress {
            println!("🔄 Re-encrypting {} files...", files.len());
        }

        let show_progress = self.options.show_progress;
        let total = files.len();
        let (files_processed, files_failed) = new_processor.reencrypt_files_batch(
            files,
            &old_processor,
            |i, _, file_path| {
                if show_progress {
                    print!("\r🔄 Processing file {i}/{total}: {}", file_path.display());
                    std::io::Write::flush(&mut std::io::stdout()).ok();
                }
            },
        )?;

        if self.options.show_progress {
            println!();
        }

        Ok((files_processed, files_failed))
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
            let sealed_key = ClassicSuite.seal_repo_key(new_key, &public_key)?;

            let updated_user_config = UserConfig {
                public: user_config.public.clone(),
                sealed_key,
                added: user_config.added.clone(),
                hybrid_public: user_config.hybrid_public.clone(),
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
    println!("   Reason: {reason}");
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

    // =========================================================================
    // Rotation correctness tests (CORR-03)
    // =========================================================================

    /// Generate a processor for use in rotation tests.
    fn make_processor_for_key(key: RepositoryKey, root: std::path::PathBuf) -> Processor {
        Processor::new_with_context(key, root, "2025-06-01T00:00:00Z".to_string()).unwrap()
    }

    /// Test: re-encrypting content with a new key produces content that the new
    /// key can decrypt, and the old key cannot.
    #[test]
    fn test_rotation_reencrypt_old_key_invalidated() {
        use std::path::PathBuf;

        let old_key = RepositoryKey::new();
        let new_key = RepositoryKey::new();

        let root = PathBuf::from(".");
        let old_proc = make_processor_for_key(old_key.clone(), root.clone());
        let new_proc = make_processor_for_key(new_key.clone(), root.clone());

        // Seal with old key
        let plaintext = "password = ⊕{topsecret}\nuser = admin\n";
        let sealed_old = old_proc
            .seal_content_with_path(plaintext, std::path::Path::new("config.txt"))
            .unwrap();
        assert!(sealed_old.contains("⊠{"), "old sealed content must contain ciphertext marker");

        // Re-encrypt: decrypt with old key, then encrypt with new key
        let decrypted = old_proc
            .open_content_with_path(&sealed_old, std::path::Path::new("config.txt"))
            .unwrap();
        assert_eq!(decrypted, plaintext, "old key must decrypt original plaintext");

        let sealed_new = new_proc
            .seal_content_with_path(&decrypted, std::path::Path::new("config.txt"))
            .unwrap();

        // New key can open the rotated content
        let opened_with_new = new_proc
            .open_content_with_path(&sealed_new, std::path::Path::new("config.txt"))
            .unwrap();
        assert_eq!(opened_with_new, plaintext, "new key must decrypt rotated content");

        // Old key cannot open the new ciphertext (should return error or corrupted plaintext)
        let old_attempt = old_proc.open_content_with_path(&sealed_new, std::path::Path::new("config.txt"));
        // The old processor will fail to decrypt the new ciphertext (returns a warning and keeps marker)
        // Either it returns Err or it returns the unchanged ciphertext marker (not the plaintext)
        match old_attempt {
            Err(_) => {} // hard error is fine
            Ok(content) => {
                // Must NOT produce the original plaintext
                assert!(
                    !content.contains("topsecret"),
                    "old key must not recover plaintext from rotated ciphertext, got: {content}"
                );
            }
        }
    }

    /// Test: rotating a RepositoryKey produces a genuinely different new key.
    #[test]
    fn test_rotation_produces_different_key() {
        let old_key = RepositoryKey::new();
        let (returned_old, new_key) = old_key.rotate();

        // Old key returned intact
        assert_eq!(returned_old.to_base64(), old_key.to_base64());

        // New key is genuinely different
        assert_ne!(new_key.to_base64(), old_key.to_base64(), "rotated key must differ from original");
    }

    /// Test: re-encrypting with reencrypt_content produces content that opens
    /// to the same plaintext under the new key.
    #[test]
    fn test_rotation_reencrypt_content_roundtrip() {
        use std::path::PathBuf;

        let old_key = RepositoryKey::new();
        let (_, new_key) = old_key.rotate();

        let root = PathBuf::from(".");
        let old_proc = make_processor_for_key(old_key, root.clone());
        let new_proc = make_processor_for_key(new_key, root);

        let plaintext = "token = ⊕{bearer_abc123}\nenv = production\n";

        // Seal with old key
        let sealed = old_proc
            .seal_content_with_path(plaintext, std::path::Path::new("app.txt"))
            .unwrap();

        // Use reencrypt_content to re-key atomically
        let reencrypted = new_proc.reencrypt_content(&sealed, &old_proc).unwrap();

        // New key opens rotated content to original plaintext
        let final_plain = new_proc
            .open_content_with_path(&reencrypted, std::path::Path::new("app.txt"))
            .unwrap();
        assert_eq!(final_plain, plaintext, "reencrypt_content round-trip must recover original plaintext");

        // Ciphertext changed after rotation
        assert_ne!(sealed, reencrypted, "ciphertext must change after key rotation");
    }
}
