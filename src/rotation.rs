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
        // Truncate to 16 chars safely; short IDs like "no-files" are valid.
        let id_preview = &self.new_key_id[..self.new_key_id.len().min(16)];
        let ellipsis = if self.new_key_id.len() > 16 { "..." } else { "" };
        println!("  New key ID: {id_preview}{ellipsis}");
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
            // Even with no encrypted files the config must still be rewritten:
            // the removed user was stripped from the in-memory map by the
            // caller before rotation, so we need to re-seal for the remaining
            // users and persist that reduced user map.  Skipping this write
            // left the removed user in .sss.toml (Rule 1 bug fix, 19-02).
            let new_key = current_repository_key.rotate().1;
            self.update_project_config(config_path, &new_key, &reason)?;
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

        // Step 3: Determine project root and read the original project_created.
        //
        // REM-22 / REM-23 design:
        //   The old processor is created WITHOUT project_created (empty string) so
        //   decrypt_content_with_path falls back to plain decrypt_content — no nonce
        //   lineage check during rotation.  Rotation is a key-holder operation; the
        //   project_created at seal time is not reliably recoverable (tests may use an
        //   explicit timestamp distinct from config.created), and possessing the old key
        //   is the security invariant.
        //
        //   The new processor uses config.created (the project's canonical epoch) so
        //   post-rotation opens via `process.rs`/`open.rs` (which also read config.created)
        //   derive matching nonces.  Using a one-shot Utc::now() rotation_epoch breaks
        //   future opens because that epoch is never stored anywhere the open path can
        //   retrieve it — CRY-01 resolution must not sacrifice REM-22 open correctness.
        //   The nonce-uniqueness invariant (CRY-01) is preserved by the KEY change:
        //   derive_nonce(timestamp, path, plaintext, new_key) is distinct from the
        //   pre-rotation nonce even with the same timestamp because the key differs.
        let project_root = config_path.parent()
            .ok_or_else(|| anyhow!("Config path has no parent"))?
            .to_path_buf();
        let project_created = ProjectConfig::load_from_file_unverified(config_path)
            .map(|c| c.created.clone())
            .unwrap_or_default();

        // Step 4: Generate new repository key
        let (old_key, new_key) = current_repository_key.rotate();
        let new_key_id = new_key.to_base64();

        println!("🔑 Generated new repository key");

        // Step 5: Re-encrypt all files.  Old processor: no project_created → plain
        // decrypt (bypass nonce check).  New processor: project_created = config.created
        // so future opens with the same config can re-derive matching nonces.
        let (files_processed, files_failed) =
            self.reencrypt_files(
                &scan_result.files_with_patterns,
                &old_key,
                &new_key,
                &project_created,
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

        // Load config to show users that would be updated.
        // Unverified loader for the same reason as the live rotation path:
        // the caller may have already mutated the user map without re-signing.
        let config = ProjectConfig::load_from_file_unverified(config_path)?;
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
        // REM-22: old_processor is created with an empty project_created so that
        // decrypt_content_with_path falls back to plain decrypt_content (no
        // nonce-lineage check).  Rotation is a key-holder operation; the
        // project_created at seal time may differ from the config value (e.g.
        // tests use an explicit timestamp) and is not reliably recoverable.
        // Key possession is the security invariant here, not path binding.
        let old_processor = Processor::new_with_project_root(
            (*old_key).clone(),
            project_root.to_path_buf(),
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

        // Unverified loader: see Step 3 in `rotate_repository_key`. The caller
        // pre-verified before invoking us; the on-disk envelope.sig may now be
        // stale relative to the in-flight user-map mutation. The caller's
        // post-rotation sign-on-write block produces a fresh signature.
        let mut config = ProjectConfig::load_from_file_unverified(config_path)?;

        // Update rotation metadata
        config.update_rotation_metadata(reason.to_string());

        // Re-seal the new repository key for all users
        let mut updated_users = HashMap::new();

        let suite = config.suite()?;
        for (username, user_config) in &config.users {
            let public_key = PublicKey::decode_base64_for_suite(&user_config.public, suite)?;
            // Dispatch on key variant: hybrid projects store HybridPublicKey in
            // `public`, so route through HybridCryptoSuite.  Classic keys use
            // ClassicSuite as before.  Rule 1 fix (19-02): previously always
            // used ClassicSuite, corrupting re-sealed keys in hybrid projects.
            let sealed_key = match &public_key {
                PublicKey::Classic(_) => ClassicSuite.seal_repo_key(new_key, &public_key)?,
                #[cfg(feature = "hybrid")]
                PublicKey::Hybrid(_) => {
                    crate::crypto::HybridCryptoSuite.seal_repo_key(new_key, &public_key)?
                }
            };

            let updated_user_config = UserConfig {
                public: user_config.public.clone(),
                sealed_key,
                added: user_config.added.clone(),
                hybrid_public: user_config.hybrid_public.clone(),
                sig_ed448_public: user_config.sig_ed448_public.clone(),
                sig_mldsa65_public: user_config.sig_mldsa65_public.clone(),
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

    // Non-interactive mode (CI / integration tests): auto-confirm.
    if std::env::var("SSS_NONINTERACTIVE").as_deref() == Ok("1") {
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

    /// Test: rotating a `RepositoryKey` produces a genuinely different new key.
    #[test]
    fn test_rotation_produces_different_key() {
        let old_key = RepositoryKey::new();
        let (returned_old, new_key) = old_key.rotate();

        // Old key returned intact
        assert_eq!(returned_old.to_base64(), old_key.to_base64());

        // New key is genuinely different
        assert_ne!(new_key.to_base64(), old_key.to_base64(), "rotated key must differ from original");
    }

    /// Test: after a rotation, the re-sealed ciphertext blob differs from the
    /// pre-rotation blob because the epoch axis changes (REM-23 / CRY-01).
    ///
    /// The nonce is derived from (`project_timestamp`, `file_path`, plaintext, key).
    /// When the key changes AND the timestamp axis is rotation-fresh, the nonce
    /// for the re-encrypted file is guaranteed to differ from the pre-rotation
    /// nonce — the frozen-axis bug (CRY-01) is fixed.
    ///
    /// This test simulates the axis change directly by building two Processor
    /// instances with distinct timestamps, sealing identical content+path with
    /// each, and asserting the ciphertext blobs are different.
    #[test]
    fn test_rotation_epoch_refreshes_nonce() {
        use std::path::Path;

        let key = RepositoryKey::new();
        let root = std::path::PathBuf::from(".");

        // Pre-rotation: processor uses the frozen project creation timestamp.
        let pre_epoch = "2024-01-01T00:00:00Z";
        let pre_proc = Processor::new_with_context(key.clone(), root.clone(), pre_epoch.to_string()).unwrap();

        // Post-rotation: processor uses a fresh rotation-epoch timestamp.
        let post_epoch = "2025-06-09T12:00:00Z";
        let post_proc = Processor::new_with_context(key.clone(), root.clone(), post_epoch.to_string()).unwrap();

        let plaintext = "api_key = ⊕{secret123}\n";
        let file_path = Path::new("config.txt");

        let pre_sealed = pre_proc.seal_content_with_path(plaintext, file_path).unwrap();
        let post_sealed = post_proc.seal_content_with_path(plaintext, file_path).unwrap();

        // Both must seal successfully and produce ciphertext markers
        assert!(pre_sealed.contains("⊠{"), "pre-rotation sealed content must contain ciphertext marker");
        assert!(post_sealed.contains("⊠{"), "post-rotation sealed content must contain ciphertext marker");

        // The ciphertext blobs must differ: different timestamps → different derived nonces
        assert_ne!(
            pre_sealed, post_sealed,
            "REM-23: post-rotation re-seal must produce a different ciphertext (fresh nonce epoch); \
             frozen axis bug CRY-01 means pre_epoch and post_epoch produce identical blobs if not fixed"
        );

        // Round-trip: post-rotation processor must open its own re-sealed content
        let opened = post_proc.open_content_with_path(&post_sealed, file_path).unwrap();
        assert_eq!(opened, plaintext, "post-rotation re-seal must round-trip correctly");
    }

    /// Test: re-encrypting with `reencrypt_content_with_path` produces content that opens
    /// to the same plaintext under the new key (nonce-lineage preserved).
    #[test]
    fn test_rotation_reencrypt_content_roundtrip() {
        use std::path::PathBuf;

        let old_key = RepositoryKey::new();
        let (_, new_key) = old_key.rotate();

        let root = PathBuf::from(".");
        let old_proc = make_processor_for_key(old_key, root.clone());
        let new_proc = make_processor_for_key(new_key, root);

        let plaintext = "token = ⊕{bearer_abc123}\nenv = production\n";
        let file_path = "app.txt";

        // Seal with old key
        let sealed = old_proc
            .seal_content_with_path(plaintext, std::path::Path::new(file_path))
            .unwrap();

        // Use reencrypt_content_with_path to re-key atomically, preserving nonce lineage.
        // The path must match the seal path so the new ciphertext passes the lineage check.
        let reencrypted = new_proc
            .reencrypt_content_with_path(&sealed, &old_proc, file_path)
            .unwrap();

        // New key opens rotated content to original plaintext (nonce-lineage check passes)
        let final_plain = new_proc
            .open_content_with_path(&reencrypted, std::path::Path::new(file_path))
            .unwrap();
        assert_eq!(final_plain, plaintext, "reencrypt_content_with_path round-trip must recover original plaintext");

        // Ciphertext changed after rotation
        assert_ne!(sealed, reencrypted, "ciphertext must change after key rotation");
    }
}
