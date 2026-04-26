#![allow(deprecated)]
//! Rotation module coverage expansion tests (TEST-03)
//!
//! Targets the 93.6% uncovered paths in src/rotation.rs that are NOT covered
//! by tests/rotation_security.rs:
//! - Old-key cryptographic invalidation after rotation (new key only)
//! - Multi-user rotation: verify both users can actually decrypt with new key
//! - Backup content is byte-identical to pre-rotation content
//! - Partial failure recovery: read-only file retains original; others rotate
//! - RotationResult field accuracy (duration > 0, exact counts)

use anyhow::Result;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use tempfile::TempDir;

use sss::crypto::{
    decrypt_from_base64, encrypt_to_base64, open_repository_key, seal_repository_key, KeyPair,
    RepositoryKey,
};
use sss::project::ProjectConfig;
use sss::rotation::{RotationManager, RotationOptions, RotationReason};

// ============================================================================
// Helper
// ============================================================================

/// Minimal .sss.toml content for a single-user project.
fn create_single_user_project(
    root: &std::path::Path,
    username: &str,
    keypair: &KeyPair,
    repo_key: &RepositoryKey,
) -> Result<PathBuf> {
    let config_path = root.join(".sss.toml");
    let mut config = ProjectConfig::new(username, &keypair.public_key())?;

    let sealed = seal_repository_key(repo_key, &keypair.public_key())?;
    if let Some(user) = config.users.get_mut(username) {
        user.sealed_key = sealed;
    }

    config.save_to_file(&config_path)?;
    Ok(config_path)
}

/// Write a file that contains an SSS sealed marker for `content`.
fn write_sealed_file(path: &std::path::Path, content: &str, key: &RepositoryKey) -> Result<()> {
    let encrypted = encrypt_to_base64(content, key)?;
    fs::write(path, format!("⊠{{{encrypted}}}"))?;
    Ok(())
}

/// Read the ciphertext from a file of the form `⊠{<b64>}`.
fn read_ciphertext(path: &std::path::Path) -> Result<String> {
    let raw = fs::read_to_string(path)?;
    // Strip the marker wrapper to get the raw base64 ciphertext
    let inner = raw
        .strip_prefix("⊠{")
        .and_then(|s| s.strip_suffix('}'))
        .ok_or_else(|| anyhow::anyhow!("File does not contain a ⊠{{}} marker: {raw}"))?;
    Ok(inner.to_string())
}

/// Convenience rotation options with no backup, force=true.
fn rotation_opts(no_backup: bool) -> RotationOptions {
    RotationOptions {
        no_backup,
        force: true,
        dry_run: false,
        show_progress: false,
    }
}

// ============================================================================
// Successful rotation — single user
// ============================================================================

/// Test: after rotation the new key decrypts the re-encrypted file and the old
/// key can no longer recover the plaintext.
#[test]
fn test_single_user_rotation_old_key_invalidated() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let root = temp_dir.path();

    let keypair = KeyPair::generate()?;
    let old_key = RepositoryKey::new();
    let config_path = create_single_user_project(root, "alice", &keypair, &old_key)?;

    let file_path = root.join("secrets.txt");
    let plaintext = "db_password = supersecret\n";
    write_sealed_file(&file_path, plaintext, &old_key)?;
    let original_ciphertext = fs::read_to_string(&file_path)?;

    let manager = RotationManager::new(rotation_opts(true));
    let result = manager.rotate_repository_key(&config_path, &old_key, RotationReason::ManualRotation)?;

    assert_eq!(result.files_processed, 1);
    assert_eq!(result.files_failed, 0);

    // Content changed after rotation
    let new_ciphertext = fs::read_to_string(&file_path)?;
    assert_ne!(
        original_ciphertext, new_ciphertext,
        "Ciphertext must change after rotation"
    );

    // New key (read from sealed key in updated config) can decrypt the new ciphertext
    let updated_config = ProjectConfig::load_from_file(&config_path)?;
    let user_sealed_key = updated_config
        .users
        .get("alice")
        .expect("alice must still exist")
        .sealed_key
        .clone();

    let new_repo_key = open_repository_key(&user_sealed_key, &keypair)?;
    let new_b64 = read_ciphertext(&file_path)?;
    let decrypted = decrypt_from_base64(&new_b64, &new_repo_key)?;
    assert_eq!(decrypted, plaintext, "New key must decrypt rotated content");

    // Old key must NOT recover the plaintext from the rotated ciphertext
    let old_b64 = read_ciphertext(&file_path)?;
    let old_attempt = decrypt_from_base64(&old_b64, &old_key);
    match old_attempt {
        Err(_) => {} // Expected: decryption fails
        Ok(content) => {
            assert!(
                !content.contains("supersecret"),
                "Old key must not recover plaintext from rotated ciphertext, got: {content}"
            );
        }
    }

    Ok(())
}

// ============================================================================
// Multi-user rotation
// ============================================================================

/// Test: rotate with two users — after rotation both users can open the new key
/// and decrypt the re-encrypted file.
#[test]
fn test_multi_user_rotation_both_users_can_decrypt() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let root = temp_dir.path();

    let kp_alice = KeyPair::generate()?;
    let kp_bob = KeyPair::generate()?;
    let old_key = RepositoryKey::new();

    // Create project with two users
    let config_path = root.join(".sss.toml");
    let mut config = ProjectConfig::new("alice", &kp_alice.public_key())?;
    config.add_user("bob", &kp_bob.public_key(), &old_key)?;

    // Seal old key for alice
    let sealed_alice = seal_repository_key(&old_key, &kp_alice.public_key())?;
    if let Some(u) = config.users.get_mut("alice") {
        u.sealed_key = sealed_alice;
    }
    config.save_to_file(&config_path)?;

    // Create a sealed file
    let file_path = root.join("shared_secret.txt");
    write_sealed_file(&file_path, "shared_token=abc123\n", &old_key)?;

    // Rotate
    let manager = RotationManager::new(rotation_opts(true));
    let result =
        manager.rotate_repository_key(&config_path, &old_key, RotationReason::ManualRotation)?;

    assert_eq!(result.files_processed, 1);
    assert_eq!(result.files_failed, 0);

    // Both alice and bob must be able to open the new sealed key and decrypt the file
    let updated_config = ProjectConfig::load_from_file(&config_path)?;
    assert_eq!(updated_config.users.len(), 2, "Both users must still be in config");

    for (username, kp) in [("alice", &kp_alice), ("bob", &kp_bob)] {
        let sealed = &updated_config
            .users
            .get(username)
            .unwrap_or_else(|| panic!("{username} must exist after rotation"))
            .sealed_key;

        let new_repo_key = open_repository_key(sealed, kp)
            .unwrap_or_else(|e| panic!("{username} must be able to open new sealed key: {e}"));

        let ciphertext_b64 = read_ciphertext(&file_path)?;
        let plaintext = decrypt_from_base64(&ciphertext_b64, &new_repo_key)
            .unwrap_or_else(|e| panic!("{username} must decrypt rotated file: {e}"));

        assert!(
            plaintext.contains("shared_token=abc123"),
            "{username} decrypted wrong content: {plaintext}"
        );
    }

    Ok(())
}

// ============================================================================
// Backup content integrity
// ============================================================================

/// Test: backup files are byte-identical to pre-rotation file content.
#[test]
fn test_backup_content_byte_identical_to_pre_rotation() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let root = temp_dir.path();

    let keypair = KeyPair::generate()?;
    let old_key = RepositoryKey::new();
    let config_path = create_single_user_project(root, "carol", &keypair, &old_key)?;

    // Write 3 sealed files and capture their pre-rotation content
    let mut pre_rotation_contents: Vec<(String, Vec<u8>)> = Vec::new();
    for i in 0..3 {
        let name = format!("file_{i}.txt");
        let path = root.join(&name);
        write_sealed_file(&path, &format!("secret_{i}"), &old_key)?;
        pre_rotation_contents.push((name, fs::read(&path)?));
    }

    let options = RotationOptions {
        no_backup: false,
        force: true,
        dry_run: false,
        show_progress: false,
    };
    let manager = RotationManager::new(options);
    let result =
        manager.rotate_repository_key(&config_path, &old_key, RotationReason::ManualRotation)?;

    let backup_path = result.backup_path.expect("backup must be created");
    assert!(backup_path.exists(), "backup directory must exist");

    // Every pre-rotation file must appear in the backup with identical bytes
    for (name, original_bytes) in &pre_rotation_contents {
        let backup_file = backup_path.join(name);
        assert!(
            backup_file.exists(),
            "backup must contain {name}"
        );
        let backup_bytes = fs::read(&backup_file)?;
        assert_eq!(
            backup_bytes, *original_bytes,
            "backup of {name} must be byte-identical to pre-rotation content"
        );
    }

    Ok(())
}

/// Test: RotationOptions { no_backup: true } does NOT create any backup directory.
#[test]
fn test_rotation_with_no_backup_creates_no_backup_dir() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let root = temp_dir.path();

    let keypair = KeyPair::generate()?;
    let old_key = RepositoryKey::new();
    let config_path = create_single_user_project(root, "dave", &keypair, &old_key)?;

    write_sealed_file(&root.join("data.txt"), "top_secret=xyz", &old_key)?;

    let manager = RotationManager::new(rotation_opts(true /* no_backup */));
    let result =
        manager.rotate_repository_key(&config_path, &old_key, RotationReason::ManualRotation)?;

    assert!(
        result.backup_path.is_none(),
        "backup_path must be None when no_backup=true"
    );

    // No .sss_backup_* directory should exist in root
    let backup_dirs: Vec<_> = fs::read_dir(root)?
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.file_name()
                .to_string_lossy()
                .starts_with(".sss_backup_")
        })
        .collect();

    assert!(
        backup_dirs.is_empty(),
        "No backup directory should be created when no_backup=true, found: {:?}",
        backup_dirs.iter().map(|e| e.file_name()).collect::<Vec<_>>()
    );

    Ok(())
}

// ============================================================================
// Partial failure recovery
// ============================================================================

/// Test: if one file is read-only (write fails), the rotation continues for the
/// other files, the read-only file keeps its old-key encryption, and the result
/// correctly records failures.
#[test]
fn test_partial_failure_read_only_file_retains_old_encryption() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let root = temp_dir.path();

    let keypair = KeyPair::generate()?;
    let old_key = RepositoryKey::new();
    let config_path = create_single_user_project(root, "eve", &keypair, &old_key)?;

    // 3 files: make the second one read-only to simulate a write failure
    let file_a = root.join("a.txt");
    let file_b = root.join("b.txt");
    let file_c = root.join("c.txt");

    write_sealed_file(&file_a, "secret_a", &old_key)?;
    write_sealed_file(&file_b, "secret_b", &old_key)?;
    write_sealed_file(&file_c, "secret_c", &old_key)?;

    let b_original_content = fs::read_to_string(&file_b)?;

    // Make file_b read-only so write fails during re-encryption
    let mut perms = fs::metadata(&file_b)?.permissions();
    perms.set_mode(0o444);
    fs::set_permissions(&file_b, perms.clone())?;

    let manager = RotationManager::new(rotation_opts(true));
    // Should NOT panic — partial failure is acceptable
    let result =
        manager.rotate_repository_key(&config_path, &old_key, RotationReason::ManualRotation);

    // Restore permissions for cleanup (tempfile TempDir requires write access)
    perms.set_mode(0o644);
    fs::set_permissions(&file_b, perms)?;

    match result {
        Ok(rotation_result) => {
            // At least one file must have failed (the read-only one)
            assert!(
                rotation_result.files_failed >= 1,
                "Expected at least 1 failed file, got: {}",
                rotation_result.files_failed
            );

            // The read-only file must NOT have been modified (old content preserved)
            let b_after = fs::read_to_string(&file_b)?;
            assert_eq!(
                b_after, b_original_content,
                "Read-only file must retain original encrypted content after partial failure"
            );
        }
        Err(_) => {
            // Acceptable: rotation may surface an error on partial failure.
            // Verify file_b still has its original content.
            let b_after = fs::read_to_string(&file_b)?;
            assert_eq!(
                b_after, b_original_content,
                "Read-only file must retain original content even when rotation returns Err"
            );
        }
    }

    Ok(())
}

// ============================================================================
// Empty project
// ============================================================================

/// Test: rotation on a project with zero sealed files completes successfully
/// with files_processed=0 and no errors.
#[test]
fn test_rotation_empty_project_zero_files_processed() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let root = temp_dir.path();

    let keypair = KeyPair::generate()?;
    let old_key = RepositoryKey::new();
    let config_path = create_single_user_project(root, "frank", &keypair, &old_key)?;

    // No sealed files — only the config exists

    let manager = RotationManager::new(rotation_opts(false));
    let result =
        manager.rotate_repository_key(&config_path, &old_key, RotationReason::ScheduledRotation)?;

    assert_eq!(result.files_processed, 0, "Zero files must be processed on empty project");
    assert_eq!(result.files_failed, 0, "Zero failures expected");
    // Key id is set to sentinel for the empty-project fast path
    assert_eq!(
        result.new_key_id, "no-files",
        "Empty project must return no-files sentinel"
    );

    Ok(())
}

// ============================================================================
// RotationResult field accuracy
// ============================================================================

/// Test: RotationResult fields (files_processed, files_failed, duration) are
/// populated correctly for a 3-file rotation.
#[test]
fn test_rotation_result_fields_accurate() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let root = temp_dir.path();

    let keypair = KeyPair::generate()?;
    let old_key = RepositoryKey::new();
    let config_path = create_single_user_project(root, "grace", &keypair, &old_key)?;

    for i in 0..3 {
        write_sealed_file(&root.join(format!("f{i}.txt")), &format!("val_{i}"), &old_key)?;
    }

    let manager = RotationManager::new(rotation_opts(true));
    let result =
        manager.rotate_repository_key(&config_path, &old_key, RotationReason::ManualRotation)?;

    assert_eq!(result.files_processed, 3, "All 3 files must be processed");
    assert_eq!(result.files_failed, 0, "No failures expected");
    assert!(
        result.duration.as_nanos() > 0,
        "Duration must be positive (got {:?})",
        result.duration
    );
    assert_ne!(
        result.new_key_id, "dry-run",
        "new_key_id must not be the dry-run sentinel"
    );
    assert_ne!(
        result.new_key_id, "no-files",
        "new_key_id must not be the no-files sentinel"
    );
    assert!(
        !result.new_key_id.is_empty(),
        "new_key_id must be populated"
    );

    Ok(())
}

// ============================================================================
// Bug-fix regression: .secrets file re-encryption and per-file nonce uniqueness
// ============================================================================

/// Regression: .secrets files must be re-encrypted (not written as plaintext)
/// after key rotation via RotationManager.
///
/// Previously RotationManager::reencrypt_single_file passed "<content>" as the
/// path to process_content, causing is_secrets_file to return false and the
/// decrypted plaintext to be written back without re-encryption.
#[test]
fn test_rotation_secrets_file_stays_encrypted() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let root = temp_dir.path();

    let keypair = KeyPair::generate()?;
    let old_key = RepositoryKey::new();
    let config_path = create_single_user_project(root, "alice", &keypair, &old_key)?;

    let secrets_path = root.join("app.secrets");
    let plaintext = "DB_PASSWORD=supersecret\nAPI_KEY=abc123\n";
    write_sealed_file(&secrets_path, plaintext, &old_key)?;

    // Verify sealed before rotation
    let before = fs::read_to_string(&secrets_path)?;
    assert!(before.trim().starts_with("⊠{"), "precondition: file must be sealed before rotation");

    let manager = RotationManager::new(rotation_opts(true));
    let result = manager.rotate_repository_key(&config_path, &old_key, RotationReason::ManualRotation)?;
    assert_eq!(result.files_processed, 1);
    assert_eq!(result.files_failed, 0);

    // Must still be encrypted — not plaintext — after rotation
    let after = fs::read_to_string(&secrets_path)?;
    assert!(
        after.trim().starts_with("⊠{"),
        "Secrets file must remain encrypted after rotation; got: {after:?}"
    );
    assert!(!after.contains("supersecret"), "Secret must not appear in plaintext after rotation");
    assert!(!after.contains("abc123"), "Secret must not appear in plaintext after rotation");

    // New key must decrypt the rotated file back to the original plaintext
    let updated_config = ProjectConfig::load_from_file(&config_path)?;
    let sealed_key = updated_config.users.get("alice").unwrap().sealed_key.clone();
    let new_repo_key = open_repository_key(&sealed_key, &keypair)?;
    let inner = after.trim()
        .strip_prefix("⊠{").unwrap()
        .strip_suffix('}').unwrap();
    let decrypted = decrypt_from_base64(inner, &new_repo_key)?;
    assert_eq!(decrypted, plaintext, "New key must recover original plaintext from rotated secrets file");

    Ok(())
}

/// Regression: after rotation, two different files containing the same secret
/// value must receive different ciphertexts (per-file nonce uniqueness).
///
/// Previously RotationManager::reencrypt_single_file passed "<content>" as the
/// path, so both files shared the same nonce derivation inputs and produced
/// identical ciphertexts for identical plaintexts.
#[test]
fn test_rotation_per_file_nonce_uniqueness() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let root = temp_dir.path();

    let keypair = KeyPair::generate()?;
    let old_key = RepositoryKey::new();
    let config_path = create_single_user_project(root, "bob", &keypair, &old_key)?;

    let shared_secret = "shared_password_value";
    write_sealed_file(&root.join("file_a.txt"), shared_secret, &old_key)?;
    write_sealed_file(&root.join("file_b.txt"), shared_secret, &old_key)?;

    let manager = RotationManager::new(rotation_opts(true));
    let result = manager.rotate_repository_key(&config_path, &old_key, RotationReason::ManualRotation)?;
    assert_eq!(result.files_processed, 2);

    let ct_a = fs::read_to_string(root.join("file_a.txt"))?;
    let ct_b = fs::read_to_string(root.join("file_b.txt"))?;
    assert_ne!(
        ct_a, ct_b,
        "Different files with the same secret must have different ciphertexts after rotation"
    );

    Ok(())
}
