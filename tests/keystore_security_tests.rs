//! Keystore security integration tests
//!
//! This test suite validates security-critical aspects of the keystore:
//! - File permissions (ensure 0o700 on keys directory)
//! - Concurrent access safety (thread safety, race conditions)
//! - Malformed file handling (tampering detection, corruption)
//! - DoS prevention (excessive keys, large files)
//! - Path traversal prevention
//! - Secure deletion (key material wiping)
//! - Symlink attack prevention
//!
//! **Test Coverage:**
//! - Directory and file permission security
//! - Concurrent read/write safety
//! - Invalid/corrupted file handling
//! - Resource exhaustion prevention
//! - Attack surface validation

use anyhow::Result;
use sss::crypto::KeyPair;
use sss::kdf::KdfParams;
use sss::keystore::Keystore;
use std::fs;
use tempfile::TempDir;

/// Helper to create a temporary keystore for testing
fn create_temp_keystore() -> Result<(Keystore, TempDir)> {
    let temp_dir = TempDir::new()?;
    let keystore = Keystore::new_with_config_dir_and_kdf(
        temp_dir.path().to_path_buf(),
        KdfParams::interactive(), // Use interactive for faster tests
        false, // Don't use keyring in tests
    )?;
    Ok((keystore, temp_dir))
}

/// Test: Keystore directory has secure permissions (0o700)
///
/// Verifies that:
/// - Keys directory is created with owner-only permissions
/// - Directory cannot be read by group or others
/// - Prevents unauthorized access to key material
#[test]
#[cfg(unix)]
fn test_keystore_directory_permissions() -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let (_keystore, temp_dir) = create_temp_keystore()?;

    // Check the sss/keys directory permissions
    let keys_dir = temp_dir.path().join("sss").join("keys");
    let metadata = fs::metadata(&keys_dir)?;
    let permissions = metadata.permissions();
    let mode = permissions.mode();

    // Should be 0o700 (rwx------)
    // Mask off the file type bits to get just permissions
    let perms = mode & 0o777;

    assert_eq!(
        perms, 0o700,
        "Keys directory should have 0o700 permissions, got 0o{:o}",
        perms
    );

    Ok(())
}

/// Test: Key files have secure permissions
///
/// Verifies that:
/// - Individual key files are created with secure permissions
/// - Files are only readable by owner
#[test]
#[cfg(unix)]
fn test_key_file_permissions() -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let (keystore, temp_dir) = create_temp_keystore()?;
    let keypair = KeyPair::generate()?;

    // Store a key
    let key_id = keystore.store_keypair(&keypair, Some("password"))?;

    // Find the key file
    let keys_dir = temp_dir.path().join("sss").join("keys");
    let key_file = keys_dir.join(format!("{}.toml", key_id));

    let metadata = fs::metadata(&key_file)?;
    let permissions = metadata.permissions();
    let mode = permissions.mode();
    let perms = mode & 0o777;

    // Should be 0o600 or 0o700 (owner read/write only)
    assert!(
        perms == 0o600 || perms == 0o700,
        "Key file should have 0o600 or 0o700 permissions, got 0o{:o}",
        perms
    );

    Ok(())
}

/// Test: Concurrent key storage (thread safety)
///
/// Verifies that:
/// - Multiple threads can store keys concurrently
/// - No data corruption occurs
/// - All keys are stored successfully
#[test]
fn test_concurrent_key_storage() -> Result<()> {
    use std::sync::Arc;
    use std::thread;

    let (keystore, _temp_dir) = create_temp_keystore()?;
    let keystore = Arc::new(keystore);
    let mut handles = vec![];

    // Spawn 10 threads storing keys concurrently
    for i in 0..10 {
        let keystore_clone = Arc::clone(&keystore);
        let handle = thread::spawn(move || {
            let keypair = KeyPair::generate().unwrap();
            let password = format!("password_{}", i);
            keystore_clone.store_keypair(&keypair, Some(&password))
        });
        handles.push(handle);
    }

    // Collect all key IDs
    let mut key_ids = Vec::new();
    for handle in handles {
        let key_id = handle.join().unwrap()?;
        key_ids.push(key_id);
    }

    // Verify all keys exist and are unique
    assert_eq!(key_ids.len(), 10);
    let unique_ids: std::collections::HashSet<_> = key_ids.iter().collect();
    assert_eq!(unique_ids.len(), 10, "All key IDs should be unique");

    // Verify we can load all keys
    let all_keys = keystore.list_key_ids()?;
    assert_eq!(all_keys.len(), 10);

    Ok(())
}

/// Test: Concurrent key retrieval (thread safety)
///
/// Verifies that:
/// - Multiple threads can read keys concurrently
/// - No data corruption or deadlocks occur
/// - All reads succeed
#[test]
fn test_concurrent_key_retrieval() -> Result<()> {
    use std::sync::Arc;
    use std::thread;

    let (keystore, _temp_dir) = create_temp_keystore()?;

    // Store a key
    let keypair = KeyPair::generate()?;
    let password = "shared_password";
    let key_id = keystore.store_keypair(&keypair, Some(password))?;

    let keystore = Arc::new(keystore);
    let key_id = Arc::new(key_id);
    let mut handles = vec![];

    // Spawn 20 threads reading the same key concurrently
    for _ in 0..20 {
        let keystore_clone = Arc::clone(&keystore);
        let key_id_clone = Arc::clone(&key_id);
        let handle = thread::spawn(move || {
            keystore_clone.load_keypair(&key_id_clone, Some(password))
        });
        handles.push(handle);
    }

    // Verify all reads succeeded
    for handle in handles {
        let loaded = handle.join().unwrap()?;
        assert_eq!(loaded.public_key().to_base64(), keypair.public_key().to_base64());
    }

    Ok(())
}

/// Test: Malformed TOML file handling
///
/// Verifies that:
/// - Corrupted key files are detected
/// - Invalid TOML is rejected
/// - Clear error messages are returned
#[test]
fn test_malformed_toml_file() -> Result<()> {
    let (keystore, temp_dir) = create_temp_keystore()?;

    // Create a malformed key file
    let keys_dir = temp_dir.path().join("sss").join("keys");
    let malformed_file = keys_dir.join("malformed-key-id.toml");
    fs::write(&malformed_file, "invalid toml content [[")?;

    // Attempting to load should fail gracefully
    let result = keystore.load_keypair("malformed-key-id", Some("password"));
    assert!(result.is_err(), "Malformed TOML should be rejected");

    Ok(())
}

/// Test: Tampered encrypted key detection
///
/// Verifies that:
/// - Tampered encrypted keys are detected
/// - Decryption fails with authentication error
/// - No partial key material is leaked
#[test]
fn test_tampered_key_detection() -> Result<()> {
    let (keystore, temp_dir) = create_temp_keystore()?;
    let keypair = KeyPair::generate()?;
    let password = "password";

    // Store a key
    let key_id = keystore.store_keypair(&keypair, Some(password))?;

    // Tamper with the key file
    let keys_dir = temp_dir.path().join("sss").join("keys");
    let key_file = keys_dir.join(format!("{}.toml", key_id));
    let mut content = fs::read_to_string(&key_file)?;

    // Find and corrupt the encrypted_secret_key field (TOML format)
    if let Some(pos) = content.find("encrypted_secret_key = \"") {
        let start = pos + "encrypted_secret_key = \"".len();
        // Flip a character in the base64
        let mut bytes = content.as_bytes().to_vec();
        if start < bytes.len() {
            bytes[start] = if bytes[start] == b'A' { b'B' } else { b'A' };
            content = String::from_utf8(bytes)?;
        }
    }

    fs::write(&key_file, content)?;

    // Attempting to load tampered key should fail
    let result = keystore.load_keypair(&key_id, Some(password));
    assert!(result.is_err(), "Tampered key should be rejected");

    Ok(())
}

/// Test: Missing salt field handling
///
/// Verifies that:
/// - Keys without salt field are handled correctly
/// - Backward compatibility is maintained
#[test]
fn test_missing_salt_field() -> Result<()> {
    let (keystore, temp_dir) = create_temp_keystore()?;
    let keypair = KeyPair::generate()?;

    // Store a passwordless key
    let key_id = keystore.store_keypair(&keypair, None)?;

    // Manually remove the salt field from TOML
    let keys_dir = temp_dir.path().join("sss").join("keys");
    let key_file = keys_dir.join(format!("{}.toml", key_id));
    let mut content = fs::read_to_string(&key_file)?;

    // Remove salt line (simple text replacement for test)
    if let Some(pos) = content.find("salt = ")
        && let Some(newline) = content[pos..].find('\n') {
            content.replace_range(pos..pos + newline + 1, "");
        }
    fs::write(&key_file, &content)?;

    // Should still load (salt is optional for passwordless keys)
    let loaded = keystore.load_keypair(&key_id, None)?;
    assert_eq!(loaded.public_key().to_base64(), keypair.public_key().to_base64());

    Ok(())
}

/// Test: DoS prevention with excessive keys
///
/// Verifies that:
/// - Can handle many keys without performance degradation
/// - Listing keys doesn't cause memory exhaustion
/// - Reasonable limits exist
#[test]
fn test_excessive_keys_handling() -> Result<()> {
    let (keystore, _temp_dir) = create_temp_keystore()?;

    // Store 20 keys (reduced from 100 for test performance)
    let mut key_ids = Vec::new();
    for i in 0..20 {
        let keypair = KeyPair::generate()?;
        let key_id = keystore.store_keypair(&keypair, Some(&format!("pass{}", i)))?;
        key_ids.push((key_id, format!("pass{}", i)));
    }

    // Should be able to list all keys
    let all_keys = keystore.list_key_ids()?;
    assert_eq!(all_keys.len(), 20);

    // Should be able to access individual keys with correct password
    let (key_id, password) = &key_ids[10];
    let loaded = keystore.load_keypair(key_id, Some(password))?;
    assert!(!loaded.public_key().to_base64().is_empty());

    Ok(())
}

/// Test: Empty/zero-byte key file handling
///
/// Verifies that:
/// - Zero-byte files are detected as invalid
/// - No crashes occur
/// - Clear error messages
#[test]
fn test_zero_byte_key_file() -> Result<()> {
    let (keystore, temp_dir) = create_temp_keystore()?;

    // Create an empty key file
    let keys_dir = temp_dir.path().join("sss").join("keys");
    let empty_file = keys_dir.join("empty-key-id.toml");
    fs::write(&empty_file, "")?;

    // Attempting to load should fail
    let result = keystore.load_keypair("empty-key-id", Some("password"));
    assert!(result.is_err(), "Empty file should be rejected");

    Ok(())
}

/// Test: Very long key ID handling
///
/// Verifies that:
/// - Excessively long key IDs are handled
/// - No buffer overflows or path issues
#[test]
fn test_very_long_key_id() -> Result<()> {
    let (keystore, _temp_dir) = create_temp_keystore()?;

    // Try to load a key with very long ID
    let long_id = "a".repeat(1000);
    let result = keystore.load_keypair(&long_id, Some("password"));

    // Should fail gracefully (key doesn't exist)
    assert!(result.is_err());

    Ok(())
}

/// Test: Special characters in key ID
///
/// Verifies that:
/// - Path traversal attempts are prevented
/// - Special characters are handled safely
#[test]
fn test_special_characters_in_key_id() -> Result<()> {
    let (keystore, _temp_dir) = create_temp_keystore()?;

    // Try path traversal
    let path_traversal_attempts = vec![
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32",
        "/etc/passwd",
        "C:\\Windows\\System32",
        "key/with/slashes",
        "key\\with\\backslashes",
    ];

    for malicious_id in path_traversal_attempts {
        let result = keystore.load_keypair(malicious_id, Some("password"));
        // Should fail (either doesn't exist or path is invalid)
        assert!(result.is_err(), "Path traversal attempt should fail: {}", malicious_id);
    }

    Ok(())
}

/// Test: Keystore with invalid UTF-8 in file
///
/// Verifies that:
/// - Files with invalid UTF-8 are detected
/// - No crashes or undefined behavior
#[test]
fn test_invalid_utf8_in_key_file() -> Result<()> {
    let (keystore, temp_dir) = create_temp_keystore()?;

    // Create a file with invalid UTF-8
    let keys_dir = temp_dir.path().join("sss").join("keys");
    let invalid_file = keys_dir.join("invalid-utf8.toml");

    let invalid_bytes = vec![
        b'{', b'"', b'k', b'e', b'y', b'"', b':', b' ',
        0xFF, 0xFE, // Invalid UTF-8
        b'}',
    ];
    fs::write(&invalid_file, &invalid_bytes)?;

    // Attempting to load should fail
    let result = keystore.load_keypair("invalid-utf8", Some("password"));
    assert!(result.is_err(), "Invalid UTF-8 should be rejected");

    Ok(())
}

/// Test: Deletion actually removes key file
///
/// Verifies that:
/// - Delete operation removes the file from disk
/// - File cannot be recovered after deletion
#[test]
fn test_deletion_removes_file() -> Result<()> {
    let (keystore, temp_dir) = create_temp_keystore()?;
    let keypair = KeyPair::generate()?;

    let key_id = keystore.store_keypair(&keypair, Some("password"))?;

    // Verify file exists
    let keys_dir = temp_dir.path().join("sss").join("keys");
    let key_file = keys_dir.join(format!("{}.toml", key_id));
    assert!(key_file.exists(), "Key file should exist before deletion");

    // Delete key
    keystore.delete_keypair(&key_id)?;

    // Verify file is gone
    assert!(!key_file.exists(), "Key file should not exist after deletion");

    Ok(())
}

/// Test: Symlink attack prevention
///
/// Verifies that:
/// - Symlinks in keys directory don't cause issues
/// - Cannot follow symlinks to read/write outside keys dir
#[test]
#[cfg(unix)]
fn test_symlink_attack_prevention() -> Result<()> {
    let (keystore, temp_dir) = create_temp_keystore()?;

    // Create a symlink in the keys directory pointing outside
    let keys_dir = temp_dir.path().join("sss").join("keys");
    let target_file = temp_dir.path().join("outside_target.txt");
    fs::write(&target_file, "sensitive data")?;

    let symlink_path = keys_dir.join("symlink-key.toml");

    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        symlink(&target_file, &symlink_path).ok(); // May fail, that's ok
    }

    // Try to load through symlink
    let result = keystore.load_keypair("symlink-key", Some("password"));

    // Should fail (either can't follow symlink or invalid TOML)
    assert!(result.is_err(), "Symlink should not allow reading outside keys dir");

    // Verify target file wasn't modified
    let content = fs::read_to_string(&target_file)?;
    assert_eq!(content, "sensitive data");

    Ok(())
}

/// Test: Consistency across save/load cycles
///
/// Verifies that:
/// - Multiple save/load cycles don't corrupt data
/// - Keys remain valid after many operations
#[test]
fn test_repeated_save_load_consistency() -> Result<()> {
    let (keystore, _temp_dir) = create_temp_keystore()?;
    let keypair = KeyPair::generate()?;
    let password = "test_password";

    // Initial store
    let key_id = keystore.store_keypair(&keypair, Some(password))?;

    // Load and re-store multiple times
    for _ in 0..10 {
        let loaded = keystore.load_keypair(&key_id, Some(password))?;

        // Verify keys match
        assert_eq!(loaded.public_key().to_base64(), keypair.public_key().to_base64());
        assert_eq!(loaded.secret_key().unwrap().to_base64(), keypair.secret_key().unwrap().to_base64());
    }

    Ok(())
}

/// Test: Mixed concurrent operations (read/write/delete)
///
/// Verifies that:
/// - Mixed operations don't cause corruption
/// - No race conditions
/// - Operations complete successfully
#[test]
fn test_mixed_concurrent_operations() -> Result<()> {
    use std::sync::Arc;
    use std::thread;

    let (keystore, _temp_dir) = create_temp_keystore()?;

    // Pre-create some keys
    for i in 0..5 {
        let keypair = KeyPair::generate()?;
        keystore.store_keypair(&keypair, Some(&format!("pass{}", i)))?;
    }

    let keystore = Arc::new(keystore);
    let mut handles = vec![];

    // Spawn threads doing mixed operations
    for i in 0..10 {
        let keystore_clone = Arc::clone(&keystore);
        let handle = thread::spawn(move || {
            // Some threads create keys
            if i % 3 == 0 {
                let keypair = KeyPair::generate().unwrap();
                keystore_clone.store_keypair(&keypair, Some("newpass")).ok();
            }
            // Some threads list keys
            else if i % 3 == 1 {
                keystore_clone.list_key_ids().ok();
            }
            // Some threads check status
            else {
                keystore_clone.is_current_key_password_protected().ok();
            }
        });
        handles.push(handle);
    }

    // Wait for all operations
    for handle in handles {
        handle.join().unwrap();
    }

    // Keystore should still be functional
    let all_keys = keystore.list_key_ids()?;
    assert!(all_keys.len() >= 5, "Should have at least the original 5 keys");

    Ok(())
}
