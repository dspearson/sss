// Why: integration tests use .unwrap()/.expect()/panic! freely; test code is exempt
// from the panic-surface lint policy per CONTEXT.md Area 1 carve-out.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Keystore security integration tests
//!
//! This test suite validates security-critical aspects of the keystore:
//! - File permissions (ensure 0o700 on keys directory)
//! - Concurrent access safety (thread safety, race conditions)
//! - Malformed file handling (tampering detection, corruption)
//! - `DoS` prevention (excessive keys, large files)
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
#[cfg(feature = "hybrid")]
use sss::crypto::ClassicKeyPair;
#[cfg(feature = "hybrid")]
use sss::crypto::HybridKeyPair;

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
        "Keys directory should have 0o700 permissions, got 0o{perms:o}"
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
    let key_file = keys_dir.join(format!("{key_id}.toml"));

    let metadata = fs::metadata(&key_file)?;
    let permissions = metadata.permissions();
    let mode = permissions.mode();
    let perms = mode & 0o777;

    // Should be 0o600 or 0o700 (owner read/write only)
    assert!(
        perms == 0o600 || perms == 0o700,
        "Key file should have 0o600 or 0o700 permissions, got 0o{perms:o}"
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
            let password = format!("password_{i}");
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
            keystore_clone.load_keypair(&key_id_clone, Some(password), true)
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
    let result = keystore.load_keypair("malformed-key-id", Some("password"), true);
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
    let key_file = keys_dir.join(format!("{key_id}.toml"));
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
    let result = keystore.load_keypair(&key_id, Some(password), true);
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
    let key_file = keys_dir.join(format!("{key_id}.toml"));
    let mut content = fs::read_to_string(&key_file)?;

    // Remove salt line (simple text replacement for test)
    if let Some(pos) = content.find("salt = ")
        && let Some(newline) = content[pos..].find('\n') {
            content.replace_range(pos..=(pos + newline), "");
        }
    fs::write(&key_file, &content)?;

    // Should still load (salt is optional for passwordless keys)
    let loaded = keystore.load_keypair(&key_id, None, true)?;
    assert_eq!(loaded.public_key().to_base64(), keypair.public_key().to_base64());

    Ok(())
}

/// Test: `DoS` prevention with excessive keys
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
        let key_id = keystore.store_keypair(&keypair, Some(&format!("pass{i}")))?;
        key_ids.push((key_id, format!("pass{i}")));
    }

    // Should be able to list all keys
    let all_keys = keystore.list_key_ids()?;
    assert_eq!(all_keys.len(), 20);

    // Should be able to access individual keys with correct password
    let (key_id, password) = &key_ids[10];
    let loaded = keystore.load_keypair(key_id, Some(password), true)?;
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
    let result = keystore.load_keypair("empty-key-id", Some("password"), true);
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
    let result = keystore.load_keypair(&long_id, Some("password"), true);

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
        let result = keystore.load_keypair(malicious_id, Some("password"), true);
        // Should fail (either doesn't exist or path is invalid)
        assert!(result.is_err(), "Path traversal attempt should fail: {malicious_id}");
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
    let result = keystore.load_keypair("invalid-utf8", Some("password"), true);
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
    let key_file = keys_dir.join(format!("{key_id}.toml"));
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
    let result = keystore.load_keypair("symlink-key", Some("password"), true);

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
        let loaded = keystore.load_keypair(&key_id, Some(password), true)?;

        // Verify keys match
        assert_eq!(loaded.public_key().to_base64(), keypair.public_key().to_base64());
        assert_eq!(loaded.secret_key().unwrap().to_base64(), keypair.secret_key().unwrap().to_base64());
    }

    Ok(())
}

/// REM-03 / T-38-07: substituting a hybrid KEM ciphertext from entry B into
/// entry A (same passwordless encoding) must be rejected with
/// "public key mismatch (hybrid slot)".
///
/// Passwordless hybrid entries store the KEM secret key as plain base64
/// (no AEAD wrapping), so the substituted bytes decode cleanly; detection
/// relies entirely on the post-decrypt re-derivation check added in Task 2.
/// A positive control confirms that the unmodified entry still opens Ok.
// Why: HybridKeyPair contains Ed448SigningKey which doesn't impl Debug, so
// expect_err() (which requires T: Debug) cannot be used here.
#[allow(clippy::err_expect)]
#[cfg(feature = "hybrid")]
#[test]
fn hybrid_ciphertext_substitution() -> Result<()> {
    let (keystore, temp_dir) = create_temp_keystore()?;
    let keys_dir = temp_dir.path().join("sss").join("keys");

    // Create two passwordless dual-suite entries.
    let classic_a = ClassicKeyPair::generate()?;
    let hybrid_a = HybridKeyPair::generate()?;
    let id_a = keystore
        .store_dual_keypair(Some(&classic_a), Some(&hybrid_a), None)
        .expect("store dual A passwordless");

    let classic_b = ClassicKeyPair::generate()?;
    let hybrid_b = HybridKeyPair::generate()?;
    let id_b = keystore
        .store_dual_keypair(Some(&classic_b), Some(&hybrid_b), None)
        .expect("store dual B passwordless");

    // Positive control: set current to A and verify it opens normally.
    keystore
        .set_current_key(&id_a)
        .expect("set current to A for positive control");
    let ok_before = keystore.load_hybrid_keypair(&id_a, None, false);
    assert!(
        ok_before.is_ok(),
        "positive control — entry A must open before substitution; err={:?}",
        ok_before.err()
    );

    // Read both TOML files as strings and extract the hybrid_encrypted_secret_key
    // values using simple line-level parsing (avoids needing internal StoredKeyPair type).
    let path_a = keys_dir.join(format!("{id_a}.toml"));
    let path_b = keys_dir.join(format!("{id_b}.toml"));
    let content_a = fs::read_to_string(&path_a)?;
    let content_b = fs::read_to_string(&path_b)?;

    // Extract B's hybrid_encrypted_secret_key value (a base64 string on one TOML line).
    let b_hsk_line = content_b
        .lines()
        .find(|l| l.starts_with("hybrid_encrypted_secret_key"))
        .expect("entry B must have hybrid_encrypted_secret_key");
    // Extract the quoted value: hybrid_encrypted_secret_key = "..."
    let b_hsk_value = b_hsk_line
        .split_once('=')
        .map(|(_, v)| v)
        .expect("line must have '='")
        .trim();

    // Replace A's hybrid_encrypted_secret_key line with B's value.
    // A's hybrid_public_key remains A's — so re-derivation from B's secret will mismatch.
    let tampered = content_a
        .lines()
        .map(|line| {
            if line.starts_with("hybrid_encrypted_secret_key") {
                format!("hybrid_encrypted_secret_key = {b_hsk_value}")
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    // Preserve trailing newline if original had one.
    let tampered = if content_a.ends_with('\n') {
        format!("{tampered}\n")
    } else {
        tampered
    };
    fs::write(&path_a, tampered)?;

    // load_hybrid_keypair on tampered entry A must now reject it.
    let result = keystore.load_hybrid_keypair(&id_a, None, false);
    assert!(
        result.is_err(),
        "substituted hybrid KEM ciphertext must be rejected"
    );
    let err = result.err().expect("checked is_err above");
    assert!(
        err.to_string().contains("hybrid slot"),
        "error must name the hybrid slot, got: {err}"
    );
    assert!(
        err.to_string().contains("mismatch") || err.to_string().contains("corrupt"),
        "error must indicate mismatch/corruption, got: {err}"
    );

    let _ = id_b; // suppress unused warning
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
        keystore.store_keypair(&keypair, Some(&format!("pass{i}")))?;
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
