//! Keystore integration tests
//!
//! This test suite validates the complete key lifecycle:
//! - Keypair generation and storage
//! - Password protection
//! - Key retrieval and decryption
//! - Passphrase changes
//! - Multiple key management

use anyhow::Result;
use sss::crypto::KeyPair;
use sss::kdf::KdfParams;
use sss::keystore::Keystore;
use tempfile::TempDir;

#[cfg(feature = "hybrid")]
use sss::crypto::hybrid::HybridKeyPair;
#[cfg(feature = "hybrid")]
use sss::crypto::ClassicKeyPair;

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

#[test]
fn test_store_and_retrieve_password_protected_keypair() -> Result<()> {
    let (keystore, _temp_dir) = create_temp_keystore()?;
    let keypair = KeyPair::generate()?;
    let password = "test_password_123";

    // Store with password
    let key_id = keystore.store_keypair(&keypair, Some(password))?;

    // Retrieve with password
    let retrieved = keystore.load_keypair(&key_id, Some(password))?;

    // Keys should match
    assert_eq!(keypair.public_key().to_base64(), retrieved.public_key().to_base64());
    assert_eq!(keypair.secret_key().unwrap().to_base64(), retrieved.secret_key().unwrap().to_base64());

    Ok(())
}

#[test]
fn test_store_and_retrieve_passwordless_keypair() -> Result<()> {
    let (keystore, _temp_dir) = create_temp_keystore()?;
    let keypair = KeyPair::generate()?;

    // Store without password
    let key_id = keystore.store_keypair(&keypair, None)?;

    // Retrieve without password
    let retrieved = keystore.load_keypair(&key_id, None)?;

    // Keys should match
    assert_eq!(keypair.public_key().to_base64(), retrieved.public_key().to_base64());
    assert_eq!(keypair.secret_key().unwrap().to_base64(), retrieved.secret_key().unwrap().to_base64());

    Ok(())
}

#[test]
fn test_wrong_password_fails() -> Result<()> {
    let (keystore, _temp_dir) = create_temp_keystore()?;
    let keypair = KeyPair::generate()?;
    let password = "correct_password";

    let key_id = keystore.store_keypair(&keypair, Some(password))?;

    // Try to retrieve with wrong password
    let result = keystore.load_keypair(&key_id, Some("wrong_password"));
    assert!(result.is_err(), "Should fail with wrong password");

    Ok(())
}

#[test]
fn test_missing_password_fails_for_protected_key() -> Result<()> {
    let (keystore, _temp_dir) = create_temp_keystore()?;
    let keypair = KeyPair::generate()?;
    let password = "test_password";

    let key_id = keystore.store_keypair(&keypair, Some(password))?;

    // Try to retrieve without password
    let result = keystore.load_keypair(&key_id, None);
    assert!(result.is_err(), "Should fail when password is missing");

    Ok(())
}

#[test]
fn test_change_passphrase() -> Result<()> {
    let (keystore, _temp_dir) = create_temp_keystore()?;
    let keypair = KeyPair::generate()?;
    let old_password = "old_password";
    let new_password = "new_password";

    let key_id = keystore.store_keypair(&keypair, Some(old_password))?;

    // Change passphrase
    keystore.set_passphrase(&key_id, Some(old_password), new_password)?;

    // Old password should no longer work
    assert!(keystore.load_keypair(&key_id, Some(old_password)).is_err());

    // New password should work
    let retrieved = keystore.load_keypair(&key_id, Some(new_password))?;
    assert_eq!(keypair.public_key().to_base64(), retrieved.public_key().to_base64());

    Ok(())
}

#[test]
fn test_add_passphrase_to_passwordless_key() -> Result<()> {
    let (keystore, _temp_dir) = create_temp_keystore()?;
    let keypair = KeyPair::generate()?;
    let new_password = "new_password";

    // Store without password
    let key_id = keystore.store_keypair(&keypair, None)?;

    // Add passphrase
    keystore.set_passphrase(&key_id, None, new_password)?;

    // Should now require password
    assert!(keystore.load_keypair(&key_id, None).is_err());
    let retrieved = keystore.load_keypair(&key_id, Some(new_password))?;
    assert_eq!(keypair.public_key().to_base64(), retrieved.public_key().to_base64());

    Ok(())
}

#[test]
fn test_remove_passphrase() -> Result<()> {
    let (keystore, _temp_dir) = create_temp_keystore()?;
    let keypair = KeyPair::generate()?;
    let password = "test_password";

    let key_id = keystore.store_keypair(&keypair, Some(password))?;

    // Remove passphrase
    keystore.remove_passphrase(&key_id, password)?;

    // Should now work without password
    let retrieved = keystore.load_keypair(&key_id, None)?;
    assert_eq!(keypair.public_key().to_base64(), retrieved.public_key().to_base64());

    Ok(())
}

#[test]
fn test_list_all_keys() -> Result<()> {
    let (keystore, _temp_dir) = create_temp_keystore()?;

    // Store multiple keys
    let keypair1 = KeyPair::generate()?;
    let keypair2 = KeyPair::generate()?;
    let keypair3 = KeyPair::generate()?;

    let key_id1 = keystore.store_keypair(&keypair1, Some("pass1"))?;
    let key_id2 = keystore.store_keypair(&keypair2, Some("pass2"))?;
    let key_id3 = keystore.store_keypair(&keypair3, None)?;

    // List all keys
    let keys = keystore.list_key_ids()?;

    assert_eq!(keys.len(), 3);
    let key_ids: Vec<String> = keys.iter().map(|(id, _)| id.clone()).collect();
    assert!(key_ids.contains(&key_id1));
    assert!(key_ids.contains(&key_id2));
    assert!(key_ids.contains(&key_id3));

    Ok(())
}

#[test]
fn test_delete_key() -> Result<()> {
    let (keystore, _temp_dir) = create_temp_keystore()?;
    let keypair = KeyPair::generate()?;

    let key_id = keystore.store_keypair(&keypair, Some("password"))?;

    // Key should exist
    assert!(keystore.load_keypair(&key_id, Some("password")).is_ok());

    // Delete key
    keystore.delete_keypair(&key_id)?;

    // Key should no longer exist
    assert!(keystore.load_keypair(&key_id, Some("password")).is_err());

    Ok(())
}

#[test]
fn test_current_key_management() -> Result<()> {
    let (keystore, _temp_dir) = create_temp_keystore()?;

    let keypair1 = KeyPair::generate()?;
    let keypair2 = KeyPair::generate()?;

    let key_id1 = keystore.store_keypair(&keypair1, Some("pass1"))?;
    let _key_id2 = keystore.store_keypair(&keypair2, Some("pass2"))?;

    // Most recent should be current (key_id2)
    let current = keystore.get_current_keypair(Some("pass2"))?;
    assert_eq!(current.public_key().to_base64(), keypair2.public_key().to_base64());

    // Switch to key_id1
    keystore.set_current_key(&key_id1)?;
    let current = keystore.get_current_keypair(Some("pass1"))?;
    assert_eq!(current.public_key().to_base64(), keypair1.public_key().to_base64());

    Ok(())
}

#[test]
fn test_is_password_protected() -> Result<()> {
    let (keystore, _temp_dir) = create_temp_keystore()?;

    let keypair1 = KeyPair::generate()?;
    let keypair2 = KeyPair::generate()?;

    let _key_id1 = keystore.store_keypair(&keypair1, Some("password"))?;
    let _key_id2 = keystore.store_keypair(&keypair2, None)?;

    // Test current key (most recently stored is key2)
    assert!(!keystore.is_current_key_password_protected()?);

    // Set to key1 and test
    keystore.set_current_key(&_key_id1)?;
    assert!(keystore.is_current_key_password_protected()?);

    Ok(())
}

#[test]
fn test_keypair_metadata_preserved() -> Result<()> {
    let (keystore, _temp_dir) = create_temp_keystore()?;
    let keypair = KeyPair::generate()?;

    let key_id = keystore.store_keypair(&keypair, Some("password"))?;

    // Verify key exists and can be loaded
    let loaded = keystore.load_keypair(&key_id, Some("password"))?;
    assert_eq!(loaded.public_key().to_base64(), keypair.public_key().to_base64());

    // Verify key ID is in the list
    let all_keys = keystore.list_key_ids()?;
    let key_ids: Vec<String> = all_keys.iter().map(|(id, _)| id.clone()).collect();
    assert!(key_ids.contains(&key_id));

    Ok(())
}

#[test]
fn test_multiple_keys_different_passwords() -> Result<()> {
    let (keystore, _temp_dir) = create_temp_keystore()?;

    let keypair1 = KeyPair::generate()?;
    let keypair2 = KeyPair::generate()?;
    let keypair3 = KeyPair::generate()?;

    let key_id1 = keystore.store_keypair(&keypair1, Some("password1"))?;
    let key_id2 = keystore.store_keypair(&keypair2, Some("password2"))?;
    let key_id3 = keystore.store_keypair(&keypair3, Some("password3"))?;

    // Each key should only work with its own password
    assert!(keystore.load_keypair(&key_id1, Some("password1")).is_ok());
    assert!(keystore.load_keypair(&key_id1, Some("password2")).is_err());
    assert!(keystore.load_keypair(&key_id1, Some("password3")).is_err());

    assert!(keystore.load_keypair(&key_id2, Some("password1")).is_err());
    assert!(keystore.load_keypair(&key_id2, Some("password2")).is_ok());
    assert!(keystore.load_keypair(&key_id2, Some("password3")).is_err());

    assert!(keystore.load_keypair(&key_id3, Some("password1")).is_err());
    assert!(keystore.load_keypair(&key_id3, Some("password2")).is_err());
    assert!(keystore.load_keypair(&key_id3, Some("password3")).is_ok());

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Dual-suite integration tests (KEYSTORE-01, KEYSTORE-03, KEYSTORE-04)
// Gated by the `hybrid` feature; all five use create_temp_keystore() helper.
// ─────────────────────────────────────────────────────────────────────────────

/// KEYSTORE-01: A classic-only TOML file deserializes with hybrid fields = None.
/// Verifies that the #[serde(default)] guards on hybrid_public_key and
/// hybrid_encrypted_secret_key prevent parse errors on pre-Phase-3 identity files.
#[cfg(feature = "hybrid")]
#[test]
fn test_classic_only_backward_compat() -> Result<()> {
    let (keystore, _temp_dir) = create_temp_keystore()?;
    let keypair = KeyPair::generate()?;
    let key_id = keystore.store_keypair(&keypair, None)?;

    // Read the TOML from disk directly and parse it
    let keys_dir = _temp_dir.path().join("sss").join("keys");
    let key_file = keys_dir.join(format!("{key_id}.toml"));
    let content = std::fs::read_to_string(&key_file)?;

    let stored: sss::keystore::StoredKeyPair = toml::from_str(&content)?;

    assert!(stored.hybrid_public_key.is_none(),
        "classic-only TOML must deserialize with hybrid_public_key = None");
    assert!(stored.hybrid_encrypted_secret_key.is_none(),
        "classic-only TOML must deserialize with hybrid_encrypted_secret_key = None");

    Ok(())
}

/// KEYSTORE-01: store_dual_keypair with both classic and hybrid, then load_hybrid_keypair
/// returns a HybridKeyPair whose public_key().bytes match the original.
#[cfg(feature = "hybrid")]
#[test]
fn test_dual_suite_roundtrip() -> Result<()> {
    let (keystore, _temp_dir) = create_temp_keystore()?;

    let classic = ClassicKeyPair::generate()?;
    let hybrid = HybridKeyPair::generate()?;
    // Capture public key bytes via the public as_bytes() accessor
    let hybrid_pub_bytes: Vec<u8> = hybrid.public_key().as_bytes().to_vec();

    let key_id = keystore.store_dual_keypair(Some(&classic), Some(&hybrid), Some("test_pass"))?;
    assert!(!key_id.is_empty(), "key_id must be non-empty");

    let loaded_hybrid = keystore.load_hybrid_keypair(&key_id, Some("test_pass"))?;
    assert_eq!(
        loaded_hybrid.public_key().as_bytes(), hybrid_pub_bytes.as_slice(),
        "loaded hybrid public key must match original"
    );

    Ok(())
}

/// KEYSTORE-03: store classic first, then upgrade with store_dual_keypair(None, hybrid, pass).
/// The public_key and encrypted_secret_key fields must be byte-for-byte identical after upgrade.
#[cfg(feature = "hybrid")]
#[test]
fn test_upgrade_classic_to_both_preserves_classic() -> Result<()> {
    let (keystore, _temp_dir) = create_temp_keystore()?;

    let classic = ClassicKeyPair::generate()?;
    let hybrid = HybridKeyPair::generate()?;

    // Store classic-only first
    let key_id = keystore.store_keypair(&KeyPair::Classic(classic.clone()), Some("test_pass"))?;

    // Capture pre-upgrade TOML values
    let keys_dir = _temp_dir.path().join("sss").join("keys");
    let key_file = keys_dir.join(format!("{key_id}.toml"));

    let pre_content = std::fs::read_to_string(&key_file)?;
    let pre_stored: sss::keystore::StoredKeyPair = toml::from_str(&pre_content)?;
    let pre_public_key = pre_stored.public_key.clone();
    let pre_enc_sk = pre_stored.encrypted_secret_key.clone();

    // Upgrade: add hybrid material to the existing identity
    let upgraded_key_id =
        keystore.store_dual_keypair(None, Some(&hybrid), Some("test_pass"))?;
    assert_eq!(
        upgraded_key_id, key_id,
        "Case B must return the same key_id (no new UUID)"
    );

    // Read post-upgrade TOML and assert classic fields are byte-for-byte identical
    let post_content = std::fs::read_to_string(&key_file)?;
    let post_stored: sss::keystore::StoredKeyPair = toml::from_str(&post_content)?;

    assert_eq!(
        post_stored.public_key, pre_public_key,
        "public_key must be byte-for-byte identical after hybrid upgrade (KEYSTORE-03)"
    );
    assert_eq!(
        post_stored.encrypted_secret_key, pre_enc_sk,
        "encrypted_secret_key must be byte-for-byte identical after hybrid upgrade (KEYSTORE-03)"
    );
    assert!(
        post_stored.hybrid_public_key.is_some(),
        "hybrid_public_key must be Some after upgrade"
    );

    Ok(())
}

/// KEYSTORE-04: Both classic and hybrid secrets in a dual-suite file are decryptable
/// with the same passphrase. Wrong passphrase must fail for both.
#[cfg(feature = "hybrid")]
#[test]
fn test_dual_suite_single_passphrase() -> Result<()> {
    let (keystore, _temp_dir) = create_temp_keystore()?;

    let classic = ClassicKeyPair::generate()?;
    let hybrid = HybridKeyPair::generate()?;

    let key_id =
        keystore.store_dual_keypair(Some(&classic), Some(&hybrid), Some("shared_pass"))?;

    // Classic key must be loadable with the shared passphrase
    let loaded_classic = keystore.load_keypair(&key_id, Some("shared_pass"));
    assert!(
        loaded_classic.is_ok(),
        "classic key must be decryptable with shared passphrase"
    );
    assert_eq!(
        loaded_classic.unwrap().public_key().to_base64(),
        KeyPair::Classic(classic).public_key().to_base64()
    );

    // Hybrid key must be loadable with the same shared passphrase
    let loaded_hybrid = keystore.load_hybrid_keypair(&key_id, Some("shared_pass"));
    assert!(
        loaded_hybrid.is_ok(),
        "hybrid key must be decryptable with shared passphrase"
    );

    // Wrong password must fail for classic
    assert!(
        keystore.load_keypair(&key_id, Some("wrong_pass")).is_err(),
        "classic load must fail with wrong passphrase"
    );

    // Wrong password must fail for hybrid
    assert!(
        keystore.load_hybrid_keypair(&key_id, Some("wrong_pass")).is_err(),
        "hybrid load must fail with wrong passphrase"
    );

    Ok(())
}

/// KEYSTORE-01 error path: load_hybrid_keypair on a classic-only identity file
/// returns Err with the exact error string "your keystore has no hybrid keypair".
#[cfg(feature = "hybrid")]
#[test]
fn test_load_hybrid_no_hybrid_key_errors() -> Result<()> {
    let (keystore, _temp_dir) = create_temp_keystore()?;
    let keypair = KeyPair::generate()?;
    let key_id = keystore.store_keypair(&keypair, Some("pass"))?;

    let result = keystore.load_hybrid_keypair(&key_id, Some("pass"));
    assert!(result.is_err(), "must return Err for classic-only identity");

    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("your keystore has no hybrid keypair"),
        "error message must contain 'your keystore has no hybrid keypair', got: {err_msg}"
    );

    Ok(())
}
