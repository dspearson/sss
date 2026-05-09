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
    let retrieved = keystore.load_keypair(&key_id, Some(password), true)?;

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
    let retrieved = keystore.load_keypair(&key_id, None, true)?;

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
    let result = keystore.load_keypair(&key_id, Some("wrong_password"), true);
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
    let result = keystore.load_keypair(&key_id, None, true);
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
    assert!(keystore.load_keypair(&key_id, Some(old_password), true).is_err());

    // New password should work
    let retrieved = keystore.load_keypair(&key_id, Some(new_password), true)?;
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
    assert!(keystore.load_keypair(&key_id, None, true).is_err());
    let retrieved = keystore.load_keypair(&key_id, Some(new_password), true)?;
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
    let retrieved = keystore.load_keypair(&key_id, None, true)?;
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
    assert!(keystore.load_keypair(&key_id, Some("password"), true).is_ok());

    // Delete key
    keystore.delete_keypair(&key_id)?;

    // Key should no longer exist
    assert!(keystore.load_keypair(&key_id, Some("password"), true).is_err());

    Ok(())
}

#[test]
fn test_current_key_management() -> Result<()> {
    let (keystore, _temp_dir) = create_temp_keystore()?;

    let keypair1 = KeyPair::generate()?;
    let keypair2 = KeyPair::generate()?;

    let key_id1 = keystore.store_keypair(&keypair1, Some("pass1"))?;
    let _key_id2 = keystore.store_keypair(&keypair2, Some("pass2"))?;

    // 18-03: classic store_keypair writes format_version=1; get_current_keypair
    // intentionally refuses unsigned legacy entries (D-11). Drive the test via
    // get_current_key_id + load_keypair(.., true) so we still exercise the
    // `current` symlink mechanism.
    let current_id = keystore.get_current_key_id()?;
    let current = keystore.load_keypair(&current_id, Some("pass2"), true)?;
    assert_eq!(current.public_key().to_base64(), keypair2.public_key().to_base64());

    // Switch to key_id1
    keystore.set_current_key(&key_id1)?;
    let current_id = keystore.get_current_key_id()?;
    let current = keystore.load_keypair(&current_id, Some("pass1"), true)?;
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
    let loaded = keystore.load_keypair(&key_id, Some("password"), true)?;
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
    assert!(keystore.load_keypair(&key_id1, Some("password1"), true).is_ok());
    assert!(keystore.load_keypair(&key_id1, Some("password2"), true).is_err());
    assert!(keystore.load_keypair(&key_id1, Some("password3"), true).is_err());

    assert!(keystore.load_keypair(&key_id2, Some("password1"), true).is_err());
    assert!(keystore.load_keypair(&key_id2, Some("password2"), true).is_ok());
    assert!(keystore.load_keypair(&key_id2, Some("password3"), true).is_err());

    assert!(keystore.load_keypair(&key_id3, Some("password1"), true).is_err());
    assert!(keystore.load_keypair(&key_id3, Some("password2"), true).is_err());
    assert!(keystore.load_keypair(&key_id3, Some("password3"), true).is_ok());

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

    let loaded_hybrid = keystore.load_hybrid_keypair(&key_id, Some("test_pass"), false)?;
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
    let loaded_classic = keystore.load_keypair(&key_id, Some("shared_pass"), false);
    assert!(
        loaded_classic.is_ok(),
        "classic key must be decryptable with shared passphrase"
    );
    assert_eq!(
        loaded_classic.unwrap().public_key().to_base64(),
        KeyPair::Classic(classic).public_key().to_base64()
    );

    // Hybrid key must be loadable with the same shared passphrase
    let loaded_hybrid = keystore.load_hybrid_keypair(&key_id, Some("shared_pass"), false);
    assert!(
        loaded_hybrid.is_ok(),
        "hybrid key must be decryptable with shared passphrase"
    );

    // Wrong password must fail for classic
    assert!(
        keystore.load_keypair(&key_id, Some("wrong_pass"), false).is_err(),
        "classic load must fail with wrong passphrase"
    );

    // Wrong password must fail for hybrid
    assert!(
        keystore.load_hybrid_keypair(&key_id, Some("wrong_pass"), false).is_err(),
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

    let result = keystore.load_hybrid_keypair(&key_id, Some("pass"), true);
    assert!(result.is_err(), "must return Err for classic-only identity");

    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("your keystore has no hybrid keypair"),
        "error message must contain 'your keystore has no hybrid keypair', got: {err_msg}"
    );

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// 16-02: KEYSTORE-05..12 branch coverage tests
//
// Lift `src/keystore.rs` line coverage by exercising previously-uncovered
// branches in `Keystore::store_dual_keypair` (Cases A-passwordless, B-already-
// present-guard, B-passwordless, C, D) and `Keystore::load_hybrid_keypair`
// (file-not-found, password-required, passwordless-roundtrip).
//
// Per 16-01-SUMMARY.md §Lift Targets §1, 5 of 8 candidates are
// EXPECTED-COVERED (KEYSTORE-05/07/09/10/11) and 3 are LIKELY-ALREADY-COVERED
// (KEYSTORE-06/08/12). All 8 tests are landed as branch-logic regression
// anchors per the orchestrator's guidance — the LIKELY-ALREADY-COVERED tests
// remain valid passing tests; they just don't add net coverage lift.
// ─────────────────────────────────────────────────────────────────────────────

/// KEYSTORE-05: Case C delegates to store_keypair — `store_dual_keypair(Some(classic), None, Some(pw))`
/// returns Ok(key_id), and the stored classic keypair byte-identically round-trips
/// through `load_keypair`. Targets src/keystore.rs:657-659 (Case C delegation arm).
#[cfg(feature = "hybrid")]
#[test]
fn test_store_dual_keypair_case_c_delegates_to_store_keypair() -> Result<()> {
    let (keystore, _temp_dir) = create_temp_keystore()?;

    let classic = ClassicKeyPair::generate()?;
    let classic_pub_b64 = KeyPair::Classic(classic.clone()).public_key().to_base64();
    let classic_sk_b64 = KeyPair::Classic(classic.clone()).secret_key()?.to_base64();

    // Case C: classic-only via store_dual_keypair — should delegate to store_keypair
    let key_id = keystore.store_dual_keypair(Some(&classic), None, Some("case_c_pw"))?;
    assert!(!key_id.is_empty(), "Case C must return non-empty key_id");

    // Round-trip via load_keypair (Case C wraps in KeyPair::Classic)
    let loaded = keystore.load_keypair(&key_id, Some("case_c_pw"), true)?;
    assert_eq!(
        loaded.public_key().to_base64(),
        classic_pub_b64,
        "Case C: loaded classic public key must match stored"
    );
    assert_eq!(
        loaded.secret_key()?.to_base64(),
        classic_sk_b64,
        "Case C: loaded classic secret key must match stored byte-identically"
    );

    Ok(())
}

/// KEYSTORE-06: Case A passwordless round-trip — `store_dual_keypair(Some(classic), Some(hybrid), None)`
/// returns Ok(key_id); both `load_hybrid_keypair` and `load_keypair` recover
/// byte-identically. Targets src/keystore.rs:692-701 (Case A passwordless else arm).
/// Note (per 16-01-SUMMARY.md): LIKELY-ALREADY-COVERED — landed as documentation-grade
/// regression anchor for branch logic (lines 692-701 already green per survey).
#[cfg(feature = "hybrid")]
#[test]
fn test_store_dual_keypair_case_a_passwordless_roundtrip() -> Result<()> {
    let (keystore, _temp_dir) = create_temp_keystore()?;

    let classic = ClassicKeyPair::generate()?;
    let hybrid = HybridKeyPair::generate()?;

    let classic_pub_b64 = KeyPair::Classic(classic.clone()).public_key().to_base64();
    let classic_sk_b64 = KeyPair::Classic(classic.clone()).secret_key()?.to_base64();
    let hybrid_pub_bytes: Vec<u8> = hybrid.public_key().as_bytes().to_vec();

    // Case A passwordless: both keys, no password
    let key_id = keystore.store_dual_keypair(Some(&classic), Some(&hybrid), None)?;
    assert!(!key_id.is_empty(), "Case A passwordless must return non-empty key_id");

    // Hybrid recovers byte-identically (passwordless raw base64 path, line 700)
    let loaded_hybrid = keystore.load_hybrid_keypair(&key_id, None, false)?;
    assert_eq!(
        loaded_hybrid.public_key().as_bytes(),
        hybrid_pub_bytes.as_slice(),
        "Case A passwordless: hybrid public key must match byte-identically"
    );

    // Classic recovers byte-identically
    let loaded_classic = keystore.load_keypair(&key_id, None, false)?;
    assert_eq!(
        loaded_classic.public_key().to_base64(),
        classic_pub_b64,
        "Case A passwordless: classic public key must match"
    );
    assert_eq!(
        loaded_classic.secret_key()?.to_base64(),
        classic_sk_b64,
        "Case A passwordless: classic secret key must match byte-identically"
    );

    Ok(())
}

/// KEYSTORE-07: Case B refuses to overwrite already-present hybrid material —
/// first `store_dual_keypair(Some(classic), Some(hybrid), Some(pw))` succeeds; second
/// `store_dual_keypair(None, Some(hybrid2), Some(pw))` returns Err with a message
/// containing "already present". Targets src/keystore.rs:752-758 (T-03-03 guard).
#[cfg(feature = "hybrid")]
#[test]
fn test_store_dual_keypair_case_b_rejects_already_present_hybrid() -> Result<()> {
    let (keystore, _temp_dir) = create_temp_keystore()?;

    let classic = ClassicKeyPair::generate()?;
    let hybrid = HybridKeyPair::generate()?;
    let hybrid2 = HybridKeyPair::generate()?;

    // First: Case A — store dual identity with hybrid material
    let key_id = keystore.store_dual_keypair(Some(&classic), Some(&hybrid), Some("guard_pw"))?;
    assert!(!key_id.is_empty(), "first store must succeed");

    // Second: Case B — try to add another hybrid; guard MUST refuse
    let result = keystore.store_dual_keypair(None, Some(&hybrid2), Some("guard_pw"));
    assert!(
        result.is_err(),
        "Case B must reject when hybrid material is already present"
    );

    let err_msg = result.unwrap_err().to_string();
    // Error message at src/keystore.rs:754-757:
    // "hybrid keypair already present in this identity; use --suite both to replace"
    assert!(
        err_msg.contains("already present"),
        "error must contain 'already present', got: {err_msg}"
    );

    Ok(())
}

/// KEYSTORE-08: Case B passwordless upgrade — store classic-only passwordless first,
/// then upgrade by adding hybrid via `store_dual_keypair(None, Some(hybrid), None)`,
/// assert Ok(key_id) and both classic + hybrid load back byte-identically.
/// Targets src/keystore.rs:783-786 (Case B passwordless else arm).
/// Note (per 16-01-SUMMARY.md): LIKELY-ALREADY-COVERED — landed as documentation-grade
/// regression anchor (lines 783-786 already green per survey).
#[cfg(feature = "hybrid")]
#[test]
fn test_store_dual_keypair_case_b_passwordless_upgrade() -> Result<()> {
    let (keystore, _temp_dir) = create_temp_keystore()?;

    let classic = ClassicKeyPair::generate()?;
    let hybrid = HybridKeyPair::generate()?;

    let classic_pub_b64 = KeyPair::Classic(classic.clone()).public_key().to_base64();
    let hybrid_pub_bytes: Vec<u8> = hybrid.public_key().as_bytes().to_vec();

    // Step 1: store classic-only passwordless via store_keypair
    let key_id =
        keystore.store_keypair(&KeyPair::Classic(classic.clone()), None)?;
    assert!(!key_id.is_empty(), "passwordless classic store must succeed");

    // Step 2: Case B passwordless — upgrade by adding hybrid material with password=None
    let upgraded_key_id = keystore.store_dual_keypair(None, Some(&hybrid), None)?;
    assert_eq!(
        upgraded_key_id, key_id,
        "Case B passwordless upgrade must keep the same key_id"
    );

    // Classic remains loadable passwordless
    let loaded_classic = keystore.load_keypair(&key_id, None, false)?;
    assert_eq!(
        loaded_classic.public_key().to_base64(),
        classic_pub_b64,
        "Case B passwordless: classic must remain byte-identical after upgrade"
    );

    // Hybrid is now loadable passwordless
    let loaded_hybrid = keystore.load_hybrid_keypair(&key_id, None, false)?;
    assert_eq!(
        loaded_hybrid.public_key().as_bytes(),
        hybrid_pub_bytes.as_slice(),
        "Case B passwordless: hybrid must round-trip byte-identically after upgrade"
    );

    Ok(())
}

/// KEYSTORE-09: Case D defensive error — `store_dual_keypair(None, None, None)` must
/// return Err containing the substring from src/keystore.rs:813-815.
/// Targets src/keystore.rs:812-815 (Case D `(None, None)` defensive arm).
#[cfg(feature = "hybrid")]
#[test]
fn test_store_dual_keypair_neither_key_errors() -> Result<()> {
    let (keystore, _temp_dir) = create_temp_keystore()?;

    let result = keystore.store_dual_keypair(None, None, None);
    assert!(
        result.is_err(),
        "Case D (None, None) must return Err"
    );

    let err_msg = result.unwrap_err().to_string();
    // Error message at src/keystore.rs:813-815:
    // "store_dual_keypair called with neither classic nor hybrid keypair"
    assert!(
        err_msg.contains("neither classic nor hybrid keypair"),
        "error must contain 'neither classic nor hybrid keypair', got: {err_msg}"
    );

    Ok(())
}

/// KEYSTORE-10: load_hybrid_keypair on a non-existent key_id returns Err with
/// "Key file not found" (src/keystore.rs:834-836). Targets the file-not-found arm.
#[cfg(feature = "hybrid")]
#[test]
fn test_load_hybrid_keypair_nonexistent_key_id_errors() -> Result<()> {
    let (keystore, _temp_dir) = create_temp_keystore()?;

    let result = keystore.load_hybrid_keypair("nonexistent_key_id_abc123", None, false);
    assert!(
        result.is_err(),
        "load_hybrid_keypair on missing file must return Err"
    );

    let err_msg = result.unwrap_err().to_string();
    // Error message at src/keystore.rs:835: "Key file not found: {key_id}"
    assert!(
        err_msg.contains("Key file not found"),
        "error must contain 'Key file not found', got: {err_msg}"
    );

    Ok(())
}

/// KEYSTORE-11: load_hybrid_keypair on a password-protected dual identity with
/// `password=None` returns Err containing "Password required". Targets
/// src/keystore.rs:857-859 (password-required ok_or_else arm on protected key).
#[cfg(feature = "hybrid")]
#[test]
fn test_load_hybrid_keypair_password_required_errors() -> Result<()> {
    let (keystore, _temp_dir) = create_temp_keystore()?;

    let classic = ClassicKeyPair::generate()?;
    let hybrid = HybridKeyPair::generate()?;

    // Store dual identity password-protected
    let key_id = keystore.store_dual_keypair(
        Some(&classic),
        Some(&hybrid),
        Some("protected_pw"),
    )?;

    // Load hybrid with password=None on protected identity — must fail
    let result = keystore.load_hybrid_keypair(&key_id, None, false);
    assert!(
        result.is_err(),
        "load_hybrid_keypair with password=None on protected identity must Err"
    );

    let err_msg = result.unwrap_err().to_string();
    // Error message at src/keystore.rs:858: "Password required for encrypted key"
    assert!(
        err_msg.contains("Password required"),
        "error must contain 'Password required', got: {err_msg}"
    );

    Ok(())
}

/// KEYSTORE-12: load_hybrid_keypair passwordless round-trip — store dual identity
/// without password; load_hybrid_keypair returns Ok with public_key bytes matching
/// the stored hybrid byte-identically. Targets src/keystore.rs:880-882
/// (passwordless-load else arm).
/// Note (per 16-01-SUMMARY.md): LIKELY-ALREADY-COVERED — landed as documentation-grade
/// regression anchor (lines 880-882 already green per survey).
#[cfg(feature = "hybrid")]
#[test]
fn test_load_hybrid_keypair_passwordless_roundtrip() -> Result<()> {
    let (keystore, _temp_dir) = create_temp_keystore()?;

    let classic = ClassicKeyPair::generate()?;
    let hybrid = HybridKeyPair::generate()?;
    let hybrid_pub_bytes: Vec<u8> = hybrid.public_key().as_bytes().to_vec();

    // Store dual identity passwordless
    let key_id = keystore.store_dual_keypair(Some(&classic), Some(&hybrid), None)?;

    // Load hybrid passwordless — exercises lines 880-882
    let loaded_hybrid = keystore.load_hybrid_keypair(&key_id, None, false)?;
    assert_eq!(
        loaded_hybrid.public_key().as_bytes(),
        hybrid_pub_bytes.as_slice(),
        "passwordless round-trip: hybrid public_key must match byte-identically"
    );

    Ok(())
}
