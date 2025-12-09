//! KDF (Key Derivation Function) security tests
//!
//! This test suite validates the security of password-based key derivation:
//! - Argon2id parameter validation
//! - Salt uniqueness
//! - Password strength enforcement
//! - Work factor adequacy

use sss::kdf::{DerivedKey, KdfParams, Salt};
use std::collections::HashSet;

#[test]
fn test_kdf_sensitive_parameters() {
    // Verify that sensitive parameters are appropriately strong
    let params = KdfParams::sensitive();

    // Sensitive should use high work factors
    // These values are from libsodium's crypto_pwhash_OPSLIMIT_SENSITIVE and MEMLIMIT_SENSITIVE
    assert!(params.ops_limit >= 3, "Sensitive ops_limit too low");
    assert!(params.mem_limit >= 128 * 1024 * 1024, "Sensitive mem_limit too low (should be >= 128 MiB)");
}

#[test]
fn test_kdf_moderate_parameters() {
    // Verify moderate parameters are balanced
    let params = KdfParams::moderate();

    assert!(params.ops_limit >= 2, "Moderate ops_limit too low");
    assert!(params.mem_limit >= 64 * 1024 * 1024, "Moderate mem_limit too low (should be >= 64 MiB)");
}

#[test]
fn test_kdf_interactive_parameters() {
    // Verify interactive parameters are reasonable
    let params = KdfParams::interactive();

    assert!(params.ops_limit >= 2, "Interactive ops_limit too low");
    assert!(params.mem_limit >= 32 * 1024 * 1024, "Interactive mem_limit too low (should be >= 32 MiB)");
}

#[test]
fn test_kdf_level_parsing() {
    // Test that all level aliases work
    assert!(KdfParams::from_level("sensitive").is_ok());
    assert!(KdfParams::from_level("high").is_ok());
    assert!(KdfParams::from_level("moderate").is_ok());
    assert!(KdfParams::from_level("medium").is_ok());
    assert!(KdfParams::from_level("balanced").is_ok());
    assert!(KdfParams::from_level("interactive").is_ok());
    assert!(KdfParams::from_level("low").is_ok());
    assert!(KdfParams::from_level("fast").is_ok());

    // Invalid level should fail
    assert!(KdfParams::from_level("invalid_level").is_err());
}

#[test]
fn test_same_password_same_salt_same_key() {
    // Deterministic: same password + salt should always produce same key
    let salt = Salt::new();
    let password = "test_password_123";
    let params = KdfParams::interactive();

    let key1 = DerivedKey::derive_with_params(password, &salt, &params).unwrap();
    let key2 = DerivedKey::derive_with_params(password, &salt, &params).unwrap();

    assert_eq!(key1.as_bytes(), key2.as_bytes());
}

#[test]
fn test_different_salt_different_key() {
    // Different salts should produce different keys
    let salt1 = Salt::new();
    let salt2 = Salt::new();
    let password = "test_password_123";
    let params = KdfParams::interactive();

    let key1 = DerivedKey::derive_with_params(password, &salt1, &params).unwrap();
    let key2 = DerivedKey::derive_with_params(password, &salt2, &params).unwrap();

    assert_ne!(key1.as_bytes(), key2.as_bytes());
}

#[test]
fn test_different_password_different_key() {
    // Different passwords should produce different keys
    let salt = Salt::new();
    let params = KdfParams::interactive();

    let key1 = DerivedKey::derive_with_params("password1", &salt, &params).unwrap();
    let key2 = DerivedKey::derive_with_params("password2", &salt, &params).unwrap();

    assert_ne!(key1.as_bytes(), key2.as_bytes());
}

#[test]
fn test_salt_size_correct() {
    // Salt should be 16 bytes (128 bits)
    let salt = Salt::new();
    assert_eq!(salt.as_bytes().len(), 16);
}

#[test]
fn test_derived_key_size_correct() {
    // Derived key should be 32 bytes (256 bits)
    let salt = Salt::new();
    let password = "test";
    let params = KdfParams::interactive();

    let key = DerivedKey::derive_with_params(password, &salt, &params).unwrap();
    assert_eq!(key.as_bytes().len(), 32);
}

#[test]
fn test_salt_uniqueness() {
    // Generate many salts and verify they're all unique
    let mut salts = HashSet::new();

    for _ in 0..1000 {
        let salt = Salt::new();
        let salt_vec = salt.as_bytes().to_vec();
        assert!(salts.insert(salt_vec), "Duplicate salt generated");
    }

    assert_eq!(salts.len(), 1000);
}

#[test]
fn test_kdf_with_empty_password() {
    // KDF should work even with empty password (though not recommended)
    let salt = Salt::new();
    let params = KdfParams::interactive();

    let key = DerivedKey::derive_with_params("", &salt, &params);
    assert!(key.is_ok(), "KDF should handle empty password");
    assert_eq!(key.unwrap().as_bytes().len(), 32);
}

#[test]
fn test_kdf_with_unicode_password() {
    // KDF should handle Unicode passwords correctly
    let salt = Salt::new();
    let params = KdfParams::interactive();

    let passwords = vec![
        "пароль",           // Russian
        "密码",             // Chinese
        "パスワード",        // Japanese
        "🔐🔑🗝️",          // Emoji
        "Ä€Öüẞáéíóú",      // Accented characters
    ];

    for password in passwords {
        let key = DerivedKey::derive_with_params(password, &salt, &params);
        assert!(key.is_ok(), "KDF should handle Unicode password: {}", password);
        assert_eq!(key.unwrap().as_bytes().len(), 32);
    }
}

#[test]
fn test_kdf_with_long_password() {
    // KDF should handle very long passwords
    let salt = Salt::new();
    let params = KdfParams::interactive();

    let long_password = "a".repeat(10000); // 10KB password
    let key = DerivedKey::derive_with_params(&long_password, &salt, &params);
    assert!(key.is_ok(), "KDF should handle long passwords");
}

#[test]
fn test_salt_base64_roundtrip() {
    // Salt should survive base64 encoding/decoding
    let salt = Salt::new();
    let encoded = salt.to_base64();
    let decoded = Salt::from_base64(&encoded).unwrap();

    assert_eq!(salt.as_bytes(), decoded.as_bytes());
}

#[test]
fn test_salt_from_bytes_validation() {
    // Salt should validate input size
    let too_short = vec![0u8; 15];
    let too_long = vec![0u8; 17];
    let correct = vec![0u8; 16];

    assert!(Salt::from_bytes(&too_short).is_err());
    assert!(Salt::from_bytes(&too_long).is_err());
    assert!(Salt::from_bytes(&correct).is_ok());
}

#[test]
fn test_kdf_output_appears_random() {
    // Derived key bytes should appear random (no obvious patterns)
    let salt = Salt::new();
    let password = "test_password";
    let params = KdfParams::interactive();

    let key = DerivedKey::derive_with_params(password, &salt, &params).unwrap();
    let bytes = key.as_bytes();

    // Check that not all bytes are the same
    let first_byte = bytes[0];
    let all_same = bytes.iter().all(|&b| b == first_byte);
    assert!(!all_same, "KDF output should not have all identical bytes");

    // Check that bytes are reasonably distributed (simple entropy check)
    let mut byte_counts = [0u32; 256];
    for &byte in bytes {
        byte_counts[byte as usize] += 1;
    }

    let unique_bytes = byte_counts.iter().filter(|&&count| count > 0).count();
    assert!(unique_bytes > 20, "KDF output should have good byte distribution");
}

#[test]
fn test_kdf_sensitive_vs_interactive_different_keys() {
    // Different parameter sets should produce different keys
    let salt = Salt::new();
    let password = "test_password";

    let key_sensitive = DerivedKey::derive_with_params(password, &salt, &KdfParams::sensitive()).unwrap();
    let key_interactive = DerivedKey::derive_with_params(password, &salt, &KdfParams::interactive()).unwrap();

    // Different parameters should produce different keys
    assert_ne!(key_sensitive.as_bytes(), key_interactive.as_bytes());
}

#[test]
fn test_kdf_default_uses_sensitive() {
    // Test that default derive() uses sensitive parameters
    let salt = Salt::new();
    let password = "test_password";

    let key_default = DerivedKey::derive(password, &salt).unwrap();
    let key_sensitive = DerivedKey::derive_with_params(password, &salt, &KdfParams::sensitive()).unwrap();

    // Default should match sensitive
    assert_eq!(key_default.as_bytes(), key_sensitive.as_bytes());
}
