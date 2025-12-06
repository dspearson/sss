//! Cryptographic security tests
//!
//! This test suite validates the security properties of the cryptographic implementation:
//! - Timing attack resistance
//! - Nonce reuse detection
//! - Key derivation security
//! - Encryption security properties

use sss::crypto::{self, KeyPair, RepositoryKey};
use sss::kdf::{DerivedKey, KdfParams, Salt};
use sss::processor::Processor;
use std::collections::HashSet;
use std::time::Instant;

#[test]
fn test_nonce_uniqueness_for_different_content() {
    // Verify that different plaintext produces different nonces (via different ciphertext)
    let key = RepositoryKey::new();
    let timestamp = "2025-01-01T00:00:00Z";
    let file_path = "test.txt";

    let plaintext1 = "secret1";
    let plaintext2 = "secret2";

    let encrypted1 = crypto::encrypt(plaintext1.as_bytes(), &key, timestamp, file_path).unwrap();
    let encrypted2 = crypto::encrypt(plaintext2.as_bytes(), &key, timestamp, file_path).unwrap();

    // Different plaintexts should produce different ciphertexts
    assert_ne!(encrypted1, encrypted2);

    // Extract nonces (first 24 bytes)
    let nonce1 = &encrypted1[0..24];
    let nonce2 = &encrypted2[0..24];

    // Nonces should be different for different plaintexts
    assert_ne!(nonce1, nonce2);
}

#[test]
fn test_deterministic_encryption_same_inputs() {
    // Verify that same inputs produce same output (for git-friendly diffs)
    let key = RepositoryKey::new();
    let timestamp = "2025-01-01T00:00:00Z";
    let file_path = "test.txt";
    let plaintext = "my_secret";

    let encrypted1 = crypto::encrypt(plaintext.as_bytes(), &key, timestamp, file_path).unwrap();
    let encrypted2 = crypto::encrypt(plaintext.as_bytes(), &key, timestamp, file_path).unwrap();

    // Same inputs should produce identical output
    assert_eq!(encrypted1, encrypted2);
}

#[test]
fn test_nonce_changes_with_file_path() {
    // Verify that changing file path changes the nonce
    let key = RepositoryKey::new();
    let timestamp = "2025-01-01T00:00:00Z";
    let plaintext = "secret";

    let encrypted1 = crypto::encrypt(plaintext.as_bytes(), &key, timestamp, "file1.txt").unwrap();
    let encrypted2 = crypto::encrypt(plaintext.as_bytes(), &key, timestamp, "file2.txt").unwrap();

    // Different file paths should produce different ciphertexts
    assert_ne!(encrypted1, encrypted2);
}

#[test]
fn test_nonce_changes_with_timestamp() {
    // Verify that changing timestamp changes the nonce
    let key = RepositoryKey::new();
    let file_path = "test.txt";
    let plaintext = "secret";

    let encrypted1 = crypto::encrypt(plaintext.as_bytes(), &key, "2025-01-01T00:00:00Z", file_path).unwrap();
    let encrypted2 = crypto::encrypt(plaintext.as_bytes(), &key, "2025-01-02T00:00:00Z", file_path).unwrap();

    // Different timestamps should produce different ciphertexts
    assert_ne!(encrypted1, encrypted2);
}

#[test]
fn test_no_nonce_reuse_across_large_dataset() {
    // Generate many nonces and ensure no duplicates
    let key = RepositoryKey::new();
    let timestamp = "2025-01-01T00:00:00Z";

    let mut nonces = HashSet::new();

    for i in 0..1000 {
        let plaintext = format!("secret_{}", i);
        let encrypted = crypto::encrypt(plaintext.as_bytes(), &key, timestamp, "test.txt").unwrap();
        let nonce = encrypted[0..24].to_vec();

        // Each nonce should be unique
        assert!(nonces.insert(nonce), "Nonce reuse detected at iteration {}", i);
    }

    // Verify we got 1000 unique nonces
    assert_eq!(nonces.len(), 1000);
}

#[test]
fn test_decryption_fails_with_wrong_key() {
    // Verify that decryption with wrong key fails
    let key1 = RepositoryKey::new();
    let key2 = RepositoryKey::new();

    let plaintext = "secret";
    let encrypted = crypto::encrypt(plaintext.as_bytes(), &key1, "2025-01-01T00:00:00Z", "test.txt").unwrap();

    // Decryption with wrong key should fail
    let result = crypto::decrypt(&encrypted, &key2);
    assert!(result.is_err());
}

#[test]
fn test_decryption_fails_with_tampered_ciphertext() {
    // Verify that tampered ciphertext is detected
    let key = RepositoryKey::new();
    let plaintext = "secret";

    let mut encrypted = crypto::encrypt(plaintext.as_bytes(), &key, "2025-01-01T00:00:00Z", "test.txt").unwrap();

    // Tamper with the ciphertext (flip a bit in the middle)
    if let Some(byte) = encrypted.get_mut(30) {
        *byte ^= 0xFF;
    }

    // Decryption should fail due to authentication tag verification
    let result = crypto::decrypt(&encrypted, &key);
    assert!(result.is_err(), "Tampered ciphertext should be rejected");
}

#[test]
fn test_kdf_timing_consistency() {
    // Test that KDF execution time is roughly consistent (prevents timing attacks)
    let salt = Salt::new();
    let params = KdfParams::interactive(); // Use interactive for faster tests

    let passwords = vec![
        "short",
        "medium_password",
        "very_long_password_with_many_characters_to_test_timing",
    ];

    let mut times = Vec::new();

    for password in &passwords {
        let start = Instant::now();
        let _ = DerivedKey::derive_with_params(password, &salt, &params).unwrap();
        let duration = start.elapsed();
        times.push(duration.as_millis());
    }

    // All KDF operations should take roughly the same time (within 50% variance)
    let min_time = *times.iter().min().unwrap();
    let max_time = *times.iter().max().unwrap();

    let variance = (max_time as f64 - min_time as f64) / min_time as f64;
    assert!(variance < 0.5, "KDF timing variance too high: {:.2}%", variance * 100.0);
}

#[test]
fn test_keypair_generation_randomness() {
    // Verify that keypair generation produces unique keys
    let mut public_keys = HashSet::new();
    let mut secret_keys = HashSet::new();

    for _ in 0..100 {
        let keypair = KeyPair::generate().unwrap();
        let pub_key = keypair.public_key.to_base64();
        let sec_key = keypair.secret_key.to_base64();

        assert!(public_keys.insert(pub_key), "Duplicate public key generated");
        assert!(secret_keys.insert(sec_key), "Duplicate secret key generated");
    }

    assert_eq!(public_keys.len(), 100);
    assert_eq!(secret_keys.len(), 100);
}

#[test]
fn test_salt_generation_randomness() {
    // Verify that salt generation produces unique salts
    let mut salts = HashSet::new();

    for _ in 0..100 {
        let salt = Salt::new();
        let salt_b64 = salt.to_base64();

        assert!(salts.insert(salt_b64), "Duplicate salt generated");
    }

    assert_eq!(salts.len(), 100);
}

#[test]
fn test_encryption_with_processor_determinism() {
    // Test that Processor produces deterministic encryption
    let key = RepositoryKey::new();
    let project_root = std::path::PathBuf::from("/test/project");
    let timestamp = "2025-01-01T00:00:00Z".to_string();

    let processor = Processor::new_with_context(key, project_root, timestamp).unwrap();

    let content = "This is a test with ⊕{secret_value} in it";

    let encrypted1 = processor.encrypt_content(content).unwrap();
    let encrypted2 = processor.encrypt_content(content).unwrap();

    // Same processor should produce same output for same input
    assert_eq!(encrypted1, encrypted2);
}

#[test]
fn test_no_plaintext_leakage_in_ciphertext() {
    // Verify that plaintext doesn't appear in ciphertext
    let key = RepositoryKey::new();
    let plaintext = "super_secret_password_12345";

    let encrypted = crypto::encrypt(plaintext.as_bytes(), &key, "2025-01-01T00:00:00Z", "test.txt").unwrap();

    // Convert encrypted bytes to string (lossy, but good enough for this test)
    let encrypted_str = String::from_utf8_lossy(&encrypted);

    // Plaintext should not appear in ciphertext
    assert!(!encrypted_str.contains("super_secret"));
    assert!(!encrypted_str.contains("password"));
    assert!(!encrypted_str.contains("12345"));
}

#[test]
fn test_ciphertext_size_appropriate() {
    // Verify ciphertext size is reasonable (nonce + plaintext + MAC)
    let key = RepositoryKey::new();
    let plaintext = "test";

    let encrypted = crypto::encrypt(plaintext.as_bytes(), &key, "2025-01-01T00:00:00Z", "test.txt").unwrap();

    // Expected size: 24 (nonce) + 4 (plaintext) + 16 (MAC) = 44 bytes
    assert_eq!(encrypted.len(), 24 + plaintext.len() + 16);
}
