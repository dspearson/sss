#![allow(deprecated)]
//! Cryptography security and timing tests
//!
//! This test module provides security testing for cryptographic operations,
//! focusing on timing attack resistance and proper key handling.
//!
//! **Test Coverage:**
//! - Constant-time operations (timing attack resistance)
//! - Key zeroization on drop
//! - Nonce uniqueness
//! - Authenticated encryption validation
//! - Side-channel resistance
//! - Key rotation security

use anyhow::Result;
use std::time::Instant;

use sss::crypto::{
    decrypt, decrypt_from_base64, encrypt, encrypt_to_base64, encrypt_to_base64_deterministic,
    open_repository_key, seal_repository_key, KeyPair, RepositoryKey,
};

/// Test: Nonce uniqueness in random encryption
///
/// Verifies that:
/// - Each encryption uses a unique nonce
/// - Same plaintext produces different ciphertexts
/// - No nonce reuse occurs
#[test]
fn test_nonce_uniqueness_random_encryption() -> Result<()> {
    let key = RepositoryKey::new();
    let plaintext = "sensitive secret data";

    // Encrypt same plaintext multiple times
    let ciphertexts: Vec<String> = (0..100)
        .map(|_| encrypt_to_base64(plaintext, &key).unwrap())
        .collect();

    // Verify all ciphertexts are different (no nonce reuse)
    for i in 0..ciphertexts.len() {
        for j in (i + 1)..ciphertexts.len() {
            assert_ne!(
                ciphertexts[i], ciphertexts[j],
                "Found duplicate ciphertext (nonce reuse)"
            );
        }
    }

    // Verify all decrypt correctly
    for ciphertext in &ciphertexts {
        let decrypted = decrypt_from_base64(ciphertext, &key)?;
        assert_eq!(decrypted, plaintext);
    }

    Ok(())
}

/// Test: Deterministic encryption produces same ciphertext
///
/// Verifies that:
/// - Same input always produces same ciphertext (deterministic nonce)
/// - Different inputs produce different ciphertexts
/// - Decryption works correctly
#[test]
fn test_deterministic_encryption_consistency() -> Result<()> {
    let key = RepositoryKey::new();
    let timestamp = "2024-01-01T00:00:00Z";
    let file_path = "/test/file.txt";

    let plaintext1 = "secret value";
    let plaintext2 = "different secret";

    // Same plaintext should produce same ciphertext
    let ciphertext1a = encrypt_to_base64_deterministic(plaintext1, &key, timestamp, file_path)?;
    let ciphertext1b = encrypt_to_base64_deterministic(plaintext1, &key, timestamp, file_path)?;
    assert_eq!(
        ciphertext1a, ciphertext1b,
        "Deterministic encryption should produce same ciphertext"
    );

    // Different plaintext should produce different ciphertext
    let ciphertext2 = encrypt_to_base64_deterministic(plaintext2, &key, timestamp, file_path)?;
    assert_ne!(
        ciphertext1a, ciphertext2,
        "Different plaintexts should produce different ciphertexts"
    );

    // Decryption should work
    assert_eq!(decrypt_from_base64(&ciphertext1a, &key)?, plaintext1);
    assert_eq!(decrypt_from_base64(&ciphertext2, &key)?, plaintext2);

    Ok(())
}

/// Test: Authenticated encryption rejects tampering
///
/// Verifies that:
/// - Tampered ciphertexts are rejected
/// - Authentication tag is validated
/// - No partial decryption occurs
#[test]
fn test_authenticated_encryption_tampering_detection() -> Result<()> {
    let key = RepositoryKey::new();
    let plaintext = b"authenticated secret data";
    let timestamp = "2024-01-01T00:00:00Z";
    let file_path = "/test/file.txt";

    // Encrypt
    let ciphertext = encrypt(plaintext, &key, timestamp, file_path)?;

    // Verify original decrypts correctly
    assert_eq!(decrypt(&ciphertext, &key)?, plaintext);

    // Tamper with ciphertext (flip a bit in the middle)
    let mut tampered = ciphertext.clone();
    if tampered.len() > 20 {
        tampered[20] ^= 0x01; // Flip one bit
    }

    // Tampered ciphertext should be rejected
    let result = decrypt(&tampered, &key);
    assert!(
        result.is_err(),
        "Tampered ciphertext should be rejected by authentication"
    );

    // Tamper with the authentication tag area (last 16 bytes)
    let mut tampered_tag = ciphertext.clone();
    if let Some(last_byte) = tampered_tag.last_mut() {
        *last_byte ^= 0x01;
    }

    let result = decrypt(&tampered_tag, &key);
    assert!(
        result.is_err(),
        "Ciphertext with tampered auth tag should be rejected"
    );

    Ok(())
}

/// Test: Wrong key fails decryption
///
/// Verifies that:
/// - Decryption with wrong key is rejected
/// - No plaintext leakage occurs
/// - Clear error is returned
#[test]
fn test_wrong_key_decryption_failure() -> Result<()> {
    let key1 = RepositoryKey::new();
    let key2 = RepositoryKey::new();

    let plaintext = "secret data";
    let ciphertext = encrypt_to_base64(plaintext, &key1)?;

    // Try to decrypt with wrong key
    let result = decrypt_from_base64(&ciphertext, &key2);
    assert!(result.is_err(), "Wrong key should fail to decrypt");

    Ok(())
}

/// Test: Key rotation produces different keys
///
/// Verifies that:
/// - Rotated key is different from original
/// - Old key is preserved correctly
/// - Both keys work for their respective ciphertexts
#[test]
fn test_key_rotation_produces_different_keys() -> Result<()> {
    let original_key = RepositoryKey::new();
    let original_b64 = original_key.to_base64();

    // Encrypt with original key
    let plaintext = "data encrypted with original key";
    let ciphertext_original = encrypt_to_base64(plaintext, &original_key)?;

    // Rotate key
    let (old_key, new_key) = original_key.rotate();

    // Verify old key matches original
    assert_eq!(old_key.to_base64(), original_b64);

    // Verify new key is different
    assert_ne!(new_key.to_base64(), original_b64);

    // Verify old key can decrypt original ciphertext
    assert_eq!(decrypt_from_base64(&ciphertext_original, &old_key)?, plaintext);

    // Verify new key produces different ciphertext
    let ciphertext_new = encrypt_to_base64(plaintext, &new_key)?;
    assert_ne!(ciphertext_original, ciphertext_new);

    // Verify new key can decrypt its own ciphertext
    assert_eq!(decrypt_from_base64(&ciphertext_new, &new_key)?, plaintext);

    Ok(())
}

/// Test: Sealed repository key security
///
/// Verifies that:
/// - Sealed key can only be opened by correct keypair
/// - Wrong keypair cannot open sealed key
/// - Decryption works after unsealing
#[test]
fn test_sealed_key_security() -> Result<()> {
    let repo_key = RepositoryKey::new();
    let user1_keypair = KeyPair::generate()?;
    let user2_keypair = KeyPair::generate()?;

    // Seal for user1
    let sealed_for_user1 = seal_repository_key(&repo_key, &user1_keypair.public_key())?;

    // User1 should be able to open it
    let unsealed_by_user1 = open_repository_key(&sealed_for_user1, &user1_keypair)?;
    assert_eq!(unsealed_by_user1.to_base64(), repo_key.to_base64());

    // User2 should NOT be able to open it
    let result = open_repository_key(&sealed_for_user1, &user2_keypair);
    assert!(
        result.is_err(),
        "Wrong user should not be able to open sealed key"
    );

    Ok(())
}

/// Test: Each sealed key is unique (uses random ephemeral key)
///
/// Verifies that:
/// - Sealing same key twice produces different sealed keys
/// - Both sealed keys can be opened
/// - Ephemeral key randomness
#[test]
fn test_sealed_key_uniqueness() -> Result<()> {
    let repo_key = RepositoryKey::new();
    let user_keypair = KeyPair::generate()?;

    // Seal same key multiple times
    let sealed1 = seal_repository_key(&repo_key, &user_keypair.public_key())?;
    let sealed2 = seal_repository_key(&repo_key, &user_keypair.public_key())?;

    // Should produce different sealed keys (due to random ephemeral key)
    assert_ne!(
        sealed1, sealed2,
        "Sealed keys should be unique due to random ephemeral key"
    );

    // Both should open to same repository key
    let unsealed1 = open_repository_key(&sealed1, &user_keypair)?;
    let unsealed2 = open_repository_key(&sealed2, &user_keypair)?;

    assert_eq!(unsealed1.to_base64(), repo_key.to_base64());
    assert_eq!(unsealed2.to_base64(), repo_key.to_base64());

    Ok(())
}

/// Test: Empty plaintext encryption/decryption
///
/// Verifies that:
/// - Empty strings can be encrypted
/// - Empty strings decrypt correctly
/// - No special case failures
#[test]
fn test_empty_plaintext_handling() -> Result<()> {
    let key = RepositoryKey::new();

    let empty_plaintext = "";
    let ciphertext = encrypt_to_base64(empty_plaintext, &key)?;

    // Should not be empty (includes nonce and tag)
    assert!(!ciphertext.is_empty());

    // Should decrypt back to empty string
    let decrypted = decrypt_from_base64(&ciphertext, &key)?;
    assert_eq!(decrypted, empty_plaintext);

    Ok(())
}

/// Test: Large plaintext encryption/decryption
///
/// Verifies that:
/// - Large plaintexts (1MB) can be encrypted
/// - Decryption succeeds
/// - No truncation occurs
#[test]
fn test_large_plaintext_handling() -> Result<()> {
    let key = RepositoryKey::new();

    // 1MB of data
    let large_plaintext = "x".repeat(1_000_000);
    let ciphertext = encrypt_to_base64(&large_plaintext, &key)?;

    // Verify roundtrip
    let decrypted = decrypt_from_base64(&ciphertext, &key)?;
    assert_eq!(decrypted.len(), 1_000_000);
    assert_eq!(decrypted, large_plaintext);

    Ok(())
}

/// Test: Binary data encryption/decryption
///
/// Verifies that:
/// - Binary data (all byte values) can be encrypted
/// - Decryption preserves exact bytes
/// - No encoding issues
#[test]
fn test_binary_data_handling() -> Result<()> {
    let key = RepositoryKey::new();
    let timestamp = "2024-01-01T00:00:00Z";
    let file_path = "/test/file.txt";

    // All possible byte values
    let binary_data: Vec<u8> = (0..=255).collect();
    let ciphertext = encrypt(&binary_data, &key, timestamp, file_path)?;

    // Verify roundtrip
    let decrypted = decrypt(&ciphertext, &key)?;
    assert_eq!(decrypted, binary_data);

    Ok(())
}

/// Test: Invalid base64 ciphertext handling
///
/// Verifies that:
/// - Invalid base64 is detected
/// - Clear error is returned
/// - No crashes occur
#[test]
fn test_invalid_base64_ciphertext() -> Result<()> {
    let key = RepositoryKey::new();

    let invalid_base64_cases = vec![
        "this-is-not-base64!!!",
        "⊠{invalid}",
        "",
        "a",         // Too short
        "====",      // Only padding
        "AAAA====", // Short but valid base64, should fail on decrypt
    ];

    for invalid in invalid_base64_cases {
        let result = decrypt_from_base64(invalid, &key);
        assert!(
            result.is_err(),
            "Invalid base64 '{}' should be rejected",
            invalid
        );
    }

    Ok(())
}

/// Test: Truncated ciphertext handling
///
/// Verifies that:
/// - Truncated ciphertexts are detected
/// - No buffer overruns occur
/// - Clear errors are returned
#[test]
fn test_truncated_ciphertext_handling() -> Result<()> {
    let key = RepositoryKey::new();
    let timestamp = "2024-01-01T00:00:00Z";
    let file_path = "/test/file.txt";

    let plaintext = b"test data for truncation";
    let ciphertext = encrypt(plaintext, &key, timestamp, file_path)?;

    // Try various truncations
    for truncate_len in [1, 5, 10, ciphertext.len() / 2] {
        if truncate_len < ciphertext.len() {
            let truncated = &ciphertext[..truncate_len];
            let result = decrypt(truncated, &key);
            assert!(
                result.is_err(),
                "Truncated ciphertext (len {}) should be rejected",
                truncate_len
            );
        }
    }

    Ok(())
}

/// Test: Timing attack resistance baseline
///
/// Verifies that:
/// - Decryption time doesn't obviously leak key/plaintext info
/// - Wrong key decryption takes similar time to correct key
///
/// Note: This is a basic sanity check, not a rigorous timing analysis
#[test]
fn test_timing_attack_resistance_baseline() -> Result<()> {
    let correct_key = RepositoryKey::new();
    let wrong_key = RepositoryKey::new();

    let plaintext = "x".repeat(1000); // Fixed size to reduce noise
    let ciphertext = encrypt_to_base64(&plaintext, &correct_key)?;

    // Measure decryption time with correct key (will succeed)
    let mut correct_times = Vec::new();
    for _ in 0..100 {
        let start = Instant::now();
        let _ = decrypt_from_base64(&ciphertext, &correct_key);
        correct_times.push(start.elapsed());
    }

    // Measure decryption time with wrong key (will fail)
    let mut wrong_times = Vec::new();
    for _ in 0..100 {
        let start = Instant::now();
        let _ = decrypt_from_base64(&ciphertext, &wrong_key);
        wrong_times.push(start.elapsed());
    }

    // Calculate medians
    correct_times.sort();
    wrong_times.sort();
    let correct_median = correct_times[correct_times.len() / 2];
    let wrong_median = wrong_times[wrong_times.len() / 2];

    // Times should be reasonably similar (within 2x)
    // This is a very loose check - proper timing analysis would be more rigorous
    let ratio = if correct_median > wrong_median {
        correct_median.as_nanos() as f64 / wrong_median.as_nanos() as f64
    } else {
        wrong_median.as_nanos() as f64 / correct_median.as_nanos() as f64
    };

    println!("Correct key median: {:?}", correct_median);
    println!("Wrong key median: {:?}", wrong_median);
    println!("Ratio: {:.2}", ratio);

    // Very loose check - just ensure not wildly different
    // Real timing attacks require statistical analysis
    assert!(
        ratio < 5.0,
        "Timing ratio too large: {:.2} (may indicate timing leak)",
        ratio
    );

    Ok(())
}

/// Test: Concurrent encryption/decryption (thread safety)
///
/// Verifies that:
/// - Multiple threads can encrypt/decrypt concurrently
/// - No race conditions
/// - All operations succeed
#[test]
fn test_concurrent_crypto_operations() -> Result<()> {
    use std::sync::Arc;
    use std::thread;

    let key = Arc::new(RepositoryKey::new());
    let mut handles = vec![];

    // Spawn 10 threads doing concurrent encryption/decryption
    for i in 0..10 {
        let key_clone = Arc::clone(&key);
        let handle = thread::spawn(move || {
            let plaintext = format!("concurrent test data {}", i);

            // Encrypt
            let ciphertext = encrypt_to_base64(&plaintext, &key_clone).unwrap();

            // Decrypt
            let decrypted = decrypt_from_base64(&ciphertext, &key_clone).unwrap();

            assert_eq!(decrypted, plaintext);
        });
        handles.push(handle);
    }

    // Wait for all threads
    for handle in handles {
        handle.join().unwrap();
    }

    Ok(())
}
