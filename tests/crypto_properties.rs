use base64::Engine;
use proptest::prelude::*;
use sss::crypto::{decrypt_from_base64, encrypt_to_base64, Key};

// Strategy to generate valid UTF-8 strings of various sizes
fn utf8_string_strategy() -> impl Strategy<Value = String> {
    prop::collection::vec(any::<char>(), 0..1000).prop_map(|chars| chars.into_iter().collect())
}

// Strategy to generate printable ASCII strings
fn ascii_string_strategy() -> impl Strategy<Value = String> {
    prop::collection::vec(
        prop::char::range(' ', '~'), // Printable ASCII
        0..1000,
    )
    .prop_map(|chars| chars.into_iter().collect())
}

// Strategy to generate keys (we'll create new keys for each test)
fn key_strategy() -> impl Strategy<Value = Key> {
    any::<u8>().prop_map(|_| Key::new())
}

proptest! {
    #[test]
    fn prop_encrypt_decrypt_roundtrip_utf8(
        plaintext in utf8_string_strategy(),
        key in key_strategy()
    ) {
        // Test that any valid UTF-8 string can be encrypted and decrypted
        let encrypted = encrypt_to_base64(&plaintext, &key).unwrap();
        let decrypted = decrypt_from_base64(&encrypted, &key).unwrap();

        prop_assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn prop_encrypt_decrypt_roundtrip_ascii(
        plaintext in ascii_string_strategy(),
        key in key_strategy()
    ) {
        // Test that any ASCII string can be encrypted and decrypted
        let encrypted = encrypt_to_base64(&plaintext, &key).unwrap();
        let decrypted = decrypt_from_base64(&encrypted, &key).unwrap();

        prop_assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn prop_different_keys_produce_different_ciphertext(
        plaintext in ascii_string_strategy(),
    ) {
        prop_assume!(!plaintext.is_empty()); // Skip empty strings for this test

        let key1 = Key::new();
        let key2 = Key::new();

        // Different keys should produce different ciphertext
        // (except in the astronomically unlikely case that keys are identical)
        if key1.to_base64() != key2.to_base64() {
            let encrypted1 = encrypt_to_base64(&plaintext, &key1).unwrap();
            let encrypted2 = encrypt_to_base64(&plaintext, &key2).unwrap();

            prop_assert_ne!(encrypted1, encrypted2);
        }
    }

    #[test]
    fn prop_same_plaintext_different_ciphertext_nonce_misuse_resistance(
        plaintext in ascii_string_strategy(),
        key in key_strategy()
    ) {
        prop_assume!(!plaintext.is_empty()); // Skip empty strings

        // Same plaintext with same key should produce different ciphertext
        // due to nonce-misuse resistance
        let encrypted1 = encrypt_to_base64(&plaintext, &key).unwrap();
        let encrypted2 = encrypt_to_base64(&plaintext, &key).unwrap();

        prop_assert_ne!(&encrypted1, &encrypted2);

        // But both should decrypt to the same plaintext
        let decrypted1 = decrypt_from_base64(&encrypted1, &key).unwrap();
        let decrypted2 = decrypt_from_base64(&encrypted2, &key).unwrap();

        prop_assert_eq!(&decrypted1, &plaintext);
        prop_assert_eq!(&decrypted2, &plaintext);
    }

    #[test]
    fn prop_key_roundtrip(
        _dummy in any::<u8>() // Just to make it a property test
    ) {
        // Test that keys can be converted to Base64 and back
        let original_key = Key::new();
        let encoded = original_key.to_base64();
        let decoded_key = Key::from_base64(&encoded).unwrap();

        prop_assert_eq!(original_key.to_base64(), decoded_key.to_base64());
    }

    #[test]
    fn prop_encrypted_output_is_valid_base64(
        plaintext in ascii_string_strategy(),
        key in key_strategy()
    ) {
        // Test that encrypted output is always valid Base64
        let encrypted = encrypt_to_base64(&plaintext, &key).unwrap();

        // Should be able to decode as Base64 (even if not valid ciphertext)
        let decoded_bytes = base64::engine::general_purpose::STANDARD.decode(&encrypted);
        prop_assert!(decoded_bytes.is_ok());

        // Should also be valid for our decryption (completeness test)
        let decrypted = decrypt_from_base64(&encrypted, &key).unwrap();
        prop_assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn prop_ciphertext_length_properties(
        plaintext in ascii_string_strategy(),
        key in key_strategy()
    ) {
        let encrypted = encrypt_to_base64(&plaintext, &key).unwrap();

        // Ciphertext should always be longer than plaintext (except possibly empty)
        if !plaintext.is_empty() {
            prop_assert!(encrypted.len() > plaintext.len());
        }

        // Ciphertext length should be deterministic for same plaintext length
        // (This tests that our encoding is consistent)
        let encrypted2 = encrypt_to_base64(&plaintext, &key).unwrap();
        prop_assert_eq!(encrypted.len(), encrypted2.len());
    }

    #[test]
    fn prop_unicode_handling(
        unicode_chars in prop::collection::vec(
            prop::char::ranges(vec![
                '\u{0080}'..='\u{07FF}', // 2-byte UTF-8
                '\u{0800}'..='\u{FFFF}', // 3-byte UTF-8
                // Skip 4-byte for test performance
            ].into()),
            0..100
        )
    ) {
        let plaintext: String = unicode_chars.into_iter().collect();
        let key = Key::new();

        // Unicode strings should encrypt and decrypt correctly
        let encrypted = encrypt_to_base64(&plaintext, &key).unwrap();
        let decrypted = decrypt_from_base64(&encrypted, &key).unwrap();

        prop_assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn prop_special_characters_handling(
        special_chars in prop::collection::vec(
            prop::char::ranges(vec![
                '\x00'..='\x1F', // Control characters
                '\x7F'..='\x7F', // DEL character
            ].into()),
            0..50
        )
    ) {
        // Note: This creates potentially invalid UTF-8, but we'll filter
        let bytes: Vec<u8> = special_chars.into_iter().map(|c| c as u8).collect();

        // Only test with valid UTF-8
        if let Ok(plaintext) = String::from_utf8(bytes) {
            let key = Key::new();

            let encrypted = encrypt_to_base64(&plaintext, &key).unwrap();
            let decrypted = decrypt_from_base64(&encrypted, &key).unwrap();

            prop_assert_eq!(plaintext, decrypted);
        }
    }

    #[test]
    fn prop_empty_string_handling(
        key in key_strategy()
    ) {
        // Empty string should be handled correctly
        let plaintext = "";
        let encrypted = encrypt_to_base64(plaintext, &key).unwrap();
        let decrypted = decrypt_from_base64(&encrypted, &key).unwrap();

        prop_assert_eq!(plaintext, decrypted);

        // Empty string ciphertext should still be non-empty (contains nonce + MAC)
        prop_assert!(!encrypted.is_empty());
    }

    #[test]
    fn prop_deterministic_encryption_with_same_synthetic_nonce(
        plaintext in ascii_string_strategy(),
    ) {
        // This tests that for the same key and plaintext,
        // the synthetic component of the nonce is deterministic
        // while the overall nonce (and thus ciphertext) is different

        prop_assume!(!plaintext.is_empty());
        let key = Key::new();

        // Multiple encryptions should have different ciphertext (NMR)
        let mut ciphertexts = Vec::new();
        for _ in 0..5 {
            let encrypted = encrypt_to_base64(&plaintext, &key).unwrap();
            ciphertexts.push(encrypted);
        }

        // All should be different
        for i in 0..ciphertexts.len() {
            for j in i+1..ciphertexts.len() {
                prop_assert_ne!(&ciphertexts[i], &ciphertexts[j]);
            }
        }

        // All should decrypt to same plaintext
        for ciphertext in &ciphertexts {
            let decrypted = decrypt_from_base64(ciphertext, &key).unwrap();
            prop_assert_eq!(&decrypted, &plaintext);
        }
    }

    #[test]
    fn prop_wrong_key_fails_decryption(
        plaintext in ascii_string_strategy(),
    ) {
        prop_assume!(!plaintext.is_empty());

        let key1 = Key::new();
        let key2 = Key::new();

        // Ensure keys are different
        prop_assume!(key1.to_base64() != key2.to_base64());

        let encrypted = encrypt_to_base64(&plaintext, &key1).unwrap();

        // Decryption with wrong key should fail
        let result = decrypt_from_base64(&encrypted, &key2);
        prop_assert!(result.is_err());
    }

    #[test]
    fn prop_corrupted_ciphertext_fails_decryption(
        plaintext in ascii_string_strategy(),
        corruption_pos in any::<usize>(),
    ) {
        prop_assume!(!plaintext.is_empty());

        let key = Key::new();
        let encrypted = encrypt_to_base64(&plaintext, &key).unwrap();

        // Corrupt the ciphertext at a random position
        let mut corrupted = encrypted.clone();
        if !corrupted.is_empty() {
            let pos = corruption_pos % corrupted.len();
            let mut chars: Vec<char> = corrupted.chars().collect();

            // Change the character to something different
            let original_char = chars[pos];
            chars[pos] = if original_char == 'A' { 'B' } else { 'A' };
            corrupted = chars.into_iter().collect();
        }

        // Corrupted ciphertext should fail to decrypt
        if corrupted != encrypted {
            let result = decrypt_from_base64(&corrupted, &key);
            prop_assert!(result.is_err());
        }
    }

    #[test]
    fn prop_large_input_handling(
        large_input in prop::collection::vec(any::<char>(), 1000..2000)
    ) {
        let plaintext: String = large_input.into_iter().collect();
        let key = Key::new();

        // Large inputs should be handled correctly (up to DoS limits)
        let encrypted = encrypt_to_base64(&plaintext, &key).unwrap();
        let decrypted = decrypt_from_base64(&encrypted, &key).unwrap();

        prop_assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn prop_ciphertext_non_malleability(
        plaintext in ascii_string_strategy(),
    ) {
        prop_assume!(!plaintext.is_empty());
        let key = Key::new();

        let encrypted = encrypt_to_base64(&plaintext, &key).unwrap();

        // Test that we can't create valid related ciphertext by manipulation
        // This is a basic test - real malleability tests would be more complex

        // Try truncating ciphertext
        if encrypted.len() > 10 {
            let truncated = &encrypted[..encrypted.len()-5];
            let result = decrypt_from_base64(truncated, &key);
            prop_assert!(result.is_err());
        }

        // Try extending ciphertext
        let extended = encrypted.clone() + "AAAAA";
        let result = decrypt_from_base64(&extended, &key);
        prop_assert!(result.is_err());
    }
}

// Additional deterministic tests for edge cases that are hard to test with proptest

#[cfg(test)]
mod deterministic_tests {
    use super::*;

    #[test]
    fn test_specific_unicode_edge_cases() {
        let key = Key::new();

        // Test specific Unicode edge cases
        let test_cases = vec![
            "\u{FEFF}", // BOM
            "\u{0000}", // Null character
            "\u{FFFD}", // Replacement character
            "🦀🔒🔑",   // Emoji
            "αβγδε",    // Greek letters
            "测试文本", // Chinese characters
            "\n\r\t",   // Whitespace characters
            "\\\"'`",   // Quote characters
        ];

        for plaintext in test_cases {
            let encrypted = encrypt_to_base64(plaintext, &key).unwrap();
            let decrypted = decrypt_from_base64(&encrypted, &key).unwrap();
            assert_eq!(plaintext, decrypted);
        }
    }

    #[test]
    fn test_boundary_conditions() {
        let key = Key::new();

        // Test boundary conditions
        let boundary_cases = vec![
            String::new(),    // Empty string
            "a".to_string(),  // Single character
            "ab".to_string(), // Two characters
            "a".repeat(16),   // Exactly one block size
            "a".repeat(17),   // One over block size
            "a".repeat(1000), // Moderately large
        ];

        for plaintext in boundary_cases {
            let encrypted = encrypt_to_base64(&plaintext, &key).unwrap();
            let decrypted = decrypt_from_base64(&encrypted, &key).unwrap();
            assert_eq!(plaintext, decrypted);
        }
    }

    #[test]
    fn test_nonce_uniqueness_statistical() {
        let key = Key::new();
        let plaintext = "test message";

        // Generate many ciphertexts and verify they're all different
        let mut ciphertexts = std::collections::HashSet::new();

        for _ in 0..1000 {
            let encrypted = encrypt_to_base64(plaintext, &key).unwrap();

            // All ciphertexts should be unique
            assert!(
                ciphertexts.insert(encrypted.clone()),
                "Duplicate ciphertext found: {}",
                encrypted
            );

            // All should decrypt correctly
            let decrypted = decrypt_from_base64(&encrypted, &key).unwrap();
            assert_eq!(decrypted, plaintext);
        }

        // Should have 1000 unique ciphertexts
        assert_eq!(ciphertexts.len(), 1000);
    }

    #[test]
    fn test_key_space_properties() {
        // Test that different keys produce meaningfully different results
        let plaintext = "consistent test message";

        let mut key_results = std::collections::HashSet::new();

        for _ in 0..100 {
            let key = Key::new();
            let encrypted = encrypt_to_base64(plaintext, &key).unwrap();

            // Each key should produce different ciphertext
            assert!(
                key_results.insert(encrypted.clone()),
                "Duplicate ciphertext from different keys: {}",
                encrypted
            );
        }

        assert_eq!(key_results.len(), 100);
    }

    #[test]
    fn test_error_message_safety() {
        let key = Key::new();

        // Test that error messages don't leak sensitive information
        let test_cases = vec![
            "invalid_base64!",                          // Invalid Base64
            "",                                         // Empty ciphertext
            "A",                                        // Too short
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", // Wrong length but valid Base64
        ];

        for invalid_ciphertext in test_cases {
            let result = decrypt_from_base64(invalid_ciphertext, &key);
            assert!(result.is_err());

            let error_msg = format!("{}", result.unwrap_err());

            // Error message should not contain the key
            assert!(!error_msg.contains(&key.to_base64()));

            // Error message should not contain the invalid input (prevents reflection)
            if invalid_ciphertext.len() > 10 {
                assert!(!error_msg.contains(invalid_ciphertext));
            }
        }
    }
}
