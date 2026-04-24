use std::env;
use std::path::Path;
use tempfile::TempDir;
use serial_test::serial;

use sss::{
    crypto::{KeyPair, RepositoryKey},
    project::ProjectConfig,
    Processor,
};

/// Test helper to set up a temporary SSS project
fn setup_test_project() -> (TempDir, String, RepositoryKey) {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let username = "testuser".to_string();

    // Generate keypair and repository key
    let keypair = KeyPair::generate().expect("Failed to generate keypair");
    let repository_key = RepositoryKey::new();

    // Create project config using Default
    let mut config = ProjectConfig::default();
    config
        .add_user(&username, &keypair.public_key(), &repository_key)
        .expect("Failed to add user");

    // Save config to temp directory
    let config_path = temp_dir.path().join(".sss.toml");
    config
        .save_to_file(&config_path)
        .expect("Failed to save config");

    // Change to temp directory
    env::set_current_dir(temp_dir.path()).expect("Failed to change directory");

    (temp_dir, username, repository_key)
}

#[test]
#[serial]
fn test_processor_seal_operation() {
    let (_temp_dir, _username, repository_key) = setup_test_project();
    let processor = Processor::new(repository_key).expect("Failed to create processor");

    // Test sealing plaintext markers
    let input = "password=⊕{my-secret}\napi_key=o+{another-secret}";
    let output = processor.encrypt_content(input).expect("Failed to seal");

    // Output should contain encrypted markers
    assert!(output.contains("⊠{"));
    assert!(!output.contains("⊕{"));
    assert!(!output.contains("o+{"));
}

#[test]
#[serial]
fn test_processor_open_operation() {
    let (_temp_dir, _username, repository_key) = setup_test_project();
    let processor = Processor::new(repository_key).expect("Failed to create processor");

    // First seal the content
    let input = "password=⊕{my-secret}";
    let sealed = processor.encrypt_content(input).expect("Failed to seal");

    // Then open it back
    let opened = processor.decrypt_content(&sealed).expect("Failed to open");

    // Should contain plaintext marker
    assert!(opened.contains("⊕{my-secret}"));
    assert!(!opened.contains("⊠{"));
}

#[test]
#[serial]
fn test_processor_render_operation() {
    let (_temp_dir, _username, repository_key) = setup_test_project();
    let processor = Processor::new(repository_key).expect("Failed to create processor");

    // First seal the content
    let input = "password=⊕{my-secret}";
    let sealed = processor.encrypt_content(input).expect("Failed to seal");

    // Then render to raw text
    let rendered = processor.decrypt_to_raw(&sealed).expect("Failed to render");

    // Should contain raw text without markers
    assert_eq!(rendered, "password=my-secret");
    assert!(!rendered.contains("⊕{"));
    assert!(!rendered.contains("⊠{"));
}

#[test]
#[serial]
fn test_seal_open_roundtrip() {
    let (_temp_dir, _username, repository_key) = setup_test_project();
    let processor = Processor::new(repository_key).expect("Failed to create processor");

    let original = "secret=⊕{test123}\nother=o+{value456}";

    // Seal
    let sealed = processor.encrypt_content(original).expect("Failed to seal");
    assert!(sealed.contains("⊠{"));

    // Open
    let opened = processor.decrypt_content(&sealed).expect("Failed to open");

    // Render both to compare
    let rendered_opened = processor
        .decrypt_to_raw(&opened)
        .expect("Failed to render opened");
    let expected_raw = "secret=test123\nother=value456";

    assert_eq!(rendered_opened, expected_raw);
}

#[test]
#[serial]
fn test_multiple_secrets_in_content() {
    let (_temp_dir, _username, repository_key) = setup_test_project();
    let processor = Processor::new(repository_key).expect("Failed to create processor");

    let input = r#"
database:
  host: localhost
  user: ⊕{dbuser}
  password: ⊕{dbpass123}

api:
  key: o+{apikey456}
  secret: ⊕{apisecret789}
"#;

    // Seal all secrets
    let sealed = processor.encrypt_content(input).expect("Failed to seal");

    // Count encrypted markers
    let encrypted_count = sealed.matches("⊠{").count();
    assert_eq!(encrypted_count, 4, "Should have 4 encrypted secrets");

    // Open and render
    let opened = processor.decrypt_content(&sealed).expect("Failed to open");
    let rendered = processor.decrypt_to_raw(&opened).expect("Failed to render");

    // Verify all secrets are present in rendered output
    assert!(rendered.contains("dbuser"));
    assert!(rendered.contains("dbpass123"));
    assert!(rendered.contains("apikey456"));
    assert!(rendered.contains("apisecret789"));
}

#[test]
#[serial]
fn test_empty_content() {
    let (_temp_dir, _username, repository_key) = setup_test_project();
    let processor = Processor::new(repository_key).expect("Failed to create processor");

    let empty = "";
    let result = processor.encrypt_content(empty).expect("Failed to seal");
    assert_eq!(result, "");
}

#[test]
#[serial]
fn test_content_without_markers() {
    let (_temp_dir, _username, repository_key) = setup_test_project();
    let processor = Processor::new(repository_key).expect("Failed to create processor");

    let input = "This is plain text without any markers";
    let output = processor.encrypt_content(input).expect("Failed to seal");
    assert_eq!(output, input);
}

#[test]
#[serial]
fn test_mixed_encrypted_and_plain() {
    let (_temp_dir, _username, repository_key) = setup_test_project();
    let processor = Processor::new(repository_key).expect("Failed to create processor");

    // Create content with both plain and marked secrets
    let input = "plain_value=123\nsecret=⊕{hidden}";

    let sealed = processor.encrypt_content(input).expect("Failed to seal");

    // Plain value should remain unchanged
    assert!(sealed.contains("plain_value=123"));
    // Secret should be encrypted
    assert!(sealed.contains("⊠{"));
    assert!(!sealed.contains("⊕{hidden}"));
}

#[test]
#[serial]
fn test_unicode_content_in_secrets() {
    let (_temp_dir, _username, repository_key) = setup_test_project();
    let processor = Processor::new(repository_key).expect("Failed to create processor");

    let input = "emoji=⊕{🔐🔑}\nunicode=⊕{日本語}";

    let sealed = processor.encrypt_content(input).expect("Failed to seal");
    let opened = processor.decrypt_content(&sealed).expect("Failed to open");
    let rendered = processor.decrypt_to_raw(&opened).expect("Failed to render");

    assert!(rendered.contains("🔐🔑"));
    assert!(rendered.contains("日本語"));
}

#[test]
#[serial]
fn test_newlines_in_secrets() {
    let (_temp_dir, _username, repository_key) = setup_test_project();
    let processor = Processor::new(repository_key).expect("Failed to create processor");

    let input =
        "cert=⊕{-----BEGIN CERTIFICATE-----\nMIIBkTCB+wIJAKHHCgVZU\n-----END CERTIFICATE-----}";

    let sealed = processor.encrypt_content(input).expect("Failed to seal");
    let opened = processor.decrypt_content(&sealed).expect("Failed to open");
    let rendered = processor.decrypt_to_raw(&opened).expect("Failed to render");

    assert!(rendered.contains("BEGIN CERTIFICATE"));
    assert!(rendered.contains("END CERTIFICATE"));
}

#[test]
#[serial]
fn test_special_characters_in_secrets() {
    let (_temp_dir, _username, repository_key) = setup_test_project();
    let processor = Processor::new(repository_key).expect("Failed to create processor");

    let input = r#"password=⊕{p@$$w0rd!#%&*()}"#;

    let sealed = processor.encrypt_content(input).expect("Failed to seal");
    let opened = processor.decrypt_content(&sealed).expect("Failed to open");
    let rendered = processor.decrypt_to_raw(&opened).expect("Failed to render");

    assert_eq!(rendered, "password=p@$$w0rd!#%&*()");
}

#[test]
#[serial]
fn test_processor_toggle_behavior() {
    let (_temp_dir, _username, repository_key) = setup_test_project();
    let processor = Processor::new(repository_key).expect("Failed to create processor");

    let input = "secret=⊕{value}";

    // Seal once
    let sealed = processor.encrypt_content(input).expect("Failed to seal");
    assert!(sealed.contains("⊠{"));

    // Processing sealed content opens it back to plaintext markers
    let opened = processor.decrypt_content(&sealed).expect("Failed to open");
    assert!(opened.contains("⊕{"));

    // Processing again seals it
    let resealed = processor
        .process_content(&opened)
        .expect("Failed to reseal");
    assert!(resealed.contains("⊠{"));

    // All should render to the same raw value
    let rendered = processor.decrypt_to_raw(&sealed).expect("Failed to render");
    assert_eq!(rendered, "secret=value");
}

#[test]
#[serial]
fn test_different_nonces_produce_different_ciphertexts() {
    let (_temp_dir, _username, repository_key) = setup_test_project();
    let processor = Processor::new(repository_key).expect("Failed to create processor");

    let input = "secret=⊕{same-value}";

    // Encrypt twice
    let sealed1 = processor.process_content(input).expect("Failed to seal");
    let sealed2 = processor.process_content(input).expect("Failed to seal");

    // Ciphertexts should be different due to random nonces
    assert_ne!(sealed1, sealed2);

    // But both should decrypt to the same plaintext
    let opened1 = processor.process_content(&sealed1).expect("Failed to open");
    let opened2 = processor.process_content(&sealed2).expect("Failed to open");

    let rendered1 = processor
        .decrypt_to_raw(&opened1)
        .expect("Failed to render");
    let rendered2 = processor
        .decrypt_to_raw(&opened2)
        .expect("Failed to render");

    assert_eq!(rendered1, "secret=same-value");
    assert_eq!(rendered2, "secret=same-value");
}

#[test]
#[serial]
fn test_ascii_marker_conversion() {
    let (_temp_dir, _username, repository_key) = setup_test_project();
    let processor = Processor::new(repository_key).expect("Failed to create processor");

    // Input with ASCII marker
    let input = "secret=o+{value}";

    let sealed = processor.encrypt_content(input).expect("Failed to seal");
    let opened = processor.decrypt_content(&sealed).expect("Failed to open");

    // Opening should convert to UTF-8 marker by default
    assert!(opened.contains("⊕{value}"));
}

#[test]
#[serial]
fn test_large_secret() {
    let (_temp_dir, _username, repository_key) = setup_test_project();
    let processor = Processor::new(repository_key).expect("Failed to create processor");

    // Create a large secret (1MB)
    // MAX_MARKER_CONTENT_SIZE is now 100MB, so 1MB is well within limits
    // This tests that large secrets are handled correctly
    let large_secret = "A".repeat(1024 * 1024);
    let input = format!("data=⊕{{{}}}", large_secret);

    let sealed = processor.process_content(&input).expect("Failed to seal");
    let opened = processor.decrypt_content(&sealed).expect("Failed to open");
    let rendered = processor.decrypt_to_raw(&opened).expect("Failed to render");

    assert_eq!(rendered, format!("data={}", large_secret));
}

#[test]
#[serial]
fn test_seal_leaves_encrypted_content_unchanged() {
    let (_temp_dir, _username, repository_key) = setup_test_project();
    let processor = Processor::new(repository_key).expect("Failed to create processor");

    // Create content that's already sealed
    let plaintext = "value=⊕{secret}";
    let sealed = processor
        .encrypt_content(plaintext)
        .expect("Failed to seal");

    // Sealing again should leave it unchanged (no plaintext markers to encrypt)
    let sealed_again = processor
        .encrypt_content(&sealed)
        .expect("Failed to seal again");
    assert_eq!(sealed, sealed_again);
}

#[test]
#[serial]
fn test_open_leaves_plaintext_markers_unchanged() {
    let (_temp_dir, _username, repository_key) = setup_test_project();
    let processor = Processor::new(repository_key).expect("Failed to create processor");

    // Content with plaintext markers
    let plaintext = "value=⊕{secret}";

    // Opening content with no ciphertext should leave it unchanged
    let opened = processor
        .decrypt_content(plaintext)
        .expect("Failed to open");
    assert_eq!(plaintext, opened);
}

#[test]
#[serial]
fn test_seal_and_open_are_independent() {
    let (_temp_dir, _username, repository_key) = setup_test_project();
    let processor = Processor::new(repository_key).expect("Failed to create processor");

    // Mix of plaintext and ciphertext
    let plaintext = "plain=⊕{secret1}";
    let sealed_part = processor
        .encrypt_content(plaintext)
        .expect("Failed to seal");

    // Create mixed content (this would be the result of partial encryption)
    let mixed = format!("{}\nmore=⊕{{secret2}}", sealed_part);

    // Seal should only encrypt the plaintext marker
    let sealed_mixed = processor
        .encrypt_content(&mixed)
        .expect("Failed to seal mixed");

    // Count ciphertext markers - should have 2 (one from before, one just encrypted)
    assert_eq!(sealed_mixed.matches("⊠{").count(), 2);
    assert_eq!(sealed_mixed.matches("⊕{").count(), 0);
}

// Note: Environment variable tests for SSS_USER vs USER/USERNAME priority
// and stdin input tests would require spawning the sss binary with specific
// environment variables and input, which is better done in a separate
// end-to-end integration test suite.

#[test]
#[serial]
fn test_nested_braces_in_json() {
    let (_temp_dir, _username, repository_key) = setup_test_project();
    let processor = Processor::new(repository_key).expect("Failed to create processor");

    // Test nested JSON in plaintext marker
    let input = r#"config=⊕{{"key":"value","nested":{"inner":"data"}}}"#;
    let sealed = processor.encrypt_content(input).expect("Failed to seal");

    // Should have one encrypted marker
    assert_eq!(sealed.matches("⊠{").count(), 1);
    assert!(!sealed.contains("⊕{"));

    // Open and render to verify content
    let opened = processor.decrypt_content(&sealed).expect("Failed to open");
    let rendered = processor.decrypt_to_raw(&opened).expect("Failed to render");

    assert_eq!(rendered, r#"config={"key":"value","nested":{"inner":"data"}}"#);
}

#[test]
#[serial]
fn test_nested_braces_in_yaml() {
    let (_temp_dir, _username, repository_key) = setup_test_project();
    let processor = Processor::new(repository_key).expect("Failed to create processor");

    // Test nested YAML-like structure
    let input = "data=o+{a:{b:{c:value}}}";
    let sealed = processor.encrypt_content(input).expect("Failed to seal");

    assert!(sealed.contains("⊠{"));
    assert!(!sealed.contains("o+{"));

    let opened = processor.decrypt_content(&sealed).expect("Failed to open");
    let rendered = processor.decrypt_to_raw(&opened).expect("Failed to render");

    assert_eq!(rendered, "data=a:{b:{c:value}}");
}

#[test]
#[serial]
fn test_secrets_interpolation_angle_bracket_normalization() {
    let (_temp_dir, _username, repository_key) = setup_test_project();
    let processor = Processor::new(repository_key).expect("Failed to create processor");

    // Test that <{...} markers are normalized to ⊲{...} (UTF-8 style)
    let input = "secret=<{SECRET_NAME}";
    let sealed = processor.encrypt_content(input).expect("Failed to seal");

    // Should be normalized to UTF-8 style but NOT encrypted
    assert!(!sealed.contains("⊠{"));
    assert!(!sealed.contains("<{"));
    assert!(sealed.contains("⊲{SECRET_NAME}"));
}

#[test]
#[serial]
fn test_secrets_interpolation_marker() {
    let (_temp_dir, _username, repository_key) = setup_test_project();
    let processor = Processor::new(repository_key).expect("Failed to create processor");

    // Test ⊲{...} secrets interpolation marker - should NOT be encrypted
    let input = "password=⊲{DB_PASSWORD}";
    let sealed = processor.encrypt_content(input).expect("Failed to seal");

    // Interpolation markers are not encrypted - they pass through unchanged
    assert!(!sealed.contains("⊠{"));
    assert!(sealed.contains("⊲{DB_PASSWORD}"));
    assert_eq!(sealed, input);
}

#[test]
#[serial]
fn test_secrets_file_whole_encryption_dotsecretsfile() {
    use std::path::Path;

    let (_temp_dir, _username, repository_key) = setup_test_project();
    let processor = Processor::new(repository_key).expect("Failed to create processor");

    let secrets_content = "DB_HOST: localhost\nDB_PASSWORD: secret123\nAPI_KEY: mykey\n";
    let file_path = Path::new("config.secrets");

    // Seal with path - should encrypt entire file
    let sealed = processor
        .seal_content_with_path(secrets_content, file_path)
        .expect("Failed to seal secrets file");

    // Should be a single encrypted block with POSIX newline
    assert!(sealed.starts_with("⊠{"));
    assert!(sealed.ends_with("}\n"), "Sealed secrets file should end with POSIX newline");
    assert_eq!(sealed.matches("⊠{").count(), 1);
    assert!(!sealed.contains("DB_HOST"));
    assert!(!sealed.contains("DB_PASSWORD"));

    // Open with path - should return plain text with NO markers
    let opened = processor
        .open_content_with_path(&sealed, file_path)
        .expect("Failed to open secrets file");

    assert_eq!(opened, secrets_content);
    assert!(!opened.contains("⊠{"));
    assert!(!opened.contains("⊕{"));
    assert!(!opened.contains("⊲{"));
}

#[test]
#[serial]
fn test_secrets_file_whole_encryption_named_secrets() {
    use std::path::Path;

    let (_temp_dir, _username, repository_key) = setup_test_project();
    let processor = Processor::new(repository_key).expect("Failed to create processor");

    let secrets_content = "ldap-bind-password: mypass\njwt-secret: secret123\n";
    let file_path = Path::new("secrets");

    // Seal file named "secrets"
    let sealed = processor
        .seal_content_with_path(secrets_content, file_path)
        .expect("Failed to seal secrets file");

    // Should be a single encrypted block with POSIX newline
    assert!(sealed.starts_with("⊠{"));
    assert!(sealed.ends_with("}\n"), "Sealed secrets file should end with POSIX newline");
    assert_eq!(sealed.matches("⊠{").count(), 1);

    // Open should return plain text with NO markers
    let opened = processor
        .open_content_with_path(&sealed, file_path)
        .expect("Failed to open secrets file");

    assert_eq!(opened, secrets_content);
    assert!(!opened.contains("⊠{"));
    assert!(!opened.contains("⊕{"));
}

#[test]
#[serial]
fn test_secrets_file_vs_regular_file() {
    use std::path::Path;

    let (_temp_dir, _username, repository_key) = setup_test_project();
    let processor = Processor::new(repository_key).expect("Failed to create processor");

    let content = "password=⊕{secret123}";

    // Regular file - encrypts markers only
    let regular_file = Path::new("config.yaml");
    let sealed_regular = processor
        .seal_content_with_path(content, regular_file)
        .expect("Failed to seal regular file");

    // Should have encrypted marker, but "password=" prefix remains
    assert!(sealed_regular.contains("password=⊠{"));

    // Secrets file - encrypts entire content as-is (including the marker text itself)
    let secrets_file = Path::new("config.secrets");
    let sealed_secrets = processor
        .seal_content_with_path(content, secrets_file)
        .expect("Failed to seal secrets file");

    // Should be single encrypted block, no prefix
    assert!(sealed_secrets.starts_with("⊠{"));
    assert!(!sealed_secrets.contains("password="));

    // Opening regular file - returns plaintext markers
    let opened_regular = processor
        .open_content_with_path(&sealed_regular, regular_file)
        .expect("Failed to open regular file");

    assert!(opened_regular.contains("⊕{secret123}"));

    // Opening secrets file - returns the exact original content (secrets files don't process markers)
    let opened_secrets = processor
        .open_content_with_path(&sealed_secrets, secrets_file)
        .expect("Failed to open secrets file");

    // Secrets file seals/unseals entire content as-is - it doesn't process the markers inside
    assert_eq!(opened_secrets, "password=⊕{secret123}");
}

#[test]
#[serial]
fn test_multiple_nested_markers_in_content() {
    let (_temp_dir, _username, repository_key) = setup_test_project();
    let processor = Processor::new(repository_key).expect("Failed to create processor");

    let input = r#"
config:
  json: ⊕{{"key":"value","nested":{"data":"here"}}}
  yaml: o+{a:{b:{c:d}}}
  secret_ref: <{API_KEY}
  plain_text: not a marker
"#;

    let sealed = processor.encrypt_content(input).expect("Failed to seal");

    // Should have 2 encrypted markers (⊕{} and o+{} only, not <{} which is for interpolation)
    assert_eq!(sealed.matches("⊠{").count(), 2);
    assert!(!sealed.contains("⊕{"));
    assert!(!sealed.contains("o+{"));
    // <{} markers are normalized to ⊲{} for interpolation
    assert!(!sealed.contains("<{"));
    assert!(sealed.contains("⊲{API_KEY}"));
    assert!(sealed.contains("plain_text: not a marker"));

    let opened = processor.decrypt_content(&sealed).expect("Failed to open");
    let rendered = processor.decrypt_to_raw(&opened).expect("Failed to render");

    // Verify all content is correctly decrypted
    assert!(rendered.contains(r#"{"key":"value","nested":{"data":"here"}}"#));
    assert!(rendered.contains("a:{b:{c:d}}"));
    assert!(rendered.contains("API_KEY"));
    assert!(rendered.contains("plain_text: not a marker"));
}

#[test]
#[serial]
fn test_empty_braces_in_markers() {
    let (_temp_dir, _username, repository_key) = setup_test_project();
    let processor = Processor::new(repository_key).expect("Failed to create processor");

    // Test empty nested braces
    let input = "data=⊕{{}}";
    let sealed = processor.encrypt_content(input).expect("Failed to seal");

    assert!(sealed.contains("⊠{"));

    let opened = processor.decrypt_content(&sealed).expect("Failed to open");
    let rendered = processor.decrypt_to_raw(&opened).expect("Failed to render");

    assert_eq!(rendered, "data={}");
}

#[test]
#[serial]
fn test_deeply_nested_braces() {
    let (_temp_dir, _username, repository_key) = setup_test_project();
    let processor = Processor::new(repository_key).expect("Failed to create processor");

    // Test deeply nested structure
    let input = "config=o+{a:{b:{c:{d:{e:{f:value}}}}}}";
    let sealed = processor.encrypt_content(input).expect("Failed to seal");

    assert!(sealed.contains("⊠{"));

    let opened = processor.decrypt_content(&sealed).expect("Failed to open");
    let rendered = processor.decrypt_to_raw(&opened).expect("Failed to render");

    assert_eq!(rendered, "config=a:{b:{c:{d:{e:{f:value}}}}}");
}

#[test]
#[serial]
fn test_secrets_file_posix_newline_and_idempotent_seal() {
    let (_temp_dir, _username, repository_key) = setup_test_project();
    let processor = Processor::new(repository_key).expect("Failed to create processor");

    // Test POSIX compliance: sealed .secrets files should end with newline
    let plaintext = "password: secret123";
    let secrets_path = Path::new("test.secrets");

    // First seal
    let sealed1 = processor.seal_content_with_path(plaintext, secrets_path)
        .expect("Failed to seal");

    // Verify ends with newline (POSIX compliance)
    assert!(sealed1.ends_with('\n'), "Sealed secrets file should end with newline for POSIX compliance");
    assert!(sealed1.starts_with("⊠{"), "Sealed content should start with encrypted marker");

    // Second seal (should be idempotent - no double encryption)
    let sealed2 = processor.seal_content_with_path(&sealed1, secrets_path)
        .expect("Failed to seal again");

    // Verify idempotent: sealing an already-sealed file should not change it
    assert_eq!(sealed1, sealed2, "Sealing should be idempotent - no double encryption");

    // Open (decrypt) the sealed content
    let opened = processor.open_content_with_path(&sealed1, secrets_path)
        .expect("Failed to open");

    assert_eq!(opened, plaintext, "Opening should return original plaintext");

    // Re-seal after opening (new nonce, but still ends with newline)
    let sealed3 = processor.seal_content_with_path(&opened, secrets_path)
        .expect("Failed to re-seal");

    assert!(sealed3.ends_with('\n'), "Re-sealed content should still end with newline");
    assert_ne!(sealed1, sealed3, "Re-sealing should use a new nonce (different ciphertext)");

    // Verify the cycle doesn't accumulate newlines
    assert_eq!(sealed3.matches('\n').count(), 1, "Should have exactly one newline");
}
