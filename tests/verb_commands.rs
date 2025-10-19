use std::env;
use tempfile::TempDir;

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
        .add_user(&username, &keypair.public_key, &repository_key)
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
fn test_empty_content() {
    let (_temp_dir, _username, repository_key) = setup_test_project();
    let processor = Processor::new(repository_key).expect("Failed to create processor");

    let empty = "";
    let result = processor.encrypt_content(empty).expect("Failed to seal");
    assert_eq!(result, "");
}

#[test]
fn test_content_without_markers() {
    let (_temp_dir, _username, repository_key) = setup_test_project();
    let processor = Processor::new(repository_key).expect("Failed to create processor");

    let input = "This is plain text without any markers";
    let output = processor.encrypt_content(input).expect("Failed to seal");
    assert_eq!(output, input);
}

#[test]
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
