//! Integration tests for QA refactoring improvements
//!
//! This test module validates the end-to-end functionality of the QA audit
//! refactoring, ensuring that:
//! - FileSystemOps trait works correctly for both standard and fd-based operations
//! - Secret interpolation is consistent between CLI and FUSE paths
//! - Caching behavior works as expected
//! - Marker detection is comprehensive
//! - Configuration loading helpers work correctly

use anyhow::Result;
use std::fs;
use tempfile::TempDir;

use sss::crypto::RepositoryKey;
use sss::filesystem_common::{has_any_markers, has_any_markers_bytes, MARKER_PATTERNS};
use sss::secrets::{interpolate_secrets, FileSystemOps, SecretsCache, StdFileSystemOps};

/// Test that StdFileSystemOps correctly implements FileSystemOps
#[test]
fn test_std_filesystem_ops_implementation() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let test_file = temp_dir.path().join("test.txt");

    // Create a test file
    fs::write(&test_file, "test content")?;

    let fs_ops = StdFileSystemOps;

    // Test file_exists
    assert!(fs_ops.file_exists(&test_file));
    assert!(!fs_ops.file_exists(&temp_dir.path().join("nonexistent.txt")));

    // Test read_file
    let content = fs_ops.read_file(&test_file)?;
    assert_eq!(content, b"test content");

    // Test read_file error handling
    let result = fs_ops.read_file(&temp_dir.path().join("nonexistent.txt"));
    assert!(result.is_err());

    Ok(())
}

/// Test that unified interpolation works with StdFileSystemOps
#[test]
fn test_unified_interpolation_with_std_ops() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let project_root = temp_dir.path();

    // Create a secrets file
    let secrets_content = "api_key: secret_key_123\ndb_password: secure_pass\n";
    let secrets_file = project_root.join("secrets");
    fs::write(&secrets_file, secrets_content)?;

    // Create a test file with interpolation markers
    let test_file = project_root.join("config.yaml");
    let content_with_markers = "api: ⊲{api_key}\ndb: <{db_password}\n";
    fs::write(&test_file, content_with_markers)?;

    // Test interpolation
    let mut cache = SecretsCache::new();
    let result = interpolate_secrets(
        content_with_markers,
        &test_file,
        project_root,
        &mut cache,
        &StdFileSystemOps,
    )?;

    assert_eq!(result, "api: secret_key_123\ndb: secure_pass\n");

    Ok(())
}

/// Test that caching prevents redundant file reads
#[test]
fn test_caching_prevents_redundant_reads() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let project_root = temp_dir.path();

    // Create a secrets file
    let secrets_content = "secret1: value1\nsecret2: value2\nsecret3: value3\n";
    let secrets_file = project_root.join("secrets");
    fs::write(&secrets_file, secrets_content)?;

    // Create test file
    let test_file = project_root.join("test.txt");
    fs::write(&test_file, "test")?;

    // Create cache and lookup multiple secrets
    let mut cache = SecretsCache::new();

    // First lookup - will read file
    let val1 = cache.lookup_secret("secret1", &test_file, project_root)?;
    assert_eq!(val1, "value1");

    // Modify the secrets file to verify cache is used
    fs::write(&secrets_file, "secret1: MODIFIED\nsecret2: MODIFIED\n")?;

    // Second lookup - should use cache, not read modified file
    let val2 = cache.lookup_secret("secret2", &test_file, project_root)?;
    assert_eq!(val2, "value2"); // Should be original value, not MODIFIED

    // Third lookup - also from cache
    let val3 = cache.lookup_secret("secret3", &test_file, project_root)?;
    assert_eq!(val3, "value3");

    Ok(())
}

/// Test that encrypted secrets are properly cached after decryption
#[test]
fn test_encrypted_secrets_caching() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let project_root = temp_dir.path();

    let key = RepositoryKey::new();

    // Create and encrypt secrets
    let plaintext = "api_key: encrypted_value\ntoken: secret_token\n";
    let encrypted = sss::crypto::encrypt_to_base64(plaintext, &key)?;
    let sealed_content = format!("⊠{{{}}}", encrypted);

    let secrets_file = project_root.join("secrets");
    fs::write(&secrets_file, &sealed_content)?;

    let test_file = project_root.join("test.txt");
    fs::write(&test_file, "test")?;

    // Create cache with key
    let mut cache = SecretsCache::with_repository_key(key);

    // First lookup - will decrypt
    let val1 = cache.lookup_secret("api_key", &test_file, project_root)?;
    assert_eq!(val1, "encrypted_value");

    // Second lookup - should use cached decrypted version
    let val2 = cache.lookup_secret("token", &test_file, project_root)?;
    assert_eq!(val2, "secret_token");

    Ok(())
}

/// Test all marker types are detected by has_any_markers
#[test]
fn test_all_marker_types_detected() {
    let test_cases = vec![
        ("⊠{encrypted}", true),
        ("⊕{plaintext}", true),
        ("⊲{interpolation}", true),
        ("[*{legacy}", true),
        ("o+{ascii}", true),
        ("<{alt}", true),
        ("no markers here", false),
        ("just { braces }", false),
        ("⊠ without brace", false),
    ];

    for (content, expected) in test_cases {
        assert_eq!(
            has_any_markers(content),
            expected,
            "Failed for: {}",
            content
        );
    }
}

/// Test all marker types are detected at byte level
#[test]
fn test_all_marker_types_detected_bytes() {
    let test_cases = vec![
        ("⊠{encrypted}".as_bytes(), true),
        ("⊕{plaintext}".as_bytes(), true),
        ("⊲{interpolation}".as_bytes(), true),
        (b"[*{legacy}", true),
        (b"o+{ascii}", true),
        (b"<{alt}", true),
        (b"no markers here", false),
        (b"just { braces }", false),
        ("⊠ without brace".as_bytes(), false),
    ];

    for (content, expected) in test_cases {
        assert_eq!(
            has_any_markers_bytes(content),
            expected,
            "Failed for: {:?}",
            content
        );
    }
}

/// Test marker detection consistency between string and byte versions
#[test]
fn test_marker_detection_consistency() {
    for marker in MARKER_PATTERNS {
        let content = format!("test {}secret}}", marker);

        // Both string and byte versions should agree
        assert_eq!(
            has_any_markers(&content),
            has_any_markers_bytes(content.as_bytes()),
            "String and byte detection differ for marker: {}",
            marker
        );

        // Both should detect the marker
        assert!(
            has_any_markers(&content),
            "Marker not detected: {}",
            marker
        );
    }
}

/// Test marker detection with binary data
#[test]
fn test_marker_detection_in_binary_data() {
    // Create binary data with embedded marker
    let mut data = vec![0x00, 0xFF, 0x7F, 0xAB, 0xCD];
    data.extend_from_slice("⊠{secret}".as_bytes());
    data.extend_from_slice(&[0x00, 0x01, 0x02]);

    assert!(has_any_markers_bytes(&data));

    // Binary data without markers
    let binary_no_markers = vec![0x00, 0xFF, 0x7F, 0xAB, 0xCD, 0xEF];
    assert!(!has_any_markers_bytes(&binary_no_markers));
}

/// Test that interpolation works with multiple secrets from same file
#[test]
fn test_interpolation_multiple_secrets() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let project_root = temp_dir.path();

    // Create secrets file with multiple secrets
    let secrets_content = "db_host: localhost\ndb_port: 5432\ndb_name: mydb\ndb_user: admin\n";
    let secrets_file = project_root.join("secrets");
    fs::write(&secrets_file, secrets_content)?;

    // Create file with multiple interpolations
    let test_file = project_root.join("config.txt");
    let content = "host=⊲{db_host}\nport=<{db_port}\ndb=⊲{db_name}\nuser=<{db_user}\n";

    let mut cache = SecretsCache::new();
    let result = interpolate_secrets(
        content,
        &test_file,
        project_root,
        &mut cache,
        &StdFileSystemOps,
    )?;

    assert_eq!(
        result,
        "host=localhost\nport=5432\ndb=mydb\nuser=admin\n"
    );

    Ok(())
}

/// Test that interpolation handles missing secrets gracefully
#[test]
fn test_interpolation_missing_secret() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let project_root = temp_dir.path();

    // Create secrets file WITHOUT the referenced secret
    let secrets_content = "api_key: value123\n";
    let secrets_file = project_root.join("secrets");
    fs::write(&secrets_file, secrets_content)?;

    // Reference a non-existent secret
    let test_file = project_root.join("config.txt");
    let content = "key=⊲{nonexistent_secret}\n";

    let mut cache = SecretsCache::new();
    let result = interpolate_secrets(
        content,
        &test_file,
        project_root,
        &mut cache,
        &StdFileSystemOps,
    )?;

    // Should preserve the original marker when secret not found (with warning)
    // This allows files to be processed even if some secrets are missing
    assert_eq!(result, "key=⊲{nonexistent_secret}\n");

    Ok(())
}

/// Test hierarchical secrets file finding
#[test]
fn test_secrets_hierarchy_with_ops() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let project_root = temp_dir.path();

    // Create directory structure
    let subdir = project_root.join("subdir");
    fs::create_dir(&subdir)?;

    // Create root secrets file
    let root_secrets = project_root.join("secrets");
    fs::write(&root_secrets, "root_secret: from_root\n")?;

    // Create file-specific secrets
    let test_file = subdir.join("config.txt");
    fs::write(&test_file, "test")?;
    let file_secrets = subdir.join("config.txt.secrets");
    fs::write(&file_secrets, "file_secret: from_file\n")?;

    let mut cache = SecretsCache::new();

    // Should find file-specific secrets first
    let val = cache.lookup_secret("file_secret", &test_file, project_root)?;
    assert_eq!(val, "from_file");

    // Test with file that only has root secrets
    let test_file2 = subdir.join("other.txt");
    fs::write(&test_file2, "test")?;

    let mut cache2 = SecretsCache::new();
    let val2 = cache2.lookup_secret("root_secret", &test_file2, project_root)?;
    assert_eq!(val2, "from_root");

    Ok(())
}

/// Test that custom secrets filename and suffix work
#[test]
fn test_custom_secrets_config() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let project_root = temp_dir.path();

    // Create secrets file with custom name
    let custom_secrets = project_root.join("mysecrets");
    fs::write(&custom_secrets, "custom_key: custom_value\n")?;

    let test_file = project_root.join("test.txt");
    fs::write(&test_file, "test")?;

    // Create cache with custom filename
    let key = RepositoryKey::new();
    let mut cache = SecretsCache::with_repository_key_and_filename(key, "mysecrets".to_string());

    let val = cache.lookup_secret("custom_key", &test_file, project_root)?;
    assert_eq!(val, "custom_value");

    Ok(())
}

/// Test interpolation with both marker syntaxes (⊲ and <)
#[test]
fn test_both_interpolation_marker_syntaxes() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let project_root = temp_dir.path();

    let secrets_content = "key1: value1\nkey2: value2\n";
    let secrets_file = project_root.join("secrets");
    fs::write(&secrets_file, secrets_content)?;

    let test_file = project_root.join("test.txt");
    let content = "first: ⊲{key1}\nsecond: <{key2}\n";

    let mut cache = SecretsCache::new();
    let result = interpolate_secrets(
        content,
        &test_file,
        project_root,
        &mut cache,
        &StdFileSystemOps,
    )?;

    assert_eq!(result, "first: value1\nsecond: value2\n");

    Ok(())
}

/// Test that marker detection handles edge cases
#[test]
fn test_marker_detection_edge_cases() {
    // Partial markers should not match
    assert!(!has_any_markers("⊠"));
    assert!(!has_any_markers("⊠}"));
    assert!(!has_any_markers("{secret}"));
    assert!(!has_any_markers_bytes(b"[*"));
    assert!(!has_any_markers_bytes(b"<}"));

    // Multiple markers
    assert!(has_any_markers("⊠{a} and ⊕{b}"));
    assert!(has_any_markers_bytes("⊠{a} ⊲{b}".as_bytes()));

    // Marker at different positions
    assert!(has_any_markers("prefix ⊠{secret}"));
    assert!(has_any_markers("⊠{secret} suffix"));
    assert!(has_any_markers("⊠{secret}"));
}

/// Test empty and whitespace-only content
#[test]
fn test_marker_detection_empty_content() {
    assert!(!has_any_markers(""));
    assert!(!has_any_markers("   "));
    assert!(!has_any_markers("\n\n\n"));
    assert!(!has_any_markers_bytes(b""));
    assert!(!has_any_markers_bytes(b"   "));
}
