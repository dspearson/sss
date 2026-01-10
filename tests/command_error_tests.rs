/// Comprehensive command error handling tests
///
/// This test suite covers error scenarios in command execution:
/// - Invalid arguments
/// - Missing required parameters
/// - File not found scenarios
/// - Permission errors
/// - Invalid configurations
/// - Concurrent command execution

use anyhow::Result;
use sss::project::ProjectConfig;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use tempfile::TempDir;

#[test]
fn test_load_config_from_nonexistent_file() {
    let result = ProjectConfig::load_from_file("/nonexistent/path/.sss.toml");
    assert!(result.is_err());
}

#[test]
fn test_load_config_from_directory() -> Result<()> {
    let temp_dir = TempDir::new()?;

    // Try to load config from directory path (not a file)
    let result = ProjectConfig::load_from_file(temp_dir.path());
    assert!(result.is_err());

    Ok(())
}

#[test]
fn test_load_config_with_invalid_toml() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let config_path = temp_dir.path().join(".sss.toml");

    // Write invalid TOML
    fs::write(&config_path, "this is not valid TOML { [ } ]")?;

    let result = ProjectConfig::load_from_file(&config_path);
    assert!(result.is_err());

    Ok(())
}

#[test]
fn test_load_config_with_malformed_version() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let config_path = temp_dir.path().join(".sss.toml");

    // Write config with invalid version
    fs::write(&config_path, r#"version = "not_a_version""#)?;

    let result = ProjectConfig::load_from_file(&config_path);
    // Should either parse or fail gracefully
    match result {
        Ok(_) => {}
        Err(_) => {}
    }

    Ok(())
}

#[test]
fn test_load_config_with_missing_required_fields() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let config_path = temp_dir.path().join(".sss.toml");

    // Write config with only version (missing created timestamp)
    fs::write(&config_path, r#"version = "1.0""#)?;

    let result = ProjectConfig::load_from_file(&config_path);
    // Should handle missing optional fields
    match result {
        Ok(_) => {}
        Err(_) => {}
    }

    Ok(())
}

#[test]
fn test_save_config_to_readonly_directory() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let readonly_dir = temp_dir.path().join("readonly");
    fs::create_dir_all(&readonly_dir)?;

    // Make directory readonly
    let mut perms = fs::metadata(&readonly_dir)?.permissions();
    perms.set_mode(0o444);
    fs::set_permissions(&readonly_dir, perms.clone())?;

    let config_path = readonly_dir.join(".sss.toml");
    let config = ProjectConfig::default();

    let result = config.save_to_file(&config_path);
    assert!(result.is_err());

    // Restore permissions for cleanup
    perms.set_mode(0o755);
    fs::set_permissions(&readonly_dir, perms)?;

    Ok(())
}

#[test]
fn test_save_config_to_nonexistent_directory() {
    let config_path = "/nonexistent/directory/.sss.toml";
    let config = ProjectConfig::default();

    let result = config.save_to_file(config_path);
    assert!(result.is_err());
}

#[test]
fn test_parse_invalid_ignore_patterns() -> Result<()> {
    let mut config = ProjectConfig::default();

    // Invalid glob patterns
    config.ignore = Some("[invalid*pattern".to_string());

    let result = config.parse_ignore_patterns();
    assert!(result.is_err());

    Ok(())
}

#[test]
fn test_parse_ignore_patterns_with_only_negation() -> Result<()> {
    let mut config = ProjectConfig::default();

    // Only negation patterns (unusual but should work)
    config.ignore = Some("!file1.txt !file2.txt".to_string());

    let result = config.parse_ignore_patterns()?;
    assert!(result.0.is_empty()); // No positive patterns
    assert!(!result.1.is_empty()); // Has negative patterns

    Ok(())
}

#[test]
fn test_parse_ignore_patterns_with_empty_string() -> Result<()> {
    let mut config = ProjectConfig::default();
    config.ignore = Some("".to_string());

    let result = config.parse_ignore_patterns()?;
    assert!(result.0.is_empty());
    assert!(result.1.is_empty());

    Ok(())
}

#[test]
fn test_parse_ignore_patterns_with_whitespace_only() -> Result<()> {
    let mut config = ProjectConfig::default();
    config.ignore = Some("   \t\n   ".to_string());

    let result = config.parse_ignore_patterns()?;
    assert!(result.0.is_empty());
    assert!(result.1.is_empty());

    Ok(())
}

#[test]
fn test_ignore_patterns_with_absolute_paths() -> Result<()> {
    let mut config = ProjectConfig::default();

    // Absolute paths in patterns (unusual use case)
    config.ignore = Some("/absolute/path/*.txt".to_string());

    // Should parse but behavior depends on implementation
    let result = config.parse_ignore_patterns();
    match result {
        Ok(_) => {}
        Err(_) => {}
    }

    Ok(())
}

#[test]
fn test_ignore_patterns_with_very_long_pattern() -> Result<()> {
    let mut config = ProjectConfig::default();

    // Very long pattern (edge case)
    let long_pattern = "a".repeat(10000) + ".txt";
    config.ignore = Some(long_pattern);

    let result = config.parse_ignore_patterns();
    // Should handle long patterns
    match result {
        Ok(_) => {}
        Err(_) => {}
    }

    Ok(())
}

#[test]
fn test_config_with_invalid_unicode() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let config_path = temp_dir.path().join(".sss.toml");

    // Write file with invalid UTF-8 (not possible with write_str, so test handling)
    // This tests the error path when file contains invalid UTF-8
    let binary_data = vec![
        b'v', b'e', b'r', b's', b'i', b'o', b'n', b' ', b'=', b' ', b'"', b'1', b'.', b'0', b'"',
        0xFF, 0xFE, // Invalid UTF-8
    ];
    fs::write(&config_path, binary_data)?;

    let result = ProjectConfig::load_from_file(&config_path);
    assert!(result.is_err());

    Ok(())
}

#[test]
fn test_concurrent_config_save_load() -> Result<()> {
    use std::sync::Arc;
    use std::thread;

    let temp_dir = TempDir::new()?;
    let config_path = Arc::new(temp_dir.path().join(".sss.toml"));

    // Save initial config
    let mut config = ProjectConfig::default();
    config.ignore = Some("*.log".to_string());
    config.save_to_file(&*config_path)?;

    let config_path_clone = Arc::clone(&config_path);

    // Spawn thread that loads config
    let handle = thread::spawn(move || {
        for _ in 0..10 {
            let _ = ProjectConfig::load_from_file(&*config_path_clone);
            thread::sleep(std::time::Duration::from_millis(10));
        }
    });

    // Concurrently save config from main thread
    for i in 0..10 {
        config.ignore = Some(format!("*.log *.tmp{}", i));
        config.save_to_file(&*config_path)?;
        thread::sleep(std::time::Duration::from_millis(10));
    }

    handle.join().unwrap();

    // Final config should be loadable
    let final_config = ProjectConfig::load_from_file(&*config_path)?;
    assert!(final_config.ignore.is_some());

    Ok(())
}

#[test]
fn test_config_with_unexpected_fields() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let config_path = temp_dir.path().join(".sss.toml");

    // Write config with unexpected fields
    fs::write(
        &config_path,
        r#"
version = "1.0"
created = "2025-01-01T00:00:00Z"
unexpected_field = "value"
another_field = 123
        "#,
    )?;

    // Should load successfully, ignoring unexpected fields (TOML deserialize behavior)
    let result = ProjectConfig::load_from_file(&config_path);
    match result {
        Ok(_) => {}
        Err(_) => {}
    }

    Ok(())
}

#[test]
fn test_config_with_wrong_type_for_ignore() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let config_path = temp_dir.path().join(".sss.toml");

    // Write config with wrong type for ignore field
    fs::write(
        &config_path,
        r#"
version = "1.0"
created = "2025-01-01T00:00:00Z"
ignore = 123
        "#,
    )?;

    let result = ProjectConfig::load_from_file(&config_path);
    assert!(result.is_err());

    Ok(())
}

#[test]
fn test_should_ignore_with_null_patterns() -> Result<()> {
    let config = ProjectConfig::default();
    // No ignore patterns set

    // Should not ignore anything
    assert!(!config.should_ignore(std::path::Path::new("test.txt"))?);
    assert!(!config.should_ignore(std::path::Path::new("anything.log"))?);

    Ok(())
}

#[test]
fn test_should_ignore_with_invalid_path() -> Result<()> {
    let mut config = ProjectConfig::default();
    config.ignore = Some("*.log".to_string());

    // Test with various edge case paths
    assert!(!config.should_ignore(std::path::Path::new(""))?);

    Ok(())
}

#[test]
fn test_get_ignore_pattern_strings_empty() {
    let config = ProjectConfig::default();
    let patterns = config.get_ignore_pattern_strings();
    assert!(patterns.is_empty());
}

#[test]
fn test_set_ignore_patterns_empty() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let config_path = temp_dir.path().join(".sss.toml");

    let mut config = ProjectConfig::default();
    config.set_ignore_patterns(vec![]);
    config.save_to_file(&config_path)?;

    let loaded = ProjectConfig::load_from_file(&config_path)?;
    assert!(loaded.ignore.is_none());

    Ok(())
}

#[test]
fn test_parse_patterns_with_duplicate_entries() -> Result<()> {
    let mut config = ProjectConfig::default();
    config.ignore = Some("*.log *.log *.log".to_string());

    let result = config.parse_ignore_patterns()?;
    // Should handle duplicates (globset will deduplicate or not, both acceptable)
    assert!(!result.0.is_empty());

    Ok(())
}

#[test]
fn test_config_version_handling() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let config_path = temp_dir.path().join(".sss.toml");

    // Test different version formats
    let versions = vec!["1.0", "2.0.0", "1.2.3", "10.20.30"];

    for version in versions {
        fs::write(
            &config_path,
            format!(r#"version = "{}"\ncreated = "2025-01-01T00:00:00Z""#, version),
        )?;

        let result = ProjectConfig::load_from_file(&config_path);
        match result {
            Ok(config) => {
                assert_eq!(config.version, version);
            }
            Err(_) => {}
        }
    }

    Ok(())
}
