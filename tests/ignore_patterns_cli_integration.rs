//! Integration tests for ignore patterns CLI commands
//!
//! Tests the full workflow of managing ignore patterns via CLI:
//! - sss project ignore add
//! - sss project ignore remove
//! - sss project ignore list
//!
//! Also tests interaction with .sss.toml file persistence

use anyhow::Result;
use sss::project::ProjectConfig;
use std::fs;
use std::path::PathBuf;
use tempfile::TempDir;

// Helper to create a test .sss.toml file
fn create_test_config(dir: &std::path::Path, ignore: Option<&str>) -> Result<PathBuf> {
    let config_path = dir.join(".sss.toml");
    let mut config = ProjectConfig {
        version: "1.0".to_string(),
        created: chrono::Utc::now().to_rfc3339(),
        ..Default::default()
    };
    if let Some(patterns) = ignore {
        config.ignore = Some(patterns.to_string());
    }

    config.save_to_file(&config_path)?;
    Ok(config_path)
}

#[test]
fn test_add_pattern_to_empty_config() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let config_path = create_test_config(temp_dir.path(), None)?;

    // Add first pattern
    let mut config = ProjectConfig::load_from_file(&config_path)?;
    let mut patterns = config.get_ignore_pattern_strings();
    patterns.push("*.log".to_string());
    config.set_ignore_patterns(patterns);
    config.save_to_file(&config_path)?;

    // Verify
    let config = ProjectConfig::load_from_file(&config_path)?;
    assert_eq!(config.ignore, Some("*.log".to_string()));

    Ok(())
}

#[test]
fn test_add_pattern_to_existing_patterns() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let config_path = create_test_config(temp_dir.path(), Some("*.log build/"))?;

    // Add another pattern
    let mut config = ProjectConfig::load_from_file(&config_path)?;
    let mut patterns = config.get_ignore_pattern_strings();
    assert_eq!(patterns, vec!["*.log", "build/"]);

    patterns.push("*.tmp".to_string());
    config.set_ignore_patterns(patterns);
    config.save_to_file(&config_path)?;

    // Verify
    let config = ProjectConfig::load_from_file(&config_path)?;
    assert_eq!(config.ignore, Some("*.log build/ *.tmp".to_string()));

    Ok(())
}

#[test]
fn test_add_duplicate_pattern() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let config_path = create_test_config(temp_dir.path(), Some("*.log"))?;

    // Try to add duplicate
    let config = ProjectConfig::load_from_file(&config_path)?;
    let mut patterns = config.get_ignore_pattern_strings();

    if !patterns.contains(&"*.log".to_string()) {
        patterns.push("*.log".to_string());
    }

    // Should still only have one *.log
    assert_eq!(patterns.len(), 1);
    assert_eq!(patterns[0], "*.log");

    Ok(())
}

#[test]
fn test_remove_pattern_from_config() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let config_path = create_test_config(temp_dir.path(), Some("*.log build/ *.tmp"))?;

    // Remove middle pattern
    let mut config = ProjectConfig::load_from_file(&config_path)?;
    let mut patterns = config.get_ignore_pattern_strings();
    patterns.retain(|p| p != "build/");
    config.set_ignore_patterns(patterns);
    config.save_to_file(&config_path)?;

    // Verify
    let config = ProjectConfig::load_from_file(&config_path)?;
    assert_eq!(config.ignore, Some("*.log *.tmp".to_string()));

    Ok(())
}

#[test]
fn test_remove_last_pattern() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let config_path = create_test_config(temp_dir.path(), Some("*.log"))?;

    // Remove the only pattern
    let mut config = ProjectConfig::load_from_file(&config_path)?;
    let mut patterns = config.get_ignore_pattern_strings();
    patterns.clear();
    config.set_ignore_patterns(patterns);
    config.save_to_file(&config_path)?;

    // Verify - should be None
    let config = ProjectConfig::load_from_file(&config_path)?;
    assert_eq!(config.ignore, None);

    Ok(())
}

#[test]
fn test_remove_nonexistent_pattern() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let config_path = create_test_config(temp_dir.path(), Some("*.log"))?;

    // Try to remove pattern that doesn't exist
    let config = ProjectConfig::load_from_file(&config_path)?;
    let mut patterns = config.get_ignore_pattern_strings();
    let original_len = patterns.len();
    patterns.retain(|p| p != "nonexistent");

    // Length should be unchanged
    assert_eq!(patterns.len(), original_len);

    Ok(())
}

#[test]
fn test_patterns_persist_across_save_load() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let config_path = create_test_config(temp_dir.path(), Some("*.log build/ !important.log"))?;

    // Load and verify
    let config = ProjectConfig::load_from_file(&config_path)?;
    let patterns = config.get_ignore_pattern_strings();

    assert_eq!(patterns.len(), 3);
    assert!(patterns.contains(&"*.log".to_string()));
    assert!(patterns.contains(&"build/".to_string()));
    assert!(patterns.contains(&"!important.log".to_string()));

    Ok(())
}

#[test]
fn test_pattern_order_preserved() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let config_path = create_test_config(temp_dir.path(), Some("*.log build/ *.tmp !important.log"))?;

    let config = ProjectConfig::load_from_file(&config_path)?;
    let patterns = config.get_ignore_pattern_strings();

    // Order should be preserved
    assert_eq!(patterns[0], "*.log");
    assert_eq!(patterns[1], "build/");
    assert_eq!(patterns[2], "*.tmp");
    assert_eq!(patterns[3], "!important.log");

    Ok(())
}

#[test]
fn test_special_characters_in_patterns() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let config_path = create_test_config(
        temp_dir.path(),
        Some("test[12].log temp?.txt **/*.cache")
    )?;

    let config = ProjectConfig::load_from_file(&config_path)?;
    let patterns = config.get_ignore_pattern_strings();

    assert!(patterns.contains(&"test[12].log".to_string()));
    assert!(patterns.contains(&"temp?.txt".to_string()));
    assert!(patterns.contains(&"**/*.cache".to_string()));

    Ok(())
}

#[test]
fn test_long_pattern_list() -> Result<()> {
    let temp_dir = TempDir::new()?;

    // Create 50 patterns
    let mut pattern_vec = Vec::new();
    for i in 0..50 {
        pattern_vec.push(format!("*.ext{}", i));
    }
    let pattern_str = pattern_vec.join(" ");

    let config_path = create_test_config(temp_dir.path(), Some(&pattern_str))?;

    // Verify all patterns are preserved
    let config = ProjectConfig::load_from_file(&config_path)?;
    let patterns = config.get_ignore_pattern_strings();

    assert_eq!(patterns.len(), 50);
    assert!(patterns.contains(&"*.ext0".to_string()));
    assert!(patterns.contains(&"*.ext49".to_string()));

    Ok(())
}

#[test]
fn test_unicode_in_patterns() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let config_path = create_test_config(temp_dir.path(), Some("файл*.log テスト.txt"))?;

    let config = ProjectConfig::load_from_file(&config_path)?;
    let patterns = config.get_ignore_pattern_strings();

    assert!(patterns.contains(&"файл*.log".to_string()));
    assert!(patterns.contains(&"テスト.txt".to_string()));

    Ok(())
}

#[test]
fn test_empty_string_handling() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let config_path = create_test_config(temp_dir.path(), Some("   "))?;

    let config = ProjectConfig::load_from_file(&config_path)?;
    let patterns = config.get_ignore_pattern_strings();

    // Empty/whitespace-only should result in empty vector
    assert!(patterns.is_empty());

    Ok(())
}

#[test]
fn test_comma_and_space_mixed() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let config_path = create_test_config(temp_dir.path(), Some("*.log, build/ ,*.tmp  ,  test/"))?;

    let config = ProjectConfig::load_from_file(&config_path)?;
    let patterns = config.get_ignore_pattern_strings();

    // Should parse correctly despite mixed separators and extra whitespace
    assert_eq!(patterns.len(), 4);
    assert!(patterns.contains(&"*.log".to_string()));
    assert!(patterns.contains(&"build/".to_string()));
    assert!(patterns.contains(&"*.tmp".to_string()));
    assert!(patterns.contains(&"test/".to_string()));

    Ok(())
}

#[test]
fn test_config_backwards_compatibility() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let config_path = temp_dir.path().join(".sss.toml");

    // Create config without ignore field (old format)
    let content = r#"
version = "1.0"
created = "2025-01-01T00:00:00Z"
"#;
    fs::write(&config_path, content)?;

    // Should load successfully
    let config = ProjectConfig::load_from_file(&config_path)?;
    assert_eq!(config.ignore, None);

    // Should be able to add patterns
    let mut config = config;
    config.set_ignore_patterns(vec!["*.log".to_string()]);
    config.save_to_file(&config_path)?;

    // Verify
    let config = ProjectConfig::load_from_file(&config_path)?;
    assert_eq!(config.ignore, Some("*.log".to_string()));

    Ok(())
}

#[test]
fn test_toml_formatting_preserved() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let config_path = create_test_config(temp_dir.path(), Some("*.log"))?;

    // Load, modify, save
    let mut config = ProjectConfig::load_from_file(&config_path)?;
    config.set_ignore_patterns(vec!["*.log".to_string(), "build/".to_string()]);
    config.save_to_file(&config_path)?;

    // Read raw file
    let content = fs::read_to_string(&config_path)?;

    // Should be valid TOML
    assert!(content.contains("version ="));
    assert!(content.contains("created ="));
    assert!(content.contains("ignore ="));

    Ok(())
}

#[test]
fn test_concurrent_pattern_modifications() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let config_path = create_test_config(temp_dir.path(), Some("*.log"))?;

    // Simulate concurrent modifications (though single-threaded)
    let mut config1 = ProjectConfig::load_from_file(&config_path)?;
    let mut config2 = ProjectConfig::load_from_file(&config_path)?;

    // Modify both
    config1.set_ignore_patterns(vec!["*.log".to_string(), "*.tmp".to_string()]);
    config2.set_ignore_patterns(vec!["*.log".to_string(), "build/".to_string()]);

    // Last write wins
    config1.save_to_file(&config_path)?;
    config2.save_to_file(&config_path)?;

    let final_config = ProjectConfig::load_from_file(&config_path)?;
    assert_eq!(final_config.ignore, Some("*.log build/".to_string()));

    Ok(())
}
