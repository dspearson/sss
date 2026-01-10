// Comprehensive tests for ignore patterns functionality in .sss.toml
//
// Tests ProjectConfig.ignore field integration with FileScanner for
// gitignore-style pattern matching with negation support

use anyhow::Result;
use sss::project::ProjectConfig;
use sss::scanner::FileScanner;
use std::fs;
use std::path::Path;
use tempfile::TempDir;

// === ProjectConfig ignore pattern parsing tests ===

#[test]
fn test_parse_ignore_patterns_empty() -> Result<()> {
    let config = ProjectConfig::default();
    let (positive, negative) = config.parse_ignore_patterns()?;

    assert!(positive.is_empty());
    assert!(negative.is_empty());

    Ok(())
}

#[test]
fn test_parse_ignore_patterns_simple() -> Result<()> {
    let mut config = ProjectConfig::default();
    config.ignore = Some("*.log *.tmp".to_string());

    let (positive, negative) = config.parse_ignore_patterns()?;

    assert!(!positive.is_empty());
    assert!(negative.is_empty());

    // Test matching
    assert!(positive.is_match(Path::new("debug.log")));
    assert!(positive.is_match(Path::new("temp.tmp")));
    assert!(!positive.is_match(Path::new("data.txt")));

    Ok(())
}

#[test]
fn test_parse_ignore_patterns_with_negation() -> Result<()> {
    let mut config = ProjectConfig::default();
    config.ignore = Some("*.db !important.db".to_string());

    let (positive, negative) = config.parse_ignore_patterns()?;

    assert!(!positive.is_empty());
    assert!(!negative.is_empty());

    assert!(positive.is_match(Path::new("test.db")));
    assert!(positive.is_match(Path::new("important.db")));
    assert!(negative.is_match(Path::new("important.db")));
    assert!(!negative.is_match(Path::new("test.db")));

    Ok(())
}

#[test]
fn test_parse_ignore_patterns_comma_separated() -> Result<()> {
    let mut config = ProjectConfig::default();
    config.ignore = Some("*.log,*.tmp,build/".to_string());

    let (positive, _) = config.parse_ignore_patterns()?;

    assert!(positive.is_match(Path::new("debug.log")));
    assert!(positive.is_match(Path::new("temp.tmp")));
    assert!(positive.is_match(Path::new("build/output.txt")));

    Ok(())
}

#[test]
fn test_parse_ignore_patterns_mixed_separators() -> Result<()> {
    let mut config = ProjectConfig::default();
    config.ignore = Some("*.log build/ *.tmp,cache/".to_string());

    let (positive, _) = config.parse_ignore_patterns()?;

    assert!(positive.is_match(Path::new("debug.log")));
    assert!(positive.is_match(Path::new("temp.tmp")));
    assert!(positive.is_match(Path::new("build/file")));
    assert!(positive.is_match(Path::new("cache/data")));

    Ok(())
}

#[test]
fn test_parse_ignore_patterns_directories() -> Result<()> {
    let mut config = ProjectConfig::default();
    config.ignore = Some("build/ node_modules/".to_string());

    let (positive, _) = config.parse_ignore_patterns()?;

    assert!(positive.is_match(Path::new("build/output.txt")));
    assert!(positive.is_match(Path::new("node_modules/package.json")));
    assert!(!positive.is_match(Path::new("src/main.rs")));

    Ok(())
}

#[test]
fn test_parse_ignore_patterns_wildcard() -> Result<()> {
    let mut config = ProjectConfig::default();
    config.ignore = Some("temp*.txt *.db test_*".to_string());

    let (positive, _) = config.parse_ignore_patterns()?;

    assert!(positive.is_match(Path::new("temp123.txt")));
    assert!(positive.is_match(Path::new("temporary.txt")));
    assert!(positive.is_match(Path::new("data.db")));
    assert!(positive.is_match(Path::new("test_file")));
    assert!(!positive.is_match(Path::new("data.txt")));

    Ok(())
}

#[test]
fn test_should_ignore_no_patterns() -> Result<()> {
    let config = ProjectConfig::default();

    assert!(!config.should_ignore(Path::new("any_file.txt"))?);

    Ok(())
}

#[test]
fn test_should_ignore_matching_pattern() -> Result<()> {
    let mut config = ProjectConfig::default();
    config.ignore = Some("*.log".to_string());

    assert!(config.should_ignore(Path::new("debug.log"))?);
    assert!(!config.should_ignore(Path::new("data.txt"))?);

    Ok(())
}

#[test]
fn test_should_ignore_with_negation() -> Result<()> {
    let mut config = ProjectConfig::default();
    config.ignore = Some("*.log !important.log".to_string());

    assert!(config.should_ignore(Path::new("debug.log"))?);
    assert!(config.should_ignore(Path::new("test.log"))?);
    assert!(!config.should_ignore(Path::new("important.log"))?);
    assert!(!config.should_ignore(Path::new("data.txt"))?);

    Ok(())
}

#[test]
fn test_should_ignore_multiple_negations() -> Result<()> {
    let mut config = ProjectConfig::default();
    config.ignore = Some("*.db !session.db !user.db".to_string());

    assert!(config.should_ignore(Path::new("temp.db"))?);
    assert!(!config.should_ignore(Path::new("session.db"))?);
    assert!(!config.should_ignore(Path::new("user.db"))?);

    Ok(())
}

#[test]
fn test_should_ignore_paths() -> Result<()> {
    let mut config = ProjectConfig::default();
    config.ignore = Some("build/ temp/".to_string());

    assert!(config.should_ignore(Path::new("build/output.txt"))?);
    assert!(config.should_ignore(Path::new("temp/cache.db"))?);
    assert!(!config.should_ignore(Path::new("src/main.rs"))?);

    Ok(())
}

#[test]
fn test_invalid_pattern_error() {
    let mut config = ProjectConfig::default();
    config.ignore = Some("[invalid".to_string());

    assert!(config.parse_ignore_patterns().is_err());
}

// === FileScanner integration tests ===

#[test]
fn test_scanner_with_ignore_patterns() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let root = temp_dir.path();

    // Create test files
    fs::write(root.join("config.txt"), "api_key=⊕{secret}")?;
    fs::write(root.join("debug.log"), "password=⊕{secret}")?;
    fs::write(root.join("important.log"), "token=⊕{secret}")?;
    fs::write(root.join("data.txt"), "normal content")?;

    // Set up config with ignore patterns
    let mut config = ProjectConfig::default();
    config.ignore = Some("*.log !important.log".to_string());
    let (ignore_set, negation_set) = config.parse_ignore_patterns()?;

    // Create scanner with ignore patterns
    let mut scanner = FileScanner::new();
    scanner.set_ignore_patterns(ignore_set, negation_set);

    let results = scanner.scan_directory(root)?;

    // Should find config.txt and important.log (negated)
    // Should NOT find debug.log (ignored)
    assert_eq!(results.len(), 2);
    assert!(results.iter().any(|p| p.file_name().unwrap() == "config.txt"));
    assert!(results.iter().any(|p| p.file_name().unwrap() == "important.log"));
    assert!(!results.iter().any(|p| p.file_name().unwrap() == "debug.log"));

    Ok(())
}

#[test]
fn test_scanner_ignore_directories() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let root = temp_dir.path();

    fs::create_dir(root.join("build"))?;
    fs::create_dir(root.join("src"))?;

    fs::write(root.join("build/output.txt"), "api_key=⊕{secret}")?;
    fs::write(root.join("src/main.rs"), "password=⊕{secret}")?;

    let mut config = ProjectConfig::default();
    config.ignore = Some("build/".to_string());
    let (ignore_set, negation_set) = config.parse_ignore_patterns()?;

    let mut scanner = FileScanner::new();
    scanner.set_ignore_patterns(ignore_set, negation_set);

    let results = scanner.scan_directory(root)?;

    assert_eq!(results.len(), 1);
    assert!(results[0].file_name().unwrap() == "main.rs");

    Ok(())
}

#[test]
fn test_scanner_complex_patterns() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let root = temp_dir.path();

    fs::write(root.join("temp123.txt"), "api_key=⊕{secret}")?;
    fs::write(root.join("data.db"), "password=⊕{secret}")?;
    fs::write(root.join("session.db"), "token=⊕{secret}")?;
    fs::write(root.join("config.yaml"), "key=⊕{secret}")?;

    let mut config = ProjectConfig::default();
    config.ignore = Some("temp*.txt *.db !session.db".to_string());
    let (ignore_set, negation_set) = config.parse_ignore_patterns()?;

    let mut scanner = FileScanner::new();
    scanner.set_ignore_patterns(ignore_set, negation_set);

    let results = scanner.scan_directory(root)?;

    assert_eq!(results.len(), 2);
    assert!(results.iter().any(|p| p.file_name().unwrap() == "session.db"));
    assert!(results.iter().any(|p| p.file_name().unwrap() == "config.yaml"));
    assert!(!results.iter().any(|p| p.file_name().unwrap() == "temp123.txt"));
    assert!(!results.iter().any(|p| p.file_name().unwrap() == "data.db"));

    Ok(())
}

#[test]
fn test_scanner_no_ignore_patterns() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let root = temp_dir.path();

    fs::write(root.join("file1.txt"), "api_key=⊕{secret}")?;
    fs::write(root.join("file2.log"), "password=⊕{secret}")?;

    // Scanner without ignore patterns should find all files with patterns
    let scanner = FileScanner::new();
    let results = scanner.scan_directory(root)?;

    assert_eq!(results.len(), 2);

    Ok(())
}

#[test]
fn test_scanner_ignore_all_with_one_exception() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let root = temp_dir.path();

    fs::write(root.join("file1.txt"), "api_key=⊕{secret}")?;
    fs::write(root.join("file2.txt"), "password=⊕{secret}")?;
    fs::write(root.join("important.txt"), "token=⊕{secret}")?;

    let mut config = ProjectConfig::default();
    config.ignore = Some("*.txt !important.txt".to_string());
    let (ignore_set, negation_set) = config.parse_ignore_patterns()?;

    let mut scanner = FileScanner::new();
    scanner.set_ignore_patterns(ignore_set, negation_set);

    let results = scanner.scan_directory(root)?;

    assert_eq!(results.len(), 1);
    assert!(results[0].file_name().unwrap() == "important.txt");

    Ok(())
}

#[test]
fn test_scanner_nested_directories_with_ignore() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let root = temp_dir.path();

    fs::create_dir_all(root.join("build/debug"))?;
    fs::create_dir_all(root.join("src/utils"))?;

    fs::write(root.join("build/output.txt"), "api_key=⊕{secret}")?;
    fs::write(root.join("build/debug/trace.log"), "password=⊕{secret}")?;
    fs::write(root.join("src/main.rs"), "token=⊕{secret}")?;
    fs::write(root.join("src/utils/helper.rs"), "key=⊕{secret}")?;

    let mut config = ProjectConfig::default();
    config.ignore = Some("build/".to_string());
    let (ignore_set, negation_set) = config.parse_ignore_patterns()?;

    let mut scanner = FileScanner::new();
    scanner.set_ignore_patterns(ignore_set, negation_set);

    let results = scanner.scan_directory(root)?;

    assert_eq!(results.len(), 2);
    assert!(results.iter().any(|p| p.file_name().unwrap() == "main.rs"));
    assert!(results.iter().any(|p| p.file_name().unwrap() == "helper.rs"));
    assert!(!results.iter().any(|p| p.to_string_lossy().contains("build")));

    Ok(())
}

#[test]
fn test_real_world_example() -> Result<()> {
    // Simulate a real project structure
    let temp_dir = TempDir::new()?;
    let root = temp_dir.path();

    fs::create_dir_all(root.join("src"))?;
    fs::create_dir_all(root.join("build"))?;
    fs::create_dir_all(root.join("tests"))?;

    fs::write(root.join("src/config.yaml"), "db_password=⊕{secret}")?;
    fs::write(root.join("tests/test.log"), "api_key=⊕{secret}")?;
    fs::write(root.join("build/artifact.txt"), "token=⊕{secret}")?;
    fs::write(root.join("Justfile"), "password=⊕{secret}")?;
    fs::write(root.join("README.md"), "# Documentation\napi_key=⊕{secret}")?;

    // Typical .sss.toml ignore patterns
    let mut config = ProjectConfig::default();
    config.ignore = Some("Justfile *.log build/ !README.md".to_string());
    let (ignore_set, negation_set) = config.parse_ignore_patterns()?;

    let mut scanner = FileScanner::new();
    scanner.set_ignore_patterns(ignore_set, negation_set);

    let results = scanner.scan_directory(root)?;

    // Should find: src/config.yaml and README.md
    // Should ignore: Justfile, tests/test.log, build/artifact.txt
    assert_eq!(results.len(), 2);
    assert!(results.iter().any(|p| p.file_name().unwrap() == "config.yaml"));
    assert!(results.iter().any(|p| p.file_name().unwrap() == "README.md"));
    assert!(!results.iter().any(|p| p.file_name().unwrap() == "Justfile"));
    assert!(!results.iter().any(|p| p.file_name().unwrap() == "test.log"));
    assert!(!results.iter().any(|p| p.to_string_lossy().contains("build")));

    Ok(())
}
// === Additional edge case tests for comprehensive coverage ===

#[test]
fn test_parse_ignore_patterns_only_negations() -> Result<()> {
    let mut config = ProjectConfig::default();
    config.ignore = Some("!important.log !session.db".to_string());

    let (positive, negative) = config.parse_ignore_patterns()?;

    // Only negations - positive should be empty, negative should have patterns
    assert!(positive.is_empty());
    assert!(!negative.is_empty());

    Ok(())
}

#[test]
fn test_parse_ignore_patterns_whitespace_handling() -> Result<()> {
    let mut config = ProjectConfig::default();
    config.ignore = Some("  *.log   build/    !important.log  ".to_string());

    let (positive, negative) = config.parse_ignore_patterns()?;

    // Should handle extra whitespace correctly
    assert!(!positive.is_empty());
    assert!(!negative.is_empty());
    assert!(positive.is_match(Path::new("debug.log")));
    assert!(negative.is_match(Path::new("important.log")));

    Ok(())
}

#[test]
fn test_parse_ignore_patterns_empty_after_negation() -> Result<()> {
    let mut config = ProjectConfig::default();
    config.ignore = Some("!".to_string());

    let (positive, negative) = config.parse_ignore_patterns()?;

    // Just "!" should be ignored (empty after stripping)
    assert!(positive.is_empty());
    assert!(negative.is_empty());

    Ok(())
}

#[test]
fn test_get_set_ignore_pattern_strings() -> Result<()> {
    let mut config = ProjectConfig::default();

    // Test set_ignore_patterns
    config.set_ignore_patterns(vec!["*.log".to_string(), "build/".to_string()]);
    assert_eq!(config.ignore, Some("*.log build/".to_string()));

    // Test get_ignore_pattern_strings
    let patterns = config.get_ignore_pattern_strings();
    assert_eq!(patterns, vec!["*.log", "build/"]);

    // Test set with empty vector
    config.set_ignore_patterns(vec![]);
    assert_eq!(config.ignore, None);

    Ok(())
}

#[test]
fn test_clear_ignore_patterns() -> Result<()> {
    let mut config = ProjectConfig::default();
    config.ignore = Some("*.log build/".to_string());

    config.clear_ignore_patterns();
    assert_eq!(config.ignore, None);

    let patterns = config.get_ignore_pattern_strings();
    assert!(patterns.is_empty());

    Ok(())
}

#[test]
fn test_should_ignore_with_complex_negations() -> Result<()> {
    let mut config = ProjectConfig::default();
    config.ignore = Some("*.* !*.rs !*.toml".to_string());

    // Should ignore most files but not .rs and .toml
    assert!(config.should_ignore(Path::new("test.log"))?);
    assert!(config.should_ignore(Path::new("data.txt"))?);
    assert!(!config.should_ignore(Path::new("main.rs"))?);
    assert!(!config.should_ignore(Path::new("Cargo.toml"))?);

    Ok(())
}

#[test]
fn test_should_ignore_directory_paths() -> Result<()> {
    let mut config = ProjectConfig::default();
    config.ignore = Some("build/ target/".to_string());

    assert!(config.should_ignore(Path::new("build/output.txt"))?);
    assert!(config.should_ignore(Path::new("target/debug/app"))?);
    assert!(config.should_ignore(Path::new("build/nested/deep/file.txt"))?);
    assert!(!config.should_ignore(Path::new("src/build.rs"))?);

    Ok(())
}

#[test]
fn test_parse_patterns_with_special_glob_chars() -> Result<()> {
    let mut config = ProjectConfig::default();
    config.ignore = Some("test[12].log temp?.txt **/*.cache".to_string());

    let (positive, _) = config.parse_ignore_patterns()?;

    assert!(positive.is_match(Path::new("test1.log")));
    assert!(positive.is_match(Path::new("test2.log")));
    assert!(positive.is_match(Path::new("tempX.txt")));
    assert!(positive.is_match(Path::new("deep/nested/file.cache")));

    Ok(())
}

#[test]
fn test_scanner_pattern_priority() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let root = temp_dir.path();

    fs::write(root.join("important.log"), "password=⊕{secret}")?;
    fs::write(root.join("debug.log"), "password=⊕{secret}")?;

    // Pattern: ignore all .log but make exception for important.log
    let mut config = ProjectConfig::default();
    config.ignore = Some("*.log !important.log".to_string());
    let (ignore_set, negation_set) = config.parse_ignore_patterns()?;

    let mut scanner = FileScanner::new();
    scanner.set_ignore_patterns(ignore_set, negation_set);

    let results = scanner.scan_directory(root)?;

    // Should only find important.log (negation overrides ignore)
    assert_eq!(results.len(), 1);
    assert!(results[0].file_name().unwrap() == "important.log");

    Ok(())
}

#[test]
fn test_ignore_patterns_case_sensitivity() -> Result<()> {
    let mut config = ProjectConfig::default();
    config.ignore = Some("*.LOG".to_string());

    // Glob patterns are case-sensitive by default
    assert!(config.should_ignore(Path::new("DEBUG.LOG"))?);
    assert!(!config.should_ignore(Path::new("debug.log"))?); // Different case

    Ok(())
}

#[test]
fn test_multiple_directory_levels() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let root = temp_dir.path();

    fs::create_dir_all(root.join("a/b/c"))?;
    fs::write(root.join("a/file.txt"), "password=⊕{secret}")?;
    fs::write(root.join("a/b/file.txt"), "password=⊕{secret}")?;
    fs::write(root.join("a/b/c/file.txt"), "password=⊕{secret}")?;

    let mut config = ProjectConfig::default();
    config.ignore = Some("a/b/".to_string());
    let (ignore_set, negation_set) = config.parse_ignore_patterns()?;

    let mut scanner = FileScanner::new();
    scanner.set_ignore_patterns(ignore_set, negation_set);

    let results = scanner.scan_directory(root)?;

    // Should only find a/file.txt, not anything in a/b/
    assert_eq!(results.len(), 1);
    assert!(results[0].to_string_lossy().contains("a/file.txt"));

    Ok(())
}
