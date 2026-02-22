//! Integration tests for ignore patterns with process commands
//!
//! Tests how ignore patterns interact with:
//! - File scanning (sss process scan)
//! - Opening/rendering files
//! - Real workflow scenarios

use anyhow::Result;
use sss::project::ProjectConfig;
use sss::scanner::FileScanner;
use std::fs;
use tempfile::TempDir;

#[test]
fn test_scan_respects_ignore_patterns() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let root = temp_dir.path();

    // Create test files
    fs::write(root.join("config.txt"), "password=⊕{secret1}")?;
    fs::write(root.join("debug.log"), "password=⊕{secret2}")?;
    fs::write(root.join("important.log"), "password=⊕{secret3}")?;

    // Create .sss.toml with ignore patterns
    let config = ProjectConfig {
        ignore: Some("*.log !important.log".to_string()),
        ..Default::default()
    };
    config.save_to_file(root.join(".sss.toml"))?;

    // Scan with patterns
    let (ignore_set, negation_set) = config.parse_ignore_patterns()?;
    let mut scanner = FileScanner::new();
    scanner.set_ignore_patterns(ignore_set, negation_set);

    let results = scanner.scan_directory(root)?;

    // Should find config.txt and important.log, but not debug.log
    assert_eq!(results.len(), 2);
    assert!(results.iter().any(|p| p.file_name().unwrap() == "config.txt"));
    assert!(results.iter().any(|p| p.file_name().unwrap() == "important.log"));
    assert!(!results.iter().any(|p| p.file_name().unwrap() == "debug.log"));

    Ok(())
}

#[test]
fn test_scan_with_no_patterns() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let root = temp_dir.path();

    fs::write(root.join("file1.txt"), "password=⊕{secret1}")?;
    fs::write(root.join("file2.log"), "password=⊕{secret2}")?;

    // No .sss.toml or no ignore patterns
    let scanner = FileScanner::new();
    let results = scanner.scan_directory(root)?;

    // Should find all files
    assert_eq!(results.len(), 2);

    Ok(())
}

#[test]
fn test_scan_directory_exclusion() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let root = temp_dir.path();

    fs::create_dir(root.join("build"))?;
    fs::create_dir(root.join("src"))?;

    fs::write(root.join("build/output.txt"), "password=⊕{secret1}")?;
    fs::write(root.join("src/main.rs"), "password=⊕{secret2}")?;

    // Ignore build directory
    let config = ProjectConfig {
        ignore: Some("build/".to_string()),
        ..Default::default()
    };
    let (ignore_set, negation_set) = config.parse_ignore_patterns()?;

    let mut scanner = FileScanner::new();
    scanner.set_ignore_patterns(ignore_set, negation_set);

    let results = scanner.scan_directory(root)?;

    assert_eq!(results.len(), 1);
    assert!(results[0].to_string_lossy().contains("main.rs"));

    Ok(())
}

#[test]
fn test_scan_nested_directories() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let root = temp_dir.path();

    fs::create_dir_all(root.join("a/b/c"))?;
    fs::write(root.join("a/file.txt"), "password=⊕{secret}")?;
    fs::write(root.join("a/b/file.txt"), "password=⊕{secret}")?;
    fs::write(root.join("a/b/c/file.txt"), "password=⊕{secret}")?;

    // Ignore a/b/ and everything under it
    let config = ProjectConfig {
        ignore: Some("a/b/".to_string()),
        ..Default::default()
    };
    let (ignore_set, negation_set) = config.parse_ignore_patterns()?;

    let mut scanner = FileScanner::new();
    scanner.set_ignore_patterns(ignore_set, negation_set);

    let results = scanner.scan_directory(root)?;

    // Only a/file.txt should be found
    assert_eq!(results.len(), 1);
    assert!(results[0].to_string_lossy().contains("a/file.txt"));
    assert!(!results[0].to_string_lossy().contains("a/b"));

    Ok(())
}

#[test]
fn test_scan_with_stats_respects_patterns() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let root = temp_dir.path();

    fs::write(root.join("included.txt"), "password=⊕{secret}")?;
    fs::write(root.join("ignored.log"), "password=⊕{secret}")?;
    fs::write(root.join("normal.txt"), "no patterns here")?;

    let config = ProjectConfig {
        ignore: Some("*.log".to_string()),
        ..Default::default()
    };
    let (ignore_set, negation_set) = config.parse_ignore_patterns()?;

    let mut scanner = FileScanner::new();
    scanner.set_ignore_patterns(ignore_set, negation_set);

    let result = scanner.scan_with_stats(root)?;

    // Should only find included.txt (ignored.log is ignored, normal.txt has no patterns)
    assert_eq!(result.files_with_patterns.len(), 1);
    assert!(result.files_with_patterns[0].file_name().unwrap() == "included.txt");

    Ok(())
}

#[test]
fn test_large_directory_scan_with_patterns() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let root = temp_dir.path();

    // Create 100 files
    for i in 0..50 {
        fs::write(root.join(format!("file{}.txt", i)), "password=⊕{secret}")?;
    }
    for i in 0..50 {
        fs::write(root.join(format!("file{}.log", i)), "password=⊕{secret}")?;
    }

    // Ignore all .log files
    let config = ProjectConfig {
        ignore: Some("*.log".to_string()),
        ..Default::default()
    };
    let (ignore_set, negation_set) = config.parse_ignore_patterns()?;

    let mut scanner = FileScanner::new();
    scanner.set_ignore_patterns(ignore_set, negation_set);

    let results = scanner.scan_directory(root)?;

    // Should only find the 50 .txt files
    assert_eq!(results.len(), 50);
    assert!(results.iter().all(|p| p.extension().unwrap() == "txt"));

    Ok(())
}

#[test]
fn test_pattern_matching_performance() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let root = temp_dir.path();

    // Create files
    for i in 0..10 {
        fs::write(root.join(format!("file{}.txt", i)), "password=⊕{secret}")?;
    }

    // Create config with many patterns
    let mut patterns = Vec::new();
    for i in 0..100 {
        patterns.push(format!("*.ext{}", i));
    }
    patterns.push("*.log".to_string());

    let config = ProjectConfig {
        ignore: Some(patterns.join(" ")),
        ..Default::default()
    };
    let (ignore_set, negation_set) = config.parse_ignore_patterns()?;

    let mut scanner = FileScanner::new();
    scanner.set_ignore_patterns(ignore_set, negation_set);

    // Should complete quickly even with many patterns
    let start = std::time::Instant::now();
    let results = scanner.scan_directory(root)?;
    let duration = start.elapsed();

    // All .txt files should be found (not matching any ignore pattern)
    assert_eq!(results.len(), 10);

    // Should be fast (< 100ms)
    assert!(duration.as_millis() < 100);

    Ok(())
}

#[test]
fn test_mixed_sss_patterns_and_normal_files() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let root = temp_dir.path();

    fs::write(root.join("secret.txt"), "password=⊕{secret}")?;
    fs::write(root.join("normal.txt"), "no secret here")?;
    fs::write(root.join("secret.log"), "password=⊕{secret}")?;

    let config = ProjectConfig {
        ignore: Some("*.log".to_string()),
        ..Default::default()
    };
    let (ignore_set, negation_set) = config.parse_ignore_patterns()?;

    let mut scanner = FileScanner::new();
    scanner.set_ignore_patterns(ignore_set, negation_set);

    let results = scanner.scan_directory(root)?;

    // Should only find secret.txt (normal.txt has no SSS pattern, secret.log is ignored)
    assert_eq!(results.len(), 1);
    assert!(results[0].file_name().unwrap() == "secret.txt");

    Ok(())
}

#[test]
fn test_negation_with_directory_patterns() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let root = temp_dir.path();

    fs::create_dir(root.join("logs"))?;
    fs::write(root.join("logs/debug.log"), "password=⊕{secret}")?;
    fs::write(root.join("logs/important.log"), "password=⊕{secret}")?;
    fs::write(root.join("logs/error.log"), "password=⊕{secret}")?;

    // Ignore logs directory but keep important.log
    let config = ProjectConfig {
        ignore: Some("logs/ !logs/important.log".to_string()),
        ..Default::default()
    };
    let (ignore_set, negation_set) = config.parse_ignore_patterns()?;

    let mut scanner = FileScanner::new();
    scanner.set_ignore_patterns(ignore_set, negation_set);

    let results = scanner.scan_directory(root)?;

    // Should only find important.log
    assert_eq!(results.len(), 1);
    assert!(results[0].file_name().unwrap() == "important.log");

    Ok(())
}

#[test]
fn test_complex_real_world_scenario() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let root = temp_dir.path();

    // Typical project structure
    fs::create_dir_all(root.join("src"))?;
    fs::create_dir_all(root.join("tests"))?;
    fs::create_dir_all(root.join("build"))?;
    fs::create_dir_all(root.join("logs"))?;

    fs::write(root.join("src/config.yaml"), "db_password=⊕{secret}")?;
    fs::write(root.join("tests/test.log"), "test_password=⊕{secret}")?;
    fs::write(root.join("build/output.txt"), "build_secret=⊕{secret}")?;
    fs::write(root.join("logs/app.log"), "log_password=⊕{secret}")?;
    fs::write(root.join(".env"), "SECRET_KEY=⊕{secret}")?;

    // Typical ignore patterns
    let config = ProjectConfig {
        ignore: Some("build/ *.log !.env".to_string()),
        ..Default::default()
    };
    let (ignore_set, negation_set) = config.parse_ignore_patterns()?;

    let mut scanner = FileScanner::new();
    scanner.set_ignore_patterns(ignore_set, negation_set);

    let results = scanner.scan_directory(root)?;

    // Should find: src/config.yaml and .env
    // Should ignore: build/, *.log files
    assert_eq!(results.len(), 2);
    assert!(results.iter().any(|p| p.file_name().unwrap() == "config.yaml"));
    assert!(results.iter().any(|p| p.file_name().unwrap() == ".env"));

    Ok(())
}

#[test]
fn test_pattern_compilation_error_handling() -> Result<()> {
    let config = ProjectConfig {
        ignore: Some("[invalid".to_string()),
        ..Default::default()
    };
    let result = config.parse_ignore_patterns();
    assert!(result.is_err());

    Ok(())
}

#[test]
fn test_empty_directory_scan() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let root = temp_dir.path();

    let config = ProjectConfig {
        ignore: Some("*.log".to_string()),
        ..Default::default()
    };
    let (ignore_set, negation_set) = config.parse_ignore_patterns()?;

    let mut scanner = FileScanner::new();
    scanner.set_ignore_patterns(ignore_set, negation_set);

    let results = scanner.scan_directory(root)?;

    // Empty directory should return empty results
    assert_eq!(results.len(), 0);

    Ok(())
}

#[test]
fn test_deeply_nested_structures() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let root = temp_dir.path();

    // Create structure with directories at root level
    for i in 0..10 {
        let dir_path = root.join(format!("level{}", i));
        fs::create_dir_all(&dir_path)?;
        fs::write(dir_path.join("secret.txt"), "password=⊕{secret}")?;

        // Also create nested files
        let nested = dir_path.join("nested");
        fs::create_dir_all(&nested)?;
        fs::write(nested.join("data.txt"), "password=⊕{nested}")?;
    }

    let config = ProjectConfig {
        ignore: Some("level5/".to_string()),
        ..Default::default()
    };
    let (ignore_set, negation_set) = config.parse_ignore_patterns()?;

    let mut scanner = FileScanner::new();
    scanner.set_ignore_patterns(ignore_set, negation_set);

    let results = scanner.scan_directory(root)?;

    // Should find files in level0-4 and level6-9 (18 files total), but not level5 (2 files)
    // 9 directories * 2 files each = 18 files
    assert_eq!(results.len(), 18);
    assert!(!results.iter().any(|p| p.to_string_lossy().contains("level5")));

    Ok(())
}
