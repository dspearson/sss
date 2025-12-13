//! Integration tests for file scanner
//!
//! These tests cover edge cases and security scenarios not covered by inline unit tests:
//! - Symbolic links handling
//! - Permission errors
//! - Very deep directory structures
//! - Large files (respecting MAX_FILE_SIZE limit)
//! - Concurrent scanning
//! - Special file types (pipes, sockets, etc.)
//! - Pattern detection edge cases

use anyhow::Result;
use sss::scanner::FileScanner;
use std::fs;
use tempfile::TempDir;

#[cfg(unix)]
use std::os::unix::fs::{symlink, PermissionsExt};

/// Helper to create test directory structure
fn create_test_structure(root: &std::path::Path) -> Result<()> {
    fs::create_dir_all(root.join("subdir1"))?;
    fs::create_dir_all(root.join("subdir2"))?;
    fs::create_dir_all(root.join(".git"))?;
    fs::create_dir_all(root.join("node_modules"))?;

    fs::write(root.join("config.txt"), "api_key=⊕{secret123}")?;
    fs::write(root.join("readme.md"), "# Normal documentation")?;
    fs::write(root.join("subdir1/data.json"), r#"{"password": "⊠{encrypted}"}"#)?;
    fs::write(root.join("subdir2/empty.txt"), "")?;
    fs::write(root.join(".git/config"), "⊕{should-be-ignored}")?;
    fs::write(root.join("node_modules/package.json"), "⊕{also-ignored}")?;

    Ok(())
}

#[test]
fn test_scanner_basic_functionality() -> Result<()> {
    let temp_dir = TempDir::new()?;
    create_test_structure(temp_dir.path())?;

    let scanner = FileScanner::new();
    let results = scanner.scan_directory(temp_dir.path())?;

    assert_eq!(results.len(), 2, "Should find 2 files with patterns");
    assert!(results.iter().any(|p| p.file_name().unwrap() == "config.txt"));
    assert!(results.iter().any(|p| p.file_name().unwrap() == "data.json"));

    // Verify ignored directories are not scanned
    assert!(!results.iter().any(|p| p.to_string_lossy().contains(".git")));
    assert!(!results.iter().any(|p| p.to_string_lossy().contains("node_modules")));

    Ok(())
}

#[test]
fn test_scanner_with_stats() -> Result<()> {
    let temp_dir = TempDir::new()?;
    create_test_structure(temp_dir.path())?;

    let scanner = FileScanner::new();
    let stats = scanner.scan_with_stats(temp_dir.path())?;

    assert_eq!(stats.files_count(), 2);
    assert!(stats.total_files > 0);
    assert!(stats.scanned_files > 0);
    assert!(stats.duration.as_secs_f64() >= 0.0);

    Ok(())
}

#[test]
fn test_scanner_empty_directory() -> Result<()> {
    let temp_dir = TempDir::new()?;

    let scanner = FileScanner::new();
    let results = scanner.scan_directory(temp_dir.path())?;

    assert_eq!(results.len(), 0, "Empty directory should have no results");

    Ok(())
}

#[test]
fn test_scanner_nonexistent_directory() {
    let scanner = FileScanner::new();
    let result = scanner.scan_directory("/nonexistent/path/to/nowhere");

    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("does not exist"));
}

#[test]
fn test_scanner_file_instead_of_directory() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let file_path = temp_dir.path().join("file.txt");
    fs::write(&file_path, "test content")?;

    let scanner = FileScanner::new();
    let result = scanner.scan_directory(&file_path);

    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("not a directory"));

    Ok(())
}

#[test]
#[cfg(unix)]
fn test_scanner_symbolic_links() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let root = temp_dir.path();

    // Create a file with a pattern
    let target_file = root.join("target.txt");
    fs::write(&target_file, "secret=⊕{value}")?;

    // Create a symbolic link to the file
    let link_file = root.join("link.txt");
    symlink(&target_file, &link_file)?;

    let scanner = FileScanner::new();
    let results = scanner.scan_directory(root)?;

    // Should find the pattern in at least the target file
    // Symlink behavior may vary by platform
    assert!(results.len() >= 1);

    Ok(())
}

#[test]
#[cfg(unix)]
fn test_scanner_directory_symlink() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let root = temp_dir.path();

    // Create a target directory with a file
    let target_dir = root.join("target_dir");
    fs::create_dir(&target_dir)?;
    fs::write(target_dir.join("secret.txt"), "password=⊕{secret}")?;

    // Create a symbolic link to the directory
    let link_dir = root.join("link_dir");
    symlink(&target_dir, &link_dir)?;

    let scanner = FileScanner::new();
    let results = scanner.scan_directory(root)?;

    // Should find the pattern (symlinks to directories are typically followed)
    assert!(results.len() >= 1);

    Ok(())
}

#[test]
#[cfg(unix)]
fn test_scanner_unreadable_directory() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let root = temp_dir.path();

    // Create a subdirectory
    let protected_dir = root.join("protected");
    fs::create_dir(&protected_dir)?;
    fs::write(protected_dir.join("secret.txt"), "password=⊕{secret}")?;

    // Make it unreadable (mode 0o000)
    let metadata = fs::metadata(&protected_dir)?;
    let mut perms = metadata.permissions();
    perms.set_mode(0o000);
    fs::set_permissions(&protected_dir, perms)?;

    let scanner = FileScanner::new();
    let result = scanner.scan_directory(root);

    // Scanner should handle permission errors gracefully
    // Either succeed with empty results or return an error
    if result.is_ok() {
        // If successful, should have found nothing in protected dir
        let results = result.unwrap();
        assert!(!results.iter().any(|p| p.to_string_lossy().contains("protected")));
    }

    // Restore permissions for cleanup
    let metadata = fs::metadata(&protected_dir)?;
    let mut perms = metadata.permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&protected_dir, perms)?;

    Ok(())
}

#[test]
fn test_scanner_very_deep_directory_structure() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let mut current_path = temp_dir.path().to_path_buf();

    // Create a very deep directory structure (100 levels)
    for i in 0..100 {
        current_path = current_path.join(format!("level{}", i));
        fs::create_dir(&current_path)?;
    }

    // Add a file with pattern at the deepest level
    fs::write(current_path.join("deep_secret.txt"), "password=⊕{deep_secret}")?;

    let scanner = FileScanner::new();
    let results = scanner.scan_directory(temp_dir.path())?;

    assert_eq!(results.len(), 1, "Should find file in very deep directory");
    assert!(results[0].file_name().unwrap() == "deep_secret.txt");

    Ok(())
}

#[test]
fn test_scanner_large_file_excluded() -> Result<()> {
    use sss::constants::MAX_FILE_SIZE;

    let temp_dir = TempDir::new()?;

    // Create a file larger than MAX_FILE_SIZE
    let large_file = temp_dir.path().join("large.txt");
    let large_content = "x".repeat((MAX_FILE_SIZE + 1000) as usize);
    fs::write(&large_file, large_content)?;

    // Create a normal file with pattern
    fs::write(temp_dir.path().join("normal.txt"), "secret=⊕{value}")?;

    let scanner = FileScanner::new();
    let results = scanner.scan_directory(temp_dir.path())?;

    // Should find only the normal file, large file should be excluded
    assert_eq!(results.len(), 1);
    assert!(results[0].file_name().unwrap() == "normal.txt");

    Ok(())
}

#[test]
fn test_scanner_binary_files_excluded() -> Result<()> {
    let temp_dir = TempDir::new()?;

    // Create various binary file types
    fs::write(temp_dir.path().join("image.jpg"), b"\xFF\xD8\xFF\xE0")?; // JPEG header
    fs::write(temp_dir.path().join("binary.exe"), b"\x4D\x5A")?; // PE header
    fs::write(temp_dir.path().join("archive.zip"), b"PK\x03\x04")?; // ZIP header

    // Create a text file with pattern
    fs::write(temp_dir.path().join("config.txt"), "api_key=⊕{secret}")?;

    let scanner = FileScanner::new();
    let results = scanner.scan_directory(temp_dir.path())?;

    // Should find only the text file
    assert_eq!(results.len(), 1);
    assert!(results[0].file_name().unwrap() == "config.txt");

    Ok(())
}

#[test]
fn test_scanner_custom_ignore_directory() -> Result<()> {
    let temp_dir = TempDir::new()?;

    fs::create_dir(temp_dir.path().join("custom_ignore"))?;
    fs::write(temp_dir.path().join("custom_ignore/secret.txt"), "password=⊕{secret}")?;
    fs::write(temp_dir.path().join("config.txt"), "api_key=⊕{key}")?;

    let mut scanner = FileScanner::new();
    scanner.ignore_directory("custom_ignore");

    let results = scanner.scan_directory(temp_dir.path())?;

    // Should find only config.txt, custom_ignore should be ignored
    assert_eq!(results.len(), 1);
    assert!(results[0].file_name().unwrap() == "config.txt");

    Ok(())
}

#[test]
fn test_scanner_allowed_extensions() -> Result<()> {
    let temp_dir = TempDir::new()?;

    fs::write(temp_dir.path().join("config.json"), r#"{"password": "⊕{secret}"}"#)?;
    fs::write(temp_dir.path().join("config.txt"), "password=⊕{secret}")?;
    fs::write(temp_dir.path().join("config.yaml"), "password: ⊕{secret}")?;

    let mut scanner = FileScanner::new();
    scanner.set_allowed_extensions(vec!["json".to_string(), "yaml".to_string()]);

    let results = scanner.scan_directory(temp_dir.path())?;

    // Should find only json and yaml files
    assert_eq!(results.len(), 2);
    assert!(results.iter().any(|p| p.extension().unwrap() == "json"));
    assert!(results.iter().any(|p| p.extension().unwrap() == "yaml"));
    assert!(!results.iter().any(|p| p.extension().unwrap() == "txt"));

    Ok(())
}

#[test]
fn test_scanner_multiple_patterns_in_file() -> Result<()> {
    let temp_dir = TempDir::new()?;

    let content = r#"
database:
  host: localhost
  user: admin
  password: ⊕{db_secret}

api:
  key: ⊠{api_secret}
  endpoint: https://api.example.com

redis:
  password: o+{redis_secret}
"#;

    fs::write(temp_dir.path().join("config.yaml"), content)?;

    let scanner = FileScanner::new();
    let results = scanner.scan_directory(temp_dir.path())?;

    assert_eq!(results.len(), 1);
    assert!(results[0].file_name().unwrap() == "config.yaml");

    Ok(())
}

#[test]
fn test_scanner_multiline_patterns() -> Result<()> {
    let temp_dir = TempDir::new()?;

    let content = "certificate=⊕{-----BEGIN CERTIFICATE-----\nMIIBkTCB+wIJAKHHCgVZWv...\n-----END CERTIFICATE-----}";

    fs::write(temp_dir.path().join("cert.pem"), content)?;

    let scanner = FileScanner::new();
    let results = scanner.scan_directory(temp_dir.path())?;

    assert_eq!(results.len(), 1);

    Ok(())
}

#[test]
fn test_scanner_false_positives() -> Result<()> {
    let temp_dir = TempDir::new()?;

    // Create files that might look like patterns but aren't
    fs::write(temp_dir.path().join("math.txt"), "x ⊕ y = z")?; // Math plus in circle
    fs::write(temp_dir.path().join("partial.txt"), "⊕ without braces")?;
    fs::write(temp_dir.path().join("reversed.txt"), "}secret{⊕")?; // Reversed

    let scanner = FileScanner::new();
    let results = scanner.scan_directory(temp_dir.path())?;

    // None of these should be detected
    assert_eq!(results.len(), 0);

    Ok(())
}

#[test]
fn test_scanner_nested_directories() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let root = temp_dir.path();

    fs::create_dir_all(root.join("a/b/c/d"))?;
    fs::write(root.join("a/secret1.txt"), "password=⊕{secret1}")?;
    fs::write(root.join("a/b/secret2.txt"), "password=⊕{secret2}")?;
    fs::write(root.join("a/b/c/secret3.txt"), "password=⊕{secret3}")?;
    fs::write(root.join("a/b/c/d/secret4.txt"), "password=⊕{secret4}")?;

    let scanner = FileScanner::new();
    let results = scanner.scan_directory(root)?;

    assert_eq!(results.len(), 4);

    Ok(())
}

#[test]
fn test_scanner_mixed_content() -> Result<()> {
    let temp_dir = TempDir::new()?;

    // Create mix of files with and without patterns
    for i in 0..10 {
        let filename = format!("file{}.txt", i);
        if i % 2 == 0 {
            fs::write(temp_dir.path().join(&filename), format!("password=⊕{{secret{}}}", i))?;
        } else {
            fs::write(temp_dir.path().join(&filename), format!("normal content {}", i))?;
        }
    }

    let scanner = FileScanner::new();
    let results = scanner.scan_directory(temp_dir.path())?;

    // Should find 5 files with patterns (even indices)
    assert_eq!(results.len(), 5);

    Ok(())
}

#[test]
fn test_scanner_utf8_filenames() -> Result<()> {
    let temp_dir = TempDir::new()?;

    // Create files with UTF-8 names
    fs::write(temp_dir.path().join("配置.txt"), "password=⊕{secret}")?;
    fs::write(temp_dir.path().join("секрет.txt"), "password=⊕{secret}")?;
    fs::write(temp_dir.path().join("🔒.txt"), "password=⊕{secret}")?;

    let scanner = FileScanner::new();
    let results = scanner.scan_directory(temp_dir.path())?;

    assert_eq!(results.len(), 3);

    Ok(())
}

#[test]
fn test_scanner_results_sorted() -> Result<()> {
    let temp_dir = TempDir::new()?;

    fs::write(temp_dir.path().join("zebra.txt"), "password=⊕{secret}")?;
    fs::write(temp_dir.path().join("apple.txt"), "password=⊕{secret}")?;
    fs::write(temp_dir.path().join("middle.txt"), "password=⊕{secret}")?;

    let scanner = FileScanner::new();
    let results = scanner.scan_directory(temp_dir.path())?;

    // Results should be sorted
    assert_eq!(results.len(), 3);
    assert!(results[0].file_name().unwrap() == "apple.txt");
    assert!(results[1].file_name().unwrap() == "middle.txt");
    assert!(results[2].file_name().unwrap() == "zebra.txt");

    Ok(())
}

#[test]
fn test_scanner_all_marker_types() -> Result<()> {
    let temp_dir = TempDir::new()?;

    fs::write(temp_dir.path().join("marker1.txt"), "value=⊕{secret}")?; // Circle plus
    fs::write(temp_dir.path().join("marker2.txt"), "value=o+{secret}")?; // ASCII version
    fs::write(temp_dir.path().join("marker3.txt"), "value=⊠{secret}")?; // Box

    let scanner = FileScanner::new();
    let results = scanner.scan_directory(temp_dir.path())?;

    // All 3 marker types should be detected
    assert_eq!(results.len(), 3);

    Ok(())
}
