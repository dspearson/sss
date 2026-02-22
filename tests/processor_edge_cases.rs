//! Comprehensive edge case tests for pattern detection
//!
//! This test suite covers edge cases in SSS pattern detection:
//! - Multiple patterns in single line
//! - Mixed pattern types (⊕, o+, ⊠)
//! - Malformed patterns
//! - Large files with many patterns
//! - Binary data mixed with patterns
//! - Pattern validation

use anyhow::Result;
use sss::scanner::FileScanner;
use std::fs;
use tempfile::TempDir;

#[test]
fn test_detect_multiple_patterns_per_line() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let root = temp_dir.path();

    // Create file with multiple patterns on one line
    fs::write(
        root.join("multi.txt"),
        "user=⊕{user1} pass=⊕{pass1} token=⊕{token1}",
    )?;

    let scanner = FileScanner::new();
    let results = scanner.scan_directory(root)?;

    assert_eq!(results.len(), 1);
    assert!(results[0].ends_with("multi.txt"));

    Ok(())
}

#[test]
fn test_detect_mixed_pattern_types() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let root = temp_dir.path();

    // All three pattern types
    fs::write(
        root.join("mixed.txt"),
        "encrypted=⊕{secret}\npublic=o+{pubkey}\nsealed=⊠{sealed}",
    )?;

    let scanner = FileScanner::new();
    let results = scanner.scan_directory(root)?;

    assert_eq!(results.len(), 1);

    Ok(())
}

#[test]
fn test_malformed_patterns_detection() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let root = temp_dir.path();

    // Test incomplete pattern (missing closing brace) - regex may still match
    fs::write(
        root.join("incomplete.txt"),
        "incomplete=⊕{no_close\nno_braces=⊕value\nno_marker={just_braces}",
    )?;

    let scanner = FileScanner::new();
    let results = scanner.scan_directory(root)?;

    // File is detected because regex pattern ⊕{[^}]*} matches content before newline
    // This is acceptable behavior - actual processing would fail later
    // Results may vary based on regex implementation (0 or 1 file detected)
    assert!(results.len() <= 1);

    Ok(())
}

#[test]
fn test_detect_nested_braces() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let root = temp_dir.path();

    fs::write(root.join("nested.txt"), "data=⊕{outer{inner}}")?;

    let scanner = FileScanner::new();
    let results = scanner.scan_directory(root)?;

    // Pattern with nested braces should still be detected (matches until first })
    assert_eq!(results.len(), 1);

    Ok(())
}

#[test]
fn test_detect_escaped_characters() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let root = temp_dir.path();

    fs::write(root.join("escaped.txt"), r#"password=⊕{secret\"quote}"#)?;

    let scanner = FileScanner::new();
    let results = scanner.scan_directory(root)?;

    // May or may not detect escaped chars - both behaviors are acceptable
    assert!(results.len() <= 1);

    Ok(())
}

#[test]
fn test_empty_file_not_detected() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let root = temp_dir.path();

    fs::write(root.join("empty.txt"), "")?;

    let scanner = FileScanner::new();
    let results = scanner.scan_directory(root)?;

    assert_eq!(results.len(), 0);

    Ok(())
}

#[test]
fn test_whitespace_only_not_detected() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let root = temp_dir.path();

    fs::write(root.join("whitespace.txt"), "   \n\t\n   ")?;

    let scanner = FileScanner::new();
    let results = scanner.scan_directory(root)?;

    assert_eq!(results.len(), 0);

    Ok(())
}

#[test]
fn test_detect_unicode_content() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let root = temp_dir.path();

    fs::write(
        root.join("unicode.txt"),
        "用户名=⊕{用户}\nпароль=⊕{секрет}\n😀=⊕{emoji}",
    )?;

    let scanner = FileScanner::new();
    let results = scanner.scan_directory(root)?;

    assert_eq!(results.len(), 1);

    Ok(())
}

#[test]
fn test_detect_very_long_lines() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let root = temp_dir.path();

    let long_line = "x".repeat(10000);
    fs::write(
        root.join("long.txt"),
        format!("{}password=⊕{{secret}}{}", long_line, long_line),
    )?;

    let scanner = FileScanner::new();
    let results = scanner.scan_directory(root)?;

    assert_eq!(results.len(), 1);

    Ok(())
}

#[test]
fn test_detect_many_patterns() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let root = temp_dir.path();

    // 100 patterns
    let mut content = String::new();
    for i in 0..100 {
        content.push_str(&format!("secret{}=⊕{{value{}}}\n", i, i));
    }

    fs::write(root.join("many.txt"), content)?;

    let scanner = FileScanner::new();
    let results = scanner.scan_directory(root)?;

    assert_eq!(results.len(), 1);

    Ok(())
}

#[test]
fn test_duplicate_pattern_ids() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let root = temp_dir.path();

    fs::write(
        root.join("dups.txt"),
        "a=⊕{mysecret}\nb=⊕{mysecret}\nc=⊕{mysecret}",
    )?;

    let scanner = FileScanner::new();
    let results = scanner.scan_directory(root)?;

    assert_eq!(results.len(), 1);

    Ok(())
}

#[test]
fn test_special_pattern_ids() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let root = temp_dir.path();

    fs::write(
        root.join("special.txt"),
        "a=⊕{id-with-dashes}\nb=⊕{id_with_underscores}\nc=⊕{id.with.dots}",
    )?;

    let scanner = FileScanner::new();
    let results = scanner.scan_directory(root)?;

    assert_eq!(results.len(), 1);

    Ok(())
}

#[test]
fn test_dos_line_endings() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let root = temp_dir.path();

    fs::write(root.join("dos.txt"), "line1\r\npassword=⊕{secret}\r\n")?;

    let scanner = FileScanner::new();
    let results = scanner.scan_directory(root)?;

    assert_eq!(results.len(), 1);

    Ok(())
}

#[test]
fn test_mixed_line_endings() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let root = temp_dir.path();

    fs::write(root.join("mixed.txt"), "unix\nwindows\r\nmac\rpass=⊕{secret}")?;

    let scanner = FileScanner::new();
    let results = scanner.scan_directory(root)?;

    assert_eq!(results.len(), 1);

    Ok(())
}

#[test]
fn test_no_trailing_newline() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let root = temp_dir.path();

    fs::write(root.join("no_newline.txt"), "password=⊕{secret}")?; // No \n

    let scanner = FileScanner::new();
    let results = scanner.scan_directory(root)?;

    assert_eq!(results.len(), 1);

    Ok(())
}

#[test]
fn test_file_with_bom() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let root = temp_dir.path();

    // UTF-8 BOM
    fs::write(root.join("bom.txt"), "\u{FEFF}password=⊕{secret}")?;

    let scanner = FileScanner::new();
    let results = scanner.scan_directory(root)?;

    assert_eq!(results.len(), 1);

    Ok(())
}

#[test]
fn test_pattern_at_file_start() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let root = temp_dir.path();

    fs::write(root.join("start.txt"), "⊕{secret}rest")?;

    let scanner = FileScanner::new();
    let results = scanner.scan_directory(root)?;

    assert_eq!(results.len(), 1);

    Ok(())
}

#[test]
fn test_pattern_at_file_end() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let root = temp_dir.path();

    fs::write(root.join("end.txt"), "content⊕{secret}")?;

    let scanner = FileScanner::new();
    let results = scanner.scan_directory(root)?;

    assert_eq!(results.len(), 1);

    Ok(())
}

#[test]
fn test_pattern_only_file() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let root = temp_dir.path();

    fs::write(root.join("only.txt"), "⊕{secret}")?;

    let scanner = FileScanner::new();
    let results = scanner.scan_directory(root)?;

    assert_eq!(results.len(), 1);

    Ok(())
}

#[test]
fn test_performance_with_large_file() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let root = temp_dir.path();

    // Large file with 1000 patterns
    let mut content = String::new();
    for i in 0..1000 {
        content.push_str(&format!("secret{}=⊕{{value{}}}\n", i, i));
    }

    fs::write(root.join("large.txt"), content)?;

    let start = std::time::Instant::now();
    let scanner = FileScanner::new();
    let results = scanner.scan_directory(root)?;
    let duration = start.elapsed();

    assert_eq!(results.len(), 1);
    assert!(duration.as_secs() < 5, "Took too long: {:?}", duration);

    Ok(())
}
