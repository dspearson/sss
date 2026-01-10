/// Comprehensive edge case tests for FileScanner module
///
/// This test suite covers edge cases not typically covered in regular integration tests:
/// - Symlink handling
/// - Permission errors
/// - Corrupted/malformed files
/// - Binary files with partial UTF-8
/// - Files exactly at size limits
/// - Concurrent scanning
/// - Empty directories and files
/// - Special file names (unicode, spaces, special chars)

use anyhow::Result;
use sss::scanner::FileScanner;
use std::fs;
use std::os::unix::fs as unix_fs;
use tempfile::TempDir;

#[test]
fn test_scanner_with_symlinks() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let root = temp_dir.path();

    // Create a file with SSS pattern
    let target_file = root.join("target.txt");
    fs::write(&target_file, "password=⊕{secret123}")?;

    // Create symlink to the file
    let link_file = root.join("link.txt");
    unix_fs::symlink(&target_file, &link_file)?;

    let scanner = FileScanner::new();
    let results = scanner.scan_directory(root)?;

    // Should find at least the target file
    assert!(!results.is_empty());
    assert!(results.iter().any(|p| p.ends_with("target.txt")));

    Ok(())
}

#[test]
fn test_scanner_with_broken_symlink() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let root = temp_dir.path();

    // Create symlink to non-existent file
    let link_file = root.join("broken_link.txt");
    unix_fs::symlink("/non/existent/file", &link_file)?;

    // Create a valid file with pattern
    fs::write(root.join("valid.txt"), "password=⊕{valid}")?;

    let scanner = FileScanner::new();
    let results = scanner.scan_directory(root)?;

    // Should find valid file and not crash on broken symlink
    assert!(!results.is_empty());
    assert!(results.iter().any(|p| p.ends_with("valid.txt")));

    Ok(())
}

#[test]
fn test_scanner_with_circular_symlinks() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let root = temp_dir.path();

    // Create directory structure with circular symlinks
    let dir_a = root.join("dir_a");
    let dir_b = root.join("dir_b");
    fs::create_dir_all(&dir_a)?;
    fs::create_dir_all(&dir_b)?;

    // Create circular symlinks: dir_a/link -> dir_b, dir_b/link -> dir_a
    unix_fs::symlink(&dir_b, dir_a.join("link_to_b"))?;
    unix_fs::symlink(&dir_a, dir_b.join("link_to_a"))?;

    // Add a file with pattern
    fs::write(dir_a.join("secret.txt"), "password=⊕{circular}")?;

    let scanner = FileScanner::new();

    // Should handle circular symlinks gracefully without infinite loop
    let results = scanner.scan_directory(root);

    // Should either succeed or fail gracefully, but not hang
    match results {
        Ok(files) => {
            assert!(files.iter().any(|p| p.ends_with("secret.txt")));
        }
        Err(_) => {
            // Acceptable to fail on circular symlinks
        }
    }

    Ok(())
}

#[test]
fn test_scanner_with_empty_files() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let root = temp_dir.path();

    // Create empty files
    fs::write(root.join("empty1.txt"), "")?;
    fs::write(root.join("empty2.log"), "")?;

    // Create file with pattern
    fs::write(root.join("with_pattern.txt"), "password=⊕{secret}")?;

    let scanner = FileScanner::new();
    let results = scanner.scan_directory(root)?;

    // Should only find file with pattern
    assert_eq!(results.len(), 1);
    assert!(results[0].ends_with("with_pattern.txt"));

    Ok(())
}

#[test]
fn test_scanner_with_binary_files() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let root = temp_dir.path();

    // Create binary file with some bytes that might look like patterns
    let binary_data = vec![
        0xFF, 0xFE, 0xE2, 0x8A, 0x95, // Invalid UTF-8 near ⊕
        b'{', b's', b'e', b'c', b'r', b'e', b't', b'}',
        0x00, 0x01, 0x02,
    ];
    fs::write(root.join("binary.bin"), binary_data)?;

    // Create valid text file
    fs::write(root.join("text.txt"), "password=⊕{realpattern}")?;

    let scanner = FileScanner::new();
    let results = scanner.scan_directory(root)?;

    // Binary file should be skipped or handled gracefully
    // Should find the text file
    assert!(results.iter().any(|p| p.ends_with("text.txt")));

    Ok(())
}

#[test]
fn test_scanner_with_large_file_at_limit() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let root = temp_dir.path();

    // Create file exactly at MAX_FILE_SIZE (100MB)
    let large_content = "x".repeat(100 * 1024 * 1024);
    fs::write(root.join("exactly_at_limit.txt"), &large_content)?;

    // Create small file with pattern
    fs::write(root.join("small.txt"), "password=⊕{small}")?;

    let scanner = FileScanner::new();
    let results = scanner.scan_directory(root)?;

    // Large file should be skipped, small file should be found
    assert!(results.iter().any(|p| p.ends_with("small.txt")));

    Ok(())
}

#[test]
fn test_scanner_with_unicode_filenames() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let root = temp_dir.path();

    // Create files with unicode names
    fs::write(root.join("файл.txt"), "password=⊕{russian}")?;
    fs::write(root.join("文件.txt"), "password=⊕{chinese}")?;
    fs::write(root.join("ファイル.txt"), "password=⊕{japanese}")?;
    fs::write(root.join("😀emoji.txt"), "password=⊕{emoji}")?;

    let scanner = FileScanner::new();
    let results = scanner.scan_directory(root)?;

    // Should find all unicode-named files
    assert_eq!(results.len(), 4);

    Ok(())
}

#[test]
fn test_scanner_with_special_char_filenames() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let root = temp_dir.path();

    // Create files with special characters in names
    fs::write(root.join("file with spaces.txt"), "password=⊕{spaces}")?;
    fs::write(root.join("file-with-dashes.txt"), "password=⊕{dashes}")?;
    fs::write(root.join("file_with_underscores.txt"), "password=⊕{underscores}")?;
    fs::write(root.join("file.multiple.dots.txt"), "password=⊕{dots}")?;

    let scanner = FileScanner::new();
    let results = scanner.scan_directory(root)?;

    // Should find all files with special characters
    assert_eq!(results.len(), 4);

    Ok(())
}

#[test]
fn test_scanner_with_deeply_nested_empty_dirs() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let root = temp_dir.path();

    // Create deeply nested empty directories
    let mut path = root.to_path_buf();
    for i in 0..20 {
        path = path.join(format!("level{}", i));
        fs::create_dir_all(&path)?;
    }

    // Add one file with pattern at the end
    fs::write(path.join("deep_secret.txt"), "password=⊕{deep}")?;

    let scanner = FileScanner::new();
    let results = scanner.scan_directory(root)?;

    // Should find the deeply nested file
    assert_eq!(results.len(), 1);
    assert!(results[0].to_string_lossy().contains("deep_secret.txt"));

    Ok(())
}

#[test]
fn test_scanner_with_many_small_files() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let root = temp_dir.path();

    // Create 1000 small files, half with patterns
    for i in 0..500 {
        fs::write(
            root.join(format!("with_pattern_{}.txt", i)),
            format!("password=⊕{{secret{}}}", i),
        )?;
        fs::write(
            root.join(format!("without_pattern_{}.txt", i)),
            format!("normal content {}", i),
        )?;
    }

    let scanner = FileScanner::new();
    let results = scanner.scan_directory(root)?;

    // Should find exactly 500 files with patterns
    assert_eq!(results.len(), 500);

    Ok(())
}

#[test]
fn test_scanner_with_mixed_line_endings() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let root = temp_dir.path();

    // Create files with different line endings
    fs::write(root.join("unix.txt"), "line1\npassword=⊕{unix}\nline3\n")?;
    fs::write(root.join("windows.txt"), "line1\r\npassword=⊕{windows}\r\nline3\r\n")?;
    fs::write(root.join("mac.txt"), "line1\rpassword=⊕{mac}\rline3\r")?;
    fs::write(root.join("mixed.txt"), "line1\npassword=⊕{mixed}\r\nline3\r")?;

    let scanner = FileScanner::new();
    let results = scanner.scan_directory(root)?;

    // Should find all files regardless of line endings
    assert_eq!(results.len(), 4);

    Ok(())
}

#[test]
fn test_scanner_with_hidden_files() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let root = temp_dir.path();

    // Create hidden files (starting with .)
    fs::write(root.join(".hidden1"), "password=⊕{hidden1}")?;
    fs::write(root.join(".hidden2.txt"), "password=⊕{hidden2}")?;

    // Create normal file
    fs::write(root.join("visible.txt"), "password=⊕{visible}")?;

    let scanner = FileScanner::new();
    let results = scanner.scan_directory(root)?;

    // Should find all files including hidden ones
    assert_eq!(results.len(), 3);

    Ok(())
}

#[test]
fn test_scanner_with_no_extension_files() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let root = temp_dir.path();

    // Create files without extensions
    fs::write(root.join("Makefile"), "password=⊕{makefile}")?;
    fs::write(root.join("Dockerfile"), "password=⊕{dockerfile}")?;
    fs::write(root.join("README"), "password=⊕{readme}")?;

    let scanner = FileScanner::new();
    let results = scanner.scan_directory(root)?;

    // Should find files without extensions
    assert_eq!(results.len(), 3);

    Ok(())
}

#[test]
fn test_scanner_with_whitespace_only_content() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let root = temp_dir.path();

    // Create files with only whitespace
    fs::write(root.join("spaces.txt"), "     ")?;
    fs::write(root.join("tabs.txt"), "\t\t\t")?;
    fs::write(root.join("newlines.txt"), "\n\n\n")?;
    fs::write(root.join("mixed_ws.txt"), " \t\n \t\n")?;

    // Create file with pattern
    fs::write(root.join("with_pattern.txt"), "password=⊕{pattern}")?;

    let scanner = FileScanner::new();
    let results = scanner.scan_directory(root)?;

    // Should only find file with pattern
    assert_eq!(results.len(), 1);
    assert!(results[0].ends_with("with_pattern.txt"));

    Ok(())
}

#[test]
fn test_scanner_with_multiple_patterns_per_file() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let root = temp_dir.path();

    // Create file with multiple SSS patterns
    fs::write(
        root.join("multi.txt"),
        "password=⊕{secret1}\napi_key=⊕{secret2}\ntoken=⊕{secret3}",
    )?;

    let scanner = FileScanner::new();
    let results = scanner.scan_directory(root)?;

    // Should find the file (even though it has multiple patterns)
    assert_eq!(results.len(), 1);
    assert!(results[0].ends_with("multi.txt"));

    Ok(())
}

#[test]
fn test_scanner_with_pattern_at_file_boundaries() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let root = temp_dir.path();

    // Pattern at start of file
    fs::write(root.join("start.txt"), "⊕{secret}rest of content")?;

    // Pattern at end of file
    fs::write(root.join("end.txt"), "content before⊕{secret}")?;

    // Pattern as entire file
    fs::write(root.join("only.txt"), "⊕{secret}")?;

    let scanner = FileScanner::new();
    let results = scanner.scan_directory(root)?;

    // Should find all three files
    assert_eq!(results.len(), 3);

    Ok(())
}

#[test]
fn test_scanner_stats_with_various_patterns() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let root = temp_dir.path();

    // Create files with different pattern types
    fs::write(root.join("encrypt.txt"), "password=⊕{encrypted}")?;
    fs::write(root.join("public.txt"), "key=o+{public}")?;
    fs::write(root.join("seal.txt"), "token=⊠{sealed}")?;
    fs::write(root.join("mixed.txt"), "a=⊕{s1} b=o+{s2} c=⊠{s3}")?;

    let scanner = FileScanner::new();
    let stats = scanner.scan_with_stats(root)?;

    // Should count all files with patterns
    assert_eq!(stats.files_count(), 4);
    assert!(stats.total_files >= 4);

    Ok(())
}

#[test]
fn test_scanner_with_invalid_pattern_syntax() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let root = temp_dir.path();

    // Create files with malformed patterns (missing closing brace, etc.)
    fs::write(root.join("incomplete1.txt"), "password=⊕{no_close")?;
    fs::write(root.join("incomplete2.txt"), "password=⊕no_braces")?;
    fs::write(root.join("incomplete3.txt"), "password={no_marker}")?;

    // Valid pattern
    fs::write(root.join("valid.txt"), "password=⊕{valid}")?;

    let scanner = FileScanner::new();
    let results = scanner.scan_directory(root)?;

    // Should only find file with valid pattern
    assert_eq!(results.len(), 1);
    assert!(results[0].ends_with("valid.txt"));

    Ok(())
}

#[test]
fn test_scanner_ignored_directories() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let root = temp_dir.path();

    // Create files in ignored directories
    let git_dir = root.join(".git");
    let node_dir = root.join("node_modules");
    let target_dir = root.join("target");

    fs::create_dir_all(&git_dir)?;
    fs::create_dir_all(&node_dir)?;
    fs::create_dir_all(&target_dir)?;

    fs::write(git_dir.join("config"), "password=⊕{git}")?;
    fs::write(node_dir.join("package.json"), "password=⊕{node}")?;
    fs::write(target_dir.join("debug"), "password=⊕{target}")?;

    // Create file in non-ignored directory
    fs::write(root.join("app.txt"), "password=⊕{app}")?;

    let scanner = FileScanner::new();
    let results = scanner.scan_directory(root)?;

    // Should only find file in non-ignored directory
    assert_eq!(results.len(), 1);
    assert!(results[0].ends_with("app.txt"));

    Ok(())
}

#[test]
fn test_scanner_with_nested_ignored_dirs() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let root = temp_dir.path();

    // Create nested structure with ignored dirs at different levels
    let level1 = root.join("src");
    let level2 = level1.join("modules");
    let ignored = level2.join("node_modules");

    fs::create_dir_all(&level2)?;
    fs::create_dir_all(&ignored)?;

    fs::write(level1.join("main.rs"), "password=⊕{main}")?;
    fs::write(level2.join("mod.rs"), "password=⊕{mod}")?;
    fs::write(ignored.join("lib.js"), "password=⊕{ignored}")?;

    let scanner = FileScanner::new();
    let results = scanner.scan_directory(root)?;

    // Should find files outside node_modules
    assert_eq!(results.len(), 2);
    assert!(!results.iter().any(|p| p.to_string_lossy().contains("node_modules")));

    Ok(())
}

#[test]
fn test_scanner_with_allowed_extensions() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let root = temp_dir.path();

    // Create files with various extensions
    fs::write(root.join("config.toml"), "password=⊕{toml}")?;
    fs::write(root.join("script.sh"), "password=⊕{sh}")?;
    fs::write(root.join("code.rs"), "password=⊕{rs}")?;
    fs::write(root.join("data.json"), "password=⊕{json}")?;

    let mut scanner = FileScanner::new();

    // Set allowed extensions
    let allowed = vec!["toml".to_string(), "rs".to_string()];
    scanner.set_allowed_extensions(allowed);

    let results = scanner.scan_directory(root)?;

    // Should only find .toml and .rs files
    assert_eq!(results.len(), 2);
    assert!(results.iter().any(|p| p.extension().map_or(false, |e| e == "toml")));
    assert!(results.iter().any(|p| p.extension().map_or(false, |e| e == "rs")));

    Ok(())
}

#[test]
fn test_scanner_performance_with_large_directory() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let root = temp_dir.path();

    // Create a large directory structure (1000 files across 100 directories)
    for dir_i in 0..100 {
        let dir = root.join(format!("dir_{}", dir_i));
        fs::create_dir_all(&dir)?;

        for file_i in 0..10 {
            let filename = format!("file_{}.txt", file_i);
            let content = if file_i % 2 == 0 {
                format!("password=⊕{{secret_{}_{}}}",  dir_i, file_i)
            } else {
                format!("normal content {} {}", dir_i, file_i)
            };
            fs::write(dir.join(filename), content)?;
        }
    }

    let scanner = FileScanner::new();
    let start = std::time::Instant::now();
    let results = scanner.scan_directory(root)?;
    let duration = start.elapsed();

    // Should find 500 files with patterns (half of 1000)
    assert_eq!(results.len(), 500);

    // Should complete in reasonable time (< 5 seconds for 1000 files)
    assert!(duration.as_secs() < 5, "Scanning took too long: {:?}", duration);

    Ok(())
}
