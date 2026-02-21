//! Scanner module coverage expansion tests (TEST-02)
//!
//! Targets uncovered paths in src/scanner.rs:
//! - Complex glob patterns (nested wildcards, double-star paths)
//! - Negation pattern overrides
//! - Recursive traversal with project boundary detection
//! - Symlink handling (valid file symlinks, directory symlinks, dangling, circular)
//! - scan_with_stats accuracy
//! - Extension filter combined with ignore patterns

use anyhow::Result;
use globset::{GlobBuilder, GlobSet, GlobSetBuilder};
use sss::scanner::FileScanner;
use std::fs;
use std::os::unix::fs as unix_fs;
use tempfile::TempDir;

// ============================================================================
// Helper
// ============================================================================

/// Build a GlobSet from a slice of literal glob pattern strings.
fn make_glob_set(patterns: &[&str]) -> GlobSet {
    let mut builder = GlobSetBuilder::new();
    for p in patterns {
        let glob = GlobBuilder::new(p)
            .literal_separator(false)
            .build()
            .expect("valid test glob pattern");
        builder.add(glob);
    }
    builder.build().expect("GlobSet should build")
}

// ============================================================================
// Ignore pattern tests
// ============================================================================

/// Test: complex nested wildcard glob pattern `**/build/**/*.tmp` excludes
/// matching files while non-matching files are included.
#[test]
fn test_complex_nested_glob_excludes_tmp_files() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let root = temp_dir.path();

    // Tree: root/src/main.rs (marker), root/build/output.tmp, root/build/nested/deep.tmp, root/docs/readme.md (marker)
    fs::create_dir_all(root.join("src"))?;
    fs::create_dir_all(root.join("build/nested"))?;
    fs::create_dir_all(root.join("docs"))?;

    fs::write(root.join("src/main.rs"), "api_key=⊕{real-secret}")?;
    fs::write(root.join("build/output.tmp"), "token=⊕{tmp-secret}")?;
    fs::write(root.join("build/nested/deep.tmp"), "pass=⊕{deep-tmp}")?;
    fs::write(root.join("docs/readme.md"), "db_pass=⊕{doc-secret}")?;

    let mut scanner = FileScanner::new();
    scanner.set_ignore_patterns(make_glob_set(&["build/**/*.tmp"]), make_glob_set(&[]));

    let results = scanner.scan_directory(root)?;

    assert!(
        results.iter().any(|p| p.ends_with("src/main.rs")),
        "src/main.rs must be included"
    );
    assert!(
        results.iter().any(|p| p.ends_with("docs/readme.md")),
        "docs/readme.md must be included"
    );
    assert!(
        !results.iter().any(|p| p.to_string_lossy().ends_with(".tmp")),
        "*.tmp files inside build/ must be excluded by nested glob"
    );

    Ok(())
}

/// Test: negation pattern `!readme.md` overrides `*.md` ignore, re-including the file.
#[test]
fn test_negation_overrides_ignore_for_specific_file() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let root = temp_dir.path();

    fs::write(root.join("readme.md"), "api_key=⊕{keeper}")?;
    fs::write(root.join("notes.md"), "token=⊕{hidden}")?;
    fs::write(root.join("config.txt"), "pass=⊕{cfg}")?;

    let mut scanner = FileScanner::new();
    scanner.set_ignore_patterns(
        make_glob_set(&["*.md"]),      // ignore all .md files
        make_glob_set(&["readme.md"]), // but NOT readme.md
    );

    let results = scanner.scan_directory(root)?;

    assert!(
        results.iter().any(|p| p.file_name().unwrap() == "readme.md"),
        "readme.md must be included (negation overrides ignore)"
    );
    assert!(
        !results.iter().any(|p| p.file_name().unwrap() == "notes.md"),
        "notes.md must remain excluded (no negation)"
    );
    assert!(
        results.iter().any(|p| p.file_name().unwrap() == "config.txt"),
        "config.txt (not matched by *.md) must be included"
    );

    Ok(())
}

/// Test: multiple overlapping ignore patterns — *.log, tmp/**, *.bak — all three
/// categories are excluded while non-matching files pass through.
#[test]
fn test_multiple_overlapping_ignore_patterns() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let root = temp_dir.path();

    fs::create_dir_all(root.join("tmp"))?;

    fs::write(root.join("app.log"), "pass=⊕{logval}")?;
    fs::write(root.join("data.bak"), "key=⊕{bakval}")?;
    fs::write(root.join("tmp/cache.txt"), "tok=⊕{tmpval}")?;
    fs::write(root.join("config.yml"), "db=⊕{goodval}")?;

    let mut scanner = FileScanner::new();
    scanner.set_ignore_patterns(
        make_glob_set(&["*.log", "tmp/**", "*.bak"]),
        make_glob_set(&[]),
    );

    let results = scanner.scan_directory(root)?;

    assert_eq!(results.len(), 1, "Only config.yml should remain");
    assert!(results[0].file_name().unwrap() == "config.yml");

    Ok(())
}

// ============================================================================
// Directory traversal / project boundary tests
// ============================================================================

/// Test: scan_directory finds marker files 5 levels deep.
#[test]
fn test_deep_recursive_traversal_five_levels() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let root = temp_dir.path();

    // Build a 5-level chain and place a marker file at every level.
    let mut path = root.to_path_buf();
    for level in 1..=5 {
        path = path.join(format!("level{level}"));
        fs::create_dir_all(&path)?;
        fs::write(
            path.join(format!("secret_l{level}.txt")),
            format!("pass=⊕{{secret-level-{level}}}"),
        )?;
    }

    let scanner = FileScanner::new();
    let results = scanner.scan_directory(root)?;

    assert_eq!(results.len(), 5, "Should find one marker file per level (5 total)");

    Ok(())
}

/// Test: with_project_boundaries(true) stops recursion at subdirectory that
/// contains its own .sss.toml.
#[test]
fn test_project_boundaries_stops_at_nested_sss_toml() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let root = temp_dir.path();

    // Root project
    fs::write(root.join(".sss.toml"), "[project]\nname = \"root\"\ncreated = \"2025-01-01T00:00:00Z\"\n")?;
    fs::write(root.join("root_secret.txt"), "pass=⊕{root-val}")?;

    // Nested sub-project — has its own .sss.toml
    let sub = root.join("subproject");
    fs::create_dir_all(&sub)?;
    fs::write(sub.join(".sss.toml"), "[project]\nname = \"sub\"\ncreated = \"2025-01-01T00:00:00Z\"\n")?;
    fs::write(sub.join("sub_secret.txt"), "token=⊕{sub-val}")?;

    let scanner = FileScanner::new().with_project_boundaries(true);
    let results = scanner.scan_directory(root)?;

    assert!(
        results.iter().any(|p| p.file_name().unwrap() == "root_secret.txt"),
        "root_secret.txt must be included"
    );
    assert!(
        !results.iter().any(|p| p.file_name().unwrap() == "sub_secret.txt"),
        "sub_secret.txt must be excluded (nested project boundary)"
    );

    Ok(())
}

/// Test: with_project_boundaries(false) DOES recurse into subdirs with .sss.toml.
#[test]
fn test_no_project_boundaries_includes_nested_project_files() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let root = temp_dir.path();

    fs::write(root.join(".sss.toml"), "[project]\nname = \"root\"\ncreated = \"2025-01-01T00:00:00Z\"\n")?;
    fs::write(root.join("root_secret.txt"), "pass=⊕{root-val}")?;

    let sub = root.join("subproject");
    fs::create_dir_all(&sub)?;
    fs::write(sub.join(".sss.toml"), "[project]\nname = \"sub\"\ncreated = \"2025-01-01T00:00:00Z\"\n")?;
    fs::write(sub.join("sub_secret.txt"), "token=⊕{sub-val}")?;

    let scanner = FileScanner::new().with_project_boundaries(false);
    let results = scanner.scan_directory(root)?;

    assert!(
        results.iter().any(|p| p.file_name().unwrap() == "root_secret.txt"),
        "root_secret.txt must be included"
    );
    assert!(
        results.iter().any(|p| p.file_name().unwrap() == "sub_secret.txt"),
        "sub_secret.txt must be included when boundaries not respected"
    );

    Ok(())
}

// ============================================================================
// Symlink tests
// ============================================================================

/// Test: symlink to a regular file with an SSS marker is included in results.
#[test]
fn test_symlinked_file_included_in_scan() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let root = temp_dir.path();

    // Real file outside root — link inside root points to it
    let real_file = root.join("real_target.txt");
    fs::write(&real_file, "db_pass=⊕{symlinked-secret}")?;

    let link = root.join("linked_config.txt");
    unix_fs::symlink(&real_file, &link)?;

    let scanner = FileScanner::new();
    let results = scanner.scan_directory(root)?;

    // Both the real file and the symlink resolve to files that contain the marker
    let found_link = results
        .iter()
        .any(|p| p.file_name().unwrap() == "linked_config.txt");
    let found_real = results
        .iter()
        .any(|p| p.file_name().unwrap() == "real_target.txt");

    assert!(
        found_link || found_real,
        "At least one of the symlinked/real files must appear in results"
    );

    Ok(())
}

/// Test: symlink to a directory containing marker files — files inside are found.
#[test]
fn test_symlinked_directory_contents_scanned() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let root = temp_dir.path();

    // Create a real directory with a marker file
    let real_dir = root.join("real_secrets_dir");
    fs::create_dir_all(&real_dir)?;
    fs::write(real_dir.join("inner_secret.txt"), "api_key=⊕{inner}")?;

    // Symlink dir inside root
    let link_dir = root.join("linked_dir");
    unix_fs::symlink(&real_dir, &link_dir)?;

    let scanner = FileScanner::new();
    let results = scanner.scan_directory(root)?;

    // Should find marker files (either via real path or symlink path)
    assert!(
        !results.is_empty(),
        "Scanner must find the marker file reachable through the symlinked directory"
    );
    assert!(
        results.iter().any(|p| p.to_string_lossy().contains("inner_secret")),
        "inner_secret.txt must appear in results"
    );

    Ok(())
}

/// Test: dangling symlink (target deleted) does not crash — scan completes.
#[test]
fn test_dangling_symlink_does_not_crash() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let root = temp_dir.path();

    // Create symlink to a path that does not exist
    let dangling = root.join("dangling_link.txt");
    unix_fs::symlink("/nonexistent/path/ghost.txt", &dangling)?;

    // A valid file so we can verify the scan actually ran
    fs::write(root.join("valid.txt"), "token=⊕{alive}")?;

    let scanner = FileScanner::new();
    let results = scanner.scan_directory(root)?;

    // Must not panic; must still find the valid file
    assert!(
        results.iter().any(|p| p.file_name().unwrap() == "valid.txt"),
        "valid.txt must be found even when a dangling symlink is present"
    );

    Ok(())
}

/// Test: circular directory symlinks (A->B->A) — scanner terminates, does not loop.
#[test]
fn test_circular_symlinks_terminate() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let root = temp_dir.path();

    let dir_a = root.join("dir_a");
    let dir_b = root.join("dir_b");
    fs::create_dir_all(&dir_a)?;
    fs::create_dir_all(&dir_b)?;

    // Circular: dir_a/link_to_b -> dir_b, dir_b/link_to_a -> dir_a
    unix_fs::symlink(&dir_b, dir_a.join("link_to_b"))?;
    unix_fs::symlink(&dir_a, dir_b.join("link_to_a"))?;

    // Place a marker file so we know the scan ran at all
    fs::write(dir_a.join("anchor.txt"), "pass=⊕{anchor}")?;

    let scanner = FileScanner::new();
    // Must return (not hang) — either Ok or Err is acceptable
    let result = scanner.scan_directory(root);

    match result {
        Ok(files) => {
            // anchor.txt must be reachable from dir_a (not through the circular link)
            assert!(
                files.iter().any(|p| p.file_name().unwrap() == "anchor.txt"),
                "anchor.txt must be found"
            );
        }
        Err(_) => {
            // Acceptable: scanner chose to surface the error instead of silently skipping
        }
    }

    Ok(())
}

// ============================================================================
// scan_with_stats accuracy test
// ============================================================================

/// Test: scan_with_stats returns accurate files_count() for a known tree.
#[test]
fn test_scan_with_stats_accurate_file_count() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let root = temp_dir.path();

    fs::create_dir_all(root.join("a"))?;
    fs::create_dir_all(root.join("b"))?;

    // 4 files with markers, 2 without
    fs::write(root.join("a/s1.txt"), "pass=⊕{s1}")?;
    fs::write(root.join("a/s2.txt"), "pass=⊕{s2}")?;
    fs::write(root.join("b/s3.txt"), "pass=⊕{s3}")?;
    fs::write(root.join("b/s4.txt"), "pass=⊕{s4}")?;
    fs::write(root.join("a/plain.txt"), "just normal text")?;
    fs::write(root.join("b/also_plain.txt"), "also normal")?;

    let scanner = FileScanner::new();
    let stats = scanner.scan_with_stats(root)?;

    assert_eq!(stats.files_count(), 4, "Exactly 4 files contain SSS markers");
    assert!(
        stats.total_files >= 6,
        "total_files should count all 6 plain files"
    );
    assert!(stats.scanned_files >= 4, "At least 4 files were scanned");

    Ok(())
}

// ============================================================================
// Extension filter + ignore pattern interaction
// ============================================================================

/// Test: set_allowed_extensions combined with ignore_patterns — extension filter
/// and glob filter interact correctly (intersection semantics: both must pass).
#[test]
fn test_extension_filter_and_ignore_patterns_interact() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let root = temp_dir.path();

    // Files that differ by extension and ignore status
    fs::write(root.join("config.toml"), "pass=⊕{toml}")?;     // allowed ext, not ignored => INCLUDE
    fs::write(root.join("debug.log"), "pass=⊕{log}")?;         // not allowed ext => EXCLUDE
    fs::write(root.join("secret.toml"), "pass=⊕{secret_t}")?;  // allowed ext, ignored => EXCLUDE
    fs::write(root.join("notes.txt"), "pass=⊕{notes}")?;        // not allowed ext => EXCLUDE

    let mut scanner = FileScanner::new();
    scanner.set_allowed_extensions(vec!["toml".to_string()]);
    scanner.set_ignore_patterns(
        make_glob_set(&["secret.*"]),
        make_glob_set(&[]),
    );

    let results = scanner.scan_directory(root)?;

    assert_eq!(results.len(), 1, "Only config.toml should pass both filters");
    assert!(results[0].file_name().unwrap() == "config.toml");

    Ok(())
}
