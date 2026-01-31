#![allow(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc, // regex expects are compile-time validated patterns
    clippy::unnecessary_wraps,  // Result return kept for API consistency
)]

use anyhow::{anyhow, Result};
use globset::GlobSet;
use regex::Regex;
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use crate::constants::MAX_FILE_SIZE;

/// File scanner for finding files with SSS patterns
pub struct FileScanner {
    /// Regex for detecting SSS patterns in files
    pattern_regex: Regex,
    /// Directories to ignore (like .git)
    ignored_dirs: HashSet<String>,
    /// File extensions to check
    allowed_extensions: Option<HashSet<String>>,
    /// Glob patterns for files to ignore (from .sss.toml)
    ignore_patterns: Option<GlobSet>,
    /// Glob patterns for negation (files that should NOT be ignored despite matching ignore patterns)
    negation_patterns: Option<GlobSet>,
    /// When true, do not recurse into subdirectories that contain their own .sss.toml
    respect_project_boundaries: bool,
}

impl Default for FileScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl FileScanner {
    #[must_use] 
    pub fn new() -> Self {
        let pattern_regex =
            Regex::new(r"(?:⊕|o\+|⊠)\{[^}]*\}").expect("Failed to compile SSS pattern regex");

        let mut ignored_dirs = HashSet::new();
        ignored_dirs.insert(".git".to_string());
        ignored_dirs.insert(".svn".to_string());
        ignored_dirs.insert("node_modules".to_string());
        ignored_dirs.insert("target".to_string());
        ignored_dirs.insert(".cargo".to_string());

        Self {
            pattern_regex,
            ignored_dirs,
            allowed_extensions: None,
            ignore_patterns: None,
            negation_patterns: None,
            respect_project_boundaries: false,
        }
    }

    /// Add a directory to ignore during scanning
    pub fn ignore_directory(&mut self, dir: impl Into<String>) {
        self.ignored_dirs.insert(dir.into());
    }

    /// Set gitignore-style patterns for files to ignore
    ///
    /// # Arguments
    ///
    /// * `ignore_set` - `GlobSet` containing patterns for files to ignore
    /// * `negation_set` - `GlobSet` containing negation patterns (files that should NOT be ignored)
    ///
    /// # Examples
    ///
    /// ```
    /// use sss::scanner::FileScanner;
    /// use sss::project::ProjectConfig;
    ///
    /// let mut config = ProjectConfig::default();
    /// config.ignore = Some("*.log !important.log".to_string());
    /// let (ignore_set, negation_set) = config.parse_ignore_patterns().unwrap();
    ///
    /// let mut scanner = FileScanner::new();
    /// scanner.set_ignore_patterns(ignore_set, negation_set);
    /// ```
    pub fn set_ignore_patterns(&mut self, ignore_set: GlobSet, negation_set: GlobSet) {
        self.ignore_patterns = Some(ignore_set);
        self.negation_patterns = Some(negation_set);
    }

    /// Set allowed file extensions (if None, all text files are checked)
    pub fn set_allowed_extensions(&mut self, extensions: Vec<String>) {
        self.allowed_extensions = Some(extensions.into_iter().collect());
    }

    /// When enabled, the scanner will not recurse into subdirectories
    /// that contain their own `.sss.toml` (nested project boundaries).
    #[must_use] 
    pub fn with_project_boundaries(mut self, respect: bool) -> Self {
        self.respect_project_boundaries = respect;
        self
    }

    /// Scan a directory recursively for files containing SSS patterns
    pub fn scan_directory<P: AsRef<Path>>(&self, root: P) -> Result<Vec<PathBuf>> {
        let mut files_with_patterns = Vec::new();
        let root = root.as_ref();

        if !root.exists() {
            return Err(anyhow!("Directory does not exist: {}", root.display()));
        }

        if !root.is_dir() {
            return Err(anyhow!("Path is not a directory: {}", root.display()));
        }

        self.scan_directory_recursive(root, root, &mut files_with_patterns)?;
        files_with_patterns.sort();
        Ok(files_with_patterns)
    }

    /// Internal recursive scanning function
    fn scan_directory_recursive(&self, root: &Path, dir: &Path, results: &mut Vec<PathBuf>) -> Result<()> {
        let entries = fs::read_dir(dir)
            .map_err(|e| anyhow!("Failed to read directory {}: {}", dir.display(), e))?;

        for entry in entries {
            let entry = entry.map_err(|e| {
                anyhow!("Failed to read directory entry in {}: {}", dir.display(), e)
            })?;
            let path = entry.path();

            if path.is_dir() {
                // Check if this directory should be ignored
                if let Some(dir_name) = path.file_name().and_then(|n| n.to_str())
                    && self.ignored_dirs.contains(dir_name) {
                        continue;
                    }

                // Don't cross into nested projects
                if self.respect_project_boundaries
                    && path != root
                    && path.join(".sss.toml").exists()
                {
                    continue;
                }

                // Recursively scan subdirectory
                self.scan_directory_recursive(root, &path, results)?;
            } else if path.is_file() {
                // Check if file matches ignore patterns (using relative path from root)
                let relative_path = path.strip_prefix(root).unwrap_or(&path);
                if self.matches_ignore_patterns_relative(&path, relative_path) {
                    continue;
                }

                // Check if file should be scanned
                if self.should_scan_file(&path)
                    && let Ok(true) = self.file_contains_patterns(&path) {
                        results.push(path);
                    }
            }
        }

        Ok(())
    }

    /// Check if a file matches ignore patterns
    ///
    /// Uses both the absolute path and relative path for matching to support different pattern styles
    ///
    /// Returns true if the file should be ignored, false otherwise
    fn matches_ignore_patterns_relative(&self, _abs_path: &Path, rel_path: &Path) -> bool {
        // If no ignore patterns set, don't ignore
        let Some(ignore_set) = &self.ignore_patterns else {
            return false;
        };

        // Try matching against relative path and filename
        // This allows both directory patterns (build/**) and file patterns (*.log) to work
        let matches_ignore = ignore_set.is_match(rel_path)
            || rel_path.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|name| ignore_set.is_match(name));

        // If doesn't match ignore patterns, don't ignore
        if !matches_ignore {
            return false;
        }

        // Check if path matches any negation pattern (should NOT be ignored)
        if let Some(negation_set) = &self.negation_patterns {
            let matches_negation = negation_set.is_match(rel_path)
                || rel_path.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|name| negation_set.is_match(name));

            if matches_negation {
                return false; // Negation pattern overrides ignore
            }
        }

        true // Matches ignore and doesn't match negation
    }

    /// Check if a file should be scanned based on extension and other criteria
    fn should_scan_file(&self, path: &Path) -> bool {
        // Skip files that are too large
        if let Ok(metadata) = fs::metadata(path) {
            if metadata.len() > MAX_FILE_SIZE as u64 {
                return false;
            }
        } else {
            return false;
        }

        // Check file extension if restrictions are set
        if let Some(ref allowed_extensions) = self.allowed_extensions {
            if let Some(extension) = path.extension().and_then(|ext| ext.to_str()) {
                if !allowed_extensions.contains(extension) {
                    return false;
                }
            } else {
                // No extension, skip if we have extension restrictions
                return false;
            }
        }

        // Skip binary files (basic heuristic)
        if let Some(extension) = path.extension().and_then(|ext| ext.to_str()) {
            match extension.to_lowercase().as_str() {
                // Skip common binary file extensions
                "exe" | "dll" | "so" | "dylib" | "bin" | "zip" | "tar" | "gz" | "bz2" | "jpg"
                | "jpeg" | "png" | "gif" | "pdf" | "mp3" | "mp4" | "avi" | "mov" => {
                    return false;
                }
                _ => {}
            }
        }

        true
    }

    /// Check if a file contains SSS patterns
    fn file_contains_patterns(&self, path: &Path) -> Result<bool> {
        // Read file content as string (will fail for binary files, which is what we want)
        let Ok(content) = fs::read_to_string(path) else {
            // Probably a binary file or encoding issue, skip
            return Ok(false);
        };

        // Search for SSS patterns
        Ok(self.pattern_regex.is_match(&content))
    }

    /// Get statistics about the scan
    pub fn scan_with_stats<P: AsRef<Path>>(&self, root: P) -> Result<ScanResult> {
        let start_time = std::time::Instant::now();
        let mut total_files = 0;
        let mut scanned_files = 0;
        let mut files_with_patterns = Vec::new();
        let root_path = root.as_ref();

        self.scan_with_stats_recursive(
            root_path,
            root_path,
            &mut total_files,
            &mut scanned_files,
            &mut files_with_patterns,
        )?;

        let duration = start_time.elapsed();

        Ok(ScanResult {
            files_with_patterns,
            total_files,
            scanned_files,
            duration,
        })
    }

    fn scan_with_stats_recursive(
        &self,
        root: &Path,
        dir: &Path,
        total_files: &mut usize,
        scanned_files: &mut usize,
        results: &mut Vec<PathBuf>,
    ) -> Result<()> {
        let entries = fs::read_dir(dir)
            .map_err(|e| anyhow!("Failed to read directory {}: {}", dir.display(), e))?;

        for entry in entries {
            let entry = entry.map_err(|e| {
                anyhow!("Failed to read directory entry in {}: {}", dir.display(), e)
            })?;
            let path = entry.path();

            if path.is_dir() {
                // Check if this directory should be ignored
                if let Some(dir_name) = path.file_name().and_then(|n| n.to_str())
                    && self.ignored_dirs.contains(dir_name) {
                        continue;
                    }

                // Don't cross into nested projects
                if self.respect_project_boundaries
                    && path != root
                    && path.join(".sss.toml").exists()
                {
                    continue;
                }

                // Recursively scan subdirectory
                self.scan_with_stats_recursive(root, &path, total_files, scanned_files, results)?;
            } else if path.is_file() {
                *total_files += 1;

                // Check if file matches ignore patterns (using relative path from root)
                let relative_path = path.strip_prefix(root).unwrap_or(&path);
                if self.matches_ignore_patterns_relative(&path, relative_path) {
                    continue;
                }

                // Check if file should be scanned
                if self.should_scan_file(&path) {
                    *scanned_files += 1;
                    if let Ok(true) = self.file_contains_patterns(&path) {
                        results.push(path);
                    }
                }
            }
        }

        Ok(())
    }
}

/// Result of a file scan operation
#[derive(Debug)]
pub struct ScanResult {
    pub files_with_patterns: Vec<PathBuf>,
    pub total_files: usize,
    pub scanned_files: usize,
    pub duration: std::time::Duration,
}

impl ScanResult {
    #[must_use] 
    pub fn files_count(&self) -> usize {
        self.files_with_patterns.len()
    }

    pub fn print_summary(&self) {
        println!("Scan completed in {:.2}s", self.duration.as_secs_f64());
        println!("Total files: {}", self.total_files);
        println!("Scanned files: {}", self.scanned_files);
        println!("Files with SSS patterns: {}", self.files_count());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_scanner_creation() {
        let scanner = FileScanner::new();
        assert!(scanner.ignored_dirs.contains(".git"));
        assert!(scanner.ignored_dirs.contains("node_modules"));
    }

    #[test]
    fn test_pattern_detection() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let file_path = temp_dir.path().join("test.txt");

        // Create a file with SSS patterns
        fs::write(&file_path, "password=⊕{my-secret}\nother=normal-text")?;

        let scanner = FileScanner::new();
        assert!(scanner.file_contains_patterns(&file_path)?);

        // Create a file without patterns
        let file_path2 = temp_dir.path().join("normal.txt");
        fs::write(&file_path2, "just normal text here")?;
        assert!(!scanner.file_contains_patterns(&file_path2)?);

        Ok(())
    }

    #[test]
    fn test_directory_scanning() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let root = temp_dir.path();

        // Create test structure
        fs::create_dir(root.join("subdir"))?;
        fs::create_dir(root.join(".git"))?; // Should be ignored

        fs::write(root.join("config.txt"), "api_key=⊕{secret}")?;
        fs::write(root.join("readme.md"), "# Normal markdown")?;
        fs::write(
            root.join("subdir").join("secrets.env"),
            "DB_PASS=⊠{encrypted}",
        )?;
        fs::write(root.join(".git").join("config"), "⊕{should-be-ignored}")?;

        let scanner = FileScanner::new();
        let results = scanner.scan_directory(root)?;

        assert_eq!(results.len(), 2);
        assert!(results
            .iter()
            .any(|p| p.file_name().unwrap() == "config.txt"));
        assert!(results
            .iter()
            .any(|p| p.file_name().unwrap() == "secrets.env"));
        assert!(!results.iter().any(|p| p.to_string_lossy().contains(".git")));

        Ok(())
    }

    // =========================================================================
    // Ignore-pattern correctness tests (CORR-05)
    // =========================================================================

    /// Helper: build a GlobSet from a space-separated pattern string (positive patterns only).
    fn build_glob_set(patterns: &[&str]) -> GlobSet {
        use globset::GlobBuilder;
        let mut builder = globset::GlobSetBuilder::new();
        for p in patterns {
            let glob = GlobBuilder::new(p)
                .literal_separator(false)
                .build()
                .expect("valid test glob");
            builder.add(glob);
        }
        builder.build().unwrap()
    }

    /// Test: FileScanner with ignore patterns skips files that match.
    #[test]
    fn test_ignore_pattern_skips_matching_files() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let root = temp_dir.path();

        // Create files — only config.txt should be found (not debug.log or build.log)
        fs::write(root.join("config.txt"), "api_key=⊕{secret}")?;
        fs::write(root.join("debug.log"), "api_key=⊕{secret}")?;
        fs::write(root.join("build.log"), "password=⊕{hunter2}")?;

        let ignore_set = build_glob_set(&["*.log"]);
        let negation_set = build_glob_set(&[]); // no negations

        let mut scanner = FileScanner::new();
        scanner.set_ignore_patterns(ignore_set, negation_set);

        let results = scanner.scan_directory(root)?;

        assert!(
            results.iter().any(|p| p.file_name().unwrap() == "config.txt"),
            "config.txt should be included"
        );
        assert!(
            !results.iter().any(|p| p.to_string_lossy().ends_with(".log")),
            "*.log files must be excluded by ignore pattern"
        );

        Ok(())
    }

    /// Test: FileScanner with ignore patterns includes files not matching the pattern.
    #[test]
    fn test_ignore_pattern_includes_non_matching_files() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let root = temp_dir.path();

        fs::write(root.join("config.yml"), "db_pass=⊕{secret}")?;
        fs::write(root.join("app.txt"), "token=⊕{abc}")?;
        fs::write(root.join("notes.log"), "log_key=⊕{logval}")?;

        let ignore_set = build_glob_set(&["*.log"]);
        let negation_set = build_glob_set(&[]);

        let mut scanner = FileScanner::new();
        scanner.set_ignore_patterns(ignore_set, negation_set);

        let results = scanner.scan_directory(root)?;

        assert!(
            results.iter().any(|p| p.file_name().unwrap() == "config.yml"),
            "config.yml should be included"
        );
        assert!(
            results.iter().any(|p| p.file_name().unwrap() == "app.txt"),
            "app.txt should be included"
        );
        assert!(
            !results.iter().any(|p| p.file_name().unwrap() == "notes.log"),
            "notes.log must be excluded"
        );

        Ok(())
    }

    /// Test: negation pattern overrides ignore — file included despite matching ignore.
    #[test]
    fn test_ignore_negation_pattern_includes_file() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let root = temp_dir.path();

        fs::write(root.join("debug.log"), "api_key=⊕{secret}")?;
        fs::write(root.join("important.log"), "token=⊕{keeper}")?;
        fs::write(root.join("config.txt"), "user=⊕{admin}")?;

        let ignore_set = build_glob_set(&["*.log"]);
        let negation_set = build_glob_set(&["important.log"]);

        let mut scanner = FileScanner::new();
        scanner.set_ignore_patterns(ignore_set, negation_set);

        let results = scanner.scan_directory(root)?;

        assert!(
            results.iter().any(|p| p.file_name().unwrap() == "important.log"),
            "important.log must be included (negation overrides ignore)"
        );
        assert!(
            !results.iter().any(|p| p.file_name().unwrap() == "debug.log"),
            "debug.log must remain excluded"
        );
        assert!(
            results.iter().any(|p| p.file_name().unwrap() == "config.txt"),
            "config.txt (no ignore) must be included"
        );

        Ok(())
    }

    /// Test: subdirectory ignore pattern (e.g. tmp/**) excludes files in that dir.
    #[test]
    fn test_ignore_directory_glob_pattern() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let root = temp_dir.path();

        fs::create_dir(root.join("tmp"))?;
        fs::write(root.join("config.txt"), "api_key=⊕{secret}")?;
        fs::write(root.join("tmp").join("cache.txt"), "cache=⊕{cached_secret}")?;

        // Use a broad pattern that matches files within tmp/
        let ignore_set = build_glob_set(&["tmp/*"]);
        let negation_set = build_glob_set(&[]);

        let mut scanner = FileScanner::new();
        scanner.set_ignore_patterns(ignore_set, negation_set);

        let results = scanner.scan_directory(root)?;

        assert!(
            results.iter().any(|p| p.file_name().unwrap() == "config.txt"),
            "config.txt must be included"
        );
        assert!(
            !results.iter().any(|p| p.file_name().unwrap() == "cache.txt"),
            "tmp/cache.txt must be excluded by directory glob"
        );

        Ok(())
    }
}
