use anyhow::{anyhow, Result};
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
}

impl Default for FileScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl FileScanner {
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
        }
    }

    /// Add a directory to ignore during scanning
    pub fn ignore_directory(&mut self, dir: impl Into<String>) {
        self.ignored_dirs.insert(dir.into());
    }

    /// Set allowed file extensions (if None, all text files are checked)
    pub fn set_allowed_extensions(&mut self, extensions: Vec<String>) {
        self.allowed_extensions = Some(extensions.into_iter().collect());
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

        self.scan_directory_recursive(root, &mut files_with_patterns)?;
        files_with_patterns.sort();
        Ok(files_with_patterns)
    }

    /// Internal recursive scanning function
    fn scan_directory_recursive(&self, dir: &Path, results: &mut Vec<PathBuf>) -> Result<()> {
        let entries = fs::read_dir(dir)
            .map_err(|e| anyhow!("Failed to read directory {}: {}", dir.display(), e))?;

        for entry in entries {
            let entry = entry.map_err(|e| {
                anyhow!("Failed to read directory entry in {}: {}", dir.display(), e)
            })?;
            let path = entry.path();

            if path.is_dir() {
                // Check if this directory should be ignored
                if let Some(dir_name) = path.file_name().and_then(|n| n.to_str()) {
                    if self.ignored_dirs.contains(dir_name) {
                        continue;
                    }
                }

                // Recursively scan subdirectory
                self.scan_directory_recursive(&path, results)?;
            } else if path.is_file() {
                // Check if file should be scanned
                if self.should_scan_file(&path) {
                    if let Ok(true) = self.file_contains_patterns(&path) {
                        results.push(path);
                    }
                }
            }
        }

        Ok(())
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
        let content = match fs::read_to_string(path) {
            Ok(content) => content,
            Err(_) => {
                // Probably a binary file or encoding issue, skip
                return Ok(false);
            }
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

        self.scan_with_stats_recursive(
            root.as_ref(),
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
                if let Some(dir_name) = path.file_name().and_then(|n| n.to_str()) {
                    if self.ignored_dirs.contains(dir_name) {
                        continue;
                    }
                }

                // Recursively scan subdirectory
                self.scan_with_stats_recursive(&path, total_files, scanned_files, results)?;
            } else if path.is_file() {
                *total_files += 1;

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
}
