use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// File access mode for virtual paths
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileMode {
    /// Normal access: fully rendered (no markers)
    Rendered,
    /// .sss-opened: opened with ⊕{} markers for editing
    Opened,
    /// .sss-sealed: raw sealed content with ⊠{} markers from backing store
    Sealed,
}

/// File operations strategy - defines how files are displayed and filtered
pub trait FileOperations: Send + Sync {
    /// Should this file be hidden from directory listings?
    fn should_hide(&self, name: &str) -> bool;

    /// Get file permissions (may adjust based on secrets, etc.)
    fn get_permissions(&self, metadata: &fs::Metadata, has_secrets: bool) -> u16;
}

/// SSS operations - renders ⊠{} to plaintext on read, seals to ⊠{} on write
pub struct SssOperations;

impl FileOperations for SssOperations {
    fn should_hide(&self, name: &str) -> bool {
        matches!(
            name,
            ".git" | ".gitignore" | ".gitattributes" | ".gitmodules"
        )
    }

    fn get_permissions(&self, metadata: &fs::Metadata, has_secrets: bool) -> u16 {
        use std::os::unix::fs::PermissionsExt;
        let perm = (metadata.permissions().mode() & 0o7777) as u16;
        if has_secrets {
            // Force chmod 600 for files with secrets
            0o600
        } else {
            perm
        }
    }
}

/// Passthrough operations - raw read/write with no SSS processing
pub struct PassthroughOperations;

impl FileOperations for PassthroughOperations {
    fn should_hide(&self, _name: &str) -> bool {
        false // Show everything including .git
    }

    fn get_permissions(&self, metadata: &fs::Metadata, _has_secrets: bool) -> u16 {
        use std::os::unix::fs::PermissionsExt;
        (metadata.permissions().mode() & 0o7777) as u16
    }
}

/// Pinned path - maps a virtual prefix to source path with specific operations
pub struct PinnedPath {
    /// Virtual mount point (e.g., "/", "/.overlay")
    pub virtual_prefix: PathBuf,

    /// Corresponding source path (e.g., "/", "/")
    pub source_path: PathBuf,

    /// Operations for files under this path
    pub operations: Arc<dyn FileOperations>,
}

/// Manages virtual file path resolution and operations
///
/// The VirtualFileSystem is responsible for:
/// - Translating virtual paths to source filesystem paths
/// - Managing pinned paths with different operation strategies
/// - Parsing virtual file suffixes (.sss-opened, .sss-sealed)
/// - Determining file access modes
pub struct VirtualFileSystem {
    /// Pinned virtual paths with their operations
    pinned_paths: Vec<PinnedPath>,
}

impl VirtualFileSystem {
    /// Creates a new VirtualFileSystem with pinned paths
    ///
    /// # Arguments
    /// * `pinned_paths` - List of pinned paths with their operations
    pub fn new(pinned_paths: Vec<PinnedPath>) -> Self {
        Self { pinned_paths }
    }

    /// Creates a default VirtualFileSystem with SSS and passthrough operations
    ///
    /// # Arguments
    /// * `source_path` - The source directory path
    ///
    /// # Returns
    /// A VirtualFileSystem with:
    /// - "/" mapped to source_path with SSS operations
    /// - "/.overlay" mapped to source_path with passthrough operations
    pub fn with_defaults(source_path: PathBuf) -> Self {
        let pinned_paths = vec![
            PinnedPath {
                virtual_prefix: PathBuf::from("/"),
                source_path: source_path.clone(),
                operations: Arc::new(SssOperations),
            },
            PinnedPath {
                virtual_prefix: PathBuf::from("/.overlay"),
                source_path,
                operations: Arc::new(PassthroughOperations),
            },
        ];

        Self::new(pinned_paths)
    }

    /// Finds the pinned path that matches the given virtual path
    ///
    /// Returns the most specific (longest) matching prefix.
    ///
    /// # Arguments
    /// * `virtual_path` - Virtual path within the FUSE filesystem
    ///
    /// # Returns
    /// Reference to the matching PinnedPath
    pub fn find_pinned_path(&self, virtual_path: &Path) -> &PinnedPath {
        // Find the most specific (longest) matching prefix
        self.pinned_paths
            .iter()
            .filter(|p| virtual_path.starts_with(&p.virtual_prefix))
            .max_by_key(|p| p.virtual_prefix.as_os_str().len())
            .unwrap_or(&self.pinned_paths[0]) // Default to root
    }

    /// Translates a virtual path to source filesystem path
    ///
    /// # Arguments
    /// * `virtual_path` - Virtual path within the FUSE filesystem
    ///
    /// # Returns
    /// Tuple of (source_relative_path, pinned_path_reference)
    pub fn translate_virtual_to_source(&self, virtual_path: &Path) -> (PathBuf, &PinnedPath) {
        let pinned = self.find_pinned_path(virtual_path);

        // Strip virtual prefix and resolve to source path
        let rel_path = virtual_path
            .strip_prefix(&pinned.virtual_prefix)
            .unwrap_or(virtual_path);

        (rel_path.to_path_buf(), pinned)
    }

    /// Parses virtual file mode suffixes from filename
    ///
    /// Recognizes:
    /// - `.sss-opened` suffix → FileMode::Opened
    /// - `.sss-sealed` suffix → FileMode::Sealed
    /// - No suffix → FileMode::Rendered
    ///
    /// # Arguments
    /// * `name` - The filename to parse
    ///
    /// # Returns
    /// Tuple of (base_name_string, file_mode)
    pub fn parse_virtual_file_mode(name: &OsStr) -> (String, FileMode) {
        let name_str = name.to_string_lossy();

        if let Some(base) = name_str.strip_suffix(".sss-opened") {
            (base.to_string(), FileMode::Opened)
        } else if let Some(base) = name_str.strip_suffix(".sss-sealed") {
            (base.to_string(), FileMode::Sealed)
        } else {
            (name_str.to_string(), FileMode::Rendered)
        }
    }

    /// Strips virtual suffix from path
    ///
    /// # Arguments
    /// * `path` - Path potentially containing virtual suffix
    /// * `is_opened_mode` - Whether to strip `.sss-opened` suffix
    ///
    /// # Returns
    /// Path with virtual suffix removed if present
    pub fn strip_virtual_suffix(path: &Path, is_opened_mode: bool) -> PathBuf {
        if !is_opened_mode {
            return path.to_path_buf();
        }

        if let Some(name) = path.file_name() {
            let name_str = name.to_string_lossy();
            if let Some(base) = name_str.strip_suffix(".sss-opened") {
                let mut new_path = path.to_path_buf();
                new_path.set_file_name(base);
                return new_path;
            }
        }

        path.to_path_buf()
    }

    /// Gets the number of pinned paths
    pub fn count(&self) -> usize {
        self.pinned_paths.len()
    }

    /// Gets reference to all pinned paths
    pub fn pinned_paths(&self) -> &[PinnedPath] {
        &self.pinned_paths
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_virtual_file_mode() {
        let (name, mode) = VirtualFileSystem::parse_virtual_file_mode(OsStr::new("file.txt"));
        assert_eq!(name, "file.txt");
        assert_eq!(mode, FileMode::Rendered);

        let (name, mode) =
            VirtualFileSystem::parse_virtual_file_mode(OsStr::new("file.txt.sss-opened"));
        assert_eq!(name, "file.txt");
        assert_eq!(mode, FileMode::Opened);

        let (name, mode) =
            VirtualFileSystem::parse_virtual_file_mode(OsStr::new("file.txt.sss-sealed"));
        assert_eq!(name, "file.txt");
        assert_eq!(mode, FileMode::Sealed);
    }

    #[test]
    fn test_strip_virtual_suffix() {
        let path = Path::new("/foo/bar.txt.sss-opened");
        let stripped = VirtualFileSystem::strip_virtual_suffix(path, true);
        assert_eq!(stripped, Path::new("/foo/bar.txt"));

        // No stripping in rendered mode
        let stripped = VirtualFileSystem::strip_virtual_suffix(path, false);
        assert_eq!(stripped, path);

        // No suffix to strip
        let path = Path::new("/foo/bar.txt");
        let stripped = VirtualFileSystem::strip_virtual_suffix(path, true);
        assert_eq!(stripped, path);
    }

    #[test]
    fn test_virtual_fs_with_defaults() {
        let vfs = VirtualFileSystem::with_defaults(PathBuf::from("/source"));
        assert_eq!(vfs.count(), 2);

        // Test root path
        let (source, pinned) = vfs.translate_virtual_to_source(Path::new("/file.txt"));
        assert_eq!(source, Path::new("file.txt"));
        assert_eq!(pinned.virtual_prefix, Path::new("/"));

        // Test overlay path
        let (source, pinned) = vfs.translate_virtual_to_source(Path::new("/.overlay/file.txt"));
        assert_eq!(source, Path::new("file.txt"));
        assert_eq!(pinned.virtual_prefix, Path::new("/.overlay"));
    }

    #[test]
    fn test_find_pinned_path() {
        let vfs = VirtualFileSystem::with_defaults(PathBuf::from("/source"));

        // Root path should match root pinned path
        let pinned = vfs.find_pinned_path(Path::new("/file.txt"));
        assert_eq!(pinned.virtual_prefix, Path::new("/"));

        // Overlay path should match overlay pinned path (more specific)
        let pinned = vfs.find_pinned_path(Path::new("/.overlay/file.txt"));
        assert_eq!(pinned.virtual_prefix, Path::new("/.overlay"));
    }

    #[test]
    fn test_sss_operations() {
        let ops = SssOperations;

        // Should hide git files
        assert!(ops.should_hide(".git"));
        assert!(ops.should_hide(".gitignore"));

        // Should not hide regular files
        assert!(!ops.should_hide("README.md"));
    }

    #[test]
    fn test_passthrough_operations() {
        let ops = PassthroughOperations;

        // Should not hide anything
        assert!(!ops.should_hide(".git"));
        assert!(!ops.should_hide(".gitignore"));
        assert!(!ops.should_hide("README.md"));
    }
}
