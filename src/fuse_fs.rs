use anyhow::{anyhow, Result};
use fuser::{
    FileAttr, FileType, Filesystem, ReplyAttr, ReplyData, ReplyDirectory, ReplyEntry, Request,
    ReplyWrite, ReplyOpen,
};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::ffi::{CString, OsStr};
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::FromRawFd;
use std::path::{Path, PathBuf};
use std::time::{Duration, UNIX_EPOCH, Instant};

use crate::filesystem_common::{has_encrypted_markers, has_any_markers};
use crate::Processor;

// Debug logging macro with timestamp and thread ID
macro_rules! fuse_debug {
    ($($arg:tt)*) => {
        {
            let thread_id = std::thread::current().id();
            let pid = std::process::id();
            eprintln!("[FUSE DEBUG {:?} PID:{}] {}", thread_id, pid, format!($($arg)*));
        }
    };
}

const TTL: Duration = Duration::from_secs(1);
const TTL_ZERO: Duration = Duration::from_secs(0);  // No caching for passthrough files
const ROOT_INO: u64 = 1;

// Synthetic inodes for virtual files
const SYNTHETIC_OVERLAY_DIR_INO: u64 = u64::MAX - 1;  // Passthrough directory with raw filesystem access

// Custom ioctl command for ssse edit to request opened mode (with ⊕{} markers)
// Only used on Linux - macOS/fuse-t doesn't support ioctl
#[cfg(not(target_os = "macos"))]
const SSS_IOC_OPENED_MODE: u32 = 0x5353_0001; // 'SS' magic + command 1
#[cfg(not(target_os = "macos"))]
const SSS_IOC_SEALED_MODE: u32 = 0x5353_0002; // 'SS' magic + command 2 - request sealed content (requires O_NONBLOCK)

/// Inode information
#[derive(Clone)]
struct InodeEntry {
    _ino: u64,
    path: PathBuf,
    parent: u64,
}

/// File access mode for virtual paths
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FileMode {
    /// Normal access: fully rendered (no markers)
    Rendered,
    /// .sss-opened: opened with ⊕{} markers for editing
    Opened,
    /// .sss-sealed: raw sealed content with ⊠{} markers from backing store
    Sealed,
}

/// File handle for tracking open files
struct FileHandle {
    ino: u64,
    path: PathBuf,
    /// Cached content (rendered or original)
    cached_content: Option<Vec<u8>>,
    /// Whether the file is open for writing
    writable: bool,
    /// Dirty flag for writes
    dirty: bool,
    /// Opened mode: return content with ⊕{} markers (for ssse edit)
    opened_mode: bool,
    /// Sealed mode: return raw sealed content with ⊠{} markers (signaled by O_NONBLOCK)
    sealed_mode: bool,
    /// Origin mode: file is under .overlay/ - raw passthrough with no processing
    origin_mode: bool,
    /// File descriptor for passthrough files (kept open for lifetime of handle)
    passthrough_fd: Option<i32>,
    /// Original sealed content from backing store (captured at open time for writable files)
    /// Used for smart reconstruction when editor truncates file before writing
    original_sealed: Option<String>,
}

/// File operations strategy - defines how files are displayed and filtered
trait FileOperations: Send + Sync {
    /// Should this file be hidden from directory listings?
    fn should_hide(&self, name: &str) -> bool;

    /// Get file permissions (may adjust based on secrets, etc.)
    fn get_permissions(&self, metadata: &fs::Metadata, has_secrets: bool) -> u16;
}

/// SSS operations - renders ⊠{} to plaintext on read, seals to ⊠{} on write
struct SssOperations {}

impl FileOperations for SssOperations {
    fn should_hide(&self, name: &str) -> bool {
        matches!(
            name,
            ".git" | ".gitignore" | ".gitattributes" | ".gitmodules"
        )
    }

    fn get_permissions(&self, metadata: &fs::Metadata, has_secrets: bool) -> u16 {
        use std::os::unix::fs::PermissionsExt;
        let perm = metadata.permissions().mode() as u16;
        if has_secrets {
            // Force chmod 600 for files with secrets
            0o600
        } else {
            perm
        }
    }
}

/// Passthrough operations - raw read/write with no SSS processing
struct PassthroughOperations {}

impl FileOperations for PassthroughOperations {
    fn should_hide(&self, _name: &str) -> bool {
        false  // Show everything including .git
    }

    fn get_permissions(&self, metadata: &fs::Metadata, _has_secrets: bool) -> u16 {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() as u16
    }
}

/// Pinned path - maps a virtual prefix to source path with specific operations
struct PinnedPath {
    /// Virtual mount point (e.g., "/", "/.overlay")
    virtual_prefix: PathBuf,

    /// Corresponding source path (e.g., "/", "/")
    source_path: PathBuf,

    /// Operations for files under this path
    operations: std::sync::Arc<dyn FileOperations>,
}

/// FUSE filesystem for transparent encryption/decryption of sss-managed files.
///
/// `SssFS` provides a FUSE-based virtual filesystem that transparently renders
/// encrypted content on read and seals (encrypts) content on write. It supports:
///
/// - **Transparent rendering**: Files with `⊠{...}` markers are automatically decrypted
/// - **Virtual files**: `.sss-opened` suffix provides content with `⊕{...}` markers for editing
/// - **Sealed mode**: Two-factor protocol (O_NONBLOCK + fsetxattr) for raw sealed access
/// - **Overlay mounting**: Can mount over source directory while preserving file access
/// - **Smart reconstruction**: Preserves encryption structure when writing edited files
///
/// # Architecture
///
/// - Uses file descriptors for all operations to support overlay mounting
/// - Maintains bidirectional inode mapping for stable file identity
/// - Caches rendered content per inode for performance
/// - Hides git-related files (`.git/`, `.gitignore`, etc.) from FUSE view
///
/// # Thread Safety
///
/// All internal state (inode tables, file handles, caches) uses `RwLock` for
/// thread-safe concurrent access required by FUSE.
pub struct SssFS {
    /// Path to the real directory being mirrored
    source_path: PathBuf,
    /// File descriptor to source directory (kept open to access files even if mounted over)
    source_fd: std::os::unix::io::RawFd,
    /// File descriptor to mount point directory (held open before mount for /proc access)
    /// Allows accessing the underlying directory via /proc/self/fd/<mount_fd> even after FUSE mount
    mount_fd: Option<std::os::unix::io::RawFd>,
    /// UID of the process running FUSE (for synthetic directories)
    uid: u32,
    /// GID of the process running FUSE (for synthetic directories)
    gid: u32,
    /// Processor for encryption/decryption operations
    processor: Processor,
    /// Inode table: maps inode number to path information
    inode_table: RwLock<HashMap<u64, InodeEntry>>,
    /// Reverse lookup: path to inode number
    path_to_ino: RwLock<HashMap<PathBuf, u64>>,
    /// Next available inode number (atomic counter)
    next_ino: RwLock<u64>,
    /// Open file handles with cached content and mode flags
    file_handles: RwLock<HashMap<u64, FileHandle>>,
    /// Next available file handle ID (atomic counter)
    next_fh: RwLock<u64>,
    /// Cache of rendered file contents (inode -> decrypted bytes)
    render_cache: RwLock<HashMap<u64, Vec<u8>>>,
    /// Pinned virtual paths with their operations
    pinned_paths: Vec<PinnedPath>,
}

impl SssFS {
    /// Creates a new FUSE filesystem for transparent sss encryption/decryption.
    ///
    /// # Arguments
    ///
    /// * `source_path` - Path to the directory containing files to be transparently processed
    /// * `processor` - Configured [`Processor`] instance for encryption/decryption operations
    /// * `mount_path` - Optional path to the mount point directory. If provided, a file descriptor
    ///   will be held open to this directory, allowing access via /proc/self/fd/<fd>
    ///   even after the FUSE filesystem is mounted over it.
    ///
    /// # Returns
    ///
    /// Returns `Ok(SssFS)` if successful, or an error if:
    /// - The source path doesn't exist
    /// - The source path is not a directory
    /// - The source directory cannot be opened (permission denied, etc.)
    /// - The mount path (if provided) cannot be opened
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use sss::fuse_fs::SssFS;
    /// # use sss::{Processor, RepositoryKey};
    /// # use std::path::PathBuf;
    /// # fn example() -> anyhow::Result<()> {
    /// let source = PathBuf::from("/path/to/project");
    /// let mount = PathBuf::from("/mnt/project");
    /// let key = RepositoryKey::new();
    /// let processor = Processor::new(key)?;
    /// // Hold fd to mount point for /proc access
    /// let fs = SssFS::new(source, processor, Some(mount))?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(source_path: PathBuf, processor: Processor, mount_path: Option<PathBuf>) -> Result<Self> {
        if !source_path.exists() {
            return Err(anyhow!("Source path does not exist: {:?}", source_path));
        }

        if !source_path.is_dir() {
            return Err(anyhow!("Source path is not a directory: {:?}", source_path));
        }

        // Open a file descriptor to the source directory before mounting
        // This allows us to access files even if we mount over the source location
        let source_fd = unsafe {
            let path_cstr = std::ffi::CString::new(source_path.to_str().unwrap())?;
            libc::open(path_cstr.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY)
        };

        if source_fd < 0 {
            return Err(anyhow!(
                "Failed to open source directory: {}",
                std::io::Error::last_os_error()
            ));
        }

        // Open a file descriptor to the mount point directory if provided
        // This allows accessing the underlying directory via /proc/self/fd/<mount_fd>
        // even after the FUSE filesystem is mounted over it
        //
        // We use O_PATH which is perfect for this purpose:
        // - Obtains a fd that can be used with /proc/PID/fd/N access
        // - Allows full read/write operations through the /proc path
        // - The actual permissions are determined by the directory's mode and user's access
        let mount_fd = if let Some(ref mount_path) = mount_path {
            let fd = unsafe {
                let path_cstr = std::ffi::CString::new(mount_path.to_str().unwrap())?;
                // O_PATH | O_DIRECTORY: path-based fd for directory access via /proc
                // macOS doesn't have O_PATH, use O_RDONLY | O_DIRECTORY instead
                #[cfg(target_os = "linux")]
                let flags = libc::O_PATH | libc::O_DIRECTORY;
                #[cfg(target_os = "macos")]
                let flags = libc::O_RDONLY | libc::O_DIRECTORY;
                libc::open(path_cstr.as_ptr(), flags)
            };

            if fd < 0 {
                // Clean up source_fd before returning error
                unsafe { libc::close(source_fd); }
                return Err(anyhow!(
                    "Failed to open mount point directory: {}",
                    std::io::Error::last_os_error()
                ));
            }

            Some(fd)
        } else {
            None
        };

        let mut inode_table = HashMap::new();
        let mut path_to_ino = HashMap::new();

        // Initialize root inode
        let root_entry = InodeEntry {
            _ino: ROOT_INO,
            path: PathBuf::from("/"),
            parent: ROOT_INO,
        };
        inode_table.insert(ROOT_INO, root_entry.clone());
        path_to_ino.insert(PathBuf::from("/"), ROOT_INO);

        // Initialize pinned paths - order matters! More specific prefixes first
        let pinned_paths = vec![
            // .overlay/ - passthrough to root with no SSS processing
            PinnedPath {
                virtual_prefix: PathBuf::from("/.overlay"),
                source_path: PathBuf::from("/"),
                operations: std::sync::Arc::new(PassthroughOperations {}),
            },
            // Root - normal SSS operations (render/seal)
            PinnedPath {
                virtual_prefix: PathBuf::from("/"),
                source_path: PathBuf::from("/"),
                operations: std::sync::Arc::new(SssOperations {}),
            },
        ];

        // Get current process uid/gid for synthetic directories
        let uid = unsafe { libc::getuid() };
        let gid = unsafe { libc::getgid() };

        Ok(Self {
            source_path,
            source_fd,
            mount_fd,
            uid,
            gid,
            processor,
            inode_table: RwLock::new(inode_table),
            path_to_ino: RwLock::new(path_to_ino),
            next_ino: RwLock::new(ROOT_INO + 1),
            file_handles: RwLock::new(HashMap::new()),
            next_fh: RwLock::new(1),
            render_cache: RwLock::new(HashMap::new()),
            pinned_paths,
        })
    }

    /// Get the mount point file descriptor (if available)
    ///
    /// Returns the raw file descriptor to the mount point directory.
    /// This can be used to access the underlying directory via /proc/self/fd/<fd>
    /// even after the FUSE filesystem is mounted over it.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use sss::fuse_fs::SssFS;
    /// # use sss::{Processor, RepositoryKey};
    /// # use std::path::PathBuf;
    /// # fn example() -> anyhow::Result<()> {
    /// # let source = PathBuf::from("/path/to/project");
    /// # let mount = PathBuf::from("/mnt/project");
    /// # let key = RepositoryKey::new();
    /// # let processor = Processor::new(key)?;
    /// let fs = SssFS::new(source, processor, Some(mount))?;
    /// if let Some(fd) = fs.get_mount_fd() {
    ///     println!("Access underlying directory: /proc/self/fd/{}", fd);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn get_mount_fd(&self) -> Option<std::os::unix::io::RawFd> {
        self.mount_fd
    }

    /// Find the pinned path that matches the given virtual path (longest prefix match)
    fn find_pinned_path(&self, virtual_path: &Path) -> &PinnedPath {
        // Longest prefix match - more specific paths come first in the vec
        for pinned in &self.pinned_paths {
            if virtual_path.starts_with(&pinned.virtual_prefix) {
                return pinned;
            }
        }

        // Should never happen if we have a root "/" entry
        panic!("No pinned path found for: {:?}", virtual_path);
    }

    /// Translate virtual path to source path and get operations
    /// Returns: (source_rel_path, pinned_path)
    fn translate_virtual_to_source(&self, virtual_path: &Path) -> (PathBuf, &PinnedPath) {
        let pinned = self.find_pinned_path(virtual_path);

        // Strip the virtual prefix and apply to source path
        let rel_to_virtual = virtual_path
            .strip_prefix(&pinned.virtual_prefix)
            .unwrap_or(Path::new(""));

        let source_path = if rel_to_virtual.as_os_str().is_empty() {
            pinned.source_path.clone()
        } else if pinned.source_path == Path::new("/") {
            PathBuf::from(rel_to_virtual)
        } else {
            pinned.source_path.join(rel_to_virtual)
        };

        // Convert to relative path for fd operations
        let source_rel = if source_path == Path::new("/") {
            PathBuf::from(".")
        } else {
            source_path.strip_prefix("/").unwrap_or(&source_path).to_path_buf()
        };

        (source_rel, pinned)
    }

    /// Get or create an inode for a path
    fn get_or_create_inode(&self, virtual_path: &Path, parent_ino: u64) -> u64 {
        // Check if we already have this path
        let path_map = self.path_to_ino.read();
        if let Some(&ino) = path_map.get(virtual_path) {
            return ino;
        }
        drop(path_map);

        // Create new inode
        let mut next_ino = self.next_ino.write();
        let ino = *next_ino;
        *next_ino += 1;
        drop(next_ino);

        let entry = InodeEntry {
            _ino: ino,
            path: virtual_path.to_path_buf(),
            parent: parent_ino,
        };

        self.inode_table.write().insert(ino, entry);
        self.path_to_ino.write().insert(virtual_path.to_path_buf(), ino);

        ino
    }

    /// Get inode entry
    fn get_inode(&self, ino: u64) -> Option<InodeEntry> {
        self.inode_table.read().get(&ino).cloned()
    }

    /// Convert filesystem metadata to FUSE FileAttr
    fn metadata_to_attr(&self, ino: u64, metadata: &fs::Metadata, size_override: Option<u64>, force_writable: bool) -> FileAttr {
        self.metadata_to_attr_with_secrets(ino, metadata, size_override, force_writable, false)
    }

    fn metadata_to_attr_with_secrets(&self, ino: u64, metadata: &fs::Metadata, size_override: Option<u64>, force_writable: bool, has_secrets: bool) -> FileAttr {
        let kind = if metadata.is_dir() {
            FileType::Directory
        } else if metadata.is_symlink() {
            FileType::Symlink
        } else {
            FileType::RegularFile
        };

        // Use override size for rendered content
        let size = size_override.unwrap_or(metadata.len());

        // Get base permissions
        let mut perm = Self::get_permissions(metadata);

        // If file contains rendered secrets, restrict permissions for security
        // chmod 600 for non-executable files, 700 for executable files
        if has_secrets && kind == FileType::RegularFile {
            let has_execute = (perm & 0o111) != 0;
            perm = if has_execute {
                0o700  // Owner read/write/execute only
            } else {
                0o600  // Owner read/write only
            };
        } else if force_writable && kind == FileType::RegularFile {
            // Ensure owner write permission (0o200) for non-secret files
            perm |= 0o200;
        }

        FileAttr {
            ino,
            size,
            blocks: size.div_ceil(512),
            atime: metadata.accessed().unwrap_or(UNIX_EPOCH),
            mtime: metadata.modified().unwrap_or(UNIX_EPOCH),
            ctime: metadata.created().unwrap_or(UNIX_EPOCH),
            crtime: metadata.created().unwrap_or(UNIX_EPOCH),
            kind,
            perm,
            nlink: Self::get_nlink(metadata) as u32,
            uid: Self::get_uid(metadata),
            gid: Self::get_gid(metadata),
            rdev: 0,
            blksize: 512,
            flags: 0,
        }
    }

    #[cfg(unix)]
    fn get_permissions(metadata: &fs::Metadata) -> u16 {
        use std::os::unix::fs::PermissionsExt;
        (metadata.permissions().mode() & 0o777) as u16
    }

    #[cfg(not(unix))]
    fn get_permissions(_metadata: &fs::Metadata) -> u16 {
        0o644
    }

    #[cfg(unix)]
    fn get_uid(metadata: &fs::Metadata) -> u32 {
        use std::os::unix::fs::MetadataExt;
        metadata.uid()
    }

    #[cfg(not(unix))]
    fn get_uid(_metadata: &fs::Metadata) -> u32 {
        0
    }

    #[cfg(unix)]
    fn get_gid(metadata: &fs::Metadata) -> u32 {
        use std::os::unix::fs::MetadataExt;
        metadata.gid()
    }

    #[cfg(not(unix))]
    fn get_gid(_metadata: &fs::Metadata) -> u32 {
        0
    }

    #[cfg(unix)]
    fn get_nlink(metadata: &fs::Metadata) -> u64 {
        use std::os::unix::fs::MetadataExt;
        metadata.nlink()
    }

    #[cfg(not(unix))]
    fn get_nlink(_metadata: &fs::Metadata) -> u64 {
        1
    }

    /// Check if a file has encrypted markers (should be processed)
    // Note: has_encrypted_markers() and has_any_markers() moved to filesystem_common module

    /// Check if a file at the given path contains encrypted markers
    fn file_has_secrets(&self, rel_path: &Path) -> bool {
        // Use fd-based access to avoid infinite loop when mounted in-place
        match self.metadata_via_fd(rel_path) {
            Ok(metadata) if metadata.is_file() => {
                // Try to read the file and check for encrypted markers
                match self.read_file_via_fd(rel_path) {
                    Ok(content) => {
                        if let Ok(s) = String::from_utf8(content) {
                            has_encrypted_markers(&s)
                        } else {
                            false  // Not UTF-8, can't have text markers
                        }
                    }
                    Err(_) => false,  // Can't read, assume no secrets
                }
            }
            _ => false,  // Not a file or doesn't exist
        }
    }

    /// Check if a file/directory should be hidden from FUSE view
    fn should_hide(name: &str) -> bool {
        matches!(
            name,
            ".git" | ".gitignore" | ".gitattributes" | ".gitmodules"
        )
    }

    /// Read and render a file (decrypt and remove all markers)
    /// Get metadata using source_fd (works even if mounted over source)
    fn metadata_via_fd(&self, rel_path: &Path) -> Result<fs::Metadata> {
        fuse_debug!("    metadata_via_fd: path={:?}", rel_path);

        // On macOS with in-place mounts, path-based operations deadlock
        // because they route through the FUSE mount. Use FD-based operations
        // through source_fd which was opened before mounting.
        #[cfg(target_os = "macos")]
        {
            use std::os::unix::ffi::OsStrExt;

            if rel_path == Path::new(".") {
                // For root directory, use fstat directly on source_fd
                fuse_debug!("    metadata_via_fd: macOS - using fstat on source_fd for root");
                let file = unsafe { std::fs::File::from_raw_fd(self.source_fd) };
                let metadata = file.metadata()?;
                std::mem::forget(file); // Don't close source_fd
                fuse_debug!("    metadata_via_fd: done (macOS fstat)");
                return Ok(metadata);
            }

            // For other paths, use fstatat relative to source_fd
            // This should work because source_fd was opened before mounting
            fuse_debug!("    metadata_via_fd: macOS - using fstatat via source_fd");
            let path_bytes = rel_path.as_os_str().as_bytes();
            let path_cstr = std::ffi::CString::new(path_bytes)?;

            let mut stat: libc::stat = unsafe { std::mem::zeroed() };
            fuse_debug!("    metadata_via_fd: calling fstatat...");
            let result = unsafe {
                libc::fstatat(self.source_fd, path_cstr.as_ptr(), &mut stat, libc::AT_SYMLINK_NOFOLLOW)
            };

            if result < 0 {
                let err = std::io::Error::last_os_error();
                fuse_debug!("    metadata_via_fd: fstatat failed: {}", err);
                return Err(anyhow!("Failed to stat file: {}", err));
            }

            fuse_debug!("    metadata_via_fd: fstatat succeeded");

            // Determine file type
            let is_dir = (stat.st_mode & libc::S_IFMT) == libc::S_IFDIR;
            let is_symlink = (stat.st_mode & libc::S_IFMT) == libc::S_IFLNK;
            fuse_debug!("    metadata_via_fd: is_dir={}, is_symlink={}", is_dir, is_symlink);

            // Open with appropriate flags based on file type
            // For symlinks: use O_SYMLINK if available (macOS) to open symlink itself
            // For directories: use O_RDONLY | O_DIRECTORY | O_NOFOLLOW
            // For regular files: use O_RDONLY | O_NOFOLLOW
            #[cfg(target_os = "macos")]
            let flags = if is_symlink {
                libc::O_RDONLY | libc::O_SYMLINK | libc::O_NOFOLLOW
            } else if is_dir {
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW
            } else {
                libc::O_RDONLY | libc::O_NOFOLLOW
            };

            fuse_debug!("    metadata_via_fd: calling openat with flags={:#x}...", flags);
            let fd = unsafe {
                libc::openat(self.source_fd, path_cstr.as_ptr(), flags)
            };

            if fd < 0 {
                let err = std::io::Error::last_os_error();
                fuse_debug!("    metadata_via_fd: openat failed: {}", err);

                // If this is a symlink and openat failed, try with O_SYMLINK | O_NOFOLLOW
                #[cfg(target_os = "macos")]
                if is_symlink && err.raw_os_error() == Some(libc::ELOOP) {
                    fuse_debug!("    metadata_via_fd: retrying symlink with O_SYMLINK | O_NOFOLLOW...");
                    let retry_fd = unsafe {
                        libc::openat(self.source_fd, path_cstr.as_ptr(),
                                   libc::O_RDONLY | libc::O_SYMLINK | libc::O_NOFOLLOW)
                    };
                    if retry_fd >= 0 {
                        fuse_debug!("    metadata_via_fd: retry succeeded, fd={}", retry_fd);
                        let file = unsafe { std::fs::File::from_raw_fd(retry_fd) };
                        let metadata = file.metadata()?;
                        fuse_debug!("    metadata_via_fd: done (macOS via retry)");
                        return Ok(metadata);
                    }
                }

                return Err(anyhow!("Failed to open file for metadata: {}", err));
            }

            fuse_debug!("    metadata_via_fd: openat succeeded, getting metadata");
            let file = unsafe { std::fs::File::from_raw_fd(fd) };
            let metadata = file.metadata()?;
            fuse_debug!("    metadata_via_fd: done (macOS via source_fd)");
            return Ok(metadata);
        }

        #[cfg(not(target_os = "macos"))]
        {
            use std::os::unix::ffi::OsStrExt;

            let path_bytes = rel_path.as_os_str().as_bytes();
            let path_cstr = std::ffi::CString::new(path_bytes)?;

            fuse_debug!("    metadata_via_fd: calling fstatat...");
            let mut stat: libc::stat = unsafe { std::mem::zeroed() };

            let result = unsafe {
                libc::fstatat(self.source_fd, path_cstr.as_ptr(), &mut stat, libc::AT_SYMLINK_NOFOLLOW)
            };

            if result < 0 {
                let err = std::io::Error::last_os_error();
                fuse_debug!("    metadata_via_fd: fstatat failed: {}", err);
                return Err(anyhow!("Failed to stat file: {}", err));
            }
            fuse_debug!("    metadata_via_fd: fstatat succeeded");

            // Determine file type from the stat result
            let is_dir = (stat.st_mode & libc::S_IFMT) == libc::S_IFDIR;
            let is_symlink = (stat.st_mode & libc::S_IFMT) == libc::S_IFLNK;
            fuse_debug!("    metadata_via_fd: is_dir={}, is_symlink={}", is_dir, is_symlink);

            // Open with appropriate flags based on file type
            // For symlinks: use O_PATH | O_NOFOLLOW to open the symlink itself
            //               without following it (avoids ELOOP for circular/broken symlinks)
            // For directories: use O_RDONLY | O_DIRECTORY | O_NOFOLLOW
            // For regular files: use O_RDONLY | O_NOFOLLOW
            let flags = if is_symlink {
                libc::O_PATH | libc::O_NOFOLLOW
            } else if is_dir {
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW
            } else {
                libc::O_RDONLY | libc::O_NOFOLLOW
            };

            fuse_debug!("    metadata_via_fd: calling openat with flags={:#x}...", flags);
            let fd = unsafe {
                libc::openat(self.source_fd, path_cstr.as_ptr(), flags)
            };

            if fd < 0 {
                let err = std::io::Error::last_os_error();
                fuse_debug!("    metadata_via_fd: openat failed: {}", err);

                // If this is a symlink and openat failed with ELOOP, try O_PATH | O_NOFOLLOW
                // as a fallback (in case the first attempt didn't use those flags)
                if is_symlink && err.raw_os_error() == Some(libc::ELOOP) {
                    fuse_debug!("    metadata_via_fd: retrying symlink with O_PATH | O_NOFOLLOW...");
                    let retry_fd = unsafe {
                        libc::openat(self.source_fd, path_cstr.as_ptr(), libc::O_PATH | libc::O_NOFOLLOW)
                    };
                    if retry_fd >= 0 {
                        fuse_debug!("    metadata_via_fd: retry succeeded, fd={}", retry_fd);
                        let file = unsafe { std::fs::File::from_raw_fd(retry_fd) };
                        let metadata = file.metadata()?;
                        fuse_debug!("    metadata_via_fd: done (via retry)");
                        return Ok(metadata);
                    }
                }

                return Err(anyhow!("Failed to open file for metadata: {}", err));
            }
            fuse_debug!("    metadata_via_fd: openat succeeded, fd={}", fd);

            fuse_debug!("    metadata_via_fd: calling file.metadata()...");
            let file = unsafe { std::fs::File::from_raw_fd(fd) };
            let metadata = file.metadata()?;
            fuse_debug!("    metadata_via_fd: done");
            Ok(metadata)
        }
    }

    /// Check if a file exists using source_fd (works even if mounted over source)
    fn file_exists_via_fd(&self, rel_path: &Path) -> bool {
        let path_bytes = rel_path.as_os_str().as_bytes();
        let path_cstr = match std::ffi::CString::new(path_bytes) {
            Ok(p) => p,
            Err(_) => return false,
        };

        // Use faccessat to check if file exists without deadlocking
        let result = unsafe {
            libc::faccessat(
                self.source_fd,
                path_cstr.as_ptr(),
                libc::F_OK,  // Check for existence
                0,
            )
        };

        result == 0
    }

    /// Read file using source_fd (works even if mounted over source)
    fn read_file_via_fd(&self, rel_path: &Path) -> Result<Vec<u8>> {
        // On macOS, openat can deadlock from FUSE handlers
        // Use full path instead
        #[cfg(target_os = "macos")]
        {
            let full_path = self.source_path.join(rel_path);
            let buffer = fs::read(&full_path)?;
            return Ok(buffer);
        }

        #[cfg(not(target_os = "macos"))]
        {
            use std::os::unix::ffi::OsStrExt;

            let path_bytes = rel_path.as_os_str().as_bytes();
            let path_cstr = std::ffi::CString::new(path_bytes)?;

            // Open file relative to source_fd
            let fd = unsafe {
                libc::openat(self.source_fd, path_cstr.as_ptr(), libc::O_RDONLY)
            };

            if fd < 0 {
                let err = std::io::Error::last_os_error();
                return Err(anyhow!("Failed to open file: {}", err));
            }

            // Read file contents
            let mut buffer = Vec::new();
            let file = unsafe { std::fs::File::from_raw_fd(fd) };
            use std::io::Read;
            std::io::BufReader::new(file).read_to_end(&mut buffer)?;

            Ok(buffer)
        }
    }

    /// Generic file reading with optional processing
    /// Reduces duplication across read_and_render, read_and_open, and read_sealed
    fn read_and_process<F>(&self, path: &Path, process_fn: F) -> Result<Vec<u8>>
    where
        F: FnOnce(&Self, String, &Path) -> Result<String>,
    {
        // Get relative path from source root
        let rel_path = path.strip_prefix(&self.source_path)
            .unwrap_or(path);

        // Read file via fd
        let bytes = self.read_file_via_fd(rel_path)?;

        // Try to convert to string
        let content = match String::from_utf8(bytes.clone()) {
            Ok(c) => c,
            Err(_) => {
                // Not a text file, return raw bytes
                return Ok(bytes);
            }
        };

        // Apply processing function with relative path for proper secrets resolution
        let processed = process_fn(self, content, rel_path)?;
        Ok(processed.into_bytes())
    }

    /// Interpolate secrets using fd-based operations (avoids FUSE deadlock)
    fn interpolate_secrets_via_fd(&self, content: &str, rel_path: &Path) -> Result<String> {
        use regex::Regex;
        use once_cell::sync::Lazy;

        static SECRETS_REGEX: Lazy<Regex> =
            Lazy::new(|| Regex::new(r"(?:⊲|<)\{([^}]+)\}").unwrap());

        let result = SECRETS_REGEX.replace_all(content, |caps: &regex::Captures| {
            let secret_name = &caps[1];

            match self.lookup_secret_via_fd(secret_name, rel_path) {
                Ok(value) => value,
                Err(_) => caps[0].to_string()
            }
        });

        Ok(result.to_string())
    }

    /// Lookup a secret using fd-based operations (avoids FUSE deadlock)
    fn lookup_secret_via_fd(&self, secret_name: &str, file_rel_path: &Path) -> Result<String> {
        // Find secrets file using fd-based operations
        let secrets_file = self.find_secrets_file_via_fd(file_rel_path)?;

        // Read secrets file content
        let secrets_content = self.read_file_via_fd(&secrets_file)?;
        let secrets_str = String::from_utf8(secrets_content)?;

        // Use the processor's built-in secrets parsing (handles encryption, multi-line values, etc.)
        // We need to decrypt AND remove all markers if it's encrypted
        let decrypted = if secrets_str.trim().starts_with("⊠{") {
            // Use decrypt_to_raw to fully remove markers, not just convert ⊠{} → ⊕{}
            self.processor.decrypt_to_raw(&secrets_str)?
        } else {
            secrets_str
        };

        // Parse using the robust parser from secrets.rs
        use crate::secrets::parse_secrets_content;
        // Need to convert relative path to absolute for parse_secrets_content
        let secrets_abs_path = self.source_path.join(&secrets_file);
        let secrets = parse_secrets_content(&decrypted, &secrets_abs_path)?;

        secrets.get(secret_name)
            .cloned()
            .ok_or_else(|| anyhow!("Secret '{}' not found in {:?}", secret_name, secrets_file))
    }

    /// Find secrets file using fd-based operations (matches behavior of SecretsCache::find_secrets_file)
    fn find_secrets_file_via_fd(&self, file_rel_path: &Path) -> Result<PathBuf> {
        let file_dir = file_rel_path.parent()
            .ok_or_else(|| anyhow!("Cannot determine parent directory"))?;

        // Strategy 1: Look for $filename.secrets in same directory
        let filename_with_suffix = PathBuf::from(format!("{}.secrets", file_rel_path.display()));
        if self.file_exists_via_fd(&filename_with_suffix) {
            return Ok(filename_with_suffix);
        }

        // Strategy 2: Search for 'secrets' file upward to project root
        // Start from file's directory and search upward
        let mut current_dir = file_dir.to_path_buf();

        loop {
            let secrets_path = current_dir.join("secrets");
            if self.file_exists_via_fd(&secrets_path) {
                return Ok(secrets_path);
            }

            // Move up one directory
            match current_dir.parent() {
                Some(parent) => {
                    // Parent of "subdir" is "", convert to "." for project root
                    let parent_path = if parent.as_os_str().is_empty() {
                        Path::new(".")
                    } else {
                        parent
                    };

                    // Check if we've already checked the project root
                    if current_dir == Path::new(".") {
                        break;
                    }

                    current_dir = parent_path.to_path_buf();
                },
                None => break,
            }
        }

        Err(anyhow!(
            "No secrets file found for {:?}. Searched: {}.secrets and 'secrets' up to project root.",
            file_rel_path,
            file_rel_path.display()
        ))
    }

    fn read_and_render(&self, path: &Path) -> Result<Vec<u8>> {
        self.read_and_process(path, |fs, content, rel_path| {
            // Process if file has any markers (sealed or opened)
            if has_any_markers(&content) {
                // First, interpolate secrets using fd-based operations (avoids deadlock)
                let content_with_secrets = fs.interpolate_secrets_via_fd(&content, rel_path)?;

                // Then decrypt and remove all markers
                fs.processor.decrypt_to_raw(&content_with_secrets)
            } else {
                // Return as-is for non-marked files
                Ok(content)
            }
        })
    }

    /// Read and open a file (decrypt ⊠{} → ⊕{} but keep markers for ssse edit)
    fn read_and_open(&self, path: &Path) -> Result<Vec<u8>> {
        self.read_and_process(path, |fs, content, _rel_path| {
            // Only process if file has encrypted markers
            if has_encrypted_markers(&content) {
                // Decrypt to opened form (⊠{} → ⊕{})
                fs.processor.decrypt_content(&content)
            } else {
                // Return as-is for non-encrypted files
                Ok(content)
            }
        })
    }

    /// Read sealed file (raw content with ⊠{} markers from backing store)
    /// This is used by .sss-sealed virtual paths for sss edit
    fn read_sealed(&self, path: &Path) -> Result<Vec<u8>> {
        // Get relative path from source root
        let rel_path = path.strip_prefix(&self.source_path)
            .unwrap_or(path);

        // Read raw file via fd - no processing!
        let bytes = self.read_file_via_fd(rel_path)?;
        Ok(bytes)
    }

    /// Write rendered content back (with smart reconstruction and sealing)
    /// Check if a file should be processed by sss encryption
    /// Files like swap files, temp files, etc. should be written through directly
    fn should_process_with_sss(path: &Path) -> bool {
        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            // Skip vim swap files and temporary files
            if name.starts_with('.') && (name.ends_with(".swp") || name.ends_with(".swo") ||
                                         name.ends_with(".swn") || name.ends_with(".tmp")) {
                return false;
            }
            // Skip other temporary file patterns
            if name.ends_with('~') || name.starts_with("#") || name.ends_with("#") {
                return false;
            }
        }
        true
    }

    /// Write raw content directly to backing store (no sss processing)
    fn write_raw_to_backing(&self, path: &Path, content: &[u8]) -> Result<()> {
        let rel_path = path.strip_prefix(&self.source_path).unwrap_or(path);
        let path_cstr = CString::new(rel_path.as_os_str().as_bytes())?;

        // Write directly via fd
        let fd = unsafe {
            libc::openat(
                self.source_fd,
                path_cstr.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC,
                0o600,
            )
        };

        if fd < 0 {
            return Err(anyhow!("Failed to open file for writing"));
        }

        let write_result = unsafe {
            let bytes_written = libc::write(
                fd,
                content.as_ptr() as *const _,
                content.len(),
            );
            libc::close(fd);
            bytes_written
        };

        if write_result < 0 || write_result != content.len() as isize {
            return Err(anyhow!("Failed to write content"));
        }

        Ok(())
    }

    /// Creates a temporary file path for atomic write operations
    fn create_temp_file_path(&self, rel_path: &Path) -> Result<(PathBuf, CString)> {
        let temp_name = format!(".{}.tmp", rel_path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unnamed"));
        let temp_rel_path = rel_path.parent()
            .unwrap_or_else(|| Path::new("."))
            .join(&temp_name);
        let temp_path_cstr = CString::new(temp_rel_path.as_os_str().as_bytes())?;
        Ok((temp_rel_path, temp_path_cstr))
    }

    /// Atomically writes content via file descriptor using temp file + rename pattern
    fn write_via_fd_atomic(&self, rel_path: &Path, content: &str) -> Result<()> {
        let path_cstr = CString::new(rel_path.as_os_str().as_bytes())?;
        let (_temp_path, temp_path_cstr) = self.create_temp_file_path(rel_path)?;

        // Write to temp file
        let temp_fd = unsafe {
            libc::openat(
                self.source_fd,
                temp_path_cstr.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC,
                0o600,
            )
        };

        if temp_fd < 0 {
            return Err(anyhow!("Failed to create temp file"));
        }

        let write_result = unsafe {
            let bytes_written = libc::write(
                temp_fd,
                content.as_ptr() as *const _,
                content.len(),
            );
            libc::close(temp_fd);
            bytes_written
        };

        if write_result < 0 || write_result != content.len() as isize {
            // Clean up temp file
            unsafe {
                libc::unlinkat(self.source_fd, temp_path_cstr.as_ptr(), 0);
            }
            return Err(anyhow!("Failed to write content"));
        }

        // Atomically rename temp to target
        let result = unsafe {
            libc::renameat(
                self.source_fd,
                temp_path_cstr.as_ptr(),
                self.source_fd,
                path_cstr.as_ptr(),
            )
        };

        if result < 0 {
            // Clean up temp file
            unsafe {
                libc::unlinkat(self.source_fd, temp_path_cstr.as_ptr(), 0);
            }
            return Err(anyhow!("Failed to rename temp file"));
        }

        Ok(())
    }

    /// Write opened content (with ⊕{} markers) directly to backing store
    /// This is used for opened_mode writes where content already has markers
    fn write_sealed_to_backing(&self, path: &Path, opened_content: &[u8]) -> Result<()> {
        // Convert bytes to string
        let opened_str = String::from_utf8(opened_content.to_vec())
            .map_err(|_| anyhow!("Content is not valid UTF-8"))?;

        // Seal the opened content (⊕{} → ⊠{})
        let sealed_content = self.processor.encrypt_content(&opened_str)?;

        // Write to backing store via file descriptor
        let rel_path = path.strip_prefix(&self.source_path).unwrap_or(path);
        self.write_via_fd_atomic(rel_path, &sealed_content)
    }

    /// Gets current sealed content from parameter or backing store
    fn get_current_sealed_content(&self, path: &Path, original_sealed: Option<&String>) -> Result<Option<String>> {
        if let Some(original) = original_sealed {
            return Ok(Some(original.clone()));
        }

        // Read current sealed version FROM BACKING STORE (not through FUSE!)
        let rel_path = path.strip_prefix(&self.source_path).unwrap_or(path);
        match self.read_file_via_fd(rel_path) {
            Ok(content) => {
                let sealed = String::from_utf8(content)
                    .map_err(|_| anyhow!("Backing file is not valid UTF-8"))?;
                Ok(Some(sealed))
            }
            Err(_) => Ok(None), // File doesn't exist or can't be read
        }
    }

    /// Performs smart reconstruction using marker inference
    fn perform_smart_reconstruction(&self, path: &Path, sealed_current: &str, rendered_str: &str) -> Result<String> {
        // Open (decrypt/open) current version to get content with markers
        let opened_current = self.processor.decrypt_content(sealed_current)?;

        // Use intelligent marker inference to reconstruct markers
        let inference_result = crate::marker_inference::infer_markers(&opened_current, rendered_str)
            .map_err(|e| anyhow!("Marker inference failed: {}", e))?;

        // Log any warnings from marker inference
        if !inference_result.warnings.is_empty() {
            eprintln!("Marker inference warnings for {:?}:", path);
            for warning in &inference_result.warnings {
                eprintln!("  - {}", warning);
            }
        }

        Ok(inference_result.output)
    }

    fn write_and_seal(&self, path: &Path, rendered_content: &[u8], original_sealed: Option<&String>) -> Result<()> {
        // Convert bytes to string
        let rendered_str = String::from_utf8(rendered_content.to_vec())
            .map_err(|_| anyhow!("Content is not valid UTF-8"))?;

        // Get current sealed version
        let sealed_current = match self.get_current_sealed_content(path, original_sealed)? {
            Some(content) => content,
            None => return self.write_raw_to_backing(path, rendered_content), // New file, write as-is
        };

        // Check if new content has plaintext markers
        let new_has_plaintext_markers = rendered_str.contains("⊕{") || rendered_str.contains("o+{");

        // Simple case: no markers in either version
        if !has_any_markers(&sealed_current) && !new_has_plaintext_markers {
            return self.write_raw_to_backing(path, rendered_content);
        }

        // Normalize case: no current markers but new has plaintext markers
        if !has_any_markers(&sealed_current) && new_has_plaintext_markers {
            let normalized = rendered_str.replace("o+{", "⊕{");
            return self.write_raw_to_backing(path, normalized.as_bytes());
        }

        // Smart reconstruction: use marker inference to preserve marker placement
        let reconstructed = self.perform_smart_reconstruction(path, &sealed_current, &rendered_str)?;
        self.write_raw_to_backing(path, reconstructed.as_bytes())
    }


    /// Internal lookup implementation that returns Result
    fn lookup_impl(&mut self, parent: u64, name: &OsStr) -> Result<(u64, FileAttr)> {
        // Handle .overlay synthetic directory
        let parent_entry = if parent == SYNTHETIC_OVERLAY_DIR_INO {
            InodeEntry {
                _ino: SYNTHETIC_OVERLAY_DIR_INO,
                path: PathBuf::from("/.overlay"),
                parent: ROOT_INO,
            }
        } else {
            self.get_inode(parent)
                .ok_or_else(|| anyhow!("Parent inode not found"))?
        };

        // Construct virtual path for the file
        let virtual_path = parent_entry.path.join(name);

        // Use translate_virtual_to_source to properly handle .overlay/ paths
        let (source_rel_path, pinned) = self.translate_virtual_to_source(&virtual_path);

        // Hide git-related files from FUSE view (but not in .overlay passthrough)
        if pinned.virtual_prefix != Path::new("/.overlay")
            && let Some(name_str) = name.to_str()
                && Self::should_hide(name_str) {
                    return Err(anyhow!("File hidden"));
                }

        let rel_path = if source_rel_path.as_os_str().is_empty() {
            Path::new(".")
        } else {
            &source_rel_path
        };

        let metadata = self.metadata_via_fd(rel_path)?;

        // Get or create inode
        let ino = self.get_or_create_inode(&virtual_path, parent);
        let attr = self.metadata_to_attr(ino, &metadata, None, false);

        Ok((ino, attr))
    }

    /// Parse virtual file name and determine file mode
    /// Returns (actual_name, file_mode)
    fn parse_virtual_file_mode(name: &OsStr) -> (&OsStr, FileMode) {
        if let Some(name_str) = name.to_str() {
            if let Some(actual) = name_str.strip_suffix(".sss-sealed") {
                (std::ffi::OsStr::new(actual), FileMode::Sealed)
            } else if let Some(actual) = name_str.strip_suffix(".sss-opened") {
                (std::ffi::OsStr::new(actual), FileMode::Opened)
            } else {
                (name, FileMode::Rendered)
            }
        } else {
            (name, FileMode::Rendered)
        }
    }

    /// Strip virtual suffix (.sss-opened) from path if present
    fn strip_virtual_suffix(path: &Path, is_opened_mode: bool) -> PathBuf {
        if is_opened_mode {
            let path_str = path.to_string_lossy();
            if let Some(stripped) = path_str.strip_suffix(".sss-opened") {
                PathBuf::from(stripped)
            } else {
                path.to_path_buf()
            }
        } else {
            path.to_path_buf()
        }
    }

    /// Pre-cache file content based on mode flags
    fn precache_for_open(&self, file_path: &Path, is_sealed_mode: bool, is_opened_mode: bool, writable: bool) -> Option<Vec<u8>> {
        if is_sealed_mode {
            // Sealed mode: pre-cache raw sealed content with ⊠{} markers
            self.read_sealed(file_path).ok()
        } else if is_opened_mode {
            // Opened mode: pre-cache with ⊕{} markers
            self.read_and_open(file_path).ok()
        } else if !writable {
            // Read-only: pre-render normally
            self.read_and_render(file_path).ok()
        } else {
            // Writable non-opened mode: no pre-cache
            None
        }
    }

    /// Get content for file handle based on its mode
    fn get_handle_content(&self, handle: &FileHandle) -> Result<Vec<u8>> {
        if handle.opened_mode {
            // Opened mode: return content with ⊕{} markers
            self.read_and_open(&handle.path)
        } else if let Some(ref cached) = handle.cached_content {
            // Use cached content
            Ok(cached.clone())
        } else {
            // Render normally
            self.read_and_render(&handle.path)
        }
    }

    /// Open directory via file descriptor (safe wrapper around openat/fdopendir)
    fn open_dir_fd(&self, rel_path: &Path) -> Result<*mut libc::DIR> {
        use std::os::unix::ffi::OsStrExt;

        // macOS has issues with fdopendir() in FUSE contexts - it can hang
        // Use direct opendir() with absolute path instead
        #[cfg(target_os = "macos")]
        {
            let full_path = self.source_path.join(rel_path);
            let path_cstr = std::ffi::CString::new(full_path.as_os_str().as_bytes())
                .map_err(|_| anyhow!("Invalid path for CString"))?;

            let dir_ptr = unsafe { libc::opendir(path_cstr.as_ptr()) };
            if dir_ptr.is_null() {
                return Err(anyhow!("opendir failed: {}", std::io::Error::last_os_error()));
            }

            return Ok(dir_ptr);
        }

        // Linux: use openat + fdopendir for proper FD-relative operations
        #[cfg(target_os = "linux")]
        {
            let path_bytes = rel_path.as_os_str().as_bytes();
            let path_cstr = std::ffi::CString::new(path_bytes)
                .map_err(|_| anyhow!("Invalid path for CString"))?;

            let dir_fd = unsafe {
                libc::openat(self.source_fd, path_cstr.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY)
            };

            if dir_fd < 0 {
                return Err(anyhow!("openat failed: {}", std::io::Error::last_os_error()));
            }

            let dir_ptr = unsafe { libc::fdopendir(dir_fd) };
            if dir_ptr.is_null() {
                unsafe { libc::close(dir_fd); }
                return Err(anyhow!("fdopendir failed"));
            }

            Ok(dir_ptr)
        }
    }

    /// Read all entries from an open directory using pinned path operations
    fn read_dir_entries_with_operations(&mut self, dir_ptr: *mut libc::DIR, parent_ino: u64, parent_path: &Path, operations: &dyn FileOperations)
        -> Vec<(u64, FileType, String)> {
        fuse_debug!("    read_dir_entries: starting, parent_path={:?}", parent_path);
        let mut items = Vec::new();
        let mut count = 0;

        unsafe {
            fuse_debug!("    read_dir_entries: entering readdir loop");
            loop {
                // Reset errno before readdir
                #[cfg(target_os = "linux")]
                { *libc::__errno_location() = 0; }
                #[cfg(target_os = "macos")]
                { *libc::__error() = 0; }

                fuse_debug!("    read_dir_entries: calling libc::readdir (iteration {})", count);
                let entry_ptr = libc::readdir(dir_ptr);
                fuse_debug!("    read_dir_entries: readdir returned {:p}", entry_ptr);

                if entry_ptr.is_null() {
                    fuse_debug!("    read_dir_entries: readdir returned null, breaking");
                    break;
                }

                let dirent = &*entry_ptr;
                let name = std::ffi::CStr::from_ptr(dirent.d_name.as_ptr())
                    .to_string_lossy()
                    .to_string();

                fuse_debug!("    read_dir_entries: got entry '{}'", name);

                // Skip . and ..
                if name == "." || name == ".." {
                    fuse_debug!("    read_dir_entries: skipping '{}' (dot entry)", name);
                    continue;
                }

                // Use operations from pinned path for hiding logic
                if operations.should_hide(&name) {
                    fuse_debug!("    read_dir_entries: hiding '{}'", name);
                    continue;
                }

                let virtual_path = parent_path.join(&name);
                let child_ino = self.get_or_create_inode(&virtual_path, parent_ino);

                let file_type = if dirent.d_type == libc::DT_DIR {
                    FileType::Directory
                } else {
                    FileType::RegularFile
                };

                fuse_debug!("    read_dir_entries: adding '{}' (ino={}, type={:?})", name, child_ino, file_type);
                items.push((child_ino, file_type, name));
                count += 1;
            }
        }

        fuse_debug!("    read_dir_entries: done, found {} items", items.len());
        items
    }

    /// Compute size override for cached/rendered content
    /// Checks file handles first, then falls back to render cache
    fn compute_size_override(&self, ino: u64, metadata: &fs::Metadata) -> Option<u64> {
        if !metadata.is_file() {
            return None;
        }

        // Check file handles for cached content
        let handles = self.file_handles.read();
        let handle_size = handles.values()
            .find(|h| h.ino == ino && h.cached_content.is_some())
            .and_then(|h| h.cached_content.as_ref())
            .map(|content| content.len() as u64);

        if handle_size.is_some() {
            handle_size
        } else {
            // Fallback to render cache
            let cache = self.render_cache.read();
            cache.get(&ino).map(|content| content.len() as u64)
        }
    }

    /// Resolve entry path to relative path suitable for fd operations
    /// Handles prefix stripping and empty path conversion to "."
    fn resolve_rel_path(&self, entry_path: &Path) -> std::borrow::Cow<'static, Path> {
        // Use translate_virtual_to_source to properly handle .overlay/ paths
        let (source_rel_path, _pinned) = self.translate_virtual_to_source(entry_path);

        
        if source_rel_path.as_os_str().is_empty() {
            std::borrow::Cow::Borrowed(Path::new("."))
        } else {
            std::borrow::Cow::Owned(source_rel_path)
        }
    }
}

impl Filesystem for SssFS {
    /// Initialize filesystem - called when FUSE connection is established
    fn init(
        &mut self,
        _req: &Request<'_>,
        _config: &mut fuser::KernelConfig,
    ) -> Result<(), libc::c_int> {
        fuse_debug!("========== FUSE INIT CALLED ==========");
        fuse_debug!("FUSE filesystem initialization starting");
        fuse_debug!("Source path: {:?}", self.source_path);
        fuse_debug!("Source FD: {}", self.source_fd);
        fuse_debug!("Mount FD: {:?}", self.mount_fd);
        fuse_debug!("UID: {}, GID: {}", self.uid, self.gid);
        fuse_debug!("Pinned paths count: {}", self.pinned_paths.len());

        for (idx, pinned) in self.pinned_paths.iter().enumerate() {
            fuse_debug!("  Pinned[{}]: {:?} -> {:?}", idx, pinned.virtual_prefix, pinned.source_path);
        }

        fuse_debug!("FUSE init completed successfully");
        fuse_debug!("========================================");
        Ok(())
    }

    /// Destroy filesystem - called when FUSE connection is terminated
    fn destroy(&mut self) {
        fuse_debug!("========== FUSE DESTROY CALLED ==========");
        fuse_debug!("FUSE filesystem cleanup starting");
        fuse_debug!("Open file handles: {}", self.file_handles.read().len());
        fuse_debug!("Allocated inodes: {}", self.inode_table.read().len());
        fuse_debug!("Render cache entries: {}", self.render_cache.read().len());
        fuse_debug!("FUSE filesystem cleanup completed");
        fuse_debug!("=========================================");
    }

    /// Get file attributes by inode
    fn getattr(&mut self, _req: &Request, ino: u64, reply: ReplyAttr) {
        let start = Instant::now();
        fuse_debug!("→ getattr(ino={})", ino);
        // Handle synthetic .overlay directory
        if ino == SYNTHETIC_OVERLAY_DIR_INO {
            fuse_debug!("  getattr: synthetic .overlay directory");
            // Get attributes from the actual source directory
            match self.metadata_via_fd(Path::new(".")) {
                Ok(metadata) => {
                    let attr = FileAttr {
                        ino: SYNTHETIC_OVERLAY_DIR_INO,
                        size: 0,
                        blocks: 0,
                        atime: metadata.accessed().unwrap_or(UNIX_EPOCH),
                        mtime: metadata.modified().unwrap_or(UNIX_EPOCH),
                        ctime: metadata.created().unwrap_or(UNIX_EPOCH),
                        crtime: metadata.created().unwrap_or(UNIX_EPOCH),
                        kind: FileType::Directory,
                        perm: 0o755,  // rwxr-xr-x
                        nlink: 2,
                        uid: self.uid,
                        gid: self.gid,
                        rdev: 0,
                        blksize: 512,
                        flags: 0,
                    };
                    fuse_debug!("← getattr(ino={}) = OK [{:.2?}]", ino, start.elapsed());
                    reply.attr(&TTL, &attr);
                }
                Err(e) => {
                    fuse_debug!("← getattr(ino={}) = EIO (metadata error: {}) [{:.2?}]", ino, e, start.elapsed());
                    reply.error(libc::EIO);
                }
            }
            return;
        }

        let entry = match self.get_inode(ino) {
            Some(e) => {
                fuse_debug!("  getattr: inode {} -> path {:?}", ino, e.path);
                e
            }
            None => {
                fuse_debug!("← getattr(ino={}) = ENOENT (inode not found) [{:.2?}]", ino, start.elapsed());
                reply.error(libc::ENOENT);
                return;
            }
        };

        fuse_debug!("  getattr: translating virtual to source path...");
        // Translate virtual path to source path using pinned paths
        let (source_rel_path, pinned) = self.translate_virtual_to_source(&entry.path);
        fuse_debug!("  getattr: source_rel_path={:?}", source_rel_path);

        fuse_debug!("  getattr: calling metadata_via_fd...");
        match self.metadata_via_fd(&source_rel_path) {
            Ok(metadata) => {
                fuse_debug!("  getattr: metadata_via_fd succeeded, is_file={}, is_dir={}", metadata.is_file(), metadata.is_dir());
                let is_passthrough = pinned.virtual_prefix == Path::new("/.overlay");
                fuse_debug!("  getattr: is_passthrough={}", is_passthrough);

                let _is_opened_mode = entry.path.to_str()
                    .map(|s| s.ends_with(".sss-opened"))
                    .unwrap_or(false);

                // Compute size override for rendered/opened modes (passthrough = no override)
                fuse_debug!("  getattr: computing size override...");
                let size_override = if is_passthrough {
                    None
                } else {
                    self.compute_size_override(ino, &metadata)
                };
                fuse_debug!("  getattr: size_override={:?}", size_override);

                fuse_debug!("  getattr: checking for secrets...");
                let has_secrets = metadata.is_file() && !is_passthrough &&
                    self.file_has_secrets(&source_rel_path);
                fuse_debug!("  getattr: has_secrets={}", has_secrets);

                // Use operations to get permissions
                let perm = pinned.operations.get_permissions(&metadata, has_secrets);

                // Build FileAttr
                let kind = if metadata.is_dir() {
                    FileType::Directory
                } else if metadata.is_symlink() {
                    FileType::Symlink
                } else {
                    FileType::RegularFile
                };

                let size = size_override.unwrap_or(metadata.len());

                let attr = FileAttr {
                    ino,
                    size,
                    blocks: size.div_ceil(512),
                    atime: metadata.accessed().unwrap_or(UNIX_EPOCH),
                    mtime: metadata.modified().unwrap_or(UNIX_EPOCH),
                    ctime: metadata.created().unwrap_or(UNIX_EPOCH),
                    crtime: metadata.created().unwrap_or(UNIX_EPOCH),
                    kind,
                    perm,
                    nlink: Self::get_nlink(&metadata) as u32,
                    uid: Self::get_uid(&metadata),
                    gid: Self::get_gid(&metadata),
                    rdev: 0,
                    blksize: 512,
                    flags: 0,
                };

                fuse_debug!("← getattr(ino={}) = OK (size={}) [{:.2?}]", ino, attr.size, start.elapsed());
                reply.attr(&TTL, &attr);
            }
            Err(e) => {
                fuse_debug!("← getattr(ino={}) = ENOENT (metadata error: {}) [{:.2?}]", ino, e, start.elapsed());
                reply.error(libc::ENOENT);
            }
        }
    }

    /// Lookup entry in directory
    fn lookup(&mut self, _req: &Request, parent: u64, name: &OsStr, reply: ReplyEntry) {
        let start = Instant::now();
        fuse_debug!("→ lookup(parent={}, name={:?})", parent, name);

        // Special case: looking up ".overlay" from root
        if parent == ROOT_INO && name == ".overlay" {
            fuse_debug!("  lookup: .overlay synthetic directory from root");
            let attr = FileAttr {
                ino: SYNTHETIC_OVERLAY_DIR_INO,
                size: 0,
                blocks: 0,
                atime: UNIX_EPOCH,
                mtime: UNIX_EPOCH,
                ctime: UNIX_EPOCH,
                crtime: UNIX_EPOCH,
                kind: FileType::Directory,
                perm: 0o755,
                nlink: 2,
                uid: self.uid,
                gid: self.gid,
                rdev: 0,
                blksize: 512,
                flags: 0,
            };
            fuse_debug!("← lookup(parent={}, name={:?}) = OK (synthetic .overlay) [{:.2?}]", parent, name, start.elapsed());
            reply.entry(&TTL, &attr, 0);
            return;
        }

        // Handle lookups within .overlay/ - parent is synthetic, build path manually
        let parent_entry = if parent == SYNTHETIC_OVERLAY_DIR_INO {
            // Parent is .overlay synthetic directory
            InodeEntry {
                _ino: SYNTHETIC_OVERLAY_DIR_INO,
                path: PathBuf::from("/.overlay"),
                parent: ROOT_INO,
            }
        } else {
            // Get parent entry from inode table
            match self.get_inode(parent) {
                Some(e) => e,
                None => {
                    reply.error(libc::ENOENT);
                    return;
                }
            }
        };


        // Parse virtual file mode (.sss-sealed, .sss-opened, or normal)
        let (actual_name, file_mode) = Self::parse_virtual_file_mode(name);
        let is_opened_mode = matches!(file_mode, FileMode::Opened);

        // Build virtual path
        let virtual_path = if is_opened_mode {
            parent_entry.path.join(name) // Keep .sss-opened suffix
        } else {
            parent_entry.path.join(actual_name)
        };


        // Translate to source path using pinned paths
        let (source_rel_path, pinned) = self.translate_virtual_to_source(&virtual_path);


        // Check if should hide (only for normal SSS paths, not passthrough)
        if pinned.virtual_prefix != Path::new("/.overlay")
            && let Some(name_str) = actual_name.to_str()
                && pinned.operations.should_hide(name_str) {
                    reply.error(libc::ENOENT);
                    return;
                }

        // Get metadata
        match self.metadata_via_fd(&source_rel_path) {
            Ok(metadata) => {
                let ino = self.get_or_create_inode(&virtual_path, parent);

                let is_passthrough = pinned.virtual_prefix == Path::new("/.overlay");

                let size_override = if is_passthrough || matches!(file_mode, FileMode::Sealed) {
                    None
                } else {
                    self.compute_size_override(ino, &metadata)
                };

                let has_secrets = metadata.is_file() && !is_passthrough &&
                    self.file_has_secrets(&source_rel_path);

                let perm = pinned.operations.get_permissions(&metadata, has_secrets);

                // Build FileAttr inline (same as getattr)
                let kind = if metadata.is_dir() {
                    FileType::Directory
                } else if metadata.is_symlink() {
                    FileType::Symlink
                } else {
                    FileType::RegularFile
                };

                let size = size_override.unwrap_or(metadata.len());

                let attr = FileAttr {
                    ino,
                    size,
                    blocks: size.div_ceil(512),
                    atime: metadata.accessed().unwrap_or(UNIX_EPOCH),
                    mtime: metadata.modified().unwrap_or(UNIX_EPOCH),
                    ctime: metadata.created().unwrap_or(UNIX_EPOCH),
                    crtime: metadata.created().unwrap_or(UNIX_EPOCH),
                    kind,
                    perm,
                    nlink: Self::get_nlink(&metadata) as u32,
                    uid: Self::get_uid(&metadata),
                    gid: Self::get_gid(&metadata),
                    rdev: 0,
                    blksize: 512,
                    flags: 0,
                };

                // Use zero TTL for passthrough files to disable kernel caching
                // This prevents stale negative lookups after rename operations
                let ttl = if is_passthrough { &TTL_ZERO } else { &TTL };
                fuse_debug!("← lookup(parent={}, name={:?}) = OK (ino={}, size={}) [{:.2?}]", parent, name, ino, attr.size, start.elapsed());
                reply.entry(ttl, &attr, 0);
            }
            Err(e) => {
                fuse_debug!("← lookup(parent={}, name={:?}) = ENOENT (metadata error: {}) [{:.2?}]", parent, name, e, start.elapsed());
                reply.error(libc::ENOENT);
            }
        }
    }

    /// Read directory contents
    fn readdir(
        &mut self,
        _req: &Request,
        ino: u64,
        _fh: u64,
        offset: i64,
        mut reply: ReplyDirectory,
    ) {
        let start = Instant::now();
        fuse_debug!("→ readdir(ino={}, offset={})", ino, offset);

        // Handle .overlay/ - parent is synthetic, build entry manually
        let entry = if ino == SYNTHETIC_OVERLAY_DIR_INO {
            fuse_debug!("  readdir: synthetic .overlay directory");
            InodeEntry {
                _ino: SYNTHETIC_OVERLAY_DIR_INO,
                path: PathBuf::from("/.overlay"),
                parent: ROOT_INO,
            }
        } else {
            // Get directory entry from inode table
            match self.get_inode(ino) {
                Some(e) => {
                    fuse_debug!("  readdir: inode {} -> path {:?}", ino, e.path);
                    e
                },
                None => {
                    fuse_debug!("  readdir: inode {} not found", ino);
                    reply.error(libc::ENOENT);
                    return;
                }
            }
        };

        fuse_debug!("  readdir: translating path {:?}", entry.path);
        // Translate virtual path to source path using pinned paths
        let (source_rel_path, pinned) = self.translate_virtual_to_source(&entry.path);
        fuse_debug!("  readdir: source_rel_path={:?}", source_rel_path);
        // Clone the operations Arc to avoid holding a borrow on self
        let operations = pinned.operations.clone();

        fuse_debug!("  readdir: opening directory via FD...");
        // Open directory via FD
        let dir_ptr = match self.open_dir_fd(&source_rel_path) {
            Ok(p) => {
                fuse_debug!("  readdir: directory opened successfully, dir_ptr={:p}", p);
                p
            },
            Err(e) => {
                fuse_debug!("  readdir: failed to open directory: {}", e);
                reply.error(libc::EIO);
                return;
            }
        };

        fuse_debug!("  readdir: building initial entry list");
        // Build entry list: . and .. first
        let mut items = vec![
            (ino, FileType::Directory, ".".to_string()),
            (entry.parent, FileType::Directory, "..".to_string()),
        ];

        fuse_debug!("  readdir: calling read_dir_entries_with_operations...");
        // Read directory entries - use pinned path operations for filtering
        let entries = self.read_dir_entries_with_operations(dir_ptr, ino, &entry.path, &*operations);
        fuse_debug!("  readdir: read {} entries from directory", entries.len());
        items.extend(entries);

        // If this is the root directory, add synthetic .overlay directory
        if ino == ROOT_INO {
            items.push((SYNTHETIC_OVERLAY_DIR_INO, FileType::Directory, ".overlay".to_string()));
        }

        // Close directory
        unsafe { libc::closedir(dir_ptr); }

        // Send entries to FUSE
        let entry_count = items.len();
        for (i, item) in items.iter().enumerate().skip(offset as usize) {
            if reply.add(item.0, (i + 1) as i64, item.1, &item.2) {
                break;
            }
        }

        fuse_debug!("← readdir(ino={}) = OK ({} entries) [{:.2?}]", ino, entry_count, start.elapsed());
        reply.ok();
    }

    /// Open a file
    fn open(&mut self, _req: &Request, ino: u64, flags: i32, reply: ReplyOpen) {
        let start = Instant::now();
        fuse_debug!("→ open(ino={}, flags=0x{:x})", ino, flags);

        // Block operations on .git blocking directory only
        if ino == SYNTHETIC_OVERLAY_DIR_INO {
            reply.error(libc::EISDIR);
            return;
        }

        let entry = match self.get_inode(ino) {
            Some(e) => e,
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };


        // Translate virtual path to source path using pinned paths
        let (source_rel_path, pinned) = self.translate_virtual_to_source(&entry.path);
        let is_passthrough = pinned.virtual_prefix == Path::new("/.overlay");


        // Determine file modes (not applicable for passthrough files)
        // Opened mode: detected by nonsense flag combination O_DIRECTORY|O_CREAT
        // (semantically invalid: can't create when opening as directory, so never used by real programs)
        let is_opened_mode = !is_passthrough &&
            (flags & libc::O_DIRECTORY) != 0 &&
            (flags & libc::O_CREAT) != 0;
        // Sealed mode: detected by nonsense flag combination O_RDONLY|O_TRUNC
        // (semantically invalid: can't truncate read-only file, so never used by real programs)
        let is_sealed_mode = !is_passthrough &&
            (flags & libc::O_ACCMODE) == libc::O_RDONLY &&
            (flags & libc::O_TRUNC) != 0;
        let writable = (flags & libc::O_RDWR) != 0 || (flags & libc::O_WRONLY) != 0;

        // Get full file path for handle
        let file_path = if is_passthrough {
            // Passthrough: use source path directly
            self.source_path.join(&source_rel_path)
        } else {
            // SSS mode: use translated source path and strip virtual suffix if opened mode
            let translated_path = self.source_path.join(&source_rel_path);
            Self::strip_virtual_suffix(&translated_path, is_opened_mode)
        };

        // Generate file handle
        let fh = {
            let mut next_fh = self.next_fh.write();
            let fh = *next_fh;
            *next_fh += 1;
            fh
        };

        // Pre-cache content based on mode (skip for passthrough - raw access)
        let cached_content = if is_passthrough {
            None
        } else {
            self.precache_for_open(&file_path, is_sealed_mode, is_opened_mode, writable)
        };

        // Capture original sealed content from backing store if file is writable
        // This is needed for smart reconstruction when editor truncates file before writing
        // Skip for passthrough files (raw, no markers)
        let original_sealed = if !is_passthrough && writable && !is_sealed_mode && !is_opened_mode {
            let rel_path = file_path.strip_prefix(&self.source_path).unwrap_or(&file_path);
            self.read_file_via_fd(rel_path)
                .ok()
                .and_then(|bytes| String::from_utf8(bytes).ok())
                .filter(|s| has_any_markers(s))
        } else {
            None
        };

        // Open file descriptor for passthrough files to avoid reopening on every operation
        let passthrough_fd = if is_passthrough && writable {
            // Build open flags for passthrough file
            let mut open_flags = if writable {
                if (flags & libc::O_RDWR) != 0 {
                    libc::O_RDWR
                } else {
                    libc::O_WRONLY
                }
            } else {
                libc::O_RDONLY
            };

            // Preserve important flags
            if (flags & libc::O_TRUNC) != 0 {
                open_flags |= libc::O_TRUNC;
            }
            if (flags & libc::O_CREAT) != 0 {
                open_flags |= libc::O_CREAT;
            }
            if (flags & libc::O_EXCL) != 0 {
                open_flags |= libc::O_EXCL;
            }

            // Open file via source_fd (with mode 0666 if creating)
            let path_cstr = match std::ffi::CString::new(source_rel_path.as_os_str().as_bytes()) {
                Ok(p) => p,
                Err(_) => {
                    reply.error(libc::EINVAL);
                    return;
                }
            };

            let fd = unsafe {
                if (open_flags & libc::O_CREAT) != 0 {
                    libc::openat(self.source_fd, path_cstr.as_ptr(), open_flags, 0o666)
                } else {
                    libc::openat(self.source_fd, path_cstr.as_ptr(), open_flags)
                }
            };

            if fd < 0 {
                let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(libc::EIO);
                reply.error(errno);
                return;
            }

            Some(fd)
        } else {
            None
        };

        // Store file handle
        let mut handle = FileHandle {
            ino,
            path: file_path.clone(),
            cached_content,
            writable,
            dirty: false,
            opened_mode: is_opened_mode,
            sealed_mode: is_sealed_mode,
            origin_mode: is_passthrough,  // Keep field name for now
            passthrough_fd,
            original_sealed,
        };

        // Handle O_TRUNC flag for writable non-passthrough files (but not sealed mode)
        // When a file is opened with O_TRUNC, it should be truncated to zero length immediately
        let should_truncate = !is_passthrough &&
                              writable &&
                              (flags & libc::O_TRUNC) != 0 &&
                              !is_sealed_mode;

        if should_truncate {
            // Truncate the file on disk immediately
            if std::fs::OpenOptions::new()
                .write(true)
                .truncate(true)
                .open(&file_path)
                .is_err()
            {
                reply.error(libc::EIO);
                return;
            }

            // Set cached content to empty since file is now truncated
            handle.cached_content = Some(Vec::new());
            handle.dirty = false;  // File is already truncated on disk
        }

        self.file_handles.write().insert(fh, handle);

        // For passthrough writable files, use FOPEN_DIRECT_IO to bypass page cache
        // This ensures mmap writes go through our handlers instead of kernel page cache
        let flags = if is_passthrough && writable {
            const FOPEN_DIRECT_IO: u32 = 1 << 0;  // From linux/fuse.h
            FOPEN_DIRECT_IO
        } else {
            0
        };

        fuse_debug!("← open(ino={}) = OK (fh={}) [{:.2?}]", ino, fh, start.elapsed());
        reply.opened(fh, flags);
    }

    /// Read file data
    fn read(
        &mut self,
        _req: &Request,
        ino: u64,
        fh: u64,
        offset: i64,
        size: u32,
        _flags: i32,
        _lock: Option<u64>,
        reply: ReplyData,
    ) {
        let start = Instant::now();
        fuse_debug!("→ read(ino={}, fh={}, offset={}, size={})", ino, fh, offset, size);

        // Get content from handle or fall back to direct read
        let handles = self.file_handles.read();
        let content = match handles.get(&fh) {
            Some(handle) => {
                // Origin mode: raw passthrough, read directly from file
                if handle.origin_mode {
                    let path = handle.path.clone();
                    drop(handles);
                    let rel_path = path.strip_prefix(&self.source_path).unwrap_or(&path);
                    match self.read_file_via_fd(rel_path) {
                        Ok(c) => c,
                        Err(_) => {
                            reply.error(libc::EIO);
                            return;
                        }
                    }
                } else if handle.sealed_mode && handle.cached_content.is_none() {
                    // Sealed mode pending: wait for setxattr confirmation
                    reply.error(libc::EAGAIN);
                    return;
                } else {
                    // Get content based on handle mode
                    match self.get_handle_content(handle) {
                        Ok(c) => c,
                        Err(_e) => {
                            reply.error(libc::EIO);
                            return;
                        }
                    }
                }
            }
            None => {
                drop(handles);

                let entry = match self.get_inode(ino) {
                    Some(e) => e,
                    None => {
                        reply.error(libc::ENOENT);
                        return;
                    }
                };

                // Use translate_virtual_to_source to properly handle .overlay/ paths
                let (source_rel_path, _pinned) = self.translate_virtual_to_source(&entry.path);
                let file_path = self.source_path.join(&source_rel_path);
                match self.read_and_render(&file_path) {
                    Ok(c) => c,
                    Err(_e) => {
                        reply.error(libc::EIO);
                        return;
                    }
                }
            }
        };

        // Return requested slice
        let offset_usize = offset as usize;
        let end = std::cmp::min(offset_usize + size as usize, content.len());

        if offset_usize < content.len() {
            let bytes_read = end - offset_usize;
            fuse_debug!("← read(ino={}, fh={}) = OK ({} bytes) [{:.2?}]", ino, fh, bytes_read, start.elapsed());
            reply.data(&content[offset_usize..end]);
        } else {
            fuse_debug!("← read(ino={}, fh={}) = OK (0 bytes, EOF) [{:.2?}]", ino, fh, start.elapsed());
            reply.data(&[]);
        }
    }

    /// Write file data
    fn write(
        &mut self,
        _req: &Request,
        ino: u64,
        fh: u64,
        offset: i64,
        data: &[u8],
        _write_flags: u32,
        _flags: i32,
        _lock: Option<u64>,
        reply: ReplyWrite,
    ) {
        let start = Instant::now();
        fuse_debug!("→ write(ino={}, fh={}, offset={}, size={})", ino, fh, offset, data.len());
        // Block writes to .git blocking directory only
        if ino == SYNTHETIC_OVERLAY_DIR_INO {
            reply.error(libc::EPERM);
            return;
        }

        let mut handles = self.file_handles.write();
        let handle = match handles.get_mut(&fh) {
            Some(h) => h,
            None => {
                reply.error(libc::EBADF);
                return;
            }
        };

        if !handle.writable {
            reply.error(libc::EBADF);
            return;
        }

        // Block writes to .git/* at project root (unless in origin_mode passthrough via .overlay/)
        if !handle.origin_mode
            && let Ok(rel_path) = handle.path.strip_prefix(&self.source_path) {
                let path_str = rel_path.to_string_lossy();
                if path_str.starts_with(".git/") || path_str == ".git" {
                    reply.error(libc::EPERM);
                    return;
                }
            }

        // For passthrough files (origin_mode), write directly to disk without caching
        // Use the stored fd to avoid reopening on every write (which fixes race conditions)
        if handle.origin_mode {
            let fd = match handle.passthrough_fd {
                Some(fd) => fd,
                None => {
                    reply.error(libc::EIO);
                    return;
                }
            };

            // Use pwrite() for atomic seek+write operation
            // Note: pwrite() may do partial writes, but FUSE handles retries,
            // so we just report how many bytes were actually written
            let bytes_written = unsafe {
                libc::pwrite(
                    fd,
                    data.as_ptr() as *const libc::c_void,
                    data.len(),
                    offset,
                )
            };

            if bytes_written < 0 {
                let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(libc::EIO);
                reply.error(errno);
                return;
            }

            if bytes_written == 0 && !data.is_empty() {
                reply.error(libc::EIO);
                return;
            }

            reply.written(bytes_written as u32);
            return;
        }

        // Non-passthrough files: use caching (for SSS processing)

        // Initialize or extend cached content
        let mut content = handle.cached_content.take().unwrap_or_else(Vec::new);

        // Ensure content is large enough
        let end_offset = offset as usize + data.len();
        if content.len() < end_offset {
            content.resize(end_offset, 0);
        }

        // Write data at offset
        content[offset as usize..end_offset].copy_from_slice(data);

        handle.cached_content = Some(content);
        handle.dirty = true;

        fuse_debug!("← write(ino={}, fh={}) = OK ({} bytes) [{:.2?}]", ino, fh, data.len(), start.elapsed());
        reply.written(data.len() as u32);
    }

    /// Release (close) file
    fn release(
        &mut self,
        _req: &Request,
        _ino: u64,
        fh: u64,
        _flags: i32,
        _lock_owner: Option<u64>,
        _flush: bool,
        reply: fuser::ReplyEmpty,
    ) {
        let start = Instant::now();
        fuse_debug!("→ release(fh={})", fh);
        let mut handles = self.file_handles.write();
        if let Some(handle) = handles.remove(&fh) {
            // Close passthrough fd if present
            if let Some(fd) = handle.passthrough_fd {
                unsafe {
                    libc::close(fd);
                }
            }

            // If file was written to, seal and write back
            if handle.dirty && handle.writable
                && let Some(content) = handle.cached_content {
                    // Check if this is an origin file (raw passthrough)
                    let write_result = if handle.origin_mode {
                        // Origin mode: write raw without any SSS processing
                        self.write_raw_to_backing(&handle.path, &content)
                    } else {
                        // Normal SSS processing
                        let content_str = String::from_utf8_lossy(&content);

                        // Check if content already has encrypted markers (⊠{})
                        let is_already_sealed = has_encrypted_markers(&content_str);

                        // Check if this file should be processed by sss or written raw
                        if !Self::should_process_with_sss(&handle.path) {
                            // Swap files and temp files: write raw (no sss processing)
                            self.write_raw_to_backing(&handle.path, &content)
                        } else if handle.sealed_mode {
                            // Sealed mode: content is already sealed (⊠{}), write raw to backing store
                            self.write_raw_to_backing(&handle.path, &content)
                        } else if is_already_sealed {
                            // Content already has ⊠{} markers - write directly (no processing)
                            self.write_raw_to_backing(&handle.path, &content)
                        } else if handle.opened_mode {
                            // Opened mode: content has ⊕{} markers, seal directly
                            self.write_sealed_to_backing(&handle.path, &content)
                        } else {
                            // Normal mode: content is rendered, do smart reconstruction
                            // Pass original_sealed if we have it (prevents marker loss when editor truncates)
                            self.write_and_seal(&handle.path, &content, handle.original_sealed.as_ref())
                        }
                    };

                    if let Err(e) = write_result {
                        eprintln!("Error writing file on close: {}", e);
                        reply.error(libc::EIO);
                        return;
                    }

                    // Invalidate render cache
                    self.render_cache.write().remove(&handle.ino);
                }
        }
        fuse_debug!("← release(fh={}) = OK [{:.2?}]", fh, start.elapsed());
        reply.ok();
    }

    /// Handle ioctl commands
    ///
    /// Note: ioctl is not supported on macOS with fuse-t. Use virtual file suffixes instead:
    /// - file.txt.sss-opened → opened mode (⊕{} markers)
    /// - file.txt.sss-sealed → sealed mode (⊠{} markers)
    fn ioctl(
        &mut self,
        _req: &Request,
        _ino: u64,
        fh: u64,
        _flags: u32,
        cmd: u32,
        _in_data: &[u8],
        _out_size: u32,
        reply: fuser::ReplyIoctl,
    ) {
        fuse_debug!("→ ioctl(fh={}, cmd=0x{:x})", fh, cmd);

        // fuse-t on macOS doesn't support ioctl operations
        // Users should use virtual file suffixes instead:
        //   file.txt.sss-opened for opened mode
        //   file.txt.sss-sealed for sealed mode
        #[cfg(target_os = "macos")]
        {
            fuse_debug!("← ioctl(fh={}) = ENOTTY (ioctl not supported on macOS/fuse-t)", fh);
            fuse_debug!("   Use virtual suffixes instead: .sss-opened or .sss-sealed");
            reply.error(libc::ENOTTY);
        }

        #[cfg(not(target_os = "macos"))]
        {
            if cmd == SSS_IOC_OPENED_MODE {
                // Enable opened mode for this file handle
                let mut handles = self.file_handles.write();
                if let Some(handle) = handles.get_mut(&fh) {
                    handle.opened_mode = true;
                    // Clear cached content - need to re-read with markers
                    handle.cached_content = None;
                    reply.ioctl(0, &[]);
                } else {
                    reply.error(libc::EBADF);
                }
            } else if cmd == SSS_IOC_SEALED_MODE {
                // Enable sealed mode - requires O_NONBLOCK was used
                let mut handles = self.file_handles.write();
                if let Some(handle) = handles.get_mut(&fh) {
                    if !handle.sealed_mode {
                        reply.error(libc::EINVAL);
                        return;
                    }

                    // O_NONBLOCK was used, now cache sealed content
                    match self.read_sealed(&handle.path) {
                        Ok(content) => {
                            handle.cached_content = Some(content);
                            reply.ioctl(0, &[]);
                        }
                        Err(_e) => {
                            reply.error(libc::EIO);
                        }
                    }
                } else {
                    reply.error(libc::EBADF);
                }
            } else {
                fuse_debug!("← ioctl(fh={}) = ENOTTY (unknown command)", fh);
                reply.error(libc::ENOTTY);
            }
        }
    }

    /// Set file attributes (permissions, timestamps, etc.)
    fn setattr(
        &mut self,
        _req: &Request,
        ino: u64,
        mode: Option<u32>,
        _uid: Option<u32>,
        _gid: Option<u32>,
        size: Option<u64>,
        _atime: Option<fuser::TimeOrNow>,
        _mtime: Option<fuser::TimeOrNow>,
        _ctime: Option<std::time::SystemTime>,
        _fh: Option<u64>,
        _crtime: Option<std::time::SystemTime>,
        _chgtime: Option<std::time::SystemTime>,
        _bkuptime: Option<std::time::SystemTime>,
        _flags: Option<u32>,
        reply: ReplyAttr,
    ) {
        // Handle .overlay synthetic directory - return current attributes
        if ino == SYNTHETIC_OVERLAY_DIR_INO {
            match self.metadata_via_fd(Path::new(".")) {
                Ok(metadata) => {
                    let attr = FileAttr {
                        ino: SYNTHETIC_OVERLAY_DIR_INO,
                        size: 0,
                        blocks: 0,
                        atime: metadata.accessed().unwrap_or(UNIX_EPOCH),
                        mtime: metadata.modified().unwrap_or(UNIX_EPOCH),
                        ctime: metadata.created().unwrap_or(UNIX_EPOCH),
                        crtime: metadata.created().unwrap_or(UNIX_EPOCH),
                        kind: FileType::Directory,
                        perm: 0o755,
                        nlink: 2,
                        uid: self.uid,
                        gid: self.gid,
                        rdev: 0,
                        blksize: 512,
                        flags: 0,
                    };
                    reply.attr(&TTL, &attr);
                }
                Err(_) => {
                    reply.error(libc::EIO);
                }
            }
            return;
        }

        let entry = match self.get_inode(ino) {
            Some(e) => e,
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        let rel_path = self.resolve_rel_path(&entry.path);

        // Handle truncate (size change)
        if let Some(new_size) = size {
            let path_cstr = match CString::new(rel_path.as_os_str().as_bytes()) {
                Ok(p) => p,
                Err(_) => {
                    reply.error(libc::EINVAL);
                    return;
                }
            };

            // Open file and truncate via fd
            let fd = unsafe {
                libc::openat(
                    self.source_fd,
                    path_cstr.as_ptr(),
                    libc::O_WRONLY,
                )
            };

            if fd < 0 {
                reply.error(libc::EIO);
                return;
            }

            let result = unsafe { libc::ftruncate(fd, new_size as i64) };
            unsafe { libc::close(fd) };

            if result != 0 {
                reply.error(libc::EIO);
                return;
            }

            // Clear render cache for this file
            self.render_cache.write().remove(&ino);

            // IMPORTANT: Clear cached_content in any open file handles for this inode
            // to prevent stale data from being written back on close
            let mut handles = self.file_handles.write();
            for handle in handles.values_mut() {
                if handle.ino == ino {
                    if new_size == 0 {
                        // Truncate to zero - clear all cached content
                        handle.cached_content = None;
                    } else if let Some(ref mut content) = handle.cached_content {
                        // Truncate to specific size
                        content.truncate(new_size as usize);
                    }
                }
            }
        }

        // Handle mode change
        if let Some(new_mode) = mode {
            let path_cstr = match CString::new(rel_path.as_os_str().as_bytes()) {
                Ok(p) => p,
                Err(_) => {
                    reply.error(libc::EINVAL);
                    return;
                }
            };

            let result = unsafe {
                libc::fchmodat(
                    self.source_fd,
                    path_cstr.as_ptr(),
                    new_mode as libc::mode_t,
                    0,
                )
            };

            if result != 0 {
                reply.error(libc::EIO);
                return;
            }
        }

        // Return updated attributes
        match self.metadata_via_fd(&rel_path) {
            Ok(metadata) => {
                let is_opened_mode = entry.path.to_str()
                    .map(|s| s.ends_with(".sss-opened"))
                    .unwrap_or(false);

                let size_override = self.compute_size_override(ino, &metadata);
                let attr = self.metadata_to_attr(ino, &metadata, size_override, is_opened_mode);
                reply.attr(&TTL, &attr);
            }
            Err(_) => reply.error(libc::EIO),
        }
    }

    /// Sync file content (flush writes)
    fn fsync(
        &mut self,
        _req: &Request,
        _ino: u64,
        fh: u64,
        datasync: bool,
        reply: fuser::ReplyEmpty,
    ) {
        let start = Instant::now();
        fuse_debug!("→ fsync(fh={}, datasync={})", fh, datasync);

        // For passthrough files with an fd, sync to flush mmap writes
        let handles = self.file_handles.read();
        if let Some(handle) = handles.get(&fh)
            && let Some(fd) = handle.passthrough_fd {
                let result = if datasync {
                    // macOS doesn't have fdatasync, use fsync or F_FULLFSYNC
                    #[cfg(target_os = "linux")]
                    unsafe { libc::fdatasync(fd) }
                    #[cfg(target_os = "macos")]
                    unsafe { libc::fsync(fd) }
                } else {
                    unsafe { libc::fsync(fd) }
                };

                if result < 0 {
                    let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(libc::EIO);
                    fuse_debug!("← fsync(fh={}) = error (errno={}) [{:.2?}]", fh, errno, start.elapsed());
                    reply.error(errno);
                    return;
                }
            }

        fuse_debug!("← fsync(fh={}) = OK [{:.2?}]", fh, start.elapsed());
        reply.ok();
    }

    /// Check file access permissions
    fn access(&mut self, _req: &Request, ino: u64, mask: i32, reply: fuser::ReplyEmpty) {
        let start = Instant::now();
        fuse_debug!("→ access(ino={}, mask=0x{:x})", ino, mask);

        // Handle synthetic directories
        if ino == SYNTHETIC_OVERLAY_DIR_INO {
            fuse_debug!("  access: synthetic overlay dir, returning OK");
            reply.ok();
            return;
        }

        // On macOS, faccessat() can deadlock when called from within FUSE handlers
        // because it may try to access through the FUSE mount itself.
        // Since actual permission checks happen at open/read/write time anyway,
        // we can safely return OK here.
        #[cfg(target_os = "macos")]
        {
            fuse_debug!("← access(ino={}) = OK (macOS: skipping faccessat) [{:.2?}]", ino, start.elapsed());
            reply.ok();
            return;
        }

        #[cfg(not(target_os = "macos"))]
        {
            fuse_debug!("  access: getting inode entry...");
            let entry = match self.get_inode(ino) {
                Some(e) => {
                    fuse_debug!("  access: got inode entry, path={:?}", e.path);
                    e
                }
                None => {
                    fuse_debug!("  access: inode not found, returning ENOENT");
                    reply.error(libc::ENOENT);
                    return;
                }
            };

            fuse_debug!("  access: translating virtual path...");
            // Translate virtual path to source path
            let (source_rel_path, _pinned) = self.translate_virtual_to_source(&entry.path);
            fuse_debug!("  access: source_rel_path={:?}", source_rel_path);

            fuse_debug!("  access: creating CString...");
            // Use faccessat to check actual permissions
            let path_cstr = match CString::new(source_rel_path.as_os_str().as_bytes()) {
                Ok(p) => p,
                Err(_) => {
                    fuse_debug!("  access: CString error, returning EINVAL");
                    reply.error(libc::EINVAL);
                    return;
                }
            };

            fuse_debug!("  access: calling faccessat(fd={}, path={:?}, mask=0x{:x})...",
                       self.source_fd, source_rel_path, mask);
            // faccessat checks access permissions relative to source_fd
            let result = unsafe {
                libc::faccessat(
                    self.source_fd,
                    path_cstr.as_ptr(),
                    mask,
                    0, // flags
                )
            };
            fuse_debug!("  access: faccessat returned {}", result);

            if result == 0 {
                fuse_debug!("← access(ino={}) = OK [{:.2?}]", ino, start.elapsed());
                reply.ok();
            } else {
                let errno = unsafe {
                    #[cfg(target_os = "linux")]
                    { *libc::__errno_location() }
                    #[cfg(target_os = "macos")]
                    { *libc::__error() }
                };
                fuse_debug!("← access(ino={}) = errno {} [{:.2?}]", ino, errno, start.elapsed());
                reply.error(errno);
            }
        }
    }

    /// Flush data before close
    fn flush(
        &mut self,
        _req: &Request,
        _ino: u64,
        fh: u64,
        _lock_owner: u64,
        reply: fuser::ReplyEmpty,
    ) {
        let start = Instant::now();
        fuse_debug!("→ flush(fh={})", fh);

        // For passthrough files, sync to flush any mmap'd writes
        let handles = self.file_handles.read();
        if let Some(handle) = handles.get(&fh) {
            if let Some(fd) = handle.passthrough_fd {
                // Use fdatasync for better performance (only data, not metadata)
                // macOS doesn't have fdatasync, use fsync instead
                #[cfg(target_os = "linux")]
                let result = unsafe { libc::fdatasync(fd) };
                #[cfg(target_os = "macos")]
                let result = unsafe { libc::fsync(fd) };

                if result < 0 {
                    let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(libc::EIO);
                    fuse_debug!("← flush(fh={}) = error (errno={}) [{:.2?}]", fh, errno, start.elapsed());
                    reply.error(errno);
                    return;
                }
            }
            fuse_debug!("← flush(fh={}) = OK [{:.2?}]", fh, start.elapsed());
            reply.ok();
        } else {
            fuse_debug!("← flush(fh={}) = EBADF [{:.2?}]", fh, start.elapsed());
            reply.error(libc::EBADF);
        }
    }

    /// Create and open a file
    fn create(
        &mut self,
        _req: &Request,
        parent: u64,
        name: &OsStr,
        _mode: u32,
        _umask: u32,
        flags: i32,
        reply: fuser::ReplyCreate,
    ) {

        // Handle .overlay synthetic directory
        let parent_entry = if parent == SYNTHETIC_OVERLAY_DIR_INO {
            InodeEntry {
                _ino: SYNTHETIC_OVERLAY_DIR_INO,
                path: PathBuf::from("/.overlay"),
                parent: ROOT_INO,
            }
        } else {
            match self.get_inode(parent) {
                Some(e) => e,
                None => {
                    reply.error(libc::ENOENT);
                    return;
                }
            }
        };

        // Build virtual path for new file
        let virtual_path = parent_entry.path.join(name);

        // Translate to source path using pinned paths
        let (source_rel_path, pinned) = self.translate_virtual_to_source(&virtual_path);
        let is_passthrough = pinned.virtual_prefix == Path::new("/.overlay");

        // Get full file path for attr response
        let file_path = self.source_path.join(&source_rel_path);

        // Create the file in the backing store
        let path_cstr = match CString::new(source_rel_path.as_os_str().as_bytes()) {
            Ok(p) => p,
            Err(_) => {
                reply.error(libc::EINVAL);
                return;
            }
        };

        // Check if file already exists
        let exists = unsafe {
            let mut stat_buf: libc::stat = std::mem::zeroed();
            libc::fstatat(
                self.source_fd,
                path_cstr.as_ptr(),
                &mut stat_buf,
                libc::AT_SYMLINK_NOFOLLOW,
            ) == 0
        };

        // Determine open flags
        // If file exists and O_EXCL is NOT in flags, open it without O_EXCL
        // If file exists and O_EXCL IS in flags, let the open fail with EEXIST
        // If file doesn't exist, create it with O_EXCL to ensure atomic creation
        let open_flags = if exists && (flags & libc::O_EXCL) == 0 {
            // File exists, caller didn't request exclusive - open existing file
            libc::O_CREAT | (flags & !libc::O_EXCL)
        } else {
            // Either file doesn't exist, or caller wants exclusive creation
            libc::O_CREAT | libc::O_EXCL | flags
        };

        let fd = unsafe {
            libc::openat(
                self.source_fd,
                path_cstr.as_ptr(),
                open_flags,
                0o600,
            )
        };

        if fd < 0 {
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(libc::EIO);
            reply.error(errno);
            return;
        }

        // For passthrough writable files, keep fd open; otherwise close it
        let writable = (flags & libc::O_WRONLY) != 0 || (flags & libc::O_RDWR) != 0;
        let passthrough_fd = if is_passthrough && writable {
            Some(fd)
        } else {
            unsafe { libc::close(fd) };
            None
        };

        // Now do a regular lookup and open
        match self.lookup_impl(parent, name) {
            Ok((ino, attr)) => {
                // Create file handle
                let mut next_fh = self.next_fh.write();
                let fh = *next_fh;
                *next_fh += 1;
                drop(next_fh);

                let handle = FileHandle {
                    ino,
                    path: file_path,
                    cached_content: None,
                    writable,
                    dirty: false,
                    opened_mode: false,
                    sealed_mode: false,
                    origin_mode: is_passthrough,
                    passthrough_fd,
                    original_sealed: None,
                };

                self.file_handles.write().insert(fh, handle);

                // For passthrough writable files, use FOPEN_DIRECT_IO to bypass page cache
                let open_flags = if is_passthrough && writable {
                    const FOPEN_DIRECT_IO: u32 = 1 << 0;  // From linux/fuse.h
                    FOPEN_DIRECT_IO
                } else {
                    0
                };

                reply.created(&TTL, &attr, 0, fh, open_flags);
            }
            Err(_) => reply.error(libc::EIO),
        }
    }

    /// Create a directory
    fn mkdir(
        &mut self,
        _req: &Request,
        parent: u64,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        reply: fuser::ReplyEntry,
    ) {
        // Handle .overlay synthetic directory
        let parent_entry = if parent == SYNTHETIC_OVERLAY_DIR_INO {
            InodeEntry {
                _ino: SYNTHETIC_OVERLAY_DIR_INO,
                path: PathBuf::from("/.overlay"),
                parent: ROOT_INO,
            }
        } else {
            match self.get_inode(parent) {
                Some(e) => e,
                None => {
                    reply.error(libc::ENOENT);
                    return;
                }
            }
        };

        // Build virtual path and translate using pinned paths
        let virtual_path = parent_entry.path.join(name);
        let (source_rel_path, _) = self.translate_virtual_to_source(&virtual_path);

        // Create the directory using mkdirat
        use std::os::unix::ffi::OsStrExt;
        let path_cstr = match std::ffi::CString::new(source_rel_path.as_os_str().as_bytes()) {
            Ok(p) => p,
            Err(_) => {
                reply.error(libc::EINVAL);
                return;
            }
        };

        let result = unsafe {
            libc::mkdirat(self.source_fd, path_cstr.as_ptr(), mode as libc::mode_t)
        };

        if result != 0 {
            reply.error(libc::EIO);
            return;
        }

        // Lookup the newly created directory to get its attributes
        match self.lookup_impl(parent, name) {
            Ok((_ino, attr)) => reply.entry(&TTL, &attr, 0),
            Err(_) => reply.error(libc::EIO),
        }
    }

    /// Remove a file
    fn unlink(&mut self, _req: &Request, parent: u64, name: &OsStr, reply: fuser::ReplyEmpty) {
        // Handle .overlay synthetic directory
        let parent_entry = if parent == SYNTHETIC_OVERLAY_DIR_INO {
            InodeEntry {
                _ino: SYNTHETIC_OVERLAY_DIR_INO,
                path: PathBuf::from("/.overlay"),
                parent: ROOT_INO,
            }
        } else {
            match self.get_inode(parent) {
                Some(e) => e,
                None => {
                    reply.error(libc::ENOENT);
                    return;
                }
            }
        };

        // Build virtual path and translate using pinned paths
        let virtual_path = parent_entry.path.join(name);
        let (source_rel_path, _pinned) = self.translate_virtual_to_source(&virtual_path);

        let path_cstr = match CString::new(source_rel_path.as_os_str().as_bytes()) {
            Ok(p) => p,
            Err(_) => {
                reply.error(libc::EINVAL);
                return;
            }
        };

        let result = unsafe { libc::unlinkat(self.source_fd, path_cstr.as_ptr(), 0) };

        if result == 0 {
            // Remove from inode cache (inode table uses virtual paths)
            let mut inodes = self.inode_table.write();
            inodes.retain(|_, entry| entry.path != virtual_path);
            drop(inodes);

            // Also remove from path-to-inode map to keep caches synchronized
            let mut path_map = self.path_to_ino.write();
            path_map.remove(&virtual_path);

            reply.ok();
        } else {
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(libc::EIO);
            reply.error(errno);
        }
    }

    /// Remove a directory
    fn rmdir(&mut self, _req: &Request, parent: u64, name: &OsStr, reply: fuser::ReplyEmpty) {
        // Handle .overlay synthetic directory
        let parent_entry = if parent == SYNTHETIC_OVERLAY_DIR_INO {
            InodeEntry {
                _ino: SYNTHETIC_OVERLAY_DIR_INO,
                path: PathBuf::from("/.overlay"),
                parent: ROOT_INO,
            }
        } else {
            match self.get_inode(parent) {
                Some(e) => e,
                None => {
                    reply.error(libc::ENOENT);
                    return;
                }
            }
        };

        // Build virtual path and translate using pinned paths
        let virtual_path = parent_entry.path.join(name);
        let (source_rel_path, _) = self.translate_virtual_to_source(&virtual_path);

        let path_cstr = match CString::new(source_rel_path.as_os_str().as_bytes()) {
            Ok(p) => p,
            Err(_) => {
                reply.error(libc::EINVAL);
                return;
            }
        };

        // Use AT_REMOVEDIR flag for rmdir
        let result = unsafe {
            libc::unlinkat(self.source_fd, path_cstr.as_ptr(), libc::AT_REMOVEDIR)
        };

        if result == 0 {
            // Remove from inode cache
            let mut inodes = self.inode_table.write();
            inodes.retain(|_, entry| entry.path != virtual_path);
            drop(inodes);

            // Also remove from path-to-inode map to keep caches synchronized
            let mut path_map = self.path_to_ino.write();
            path_map.remove(&virtual_path);

            reply.ok();
        } else {
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(libc::EIO);
            reply.error(errno);
        }
    }

    /// Create a hard link to a file
    fn link(
        &mut self,
        _req: &Request,
        ino: u64,
        newparent: u64,
        newname: &OsStr,
        reply: ReplyEntry,
    ) {

        // Get the existing file's path
        let existing_entry = match self.get_inode(ino) {
            Some(e) => e,
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        // Get the new parent directory's path
        let new_parent_entry = if newparent == SYNTHETIC_OVERLAY_DIR_INO {
            InodeEntry {
                _ino: SYNTHETIC_OVERLAY_DIR_INO,
                path: PathBuf::from("/.overlay"),
                parent: ROOT_INO,
            }
        } else {
            match self.get_inode(newparent) {
                Some(e) => e,
                None => {
                    reply.error(libc::ENOENT);
                    return;
                }
            }
        };


        // Build paths and translate to source
        let (old_rel, old_pinned) = self.translate_virtual_to_source(&existing_entry.path);

        let new_virtual_path = new_parent_entry.path.join(newname);
        let (new_rel, new_pinned) = self.translate_virtual_to_source(&new_virtual_path);

        // Only allow hard links for passthrough files in .overlay
        let is_passthrough = old_pinned.virtual_prefix == Path::new("/.overlay")
            && new_pinned.virtual_prefix == Path::new("/.overlay");

        if !is_passthrough {
            reply.error(libc::EPERM);
            return;
        }


        // Convert paths to CStrings
        let old_cstr = match CString::new(old_rel.as_os_str().as_bytes()) {
            Ok(p) => p,
            Err(_) => {
                reply.error(libc::EINVAL);
                return;
            }
        };

        let new_cstr = match CString::new(new_rel.as_os_str().as_bytes()) {
            Ok(p) => p,
            Err(_) => {
                reply.error(libc::EINVAL);
                return;
            }
        };

        // Create hard link using linkat()
        let result = unsafe {
            libc::linkat(
                self.source_fd,
                old_cstr.as_ptr(),
                self.source_fd,
                new_cstr.as_ptr(),
                0,
            )
        };

        if result == 0 {

            // Invalidate cache for new path
            let mut path_map = self.path_to_ino.write();
            path_map.remove(&new_virtual_path);
            drop(path_map);

            // Look up the newly created link and return its attributes
            match self.lookup_impl(newparent, newname) {
                Ok((_, attr)) => {
                    let ttl = &TTL_ZERO;  // Use zero TTL for passthrough files
                    reply.entry(ttl, &attr, 0);
                }
                Err(_) => {
                    reply.error(libc::EIO);
                }
            }
        } else {
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(libc::EIO);
            reply.error(errno);
        }
    }

    /// Rename a file
    fn rename(
        &mut self,
        _req: &Request,
        parent: u64,
        name: &OsStr,
        newparent: u64,
        newname: &OsStr,
        _flags: u32,
        reply: fuser::ReplyEmpty,
    ) {
        // Handle .overlay synthetic directory for old parent
        let old_parent_entry = if parent == SYNTHETIC_OVERLAY_DIR_INO {
            InodeEntry {
                _ino: SYNTHETIC_OVERLAY_DIR_INO,
                path: PathBuf::from("/.overlay"),
                parent: ROOT_INO,
            }
        } else {
            match self.get_inode(parent) {
                Some(e) => e,
                None => {
                    reply.error(libc::ENOENT);
                    return;
                }
            }
        };

        // Handle .overlay synthetic directory for new parent
        let new_parent_entry = if newparent == SYNTHETIC_OVERLAY_DIR_INO {
            InodeEntry {
                _ino: SYNTHETIC_OVERLAY_DIR_INO,
                path: PathBuf::from("/.overlay"),
                parent: ROOT_INO,
            }
        } else {
            match self.get_inode(newparent) {
                Some(e) => e,
                None => {
                    reply.error(libc::ENOENT);
                    return;
                }
            }
        };

        // Build virtual paths and translate using pinned paths
        let old_virtual_path = old_parent_entry.path.join(name);
        let (old_rel, _) = self.translate_virtual_to_source(&old_virtual_path);

        let new_virtual_path = new_parent_entry.path.join(newname);
        let (new_rel, _) = self.translate_virtual_to_source(&new_virtual_path);

        let old_cstr = match CString::new(old_rel.as_os_str().as_bytes()) {
            Ok(p) => p,
            Err(_) => {
                reply.error(libc::EINVAL);
                return;
            }
        };

        let new_cstr = match CString::new(new_rel.as_os_str().as_bytes()) {
            Ok(p) => p,
            Err(_) => {
                reply.error(libc::EINVAL);
                return;
            }
        };


        let result = unsafe {
            libc::renameat(
                self.source_fd,
                old_cstr.as_ptr(),
                self.source_fd,
                new_cstr.as_ptr(),
            )
        };

        if result == 0 {

            // Update inode cache - remove both old and new paths to force fresh lookups
            // This prevents stale cache entries from causing ENOENT errors
            let mut inodes = self.inode_table.write();
            inodes.retain(|_, entry| entry.path != old_virtual_path && entry.path != new_virtual_path);
            drop(inodes);

            // Also remove from path-to-inode map to keep caches synchronized
            let mut path_map = self.path_to_ino.write();
            path_map.remove(&old_virtual_path);
            path_map.remove(&new_virtual_path);


            reply.ok();
        } else {
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(libc::EIO);
            reply.error(errno);
        }
    }

    /// Set extended attribute - used for sealed mode confirmation
    /// Protocol: O_NONBLOCK on open, then fsetxattr("user.sss.sealed", "1") to confirm
    fn setxattr(
        &mut self,
        _req: &Request,
        _ino: u64,
        name: &OsStr,
        value: &[u8],
        _flags: i32,
        _position: u32,
        reply: fuser::ReplyEmpty,
    ) {

        // Check if this is our sealed mode confirmation signal
        if name == "user.sss.sealed" && value == b"1" {

            // We need to find the file handle, but setxattr doesn't give us fh!
            // We'll need to match by inode and sealed_mode flag
            let mut handles = self.file_handles.write();

            // Find a handle with sealed_mode=true (there should only be one per file)
            let mut found = false;
            for (_fh, handle) in handles.iter_mut() {
                if handle.sealed_mode && handle.cached_content.is_none() {

                    // Both signals present! Cache sealed content
                    match self.read_sealed(&handle.path) {
                        Ok(content) => {
                            handle.cached_content = Some(content);
                            found = true;
                            break;
                        }
                        Err(_e) => {
                            reply.error(libc::EIO);
                            return;
                        }
                    }
                }
            }

            if found {
                reply.ok();
            } else {
                reply.error(libc::EINVAL);
            }
        } else {
            // Not our signal - reject
            reply.error(libc::ENOTSUP);
        }
    }

    /// Create a symlink
    fn symlink(
        &mut self,
        _req: &Request,
        parent: u64,
        name: &OsStr,
        link: &std::path::Path,
        reply: fuser::ReplyEntry,
    ) {
        // Handle .overlay synthetic directory
        let parent_entry = if parent == SYNTHETIC_OVERLAY_DIR_INO {
            InodeEntry {
                _ino: SYNTHETIC_OVERLAY_DIR_INO,
                path: PathBuf::from("/.overlay"),
                parent: ROOT_INO,
            }
        } else {
            match self.get_inode(parent) {
                Some(e) => e,
                None => {
                    reply.error(libc::ENOENT);
                    return;
                }
            }
        };

        // Build virtual path and translate using pinned paths
        let virtual_path = parent_entry.path.join(name);
        let (rel_path, _) = self.translate_virtual_to_source(&virtual_path);

        // Create the symlink using symlinkat
        use std::os::unix::ffi::OsStrExt;
        let link_cstr = match std::ffi::CString::new(link.as_os_str().as_bytes()) {
            Ok(p) => p,
            Err(_) => {
                reply.error(libc::EINVAL);
                return;
            }
        };

        let name_cstr = match std::ffi::CString::new(rel_path.as_os_str().as_bytes()) {
            Ok(p) => p,
            Err(_) => {
                reply.error(libc::EINVAL);
                return;
            }
        };

        let result = unsafe {
            libc::symlinkat(
                link_cstr.as_ptr(),
                self.source_fd,
                name_cstr.as_ptr(),
            )
        };

        if result != 0 {
            reply.error(libc::EIO);
            return;
        }

        // Lookup the newly created symlink
        match self.lookup_impl(parent, name) {
            Ok((_ino, attr)) => reply.entry(&TTL, &attr, 0),
            Err(_) => reply.error(libc::EIO),
        }
    }

    /// Read symlink target
    fn readlink(&mut self, _req: &Request, ino: u64, reply: fuser::ReplyData) {
        // Block operations on .git synthetic directories
        if ino == SYNTHETIC_OVERLAY_DIR_INO {
            reply.error(libc::EINVAL);
            return;
        }

        let entry = match self.get_inode(ino) {
            Some(e) => e,
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        // Translate virtual path to source path using pinned paths
        let (rel_path, _) = self.translate_virtual_to_source(&entry.path);

        // Read symlink target using readlinkat
        use std::os::unix::ffi::OsStrExt;
        let path_cstr = match std::ffi::CString::new(rel_path.as_os_str().as_bytes()) {
            Ok(p) => p,
            Err(_) => {
                reply.error(libc::EINVAL);
                return;
            }
        };

        let mut buf = vec![0u8; libc::PATH_MAX as usize];
        let len = unsafe {
            libc::readlinkat(
                self.source_fd,
                path_cstr.as_ptr(),
                buf.as_mut_ptr() as *mut libc::c_char,
                buf.len(),
            )
        };

        if len < 0 {
            reply.error(libc::EIO);
        } else {
            buf.truncate(len as usize);
            reply.data(&buf);
        }
    }

    /// Get filesystem statistics
    fn statfs(&mut self, _req: &Request, _ino: u64, reply: fuser::ReplyStatfs) {

        // Get statfs from the underlying filesystem
        let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
        let result = unsafe {
            libc::fstatfs(self.source_fd, &mut stat)
        };

        if result == 0 {
            // Return the underlying filesystem's stats
            // This ensures all directories appear to be on the same filesystem
            #[cfg(target_os = "linux")]
            reply.statfs(
                stat.f_blocks,           // Total blocks
                stat.f_bfree,            // Free blocks
                stat.f_bavail,           // Available blocks
                stat.f_files,            // Total inodes
                stat.f_ffree,            // Free inodes
                stat.f_bsize as u32,     // Block size
                stat.f_namelen as u32,   // Max filename length
                stat.f_frsize as u32,    // Fragment size
            );
            #[cfg(target_os = "macos")]
            reply.statfs(
                stat.f_blocks,           // Total blocks
                stat.f_bfree,            // Free blocks
                stat.f_bavail,           // Available blocks
                stat.f_files,            // Total inodes
                stat.f_ffree,            // Free inodes
                stat.f_bsize as u32,     // Block size
                255,                     // Max filename length (macOS typical)
                stat.f_bsize as u32,     // Fragment size (use bsize)
            );
        } else {
            reply.error(libc::EIO);
        }
    }
}

impl Drop for SssFS {
    fn drop(&mut self) {
        // Close the source directory file descriptor
        unsafe {
            libc::close(self.source_fd);
        }
        // Close the mount point directory file descriptor if present
        if let Some(mount_fd) = self.mount_fd {
            unsafe {
                libc::close(mount_fd);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_has_encrypted_markers_true() {
        assert!(has_encrypted_markers("password: ⊠{abc123}"));
        assert!(has_encrypted_markers("⊠{secret}"));
        assert!(has_encrypted_markers("prefix ⊠{data} suffix"));
    }

    #[test]
    fn test_has_encrypted_markers_false() {
        assert!(!has_encrypted_markers("password: plaintext"));
        assert!(!has_encrypted_markers("⊕{plaintext_marker}"));
        assert!(!has_encrypted_markers(""));
        assert!(!has_encrypted_markers("no markers here"));
    }

    #[test]
    fn test_should_hide_git_files() {
        assert!(SssFS::should_hide(".git"));
        assert!(SssFS::should_hide(".gitignore"));
        assert!(SssFS::should_hide(".gitattributes"));
        assert!(SssFS::should_hide(".gitmodules"));
    }

    #[test]
    fn test_should_hide_regular_files() {
        assert!(!SssFS::should_hide("README.md"));
        assert!(!SssFS::should_hide("config.yml"));
        assert!(!SssFS::should_hide(".hidden"));
        assert!(!SssFS::should_hide("gitignore")); // No leading dot
    }

    #[test]
    fn test_should_process_with_sss_regular_files() {
        assert!(SssFS::should_process_with_sss(Path::new("config.yml")));
        assert!(SssFS::should_process_with_sss(Path::new("README.md")));
        assert!(SssFS::should_process_with_sss(Path::new("src/main.rs")));
    }

    #[test]
    fn test_should_process_with_sss_vim_swap_files() {
        assert!(!SssFS::should_process_with_sss(Path::new(".config.yml.swp")));
        assert!(!SssFS::should_process_with_sss(Path::new(".file.swo")));
        assert!(!SssFS::should_process_with_sss(Path::new(".test.swn")));
        assert!(!SssFS::should_process_with_sss(Path::new(".temp.tmp")));
    }

    #[test]
    fn test_should_process_with_sss_temp_files() {
        assert!(!SssFS::should_process_with_sss(Path::new("file~")));
        assert!(!SssFS::should_process_with_sss(Path::new("#file#")));
        assert!(!SssFS::should_process_with_sss(Path::new("#backup")));
    }

    #[test]
    fn test_parse_virtual_file_mode_sealed() {
        let (name, mode) = SssFS::parse_virtual_file_mode(OsStr::new("config.yml.sss-sealed"));
        assert_eq!(name, OsStr::new("config.yml"));
        assert_eq!(mode, FileMode::Sealed);
    }

    #[test]
    fn test_parse_virtual_file_mode_opened() {
        let (name, mode) = SssFS::parse_virtual_file_mode(OsStr::new("config.yml.sss-opened"));
        assert_eq!(name, OsStr::new("config.yml"));
        assert_eq!(mode, FileMode::Opened);
    }

    #[test]
    fn test_parse_virtual_file_mode_rendered() {
        let (name, mode) = SssFS::parse_virtual_file_mode(OsStr::new("config.yml"));
        assert_eq!(name, OsStr::new("config.yml"));
        assert_eq!(mode, FileMode::Rendered);
    }

    #[test]
    fn test_parse_virtual_file_mode_double_suffix() {
        // Should only strip one suffix
        let (name, mode) = SssFS::parse_virtual_file_mode(OsStr::new("file.sss-opened.sss-sealed"));
        assert_eq!(name, OsStr::new("file.sss-opened"));
        assert_eq!(mode, FileMode::Sealed);
    }

    #[test]
    fn test_strip_virtual_suffix_with_opened() {
        let path = PathBuf::from("/path/to/file.txt.sss-opened");
        let result = SssFS::strip_virtual_suffix(&path, true);
        assert_eq!(result, PathBuf::from("/path/to/file.txt"));
    }

    #[test]
    fn test_strip_virtual_suffix_without_opened_mode() {
        let path = PathBuf::from("/path/to/file.txt.sss-opened");
        let result = SssFS::strip_virtual_suffix(&path, false);
        assert_eq!(result, path); // Unchanged when not in opened mode
    }

    #[test]
    fn test_strip_virtual_suffix_no_suffix() {
        let path = PathBuf::from("/path/to/file.txt");
        let result = SssFS::strip_virtual_suffix(&path, true);
        assert_eq!(result, path); // Unchanged when no suffix
    }

    // Note: Testing methods that require SssFS instance or file I/O:
    // - new() requires a real directory and Processor
    // - metadata_via_fd(), read_file_via_fd() require valid file descriptors
    // - read_and_render(), read_and_open(), read_sealed() require Processor and files
    // - write_*() methods require file I/O
    // - FUSE operations (lookup, getattr, read, write) require FUSE context
    // These are better tested through integration tests with actual filesystems
}
