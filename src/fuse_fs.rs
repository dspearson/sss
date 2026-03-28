// This module contains multiple unsafe blocks for libc FFI calls (openat, faccessat,
// fstatat, open, close, read, write, opendir, fdopendir, closedir, getuid, getgid).
// All are necessary for FUSE filesystem implementation using fd-relative syscalls.
// Each unsafe block is documented with a SAFETY comment. See STRUCT-04 audit.

use anyhow::{anyhow, Result};
use fuser::{
    FileAttr, FileType, Filesystem, ReplyAttr, ReplyData, ReplyDirectory, ReplyEntry, Request,
    ReplyWrite, ReplyOpen,
};
use globset::GlobSet;
use parking_lot::RwLock;
use std::collections::{HashMap, HashSet};
use std::ffi::{CString, OsStr};
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::FromRawFd;
use std::path::{Path, PathBuf};
use std::time::{Duration, UNIX_EPOCH, Instant};

use crate::filesystem_common::{has_encrypted_markers, has_any_markers, has_any_markers_bytes};
use crate::project::ProjectConfig;
use crate::secrets::{FileSystemOps, SecretsCache, interpolate_secrets};
use crate::Processor;

/// Debug logging macro for FUSE operations. Enabled by setting SSS_FUSE_DEBUG=1.
/// Includes thread ID and PID for diagnosing deadlocks and concurrency issues.
macro_rules! fuse_debug {
    ($($arg:tt)*) => {
        if FUSE_DEBUG.load(std::sync::atomic::Ordering::Relaxed) {
            let thread_id = std::thread::current().id();
            let pid = std::process::id();
            eprintln!("[FUSE DEBUG {:?} PID:{}] {}", thread_id, pid, format!($($arg)*));
        }
    };
}

/// Global flag checked by fuse_debug! — set once from SSS_FUSE_DEBUG env var.
static FUSE_DEBUG: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Initialise the debug flag from the environment. Call once at startup.
fn init_fuse_debug() {
    if std::env::var("SSS_FUSE_DEBUG").map_or(false, |v| v == "1" || v.eq_ignore_ascii_case("true")) {
        FUSE_DEBUG.store(true, std::sync::atomic::Ordering::Relaxed);
    }
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
}

/// Passthrough operations - raw read/write with no SSS processing
struct PassthroughOperations {}

impl FileOperations for PassthroughOperations {
    fn should_hide(&self, _name: &str) -> bool {
        false  // Show everything including .git
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
    /// Processor for encryption/decryption operations
    processor: Processor,
    /// Secrets cache for finding and loading .secrets files
    secrets_cache: RwLock<SecretsCache>,
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
    /// Processors for nested projects (rel_path from source → Processor)
    nested_processors: HashMap<PathBuf, Processor>,
    /// Relative paths of nested projects where we have no matching keys
    no_key_roots: HashSet<PathBuf>,
    /// Ignore patterns from root project config (positive matches → skip processing)
    ignore_patterns: Option<GlobSet>,
    /// Negation patterns from root project config (overrides ignore)
    negation_patterns: Option<GlobSet>,
    /// Per-nested-project ignore patterns (rel_path → (positive, negation))
    nested_ignore: HashMap<PathBuf, (GlobSet, GlobSet)>,
}

/// FD-based filesystem operations for FUSE in-place mounts
///
/// When FUSE is mounted over the source directory, normal filesystem operations
/// like .exists() and fs::read() will route back through the FUSE mount, causing
/// deadlock. This implementation uses fd-based operations (openat, faccessat) with
/// source_fd to access the real filesystem underneath the mount.
///
/// IMPORTANT: All paths MUST be relative to source_fd. Absolute paths are
/// automatically relativised by stripping `source_path` to prevent deadlocks
/// when faccessat/openat would otherwise resolve through the FUSE mount.
struct FdFileSystemOps {
    source_fd: std::os::unix::io::RawFd,
    source_path: PathBuf,
}

impl FdFileSystemOps {
    /// Convert a path to be relative to source_fd.
    /// Absolute paths starting with source_path are stripped; other absolute
    /// paths are returned as-is (openat will resolve them through VFS).
    fn relativise<'a>(&self, path: &'a Path) -> &'a Path {
        if path.is_absolute() {
            path.strip_prefix(&self.source_path).unwrap_or(path)
        } else {
            path
        }
    }
}

impl FileSystemOps for FdFileSystemOps {
    fn file_exists(&self, path: &Path) -> bool {
        let rel = self.relativise(path);
        let path_bytes = rel.as_os_str().as_bytes();
        let path_cstr = match std::ffi::CString::new(path_bytes) {
            Ok(p) => p,
            Err(_) => return false,
        };

        // SAFETY: `self.source_fd` is a valid open directory fd obtained in `new()`.
        // `path_cstr` is a valid NUL-terminated C string derived from a Rust Path.
        // `faccessat` does not retain the pointer after returning.
        let result = unsafe {
            libc::faccessat(
                self.source_fd,
                path_cstr.as_ptr(),
                libc::F_OK,
                0,
            )
        };

        result == 0
    }

    fn read_file(&self, path: &Path) -> Result<Vec<u8>> {
        let rel = self.relativise(path);
        let path_bytes = rel.as_os_str().as_bytes();
        let path_cstr = std::ffi::CString::new(path_bytes)?;

        // SAFETY: `self.source_fd` is a valid open directory fd. `path_cstr` is a valid
        // NUL-terminated path. `openat` returns a new fd or -1 on error.
        let fd = unsafe {
            libc::openat(self.source_fd, path_cstr.as_ptr(), libc::O_RDONLY)
        };

        if fd < 0 {
            return Err(anyhow!("Failed to open file {:?}", path));
        }

        // Read file contents
        // SAFETY: `fd` is a valid file descriptor returned by `openat` above (fd >= 0).
        // `File::from_raw_fd` takes ownership; `mem::forget` prevents double-close since
        // we close `fd` manually below after reading.
        let mut file = unsafe { fs::File::from_raw_fd(fd) };
        let mut contents = Vec::new();
        std::io::Read::read_to_end(&mut file, &mut contents)?;
        std::mem::forget(file); // Don't close fd automatically

        // Close fd manually
        // SAFETY: `fd` was opened above, `mem::forget` on `file` means it was not closed.
        unsafe { libc::close(fd); }

        Ok(contents)
    }
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
    /// let fs = SssFS::new(source, processor, Some(mount), None)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(source_path: PathBuf, processor: Processor, mount_path: Option<PathBuf>,
               config: Option<&ProjectConfig>) -> Result<Self> {
        init_fuse_debug();
        fuse_debug!("SssFS::new source={:?} mount={:?}", source_path, mount_path);

        if !source_path.exists() {
            return Err(anyhow!("Source path does not exist: {:?}", source_path));
        }

        if !source_path.is_dir() {
            return Err(anyhow!("Source path is not a directory: {:?}", source_path));
        }

        // Open a file descriptor to the source directory before mounting
        // This allows us to access files even if we mount over the source location
        // SAFETY: `source_path` was verified to exist and be a directory above.
        // `CString::new` is called inside the block; the pointer is valid for the duration
        // of the `open` syscall. The returned fd is checked for errors immediately.
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
            // SAFETY: `mount_path` exists (checked by caller). `CString::new` is called inside
            // the block; pointer is valid for the duration of `open`. The fd is checked immediately.
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
                // SAFETY: `source_fd` is valid (checked above, fd >= 0); closing it here
                // because we are about to return an error without storing it in `self`.
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

        // Create secrets cache from processor configuration
        let secrets_cache = processor.get_secrets_cache().clone();

        // Parse root project ignore patterns from config
        let (ignore_patterns, negation_patterns) = if let Some(cfg) = config {
            let (pos, neg) = cfg.parse_ignore_patterns()?;
            (
                if pos.is_empty() { None } else { Some(pos) },
                if neg.is_empty() { None } else { Some(neg) },
            )
        } else {
            (None, None)
        };

        // Scan for nested projects (subdirectories with their own .sss.toml)
        let mut nested_processors = HashMap::new();
        let mut no_key_roots = HashSet::new();
        let mut nested_ignore = HashMap::new();

        for entry in walkdir::WalkDir::new(&source_path)
            .follow_links(false)
            .into_iter()
            .filter_entry(|e| {
                let name = e.file_name().to_string_lossy();
                if name.starts_with('.') { return false; }
                if e.file_type().is_dir() {
                    let skip = ["target", "node_modules", "dist", "build"];
                    return !skip.contains(&name.as_ref());
                }
                true
            })
        {
            let entry = match entry {
                Ok(e) => e,
                Err(_) => continue,
            };
            if !entry.file_type().is_dir() { continue; }
            if entry.path() == source_path { continue; }

            let config_path = entry.path().join(".sss.toml");
            if !config_path.exists() { continue; }

            let rel_path = entry.path().strip_prefix(&source_path)
                .unwrap_or(entry.path())
                .to_path_buf();

            match crate::commands::utils::try_create_processor_for_config(&config_path) {
                Ok(Some((cfg, proc))) => {
                    // Parse ignore patterns for this nested project
                    if let Ok((pos, neg)) = cfg.parse_ignore_patterns() {
                        if !pos.is_empty() {
                            nested_ignore.insert(rel_path.clone(), (pos, neg));
                        }
                    }
                    nested_processors.insert(rel_path, proc);
                }
                Ok(None) => {
                    eprintln!("Note: FUSE - no keys for nested project at {}", rel_path.display());
                    no_key_roots.insert(rel_path);
                }
                Err(e) => {
                    eprintln!("Warning: FUSE - cannot load nested project at {}: {}", rel_path.display(), e);
                    no_key_roots.insert(rel_path);
                }
            }
        }

        Ok(Self {
            source_path,
            source_fd,
            mount_fd,
            processor,
            secrets_cache: RwLock::new(secrets_cache),
            inode_table: RwLock::new(inode_table),
            path_to_ino: RwLock::new(path_to_ino),
            next_ino: RwLock::new(ROOT_INO + 1),
            file_handles: RwLock::new(HashMap::new()),
            next_fh: RwLock::new(1),
            render_cache: RwLock::new(HashMap::new()),
            pinned_paths,
            nested_processors,
            no_key_roots,
            ignore_patterns,
            negation_patterns,
            nested_ignore,
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
    /// let fs = SssFS::new(source, processor, Some(mount), None)?;
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

    /// Convert filesystem metadata to FUSE FileAttr — always mirrors original metadata.
    /// Only `size` may differ (via size_override) because rendered content length differs from on-disk.
    fn metadata_to_attr_with_secrets(&self, ino: u64, metadata: &fs::Metadata, size_override: Option<u64>, _force_writable: bool, _has_secrets: bool) -> FileAttr {
        let kind = if metadata.is_dir() {
            FileType::Directory
        } else if metadata.is_symlink() {
            FileType::Symlink
        } else {
            FileType::RegularFile
        };

        // Use override size for rendered content
        let size = size_override.unwrap_or(metadata.len());

        FileAttr {
            ino,
            size,
            blocks: Self::get_blocks(metadata),
            atime: metadata.accessed().unwrap_or(UNIX_EPOCH),
            mtime: metadata.modified().unwrap_or(UNIX_EPOCH),
            ctime: Self::get_ctime(metadata),
            crtime: metadata.created().unwrap_or(UNIX_EPOCH),
            kind,
            perm: Self::get_permissions(metadata),
            nlink: Self::get_nlink(metadata) as u32,
            uid: Self::get_uid(metadata),
            gid: Self::get_gid(metadata),
            rdev: Self::get_rdev(metadata),
            blksize: Self::get_blksize(metadata),
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

    #[cfg(unix)]
    fn get_ctime(metadata: &fs::Metadata) -> std::time::SystemTime {
        use std::os::unix::fs::MetadataExt;
        let secs = metadata.ctime();
        let nsecs = metadata.ctime_nsec() as u32;
        if secs >= 0 {
            UNIX_EPOCH + Duration::new(secs as u64, nsecs)
        } else {
            UNIX_EPOCH
        }
    }

    #[cfg(not(unix))]
    fn get_ctime(metadata: &fs::Metadata) -> std::time::SystemTime {
        metadata.created().unwrap_or(UNIX_EPOCH)
    }

    #[cfg(unix)]
    fn get_blocks(metadata: &fs::Metadata) -> u64 {
        use std::os::unix::fs::MetadataExt;
        metadata.blocks()
    }

    #[cfg(not(unix))]
    fn get_blocks(metadata: &fs::Metadata) -> u64 {
        metadata.len().div_ceil(512)
    }

    #[cfg(unix)]
    fn get_blksize(metadata: &fs::Metadata) -> u32 {
        use std::os::unix::fs::MetadataExt;
        metadata.blksize() as u32
    }

    #[cfg(not(unix))]
    fn get_blksize(_metadata: &fs::Metadata) -> u32 {
        512
    }

    #[cfg(unix)]
    fn get_rdev(metadata: &fs::Metadata) -> u32 {
        use std::os::unix::fs::MetadataExt;
        metadata.rdev() as u32
    }

    #[cfg(not(unix))]
    fn get_rdev(_metadata: &fs::Metadata) -> u32 {
        0
    }

    /// Get the processor for a given relative path by walking up to find
    /// the nearest nested project, or falling back to the root processor.
    /// Returns `None` if the path falls inside a no-key root (passthrough).
    fn get_processor_for_path(&self, rel_path: &Path) -> Option<&Processor> {
        let mut current = Some(rel_path);
        while let Some(p) = current {
            if self.no_key_roots.contains(p) {
                return None;
            }
            if let Some(proc) = self.nested_processors.get(p) {
                return Some(proc);
            }
            current = p.parent();
        }
        Some(&self.processor)
    }

    /// Check if a file should skip SSS processing due to ignore patterns.
    /// Ignored files are still visible but returned as raw bytes (no decrypt/render).
    fn should_skip_processing(&self, rel_path: &Path) -> bool {
        // Walk up from rel_path to find the nearest nested project with ignore patterns
        let mut current = Some(rel_path);
        while let Some(p) = current {
            if let Some((positive, negative)) = self.nested_ignore.get(p) {
                // Found nested project — check path relative to this project root
                let sub_path = rel_path.strip_prefix(p).unwrap_or(rel_path);
                return Self::matches_ignore_patterns(sub_path, positive, negative);
            }
            current = p.parent();
        }

        // No nested project found, use root patterns
        if let Some(ref positive) = self.ignore_patterns {
            let negative = self.negation_patterns.as_ref();
            let empty = GlobSet::empty();
            let neg = negative.unwrap_or(&empty);
            Self::matches_ignore_patterns(rel_path, positive, neg)
        } else {
            false
        }
    }

    /// Check if a path matches positive ignore patterns without being overridden by negation.
    fn matches_ignore_patterns(path: &Path, positive: &GlobSet, negative: &GlobSet) -> bool {
        if positive.is_empty() {
            return false;
        }

        // Check both full path and filename (so *.log matches subdir/debug.log)
        let matches_ignore = positive.is_match(path)
            || path.file_name()
                .and_then(|n| n.to_str())
                .map(|name| positive.is_match(name))
                .unwrap_or(false);

        if !matches_ignore {
            return false;
        }

        // Check negation override
        if !negative.is_empty() {
            let matches_negation = negative.is_match(path)
                || path.file_name()
                    .and_then(|n| n.to_str())
                    .map(|name| negative.is_match(name))
                    .unwrap_or(false);

            if matches_negation {
                return false; // Negation overrides ignore
            }
        }

        true
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

        // On macOS with in-place mounts, path-based operations deadlock
        // because they route through the FUSE mount. Use FD-based operations
        // through source_fd which was opened before mounting.
        #[cfg(target_os = "macos")]
        {
            use std::os::unix::ffi::OsStrExt;

            if rel_path == Path::new(".") {
                // For root directory, use fstat directly on source_fd
                // SAFETY: `self.source_fd` is a valid open fd held for the lifetime of SssFS.
                // `mem::forget` prevents File from closing the fd — it is managed by SssFS::drop.
                let file = unsafe { std::fs::File::from_raw_fd(self.source_fd) };
                let metadata = file.metadata()?;
                std::mem::forget(file); // Don't close source_fd
                return Ok(metadata);
            }

            // For other paths, use fstatat relative to source_fd
            // This should work because source_fd was opened before mounting
            let path_bytes = rel_path.as_os_str().as_bytes();
            let path_cstr = std::ffi::CString::new(path_bytes)?;

            // SAFETY: `self.source_fd` is valid. `path_cstr` is NUL-terminated.
            // `stat` is zeroed stack memory of the correct size for `libc::stat`.
            // `fstatat` writes into `stat` and returns 0 on success, -1 on error.
            let mut stat: libc::stat = unsafe { std::mem::zeroed() };
            let result = unsafe {
                libc::fstatat(self.source_fd, path_cstr.as_ptr(), &mut stat, libc::AT_SYMLINK_NOFOLLOW)
            };

            if result < 0 {
                let err = std::io::Error::last_os_error();
                return Err(anyhow!("Failed to stat file: {}", err));
            }


            // Determine file type
            let is_dir = (stat.st_mode & libc::S_IFMT) == libc::S_IFDIR;
            let is_symlink = (stat.st_mode & libc::S_IFMT) == libc::S_IFLNK;

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

            // SAFETY: `self.source_fd` is valid. `path_cstr` is NUL-terminated.
            // `flags` are platform-appropriate open flags computed above.
            let fd = unsafe {
                libc::openat(self.source_fd, path_cstr.as_ptr(), flags)
            };

            if fd < 0 {
                let err = std::io::Error::last_os_error();

                // If this is a symlink and openat failed, try with O_SYMLINK | O_NOFOLLOW
                #[cfg(target_os = "macos")]
                if is_symlink && err.raw_os_error() == Some(libc::ELOOP) {
                    // SAFETY: retry with O_SYMLINK flag; same preconditions as above.
                    let retry_fd = unsafe {
                        libc::openat(self.source_fd, path_cstr.as_ptr(),
                                   libc::O_RDONLY | libc::O_SYMLINK | libc::O_NOFOLLOW)
                    };
                    if retry_fd >= 0 {
                        // SAFETY: `retry_fd` is valid (>= 0). File takes ownership and
                        // will close it when dropped.
                        let file = unsafe { std::fs::File::from_raw_fd(retry_fd) };
                        let metadata = file.metadata()?;
                        return Ok(metadata);
                    }
                }

                return Err(anyhow!("Failed to open file for metadata: {}", err));
            }

            // SAFETY: `fd` is valid (>= 0). File takes ownership and closes it when dropped.
            let file = unsafe { std::fs::File::from_raw_fd(fd) };
            let metadata = file.metadata()?;
            return Ok(metadata);
        }

        #[cfg(not(target_os = "macos"))]
        {
            use std::os::unix::ffi::OsStrExt;

            let path_bytes = rel_path.as_os_str().as_bytes();
            let path_cstr = std::ffi::CString::new(path_bytes)?;

            // SAFETY: `stat` is zeroed stack memory of the correct size. `self.source_fd`
            // is valid. `path_cstr` is NUL-terminated. Result checked immediately.
            let mut stat: libc::stat = unsafe { std::mem::zeroed() };

            let result = unsafe {
                libc::fstatat(self.source_fd, path_cstr.as_ptr(), &mut stat, libc::AT_SYMLINK_NOFOLLOW)
            };

            if result < 0 {
                let err = std::io::Error::last_os_error();
                return Err(anyhow!("Failed to stat file: {}", err));
            }

            // Determine file type from the stat result
            let is_dir = (stat.st_mode & libc::S_IFMT) == libc::S_IFDIR;
            let is_symlink = (stat.st_mode & libc::S_IFMT) == libc::S_IFLNK;

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

            // SAFETY: `self.source_fd` is valid. `path_cstr` is NUL-terminated.
            // `flags` are computed above based on file type from `fstatat` result.
            let fd = unsafe {
                libc::openat(self.source_fd, path_cstr.as_ptr(), flags)
            };

            if fd < 0 {
                let err = std::io::Error::last_os_error();

                // If this is a symlink and openat failed with ELOOP, try O_PATH | O_NOFOLLOW
                // as a fallback (in case the first attempt didn't use those flags)
                if is_symlink && err.raw_os_error() == Some(libc::ELOOP) {
                    // SAFETY: retry with O_PATH|O_NOFOLLOW; same source_fd/path preconditions.
                    let retry_fd = unsafe {
                        libc::openat(self.source_fd, path_cstr.as_ptr(), libc::O_PATH | libc::O_NOFOLLOW)
                    };
                    if retry_fd >= 0 {
                        // SAFETY: `retry_fd` is valid (>= 0). File takes ownership and closes on drop.
                        let file = unsafe { std::fs::File::from_raw_fd(retry_fd) };
                        let metadata = file.metadata()?;
                        return Ok(metadata);
                    }
                }

                return Err(anyhow!("Failed to open file for metadata: {}", err));
            }

            // SAFETY: `fd` is valid (>= 0). File takes ownership and closes it when dropped.
            let file = unsafe { std::fs::File::from_raw_fd(fd) };
            let metadata = file.metadata()?;
            Ok(metadata)
        }
    }

    /// Check if a file exists using source_fd (works even if mounted over source)
    #[allow(dead_code)]
    fn file_exists_via_fd(&self, rel_path: &Path) -> bool {
        let path_bytes = rel_path.as_os_str().as_bytes();
        let path_cstr = match std::ffi::CString::new(path_bytes) {
            Ok(p) => p,
            Err(_) => return false,
        };

        // Use faccessat to check if file exists without deadlocking
        // SAFETY: `self.source_fd` is a valid directory fd. `path_cstr` is NUL-terminated.
        // `faccessat` does not retain the pointer after returning.
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
        fuse_debug!("      read_file_via_fd: rel_path={:?} source_fd={}", rel_path, self.source_fd);
        // On macOS, openat can deadlock from FUSE handlers
        // Use full path instead
        #[cfg(target_os = "macos")]
        {
            let full_path = self.source_path.join(rel_path);
            fuse_debug!("      read_file_via_fd: macOS fs::read {:?}", full_path);
            let buffer = fs::read(&full_path)?;
            fuse_debug!("      read_file_via_fd: done, {}bytes", buffer.len());
            return Ok(buffer);
        }

        #[cfg(not(target_os = "macos"))]
        {
            use std::os::unix::ffi::OsStrExt;

            let path_bytes = rel_path.as_os_str().as_bytes();
            let path_cstr = std::ffi::CString::new(path_bytes)?;

            // Open file relative to source_fd
            fuse_debug!("      read_file_via_fd: calling openat(fd={}, {:?}, O_RDONLY)", self.source_fd, rel_path);
            // SAFETY: `self.source_fd` is a valid directory fd. `path_cstr` is NUL-terminated.
            // The returned fd is checked for errors before use.
            let fd = unsafe {
                libc::openat(self.source_fd, path_cstr.as_ptr(), libc::O_RDONLY)
            };
            fuse_debug!("      read_file_via_fd: openat returned fd={}", fd);

            if fd < 0 {
                let err = std::io::Error::last_os_error();
                return Err(anyhow!("Failed to open file: {}", err));
            }

            // Read file contents
            fuse_debug!("      read_file_via_fd: reading contents");
            let mut buffer = Vec::new();
            // SAFETY: `fd` is valid (>= 0). File takes ownership and closes it when dropped
            // (via BufReader, which consumes File).
            let file = unsafe { std::fs::File::from_raw_fd(fd) };
            use std::io::Read;
            std::io::BufReader::new(file).read_to_end(&mut buffer)?;
            fuse_debug!("      read_file_via_fd: done, {}bytes", buffer.len());

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

        fuse_debug!("    read_and_process: rel_path={:?}", rel_path);

        // Read file via fd
        fuse_debug!("    read_and_process: calling read_file_via_fd");
        let bytes = self.read_file_via_fd(rel_path)?;
        fuse_debug!("    read_and_process: read {}bytes", bytes.len());

        // Skip processing for files matching ignore patterns — return raw bytes
        if self.should_skip_processing(rel_path) {
            fuse_debug!("    read_and_process: skipped (ignore pattern)");
            return Ok(bytes);
        }

        // Quick byte-level scan for marker opening sequences (avoids String conversion
        // for the vast majority of files that have no markers at all)
        use crate::filesystem_common::has_any_markers_bytes;
        if !has_any_markers_bytes(&bytes) {
            fuse_debug!("    read_and_process: no markers, returning raw");
            return Ok(bytes);
        }

        // File has marker-like bytes — convert to string for deeper validation
        let content = match String::from_utf8(bytes.clone()) {
            Ok(c) => c,
            Err(_) => {
                // Has marker-like bytes but not valid UTF-8, return raw bytes
                return Ok(bytes);
            }
        };

        // Verify file actually has balanced markers (prefix + { + content + })
        // Files that merely mention marker characters (e.g. in grep patterns or
        // documentation) are returned as-is to avoid false-positive processing
        use crate::filesystem_common::has_balanced_markers;
        if !has_balanced_markers(&content) {
            fuse_debug!("    read_and_process: no balanced markers, returning raw");
            return Ok(bytes);
        }

        fuse_debug!("    read_and_process: has balanced markers, processing");

        // Apply processing function with relative path for proper secrets resolution
        let processed = process_fn(self, content, rel_path)?;
        fuse_debug!("    read_and_process: done");
        Ok(processed.into_bytes())
    }

    fn read_and_render(&self, path: &Path) -> Result<Vec<u8>> {
        self.read_and_process(path, |fs, content, rel_path| {
            // Check for a nested-project processor (None → no keys, passthrough)
            let proc = match fs.get_processor_for_path(rel_path) {
                Some(p) => p,
                None => return Ok(content), // no keys — return as-is
            };

            // Process if file has any markers (sealed or opened)
            if has_any_markers(&content) {
                // First, interpolate secrets using unified function with fd-based operations (avoids deadlock)
                let fd_ops = FdFileSystemOps {
                    source_fd: fs.source_fd,
                    source_path: fs.source_path.clone(),
                };
                let mut secrets_cache = fs.secrets_cache.write();
                let content_with_secrets = interpolate_secrets(
                    &content,
                    rel_path,
                    &fs.source_path,
                    &mut *secrets_cache,
                    &fd_ops,
                )?;

                // Then decrypt and remove all markers using the correct processor
                proc.decrypt_to_raw(&content_with_secrets)
            } else {
                // Return as-is for non-marked files
                Ok(content)
            }
        })
    }

    /// Read and open a file (decrypt ⊠{} → ⊕{} but keep markers for ssse edit)
    fn read_and_open(&self, path: &Path) -> Result<Vec<u8>> {
        self.read_and_process(path, |fs, content, rel_path| {
            // Check for a nested-project processor (None → no keys, passthrough)
            let proc = match fs.get_processor_for_path(rel_path) {
                Some(p) => p,
                None => return Ok(content), // no keys — return as-is
            };

            // Only process if file has encrypted markers
            if has_encrypted_markers(&content) {
                // Decrypt to opened form (⊠{} → ⊕{})
                proc.decrypt_content(&content)
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
        // SAFETY: `self.source_fd` is a valid directory fd. `path_cstr` is NUL-terminated.
        // Mode 0o600 restricts access to the file owner. Error checked immediately.
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

        // SAFETY: `fd` is valid (>= 0). `content.as_ptr()` points to `content.len()` valid bytes.
        // `libc::write` does not retain the pointer. `close` is called after write completes.
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
        // SAFETY: `self.source_fd` is a valid directory fd. `temp_path_cstr` is NUL-terminated.
        // Mode 0o600 restricts access to the file owner. Error checked immediately.
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

        // SAFETY: `temp_fd` is valid (>= 0). `content.as_ptr()` points to `content.len()` valid
        // UTF-8 bytes. `libc::write` does not retain the pointer. `close` follows immediately.
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
            // SAFETY: `self.source_fd` is valid. `temp_path_cstr` is NUL-terminated.
            // `unlinkat` is best-effort cleanup on error path; ignoring return value is intentional.
            unsafe {
                libc::unlinkat(self.source_fd, temp_path_cstr.as_ptr(), 0);
            }
            return Err(anyhow!("Failed to write content"));
        }

        // Atomically rename temp to target
        // SAFETY: both `temp_path_cstr` and `path_cstr` are NUL-terminated. `self.source_fd`
        // is the same directory fd for both paths (relative rename within one directory).
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
            // SAFETY: `self.source_fd` valid. `temp_path_cstr` NUL-terminated. Best-effort cleanup.
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

        // Select the correct processor for this path
        let rel_path = path.strip_prefix(&self.source_path).unwrap_or(path);
        let proc = self.get_processor_for_path(rel_path).unwrap_or(&self.processor);

        // Seal the opened content (⊕{} → ⊠{})
        let sealed_content = proc.encrypt_content(&opened_str)?;

        // Write to backing store via file descriptor
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
        // Select the correct processor for this path
        let rel_path = path.strip_prefix(&self.source_path).unwrap_or(path);
        let proc = self.get_processor_for_path(rel_path).unwrap_or(&self.processor);

        // Open (decrypt/open) current version to get content with markers
        let opened_current = proc.decrypt_content(sealed_current)?;

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
        // Check if this file is in a no-key zone — write raw
        let rel_path = path.strip_prefix(&self.source_path).unwrap_or(path);
        if self.get_processor_for_path(rel_path).is_none() {
            return self.write_raw_to_backing(path, rendered_content);
        }

        // Skip processing for files matching ignore patterns — write raw
        if self.should_skip_processing(rel_path) {
            return self.write_raw_to_backing(path, rendered_content);
        }

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
        let is_passthrough = pinned.virtual_prefix == Path::new("/.overlay");
        let size_override = if is_passthrough {
            None
        } else {
            self.compute_size_override(ino, &metadata)
        };
        let attr = self.metadata_to_attr(ino, &metadata, size_override, false);

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
        fuse_debug!("  precache: path={:?} sealed={} opened={} writable={}", file_path, is_sealed_mode, is_opened_mode, writable);
        let result = if is_sealed_mode {
            // Sealed mode: pre-cache raw sealed content with ⊠{} markers
            fuse_debug!("  precache: reading sealed");
            self.read_sealed(file_path).ok()
        } else if is_opened_mode {
            // Opened mode: pre-cache with ⊕{} markers
            fuse_debug!("  precache: reading opened");
            self.read_and_open(file_path).ok()
        } else {
            // Normal mode (read-only or writable): pre-render so that
            // getattr reports the correct rendered size rather than the
            // on-disk size (which includes encrypted markers and differs).
            // For writable files the cached content is updated in-place by
            // write() and flushed/sealed in release(), so precaching is safe.
            fuse_debug!("  precache: reading rendered (writable={})", writable);
            self.read_and_render(file_path).ok()
        };
        fuse_debug!("  precache: done, got={}bytes", result.as_ref().map_or(0, |c| c.len()));
        result
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

            // SAFETY: `path_cstr` is a valid NUL-terminated absolute path.
            // `opendir` returns a DIR* or NULL on error; checked immediately.
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

            // SAFETY: `self.source_fd` is valid. `path_cstr` is NUL-terminated.
            // O_RDONLY|O_DIRECTORY ensures we only open a directory. Error checked immediately.
            let dir_fd = unsafe {
                libc::openat(self.source_fd, path_cstr.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY)
            };

            if dir_fd < 0 {
                return Err(anyhow!("openat failed: {}", std::io::Error::last_os_error()));
            }

            // SAFETY: `dir_fd` is a valid directory fd (>= 0). `fdopendir` takes ownership;
            // if it fails (returns NULL) we close `dir_fd` manually to avoid a leak.
            let dir_ptr = unsafe { libc::fdopendir(dir_fd) };
            if dir_ptr.is_null() {
                // SAFETY: `dir_fd` is still valid; fdopendir failed so we own it.
                unsafe { libc::close(dir_fd); }
                return Err(anyhow!("fdopendir failed"));
            }

            Ok(dir_ptr)
        }
    }

    /// Read all entries from an open directory using pinned path operations
    fn read_dir_entries_with_operations(&mut self, dir_ptr: *mut libc::DIR, parent_ino: u64, parent_path: &Path, operations: &dyn FileOperations)
        -> Vec<(u64, FileType, String)> {
        let mut items = Vec::new();
        let mut _count = 0;

        // SAFETY: `dir_ptr` is a valid non-null DIR* obtained from `open_dir_fd`.
        // `readdir` returns a pointer to a static dirent buffer owned by the DIR stream;
        // the pointer is valid until the next `readdir`/`closedir` call. We copy all
        // needed fields (d_name, d_type) before the next iteration. `__errno_location`
        // and `__error` return a valid per-thread errno pointer; dereferencing to reset
        // it is safe in a single-threaded FUSE callback context.
        unsafe {
            loop {
                // Reset errno before readdir
                #[cfg(target_os = "linux")]
                { *libc::__errno_location() = 0; }
                #[cfg(target_os = "macos")]
                { *libc::__error() = 0; }

                let entry_ptr = libc::readdir(dir_ptr);

                if entry_ptr.is_null() {
                    break;
                }

                let dirent = &*entry_ptr;
                let name = std::ffi::CStr::from_ptr(dirent.d_name.as_ptr())
                    .to_string_lossy()
                    .to_string();


                // Skip . and ..
                if name == "." || name == ".." {
                    continue;
                }

                // Use operations from pinned path for hiding logic
                if operations.should_hide(&name) {
                    continue;
                }

                let virtual_path = parent_path.join(&name);
                let child_ino = self.get_or_create_inode(&virtual_path, parent_ino);

                let file_type = if dirent.d_type == libc::DT_DIR {
                    FileType::Directory
                } else {
                    FileType::RegularFile
                };

                items.push((child_ino, file_type, name));
                _count += 1;
            }
        }

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
            return handle_size;
        }
        drop(handles);

        // Check render cache
        {
            let cache = self.render_cache.read();
            if let Some(content) = cache.get(&ino) {
                return Some(content.len() as u64);
            }
        }

        // Nothing cached yet — eagerly render files with markers so that
        // getattr/lookup report the correct (rendered) size instead of the
        // on-disk size.  Without this, editors like vim see the larger
        // on-disk size, read fewer rendered bytes, and display trailing NULs.
        let entry = self.get_inode(ino)?;
        let (source_rel_path, pinned) = self.translate_virtual_to_source(&entry.path);
        if pinned.virtual_prefix == Path::new("/.overlay") {
            return None; // passthrough — on-disk size is correct
        }

        // Quick byte-level scan: only render if markers are present
        let bytes = self.read_file_via_fd(&source_rel_path).ok()?;
        if !has_any_markers_bytes(&bytes) {
            return None; // no markers — on-disk size matches rendered size
        }

        // File has markers — render and cache to get the true size
        let file_path = self.source_path.join(&source_rel_path);
        match self.read_and_render(&file_path) {
            Ok(content) => {
                let size = content.len() as u64;
                self.render_cache.write().insert(ino, content);
                Some(size)
            }
            Err(_) => None,
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

    /// Map an inode to the backing source file path that xattr queries should target.
    /// Strips virtual suffixes (.sss-opened/.sss-sealed) so xattrs are read from the
    /// real underlying file, and handles the synthetic .overlay root specially.
    fn resolve_source_for_xattr(&self, ino: u64) -> Option<PathBuf> {
        if ino == SYNTHETIC_OVERLAY_DIR_INO {
            return Some(PathBuf::from("."));
        }
        let entry = self.get_inode(ino)?;
        let virtual_path = entry.path.clone();

        let stripped = if let Some(name) = virtual_path.file_name() {
            let (actual, _mode) = Self::parse_virtual_file_mode(name);
            if actual != name {
                let parent = virtual_path.parent().unwrap_or(Path::new(""));
                parent.join(actual)
            } else {
                virtual_path
            }
        } else {
            virtual_path
        };

        let (rel, _pinned) = self.translate_virtual_to_source(&stripped);
        Some(rel)
    }

    /// Open an fd for xattr operations against a source-relative path. Returns a raw
    /// fd that the caller MUST close (-1 on error, errno set via last_os_error).
    /// Uses O_PATH|O_NOFOLLOW on Linux so we can inspect symlinks and special files
    /// without opening them for I/O; fgetxattr on O_PATH fds has been supported since
    /// Linux 4.17 (RHEL 8 kernel is 4.18+).
    #[cfg(target_os = "linux")]
    fn open_fd_for_xattr(&self, rel_path: &Path) -> i32 {
        use std::os::unix::ffi::OsStrExt;
        let path_bytes = rel_path.as_os_str().as_bytes();
        let path_cstr = match std::ffi::CString::new(path_bytes) {
            Ok(c) => c,
            Err(_) => return -1,
        };
        // SAFETY: `self.source_fd` is a valid dir fd held for the lifetime of SssFS.
        // `path_cstr` is NUL-terminated. O_PATH|O_NOFOLLOW opens the dirent itself
        // without following the final symlink and without acquiring a read reference.
        unsafe {
            libc::openat(
                self.source_fd,
                path_cstr.as_ptr(),
                libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        }
    }

    /// Implementation of getxattr passthrough.
    #[cfg(target_os = "linux")]
    fn xattr_get_impl(&self, rel_path: &Path, name: &OsStr, size: u32, reply: fuser::ReplyXattr) {
        use std::os::unix::ffi::OsStrExt;

        let fd = self.open_fd_for_xattr(rel_path);
        if fd < 0 {
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(libc::EIO);
            reply.error(errno);
            return;
        }

        let name_cstr = match std::ffi::CString::new(name.as_bytes()) {
            Ok(c) => c,
            Err(_) => {
                // SAFETY: `fd` was just opened via openat() above and is >=0.
                unsafe { libc::close(fd); }
                reply.error(libc::EINVAL);
                return;
            }
        };

        // When size=0 the kernel just wants the size of the value; otherwise we
        // must fill the provided buffer or return ERANGE.
        let (ret, buf): (libc::ssize_t, Vec<u8>) = if size == 0 {
            // SAFETY: `fd` is a valid O_PATH fd. `name_cstr` is NUL-terminated.
            // Passing NULL buffer with size=0 is well-defined — returns value size.
            let r = unsafe {
                libc::fgetxattr(fd, name_cstr.as_ptr(), std::ptr::null_mut(), 0)
            };
            (r, Vec::new())
        } else {
            let mut buf = vec![0u8; size as usize];
            // SAFETY: `fd` is valid, `name_cstr` NUL-terminated, `buf` is a heap slice
            // of exactly `size` bytes. fgetxattr writes at most `size` bytes.
            let r = unsafe {
                libc::fgetxattr(
                    fd,
                    name_cstr.as_ptr(),
                    buf.as_mut_ptr() as *mut libc::c_void,
                    size as usize,
                )
            };
            (r, buf)
        };
        let errno = if ret < 0 {
            std::io::Error::last_os_error().raw_os_error().unwrap_or(libc::ENOTSUP)
        } else { 0 };
        // SAFETY: close the fd opened above regardless of success.
        unsafe { libc::close(fd); }

        if ret < 0 {
            reply.error(errno);
        } else if size == 0 {
            reply.size(ret as u32);
        } else {
            reply.data(&buf[..ret as usize]);
        }
    }

    /// Implementation of listxattr passthrough.
    #[cfg(target_os = "linux")]
    fn xattr_list_impl(&self, rel_path: &Path, size: u32, reply: fuser::ReplyXattr) {
        let fd = self.open_fd_for_xattr(rel_path);
        if fd < 0 {
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(libc::EIO);
            reply.error(errno);
            return;
        }

        let (ret, buf): (libc::ssize_t, Vec<u8>) = if size == 0 {
            // SAFETY: fd valid, NULL buffer with size 0 is documented behaviour.
            let r = unsafe {
                libc::flistxattr(fd, std::ptr::null_mut(), 0)
            };
            (r, Vec::new())
        } else {
            let mut buf = vec![0u8; size as usize];
            // SAFETY: fd valid; buf is a heap slice of exactly `size` bytes.
            let r = unsafe {
                libc::flistxattr(fd, buf.as_mut_ptr() as *mut libc::c_char, size as usize)
            };
            (r, buf)
        };
        let errno = if ret < 0 {
            std::io::Error::last_os_error().raw_os_error().unwrap_or(libc::ENOTSUP)
        } else { 0 };
        // SAFETY: close the fd opened above.
        unsafe { libc::close(fd); }

        if ret < 0 {
            reply.error(errno);
        } else if size == 0 {
            reply.size(ret as u32);
        } else {
            reply.data(&buf[..ret as usize]);
        }
    }

    /// Non-Linux fallback — we don't have fd-relative xattr on macOS (macFUSE adds a
    /// position argument and HFS/APFS xattrs aren't used by SELinux tooling anyway).
    #[cfg(not(target_os = "linux"))]
    fn xattr_get_impl(&self, _rel_path: &Path, _name: &OsStr, _size: u32, reply: fuser::ReplyXattr) {
        reply.error(libc::ENOTSUP);
    }

    #[cfg(not(target_os = "linux"))]
    fn xattr_list_impl(&self, _rel_path: &Path, _size: u32, reply: fuser::ReplyXattr) {
        reply.error(libc::ENOTSUP);
    }
}

impl Filesystem for SssFS {
    /// Initialize filesystem - called when FUSE connection is established
    fn init(
        &mut self,
        _req: &Request<'_>,
        _config: &mut fuser::KernelConfig,
    ) -> Result<(), libc::c_int> {
        fuse_debug!("========== FUSE INIT ==========");
        fuse_debug!("source={:?} pinned_paths={}", self.source_path, self.pinned_paths.len());

        for (_idx, _pinned) in self.pinned_paths.iter().enumerate() {
        }

        fuse_debug!("INIT complete");
        Ok(())
    }

    /// Destroy filesystem - called when FUSE connection is terminated
    fn destroy(&mut self) {
        fuse_debug!("========== FUSE DESTROY ==========");
    }

    /// Get file attributes by inode
    fn getattr(&mut self, _req: &Request, ino: u64, reply: ReplyAttr) {
        let _start = Instant::now();
        fuse_debug!("getattr ino={}", ino);
        // Handle synthetic .overlay directory
        if ino == SYNTHETIC_OVERLAY_DIR_INO {
            // Get attributes from the actual source directory — mirror all metadata
            match self.metadata_via_fd(Path::new(".")) {
                Ok(metadata) => {
                    let attr = FileAttr {
                        ino: SYNTHETIC_OVERLAY_DIR_INO,
                        size: metadata.len(),
                        blocks: Self::get_blocks(&metadata),
                        atime: metadata.accessed().unwrap_or(UNIX_EPOCH),
                        mtime: metadata.modified().unwrap_or(UNIX_EPOCH),
                        ctime: Self::get_ctime(&metadata),
                        crtime: metadata.created().unwrap_or(UNIX_EPOCH),
                        kind: FileType::Directory,
                        perm: Self::get_permissions(&metadata),
                        nlink: Self::get_nlink(&metadata) as u32,
                        uid: Self::get_uid(&metadata),
                        gid: Self::get_gid(&metadata),
                        rdev: Self::get_rdev(&metadata),
                        blksize: Self::get_blksize(&metadata),
                        flags: 0,
                    };
                    reply.attr(&TTL, &attr);
                }
                Err(_e) => {
                    reply.error(libc::EIO);
                }
            }
            return;
        }

        let entry = match self.get_inode(ino) {
            Some(e) => {
                e
            }
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        // Translate virtual path to source path using pinned paths
        let (source_rel_path, pinned) = self.translate_virtual_to_source(&entry.path);

        match self.metadata_via_fd(&source_rel_path) {
            Ok(metadata) => {
                let is_passthrough = pinned.virtual_prefix == Path::new("/.overlay");

                let _is_opened_mode = entry.path.to_str()
                    .map(|s| s.ends_with(".sss-opened"))
                    .unwrap_or(false);

                // Compute size override for rendered/opened modes (passthrough = no override)
                let size_override = if is_passthrough {
                    None
                } else {
                    self.compute_size_override(ino, &metadata)
                };

                // Build FileAttr — mirror all original metadata
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
                    blocks: Self::get_blocks(&metadata),
                    atime: metadata.accessed().unwrap_or(UNIX_EPOCH),
                    mtime: metadata.modified().unwrap_or(UNIX_EPOCH),
                    ctime: Self::get_ctime(&metadata),
                    crtime: metadata.created().unwrap_or(UNIX_EPOCH),
                    kind,
                    perm: Self::get_permissions(&metadata),
                    nlink: Self::get_nlink(&metadata) as u32,
                    uid: Self::get_uid(&metadata),
                    gid: Self::get_gid(&metadata),
                    rdev: Self::get_rdev(&metadata),
                    blksize: Self::get_blksize(&metadata),
                    flags: 0,
                };

                reply.attr(&TTL, &attr);
            }
            Err(_e) => {
                reply.error(libc::ENOENT);
            }
        }
    }

    /// Lookup entry in directory
    fn lookup(&mut self, _req: &Request, parent: u64, name: &OsStr, reply: ReplyEntry) {
        let _start = Instant::now();
        fuse_debug!("lookup parent={} name={:?}", parent, name);

        // Special case: looking up ".overlay" from root
        if parent == ROOT_INO && name == ".overlay" {
            match self.metadata_via_fd(Path::new(".")) {
                Ok(metadata) => {
                    let attr = FileAttr {
                        ino: SYNTHETIC_OVERLAY_DIR_INO,
                        size: metadata.len(),
                        blocks: Self::get_blocks(&metadata),
                        atime: metadata.accessed().unwrap_or(UNIX_EPOCH),
                        mtime: metadata.modified().unwrap_or(UNIX_EPOCH),
                        ctime: Self::get_ctime(&metadata),
                        crtime: metadata.created().unwrap_or(UNIX_EPOCH),
                        kind: FileType::Directory,
                        perm: Self::get_permissions(&metadata),
                        nlink: Self::get_nlink(&metadata) as u32,
                        uid: Self::get_uid(&metadata),
                        gid: Self::get_gid(&metadata),
                        rdev: Self::get_rdev(&metadata),
                        blksize: Self::get_blksize(&metadata),
                        flags: 0,
                    };
                    reply.entry(&TTL, &attr, 0);
                }
                Err(_) => {
                    reply.error(libc::EIO);
                }
            }
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

                // Build FileAttr — mirror all original metadata
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
                    blocks: Self::get_blocks(&metadata),
                    atime: metadata.accessed().unwrap_or(UNIX_EPOCH),
                    mtime: metadata.modified().unwrap_or(UNIX_EPOCH),
                    ctime: Self::get_ctime(&metadata),
                    crtime: metadata.created().unwrap_or(UNIX_EPOCH),
                    kind,
                    perm: Self::get_permissions(&metadata),
                    nlink: Self::get_nlink(&metadata) as u32,
                    uid: Self::get_uid(&metadata),
                    gid: Self::get_gid(&metadata),
                    rdev: Self::get_rdev(&metadata),
                    blksize: Self::get_blksize(&metadata),
                    flags: 0,
                };

                // Use zero TTL for passthrough files to disable kernel caching
                // This prevents stale negative lookups after rename operations
                let ttl = if is_passthrough { &TTL_ZERO } else { &TTL };
                reply.entry(ttl, &attr, 0);
            }
            Err(_e) => {
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
        let _start = Instant::now();
        fuse_debug!("readdir ino={} offset={}", ino, offset);

        // Handle .overlay/ - parent is synthetic, build entry manually
        let entry = if ino == SYNTHETIC_OVERLAY_DIR_INO {
            InodeEntry {
                _ino: SYNTHETIC_OVERLAY_DIR_INO,
                path: PathBuf::from("/.overlay"),
                parent: ROOT_INO,
            }
        } else {
            // Get directory entry from inode table
            match self.get_inode(ino) {
                Some(e) => {
                    e
                },
                None => {
                    reply.error(libc::ENOENT);
                    return;
                }
            }
        };

        // Translate virtual path to source path using pinned paths
        let (source_rel_path, pinned) = self.translate_virtual_to_source(&entry.path);
        // Clone the operations Arc to avoid holding a borrow on self
        let operations = pinned.operations.clone();

        // Open directory via FD
        let dir_ptr = match self.open_dir_fd(&source_rel_path) {
            Ok(p) => {
                p
            },
            Err(_e) => {
                reply.error(libc::EIO);
                return;
            }
        };

        // Build entry list: . and .. first
        let mut items = vec![
            (ino, FileType::Directory, ".".to_string()),
            (entry.parent, FileType::Directory, "..".to_string()),
        ];

        // Read directory entries - use pinned path operations for filtering
        let entries = self.read_dir_entries_with_operations(dir_ptr, ino, &entry.path, &*operations);
        items.extend(entries);

        // If this is the root directory, add synthetic .overlay directory
        if ino == ROOT_INO {
            items.push((SYNTHETIC_OVERLAY_DIR_INO, FileType::Directory, ".overlay".to_string()));
        }

        // Close directory
        // SAFETY: `dir_ptr` is a valid non-null DIR* from `open_dir_fd`; closedir is the
        // matching cleanup call. Not called again after this point.
        unsafe { libc::closedir(dir_ptr); }

        // Send entries to FUSE
        let _entry_count = items.len();
        for (i, item) in items.iter().enumerate().skip(offset as usize) {
            if reply.add(item.0, (i + 1) as i64, item.1, &item.2) {
                break;
            }
        }

        reply.ok();
    }

    /// Open a file
    fn open(&mut self, _req: &Request, ino: u64, flags: i32, reply: ReplyOpen) {
        let _start = Instant::now();
        fuse_debug!("open ino={} flags={:#x}", ino, flags);

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

        fuse_debug!("  open: path={:?}", entry.path);

        // Translate virtual path to source path using pinned paths
        let (source_rel_path, pinned) = self.translate_virtual_to_source(&entry.path);
        let is_passthrough = pinned.virtual_prefix == Path::new("/.overlay");

        fuse_debug!("  open: source_rel={:?} passthrough={}", source_rel_path, is_passthrough);

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

        fuse_debug!("  open: file_path={:?} writable={} sealed={} opened={}", file_path, writable, is_sealed_mode, is_opened_mode);

        // Generate file handle
        let fh = {
            let mut next_fh = self.next_fh.write();
            let fh = *next_fh;
            *next_fh += 1;
            fh
        };

        fuse_debug!("  open: fh={}, starting precache", fh);

        // Pre-cache content based on mode (skip for passthrough - raw access)
        let cached_content = if is_passthrough {
            None
        } else {
            self.precache_for_open(&file_path, is_sealed_mode, is_opened_mode, writable)
        };

        fuse_debug!("  open: precache done, cached={}bytes", cached_content.as_ref().map_or(0, |c| c.len()));

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

            // SAFETY: `self.source_fd` is a valid directory fd. `path_cstr` is NUL-terminated.
            // `open_flags` are caller-supplied FUSE open flags. Mode 0o666 applies only with
            // O_CREAT; the actual mode is masked by umask. Error checked immediately.
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
        let _start = Instant::now();
        fuse_debug!("read ino={} fh={} offset={} size={}", ino, fh, offset, size);

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
            let _bytes_read = end - offset_usize;
            reply.data(&content[offset_usize..end]);
        } else {
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
        let _start = Instant::now();
        fuse_debug!("write ino={} fh={} offset={} size={}", ino, fh, offset, data.len());
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
            // SAFETY: `fd` is a valid open file descriptor from `passthrough_fd` (opened in
            // `open`). `data.as_ptr()` points to `data.len()` valid bytes. `pwrite` does
            // not retain the pointer. `offset` is the FUSE-supplied byte offset.
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
        let _start = Instant::now();
        fuse_debug!("release fh={} flush={}", fh, _flush);
        let mut handles = self.file_handles.write();
        if let Some(handle) = handles.remove(&fh) {
            // Close passthrough fd if present
            if let Some(fd) = handle.passthrough_fd {
                // SAFETY: `fd` is a valid open file descriptor stored in `FileHandle`.
                // We have exclusive access here (handle removed from the map).
                // Not closed anywhere else after removal.
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

        // fuse-t on macOS doesn't support ioctl operations
        // Users should use virtual file suffixes instead:
        //   file.txt.sss-opened for opened mode
        //   file.txt.sss-sealed for sealed mode
        #[cfg(target_os = "macos")]
        {
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
        fuse_debug!("setattr ino={} mode={:?} size={:?}", ino, mode, size);
        // Handle .overlay synthetic directory - return current attributes
        if ino == SYNTHETIC_OVERLAY_DIR_INO {
            match self.metadata_via_fd(Path::new(".")) {
                Ok(metadata) => {
                    let attr = FileAttr {
                        ino: SYNTHETIC_OVERLAY_DIR_INO,
                        size: metadata.len(),
                        blocks: Self::get_blocks(&metadata),
                        atime: metadata.accessed().unwrap_or(UNIX_EPOCH),
                        mtime: metadata.modified().unwrap_or(UNIX_EPOCH),
                        ctime: Self::get_ctime(&metadata),
                        crtime: metadata.created().unwrap_or(UNIX_EPOCH),
                        kind: FileType::Directory,
                        perm: Self::get_permissions(&metadata),
                        nlink: Self::get_nlink(&metadata) as u32,
                        uid: Self::get_uid(&metadata),
                        gid: Self::get_gid(&metadata),
                        rdev: Self::get_rdev(&metadata),
                        blksize: Self::get_blksize(&metadata),
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
            // SAFETY: `self.source_fd` is a valid directory fd. `path_cstr` is NUL-terminated.
            // Error checked immediately; `fd` is closed after use.
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

            // SAFETY: `fd` is valid (>= 0). `ftruncate` adjusts the file size.
            // `close` is called unconditionally after (regardless of ftruncate result).
            let result = unsafe { libc::ftruncate(fd, new_size as i64) };
            // SAFETY: `fd` is valid and not closed yet.
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

            // SAFETY: `self.source_fd` is a valid directory fd. `path_cstr` is NUL-terminated.
            // `new_mode` is a valid mode_t from the FUSE request. Error checked immediately.
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
        let _start = Instant::now();
        fuse_debug!("fsync fh={} datasync={}", fh, datasync);

        // For passthrough files with an fd, sync to flush mmap writes
        let handles = self.file_handles.read();
        if let Some(handle) = handles.get(&fh)
            && let Some(fd) = handle.passthrough_fd {
                // SAFETY: `fd` is a valid open file descriptor stored in `passthrough_fd`.
                // `fdatasync`/`fsync` are always safe to call on a valid fd.
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
                    reply.error(errno);
                    return;
                }
            }

        reply.ok();
    }

    /// Check file access permissions
    fn access(&mut self, _req: &Request, ino: u64, mask: i32, reply: fuser::ReplyEmpty) {
        let _start = Instant::now();
        fuse_debug!("access ino={} mask={:#x}", ino, mask);

        // Handle synthetic directories
        if ino == SYNTHETIC_OVERLAY_DIR_INO {
            reply.ok();
            return;
        }

        // On macOS, faccessat() can deadlock when called from within FUSE handlers
        // because it may try to access through the FUSE mount itself.
        // Since actual permission checks happen at open/read/write time anyway,
        // we can safely return OK here.
        #[cfg(target_os = "macos")]
        {
            reply.ok();
            return;
        }

        #[cfg(not(target_os = "macos"))]
        {
            let entry = match self.get_inode(ino) {
                Some(e) => {
                    e
                }
                None => {
                    reply.error(libc::ENOENT);
                    return;
                }
            };

            // Translate virtual path to source path
            let (source_rel_path, _pinned) = self.translate_virtual_to_source(&entry.path);

            // Use faccessat to check actual permissions
            let path_cstr = match CString::new(source_rel_path.as_os_str().as_bytes()) {
                Ok(p) => p,
                Err(_) => {
                    reply.error(libc::EINVAL);
                    return;
                }
            };

            // faccessat checks access permissions relative to source_fd
            // SAFETY: `self.source_fd` is a valid directory fd. `path_cstr` is NUL-terminated.
            // `mask` is a valid access mode from the FUSE request. Flags=0 uses normal behavior.
            let result = unsafe {
                libc::faccessat(
                    self.source_fd,
                    path_cstr.as_ptr(),
                    mask,
                    0, // flags
                )
            };

            if result == 0 {
                reply.ok();
            } else {
                // SAFETY: `__errno_location`/`__error` return the per-thread errno pointer.
                // Dereferencing to read errno immediately after the failed syscall is safe.
                let errno = unsafe {
                    #[cfg(target_os = "linux")]
                    { *libc::__errno_location() }
                    #[cfg(target_os = "macos")]
                    { *libc::__error() }
                };
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
        let _start = Instant::now();
        fuse_debug!("flush fh={}", fh);

        // For passthrough files, sync to flush any mmap'd writes
        let handles = self.file_handles.read();
        if let Some(handle) = handles.get(&fh) {
            if let Some(fd) = handle.passthrough_fd {
                // Use fdatasync for better performance (only data, not metadata)
                // macOS doesn't have fdatasync, use fsync instead
                // SAFETY: `fd` is a valid open file descriptor stored in `passthrough_fd`.
                // `fdatasync`/`fsync` are safe to call on any valid fd.
                #[cfg(target_os = "linux")]
                let result = unsafe { libc::fdatasync(fd) };
                #[cfg(target_os = "macos")]
                let result = unsafe { libc::fsync(fd) };

                if result < 0 {
                    let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(libc::EIO);
                    reply.error(errno);
                    return;
                }
            }
            reply.ok();
        } else {
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
        fuse_debug!("create parent={} name={:?} flags={:#x}", parent, name, flags);

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
        // SAFETY: `self.source_fd` is valid. `path_cstr` is NUL-terminated. `stat_buf` is
        // zeroed stack memory. Result is only used as a boolean (== 0 means exists).
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

        // SAFETY: `self.source_fd` is valid. `path_cstr` is NUL-terminated. `open_flags`
        // are FUSE-supplied flags. Mode 0o600 restricts to file owner; masked by umask.
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
            // SAFETY: `fd` is valid (>= 0); not stored anywhere; closing here to avoid leak.
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
        fuse_debug!("mkdir parent={} name={:?} mode={:#o}", parent, name, mode);
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

        // SAFETY: `self.source_fd` is valid. `path_cstr` is NUL-terminated. `mode` is from
        // FUSE request; cast to `mode_t` is valid (both are unsigned integers). Error checked.
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
        fuse_debug!("unlink parent={} name={:?}", parent, name);
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

        // SAFETY: `self.source_fd` is a valid directory fd. `path_cstr` is NUL-terminated.
        // flags=0 means unlink the file (not the directory). Error checked immediately.
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
        fuse_debug!("rmdir parent={} name={:?}", parent, name);
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
        // SAFETY: `self.source_fd` is a valid directory fd. `path_cstr` is NUL-terminated.
        // `AT_REMOVEDIR` tells `unlinkat` to remove the directory (equivalent to rmdir).
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
        // SAFETY: `self.source_fd` is a valid directory fd for both old and new paths.
        // Both `old_cstr` and `new_cstr` are NUL-terminated. flags=0 means no special behavior.
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
        fuse_debug!("rename parent={} name={:?} newparent={} newname={:?}", parent, name, newparent, newname);
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


        // SAFETY: `self.source_fd` is a valid directory fd for both paths.
        // Both `old_cstr` and `new_cstr` are NUL-terminated. `renameat` is atomic on POSIX.
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

    /// Get extended attribute — passes through to the backing source file so that
    /// security.selinux and other xattrs observed through the mount match the raw
    /// files (important for tools like stat -Z, ls -Z, restorecon and SELinux-aware
    /// processes such as `openstack undercloud install`).
    fn getxattr(
        &mut self,
        _req: &Request,
        ino: u64,
        name: &OsStr,
        size: u32,
        reply: fuser::ReplyXattr,
    ) {
        let rel_path = match self.resolve_source_for_xattr(ino) {
            Some(p) => p,
            None => { reply.error(libc::ENOENT); return; }
        };
        self.xattr_get_impl(&rel_path, name, size, reply);
    }

    /// List extended attribute names — passthrough, same rationale as getxattr.
    fn listxattr(
        &mut self,
        _req: &Request,
        ino: u64,
        size: u32,
        reply: fuser::ReplyXattr,
    ) {
        let rel_path = match self.resolve_source_for_xattr(ino) {
            Some(p) => p,
            None => { reply.error(libc::ENOENT); return; }
        };
        self.xattr_list_impl(&rel_path, size, reply);
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

        // SAFETY: `link_cstr` (the symlink target) and `name_cstr` (the symlink name) are both
        // NUL-terminated. `self.source_fd` is a valid directory fd. Error checked immediately.
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
        // SAFETY: `self.source_fd` is a valid directory fd. `path_cstr` is NUL-terminated.
        // `buf` is a heap-allocated slice of `PATH_MAX` bytes — sufficient for any symlink target.
        // `readlinkat` writes at most `buf.len()` bytes; we truncate to `len` afterwards.
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
        // SAFETY: `stat` is zeroed stack memory of the correct size for `libc::statfs`.
        // `self.source_fd` is a valid file descriptor (the source directory fd).
        // `fstatfs` writes filesystem statistics into `stat`; result checked before use.
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
        // SAFETY: `self.source_fd` is a valid open fd opened in `new()`. Drop is called
        // exactly once, so there is no double-close. No other code closes `source_fd`.
        unsafe {
            libc::close(self.source_fd);
        }
        // Close the mount point directory file descriptor if present
        if let Some(mount_fd) = self.mount_fd {
            // SAFETY: `mount_fd` is a valid open fd opened in `new()`. Drop is called
            // exactly once. The Option ensures we only close it if it was opened.
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

    // --- CORR-07: FUSE data integrity tests ---
    // Tests for the pure logic layer (mode parsing, file filtering) that guards
    // the read/write transformation pipeline.  Full mount tests live in
    // tests/fuse_integration.rs.

    #[test]
    fn test_transform_fuse_file_mode_all_variants() {
        // CORR-07: parse_virtual_file_mode must correctly classify every recognised
        // virtual suffix so that the correct transformation (render/open/sealed) is
        // applied on read.

        // Rendered — no suffix
        let (name, mode) = SssFS::parse_virtual_file_mode(OsStr::new("secrets.yaml"));
        assert_eq!(name, OsStr::new("secrets.yaml"));
        assert_eq!(mode, FileMode::Rendered, ".yaml with no suffix must be Rendered");

        // Opened — .sss-opened suffix
        let (name, mode) = SssFS::parse_virtual_file_mode(OsStr::new("secrets.yaml.sss-opened"));
        assert_eq!(name, OsStr::new("secrets.yaml"));
        assert_eq!(mode, FileMode::Opened, ".sss-opened suffix must give Opened mode");

        // Sealed — .sss-sealed suffix
        let (name, mode) = SssFS::parse_virtual_file_mode(OsStr::new("secrets.yaml.sss-sealed"));
        assert_eq!(name, OsStr::new("secrets.yaml"));
        assert_eq!(mode, FileMode::Sealed, ".sss-sealed suffix must give Sealed mode");
    }

    #[test]
    fn test_transform_fuse_mode_sealed_takes_priority_over_opened() {
        // CORR-07: when both virtual suffixes are stacked, only the outermost one is
        // stripped — preventing accidental mode mis-classification.
        let (name, mode) = SssFS::parse_virtual_file_mode(OsStr::new("file.sss-opened.sss-sealed"));
        // Outermost suffix is .sss-sealed → Sealed mode; inner suffix remains in basename
        assert_eq!(name, OsStr::new("file.sss-opened"));
        assert_eq!(mode, FileMode::Sealed);
    }

    #[test]
    fn test_transform_fuse_strip_suffix_opened_mode() {
        // CORR-07: strip_virtual_suffix must remove .sss-opened when in opened mode,
        // ensuring writes go to the correct backing-store path (not a .sss-opened file).
        let path = PathBuf::from("/mnt/project/config.toml.sss-opened");
        let stripped = SssFS::strip_virtual_suffix(&path, true);
        assert_eq!(stripped, PathBuf::from("/mnt/project/config.toml"),
            "Opened-mode suffix must be stripped for backing-store writes");
    }

    #[test]
    fn test_transform_fuse_strip_suffix_not_in_opened_mode() {
        // CORR-07: strip_virtual_suffix must be a no-op when not in opened mode —
        // preventing accidental path mutation for normal (Rendered) reads.
        let path = PathBuf::from("/mnt/project/config.toml.sss-opened");
        let stripped = SssFS::strip_virtual_suffix(&path, false);
        assert_eq!(stripped, path, "Path must not be modified when opened_mode=false");
    }

    #[test]
    fn test_transform_fuse_should_process_excludes_editor_artifacts() {
        // CORR-07: editor temporary files must never be passed through the
        // encryption/decryption pipeline — doing so would corrupt them or leak
        // secrets into editor state.
        for artifact in &[
            ".config.yml.swp",   // vim swap
            ".file.swo",         // vim swap (alternate)
            ".notes.swn",        // vim swap (third)
            ".tmp_file.tmp",     // generic temp
            "backup~",           // emacs/vim backup
            "#autosave#",        // emacs auto-save
        ] {
            assert!(
                !SssFS::should_process_with_sss(Path::new(artifact)),
                "Editor artifact {artifact:?} must be excluded from SSS processing"
            );
        }
    }

    #[test]
    fn test_transform_fuse_should_process_includes_regular_files() {
        // CORR-07: regular project files must pass through the encryption pipeline.
        for regular in &[
            "config.toml",
            "secrets.yaml",
            ".env",
            "src/main.rs",
            "README.md",
        ] {
            assert!(
                SssFS::should_process_with_sss(Path::new(regular)),
                "Regular file {regular:?} must be included in SSS processing"
            );
        }
    }
}
