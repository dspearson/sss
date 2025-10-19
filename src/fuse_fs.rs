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
use std::time::{Duration, UNIX_EPOCH};

use crate::Processor;

const TTL: Duration = Duration::from_secs(1);
const ROOT_INO: u64 = 1;

// Custom ioctl command for ssse edit to request opened mode (with ⊕{} markers)
const SSS_IOC_OPENED_MODE: u32 = 0x5353_0001; // 'SS' magic + command 1
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
}

impl SssFS {
    /// Creates a new FUSE filesystem for transparent sss encryption/decryption.
    ///
    /// # Arguments
    ///
    /// * `source_path` - Path to the directory containing files to be transparently processed
    /// * `processor` - Configured [`Processor`] instance for encryption/decryption operations
    ///
    /// # Returns
    ///
    /// Returns `Ok(SssFS)` if successful, or an error if:
    /// - The source path doesn't exist
    /// - The source path is not a directory
    /// - The source directory cannot be opened (permission denied, etc.)
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use sss::fuse_fs::SssFS;
    /// # use sss::{Processor, RepositoryKey};
    /// # use std::path::PathBuf;
    /// # fn example() -> anyhow::Result<()> {
    /// let source = PathBuf::from("/path/to/project");
    /// let key = RepositoryKey::new();
    /// let processor = Processor::new(key)?;
    /// let fs = SssFS::new(source, processor)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(source_path: PathBuf, processor: Processor) -> Result<Self> {
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

        Ok(Self {
            source_path,
            source_fd,
            processor,
            inode_table: RwLock::new(inode_table),
            path_to_ino: RwLock::new(path_to_ino),
            next_ino: RwLock::new(ROOT_INO + 1),
            file_handles: RwLock::new(HashMap::new()),
            next_fh: RwLock::new(1),
            render_cache: RwLock::new(HashMap::new()),
        })
    }

    /// Get the real path for a given virtual path
    fn real_path(&self, virtual_path: &Path) -> PathBuf {
        if virtual_path == Path::new("/") {
            self.source_path.clone()
        } else {
            self.source_path.join(virtual_path.strip_prefix("/").unwrap())
        }
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
        let kind = if metadata.is_dir() {
            FileType::Directory
        } else if metadata.is_symlink() {
            FileType::Symlink
        } else {
            FileType::RegularFile
        };

        // Use override size for rendered content
        let size = size_override.unwrap_or(metadata.len());

        // Get base permissions and add write if needed
        let mut perm = Self::get_permissions(metadata);
        if force_writable && kind == FileType::RegularFile {
            // Ensure owner write permission (0o200)
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
            nlink: 1,
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

    /// Check if a file has encrypted markers (should be processed)
    fn has_encrypted_markers(content: &str) -> bool {
        content.contains("⊠{")
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
        use std::os::unix::ffi::OsStrExt;

        let path_bytes = rel_path.as_os_str().as_bytes();
        let path_cstr = std::ffi::CString::new(path_bytes)?;

        let mut stat: libc::stat = unsafe { std::mem::zeroed() };

        let result = unsafe {
            libc::fstatat(self.source_fd, path_cstr.as_ptr(), &mut stat, 0)
        };

        if result < 0 {
            return Err(anyhow!("Failed to stat file: {}", std::io::Error::last_os_error()));
        }

        // Convert libc::stat to std::fs::Metadata
        // We need to open the file briefly to get proper Metadata
        let fd = unsafe {
            libc::openat(self.source_fd, path_cstr.as_ptr(), libc::O_RDONLY)
        };

        if fd < 0 {
            return Err(anyhow!("Failed to open file for metadata: {}", std::io::Error::last_os_error()));
        }

        let file = unsafe { std::fs::File::from_raw_fd(fd) };
        Ok(file.metadata()?)
    }

    /// Read file using source_fd (works even if mounted over source)
    fn read_file_via_fd(&self, rel_path: &Path) -> Result<Vec<u8>> {
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

    /// Generic file reading with optional processing
    /// Reduces duplication across read_and_render, read_and_open, and read_sealed
    fn read_and_process<F>(&self, path: &Path, process_fn: F) -> Result<Vec<u8>>
    where
        F: FnOnce(&Self, String) -> Result<String>,
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

        // Apply processing function
        let processed = process_fn(self, content)?;
        Ok(processed.into_bytes())
    }

    fn read_and_render(&self, path: &Path) -> Result<Vec<u8>> {
        self.read_and_process(path, |fs, content| {
            // Only process if file has encrypted markers
            if Self::has_encrypted_markers(&content) {
                // Decrypt and render (remove all markers)
                fs.processor.decrypt_to_raw(&content)
            } else {
                // Return as-is for non-encrypted files
                Ok(content)
            }
        })
    }

    /// Read and open a file (decrypt ⊠{} → ⊕{} but keep markers for ssse edit)
    fn read_and_open(&self, path: &Path) -> Result<Vec<u8>> {
        self.read_and_process(path, |fs, content| {
            // Only process if file has encrypted markers
            if Self::has_encrypted_markers(&content) {
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
        let path_cstr = CString::new(rel_path.as_os_str().as_bytes())?;

        // Create temporary file via fd
        let temp_name = format!(".{}.tmp", rel_path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unnamed"));
        let temp_rel_path = rel_path.parent()
            .unwrap_or_else(|| Path::new("."))
            .join(&temp_name);
        let temp_path_cstr = CString::new(temp_rel_path.as_os_str().as_bytes())?;

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
                sealed_content.as_ptr() as *const _,
                sealed_content.len(),
            );
            libc::close(temp_fd);
            bytes_written
        };

        if write_result < 0 || write_result != sealed_content.len() as isize {
            // Clean up temp file
            unsafe {
                libc::unlinkat(self.source_fd, temp_path_cstr.as_ptr(), 0);
            }
            return Err(anyhow!("Failed to write sealed content"));
        }

        // Rename temp to target (atomic)
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

    fn write_and_seal(&self, path: &Path, rendered_content: &[u8]) -> Result<()> {
        // Convert bytes to string
        let rendered_str = String::from_utf8(rendered_content.to_vec())
            .map_err(|_| anyhow!("Content is not valid UTF-8"))?;

        // Read current sealed version FROM BACKING STORE (not through FUSE!)
        let rel_path = path.strip_prefix(&self.source_path).unwrap_or(path);
        let sealed_current = match self.read_file_via_fd(rel_path) {
            Ok(content) => String::from_utf8(content)
                .map_err(|_| anyhow!("Backing file is not valid UTF-8"))?,
            Err(_) => {
                // File doesn't exist or can't be read, write as-is
                return self.write_raw_to_backing(path, rendered_content);
            }
        };

        // If current version has no markers, just write the rendered content
        if !Self::has_encrypted_markers(&sealed_current) {
            return self.write_raw_to_backing(path, rendered_content);
        }

        // Perform smart reconstruction:
        // 1. Open (decrypt) current sealed version to get markers
        let opened_current = self.processor.decrypt_content(&sealed_current)?;

        // 2. Render current version for comparison
        let rendered_current = self.processor.decrypt_to_raw(&sealed_current)?;

        // 3. Use similar diffing to reconstruct markers (from merge module)
        let reconstructed = crate::merge::smart_reconstruct(&rendered_str, &opened_current, &rendered_current)?;

        // 4. Seal the reconstructed content
        let sealed_new = self.processor.encrypt_content(&reconstructed)?;

        // 5. Write to backing store (not through FUSE!)
        self.write_raw_to_backing(path, sealed_new.as_bytes())
    }


    /// Internal lookup implementation that returns Result
    fn lookup_impl(&mut self, parent: u64, name: &OsStr) -> Result<(u64, FileAttr)> {
        // Hide git-related files from FUSE view
        if let Some(name_str) = name.to_str() {
            if Self::should_hide(name_str) {
                return Err(anyhow!("File hidden"));
            }
        }

        let parent_entry = self.get_inode(parent)
            .ok_or_else(|| anyhow!("Parent inode not found"))?;

        let parent_path = self.real_path(&parent_entry.path);
        let file_path = parent_path.join(name);

        let real_path = self.real_path(&file_path);
        let mut rel_path = real_path.strip_prefix(&self.source_path).unwrap_or(&real_path);

        if rel_path.as_os_str().is_empty() {
            rel_path = Path::new(".");
        }

        let metadata = self.metadata_via_fd(rel_path)?;

        // Get or create inode
        let ino = self.get_or_create_inode(&file_path, parent);
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

    /// Cache file content based on mode and return size override
    fn cache_file_content(&self, file_mode: FileMode, real_path: &Path, ino: u64) -> Option<u64> {
        match file_mode {
            FileMode::Sealed => {
                self.read_sealed(real_path).ok().map(|sealed| {
                    let size = sealed.len() as u64;
                    self.render_cache.write().insert(ino, sealed);
                    size
                })
            }
            FileMode::Opened => {
                self.read_and_open(real_path).ok().map(|opened| {
                    let size = opened.len() as u64;
                    self.render_cache.write().insert(ino, opened);
                    size
                })
            }
            FileMode::Rendered => {
                self.read_and_render(real_path).ok().map(|rendered| {
                    let size = rendered.len() as u64;
                    self.render_cache.write().insert(ino, rendered);
                    size
                })
            }
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
            // Sealed mode: wait for setxattr confirmation
            None
        } else if is_opened_mode {
            // Opened mode: pre-cache with markers
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

    /// Read all entries from an open directory
    fn read_dir_entries(&mut self, dir_ptr: *mut libc::DIR, parent_ino: u64, parent_path: &Path)
        -> Vec<(u64, FileType, String)> {
        let mut items = Vec::new();

        unsafe {
            loop {
                *libc::__errno_location() = 0;
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

                // Hide git-related files
                if Self::should_hide(&name) {
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
            handle_size
        } else {
            // Fallback to render cache
            let cache = self.render_cache.read();
            cache.get(&ino).map(|content| content.len() as u64)
        }
    }

    /// Resolve entry path to relative path suitable for fd operations
    /// Handles prefix stripping and empty path conversion to "."
    fn resolve_rel_path<'a>(&self, entry_path: &'a Path) -> std::borrow::Cow<'a, Path> {
        let real_path = self.real_path(entry_path);
        let rel_path = real_path.strip_prefix(&self.source_path)
            .unwrap_or(&real_path);

        if rel_path.as_os_str().is_empty() {
            std::borrow::Cow::Borrowed(Path::new("."))
        } else {
            std::borrow::Cow::Owned(rel_path.to_path_buf())
        }
    }
}

impl Filesystem for SssFS {
    /// Get file attributes by inode
    fn getattr(&mut self, _req: &Request, ino: u64, reply: ReplyAttr) {
        let entry = match self.get_inode(ino) {
            Some(e) => e,
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        let rel_path = self.resolve_rel_path(&entry.path);

        match self.metadata_via_fd(&rel_path) {
            Ok(metadata) => {
                let is_opened_mode = entry.path.to_str()
                    .map(|s| s.ends_with(".sss-opened"))
                    .unwrap_or(false);

                let size_override = self.compute_size_override(ino, &metadata);
                let attr = self.metadata_to_attr(ino, &metadata, size_override, is_opened_mode);
                reply.attr(&TTL, &attr);
            }
            Err(_) => reply.error(libc::ENOENT),
        }
    }

    /// Lookup entry in directory
    fn lookup(&mut self, _req: &Request, parent: u64, name: &OsStr, reply: ReplyEntry) {

        // Parse virtual file mode (.sss-sealed, .sss-opened, or normal)
        let (actual_name, file_mode) = Self::parse_virtual_file_mode(name);
        let is_opened_mode = matches!(file_mode, FileMode::Opened);

        // Hide git-related files from FUSE view
        if let Some(name_str) = actual_name.to_str() {
            if Self::should_hide(name_str) {
                reply.error(libc::ENOENT);
                return;
            }
        }

        let parent_entry = match self.get_inode(parent) {
            Some(e) => e,
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        // Build paths
        let virtual_path = if is_opened_mode {
            parent_entry.path.join(name) // Keep .sss-opened suffix
        } else {
            parent_entry.path.join(actual_name)
        };
        let real_path = self.real_path(&parent_entry.path.join(actual_name));
        let rel_path = real_path.strip_prefix(&self.source_path)
            .unwrap_or(&real_path);
        let rel_path = if rel_path.as_os_str().is_empty() {
            Path::new(".")
        } else {
            rel_path
        };


        match self.metadata_via_fd(rel_path) {
            Ok(metadata) => {
                let ino = self.get_or_create_inode(&virtual_path, parent);

                let (size_override, force_writable) = if metadata.is_file() {
                    (self.cache_file_content(file_mode, &real_path, ino), is_opened_mode)
                } else {
                    (None, false)
                };

                let attr = self.metadata_to_attr(ino, &metadata, size_override, force_writable);
                reply.entry(&TTL, &attr, 0);
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

        let entry = match self.get_inode(ino) {
            Some(e) => e,
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        let rel_path = self.resolve_rel_path(&entry.path);

        // Open directory via FD
        let dir_ptr = match self.open_dir_fd(&rel_path) {
            Ok(p) => p,
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

        // Read directory entries
        items.extend(self.read_dir_entries(dir_ptr, ino, &entry.path));

        // Close directory
        unsafe { libc::closedir(dir_ptr); }


        // Send entries to FUSE
        for (i, item) in items.iter().enumerate().skip(offset as usize) {
            if reply.add(item.0, (i + 1) as i64, item.1, &item.2) {
                break;
            }
        }

        reply.ok();
    }

    /// Open a file
    fn open(&mut self, _req: &Request, ino: u64, flags: i32, reply: ReplyOpen) {

        let entry = match self.get_inode(ino) {
            Some(e) => e,
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        // Determine file modes
        let is_opened_mode = entry.path.to_str()
            .map(|s| s.ends_with(".sss-opened"))
            .unwrap_or(false);
        let is_sealed_mode = (flags & libc::O_NONBLOCK) != 0;
        let writable = (flags & libc::O_RDWR) != 0 || (flags & libc::O_WRONLY) != 0;

        
        

        // Strip virtual suffix and get real file path
        let real_path = self.real_path(&entry.path);
        let file_path = Self::strip_virtual_suffix(&real_path, is_opened_mode);

        // Generate file handle
        let fh = {
            let mut next_fh = self.next_fh.write();
            let fh = *next_fh;
            *next_fh += 1;
            fh
        };

        // Pre-cache content based on mode
        let cached_content = self.precache_for_open(&file_path, is_sealed_mode, is_opened_mode, writable);

        // Store file handle
        let handle = FileHandle {
            ino,
            path: file_path,
            cached_content,
            writable,
            dirty: false,
            opened_mode: is_opened_mode,
            sealed_mode: is_sealed_mode,
        };

        self.file_handles.write().insert(fh, handle);
        reply.opened(fh, 0);
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

        // Get content from handle or fall back to direct read
        let handles = self.file_handles.read();
        let content = match handles.get(&fh) {
            Some(handle) => {
                // Sealed mode pending: wait for setxattr confirmation
                if handle.sealed_mode && handle.cached_content.is_none() {
                    reply.error(libc::EAGAIN);
                    return;
                }

                // Get content based on handle mode
                match self.get_handle_content(handle) {
                    Ok(c) => c,
                    Err(_e) => {
                        reply.error(libc::EIO);
                        return;
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

                let real_path = self.real_path(&entry.path);
                match self.read_and_render(&real_path) {
                    Ok(c) => c,
                    Err(_e) => {
                        reply.error(libc::EIO);
                        return;
                    }
                }
            }
        };

        // Return requested slice
        let start = offset as usize;
        let end = std::cmp::min(start + size as usize, content.len());

        if start < content.len() {
            reply.data(&content[start..end]);
        } else {
            reply.data(&[]);
        }
    }

    /// Write file data
    fn write(
        &mut self,
        _req: &Request,
        _ino: u64,
        fh: u64,
        offset: i64,
        data: &[u8],
        _write_flags: u32,
        _flags: i32,
        _lock: Option<u64>,
        reply: ReplyWrite,
    ) {
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
        let mut handles = self.file_handles.write();
        if let Some(handle) = handles.remove(&fh) {
            // If file was written to, seal and write back
            if handle.dirty && handle.writable {
                if let Some(content) = handle.cached_content {
                    // Convert content to string for analysis
                    let content_str = String::from_utf8_lossy(&content);

                    // Check if content already has encrypted markers (⊠{})
                    let is_already_sealed = Self::has_encrypted_markers(&content_str);

                    // Check if this file should be processed by sss or written raw
                    let write_result = if !Self::should_process_with_sss(&handle.path) {
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
                        self.write_and_seal(&handle.path, &content)
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
        }
        reply.ok();
    }

    /// Handle ioctl commands
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
                    new_mode,
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
        _fh: u64,
        _datasync: bool,
        reply: fuser::ReplyEmpty,
    ) {
        // No-op for now - writes are already synchronous
        reply.ok();
    }

    /// Check file access permissions
    fn access(&mut self, _req: &Request, ino: u64, _mask: i32, reply: fuser::ReplyEmpty) {
        // For simplicity, allow all access
        // In a more secure implementation, we'd check actual permissions
        let entry = match self.get_inode(ino) {
            Some(e) => e,
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        let real_path = self.real_path(&entry.path);
        let mut rel_path = real_path.strip_prefix(&self.source_path).unwrap_or(&real_path);

        if rel_path.as_os_str().is_empty() {
            rel_path = Path::new(".");
        }

        // Check if file exists via fd
        match self.metadata_via_fd(rel_path) {
            Ok(_) => reply.ok(),
            Err(_) => reply.error(libc::EACCES),
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
        // Check if file handle exists
        let handles = self.file_handles.read();
        if handles.contains_key(&fh) {
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
        // Get parent directory path
        let parent_entry = match self.get_inode(parent) {
            Some(e) => e,
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        let parent_path = self.real_path(&parent_entry.path);
        let file_path = parent_path.join(name);

        // Create the file in the backing store
        let rel_path = file_path.strip_prefix(&self.source_path).unwrap_or(&file_path);
        let path_cstr = match CString::new(rel_path.as_os_str().as_bytes()) {
            Ok(p) => p,
            Err(_) => {
                reply.error(libc::EINVAL);
                return;
            }
        };

        // Create file via fd with O_CREAT | O_EXCL
        let fd = unsafe {
            libc::openat(
                self.source_fd,
                path_cstr.as_ptr(),
                libc::O_CREAT | libc::O_WRONLY | libc::O_EXCL | flags,
                0o644,
            )
        };

        if fd < 0 {
            reply.error(libc::EIO);
            return;
        }

        unsafe { libc::close(fd) };

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
                    writable: (flags & libc::O_WRONLY != 0) || (flags & libc::O_RDWR != 0),
                    dirty: false,
                    opened_mode: false,
                    sealed_mode: false,
                };

                self.file_handles.write().insert(fh, handle);
                reply.created(&TTL, &attr, 0, fh, 0);
            }
            Err(_) => reply.error(libc::EIO),
        }
    }

    /// Remove a file
    fn unlink(&mut self, _req: &Request, parent: u64, name: &OsStr, reply: fuser::ReplyEmpty) {
        let parent_entry = match self.get_inode(parent) {
            Some(e) => e,
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        let parent_path = self.real_path(&parent_entry.path);
        let file_path = parent_path.join(name);
        let rel_path = file_path.strip_prefix(&self.source_path).unwrap_or(&file_path);

        let path_cstr = match CString::new(rel_path.as_os_str().as_bytes()) {
            Ok(p) => p,
            Err(_) => {
                reply.error(libc::EINVAL);
                return;
            }
        };

        let result = unsafe { libc::unlinkat(self.source_fd, path_cstr.as_ptr(), 0) };

        if result == 0 {
            // Remove from inode cache
            let mut inodes = self.inode_table.write();
            inodes.retain(|_, entry| entry.path != file_path.strip_prefix(&self.source_path).unwrap_or(&file_path));
            reply.ok();
        } else {
            reply.error(libc::EIO);
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
        let old_parent_entry = match self.get_inode(parent) {
            Some(e) => e,
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        let new_parent_entry = match self.get_inode(newparent) {
            Some(e) => e,
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        let old_parent_path = self.real_path(&old_parent_entry.path);
        let new_parent_path = self.real_path(&new_parent_entry.path);

        let old_path = old_parent_path.join(name);
        let new_path = new_parent_path.join(newname);

        let old_rel = old_path.strip_prefix(&self.source_path).unwrap_or(&old_path);
        let new_rel = new_path.strip_prefix(&self.source_path).unwrap_or(&new_path);

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
            // Update inode cache
            let mut inodes = self.inode_table.write();
            inodes.retain(|_, entry| entry.path != old_rel);
            reply.ok();
        } else {
            reply.error(libc::EIO);
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
}

impl Drop for SssFS {
    fn drop(&mut self) {
        // Close the source directory file descriptor
        unsafe {
            libc::close(self.source_fd);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_has_encrypted_markers_true() {
        assert!(SssFS::has_encrypted_markers("password: ⊠{abc123}"));
        assert!(SssFS::has_encrypted_markers("⊠{secret}"));
        assert!(SssFS::has_encrypted_markers("prefix ⊠{data} suffix"));
    }

    #[test]
    fn test_has_encrypted_markers_false() {
        assert!(!SssFS::has_encrypted_markers("password: plaintext"));
        assert!(!SssFS::has_encrypted_markers("⊕{plaintext_marker}"));
        assert!(!SssFS::has_encrypted_markers(""));
        assert!(!SssFS::has_encrypted_markers("no markers here"));
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
