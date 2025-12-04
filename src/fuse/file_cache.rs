use parking_lot::RwLock;
use std::collections::HashMap;
use std::path::PathBuf;

/// File handle for tracking open files
pub struct FileHandle {
    pub ino: u64,
    pub path: PathBuf,
    /// Cached content (rendered or original)
    pub cached_content: Option<Vec<u8>>,
    /// Whether the file is open for writing
    pub writable: bool,
    /// Dirty flag for writes
    pub dirty: bool,
    /// Opened mode: return content with ⊕{} markers (for ssse edit)
    pub opened_mode: bool,
    /// Sealed mode: return raw sealed content with ⊠{} markers (signaled by O_NONBLOCK)
    pub sealed_mode: bool,
    /// Origin mode: file is under .overlay/ - raw passthrough with no processing
    pub origin_mode: bool,
    /// File descriptor for passthrough files (kept open for lifetime of handle)
    pub passthrough_fd: Option<i32>,
    /// Original sealed content from backing store (captured at open time for writable files)
    /// Used for smart reconstruction when editor truncates file before writing
    pub original_sealed: Option<String>,
}

/// Manages file handles and content caching for open files
///
/// The FileCache is responsible for:
/// - Allocating unique file handle IDs
/// - Managing open file handles with their metadata
/// - Caching rendered content for performance
/// - Tracking file open modes (rendered/opened/sealed/origin)
///
/// # Thread Safety
/// All operations use RwLock for thread-safe concurrent access required by FUSE.
pub struct FileCache {
    /// Open file handles with cached content and mode flags
    file_handles: RwLock<HashMap<u64, FileHandle>>,

    /// Next available file handle ID (atomic counter)
    next_fh: RwLock<u64>,

    /// Cache of rendered file contents (inode -> decrypted bytes)
    render_cache: RwLock<HashMap<u64, Vec<u8>>>,
}

impl FileCache {
    /// Creates a new FileCache with empty state
    pub fn new() -> Self {
        Self {
            file_handles: RwLock::new(HashMap::new()),
            next_fh: RwLock::new(1),
            render_cache: RwLock::new(HashMap::new()),
        }
    }

    /// Allocates a new file handle ID and registers the handle
    ///
    /// # Arguments
    /// * `handle` - The file handle to register
    ///
    /// # Returns
    /// The allocated file handle ID
    pub fn create_handle(&self, handle: FileHandle) -> u64 {
        let mut handles = self.file_handles.write();
        let mut next_fh = self.next_fh.write();

        let fh = *next_fh;
        *next_fh += 1;

        handles.insert(fh, handle);
        fh
    }

    /// Retrieves a file handle by ID (read-only access)
    ///
    /// # Arguments
    /// * `fh` - The file handle ID
    /// * `accessor` - Closure that accesses the handle
    ///
    /// # Returns
    /// Result of the accessor closure, or None if handle doesn't exist
    pub fn with_handle<F, R>(&self, fh: u64, accessor: F) -> Option<R>
    where
        F: FnOnce(&FileHandle) -> R,
    {
        let handles = self.file_handles.read();
        handles.get(&fh).map(accessor)
    }

    /// Retrieves a file handle by ID (mutable access)
    ///
    /// # Arguments
    /// * `fh` - The file handle ID
    /// * `accessor` - Closure that modifies the handle
    ///
    /// # Returns
    /// Result of the accessor closure, or None if handle doesn't exist
    pub fn with_handle_mut<F, R>(&self, fh: u64, accessor: F) -> Option<R>
    where
        F: FnOnce(&mut FileHandle) -> R,
    {
        let mut handles = self.file_handles.write();
        handles.get_mut(&fh).map(accessor)
    }

    /// Removes and returns a file handle
    ///
    /// # Arguments
    /// * `fh` - The file handle ID to remove
    ///
    /// # Returns
    /// The removed FileHandle if it existed, None otherwise
    pub fn remove_handle(&self, fh: u64) -> Option<FileHandle> {
        let mut handles = self.file_handles.write();
        handles.remove(&fh)
    }

    /// Caches rendered content for an inode
    ///
    /// # Arguments
    /// * `ino` - The inode number
    /// * `content` - The rendered content to cache
    pub fn cache_rendered_content(&self, ino: u64, content: Vec<u8>) {
        let mut cache = self.render_cache.write();
        cache.insert(ino, content);
    }

    /// Retrieves cached rendered content for an inode
    ///
    /// # Arguments
    /// * `ino` - The inode number
    ///
    /// # Returns
    /// Cloned content if cached, None otherwise
    pub fn get_rendered_content(&self, ino: u64) -> Option<Vec<u8>> {
        let cache = self.render_cache.read();
        cache.get(&ino).cloned()
    }

    /// Invalidates (removes) cached rendered content for an inode
    ///
    /// Should be called when a file is written to ensure fresh content on next read.
    ///
    /// # Arguments
    /// * `ino` - The inode number to invalidate
    pub fn invalidate_render_cache(&self, ino: u64) {
        let mut cache = self.render_cache.write();
        cache.remove(&ino);
    }

    /// Returns the number of open file handles
    ///
    /// Useful for debugging and monitoring file handle usage.
    pub fn handle_count(&self) -> usize {
        let handles = self.file_handles.read();
        handles.len()
    }

    /// Returns the number of cached items
    ///
    /// Useful for debugging and monitoring cache usage.
    pub fn cache_size(&self) -> usize {
        let cache = self.render_cache.read();
        cache.len()
    }

    /// Clears all cached rendered content
    ///
    /// Useful for testing or manual cache invalidation.
    pub fn clear_render_cache(&self) {
        let mut cache = self.render_cache.write();
        cache.clear();
    }
}

impl Default for FileCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn create_test_handle(ino: u64, path: &str) -> FileHandle {
        FileHandle {
            ino,
            path: PathBuf::from(path),
            cached_content: None,
            writable: false,
            dirty: false,
            opened_mode: false,
            sealed_mode: false,
            origin_mode: false,
            passthrough_fd: None,
            original_sealed: None,
        }
    }

    #[test]
    fn test_file_cache_creation() {
        let cache = FileCache::new();
        assert_eq!(cache.handle_count(), 0);
        assert_eq!(cache.cache_size(), 0);
    }

    #[test]
    fn test_create_and_get_handle() {
        let cache = FileCache::new();
        let handle = create_test_handle(1, "/test.txt");

        let fh = cache.create_handle(handle);
        assert_eq!(fh, 1); // First handle ID

        // Verify handle exists
        let exists = cache.with_handle(fh, |h| {
            assert_eq!(h.ino, 1);
            assert_eq!(h.path, Path::new("/test.txt"));
            true
        });
        assert_eq!(exists, Some(true));

        // Verify count
        assert_eq!(cache.handle_count(), 1);
    }

    #[test]
    fn test_multiple_handles() {
        let cache = FileCache::new();

        let fh1 = cache.create_handle(create_test_handle(1, "/file1.txt"));
        let fh2 = cache.create_handle(create_test_handle(2, "/file2.txt"));

        assert_eq!(fh1, 1);
        assert_eq!(fh2, 2);
        assert_eq!(cache.handle_count(), 2);
    }

    #[test]
    fn test_modify_handle() {
        let cache = FileCache::new();
        let fh = cache.create_handle(create_test_handle(1, "/test.txt"));

        // Modify handle
        cache.with_handle_mut(fh, |h| {
            h.writable = true;
            h.dirty = true;
        });

        // Verify modifications
        cache.with_handle(fh, |h| {
            assert!(h.writable);
            assert!(h.dirty);
        });
    }

    #[test]
    fn test_remove_handle() {
        let cache = FileCache::new();
        let fh = cache.create_handle(create_test_handle(1, "/test.txt"));

        assert_eq!(cache.handle_count(), 1);

        let removed = cache.remove_handle(fh);
        assert!(removed.is_some());
        assert_eq!(removed.unwrap().ino, 1);

        assert_eq!(cache.handle_count(), 0);

        // Verify handle no longer exists
        let exists = cache.with_handle(fh, |_| true);
        assert_eq!(exists, None);
    }

    #[test]
    fn test_render_cache() {
        let cache = FileCache::new();
        let ino = 42;
        let content = b"Hello, world!".to_vec();

        // Cache content
        cache.cache_rendered_content(ino, content.clone());
        assert_eq!(cache.cache_size(), 1);

        // Retrieve content
        let retrieved = cache.get_rendered_content(ino);
        assert_eq!(retrieved, Some(content));

        // Invalidate cache
        cache.invalidate_render_cache(ino);
        assert_eq!(cache.cache_size(), 0);
        assert_eq!(cache.get_rendered_content(ino), None);
    }

    #[test]
    fn test_clear_render_cache() {
        let cache = FileCache::new();

        cache.cache_rendered_content(1, b"content1".to_vec());
        cache.cache_rendered_content(2, b"content2".to_vec());
        cache.cache_rendered_content(3, b"content3".to_vec());

        assert_eq!(cache.cache_size(), 3);

        cache.clear_render_cache();
        assert_eq!(cache.cache_size(), 0);
    }
}
