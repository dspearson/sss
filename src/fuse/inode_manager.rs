use parking_lot::RwLock;
use std::collections::HashMap;
use std::path::PathBuf;

/// Inode information
#[derive(Clone)]
pub struct InodeEntry {
    pub ino: u64,
    pub path: PathBuf,
    pub parent: u64,
}

/// Manages inode allocation and bidirectional path↔inode mapping
///
/// The InodeManager is responsible for:
/// - Allocating unique inode numbers
/// - Maintaining bidirectional mapping between paths and inodes
/// - Looking up inode information by number
/// - Creating new inode entries for discovered files
///
/// # Thread Safety
/// All operations use RwLock for thread-safe concurrent access required by FUSE.
pub struct InodeManager {
    /// Maps inode numbers to path information
    inode_table: RwLock<HashMap<u64, InodeEntry>>,

    /// Reverse lookup: path to inode number
    path_to_ino: RwLock<HashMap<PathBuf, u64>>,

    /// Next available inode number (atomic counter)
    next_ino: RwLock<u64>,
}

impl InodeManager {
    /// Creates a new InodeManager with root inode pre-allocated
    ///
    /// # Arguments
    /// * `root_ino` - The inode number for the root directory (typically 1)
    /// * `root_path` - The path for the root directory
    pub fn new(root_ino: u64, root_path: PathBuf) -> Self {
        let mut inode_table = HashMap::new();
        let mut path_to_ino = HashMap::new();

        // Pre-allocate root inode
        inode_table.insert(
            root_ino,
            InodeEntry {
                ino: root_ino,
                path: root_path.clone(),
                parent: root_ino, // Root is its own parent
            },
        );
        path_to_ino.insert(root_path, root_ino);

        Self {
            inode_table: RwLock::new(inode_table),
            path_to_ino: RwLock::new(path_to_ino),
            next_ino: RwLock::new(root_ino + 1),
        }
    }

    /// Gets or creates an inode for the given path
    ///
    /// If the path already has an inode assigned, returns the existing inode number.
    /// Otherwise, allocates a new inode number and creates the mapping.
    ///
    /// # Arguments
    /// * `path` - Virtual path within the FUSE filesystem
    /// * `parent_ino` - Inode number of the parent directory
    ///
    /// # Returns
    /// The inode number for the path (either existing or newly allocated)
    pub fn get_or_create_inode(&self, path: PathBuf, parent_ino: u64) -> u64 {
        // Fast path: check if inode already exists
        {
            let path_map = self.path_to_ino.read();
            if let Some(&ino) = path_map.get(&path) {
                return ino;
            }
        }

        // Slow path: allocate new inode
        let mut inode_table = self.inode_table.write();
        let mut path_map = self.path_to_ino.write();
        let mut next_ino = self.next_ino.write();

        // Double-check after acquiring write lock
        if let Some(&ino) = path_map.get(&path) {
            return ino;
        }

        // Allocate new inode number
        let ino = *next_ino;
        *next_ino += 1;

        // Create entry
        let entry = InodeEntry {
            ino,
            path: path.clone(),
            parent: parent_ino,
        };

        // Store in both maps
        inode_table.insert(ino, entry);
        path_map.insert(path, ino);

        ino
    }

    /// Retrieves inode information by inode number
    ///
    /// # Arguments
    /// * `ino` - The inode number to look up
    ///
    /// # Returns
    /// `Some(InodeEntry)` if the inode exists, `None` otherwise
    pub fn get_inode(&self, ino: u64) -> Option<InodeEntry> {
        let table = self.inode_table.read();
        table.get(&ino).cloned()
    }

    /// Gets the inode number for a path if it exists
    ///
    /// # Arguments
    /// * `path` - The path to look up
    ///
    /// # Returns
    /// `Some(u64)` with the inode number if the path is registered, `None` otherwise
    pub fn get_inode_for_path(&self, path: &PathBuf) -> Option<u64> {
        let path_map = self.path_to_ino.read();
        path_map.get(path).copied()
    }

    /// Returns the number of allocated inodes
    ///
    /// Useful for debugging and monitoring inode usage.
    pub fn count(&self) -> usize {
        let table = self.inode_table.read();
        table.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn test_inode_manager_creation() {
        let manager = InodeManager::new(1, PathBuf::from("/"));
        assert_eq!(manager.count(), 1);

        // Root should be accessible
        let root = manager.get_inode(1);
        assert!(root.is_some());
        assert_eq!(root.unwrap().path, Path::new("/"));
    }

    #[test]
    fn test_get_or_create_inode() {
        let manager = InodeManager::new(1, PathBuf::from("/"));

        // Create new inode
        let ino1 = manager.get_or_create_inode(PathBuf::from("/file1.txt"), 1);
        assert_eq!(ino1, 2); // First allocated inode after root

        // Get existing inode
        let ino2 = manager.get_or_create_inode(PathBuf::from("/file1.txt"), 1);
        assert_eq!(ino1, ino2); // Should return same inode

        // Create another new inode
        let ino3 = manager.get_or_create_inode(PathBuf::from("/file2.txt"), 1);
        assert_eq!(ino3, 3); // Next inode number

        assert_eq!(manager.count(), 3);
    }

    #[test]
    fn test_get_inode_for_path() {
        let manager = InodeManager::new(1, PathBuf::from("/"));
        let path = PathBuf::from("/test.txt");

        // Path doesn't exist yet
        assert!(manager.get_inode_for_path(&path).is_none());

        // Create inode
        let ino = manager.get_or_create_inode(path.clone(), 1);

        // Now path should be found
        assert_eq!(manager.get_inode_for_path(&path), Some(ino));
    }

    #[test]
    fn test_bidirectional_mapping() {
        let manager = InodeManager::new(1, PathBuf::from("/"));
        let path = PathBuf::from("/nested/file.txt");

        // Create inode
        let ino = manager.get_or_create_inode(path.clone(), 1);

        // Verify bidirectional mapping
        assert_eq!(manager.get_inode_for_path(&path), Some(ino));

        let entry = manager.get_inode(ino);
        assert!(entry.is_some());
        assert_eq!(entry.unwrap().path, path);
    }
}
