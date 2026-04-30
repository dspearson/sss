// FUSE filesystem component modules
//
// This module organizes the FUSE filesystem implementation into focused components:
// - `fs`: Top-level SssFS implementation (libc-FFI filesystem operations)
// - `inode_manager`: Inode allocation and bidirectional path↔inode mapping
// - `file_cache`: Content caching and handle management
// - `virtual_fs`: Virtual file path resolution and operations

pub mod fs;
pub mod inode_manager;
pub mod file_cache;
pub mod virtual_fs;
