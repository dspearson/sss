/// Application constants for SSS
pub const CONFIG_FILE_NAME: &str = ".sss.toml";

/// Security limits to prevent DoS attacks
pub const MAX_FILE_SIZE: usize = 100 * 1024 * 1024; // 100MB
pub const MAX_MARKER_CONTENT_SIZE: usize = 10 * 1024; // 10KB per marker

/// Editor fallbacks in order of preference
pub const EDITOR_FALLBACKS: &[&str] = &["nano", "vim", "emacs", "vi"];

/// Key rotation constants
pub const ROTATION_BACKUP_PREFIX: &str = ".sss_backup_";
pub const ROTATION_PROGRESS_UPDATE_INTERVAL: usize = 10; // Update progress every N files
pub const ROTATION_MAX_CONCURRENT_FILES: usize = 100; // Max files to process in parallel
