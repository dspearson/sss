/// Application constants for SSS
pub const CONFIG_FILE_NAME: &str = ".sss.toml";
pub const BACKUP_FILE_PREFIX: &str = ".";
pub const BACKUP_FILE_SUFFIX: &str = ".sss";

/// Security limits to prevent DoS attacks
pub const MAX_FILE_SIZE: usize = 100 * 1024 * 1024; // 100MB
pub const MAX_MARKER_CONTENT_SIZE: usize = 10 * 1024; // 10KB per marker

/// Editor fallbacks in order of preference
pub const EDITOR_FALLBACKS: &[&str] = &["nano", "vim", "emacs", "vi"];
