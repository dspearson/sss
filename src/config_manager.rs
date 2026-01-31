#![allow(clippy::missing_errors_doc, clippy::unnecessary_wraps)]

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use crate::project::{HooksConfig, ProjectConfig};
use crate::validation::validate_username;

/// Centralized configuration manager that handles multiple configuration sources
/// with proper precedence: CLI args > Environment > Project config > User config > System defaults
#[derive(Debug)]
pub struct ConfigManager {
    project_config: Option<ProjectConfig>,
    user_settings: UserSettings,
    system_settings: SystemSettings,
    project_path: Option<PathBuf>,
}

/// User-specific settings stored in user config directory
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct UserSettings {
    /// Default username for operations
    pub default_username: Option<String>,
    /// Default editor preference
    pub editor: Option<String>,
    /// Per-project settings and permissions
    #[serde(default)]
    pub projects: HashMap<String, ProjectSettings>,
    /// Keystore configuration
    pub keystore: KeystoreSettings,
    /// UI preferences
    pub ui: UiSettings,
    /// Default secrets filename (e.g., "secrets", ".secrets", "passwords")
    pub secrets_filename: Option<String>,
    /// Default secrets file suffix (e.g., ".secrets", ".sealed", ".passwords")
    pub secrets_suffix: Option<String>,
}

/// Per-project settings and permissions
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProjectSettings {
    /// Allow automatic rendering for this project (used by git hooks)
    #[serde(default)]
    pub allow_auto_render: bool,
    /// Allow automatic opening for this project (used by git hooks)
    #[serde(default)]
    pub allow_auto_open: bool,
    /// Glob patterns to ignore in project-wide operations
    #[serde(default)]
    pub ignore_patterns: Vec<String>,
}

/// Keystore configuration settings
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct KeystoreSettings {
    /// Auto-lock timeout in minutes
    pub auto_lock_minutes: Option<u32>,
    /// Cache password for session
    pub cache_password: Option<bool>,
    /// Maximum key retention count
    pub max_keys: Option<u32>,
    /// KDF security level (interactive, moderate, sensitive)
    pub kdf_level: Option<String>,
    /// Use system keyring for passwordless key storage
    pub use_system_keyring: Option<bool>,
}

/// UI and output preferences
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct UiSettings {
    /// Use coloured output
    pub coloured_output: Option<bool>,
    /// Show progress bars
    pub show_progress: Option<bool>,
    /// Verbosity level (0-3)
    pub verbosity: Option<u8>,
    /// Confirm destructive operations
    pub confirm_destructive: Option<bool>,
}

/// System-wide settings and defaults
#[derive(Debug, Default)]
pub struct SystemSettings {
    pub config_dir: PathBuf,
    pub default_editor: String,
    pub max_file_size: usize,
    pub default_keystore_timeout: u32,
}

impl ConfigManager {
    /// Create a new configuration manager
    pub fn new() -> Result<Self> {
        let system_settings = SystemSettings::load()?;
        let user_settings = UserSettings::load(&system_settings.config_dir)?;

        Ok(Self {
            project_config: None,
            user_settings,
            system_settings,
            project_path: None,
        })
    }

    /// Create a new configuration manager with a custom config directory
    pub fn new_with_config_dir(config_dir: PathBuf) -> Result<Self> {
        let system_settings = SystemSettings::load_with_config_dir(config_dir)?;
        let user_settings = UserSettings::load(&system_settings.config_dir)?;

        Ok(Self {
            project_config: None,
            user_settings,
            system_settings,
            project_path: None,
        })
    }

    /// Load project configuration from a specific path
    pub fn load_project<P: AsRef<Path>>(&mut self, config_path: P) -> Result<()> {
        let config_path = config_path.as_ref();

        if !config_path.exists() {
            return Err(anyhow!(
                "Project configuration not found: {}",
                config_path.display()
            ));
        }

        self.project_config = Some(ProjectConfig::load_from_file(config_path)?);
        self.project_path = Some(config_path.parent().unwrap_or(Path::new(".")).to_path_buf());

        Ok(())
    }

    /// Get the default username from user settings (without precedence logic)
    /// Returns None if no default username is configured
    #[must_use] 
    pub fn get_default_username(&self) -> Option<String> {
        self.user_settings.default_username.clone()
    }

    /// Get the effective username (with precedence)
    pub fn get_username(&self, cli_override: Option<&str>) -> Result<String> {
        // CLI override has highest precedence
        if let Some(username) = cli_override {
            validate_username(username)?;
            return Ok(username.to_string());
        }

        // Environment variable
        if let Ok(username) = env::var("SSS_USER") {
            validate_username(&username)?;
            return Ok(username);
        }

        // User settings
        if let Some(username) = &self.user_settings.default_username {
            validate_username(username)?;
            return Ok(username.clone());
        }

        // System username as fallback
        if let Ok(username) = env::var("USER").or_else(|_| env::var("USERNAME")) {
            validate_username(&username)?;
            return Ok(username);
        }

        Err(anyhow!(
            "No username found. Specify with --user or set SSS_USER environment variable"
        ))
    }

    /// Get the effective editor (with precedence)
    #[must_use] 
    pub fn get_editor(&self, cli_override: Option<&str>) -> String {
        if let Some(editor) = cli_override {
            return editor.to_string();
        }

        if let Ok(editor) = env::var("EDITOR").or_else(|_| env::var("VISUAL")) {
            return editor;
        }

        if let Some(editor) = &self.user_settings.editor {
            return editor.clone();
        }

        self.system_settings.default_editor.clone()
    }

    /// Get keystore auto-lock timeout
    #[must_use] 
    pub fn get_auto_lock_timeout(&self) -> u32 {
        self.user_settings
            .keystore
            .auto_lock_minutes
            .unwrap_or(self.system_settings.default_keystore_timeout)
    }

    /// Get KDF security level with precedence: CLI > ENV > Config > Default (sensitive)
    #[must_use] 
    pub fn get_kdf_level(&self, cli_override: Option<&str>) -> String {
        // CLI override has highest precedence
        if let Some(level) = cli_override {
            return level.to_string();
        }

        // Environment variable
        if let Ok(level) = std::env::var("SSS_KDF_LEVEL") {
            return level;
        }

        // User settings
        if let Some(level) = &self.user_settings.keystore.kdf_level {
            return level.clone();
        }

        // Default to sensitive for better security
        "sensitive".to_string()
    }

    /// Check if system keyring should be used with precedence: CLI > ENV > Config > Default (false)
    #[must_use] 
    pub fn use_system_keyring(&self, cli_override: Option<bool>) -> bool {
        // CLI override has highest precedence
        if let Some(use_keyring) = cli_override {
            return use_keyring;
        }

        // Environment variable
        if let Ok(val) = std::env::var("SSS_USE_KEYRING") {
            return val.to_lowercase() == "true" || val == "1";
        }

        // User settings
        self.user_settings.keystore.use_system_keyring.unwrap_or(false)
    }

    /// Set KDF security level
    pub fn set_kdf_level(&mut self, level: Option<String>) {
        self.user_settings.keystore.kdf_level = level;
    }

    /// Set system keyring preference
    pub fn set_use_system_keyring(&mut self, use_keyring: bool) {
        self.user_settings.keystore.use_system_keyring = Some(use_keyring);
    }

    /// Get UI preferences
    #[must_use] 
    pub fn use_coloured_output(&self) -> bool {
        // Check if output supports colour
        if !atty::is(atty::Stream::Stdout) {
            return false;
        }

        self.user_settings.ui.coloured_output.unwrap_or(true)
    }

    #[must_use] 
    pub fn show_progress(&self) -> bool {
        self.user_settings.ui.show_progress.unwrap_or(true)
    }

    #[must_use] 
    pub fn verbosity_level(&self) -> u8 {
        self.user_settings.ui.verbosity.unwrap_or(1)
    }

    #[must_use] 
    pub fn confirm_destructive(&self) -> bool {
        self.user_settings.ui.confirm_destructive.unwrap_or(true)
    }

    /// Get project users
    pub fn get_project_users(&self) -> Result<Vec<String>> {
        let config = self
            .project_config
            .as_ref()
            .ok_or_else(|| anyhow!("No project configuration loaded"))?;

        Ok(config.list_users())
    }

    /// Check if user exists in project
    pub fn user_exists(&self, username: &str) -> Result<bool> {
        let config = self
            .project_config
            .as_ref()
            .ok_or_else(|| anyhow!("No project configuration loaded"))?;

        Ok(config.users.contains_key(username))
    }

    /// Save user settings
    pub fn save_user_settings(&self) -> Result<()> {
        self.user_settings.save(&self.system_settings.config_dir)
    }

    /// Update user setting
    pub fn set_default_username(&mut self, username: Option<String>) -> Result<()> {
        if let Some(ref username) = username {
            validate_username(username)?;
        }
        self.user_settings.default_username = username;
        Ok(())
    }

    pub fn set_editor(&mut self, editor: Option<String>) {
        self.user_settings.editor = editor;
    }

    pub fn set_coloured_output(&mut self, enabled: bool) {
        self.user_settings.ui.coloured_output = Some(enabled);
    }

    /// Get the current project path
    #[must_use] 
    pub fn project_path(&self) -> Option<&Path> {
        self.project_path.as_deref()
    }

    /// Get merged hooks configuration
    #[must_use] 
    pub fn get_hooks_config(&self) -> HooksConfig {
        self.project_config
            .as_ref()
            .map(|c| c.hooks.clone())
            .unwrap_or_default()
    }

    // Project-specific settings methods

    /// Get all configured projects
    #[must_use] 
    pub fn get_all_projects(&self) -> &HashMap<String, ProjectSettings> {
        &self.user_settings.projects
    }

    /// Enable automatic rendering for a project
    pub fn enable_project_render(&mut self, project_path: &Path) -> Result<()> {
        let path_str = project_path.to_string_lossy().to_string();
        self.user_settings
            .projects
            .entry(path_str)
            .or_default()
            .allow_auto_render = true;
        Ok(())
    }

    /// Disable automatic rendering for a project
    pub fn disable_project_render(&mut self, project_path: &Path) -> Result<()> {
        let path_str = project_path.to_string_lossy().to_string();
        if let Some(settings) = self.user_settings.projects.get_mut(&path_str) {
            settings.allow_auto_render = false;
        }
        Ok(())
    }

    /// Enable automatic opening for a project
    pub fn enable_project_open(&mut self, project_path: &Path) -> Result<()> {
        let path_str = project_path.to_string_lossy().to_string();
        self.user_settings
            .projects
            .entry(path_str)
            .or_default()
            .allow_auto_open = true;
        Ok(())
    }

    /// Disable automatic opening for a project
    pub fn disable_project_open(&mut self, project_path: &Path) -> Result<()> {
        let path_str = project_path.to_string_lossy().to_string();
        if let Some(settings) = self.user_settings.projects.get_mut(&path_str) {
            settings.allow_auto_open = false;
        }
        Ok(())
    }

    /// Check if automatic rendering is enabled for a project
    pub fn is_project_render_enabled(&self, project_path: &Path) -> Result<bool> {
        let path_str = project_path.to_string_lossy().to_string();
        Ok(self
            .user_settings
            .projects
            .get(&path_str)
            .is_some_and(|s| s.allow_auto_render))
    }

    /// Check if automatic opening is enabled for a project
    pub fn is_project_open_enabled(&self, project_path: &Path) -> Result<bool> {
        let path_str = project_path.to_string_lossy().to_string();
        Ok(self
            .user_settings
            .projects
            .get(&path_str)
            .is_some_and(|s| s.allow_auto_open))
    }

    /// Remove a project from settings
    pub fn remove_project(&mut self, project_path: &Path) -> Result<bool> {
        let path_str = project_path.to_string_lossy().to_string();
        Ok(self.user_settings.projects.remove(&path_str).is_some())
    }

    /// Add an ignore pattern for a project
    pub fn add_ignore_pattern(&mut self, project_path: &Path, pattern: String) -> Result<()> {
        let path_str = project_path.to_string_lossy().to_string();
        let settings = self
            .user_settings
            .projects
            .entry(path_str)
            .or_default();

        if !settings.ignore_patterns.contains(&pattern) {
            settings.ignore_patterns.push(pattern);
        }
        Ok(())
    }

    /// Remove an ignore pattern from a project
    pub fn remove_ignore_pattern(&mut self, project_path: &Path, pattern: &str) -> Result<bool> {
        let path_str = project_path.to_string_lossy().to_string();
        if let Some(settings) = self.user_settings.projects.get_mut(&path_str)
            && let Some(pos) = settings.ignore_patterns.iter().position(|p| p == pattern) {
                settings.ignore_patterns.remove(pos);
                return Ok(true);
            }
        Ok(false)
    }

    /// Get ignore patterns for a project
    pub fn get_ignore_patterns(&self, project_path: &Path) -> Result<Vec<String>> {
        let path_str = project_path.to_string_lossy().to_string();
        Ok(self
            .user_settings
            .projects
            .get(&path_str)
            .map(|s| s.ignore_patterns.clone())
            .unwrap_or_default())
    }

    /// Get the effective secrets filename with precedence:
    /// Project config > User settings > Default ("secrets")
    #[must_use] 
    pub fn get_secrets_filename(&self) -> String {
        // Check project config first
        if let Some(ref config) = self.project_config
            && let Some(ref filename) = config.secrets_filename {
                return filename.clone();
            }

        // Check user settings
        if let Some(ref filename) = self.user_settings.secrets_filename {
            return filename.clone();
        }

        // Default
        "secrets".to_string()
    }

    /// Get the effective secrets file suffix with precedence:
    /// Project config > User settings > Default (".secrets")
    #[must_use] 
    pub fn get_secrets_suffix(&self) -> String {
        // Check project config first
        if let Some(ref config) = self.project_config
            && let Some(ref suffix) = config.secrets_suffix {
                return suffix.clone();
            }

        // Check user settings
        if let Some(ref suffix) = self.user_settings.secrets_suffix {
            return suffix.clone();
        }

        // Default
        ".secrets".to_string()
    }

    /// Set the secrets filename in user settings
    pub fn set_secrets_filename(&mut self, filename: Option<String>) {
        self.user_settings.secrets_filename = filename;
    }

    /// Set the secrets suffix in user settings
    pub fn set_secrets_suffix(&mut self, suffix: Option<String>) {
        self.user_settings.secrets_suffix = suffix;
    }
}

impl Default for ConfigManager {
    fn default() -> Self {
        Self::new().expect("Failed to create default ConfigManager")
    }
}

impl UserSettings {
    /// Load user settings from config directory
    fn load(config_dir: &Path) -> Result<Self> {
        let settings_path = config_dir.join("settings.toml");

        if !settings_path.exists() {
            return Ok(Self::default());
        }

        let content = fs::read_to_string(&settings_path)
            .map_err(|e| anyhow!("Failed to read user settings: {e}"))?;

        let settings: Self = toml::from_str(&content)
            .map_err(|e| anyhow!("Failed to parse user settings: {e}"))?;

        Ok(settings)
    }

    /// Save user settings to config directory
    fn save(&self, config_dir: &Path) -> Result<()> {
        fs::create_dir_all(config_dir)
            .map_err(|e| anyhow!("Failed to create config directory: {e}"))?;

        let settings_path = config_dir.join("settings.toml");
        let content = toml::to_string_pretty(self)
            .map_err(|e| anyhow!("Failed to serialise user settings: {e}"))?;

        fs::write(&settings_path, content)
            .map_err(|e| anyhow!("Failed to write user settings: {e}"))?;

        Ok(())
    }
}

impl SystemSettings {
    fn load() -> Result<Self> {
        let config_dir = dirs::config_dir()
            .ok_or_else(|| anyhow!("Could not determine config directory"))?
            .join("sss");

        Self::load_with_config_dir(config_dir)
    }

    fn load_with_config_dir(config_dir: PathBuf) -> Result<Self> {
        let default_editor = if cfg!(windows) {
            "notepad".to_string()
        } else {
            "nano".to_string()
        };

        Ok(Self {
            config_dir,
            default_editor,
            max_file_size: 100 * 1024 * 1024, // 100MB
            default_keystore_timeout: 30,     // 30 minutes
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_config_manager_creation() {
        let config_manager = ConfigManager::new();
        assert!(config_manager.is_ok());
    }

    #[test]
    fn test_username_precedence() {
        let config_manager = ConfigManager::new().unwrap();

        // CLI override should take precedence
        let username = config_manager.get_username(Some("cli_user"));
        assert!(username.is_ok());
        assert_eq!(username.unwrap(), "cli_user");
    }

    #[test]
    fn test_editor_fallback() {
        let config_manager = ConfigManager::new().unwrap();

        // Should return system default when no override
        let editor = config_manager.get_editor(None);
        assert!(!editor.is_empty());
    }

    #[test]
    fn test_user_settings_save_load() {
        let temp_dir = TempDir::new().unwrap();
        let config_dir = temp_dir.path();

        let settings = UserSettings {
            default_username: Some("testuser".to_string()),
            editor: Some("vim".to_string()),
            ..Default::default()
        };

        // Save settings
        assert!(settings.save(config_dir).is_ok());

        // Load settings
        let loaded_settings = UserSettings::load(config_dir).unwrap();
        assert_eq!(
            loaded_settings.default_username,
            Some("testuser".to_string())
        );
        assert_eq!(loaded_settings.editor, Some("vim".to_string()));
    }

    // --- CORR-10: Config loading precedence tests ---

    /// Build a ConfigManager backed by a fresh temp dir (no real user config)
    fn make_config_manager_with_user_editor(editor: Option<&str>) -> (ConfigManager, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let config_dir = temp_dir.path().to_path_buf();

        // Write settings.toml with the requested editor value using the proper serialization
        // path (round-trip through UserSettings) to guarantee valid TOML structure.
        if let Some(ed) = editor {
            let settings = UserSettings {
                editor: Some(ed.to_string()),
                ..Default::default()
            };
            settings.save(&config_dir).unwrap();
        }

        let manager = ConfigManager::new_with_config_dir(config_dir).unwrap();
        (manager, temp_dir)
    }

    #[test]
    fn test_editor_precedence_cli_override_wins() {
        // CORR-10: CLI override must be the highest-priority source.
        let (manager, _dir) = make_config_manager_with_user_editor(Some("nano"));
        let editor = manager.get_editor(Some("emacs"));
        assert_eq!(editor, "emacs", "CLI override must take precedence over user settings");
    }

    #[test]
    fn test_editor_precedence_user_settings_used_when_no_env() {
        // CORR-10: when no CLI override is provided and no EDITOR/VISUAL env var is set,
        // the value from user settings (settings.toml) must be returned.
        // We temporarily remove EDITOR/VISUAL from the environment for this test.
        let (manager, _dir) = make_config_manager_with_user_editor(Some("vim"));

        // Guard: only run this check when the environment doesn't already set EDITOR/VISUAL,
        // since we cannot safely mutate env vars in a multi-threaded test binary.
        if env::var("EDITOR").is_err() && env::var("VISUAL").is_err() {
            let editor = manager.get_editor(None);
            assert_eq!(editor, "vim", "User settings editor should be returned when no env var is set");
        }
        // If EDITOR/VISUAL are set by the test environment, the env-var layer will win
        // (which is correct behaviour — this is documented in the else branch below).
        else {
            // Verify that the env var is indeed returned (env wins over user settings).
            let editor = manager.get_editor(None);
            let env_editor = env::var("EDITOR")
                .or_else(|_| env::var("VISUAL"))
                .unwrap();
            assert_eq!(editor, env_editor, "EDITOR/VISUAL env var must override user settings");
        }
    }

    #[test]
    fn test_editor_precedence_system_default_when_no_config() {
        // CORR-10: when no CLI override, no env var (tested conditionally), and no user
        // setting, the system default must be returned.
        let (manager, _dir) = make_config_manager_with_user_editor(None);

        if env::var("EDITOR").is_err() && env::var("VISUAL").is_err() {
            let editor = manager.get_editor(None);
            // System default is platform-dependent ("nano" on Linux/macOS, "notepad" on Windows)
            assert!(!editor.is_empty(), "System default editor must not be empty");
            // Verify it's the platform default (not an empty string or a user value)
            #[cfg(windows)]
            assert_eq!(editor, "notepad");
            #[cfg(not(windows))]
            assert_eq!(editor, "nano");
        }
    }

    #[test]
    fn test_kdf_level_precedence_cli_wins_over_env_and_config() {
        // CORR-10: KDF level has the same CLI > ENV > Config > Default precedence.
        let (manager, _dir) = make_config_manager_with_user_editor(None);
        let level = manager.get_kdf_level(Some("interactive"));
        assert_eq!(level, "interactive", "CLI override must win for KDF level");
    }

    #[test]
    fn test_kdf_level_precedence_default_is_sensitive() {
        // CORR-10: when nothing is configured, KDF level must default to "sensitive"
        // for maximum security.
        let (manager, _dir) = make_config_manager_with_user_editor(None);
        if env::var("SSS_KDF_LEVEL").is_err() {
            let level = manager.get_kdf_level(None);
            assert_eq!(level, "sensitive", "Default KDF level must be 'sensitive'");
        }
    }

    #[test]
    fn test_username_precedence_cli_over_env() {
        // CORR-10: CLI username must override SSS_USER env var.
        let (manager, _dir) = make_config_manager_with_user_editor(None);
        let username = manager.get_username(Some("cli_user")).unwrap();
        assert_eq!(username, "cli_user", "CLI username must take highest precedence");
    }

    #[test]
    fn test_secrets_filename_precedence_default() {
        // CORR-10: when no project config or user settings define secrets_filename,
        // the default "secrets" must be returned.
        let (manager, _dir) = make_config_manager_with_user_editor(None);
        assert_eq!(manager.get_secrets_filename(), "secrets");
    }

    #[test]
    fn test_secrets_suffix_precedence_default() {
        // CORR-10: when no project config or user settings define secrets_suffix,
        // the default ".secrets" must be returned.
        let (manager, _dir) = make_config_manager_with_user_editor(None);
        assert_eq!(manager.get_secrets_suffix(), ".secrets");
    }
}
