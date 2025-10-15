use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
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
    /// Keystore configuration
    pub keystore: KeystoreSettings,
    /// UI preferences
    pub ui: UiSettings,
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
    pub fn get_auto_lock_timeout(&self) -> u32 {
        self.user_settings
            .keystore
            .auto_lock_minutes
            .unwrap_or(self.system_settings.default_keystore_timeout)
    }

    /// Get UI preferences
    pub fn use_coloured_output(&self) -> bool {
        // Check if output supports colour
        if !atty::is(atty::Stream::Stdout) {
            return false;
        }

        self.user_settings.ui.coloured_output.unwrap_or(true)
    }

    pub fn show_progress(&self) -> bool {
        self.user_settings.ui.show_progress.unwrap_or(true)
    }

    pub fn verbosity_level(&self) -> u8 {
        self.user_settings.ui.verbosity.unwrap_or(1)
    }

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
    pub fn project_path(&self) -> Option<&Path> {
        self.project_path.as_deref()
    }

    /// Get merged hooks configuration
    pub fn get_hooks_config(&self) -> HooksConfig {
        self.project_config
            .as_ref()
            .map(|c| c.hooks.clone())
            .unwrap_or_default()
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
            .map_err(|e| anyhow!("Failed to read user settings: {}", e))?;

        let settings: Self = toml::from_str(&content)
            .map_err(|e| anyhow!("Failed to parse user settings: {}", e))?;

        Ok(settings)
    }

    /// Save user settings to config directory
    fn save(&self, config_dir: &Path) -> Result<()> {
        fs::create_dir_all(config_dir)
            .map_err(|e| anyhow!("Failed to create config directory: {}", e))?;

        let settings_path = config_dir.join("settings.toml");
        let content = toml::to_string_pretty(self)
            .map_err(|e| anyhow!("Failed to serialise user settings: {}", e))?;

        fs::write(&settings_path, content)
            .map_err(|e| anyhow!("Failed to write user settings: {}", e))?;

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
}
