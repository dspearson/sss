//! Edge-case and coverage tests for the secrets and config_manager modules.
//!
//! These tests target parsing edge cases (TEST-04) and settings precedence / corruption
//! handling (TEST-05) that are not exercised by the inline unit tests in secrets.rs and
//! config_manager.rs or by the existing integration tests.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::Result;
use tempfile::TempDir;

use sss::config_manager::{ConfigManager, UserSettings};
use sss::secrets::{parse_secrets_content, SecretsCache, StdFileSystemOps};

// ─────────────────────────────────────────────────────────────────────────────
// Secrets parsing edge cases (TEST-04)
// ─────────────────────────────────────────────────────────────────────────────

/// Empty secrets file returns an empty map without error.
#[test]
fn test_parse_empty_secrets_file() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let path = temp_dir.path().join("secrets");
    fs::write(&path, "")?;

    let secrets = parse_secrets_content("", &path)?;
    assert!(secrets.is_empty(), "Expected empty map for empty content");
    Ok(())
}

/// A secrets file containing only comment lines returns an empty map.
#[test]
fn test_parse_comments_only_returns_empty() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let path = temp_dir.path().join("secrets");

    let content = "# This is a comment\n# Another comment\n\n# Yet another\n";
    let secrets = parse_secrets_content(content, &path)?;
    assert!(secrets.is_empty(), "Comment-only file should produce empty map");
    Ok(())
}

/// When a key appears more than once the last value wins.
#[test]
fn test_parse_duplicate_key_last_value_wins() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let path = temp_dir.path().join("secrets");

    let content = "API_KEY: first_value\nAPI_KEY: second_value\n";
    let secrets = parse_secrets_content(content, &path)?;
    assert_eq!(
        secrets.get("API_KEY").map(String::as_str),
        Some("second_value"),
        "Duplicate key should resolve to last value"
    );
    Ok(())
}

/// A UTF-8 BOM (\u{FEFF}) at the very start of the file is handled gracefully —
/// the parser either strips it or returns a key that contains it, but must NOT panic.
#[test]
fn test_parse_bom_prefix_no_panic() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let path = temp_dir.path().join("secrets");

    // BOM followed by a valid secrets line
    let content_with_bom = "\u{FEFF}BOM_KEY: bom_value\n";

    // The parse must not panic regardless of whether it strips the BOM.
    let result = parse_secrets_content(content_with_bom, &path);
    // Either succeeds (possibly with the BOM baked into the key name — acceptable)
    // or returns an error. Either way: no panic.
    let _ = result;
    Ok(())
}

/// Windows-style CRLF line endings are handled: parsed values must NOT contain '\r'.
#[test]
fn test_parse_crlf_line_endings() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let path = temp_dir.path().join("secrets");

    let content = "CRLF_KEY: crlf_value\r\nSECOND_KEY: second\r\n";
    let secrets = parse_secrets_content(content, &path)?;

    let value = secrets.get("CRLF_KEY").expect("CRLF_KEY should be present");
    assert!(
        !value.contains('\r'),
        "Parsed value must not contain carriage-return character, got: {:?}",
        value
    );
    Ok(())
}

/// Values longer than 4 KB are preserved without truncation.
#[test]
fn test_parse_very_long_value() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let path = temp_dir.path().join("secrets");

    let long_value = "x".repeat(5000);
    let content = format!("LONG_KEY: {long_value}\n");
    let secrets = parse_secrets_content(&content, &path)?;

    let value = secrets.get("LONG_KEY").expect("LONG_KEY should be present");
    assert_eq!(
        value.len(),
        5000,
        "Long value must be preserved in full, got {} chars",
        value.len()
    );
    Ok(())
}

/// Keys and values with surrounding whitespace are trimmed.
#[test]
fn test_parse_whitespace_trimming() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let path = temp_dir.path().join("secrets");

    // The regex-based parser is expected to trim surrounding whitespace.
    let content = "TRIMMED_KEY:   trimmed_value   \n";
    let secrets = parse_secrets_content(content, &path)?;

    let value = secrets.get("TRIMMED_KEY").expect("TRIMMED_KEY should be present");
    assert_eq!(
        value.as_str(),
        "trimmed_value",
        "Value whitespace should be trimmed"
    );
    Ok(())
}

/// When interpolation encounters a missing key the original marker is preserved
/// (graceful degradation — no error is returned).
#[test]
fn test_interpolation_missing_key_preserves_marker() -> Result<()> {
    use sss::secrets::interpolate_secrets;

    let temp_dir = TempDir::new()?;
    let project_root = temp_dir.path();

    // Create a secrets file that does NOT contain MISSING_KEY
    let secrets_file = project_root.join("secrets");
    fs::write(&secrets_file, "EXISTING_KEY: some_value\n")?;

    // Create a dummy file to anchor the lookup
    let test_file = project_root.join("test.txt");
    fs::write(&test_file, "placeholder")?;

    let content = "Hello \u{22b2}{MISSING_KEY} world";
    let mut cache = SecretsCache::new();
    let result = interpolate_secrets(content, &test_file, project_root, &mut cache, &StdFileSystemOps)?;

    // The missing marker must be preserved in the output (not silently dropped).
    assert!(
        result.contains("MISSING_KEY"),
        "Missing secret marker should be preserved, got: {:?}",
        result
    );
    Ok(())
}

/// `find_secrets_file` walks the directory hierarchy upward and finds the secrets
/// file placed in an ancestor directory.
#[test]
fn test_find_secrets_file_walks_hierarchy() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let root = temp_dir.path();

    // Layout: root/secrets  (the file to find)
    //         root/sub/subsub/ (where we start the search)
    let sub = root.join("sub").join("subsub");
    fs::create_dir_all(&sub)?;

    let secrets_path = root.join("secrets");
    fs::write(&secrets_path, "HIERARCHY_KEY: found\n")?;

    // Create a dummy file in the deep subdirectory
    let test_file = sub.join("dummy.txt");
    fs::write(&test_file, "dummy")?;

    let cache = SecretsCache::new();
    let found = cache.find_secrets_file(&test_file, root)?;

    assert_eq!(
        found.canonicalize()?,
        secrets_path.canonicalize()?,
        "Should have found the secrets file in the ancestor directory"
    );
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Config manager edge cases (TEST-05)
// ─────────────────────────────────────────────────────────────────────────────

/// Helper: create a ConfigManager backed by a fresh temporary config directory,
/// optionally pre-populating it with UserSettings written via the proper
/// serialization path (guarantees valid TOML).
fn make_manager(
    f: impl FnOnce(&mut UserSettings),
) -> Result<(ConfigManager, TempDir)> {
    let temp_dir = TempDir::new()?;
    let config_dir: PathBuf = temp_dir.path().to_path_buf();

    let mut settings = UserSettings::default();
    f(&mut settings);
    settings.save_to_dir(&config_dir)?;

    let manager = ConfigManager::new_with_config_dir(config_dir)?;
    Ok((manager, temp_dir))
}

/// Extension trait to expose `save_to_dir` for test helpers.
trait UserSettingsSaveHelper {
    fn save_to_dir(&self, dir: &Path) -> Result<()>;
}

impl UserSettingsSaveHelper for UserSettings {
    fn save_to_dir(&self, dir: &Path) -> Result<()> {
        fs::create_dir_all(dir)?;
        let settings_path = dir.join("settings.toml");
        let content = toml::to_string_pretty(self)
            .map_err(|e| anyhow::anyhow!("Failed to serialise settings: {e}"))?;
        fs::write(&settings_path, content)
            .map_err(|e| anyhow::anyhow!("Failed to write settings: {e}"))?;
        Ok(())
    }
}

/// CLI override takes precedence over user settings and SSS_USER env var.
#[test]
fn test_cli_username_wins_over_settings() -> Result<()> {
    let (manager, _dir) = make_manager(|s| {
        s.default_username = Some("settings_user".to_string());
    })?;

    let username = manager.get_username(Some("cli_user"))?;
    assert_eq!(username, "cli_user", "CLI override must win");
    Ok(())
}

/// When EDITOR/VISUAL env vars are absent, the editor stored in user settings
/// is returned (env > settings).
/// This test is skipped if EDITOR/VISUAL are set in the test environment.
#[test]
fn test_user_settings_editor_used_when_no_env() -> Result<()> {
    let (manager, _dir) = make_manager(|s| {
        s.editor = Some("zed".to_string());
    })?;

    if std::env::var("EDITOR").is_err() && std::env::var("VISUAL").is_err() {
        let editor = manager.get_editor(None);
        assert_eq!(editor, "zed", "User settings editor must be returned when no env var");
    }
    Ok(())
}

/// KDF level from user settings is used when no CLI override and no SSS_KDF_LEVEL env var.
#[test]
fn test_kdf_level_from_settings_used_when_no_override() -> Result<()> {
    let (manager, _dir) = make_manager(|s| {
        s.keystore.kdf_level = Some("interactive".to_string());
    })?;

    if std::env::var("SSS_KDF_LEVEL").is_err() {
        let level = manager.get_kdf_level(None);
        assert_eq!(
            level, "interactive",
            "KDF level from settings must be returned when no env or CLI override"
        );
    }
    Ok(())
}

/// A corrupted / malformed settings.toml returns an error from `new_with_config_dir`
/// rather than panicking.
#[test]
fn test_malformed_settings_toml_returns_error_no_panic() {
    let temp_dir = TempDir::new().unwrap();
    let config_dir = temp_dir.path().to_path_buf();

    // Write an invalid TOML file
    let settings_path = config_dir.join("settings.toml");
    fs::write(&settings_path, "key = [unclosed bracket\nBAD CONTENT @@@").unwrap();

    let result = ConfigManager::new_with_config_dir(config_dir);
    assert!(
        result.is_err(),
        "Malformed settings.toml must return an error, not panic"
    );
}

/// When settings.toml is absent, ConfigManager creates successfully with defaults.
#[test]
fn test_missing_settings_toml_uses_defaults() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let config_dir = temp_dir.path().to_path_buf();
    // No settings.toml written — directory exists but is empty.

    let manager = ConfigManager::new_with_config_dir(config_dir)?;

    // Default KDF level must be "sensitive" (the secure default).
    if std::env::var("SSS_KDF_LEVEL").is_err() {
        assert_eq!(
            manager.get_kdf_level(None),
            "sensitive",
            "Default KDF level should be 'sensitive'"
        );
    }

    // Default secrets filename must be "secrets".
    assert_eq!(manager.get_secrets_filename(), "secrets");

    Ok(())
}

/// Settings survive a save → reload roundtrip.
#[test]
fn test_save_load_settings_roundtrip() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let config_dir = temp_dir.path().to_path_buf();

    // Create, configure, and save.
    let mut manager = ConfigManager::new_with_config_dir(config_dir.clone())?;
    manager.set_editor(Some("helix".to_string()));
    manager.set_kdf_level(Some("moderate".to_string()));
    manager.set_default_username(Some("roundtrip_user".to_string()))?;
    manager.save_user_settings()?;

    // Reload from the same directory.
    let manager2 = ConfigManager::new_with_config_dir(config_dir)?;

    if std::env::var("EDITOR").is_err() && std::env::var("VISUAL").is_err() {
        assert_eq!(
            manager2.get_editor(None),
            "helix",
            "Editor should survive roundtrip"
        );
    }

    if std::env::var("SSS_KDF_LEVEL").is_err() {
        assert_eq!(
            manager2.get_kdf_level(None),
            "moderate",
            "KDF level should survive roundtrip"
        );
    }

    // Username from settings (SSS_USER env may override — guard accordingly).
    if std::env::var("SSS_USER").is_err() {
        let username = manager2.get_username(None);
        // username resolution falls through to USER/USERNAME env if SSS_USER absent,
        // so we only assert if the default_username was indeed stored.
        let default = manager2.get_default_username();
        assert_eq!(
            default.as_deref(),
            Some("roundtrip_user"),
            "Default username should survive roundtrip"
        );
        let _ = username; // resolution outcome varies with env
    }

    Ok(())
}

/// Secrets filename set in user settings is returned via ConfigManager.
#[test]
fn test_user_settings_secrets_filename_returned() -> Result<()> {
    let (mut manager, _dir) = make_manager(|_| {})?;
    // Set via the public API.
    manager.set_secrets_filename(Some("my_secrets".to_string()));
    assert_eq!(manager.get_secrets_filename(), "my_secrets");
    Ok(())
}

/// Secrets suffix set in user settings is returned via ConfigManager.
#[test]
fn test_user_settings_secrets_suffix_returned() -> Result<()> {
    let (mut manager, _dir) = make_manager(|_| {})?;
    manager.set_secrets_suffix(Some(".sealed".to_string()));
    assert_eq!(manager.get_secrets_suffix(), ".sealed");
    Ok(())
}

/// CLI override for the editor wins over both env vars and user settings.
#[test]
fn test_cli_editor_wins_over_settings_and_env() -> Result<()> {
    let (manager, _dir) = make_manager(|s| {
        s.editor = Some("vim".to_string());
    })?;

    let editor = manager.get_editor(Some("nano-cli"));
    assert_eq!(editor, "nano-cli", "CLI override must be highest priority for editor");
    Ok(())
}
