use anyhow::{anyhow, Result};
use clap::ArgMatches;

use crate::commands::utils::create_config_manager;
use crate::validation::validate_username;

pub fn handle_settings(main_matches: &ArgMatches, matches: &ArgMatches) -> Result<()> {
    let mut config_manager = create_config_manager(main_matches)?;

    match matches.subcommand() {
        Some(("show", _)) => handle_settings_show(&config_manager)?,
        Some(("set", sub_matches)) => handle_settings_set(&mut config_manager, sub_matches)?,
        Some(("reset", sub_matches)) => handle_settings_reset(&mut config_manager, sub_matches)?,
        Some(("location", _)) => handle_settings_location(&config_manager)?,
        None => {
            // No subcommand provided, show available subcommands
            return Err(anyhow!(
                "No subcommand provided\n\n\
                Available subcommands:\n\
                  show        Show current settings\n\
                  set         Set configuration values\n\
                  reset       Reset all settings to defaults\n\
                  location    Show configuration file locations\n\n\
                Use 'sss settings <subcommand> --help' for more information on a subcommand."
            ));
        }
        _ => unreachable!(),
    }

    Ok(())
}

fn handle_settings_show(config_manager: &crate::config_manager::ConfigManager) -> Result<()> {
    println!("Current Settings:");
    println!("================");

    // Show username
    match config_manager.get_username(None) {
        Ok(username) => println!("Default username: {}", username),
        Err(_) => println!("Default username: <not set>"),
    }

    // Show editor
    let editor = config_manager.get_editor(None);
    println!("Editor: {}", editor);

    // Show UI preferences
    println!("Coloured output: {}", config_manager.use_coloured_output());
    println!("Show progress: {}", config_manager.show_progress());
    println!("Verbosity level: {}", config_manager.verbosity_level());
    println!(
        "Confirm destructive: {}",
        config_manager.confirm_destructive()
    );

    // Show keystore settings
    println!(
        "Auto-lock timeout: {} minutes",
        config_manager.get_auto_lock_timeout()
    );
    println!("KDF security level: {}", config_manager.get_kdf_level(None));
    println!("Use system keyring: {}", config_manager.use_system_keyring(None));

    // Show secrets file configuration
    println!("\nSecrets File Configuration:");
    println!("---------------------------");
    println!("Secrets filename: {}", config_manager.get_secrets_filename());
    println!("Secrets suffix: {}", config_manager.get_secrets_suffix());

    // Show project info if available
    println!("\nProject Information:");
    println!("-------------------");
    if let Some(project_path) = config_manager.project_path() {
        println!("Project path: {}", project_path.display());
        match config_manager.get_project_users() {
            Ok(users) => {
                println!("Project users: {}", users.join(", "));
            }
            Err(e) => eprintln!("Project users: <error: {}>", e),
        }
    } else {
        println!("No project loaded");
    }
    Ok(())
}

fn handle_settings_set(config_manager: &mut crate::config_manager::ConfigManager, sub_matches: &ArgMatches) -> Result<()> {
    if let Some(username) = sub_matches.get_one::<String>("username") {
        if username == "none" {
            config_manager.set_default_username(None)?;
            println!("Cleared default username");
        } else {
            validate_username(username)?;
            config_manager.set_default_username(Some(username.clone()))?;
            println!("Set default username to: {}", username);
        }
    }

    if let Some(editor) = sub_matches.get_one::<String>("editor") {
        if editor == "none" {
            config_manager.set_editor(None);
            println!("Cleared editor preference (will use system default)");
        } else {
            config_manager.set_editor(Some(editor.clone()));
            println!("Set editor to: {}", editor);
        }
    }

    if let Some(coloured) = sub_matches.get_one::<bool>("coloured") {
        config_manager.set_coloured_output(*coloured);
        println!("Set coloured output to: {}", coloured);
    }

    if let Some(filename) = sub_matches.get_one::<String>("secrets-filename") {
        if filename == "none" {
            config_manager.set_secrets_filename(None);
            println!("Cleared secrets filename (will use default: 'secrets')");
        } else {
            config_manager.set_secrets_filename(Some(filename.clone()));
            println!("Set secrets filename to: {}", filename);
        }
    }

    if let Some(suffix) = sub_matches.get_one::<String>("secrets-suffix") {
        if suffix == "none" {
            config_manager.set_secrets_suffix(None);
            println!("Cleared secrets suffix (will use default: '.secrets')");
        } else {
            config_manager.set_secrets_suffix(Some(suffix.clone()));
            println!("Set secrets suffix to: {}", suffix);
        }
    }

    if let Some(kdf_level) = sub_matches.get_one::<String>("kdf-level") {
        // Validate KDF level
        use crate::kdf::KdfParams;
        KdfParams::from_level(kdf_level)?;  // This validates the level

        if kdf_level == "none" {
            config_manager.set_kdf_level(None);
            println!("Cleared KDF level (will use default: 'sensitive')");
        } else {
            config_manager.set_kdf_level(Some(kdf_level.clone()));
            println!("Set KDF security level to: {}", kdf_level);
            println!("\nNote: This only affects newly generated keys.");
            println!("Existing keys will continue to use their original KDF parameters.");
        }
    }

    if let Some(use_keyring) = sub_matches.get_one::<bool>("use-keyring") {
        config_manager.set_use_system_keyring(*use_keyring);
        if *use_keyring {
            // Check if keyring is actually available
            use crate::keyring_support;
            if keyring_support::is_keyring_available() {
                println!("Enabled system keyring for key storage");
                println!("✓ System keyring is available");
            } else {
                eprintln!("\n⚠️  WARNING: System keyring is not available on this system!");
                eprintln!("   Keys will still be stored in files.");
                eprintln!("   On Linux, install gnome-keyring or kwallet.");
            }
        } else {
            println!("Disabled system keyring (keys will be stored in files)");
        }
    }

    // Save settings
    config_manager.save_user_settings()?;
    println!("\nSettings saved successfully");
    Ok(())
}

fn handle_settings_reset(config_manager: &mut crate::config_manager::ConfigManager, sub_matches: &ArgMatches) -> Result<()> {
    let confirm = sub_matches.get_flag("confirm");

    if !confirm {
        println!("This will reset all user settings to defaults.");
        println!("Use --confirm to proceed with the reset.");
        return Ok(());
    }

    // Reset to defaults
    config_manager.set_default_username(None)?;
    config_manager.set_editor(None);
    config_manager.set_coloured_output(true);

    config_manager.save_user_settings()?;
    println!("All settings have been reset to defaults");
    Ok(())
}

fn handle_settings_location(config_manager: &crate::config_manager::ConfigManager) -> Result<()> {
    if let Some(project_path) = config_manager.project_path() {
        println!(
            "Project config: {}",
            project_path.join(".sss.toml").display()
        );
    }

    // Show user config location
    if let Some(config_dir) = dirs::config_dir() {
        let user_config = config_dir.join("sss").join("settings.toml");
        println!("User config: {}", user_config.display());
    }
    Ok(())
}

pub fn handle_config_deprecated(main_matches: &ArgMatches, matches: &ArgMatches) -> Result<()> {
    eprintln!("Warning: 'sss config' is deprecated. Use 'sss settings' instead.");
    handle_settings(main_matches, matches)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Command;

    #[test]
    fn test_handle_settings_requires_subcommand() {
        // Create minimal ArgMatches without subcommand
        let app = Command::new("test")
            .arg(clap::Arg::new("confdir").long("confdir"));
        let main_matches = app.get_matches_from(vec!["test"]);

        let settings_app = Command::new("settings");
        let settings_matches = settings_app.get_matches_from(vec!["settings"]);

        let result = handle_settings(&main_matches, &settings_matches);

        // Should return error when no subcommand provided
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("No subcommand provided"));
        assert!(err_msg.contains("show"));
        assert!(err_msg.contains("set"));
        assert!(err_msg.contains("reset"));
        assert!(err_msg.contains("location"));
    }

    // Note: Most of handle_settings() requires filesystem I/O through ConfigManager
    // The logic delegates to config_manager methods which are tested in config_manager module
    // Integration tests verify the full command behavior with actual config files
}
