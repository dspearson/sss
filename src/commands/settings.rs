use anyhow::Result;
use clap::ArgMatches;

use crate::config_manager::ConfigManager;
use crate::validation::validate_username;

pub fn handle_settings(matches: &ArgMatches) -> Result<()> {
    let mut config_manager = ConfigManager::new()?;

    match matches.subcommand() {
        Some(("show", _)) => {
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
            println!("Colored output: {}", config_manager.use_colored_output());
            println!("Show progress: {}", config_manager.show_progress());
            println!("Verbosity level: {}", config_manager.verbosity_level());
            println!("Confirm destructive: {}", config_manager.confirm_destructive());

            // Show keystore settings
            println!("Auto-lock timeout: {} minutes", config_manager.get_auto_lock_timeout());

            // Show project info if available
            if let Some(project_path) = config_manager.project_path() {
                println!("Project path: {}", project_path.display());
                match config_manager.get_project_users() {
                    Ok(users) => {
                        println!("Project users: {}", users.join(", "));
                    }
                    Err(_) => println!("Project users: <error loading>"),
                }
            } else {
                println!("No project loaded");
            }
        }

        Some(("set", sub_matches)) => {
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

            if let Some(colored) = sub_matches.get_one::<bool>("colored") {
                config_manager.set_colored_output(*colored);
                println!("Set colored output to: {}", colored);
            }

            // Save settings
            config_manager.save_user_settings()?;
            println!("Settings saved successfully");
        }

        Some(("reset", sub_matches)) => {
            let confirm = sub_matches.get_flag("confirm");

            if !confirm {
                println!("This will reset all user settings to defaults.");
                println!("Use --confirm to proceed with the reset.");
                return Ok(());
            }

            // Reset to defaults
            config_manager.set_default_username(None)?;
            config_manager.set_editor(None);
            config_manager.set_colored_output(true);

            config_manager.save_user_settings()?;
            println!("All settings have been reset to defaults");
        }

        Some(("location", _)) => {
            let config_manager = ConfigManager::new()?;
            if let Some(project_path) = config_manager.project_path() {
                println!("Project config: {}", project_path.join(".sss.toml").display());
            }

            // Show user config location
            if let Some(config_dir) = dirs::config_dir() {
                let user_config = config_dir.join("sss").join("settings.toml");
                println!("User config: {}", user_config.display());
            }
        }

        _ => {
            println!("Available settings commands:");
            println!("  show     - Show current settings");
            println!("  set      - Set configuration values");
            println!("  reset    - Reset all settings to defaults");
            println!("  location - Show configuration file locations");
        }
    }

    Ok(())
}

pub fn handle_config_deprecated(matches: &ArgMatches) -> Result<()> {
    eprintln!("Warning: 'sss config' is deprecated. Use 'sss settings' instead.");
    handle_settings(matches)
}