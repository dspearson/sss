use anyhow::{anyhow, Result};
use clap::ArgMatches;
use std::path::PathBuf;

use crate::config_manager::ConfigManager;
use crate::validation::validate_username;

/// Create config manager instance based on global confdir parameter
fn create_config_manager(main_matches: &ArgMatches) -> Result<ConfigManager> {
    if let Some(confdir) = main_matches.get_one::<String>("confdir") {
        ConfigManager::new_with_config_dir(PathBuf::from(confdir))
    } else {
        ConfigManager::new()
    }
}

pub fn handle_settings(main_matches: &ArgMatches, matches: &ArgMatches) -> Result<()> {
    let mut config_manager = create_config_manager(main_matches)?;

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

            if let Some(coloured) = sub_matches.get_one::<bool>("coloured") {
                config_manager.set_coloured_output(*coloured);
                println!("Set coloured output to: {}", coloured);
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
            config_manager.set_coloured_output(true);

            config_manager.save_user_settings()?;
            println!("All settings have been reset to defaults");
        }

        Some(("location", _)) => {
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
        }

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

pub fn handle_config_deprecated(main_matches: &ArgMatches, matches: &ArgMatches) -> Result<()> {
    eprintln!("Warning: 'sss config' is deprecated. Use 'sss settings' instead.");
    handle_settings(main_matches, matches)
}
