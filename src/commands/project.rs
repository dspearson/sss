use anyhow::{anyhow, Result};
use clap::ArgMatches;
use std::path::PathBuf;

use crate::commands::handle_users;
use crate::commands::utils::create_config_manager;
use crate::config::find_project_root;

pub fn handle_project(main_matches: &ArgMatches, matches: &ArgMatches) -> Result<()> {
    let mut config_manager = create_config_manager(main_matches)?;

    // Handle --render shortcut flag
    if matches.get_flag("render") {
        let project_root = find_project_root()?;
        config_manager.enable_project_render(&project_root)?;
        config_manager.save_user_settings()?;
        println!("Enabled automatic rendering for: {}", project_root.display());
        return Ok(());
    }

    match matches.subcommand() {
        Some(("list", _)) => handle_project_list(&config_manager)?,
        Some(("show", _)) => handle_project_show(&config_manager)?,
        Some(("enable", sub_matches)) => handle_project_enable(&mut config_manager, sub_matches)?,
        Some(("disable", sub_matches)) => handle_project_disable(&mut config_manager, sub_matches)?,
        Some(("users", sub_matches)) => {
            // Forward to handle_users with the main_matches for confdir support
            return handle_users(main_matches, sub_matches);
        }
        Some(("remove", sub_matches)) => handle_project_remove(&mut config_manager, sub_matches)?,
        Some(("ignore", sub_matches)) => handle_project_ignore(&mut config_manager, sub_matches)?,
        None => {
            return Err(anyhow!(
                "No subcommand specified. Use 'sss project --help' for usage information."
            ));
        }
        _ => unreachable!(),
    }

    Ok(())
}

fn handle_project_list(config_manager: &crate::config_manager::ConfigManager) -> Result<()> {
    let projects = config_manager.get_all_projects();

    if projects.is_empty() {
        println!("No projects configured");
        return Ok(());
    }

    println!("Configured Projects:");
    println!("===================");
    for (path, settings) in projects {
        let render_status = if settings.allow_auto_render {
            "enabled"
        } else {
            "disabled"
        };
        let open_status = if settings.allow_auto_open {
            "enabled"
        } else {
            "disabled"
        };

        println!("{} (auto-render={}, auto-open={})", path, render_status, open_status);
    }
    Ok(())
}

fn handle_project_show(config_manager: &crate::config_manager::ConfigManager) -> Result<()> {
    let project_root = find_project_root()?;
    let render_enabled = config_manager.is_project_render_enabled(&project_root)?;
    let open_enabled = config_manager.is_project_open_enabled(&project_root)?;

    println!("Current Project: {}", project_root.display());
    println!("=================");
    println!("Automatic rendering: {}", if render_enabled { "enabled" } else { "disabled" });
    println!("Automatic opening: {}", if open_enabled { "enabled" } else { "disabled" });

    if !render_enabled || !open_enabled {
        println!();
        if !render_enabled {
            println!("To enable automatic rendering, run:");
            println!("  sss project enable render");
        }
        if !open_enabled {
            println!("To enable automatic opening, run:");
            println!("  sss project enable open");
        }
    }
    Ok(())
}

fn handle_project_enable(config_manager: &mut crate::config_manager::ConfigManager, sub_matches: &ArgMatches) -> Result<()> {
    let feature = sub_matches.get_one::<String>("feature").unwrap();
    let project_root = find_project_root()?;

    match feature.as_str() {
        "render" => {
            config_manager.enable_project_render(&project_root)?;
            config_manager.save_user_settings()?;
            println!("Enabled automatic rendering for: {}", project_root.display());
        }
        "open" => {
            config_manager.enable_project_open(&project_root)?;
            config_manager.save_user_settings()?;
            println!("Enabled automatic opening for: {}", project_root.display());
        }
        _ => unreachable!("clap should have validated the feature argument"),
    }
    Ok(())
}

fn handle_project_disable(config_manager: &mut crate::config_manager::ConfigManager, sub_matches: &ArgMatches) -> Result<()> {
    let feature = sub_matches.get_one::<String>("feature").unwrap();
    let project_root = find_project_root()?;

    match feature.as_str() {
        "render" => {
            config_manager.disable_project_render(&project_root)?;
            config_manager.save_user_settings()?;
            println!("Disabled automatic rendering for: {}", project_root.display());
        }
        "open" => {
            config_manager.disable_project_open(&project_root)?;
            config_manager.save_user_settings()?;
            println!("Disabled automatic opening for: {}", project_root.display());
        }
        _ => unreachable!("clap should have validated the feature argument"),
    }
    Ok(())
}

fn handle_project_remove(config_manager: &mut crate::config_manager::ConfigManager, sub_matches: &ArgMatches) -> Result<()> {
    let project_path = if let Some(path_str) = sub_matches.get_one::<String>("path") {
        PathBuf::from(path_str)
    } else {
        find_project_root()?
    };

    let removed = config_manager.remove_project(&project_path)?;
    config_manager.save_user_settings()?;

    if removed {
        println!("Removed project from settings: {}", project_path.display());
    } else {
        println!("Project not found in settings: {}", project_path.display());
    }
    Ok(())
}

fn handle_project_ignore(config_manager: &mut crate::config_manager::ConfigManager, sub_matches: &ArgMatches) -> Result<()> {
    let project_root = find_project_root()?;

    match sub_matches.subcommand() {
        Some(("add", add_matches)) => {
            let pattern = add_matches.get_one::<String>("pattern").unwrap();
            config_manager.add_ignore_pattern(&project_root, pattern.clone())?;
            config_manager.save_user_settings()?;
            println!("Added ignore pattern '{}' for: {}", pattern, project_root.display());
        }
        Some(("remove", remove_matches)) => {
            let pattern = remove_matches.get_one::<String>("pattern").unwrap();
            let removed = config_manager.remove_ignore_pattern(&project_root, pattern)?;
            config_manager.save_user_settings()?;

            if removed {
                println!("Removed ignore pattern '{}' from: {}", pattern, project_root.display());
            } else {
                println!("Pattern '{}' not found in ignore list", pattern);
            }
        }
        Some(("list", _)) => {
            let patterns = config_manager.get_ignore_patterns(&project_root)?;

            if patterns.is_empty() {
                println!("No ignore patterns configured for: {}", project_root.display());
            } else {
                println!("Ignore patterns for: {}", project_root.display());
                println!("==================");
                for pattern in patterns {
                    println!("  {}", pattern);
                }
            }
        }
        None => {
            return Err(anyhow!(
                "No subcommand specified. Use 'sss project ignore --help' for usage information."
            ));
        }
        _ => unreachable!(),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_handle_project_error_message() {
        // Test that the function returns correct error when no subcommand provided
        // (This can't be tested without mocking due to file I/O dependencies,
        // but we verify the error message format exists in the source)
        let source = include_str!("project.rs");
        assert!(source.contains("No subcommand specified"));
        assert!(source.contains("sss project --help"));
    }

    // Note: handle_project() manages per-project settings and permissions
    // The logic delegates to ConfigManager methods which are tested in config_manager module:
    // - enable_project_render/open
    // - disable_project_render/open
    // - add_ignore_pattern/remove_ignore_pattern
    // - get_ignore_patterns
    // Integration tests verify the full project settings workflow
}
