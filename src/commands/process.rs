use anyhow::{anyhow, Result};
use clap::ArgMatches;
use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use crate::{
    aliases::AliasManager,
    config::load_project_config_with_repository_key,
    constants::{BACKUP_FILE_PREFIX, BACKUP_FILE_SUFFIX, EDITOR_FALLBACKS},
    validation::validate_file_path,
    Processor,
};


/// Create alias manager instance based on global confdir parameter
fn create_alias_manager(matches: &ArgMatches) -> Result<AliasManager> {
    if let Some(confdir) = matches.get_one::<String>("confdir") {
        AliasManager::new_with_config_dir(PathBuf::from(confdir))
    } else {
        AliasManager::new()
    }
}

/// Resolve username through alias system with optional custom config dir
fn resolve_username_with_config(
    username_or_alias: &str,
    matches: &ArgMatches,
) -> Result<String> {
    let alias_manager = create_alias_manager(matches)?;
    alias_manager.resolve(username_or_alias)
}

/// Get the default system username
fn get_default_username() -> Result<String> {
    if let Ok(system_user) = env::var("USER") {
        Ok(system_user)
    } else if let Ok(system_user) = env::var("USERNAME") {
        Ok(system_user)
    } else {
        Err(anyhow!(
            "Could not determine username. Please specify with --user <username>"
        ))
    }
}


/// Create a backup of the file before editing
fn create_backup(file_path: &Path) -> Result<PathBuf> {
    let mut backup_path = file_path.to_path_buf();
    backup_path.set_file_name(format!(
        "{}{}{}",
        BACKUP_FILE_PREFIX,
        file_path.file_name().unwrap().to_string_lossy(),
        BACKUP_FILE_SUFFIX
    ));

    if file_path.exists() {
        fs::copy(file_path, &backup_path)?;
    }

    Ok(backup_path)
}


/// Launch editor for file editing
fn launch_editor(file_path: &Path) -> Result<()> {
    let editor = env::var("EDITOR")
        .or_else(|_| env::var("VISUAL"))
        .unwrap_or_else(|_| {
            // Try to find a suitable editor
            for fallback in EDITOR_FALLBACKS {
                if which::which(fallback).is_ok() {
                    return fallback.to_string();
                }
            }
            "nano".to_string()
        });

    let status = process::Command::new(&editor)
        .arg(file_path)
        .status()
        .map_err(|e| anyhow!("Failed to launch editor '{}': {}", editor, e))?;

    if !status.success() {
        return Err(anyhow!("Editor exited with non-zero status"));
    }

    Ok(())
}

pub fn handle_process(matches: &ArgMatches) -> Result<()> {
    if let Some(file_path_str) = matches.get_one::<String>("file") {
        let file_path = validate_file_path(file_path_str)?;
        let username_or_alias = if let Some(user) = matches.get_one::<String>("user") {
            user.as_str()
        } else {
            &get_default_username()?
        };
        let username = resolve_username_with_config(username_or_alias, matches)?;
        let in_place = matches.get_flag("in-place");
        let render = matches.get_flag("render");
        let edit = matches.get_flag("edit");

        let (_config, repository_key) = load_project_config_with_repository_key(".sss.toml", &username)?;

        if render {
            // Create processor
            let processor = Processor::new(repository_key)?;

            if !file_path.exists() {
                return Err(anyhow!("File does not exist: {:?}", file_path));
            }

            // Read and process the file content to raw text
            let content = fs::read_to_string(&file_path)?;
            let raw_content = processor.decrypt_to_raw(&content)?;

            if in_place {
                // In-place render: replace file with rendered content
                fs::write(&file_path, raw_content)?;
                println!("File rendered in-place: {:?}", file_path);
            } else {
                // Copy original to .sss and write rendered content to original location
                let backup_path = format!("{}.sss", file_path.to_string_lossy());
                fs::copy(&file_path, &backup_path)?;
                fs::write(&file_path, raw_content)?;
                println!("Original saved to: {:?}", backup_path);
                println!("Rendered content written to: {:?}", file_path);
            }
            return Ok(());
        }
        let processor = Processor::new(repository_key)?;

        if edit {
            // Edit mode: decrypt -> edit -> encrypt
            if !file_path.exists() {
                return Err(anyhow!("File does not exist: {:?}", file_path));
            }

            // Create backup
            let _backup_path = create_backup(&file_path)?;

            // Read and prepare content for editing
            let content = fs::read_to_string(&file_path)?;
            let edit_content = processor.prepare_for_editing(&content)?;

            // Write to temporary file
            let temp_path = format!("{}.tmp", file_path.to_string_lossy());
            fs::write(&temp_path, edit_content)?;

            #[cfg(unix)]
            {
                let mut perms = fs::metadata(&temp_path)?.permissions();
                perms.set_mode(0o600);
                fs::set_permissions(&temp_path, perms)?;
            }

            // Launch editor
            launch_editor(Path::new(&temp_path))?;

            // Read back and finalize
            let edited_content = fs::read_to_string(&temp_path)?;
            let final_content = processor.finalise_after_editing(&edited_content)?;

            // Write final content
            fs::write(&file_path, final_content)?;
            fs::remove_file(temp_path)?;

            println!("File edited and encrypted: {:?}", file_path);
        } else {
            // Regular processing mode
            if !file_path.exists() {
                return Err(anyhow!("File does not exist: {:?}", file_path));
            }

            let content = fs::read_to_string(&file_path)?;
            let processed_content = processor.process_content(&content)?;

            if in_place {
                // Create backup before in-place modification
                let _backup_path = create_backup(&file_path)?;
                fs::write(&file_path, processed_content)?;
                println!("File processed in-place: {:?}", file_path);
            } else {
                // Output to stdout
                print!("{}", processed_content);
                io::stdout().flush()?;
            }
        }

        Ok(())
    } else {
        Err(anyhow!("No file specified for processing"))
    }
}