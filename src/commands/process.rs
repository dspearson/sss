use anyhow::{anyhow, Result};
use clap::ArgMatches;
use std::env;
use std::fs;
use std::io::{self, Read, Write};
use std::path::Path;
use std::process;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use crate::{
    config::load_project_config_with_repository_key, constants::EDITOR_FALLBACKS,
    validation::validate_file_path, Processor,
};

/// Get the default username with precedence: SSS_USER > USER > USERNAME
fn get_default_username() -> Result<String> {
    // Check SSS_USER first
    if let Ok(sss_user) = env::var("SSS_USER") {
        return Ok(sss_user);
    }

    // Fall back to system username
    if let Ok(system_user) = env::var("USER") {
        Ok(system_user)
    } else if let Ok(system_user) = env::var("USERNAME") {
        Ok(system_user)
    } else {
        Err(anyhow!(
            "Could not determine username. Please specify with --user or set SSS_USER"
        ))
    }
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

fn handle_stdin_process(matches: &ArgMatches) -> Result<()> {
    let username = if let Some(user) = matches.get_one::<String>("user") {
        user.to_string()
    } else {
        get_default_username()?
    };
    let render = matches.get_flag("render");

    // in-place and edit don't make sense for stdin
    if matches.get_flag("in-place") {
        return Err(anyhow!("Cannot use --in-place with stdin"));
    }
    if matches.get_flag("edit") {
        return Err(anyhow!("Cannot use --edit with stdin"));
    }

    let (_config, repository_key) =
        load_project_config_with_repository_key(".sss.toml", &username)?;
    let processor = Processor::new(repository_key)?;

    // Read from stdin
    let mut input = String::new();
    io::stdin().read_to_string(&mut input)?;

    // Process content
    let output = if render {
        processor.decrypt_to_raw(&input)?
    } else {
        processor.process_content(&input)?
    };

    // Write to stdout
    print!("{}", output);
    io::stdout().flush()?;

    Ok(())
}

pub fn handle_process(matches: &ArgMatches) -> Result<()> {
    if let Some(file_path_str) = matches.get_one::<String>("file") {
        // Handle stdin if file is "-"
        if file_path_str == "-" {
            return handle_stdin_process(matches);
        }

        let file_path = validate_file_path(file_path_str)?;
        let username = if let Some(user) = matches.get_one::<String>("user") {
            user.to_string()
        } else {
            get_default_username()?
        };
        let in_place = matches.get_flag("in-place");
        let render = matches.get_flag("render");
        let edit = matches.get_flag("edit");

        let (_config, repository_key) =
            load_project_config_with_repository_key(".sss.toml", &username)?;

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
                eprintln!("File rendered in-place: {:?}", file_path);
            } else {
                // Output to stdout
                print!("{}", raw_content);
            }
            return Ok(());
        }
        let processor = Processor::new(repository_key)?;

        if edit {
            // Edit mode: decrypt -> edit -> encrypt
            if !file_path.exists() {
                return Err(anyhow!("File does not exist: {:?}", file_path));
            }

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

/// Process a file or stdin with a specific operation
fn process_file_or_stdin(
    _main_matches: &ArgMatches,
    sub_matches: &ArgMatches,
    operation: &str,
) -> Result<()> {
    let file_path_str = sub_matches.get_one::<String>("file").unwrap();
    let username = if let Some(user) = sub_matches.get_one::<String>("user") {
        user.to_string()
    } else {
        get_default_username()?
    };
    let in_place = sub_matches.get_flag("in-place");

    // Load project config and repository key
    let (_config, repository_key) =
        load_project_config_with_repository_key(".sss.toml", &username)?;
    let processor = Processor::new(repository_key)?;

    // Handle stdin
    if file_path_str == "-" {
        if in_place {
            return Err(anyhow!("Cannot use --in-place with stdin"));
        }

        let mut input = String::new();
        io::stdin().read_to_string(&mut input)?;

        let output = match operation {
            "seal" => processor.encrypt_content(&input)?,
            "open" => processor.decrypt_content(&input)?,
            "render" => processor.decrypt_to_raw(&input)?,
            _ => unreachable!(),
        };

        print!("{}", output);
        io::stdout().flush()?;
        return Ok(());
    }

    // Handle file
    let file_path = validate_file_path(file_path_str)?;

    if !file_path.exists() {
        return Err(anyhow!("File does not exist: {:?}", file_path));
    }

    let content = fs::read_to_string(&file_path)?;
    let output = match operation {
        "seal" => processor.encrypt_content(&content)?,
        "open" => processor.decrypt_content(&content)?,
        "render" => processor.decrypt_to_raw(&content)?,
        _ => unreachable!(),
    };

    if in_place {
        fs::write(&file_path, &output)?;
        eprintln!("File processed in-place: {:?}", file_path);
    } else {
        print!("{}", output);
        io::stdout().flush()?;
    }

    Ok(())
}

/// Handle 'seal' command - encrypt plaintext markers
pub fn handle_seal(main_matches: &ArgMatches, sub_matches: &ArgMatches) -> Result<()> {
    process_file_or_stdin(main_matches, sub_matches, "seal")
}

/// Handle 'open' command - decrypt ciphertext to plaintext markers
pub fn handle_open(main_matches: &ArgMatches, sub_matches: &ArgMatches) -> Result<()> {
    process_file_or_stdin(main_matches, sub_matches, "open")
}

/// Handle 'render' command - decrypt to raw text (remove all markers)
pub fn handle_render(main_matches: &ArgMatches, sub_matches: &ArgMatches) -> Result<()> {
    process_file_or_stdin(main_matches, sub_matches, "render")
}

/// Handle 'edit' command - edit file with automatic encrypt/decrypt
pub fn handle_edit(_main_matches: &ArgMatches, sub_matches: &ArgMatches) -> Result<()> {
    let file_path_str = sub_matches.get_one::<String>("file").unwrap();
    let username = if let Some(user) = sub_matches.get_one::<String>("user") {
        user.to_string()
    } else {
        get_default_username()?
    };

    // Cannot edit stdin
    if file_path_str == "-" {
        return Err(anyhow!("Cannot use edit mode with stdin"));
    }

    let file_path = validate_file_path(file_path_str)?;

    if !file_path.exists() {
        return Err(anyhow!("File does not exist: {:?}", file_path));
    }

    let (_config, repository_key) =
        load_project_config_with_repository_key(".sss.toml", &username)?;
    let processor = Processor::new(repository_key)?;

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

    // Read edited content and process it
    let edited_content = fs::read_to_string(&temp_path)?;
    let final_content = processor.finalise_after_editing(&edited_content)?;

    // Write back to original file
    fs::write(&file_path, final_content)?;

    // Remove temp file
    fs::remove_file(&temp_path)?;

    eprintln!("File edited and encrypted: {:?}", file_path);
    Ok(())
}
