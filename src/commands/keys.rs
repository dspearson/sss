use anyhow::{anyhow, Result};
use clap::ArgMatches;
use std::io::{self, Write};
use std::path::PathBuf;

use crate::{crypto::KeyPair, keystore::Keystore, secure_memory::password};

/// Create keystore instance based on global confdir parameter
fn create_keystore(matches: &ArgMatches) -> Result<Keystore> {
    if let Some(confdir) = matches.get_one::<String>("confdir") {
        Keystore::new_with_config_dir(PathBuf::from(confdir))
    } else {
        Keystore::new()
    }
}

fn handle_keys_generate_command(main_matches: &ArgMatches, matches: &ArgMatches) -> Result<()> {
    let force = matches.get_flag("force");
    let no_password = matches.get_flag("no-password");

    let keystore = create_keystore(main_matches)?;

    // Check if current keypair exists
    if !force && keystore.get_current_keypair(None).is_ok() {
        return Err(anyhow!(
            "A keypair already exists. Use --force to overwrite."
        ));
    }

    let password_option = if no_password {
        None
    } else {
        let passphrase = password::read_password_with_confirmation(
            "Enter passphrase for new keypair: ",
            "Confirm passphrase: ",
        )?;

        if passphrase.is_empty() {
            return Err(anyhow!(
                "Passphrase cannot be empty. Use --no-password for passwordless keys."
            ));
        }

        Some(passphrase.as_str()?.to_string())
    };

    let keypair = KeyPair::generate()?;
    let key_id = keystore.store_keypair(&keypair, password_option.as_deref())?;

    println!("Generated new keypair: {}", key_id);
    println!("Public key: {}", keypair.public_key.to_base64());

    if no_password {
        println!("Warning: Keypair stored without password protection. Consider using a passphrase for better security.");
    }

    Ok(())
}

pub fn handle_keys(main_matches: &ArgMatches, matches: &ArgMatches) -> Result<()> {
    let keystore = create_keystore(main_matches)?;

    match matches.subcommand() {
        Some(("generate", sub_matches)) => handle_keys_generate_command(main_matches, sub_matches)?,
        Some(("list", _)) => {
            let keys = keystore.list_key_ids()?;
            if keys.is_empty() {
                println!("No keypairs found. Generate one with: sss keys generate");
            } else {
                println!("Found {} keypair(s):", keys.len());

                let current_id = keystore.get_current_key_id().ok();

                for (key_id, stored) in keys {
                    let is_current = current_id.as_ref() == Some(&key_id);
                    let status = if is_current { " (current)" } else { "" };
                    let protection = if stored.is_password_protected {
                        " [protected]"
                    } else {
                        ""
                    };

                    println!(
                        "  {}... - Created: {}{}{}",
                        &key_id[..8],
                        stored.created_at.format("%Y-%m-%d %H:%M"),
                        protection,
                        status
                    );
                }
            }
        }
        Some(("pubkey", sub_matches)) => {
            let show_fingerprint = sub_matches.get_flag("fingerprint");
            let password =
                password::read_password("Enter passphrase (or press Enter if unprotected): ")?;
            let password_opt = if password.is_empty() {
                None
            } else {
                Some(password.as_str()?)
            };

            let keypair = keystore.get_current_keypair(password_opt)?;
            if show_fingerprint {
                // Show a shortened fingerprint (first 16 chars of base64)
                let full_key = keypair.public_key.to_base64();
                println!("{}...", &full_key[..16.min(full_key.len())]);
            } else {
                println!("{}", keypair.public_key.to_base64());
            }
        }
        Some(("delete", sub_matches)) => {
            let key_name = sub_matches.get_one::<String>("name").unwrap();

            print!(
                "Are you sure you want to delete keypair '{}'? [y/N]: ",
                key_name
            );
            io::stdout().flush()?;

            let mut input = String::new();
            io::stdin().read_line(&mut input)?;

            if input.trim().to_lowercase() == "y" {
                keystore.delete_keypair(key_name)?;
                println!("Deleted keypair: {}", key_name);
            } else {
                println!("Cancelled");
            }
        }
        Some(("current", sub_matches)) => {
            if let Some(key_name) = sub_matches.get_one::<String>("name") {
                // Set current key
                let keys = keystore.list_key_ids()?;
                let key_to_set = keys.iter().find(|(id, _)| id.starts_with(key_name));

                match key_to_set {
                    Some((key_id, _)) => {
                        keystore.set_current_key(key_id)?;
                        println!("Set current key to: {}", key_id);
                    }
                    None => {
                        println!("Key not found: {}", key_name);
                        println!("Available keys:");
                        for (key_id, stored) in keys {
                            println!(
                                "  {} (created: {})",
                                &key_id[..8],
                                stored.created_at.format("%Y-%m-%d")
                            );
                        }
                    }
                }
            } else {
                // Show current key
                match keystore.get_current_key_id() {
                    Ok(current_id) => {
                        println!("Current key ID: {}", current_id);
                        match keystore.get_current_keypair(None) {
                            Ok(keypair) => {
                                println!("Public key: {}", keypair.public_key.to_base64());
                            }
                            Err(_) => {
                                println!("(Key is password protected)");
                            }
                        }
                    }
                    Err(_) => {
                        println!("No current key set");
                    }
                }
            }
        }
        Some(("rotate", sub_matches)) => {
            handle_keys_rotate_command(main_matches, sub_matches)?;
        }
        None => {
            // No subcommand provided, show available subcommands
            return Err(anyhow!(
                "No subcommand provided\n\n\
                Available subcommands:\n\
                  generate    Generate a new keypair\n\
                  list        List your private keys\n\
                  pubkey      Show your public key\n\
                  current     Show or set current keypair\n\
                  delete      Delete a keypair\n\
                  rotate      Rotate repository encryption key\n\n\
                Use 'sss keys <subcommand> --help' for more information on a subcommand."
            ));
        }
        _ => unreachable!(),
    }

    Ok(())
}

fn handle_keys_rotate_command(_main_matches: &ArgMatches, matches: &ArgMatches) -> Result<()> {
    use crate::{
        config::load_project_config_with_repository_key,
        constants::CONFIG_FILE_NAME,
        rotation::{confirm_rotation, RotationManager, RotationOptions, RotationReason},
    };

    let force = matches.get_flag("force");
    let no_backup = matches.get_flag("no-backup");
    let dry_run = matches.get_flag("dry-run");

    // Check if we're in a project
    let config_path = CONFIG_FILE_NAME;
    if !std::path::Path::new(config_path).exists() {
        return Err(anyhow!(
            "No project configuration found. Run 'sss init' first."
        ));
    }

    let reason = RotationReason::ManualRotation;

    // Confirm rotation unless forced or dry run
    if !dry_run && !confirm_rotation(&reason, force)? {
        println!("Key rotation cancelled");
        return Ok(());
    }

    // Get current user and repository key
    let current_user = std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "unknown".to_string());

    let (_, repository_key) = load_project_config_with_repository_key(config_path, &current_user)?;

    // Set up rotation options
    let options = RotationOptions {
        no_backup,
        force,
        dry_run,
        show_progress: true,
    };

    // Perform the rotation
    let rotation_manager = RotationManager::new(options);
    let result = rotation_manager.rotate_repository_key(
        &std::path::PathBuf::from(config_path),
        &repository_key,
        reason,
    )?;

    result.print_summary();

    if dry_run {
        println!("This was a dry run. Use 'sss keys rotate' (without --dry-run) to perform the actual rotation.");
    }

    Ok(())
}

pub fn handle_keygen_deprecated(main_matches: &ArgMatches, matches: &ArgMatches) -> Result<()> {
    eprintln!("Warning: 'sss keygen' is deprecated. Use 'sss keys generate' instead.");
    handle_keys_generate_command(main_matches, matches)
}
