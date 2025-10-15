use anyhow::{anyhow, Result};
use clap::ArgMatches;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use crate::{
    constants::CONFIG_FILE_NAME,
    crypto::{open_repository_key, PublicKey},
    keystore::Keystore,
    project::ProjectConfig,
    secure_memory::password,
};

/// Create keystore instance based on global confdir parameter
fn create_keystore(matches: &ArgMatches) -> Result<Keystore> {
    if let Some(confdir) = matches.get_one::<String>("confdir") {
        Keystore::new_with_config_dir(PathBuf::from(confdir))
    } else {
        Keystore::new()
    }
}

pub fn handle_users(main_matches: &ArgMatches, matches: &ArgMatches) -> Result<()> {
    let config_path = CONFIG_FILE_NAME;

    match matches.subcommand() {
        Some(("list", _)) => {
            let config = ProjectConfig::load_from_file(config_path)
                .map_err(|_| anyhow!("No project configuration found. Run 'sss init' first."))?;

            let users = config.list_users();
            if users.is_empty() {
                println!("No users in project");
            } else {
                println!("Project users:");
                for username in users {
                    if let Some(user_config) = config.users.get(&username) {
                        match PublicKey::from_base64(&user_config.public) {
                            Ok(_) => {
                                println!(
                                    "  {} - Public key: {}...",
                                    username,
                                    &user_config.public[..16]
                                );
                            }
                            Err(_) => {
                                println!("  {} - (invalid public key)", username);
                            }
                        }
                    }
                }
            }
        }
        Some(("add", sub_matches)) => {
            let username = sub_matches.get_one::<String>("username").unwrap();
            let public_key_input = sub_matches.get_one::<String>("public-key").unwrap();

            // Parse public key (either from file or inline base64)
            let public_key = if Path::new(public_key_input).exists() {
                let content = fs::read_to_string(public_key_input)?;
                PublicKey::from_base64(content.trim())?
            } else {
                PublicKey::from_base64(public_key_input)?
            };

            // Load project config
            let mut config = match ProjectConfig::load_from_file(config_path) {
                Ok(config) => config,
                Err(_) => {
                    return Err(anyhow!(
                        "No project configuration found. Run 'sss init' first."
                    ));
                }
            };

            // Get our keypair to decrypt the repository key
            let keystore = create_keystore(main_matches)?;

            // Only prompt for password if the current key is password protected
            let password = if keystore.is_current_key_password_protected()? {
                Some(password::read_password(
                    "Enter your passphrase to add user (or press Enter if none): ",
                )?)
            } else {
                None
            };

            let password_opt = if let Some(ref pwd) = password {
                if pwd.is_empty() {
                    None
                } else {
                    Some(pwd.as_str()?)
                }
            } else {
                None
            };
            let our_keypair = keystore.get_current_keypair(password_opt)?;

            // Get our sealed repository key and decrypt it
            let current_user = env::var("USER")
                .or_else(|_| env::var("USERNAME"))
                .unwrap_or_else(|_| "unknown".to_string());

            let sealed_key = config.get_sealed_key_for_user(&current_user)?;
            let repository_key = open_repository_key(&sealed_key, &our_keypair)?;

            // Add the new user
            config.add_user(username, &public_key, &repository_key)?;
            config.save_to_file(config_path)?;

            println!("Added user '{}' to project", username);
            println!("Public key: {}", public_key.to_base64());
        }
        Some(("remove", sub_matches)) => {
            let username = sub_matches.get_one::<String>("username").unwrap();

            // Load project config
            let mut config = ProjectConfig::load_from_file(config_path)?;

            // Check if user exists
            if !config.users.contains_key(username) {
                return Err(anyhow!("User '{}' not found in project", username));
            }

            // Check if this is the last user
            if config.users.len() == 1 {
                return Err(anyhow!(
                    "Cannot remove the last user from the project. Use 'sss init' to recreate the project if needed."
                ));
            }

            // Remove user from config first
            config.remove_user(username)?;

            println!("Removing user '{}' from project...", username);
            println!("⚠️  This will trigger automatic key rotation for security");

            // Confirm rotation
            use crate::rotation::{confirm_rotation, RotationReason};
            let reason = RotationReason::UserRemoved(username.to_string());
            if !confirm_rotation(&reason, false)? {
                println!("Operation cancelled");
                return Ok(());
            }

            // Get our keypair to decrypt the current repository key
            let keystore = create_keystore(main_matches)?;

            // Only prompt for password if the current key is password protected
            let password = if keystore.is_current_key_password_protected()? {
                Some(password::read_password(
                    "Enter your passphrase to perform key rotation (or press Enter if none): ",
                )?)
            } else {
                None
            };

            let password_opt = if let Some(ref pwd) = password {
                if pwd.is_empty() {
                    None
                } else {
                    Some(pwd.as_str()?)
                }
            } else {
                None
            };
            let our_keypair = keystore.get_current_keypair(password_opt)?;

            // Get our sealed repository key and decrypt it
            let current_user = std::env::var("USER")
                .or_else(|_| std::env::var("USERNAME"))
                .unwrap_or_else(|_| "unknown".to_string());

            // We need to get the current repository key before removing the user
            // So we need to reload the original config
            let original_config = ProjectConfig::load_from_file(config_path)?;
            let sealed_key = original_config.get_sealed_key_for_user(&current_user)?;
            let current_repository_key =
                crate::crypto::open_repository_key(&sealed_key, &our_keypair)?;

            // Now perform the key rotation
            use crate::rotation::{RotationManager, RotationOptions};
            let options = RotationOptions {
                no_backup: false,
                force: false,
                dry_run: false,
                show_progress: true,
            };

            let rotation_manager = RotationManager::new(options);
            let result = rotation_manager.rotate_repository_key(
                &std::path::PathBuf::from(config_path),
                &current_repository_key,
                reason,
            )?;

            result.print_summary();
            println!("✓ User '{}' removed and repository key rotated", username);
        }
        Some(("info", sub_matches)) => {
            let username = sub_matches.get_one::<String>("username").unwrap();

            let config = ProjectConfig::load_from_file(config_path)
                .map_err(|_| anyhow!("No project configuration found. Run 'sss init' first."))?;

            if let Some(user_config) = config.users.get(username) {
                println!("User: {}", username);
                println!("Public key: {}", user_config.public);
                match PublicKey::from_base64(&user_config.public) {
                    Ok(pubkey) => {
                        // Could add fingerprint or other details here
                        println!("Key fingerprint: {}...", &pubkey.to_base64()[..32]);
                    }
                    Err(_) => {
                        println!("WARNING: Invalid public key format");
                    }
                }
            } else {
                return Err(anyhow!("User '{}' not found in project", username));
            }
        }
        None => {
            // No subcommand provided, show available subcommands
            return Err(anyhow!(
                "No subcommand provided\n\n\
                Available subcommands:\n\
                  list        List project users\n\
                  add         Add a user to the project\n\
                  remove      Remove a user from the project\n\
                  info        Show information about a user\n\n\
                Use 'sss users <subcommand> --help' for more information on a subcommand."
            ));
        }
        _ => unreachable!(),
    }

    Ok(())
}
