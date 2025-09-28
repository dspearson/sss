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
            let password = rpassword::prompt_password(
                "Enter your passphrase to add user (or press Enter if none): ",
            )?;
            let password_opt = if password.is_empty() {
                None
            } else {
                Some(password.as_str())
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

            let mut config = ProjectConfig::load_from_file(config_path)?;
            config.remove_user(username)?;
            config.save_to_file(config_path)?;

            println!("Removed user '{}' from project", username);
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
            eprintln!("Error: No subcommand provided");
            eprintln!();
            eprintln!("Available subcommands:");
            eprintln!("  list        List project users");
            eprintln!("  add         Add a user to the project");
            eprintln!("  remove      Remove a user from the project");
            eprintln!("  info        Show information about a user");
            eprintln!();
            eprintln!("Use 'sss users <subcommand> --help' for more information on a subcommand.");
            std::process::exit(1);
        }
        _ => unreachable!(),
    }

    Ok(())
}
