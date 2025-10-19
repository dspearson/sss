use anyhow::{anyhow, Result};
use clap::ArgMatches;
use std::fs;
use std::path::Path;

use crate::{
    commands::utils::{create_keystore, get_password_if_protected, get_system_username},
    constants::{CONFIG_FILE_NAME, DEFAULT_USERNAME_FALLBACK, ERR_NO_PROJECT_CONFIG},
    crypto::{open_repository_key, PublicKey},
    project::ProjectConfig,
};

pub fn handle_users(main_matches: &ArgMatches, matches: &ArgMatches) -> Result<()> {
    match matches.subcommand() {
        Some(("list", _)) => handle_users_list()?,
        Some(("add", sub_matches)) => handle_users_add(main_matches, sub_matches)?,
        Some(("remove", sub_matches)) => handle_users_remove(main_matches, sub_matches)?,
        Some(("info", sub_matches)) => handle_users_info(sub_matches)?,
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

fn handle_users_list() -> Result<()> {
    let config = ProjectConfig::load_from_file(CONFIG_FILE_NAME)
        .map_err(|_| anyhow!(ERR_NO_PROJECT_CONFIG))?;

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
    Ok(())
}

fn handle_users_add(main_matches: &ArgMatches, sub_matches: &ArgMatches) -> Result<()> {
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
    let mut config = ProjectConfig::load_from_file(CONFIG_FILE_NAME)
        .map_err(|_| anyhow!("No project configuration found. Run 'sss init' first."))?;

    // Get our keypair to decrypt the repository key
    let keystore = create_keystore(main_matches)?;

    // Get password if key is protected
    let password_str = get_password_if_protected(
        &keystore,
        "Enter your passphrase to add user (or press Enter if none): ",
    )?;
    let our_keypair = keystore.get_current_keypair(password_str.as_deref())?;

    // Get our sealed repository key and decrypt it
    let current_user =
        get_system_username().unwrap_or_else(|_| DEFAULT_USERNAME_FALLBACK.to_string());

    let sealed_key = config.get_sealed_key_for_user(&current_user)?;
    let repository_key = open_repository_key(&sealed_key, &our_keypair)?;

    // Add the new user
    config.add_user(username, &public_key, &repository_key)?;
    config.save_to_file(CONFIG_FILE_NAME)?;

    println!("Added user '{}' to project", username);
    println!("Public key: {}", public_key.to_base64());
    Ok(())
}

fn handle_users_remove(main_matches: &ArgMatches, sub_matches: &ArgMatches) -> Result<()> {
    let username = sub_matches.get_one::<String>("username").unwrap();

    // Load project config
    let mut config = ProjectConfig::load_from_file(CONFIG_FILE_NAME)?;

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

    // Get password if key is protected
    let password_str = get_password_if_protected(
        &keystore,
        "Enter your passphrase to perform key rotation (or press Enter if none): ",
    )?;
    let our_keypair = keystore.get_current_keypair(password_str.as_deref())?;

    // Get our sealed repository key and decrypt it
    let current_user =
        get_system_username().unwrap_or_else(|_| DEFAULT_USERNAME_FALLBACK.to_string());

    // We need to get the current repository key before removing the user
    // So we need to reload the original config
    let original_config = ProjectConfig::load_from_file(CONFIG_FILE_NAME)?;
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
        &std::path::PathBuf::from(CONFIG_FILE_NAME),
        &current_repository_key,
        reason,
    )?;

    result.print_summary();
    println!("✓ User '{}' removed and repository key rotated", username);
    Ok(())
}

fn handle_users_info(sub_matches: &ArgMatches) -> Result<()> {
    let username = sub_matches.get_one::<String>("username").unwrap();

    let config = ProjectConfig::load_from_file(CONFIG_FILE_NAME)
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
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Command;

    #[test]
    fn test_handle_users_requires_subcommand() {
        // Create minimal ArgMatches without subcommand
        let app = Command::new("test")
            .arg(clap::Arg::new("confdir").long("confdir"));
        let main_matches = app.get_matches_from(vec!["test"]);

        let users_app = Command::new("users");
        let users_matches = users_app.get_matches_from(vec!["users"]);

        let result = handle_users(&main_matches, &users_matches);

        // Should return error when no subcommand provided
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("No subcommand provided"));
        assert!(err_msg.contains("list"));
        assert!(err_msg.contains("add"));
        assert!(err_msg.contains("remove"));
        assert!(err_msg.contains("info"));
    }

    // Note: Most of handle_users() requires:
    // - Valid sss project with .sss.toml
    // - User keypairs for encryption
    // - Password prompts for protected keys
    // The logic delegates to well-tested functions:
    // - ProjectConfig::load_from_file() (tested in project module)
    // - create_keystore() (tested in utils)
    // - PublicKey::from_base64() (tested in crypto)
    // Integration tests verify the full user management workflow
}
