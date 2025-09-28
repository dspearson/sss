use anyhow::{anyhow, Result};
use clap::ArgMatches;
use std::path::PathBuf;

use crate::{
    config::init_project_config,
    constants::CONFIG_FILE_NAME,
    keystore::Keystore,
    secure_memory::password,
    validation::validate_username,
};

/// Create keystore instance based on global confdir parameter
fn create_keystore(matches: &ArgMatches) -> Result<Keystore> {
    if let Some(confdir) = matches.get_one::<String>("confdir") {
        Keystore::new_with_config_dir(PathBuf::from(confdir))
    } else {
        Keystore::new()
    }
}

/// Get the default system username
fn get_default_username() -> Result<String> {
    use std::env;

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

pub fn handle_init(main_matches: &ArgMatches, matches: &ArgMatches) -> Result<()> {
    let config_path = CONFIG_FILE_NAME;

    // Get username
    let username = if let Some(user) = matches.get_one::<String>("username") {
        user.clone()
    } else {
        get_default_username().map_err(|_| {
            anyhow!("Could not determine username. Please provide one: sss init <username>")
        })?
    };

    // Validate username
    validate_username(&username)?;

    // Check if user has a current keypair (MUST exist, no generation)
    let keystore = create_keystore(main_matches)?;
    let keypair = match keystore.get_current_keypair(None) {
        Ok(keypair) => {
            println!("Using existing keypair for project initialization");
            keypair
        }
        Err(_) => {
            // Key exists but is password protected - ask for password
            let password = password::read_password(
                "Enter passphrase for existing keypair (or press Enter if none): ",
            )?;

            if password.is_empty() {
                // User pressed Enter, try again without password
                match keystore.get_current_keypair(None) {
                    Ok(keypair) => keypair,
                    Err(_) => {
                        return Err(anyhow!(
                            "No keypair found.\n\
                            Generate a keypair first with: sss keys generate\n\
                            Or for passwordless keys: sss keys generate --no-password"
                        ));
                    }
                }
            } else {
                // User provided a password
                match keystore.get_current_keypair(Some(password.as_str()?)) {
                    Ok(keypair) => keypair,
                    Err(_) => {
                        return Err(anyhow!(
                            "Incorrect passphrase or no keypair found.\n\
                            Generate a keypair first with: sss keys generate\n\
                            Or for passwordless keys: sss keys generate --no-password"
                        ));
                    }
                }
            }
        }
    };

    // Initialize project
    init_project_config(config_path, &username, &keypair.public_key)?;

    println!("Project initialized successfully!");
    println!("Username: {}", username);
    println!("Public key: {}...", &keypair.public_key.to_base64()[..32]);

    Ok(())
}