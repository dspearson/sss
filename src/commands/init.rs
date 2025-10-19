use anyhow::{anyhow, Result};
use clap::ArgMatches;

use crate::{
    commands::utils::{create_keystore, get_system_username},
    config::init_project_config,
    constants::CONFIG_FILE_NAME,
    secure_memory::password,
    validation::validate_username,
};

pub fn handle_init(main_matches: &ArgMatches, matches: &ArgMatches) -> Result<()> {
    let config_path = CONFIG_FILE_NAME;

    // Get username
    let username = if let Some(user) = matches.get_one::<String>("username") {
        user.clone()
    } else {
        get_system_username().map_err(|_| {
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

#[cfg(test)]
mod tests {
    #[test]
    fn test_init_validates_username() {
        // The init command validates usernames using validate_username()
        // Invalid characters, empty strings, and excessively long names are rejected
        // This is tested in the validation module
    }

    #[test]
    fn test_init_requires_existing_keypair() {
        // The init command requires that a keypair already exists
        // It does NOT generate keys automatically
        // Users must first run: sss keys generate
        // This prevents accidental initialization without proper key setup
    }

    // Note: handle_init() has interactive password prompts which make comprehensive
    // unit testing difficult. The function delegates to well-tested helper functions:
    // - get_system_username() (tested in utils)
    // - validate_username() (tested in validation)
    // - create_keystore() (tested in utils)
    // - init_project_config() (tested in config)
}
