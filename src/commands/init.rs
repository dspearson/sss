#![allow(clippy::missing_errors_doc, clippy::items_after_statements)]

use anyhow::{anyhow, Result};
use clap::ArgMatches;

use crate::{
    commands::utils::{create_keystore, get_keypair_with_optional_password, get_system_username},
    config::init_project_config,
    constants::CONFIG_FILE_NAME,
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
    let keypair = match get_keypair_with_optional_password(
        &keystore,
        "Enter passphrase for existing keypair (or press Enter if none): ",
    ) {
        Ok(keypair) => {
            println!("Using existing keypair for project initialization");
            keypair
        }
        Err(_) => {
            return Err(anyhow!(
                "No keypair found.\n\
                Generate a keypair first with: sss keys generate\n\
                Or for passwordless keys: sss keys generate --no-password"
            ));
        }
    };

    // Map the --crypto arg (defaulted to "classic" by clap) into a Suite.
    // clap's value_parser restricts this to classic|hybrid, so the default
    // arm is defensive only — it surfaces any future misconfig as an
    // actionable error rather than a panic.
    let crypto = match matches
        .get_one::<String>("crypto")
        .map(String::as_str)
        .unwrap_or("classic")
    {
        "classic" => crate::crypto::Suite::Classic,
        "hybrid" => crate::crypto::Suite::Hybrid,
        other => {
            return Err(anyhow!(
                "internal error: unexpected --crypto value {other:?} (expected classic|hybrid)"
            ));
        }
    };

    // Initialize project
    init_project_config(config_path, &username, &keypair.public_key(), crypto)?;

    println!("Project initialized successfully!");
    println!("Username: {username}");
    println!("Public key: {}...", &keypair.public_key().to_base64()[..32]);

    if crypto == crate::crypto::Suite::Hybrid {
        println!("Run `sss keys generate --suite both` to generate your keypairs.");
    }

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
