#![allow(clippy::missing_errors_doc, clippy::items_after_statements)]

use anyhow::{anyhow, Result};
use clap::ArgMatches;
use std::fs;
use std::path::Path;

use crate::{
    commands::utils::{create_keystore, get_password_if_protected, get_system_username},
    config::get_project_config_path,
    constants::{DEFAULT_USERNAME_FALLBACK, ERR_NO_PROJECT_CONFIG},
    crypto::{KeyPair, PublicKey, Suite, suite_for},
    project::ProjectConfig,
};

pub fn handle_users(main_matches: &ArgMatches, matches: &ArgMatches) -> Result<()> {
    match matches.subcommand() {
        Some(("list", _)) => handle_users_list()?,
        Some(("add", sub_matches)) => handle_users_add(main_matches, sub_matches)?,
        Some(("remove", sub_matches)) => handle_users_remove(main_matches, sub_matches)?,
        Some(("info", sub_matches)) => handle_users_info(sub_matches)?,
        Some(("add-hybrid-key", sub_matches)) => handle_users_add_hybrid_key(sub_matches)?,
        None => {
            // No subcommand provided, show available subcommands
            return Err(anyhow!(
                "No subcommand provided\n\n\
                Available subcommands:\n\
                  list           List project users\n\
                  add            Add a user to the project\n\
                  remove         Remove a user from the project\n\
                  info           Show information about a user\n\
                  add-hybrid-key Register a user's hybrid public key\n\n\
                Use 'sss users <subcommand> --help' for more information on a subcommand."
            ));
        }
        _ => unreachable!(),
    }

    Ok(())
}

fn handle_users_list() -> Result<()> {
    let config_path = get_project_config_path()?;
    let config = ProjectConfig::load_from_file(&config_path)
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
                        println!("  {username} - (invalid public key)");
                    }
                }
            }
        }
    }
    Ok(())
}

fn handle_users_add(main_matches: &ArgMatches, sub_matches: &ArgMatches) -> Result<()> {
    use base64::Engine as _;

    let username = sub_matches.get_one::<String>("username").unwrap();
    let public_key_input = sub_matches.get_one::<String>("public-key").unwrap();

    // Decode raw bytes from file or inline base64; dispatch on length below.
    let raw: Vec<u8> = if Path::new(public_key_input).exists() {
        let content = fs::read_to_string(public_key_input)?;
        base64::prelude::BASE64_STANDARD
            .decode(content.trim())
            .map_err(|e| anyhow!("invalid base64 in key file: {e}"))?
    } else {
        base64::prelude::BASE64_STANDARD
            .decode(public_key_input)
            .map_err(|e| anyhow!("invalid base64 public key: {e}"))?
    };

    // 32 bytes → classic X25519;  1214 bytes → hybrid X448+sntrup761.
    let new_pub: PublicKey = match raw.len() {
        32 => PublicKey::Classic(raw.try_into().unwrap()),
        #[cfg(feature = "hybrid")]
        n if n == crate::constants::HYBRID_PUBLIC_KEY_SIZE => {
            PublicKey::Hybrid(crate::crypto::HybridPublicKey::from_bytes(&raw)?)
        }
        n => {
            #[cfg(feature = "hybrid")]
            return Err(anyhow!(
                "unrecognised public key length {n} bytes — \
                 expected 32 (classic X25519) or {} (hybrid X448+sntrup761)",
                crate::constants::HYBRID_PUBLIC_KEY_SIZE
            ));
            #[cfg(not(feature = "hybrid"))]
            return Err(anyhow!(
                "unrecognised public key length {n} bytes — expected 32 bytes (classic X25519)"
            ));
        }
    };

    let config_path = get_project_config_path()?;
    let mut config = ProjectConfig::load_from_file(&config_path)
        .map_err(|_| anyhow!("No project configuration found. Run 'sss init' first."))?;

    // Reject mismatches between the provided key type and the project suite.
    let suite = config.suite()?;
    match (&new_pub, suite) {
        (PublicKey::Classic(_), Suite::Hybrid) => {
            return Err(anyhow!(
                "this is a v2 (hybrid) project — provide a hybrid public key (~1600 chars base64).\n\
                 Run `sss keys pubkey` on their machine to get it."
            ));
        }
        #[cfg(feature = "hybrid")]
        (PublicKey::Hybrid(_), Suite::Classic) => {
            return Err(anyhow!(
                "this is a v1 (classic) project — provide a classic public key (~44 chars base64).\n\
                 Run `sss keys pubkey` on their machine to get it."
            ));
        }
        _ => {}
    }

    let keystore = create_keystore(main_matches)?;
    let password_str = get_password_if_protected(
        &keystore,
        "Enter your passphrase to add user (or press Enter if none): ",
    )?;

    let current_user =
        get_system_username().unwrap_or_else(|_| DEFAULT_USERNAME_FALLBACK.to_string());
    let sealed_key = config.get_sealed_key_for_user(&current_user)?;

    // Open with the suite that sealed it — classic for v1, hybrid for v2.
    let open_suite = suite_for(suite)?;
    let our_keypair: KeyPair = if suite == Suite::Hybrid {
        #[cfg(feature = "hybrid")]
        {
            let id = keystore.get_current_key_id()?;
            KeyPair::Hybrid(keystore.load_hybrid_keypair(&id, password_str.as_deref())?)
        }
        #[cfg(not(feature = "hybrid"))]
        return Err(anyhow!("hybrid suite requires a --features hybrid build"));
    } else {
        keystore.get_current_keypair(password_str.as_deref())?
    };
    let repository_key = open_suite.open_repo_key(&sealed_key, &our_keypair)?;

    // add_user dispatches sealing via config.suite() internally.
    config.add_user(username, &new_pub, &repository_key)?;
    config.save_to_file(&config_path)?;

    println!("Added user '{username}' to project");
    println!("Public key: {}", new_pub.to_base64());
    Ok(())
}

fn handle_users_remove(main_matches: &ArgMatches, sub_matches: &ArgMatches) -> Result<()> {
    let username = sub_matches.get_one::<String>("username").unwrap();

    // Load project config once.
    let config_path = get_project_config_path()?;
    let mut config = ProjectConfig::load_from_file(&config_path)?;
    let suite = config.suite()?;

    // Check if user exists
    if !config.users.contains_key(username) {
        return Err(anyhow!("User '{username}' not found in project"));
    }

    // Check if this is the last user
    if config.users.len() == 1 {
        return Err(anyhow!(
            "Cannot remove the last user from the project. Use 'sss init' to recreate the project if needed."
        ));
    }

    // Capture the current user's sealed repository key BEFORE any in-memory
    // mutation — otherwise removing the target user from the map first would
    // be brittle (today's rotation path reloads from disk, but that is an
    // implementation detail we should not rely on here).
    let current_user =
        get_system_username().unwrap_or_else(|_| DEFAULT_USERNAME_FALLBACK.to_string());
    let sealed_key = config.get_sealed_key_for_user(&current_user)?;

    // Now it is safe to remove the user from the in-memory copy. `rotation`
    // rewrites the user map wholesale from disk, but keeping the local state
    // honest makes future refactors safer.
    config.remove_user(username)?;

    println!("Removing user '{username}' from project...");
    println!("⚠️  This will trigger automatic key rotation for security");

    // Confirm rotation
    use crate::rotation::{confirm_rotation, RotationReason};
    let reason = RotationReason::UserRemoved(username.clone());
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
    // Open with the suite that sealed it — classic for v1, hybrid for v2.
    let open_suite = suite_for(suite)?;
    let our_keypair: KeyPair = if suite == Suite::Hybrid {
        #[cfg(feature = "hybrid")]
        {
            let id = keystore.get_current_key_id()?;
            KeyPair::Hybrid(keystore.load_hybrid_keypair(&id, password_str.as_deref())?)
        }
        #[cfg(not(feature = "hybrid"))]
        return Err(anyhow!("hybrid suite requires a --features hybrid build"));
    } else {
        keystore.get_current_keypair(password_str.as_deref())?
    };

    // Decrypt the sealed repository key captured above.
    let current_repository_key = open_suite.open_repo_key(&sealed_key, &our_keypair)?;

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
        &config_path,
        &current_repository_key,
        reason,
    )?;

    result.print_summary();
    println!("✓ User '{username}' removed and repository key rotated");
    Ok(())
}

fn handle_users_info(sub_matches: &ArgMatches) -> Result<()> {
    let username = sub_matches.get_one::<String>("username").unwrap();

    let config_path = get_project_config_path()?;
    let config = ProjectConfig::load_from_file(&config_path)
        .map_err(|_| anyhow!("No project configuration found. Run 'sss init' first."))?;

    if let Some(user_config) = config.users.get(username) {
        println!("User: {username}");
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
        return Err(anyhow!("User '{username}' not found in project"));
    }
    Ok(())
}

/// Register a hybrid public key for a user in the project config.
///
/// Validates the base64 string decodes to exactly `HYBRID_PUBLIC_KEY_SIZE`
/// bytes, then writes it into the user's `hybrid_public` field in `.sss.toml`.
/// Does NOT unseal `K` or touch `sealed_key`.
#[cfg(feature = "hybrid")]
fn handle_users_add_hybrid_key(sub_matches: &ArgMatches) -> Result<()> {
    use base64::Engine as _;
    use crate::constants::HYBRID_PUBLIC_KEY_SIZE;

    let username = sub_matches.get_one::<String>("username").unwrap();
    let hybrid_b64 = sub_matches.get_one::<String>("hybrid-pubkey").unwrap();

    // Validate length before touching disk (T-04-01-01)
    let raw = base64::prelude::BASE64_STANDARD
        .decode(hybrid_b64)
        .map_err(|e| anyhow!("invalid base64 for hybrid public key: {e}"))?;
    if raw.len() != HYBRID_PUBLIC_KEY_SIZE {
        return Err(anyhow!(
            "hybrid public key must be {HYBRID_PUBLIC_KEY_SIZE} bytes when decoded, got {}",
            raw.len()
        ));
    }

    let config_path = crate::config::get_project_config_path()?;
    let mut config = ProjectConfig::load_from_file(&config_path)
        .map_err(|_| anyhow!("No project configuration found. Run 'sss init' first."))?;

    let user = config.users.get_mut(username.as_str()).ok_or_else(|| {
        anyhow!("User '{}' not found in project", username)
    })?;
    user.hybrid_public = Some(hybrid_b64.clone());

    config.save_to_file(&config_path)?;
    println!("Registered hybrid public key for user '{username}'");
    Ok(())
}

/// Feature-absent stub — fires when `hybrid` feature is not compiled in.
#[cfg(not(feature = "hybrid"))]
fn handle_users_add_hybrid_key(_sub_matches: &ArgMatches) -> Result<()> {
    Err(anyhow!("hybrid suite requires a --features hybrid build"))
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
        assert!(err_msg.contains("add-hybrid-key"), "error must mention add-hybrid-key: {err_msg}");
    }

    // --- Plan 04-01: handle_users_add_hybrid_key unit tests ---

    /// Build a minimal ArgMatches for the add-hybrid-key subcommand.
    #[cfg(feature = "hybrid")]
    fn make_add_hybrid_key_matches(username: &str, hybrid_b64: &str) -> ArgMatches {
        use clap::{Arg, Command};
        let app = Command::new("add-hybrid-key")
            .arg(Arg::new("username").required(true))
            .arg(Arg::new("hybrid-pubkey").required(true));
        app.get_matches_from(vec!["add-hybrid-key", username, hybrid_b64])
    }

    #[test]
    #[cfg(feature = "hybrid")]
    fn test_add_hybrid_key_wrong_length_errors() {
        use base64::Engine as _;
        // Encode 100 bytes (not 1214) — must error with "1214 bytes"
        let short_b64 = base64::prelude::BASE64_STANDARD.encode(vec![0u8; 100]);
        let matches = make_add_hybrid_key_matches("alice", &short_b64);
        let err = handle_users_add_hybrid_key(&matches).unwrap_err().to_string();
        assert!(
            err.contains("1214"),
            "error must mention 1214 bytes; got: {err}"
        );
    }

    #[test]
    #[cfg(feature = "hybrid")]
    fn test_add_hybrid_key_invalid_base64_errors() {
        let matches = make_add_hybrid_key_matches("alice", "not-valid-base64!!!");
        let err = handle_users_add_hybrid_key(&matches).unwrap_err().to_string();
        assert!(
            err.contains("invalid base64") || err.contains("base64"),
            "error must mention base64 decoding; got: {err}"
        );
    }

    #[test]
    #[cfg(feature = "hybrid")]
    fn test_add_hybrid_key_correct_length_sets_field() {
        use base64::Engine as _;
        use crate::constants::HYBRID_PUBLIC_KEY_SIZE;
        use tempfile::tempdir;

        // Build a minimal .sss.toml with one user "alice".
        let temp_dir = tempdir().unwrap();
        let config_path = temp_dir.path().join(".sss.toml");
        let keypair = crate::crypto::KeyPair::generate().unwrap();
        crate::project::ProjectConfig::new("alice", &keypair.public_key())
            .unwrap()
            .save_to_file(&config_path)
            .unwrap();

        // Override cwd so get_project_config_path() finds the temp dir.
        let _orig = std::env::current_dir().unwrap();
        std::env::set_current_dir(temp_dir.path()).unwrap();

        let valid_b64 = base64::prelude::BASE64_STANDARD.encode(vec![0x42u8; HYBRID_PUBLIC_KEY_SIZE]);
        let matches = make_add_hybrid_key_matches("alice", &valid_b64);
        let result = handle_users_add_hybrid_key(&matches);

        // Restore cwd regardless
        std::env::set_current_dir(_orig).unwrap();

        result.expect("correct 1214-byte key must succeed");

        // Verify the field was persisted.
        let saved = crate::project::ProjectConfig::load_from_file(&config_path).unwrap();
        assert_eq!(
            saved.users.get("alice").unwrap().hybrid_public.as_deref(),
            Some(valid_b64.as_str()),
            "hybrid_public must be persisted after add-hybrid-key"
        );
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
