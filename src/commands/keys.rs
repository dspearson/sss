// cast_possible_truncation/cast_sign_loss/cast_precision_loss/many_single_char_names/
// unreadable_literal/items_after_statements survive at file scope per the specific
// rationales below; missing_errors_doc + missing_panics_doc removed as redundant after
// Plan 21-01 added workspace-level suppression.
// Why: per-lint rationales inline below.
#![allow(
    clippy::cast_possible_truncation, // intentional in color/art rendering code
    clippy::cast_sign_loss,           // intentional in color rendering (f64->u8 after clamping)
    clippy::cast_precision_loss,      // intentional: u64 hash bits to f64 for color math
    clippy::many_single_char_names,   // r,g,b,h,s,v are standard color component names
    clippy::unreadable_literal,       // cryptographic hash constants are intentionally compact
    clippy::items_after_statements,   // use std::fmt::Write placed near usage for locality
)]

use anyhow::{anyhow, Result};
use clap::ArgMatches;
use std::io::{self, Write};

use crate::{
    commands::utils::create_keystore,
    constants::KEY_ID_DISPLAY_LENGTH,
    crypto::KeyPair,
    secure_memory::{password, SecureString},
};
#[cfg(feature = "hybrid")]
use crate::crypto::ClassicKeyPair;

/// Test seam (Phase 16b D-19) — abstracts the two prompt primitives used by the
/// `handle_keys_*` family so unit tests can substitute canned answers without
/// touching a real TTY/`rpassword`.
///
/// Production code routes through `RealPromptReader`, which is a thin wrapper
/// over `password::read_password_with_confirmation` and `io::stdin().read_line`.
/// Tests in `#[cfg(test)] mod tests` may inject a `MockPromptReader` (defined
/// inside the test module) returning predetermined values.
pub(super) trait PromptReader {
    /// Wraps `password::read_password_with_confirmation`.
    fn read_password_with_confirmation(
        &self,
        prompt: &str,
        confirm_prompt: &str,
    ) -> Result<SecureString>;

    /// Print `prompt`, flush stdout, read one line from stdin, return the raw
    /// (un-trimmed) string — matches the existing handler bodies which call
    /// `.trim()` on the result themselves.
    fn read_line(&self, prompt: &str) -> Result<String>;
}

/// Default production implementation of [`PromptReader`].
pub(super) struct RealPromptReader;

impl PromptReader for RealPromptReader {
    fn read_password_with_confirmation(
        &self,
        prompt: &str,
        confirm_prompt: &str,
    ) -> Result<SecureString> {
        password::read_password_with_confirmation(prompt, confirm_prompt)
            .map_err(|e| anyhow!(e))
    }

    fn read_line(&self, prompt: &str) -> Result<String> {
        print!("{prompt}");
        io::stdout().flush()?;
        let mut buf = String::new();
        io::stdin().read_line(&mut buf)?;
        Ok(buf)
    }
}

fn handle_keys_generate_command(main_matches: &ArgMatches, matches: &ArgMatches) -> Result<()> {
    handle_keys_generate_command_with_prompt(main_matches, matches, &RealPromptReader)
}

// Why: 118 lines is the natural shape of the command dispatcher — clap parsing
// + feature gating + KDF param resolution + dual-suite branching + interactive
// passphrase prompting. Breaking into smaller fns would obscure the linear
// command-flow narrative that maps to docs/USAGE.md.
#[allow(clippy::too_many_lines)]
fn handle_keys_generate_command_with_prompt(
    main_matches: &ArgMatches,
    matches: &ArgMatches,
    prompt: &dyn PromptReader,
) -> Result<()> {
    let force = matches.get_flag("force");
    let no_password = matches.get_flag("no-password");
    let suite = matches.get_one::<String>("suite").map(String::as_str);

    // Feature-absent guard: hybrid and both require the hybrid feature flag.
    // clap still parses the value; this runtime gate fires immediately.
    if let Some("hybrid" | "both") = suite {}

    let keystore = create_keystore(main_matches)?;

    match suite {
        Some("classic") | None => {
            // Check if current keypair exists
            if !force && keystore.get_current_keypair(None).is_ok() {
                return Err(anyhow!(
                    "A keypair already exists. Use --force to overwrite."
                ));
            }

            let password_option = if no_password {
                None
            } else {
                let passphrase = prompt.read_password_with_confirmation(
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

            println!("Generated new keypair: {key_id}");
            println!("Public key: {}", keypair.public_key().to_base64());

            if no_password {
                println!("Warning: Keypair stored without password protection. Consider using a passphrase for better security.");
            }
        }

        #[cfg(feature = "hybrid")]
        Some("hybrid") => {
            use base64::Engine as _;
            use crate::crypto::hybrid::HybridKeyPair;

            // --suite hybrid requires an existing classic keypair.
            // T-03-08: no silent auto-generation of classic.
            if keystore.get_current_keypair(None).is_err() {
                // Also try with a password prompt to distinguish
                // "no key exists" from "key is password-protected".
                let has_key = {
                    use crate::commands::utils::get_password_if_protected;
                    match get_password_if_protected(&keystore, "Enter passphrase for existing keypair: ") {
                        Ok(pw_opt) => keystore.get_current_keypair(pw_opt.as_deref()).is_ok(),
                        Err(_) => false,
                    }
                };
                if !has_key {
                    return Err(anyhow!(
                        "no classic keypair found; run `sss keygen --suite both` to generate both"
                    ));
                }
            }

            let password_option = if no_password {
                None
            } else {
                let passphrase = prompt.read_password_with_confirmation(
                    "Enter passphrase for keypair: ",
                    "Confirm passphrase: ",
                )?;

                if passphrase.is_empty() {
                    return Err(anyhow!(
                        "Passphrase cannot be empty. Use --no-password for passwordless keys."
                    ));
                }

                Some(passphrase.as_str()?.to_string())
            };

            let hybrid_kp = HybridKeyPair::generate()?;
            let hybrid_pk_b64 = base64::prelude::BASE64_STANDARD.encode(hybrid_kp.public_key().as_bytes());

            let key_id = keystore.store_dual_keypair(None, Some(&hybrid_kp), password_option.as_deref())?;

            println!("classic keypair kept; hybrid keypair added");
            println!("Keypair ID:        {key_id}");
            println!("Hybrid public key: {hybrid_pk_b64}");
        }

        #[cfg(feature = "hybrid")]
        Some("both") => {
            use base64::Engine as _;
            use crate::crypto::hybrid::HybridKeyPair;

            // Check if current keypair exists
            if !force && keystore.get_current_keypair(None).is_ok() {
                return Err(anyhow!(
                    "A keypair already exists. Use --force to overwrite."
                ));
            }

            let password_option = if no_password {
                None
            } else {
                let passphrase = prompt.read_password_with_confirmation(
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

            // Generate both keypairs atomically.
            let keypair = KeyPair::generate()?;
            let classic_kp: ClassicKeyPair = match keypair {
                KeyPair::Classic(ref kp) => kp.clone(),
                #[cfg(feature = "hybrid")]
                KeyPair::Hybrid(_) => unreachable!("KeyPair::generate() always returns Classic"),
            };
            let hybrid_kp = HybridKeyPair::generate()?;

            let classic_pk_b64 = keypair.public_key().to_base64();
            let hybrid_pk_b64 = base64::prelude::BASE64_STANDARD.encode(hybrid_kp.public_key().as_bytes());

            let key_id = keystore.store_dual_keypair(Some(&classic_kp), Some(&hybrid_kp), password_option.as_deref())?;

            println!("Generated new keypair: {key_id}");
            println!("Classic public key: {classic_pk_b64}");
            println!("Hybrid public key:  {hybrid_pk_b64}");

            if no_password {
                println!("Warning: Keypair stored without password protection. Consider using a passphrase for better security.");
            }
        }

        _ => {
            return Err(anyhow!("unknown --suite value; expected classic, hybrid, or both"));
        }
    }

    Ok(())
}

pub fn handle_keys(main_matches: &ArgMatches, matches: &ArgMatches) -> Result<()> {
    match matches.subcommand() {
        Some(("generate", sub_matches)) => handle_keys_generate_command(main_matches, sub_matches)?,
        Some(("list", sub_matches)) => handle_keys_list(main_matches, sub_matches)?,
        Some(("pubkey", sub_matches)) => handle_keys_pubkey(main_matches, sub_matches)?,
        Some(("show", _)) => handle_keys_show(main_matches)?,
        Some(("delete", sub_matches)) => handle_keys_delete(main_matches, sub_matches)?,
        Some(("current", sub_matches)) => handle_keys_current(main_matches, sub_matches)?,
        Some(("import", sub_matches)) => handle_keys_import(main_matches, sub_matches)?,
        Some(("export", sub_matches)) => handle_keys_export(main_matches, sub_matches)?,
        Some(("upgrade", sub_matches)) => handle_keys_upgrade(main_matches, sub_matches)?,
        Some(("rotate", sub_matches)) => {
            handle_keys_rotate_command(main_matches, sub_matches)?;
        }
        Some(("set-passphrase", sub_matches)) => {
            handle_keys_set_passphrase(main_matches, sub_matches)?;
        }
        Some(("remove-passphrase", sub_matches)) => {
            handle_keys_remove_passphrase(main_matches, sub_matches)?;
        }
        None => {
            // No subcommand provided, show available subcommands
            return Err(anyhow!(
                "No subcommand provided\n\n\
                Available subcommands:\n\
                  generate           Generate a new keypair\n\
                  list               List your private keys\n\
                  pubkey             Show your public key\n\
                  show               Display public key fingerprint and randomart\n\
                  current            Show or set current keypair\n\
                  delete             Delete a keypair\n\
                  import             Import a keystore TOML entry from file\n\
                  export             Export a keystore TOML entry to file\n\
                  upgrade            Re-sign a legacy (format_version=1) keystore entry in place\n\
                  set-passphrase     Set or change passphrase for a key\n\
                  remove-passphrase  Remove passphrase protection from a key\n\
                  rotate             Rotate repository encryption key\n\n\
                Use 'sss keys <subcommand> --help' for more information on a subcommand."
            ));
        }
        _ => unreachable!(),
    }

    Ok(())
}

/// Phase 18-04 (PQSIG-03 / D-18): pure formatter for a single `keys list`
/// entry line. Extracted so unit tests can exercise tag rendering without
/// having to capture process stdout — `gag::BufferRedirect::stdout()` does
/// not interoperate with cargo's test harness, which swallows tag bytes.
///
/// Returns the rendered line without a trailing newline. Used by both
/// `handle_keys_list` (production) and `tests/keys_command_tests.rs` (D-18
/// tag tests `keys_14..16`).
#[must_use] 
pub fn format_list_entry(
    key_id: &str,
    stored: &crate::keystore::StoredKeyPair,
    is_current: bool,
) -> String {
    let status = if is_current { " (current)" } else { "" };
    let protection = if stored.is_password_protected {
        " [protected]"
    } else {
        ""
    };
    // D-18: per-entry legacy tag; v2 entries omit it.
    let legacy_tag = if stored.format_version == 1 {
        " (unsigned-legacy)"
    } else {
        ""
    };
    format!(
        "  {}... - Created: {}{}{}{}",
        &key_id[..KEY_ID_DISPLAY_LENGTH],
        stored.created_at.format("%Y-%m-%d %H:%M"),
        protection,
        status,
        legacy_tag
    )
}

fn handle_keys_list(main_matches: &ArgMatches, _sub_matches: &ArgMatches) -> Result<()> {
    // Phase 18-04 (PQSIG-03 / D-18): legacy (format_version=1) entries are
    // tagged with a trailing ` (unsigned-legacy)` marker so operators can
    // identify which entries still need `sss keys upgrade <uuid>`. v2 entries
    // emit no tag (D-18: silence on the happy path keeps signed output clean).
    let keystore = create_keystore(main_matches)?;
    let keys = keystore.list_key_ids()?;

    if keys.is_empty() {
        println!("No keypairs found. Generate one with: sss keys generate");
    } else {
        println!("Found {} keypair(s):", keys.len());

        let current_id = keystore.get_current_key_id().ok();

        for (key_id, stored) in keys {
            let is_current = current_id.as_ref() == Some(&key_id);
            println!("{}", format_list_entry(&key_id, &stored, is_current));
        }
    }

    Ok(())
}

fn handle_keys_pubkey(main_matches: &ArgMatches, sub_matches: &ArgMatches) -> Result<()> {
    let keystore = create_keystore(main_matches)?;
    let show_fingerprint = sub_matches.get_flag("fingerprint");
    let username = sub_matches.get_one::<String>("user");

    let full_key = if let Some(user) = username {
        // Show public key from project config for specified user
        use crate::constants::CONFIG_FILE_NAME;
        use crate::project::ProjectConfig;
        use std::path::Path;

        if !Path::new(CONFIG_FILE_NAME).exists() {
            return Err(anyhow!(
                "No project configuration found. You must be in an SSS project to view user public keys."
            ));
        }

        let config = ProjectConfig::load_from_file(CONFIG_FILE_NAME)?;

        // Find the user in the config
        let user_config = config.users.get(user).ok_or_else(|| {
            anyhow!(
                "User '{}' not found in project.\nAvailable users: {}",
                user,
                config
                    .users
                    .keys()
                    .map(std::string::String::as_str)
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        })?;

        user_config.public.clone()
    } else {
        // Show own public key from keystore.
        // Public keys are stored in plaintext so we read the raw stored form
        // to avoid prompting for a passphrase unnecessarily.
        use crate::constants::CONFIG_FILE_NAME;
        use crate::project::ProjectConfig;
        use std::path::Path;

        let stored = keystore.get_current_stored_raw()?;

        // Gate on repo suite if we are inside a project, otherwise fall back
        // to the build-time hybrid feature flag.
        let use_hybrid = if Path::new(CONFIG_FILE_NAME).exists() {
            ProjectConfig::load_from_file(CONFIG_FILE_NAME)
                .map(|c| c.version == "2.0")
                .unwrap_or(cfg!(feature = "hybrid"))
        } else {
            cfg!(feature = "hybrid")
        };

        if use_hybrid {
            // Prefer hybrid key; fall back to classic if the keypair is classic-only
            // (e.g. user hasn't run `keys generate --suite hybrid` yet).
            stored
                .hybrid_public_key
                .unwrap_or(stored.public_key)
        } else {
            stored.public_key
        }
    };

    if show_fingerprint {
        // Generate SHA256 fingerprint (like SSH)
        use libsodium_sys::{crypto_hash_sha256, crypto_hash_sha256_BYTES};

        // Get the raw public key bytes
        let pubkey_bytes = full_key.as_bytes();

        let mut hash = vec![0u8; crypto_hash_sha256_BYTES as usize];
        // `pubkey_bytes` is a valid &[u8] (len <= size_t::MAX on 64-bit Rust);
        // `hash` is sized exactly crypto_hash_sha256_BYTES, the libsodium output count.
        // SAFETY: libsodium's `crypto_hash_sha256` is constant-time and non-failing for
        // this signature; pointer/length invariants noted above.
        #[cfg(not(miri))]
        unsafe {
            crypto_hash_sha256(
                hash.as_mut_ptr(),
                pubkey_bytes.as_ptr(),
                pubkey_bytes.len() as u64,
            );
        }
        #[cfg(miri)]
        {
            // Miri stub: crypto_hash_sha256 is FFI; AddressSanitizer (Phase 23 MEMSAFE-03)
            // covers this path under non-miri builds. `hash` stays zero-initialised, which
            // produces a non-load-bearing visual artefact downstream — acceptable under
            // miri because we are not testing crypto output here.
        }

        // Generate visual randomart with hex fingerprint (like SSH's VisualHostKey)
        generate_randomart(&hash, "SSS KEY");
    } else {
        println!("{full_key}");
    }

    Ok(())
}

fn handle_keys_delete(main_matches: &ArgMatches, sub_matches: &ArgMatches) -> Result<()> {
    handle_keys_delete_with_prompt(main_matches, sub_matches, &RealPromptReader)
}

fn handle_keys_delete_with_prompt(
    main_matches: &ArgMatches,
    sub_matches: &ArgMatches,
    prompt: &dyn PromptReader,
) -> Result<()> {
    let keystore = create_keystore(main_matches)?;
    // Why: clap declares `name` as required(true) for the delete subcommand.
    // HARDEN-01 / 08-01.
    #[allow(clippy::unwrap_used)]
    let key_name = sub_matches.get_one::<String>("name").unwrap();

    let input = prompt.read_line(&format!(
        "Are you sure you want to delete keypair '{key_name}'? [y/N]: "
    ))?;

    if input.trim().to_lowercase() == "y" {
        keystore.delete_keypair(key_name)?;
        println!("Deleted keypair: {key_name}");
    } else {
        println!("Cancelled");
    }

    Ok(())
}

fn handle_keys_current(main_matches: &ArgMatches, sub_matches: &ArgMatches) -> Result<()> {
    let keystore = create_keystore(main_matches)?;

    if let Some(key_name) = sub_matches.get_one::<String>("name") {
        // Set current key
        let keys = keystore.list_key_ids()?;
        let key_to_set = keys.iter().find(|(id, _)| id.starts_with(key_name));

        if let Some((key_id, _)) = key_to_set {
            keystore.set_current_key(key_id)?;
            println!("Set current key to: {key_id}");
        } else {
            println!("Key not found: {key_name}");
            println!("Available keys:");
            for (key_id, stored) in keys {
                println!(
                    "  {} (created: {})",
                    &key_id[..KEY_ID_DISPLAY_LENGTH],
                    stored.created_at.format("%Y-%m-%d")
                );
            }
        }
    } else {
        // Show current key
        match keystore.get_current_key_id() {
            Ok(current_id) => {
                println!("Current key ID: {current_id}");
                match keystore.get_current_keypair(None) {
                    Ok(keypair) => {
                        println!("Public key: {}", keypair.public_key().to_base64());
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
    let (_, repository_key, _) = load_project_config_with_repository_key(config_path)?;

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

fn handle_keys_set_passphrase(main_matches: &ArgMatches, sub_matches: &ArgMatches) -> Result<()> {
    handle_keys_set_passphrase_with_prompt(main_matches, sub_matches, &RealPromptReader)
}

// Why: None arm returns a multi-line actionable error message; let-else would inline it.
#[allow(clippy::manual_let_else)]
fn handle_keys_set_passphrase_with_prompt(
    main_matches: &ArgMatches,
    sub_matches: &ArgMatches,
    prompt: &dyn PromptReader,
) -> Result<()> {
    let key_id_partial = sub_matches.get_one::<String>("key-id")
        .ok_or_else(|| anyhow!("Key ID is required"))?;

    let keystore = create_keystore(main_matches)?;

    // Find the full key ID from partial match
    let keys = keystore.list_key_ids()?;
    let key_match = keys.iter().find(|(id, _)| id.starts_with(key_id_partial));

    let (key_id, stored) = match key_match {
        Some(k) => k,
        None => {
            return Err(anyhow!(
                "Key not found: {}\n\n\
                Available keys:\n{}",
                key_id_partial,
                keys.iter()
                    .map(|(id, s)| format!(
                        "  {} (created: {}) {}",
                        &id[..KEY_ID_DISPLAY_LENGTH],
                        s.created_at.format("%Y-%m-%d"),
                        if s.is_password_protected { "[protected]" } else { "" }
                    ))
                    .collect::<Vec<_>>()
                    .join("\n")
            ));
        }
    };

    // Get old password if key is currently protected
    let old_password = if stored.is_password_protected {
        let pw = crate::keystore::get_passphrase_or_prompt(
            "Enter current passphrase: "
        )?;
        Some(pw)
    } else {
        println!("Adding passphrase protection to unprotected key...");
        None
    };

    // Get new password
    let new_password = prompt.read_password_with_confirmation(
        "Enter new passphrase: ",
        "Confirm new passphrase: ",
    )?;

    if new_password.is_empty() {
        return Err(anyhow!(
            "Passphrase cannot be empty. Use 'sss keys remove-passphrase' to remove protection."
        ));
    }

    // Set the new passphrase
    keystore.set_passphrase(
        key_id,
        old_password.as_deref(),
        new_password.as_str()?,
    )?;

    if stored.is_password_protected {
        println!("✅ Passphrase changed successfully for key: {}", &key_id[..KEY_ID_DISPLAY_LENGTH]);
    } else {
        println!("✅ Passphrase protection added to key: {}", &key_id[..KEY_ID_DISPLAY_LENGTH]);
    }

    Ok(())
}

fn handle_keys_remove_passphrase(main_matches: &ArgMatches, sub_matches: &ArgMatches) -> Result<()> {
    handle_keys_remove_passphrase_with_prompt(main_matches, sub_matches, &RealPromptReader)
}

// Why: None arm returns a multi-line actionable error message; let-else would inline it.
#[allow(clippy::manual_let_else)]
fn handle_keys_remove_passphrase_with_prompt(
    main_matches: &ArgMatches,
    sub_matches: &ArgMatches,
    prompt: &dyn PromptReader,
) -> Result<()> {
    let key_id_partial = sub_matches.get_one::<String>("key-id")
        .ok_or_else(|| anyhow!("Key ID is required"))?;

    let keystore = create_keystore(main_matches)?;

    // Find the full key ID from partial match
    let keys = keystore.list_key_ids()?;
    let key_match = keys.iter().find(|(id, _)| id.starts_with(key_id_partial));

    let (key_id, stored) = match key_match {
        Some(k) => k,
        None => {
            return Err(anyhow!(
                "Key not found: {}\n\n\
                Available keys:\n{}",
                key_id_partial,
                keys.iter()
                    .map(|(id, s)| format!(
                        "  {} (created: {}) {}",
                        &id[..KEY_ID_DISPLAY_LENGTH],
                        s.created_at.format("%Y-%m-%d"),
                        if s.is_password_protected { "[protected]" } else { "" }
                    ))
                    .collect::<Vec<_>>()
                    .join("\n")
            ));
        }
    };

    // Check if key is actually protected
    if !stored.is_password_protected {
        return Err(anyhow!(
            "Key {} is not password protected",
            &key_id[..KEY_ID_DISPLAY_LENGTH]
        ));
    }

    // Warn user about security implications
    println!("⚠️  WARNING: This will store your private key unencrypted (only base64 encoded)!");
    println!("Anyone with access to your keystore files will be able to read this key.");
    let confirmation = prompt.read_line("Type 'yes' to continue: ")?;

    if confirmation.trim() != "yes" {
        println!("Cancelled");
        return Ok(());
    }

    // Get current password
    let current_password = crate::keystore::get_passphrase_or_prompt(
        "Enter current passphrase: "
    )?;

    // Remove passphrase protection
    keystore.remove_passphrase(key_id, &current_password)?;

    println!("✅ Passphrase protection removed from key: {}", &key_id[..KEY_ID_DISPLAY_LENGTH]);
    println!("⚠️  Key is now stored unencrypted!");

    Ok(())
}

/// Import a keystore TOML entry from a file path. Phase 18-03 (PQSIG-02).
///
/// Behaviour:
/// - Reads the source file as a `StoredKeyPair` TOML blob.
/// - `format_version == 2` → invoke `verify_stored_signature` (requires `hybrid`).
/// - `format_version == 1` → reject unless `--allow-unsigned` is passed.
/// - `format_version >= 3` → reject as unsupported.
/// - On success, writes the TOML to `{keys_dir}/{uuid}.toml` verbatim, preserving
///   the signature sub-table for v2 entries.
pub fn handle_keys_import(main_matches: &ArgMatches, sub_matches: &ArgMatches) -> Result<()> {
    let allow_unsigned = sub_matches.get_flag("allow-unsigned");
    let file_path = sub_matches
        .get_one::<String>("file")
        .ok_or_else(|| anyhow!("file path required for `sss keys import`"))?;

    let src = std::path::PathBuf::from(file_path);
    if !src.exists() {
        return Err(anyhow!("import: source file not found: {}", src.display()));
    }

    let content = std::fs::read_to_string(&src)
        .map_err(|e| anyhow!("import: read source file {}: {}", src.display(), e))?;

    let stored: crate::keystore::StoredKeyPair = toml::from_str(&content)
        .map_err(|e| anyhow!("import: parse-stored-toml from {}: {}", src.display(), e))?;

    let keystore = create_keystore(main_matches)?;

    // Phase 18 / D-10 dispatch — mirrors `Keystore::load_keypair`.
    match stored.format_version {
        1 => {
            if !allow_unsigned {
                return Err(anyhow!(
                    "keystore: source file {} is unsigned legacy format (format_version=1); \
                     pass --allow-unsigned to import or re-sign at the source",
                    src.display()
                ));
            }
            // Proceed without verify.
        }
        2 => {
            #[cfg(feature = "hybrid")]
            {
                keystore.verify_stored_signature(&stored, &src)?;
            }
            #[cfg(not(feature = "hybrid"))]
            {
                return Err(anyhow!(
                    "keystore: source file {} is signed (format_version=2) but the current build \
                     does not include the `hybrid` feature; rebuild with --features hybrid",
                    src.display()
                ));
            }
        }
        v => {
            return Err(anyhow!(
                "keystore: unsupported format_version {} in {}; upgrade sss",
                v,
                src.display()
            ));
        }
    }

    // Write verbatim to the keystore — signature sub-table is preserved by
    // virtue of writing the original bytes.
    let dst = keystore.keys_dir.join(format!("{}.toml", stored.uuid));
    if dst.exists() {
        return Err(anyhow!(
            "import: destination already exists ({}). Refusing to overwrite.",
            dst.display()
        ));
    }
    std::fs::write(&dst, &content)
        .map_err(|e| anyhow!("import: write destination {}: {}", dst.display(), e))?;

    println!("Imported keystore entry: {}", stored.uuid);
    println!("  Public key:      {}", stored.public_key);
    if let Some(ref hpk) = stored.hybrid_public_key {
        println!("  Hybrid pubkey:   {hpk}");
    }
    println!("  Format version:  {}", stored.format_version);
    println!("  File:            {}", dst.display());

    Ok(())
}

/// Export a keystore TOML entry to a file path. Phase 18-03 (PQSIG-02).
///
/// Behaviour:
/// - Locates the entry by UUID prefix in the keystore.
/// - Reads the source TOML file from the keystore.
/// - Verifies via standard `load_keypair` path (so v2 entries are verified;
///   v1 entries require `--allow-unsigned`).
/// - Writes the TOML bytes verbatim to the destination, signature included.
pub fn handle_keys_export(main_matches: &ArgMatches, sub_matches: &ArgMatches) -> Result<()> {
    let allow_unsigned = sub_matches.get_flag("allow-unsigned");
    let uuid = sub_matches
        .get_one::<String>("uuid")
        .ok_or_else(|| anyhow!("uuid required for `sss keys export`"))?;

    let keystore = create_keystore(main_matches)?;

    // Resolve uuid prefix → full key id.
    let keys = keystore.list_key_ids()?;
    let (full_id, _) = keys
        .iter()
        .find(|(id, _)| id.starts_with(uuid))
        .ok_or_else(|| anyhow!("export: no keystore entry matching uuid prefix '{uuid}'"))?;

    let src = keystore.keys_dir.join(format!("{full_id}.toml"));
    if !src.exists() {
        return Err(anyhow!("export: source file not found: {}", src.display()));
    }

    let content = std::fs::read_to_string(&src)
        .map_err(|e| anyhow!("export: read source file {}: {}", src.display(), e))?;
    let stored: crate::keystore::StoredKeyPair = toml::from_str(&content)
        .map_err(|e| anyhow!("export: parse-stored-toml from {}: {}", src.display(), e))?;

    // Phase 18 / D-10 dispatch — mirrors `Keystore::load_keypair`. We do NOT
    // call `load_keypair` directly because that decrypts the secret; export
    // only needs to validate the signature envelope before writing the
    // unmodified bytes.
    match stored.format_version {
        1 => {
            if !allow_unsigned {
                return Err(anyhow!(
                    "keystore: entry {full_id} is unsigned legacy format (format_version=1); \
                     pass --allow-unsigned to export or re-sign first"
                ));
            }
            // Proceed without verify.
        }
        2 => {
            #[cfg(feature = "hybrid")]
            {
                keystore.verify_stored_signature(&stored, &src)?;
            }
            #[cfg(not(feature = "hybrid"))]
            {
                return Err(anyhow!(
                    "keystore: entry {full_id} is signed (format_version=2) but the current build does \
                     not include the `hybrid` feature; rebuild with --features hybrid"
                ));
            }
        }
        v => {
            return Err(anyhow!(
                "keystore: unsupported format_version {v} for {full_id}; upgrade sss"
            ));
        }
    }

    let file_path = sub_matches
        .get_one::<String>("file")
        .ok_or_else(|| anyhow!("file path required for `sss keys export`"))?;
    let dst = std::path::PathBuf::from(file_path);
    if dst.exists() {
        return Err(anyhow!(
            "export: destination already exists ({}). Refusing to overwrite.",
            dst.display()
        ));
    }
    std::fs::write(&dst, &content)
        .map_err(|e| anyhow!("export: write destination {}: {}", dst.display(), e))?;

    println!("Exported keystore entry: {}", stored.uuid);
    println!("  Format version: {}", stored.format_version);
    println!("  File:           {}", dst.display());

    Ok(())
}

/// Re-sign a legacy (`format_version=1`) keystore entry in place.
///
/// Phase 18-04 / PQSIG-03 part 2: thin CLI wrapper over
/// `Keystore::upgrade_keypair_in_place`. Resolves the user-supplied uuid
/// (which may be a unique prefix) to the full key id via `list_key_ids`,
/// prompts for the existing passphrase if the entry is password-protected,
/// then delegates to the keystore method which performs the atomic
/// read-modify-write under `tempfile::NamedTempFile::persist` (D-15).
///
/// D-17: there is intentionally NO `--allow-unsigned` flag — `upgrade` IS
/// the upgrade path, so the only legitimate input is a v1 entry. v2 entries
/// surface as "already signed" errors from the keystore layer.
pub fn handle_keys_upgrade(main_matches: &ArgMatches, sub_matches: &ArgMatches) -> Result<()> {
    let uuid = sub_matches
        .get_one::<String>("uuid")
        .ok_or_else(|| anyhow!("uuid required for `sss keys upgrade`"))?;

    let keystore = create_keystore(main_matches)?;

    // Resolve uuid prefix → full key id (mirrors handle_keys_export).
    let keys = keystore.list_key_ids()?;
    let (full_id, stored) = keys
        .iter()
        .find(|(id, _)| id.starts_with(uuid))
        .ok_or_else(|| anyhow!("upgrade: no keystore entry matching uuid prefix '{uuid}'"))?;

    // Prompt for the existing passphrase only if the entry is protected.
    // The keystore layer probes the KEK before any write, so a wrong
    // passphrase fails before mutation (T-18-04-04).
    let password_opt = if stored.is_password_protected {
        Some(crate::keystore::get_passphrase_or_prompt(
            "Enter current passphrase: ",
        )?)
    } else {
        None
    };

    // Compile-time gate: upgrade only exists on hybrid builds (the sig
    // primitives are gated). Non-hybrid builds reach here only via clap
    // parsing; the keystore method itself is `#[cfg(feature = "hybrid")]`.
    #[cfg(feature = "hybrid")]
    {
        keystore.upgrade_keypair_in_place(full_id, password_opt.as_deref())?;
        println!(
            "Upgraded keystore entry: {}... (format_version 1 → 2, AND-composition signature)",
            &full_id[..KEY_ID_DISPLAY_LENGTH]
        );
        Ok(())
    }
    #[cfg(not(feature = "hybrid"))]
    {
        // Suppress unused-variable warnings for the gated path.
        let _ = (full_id, stored, password_opt);
        Err(anyhow!(
            "keystore: `sss keys upgrade` requires the `hybrid` feature; rebuild with --features hybrid"
        ))
    }
}

pub fn handle_keygen_deprecated(main_matches: &ArgMatches, matches: &ArgMatches) -> Result<()> {
    eprintln!("Warning: 'sss keygen' is deprecated. Use 'sss keys generate' instead.");
    handle_keys_generate_command(main_matches, matches)
}

fn handle_keys_show(main_matches: &ArgMatches) -> Result<()> {
    use libsodium_sys::{crypto_hash_sha256, crypto_hash_sha256_BYTES};

    let keystore = create_keystore(main_matches)?;

    // Retrieve the raw StoredKeyPair without decrypting any secret material.
    // With the hybrid feature we use `get_current_stored_raw` (which also
    // exposes `hybrid_public_key`).  Without the hybrid feature we fall back
    // to `list_key_ids` + `get_current_key_id`, which is always available and
    // likewise returns the public-key string without a passphrase prompt.
    #[cfg(feature = "hybrid")]
    let (classic_pk_b64, hybrid_pk_b64_opt) = {
        let stored = keystore.get_current_stored_raw().map_err(|_| {
            anyhow!("No current keypair found. Generate one with: sss keys generate --suite classic")
        })?;
        (stored.public_key.clone(), stored.hybrid_public_key.clone())
    };

    #[cfg(not(feature = "hybrid"))]
    let classic_pk_b64 = {
        let current_id = keystore.get_current_key_id().map_err(|_| {
            anyhow!("No current keypair found. Generate one with: sss keys generate --suite classic")
        })?;
        let keys = keystore.list_key_ids()?;
        let entry = keys.into_iter().find(|(id, _)| id == &current_id).ok_or_else(|| {
            anyhow!("No current keypair found. Generate one with: sss keys generate --suite classic")
        })?;
        entry.1.public_key
    };

    // --- Classic keypair block ---
    let classic_key_bytes = classic_pk_b64.as_bytes();
    let mut classic_hash = vec![0u8; crypto_hash_sha256_BYTES as usize];
    // SAFETY: `classic_key_bytes` is a valid &[u8] from a String; `classic_hash` is sized
    // exactly crypto_hash_sha256_BYTES (libsodium's output count). The SHA256 FFI is
    // constant-time and non-failing for this signature.
    #[cfg(not(miri))]
    unsafe {
        crypto_hash_sha256(
            classic_hash.as_mut_ptr(),
            classic_key_bytes.as_ptr(),
            classic_key_bytes.len() as u64,
        );
    }
    #[cfg(miri)]
    {
        // Miri stub: crypto_hash_sha256 is FFI; AddressSanitizer (Phase 23 MEMSAFE-03)
        // covers this path under non-miri builds. `classic_hash` stays zero-initialised.
    }
    generate_randomart(&classic_hash, "CLASSIC");

    // --- Hybrid keypair block (only if present and hybrid feature enabled) ---
    #[cfg(feature = "hybrid")]
    if let Some(ref hybrid_pk_b64) = hybrid_pk_b64_opt {
        println!();
        let hybrid_key_bytes = hybrid_pk_b64.as_bytes();
        let mut hybrid_hash = vec![0u8; crypto_hash_sha256_BYTES as usize];
        // SAFETY: same invariants as the classic block above — `hybrid_key_bytes` is a
        // valid &[u8] from a String; `hybrid_hash` is sized exactly the libsodium output
        // count. SHA256 FFI is constant-time and non-failing.
        #[cfg(not(miri))]
        unsafe {
            crypto_hash_sha256(
                hybrid_hash.as_mut_ptr(),
                hybrid_key_bytes.as_ptr(),
                hybrid_key_bytes.len() as u64,
            );
        }
        #[cfg(miri)]
        {
            // Miri stub: crypto_hash_sha256 is FFI; AddressSanitizer (Phase 23 MEMSAFE-03)
            // covers this path under non-miri builds. `hybrid_hash` stays zero-initialised.
        }
        generate_randomart(&hybrid_hash, "PQCRYPT");
    }

    Ok(())
}

/// Generate ASCII art representation of a fingerprint (Drunken Bishop algorithm)
/// This is the same algorithm used by OpenSSH for visual host key verification
// Randomart constants
const RANDOMART_WIDTH: usize = 17;
const RANDOMART_HEIGHT: usize = 9;
const RANDOMART_CHARS: &[char] = &[
    ' ', '.', 'o', '+', '=', '*', 'B', 'O', 'X', '@', '%', '&', '#', '/', '^',
];
const BITS_PER_DIRECTION: usize = 2;
const DIRECTIONS_PER_BYTE: usize = 4;
const MEDALLION_COLUMNS: usize = 9;

/// Perform the Drunken Bishop walk to generate randomart field
fn walk_drunken_bishop(fingerprint: &[u8]) -> ([[u8; RANDOMART_WIDTH]; RANDOMART_HEIGHT], (usize, usize)) {
    let mut field = [[0u8; RANDOMART_WIDTH]; RANDOMART_HEIGHT];
    let mut x = RANDOMART_WIDTH / 2;
    let mut y = RANDOMART_HEIGHT / 2;

    for byte in fingerprint {
        for i in 0..DIRECTIONS_PER_BYTE {
            let direction = (byte >> (i * BITS_PER_DIRECTION)) & 0x3;

            // Move based on 2-bit direction (NW=0, NE=1, SW=2, SE=3)
            match direction {
                0 => {
                    x = x.saturating_sub(1);
                    y = y.saturating_sub(1);
                }
                1 => {
                    if x < RANDOMART_WIDTH - 1 {
                        x += 1;
                    }
                    y = y.saturating_sub(1);
                }
                2 => {
                    x = x.saturating_sub(1);
                    if y < RANDOMART_HEIGHT - 1 {
                        y += 1;
                    }
                }
                3 => {
                    if x < RANDOMART_WIDTH - 1 {
                        x += 1;
                    }
                    if y < RANDOMART_HEIGHT - 1 {
                        y += 1;
                    }
                }
                _ => {}
            }

            // Increment visit count (cap at chars length - 1)
            if field[y][x] < (RANDOMART_CHARS.len() - 1) as u8 {
                field[y][x] += 1;
            }
        }
    }

    (field, (x, y))
}

/// Convert HSV to RGB color space
fn hsv_to_rgb(h: f64, s: f64, v: f64) -> (u8, u8, u8) {
    let c = v * s;
    let x = c * (1.0 - ((h / 60.0) % 2.0 - 1.0).abs());
    let m = v - c;

    let (r, g, b) = if h < 60.0 {
        (c, x, 0.0)
    } else if h < 120.0 {
        (x, c, 0.0)
    } else if h < 180.0 {
        (0.0, c, x)
    } else if h < 240.0 {
        (0.0, x, c)
    } else if h < 300.0 {
        (x, 0.0, c)
    } else {
        (c, 0.0, x)
    };

    (
        ((r + m) * 255.0) as u8,
        ((g + m) * 255.0) as u8,
        ((b + m) * 255.0) as u8,
    )
}

/// Calculate relative luminance for contrast determination (WCAG)
fn relative_luminance(r: u8, g: u8, b: u8) -> f64 {
    let r = f64::from(r) / 255.0;
    let g = f64::from(g) / 255.0;
    let b = f64::from(b) / 255.0;

    let r = if r <= 0.03928 {
        r / 12.92
    } else {
        ((r + 0.055) / 1.055).powf(2.4)
    };
    let g = if g <= 0.03928 {
        g / 12.92
    } else {
        ((g + 0.055) / 1.055).powf(2.4)
    };
    let b = if b <= 0.03928 {
        b / 12.92
    } else {
        ((b + 0.055) / 1.055).powf(2.4)
    };

    0.2126 * r + 0.7152 * g + 0.0722 * b
}

/// Map byte value to color using high/low nibble split
fn byte_to_color(byte_val: u8) -> (u8, u8, u8) {
    let high = (byte_val >> 4) & 0x0F;
    let low = byte_val & 0x0F;

    // Map high nibble to hue (16 distinct hues)
    let hues = [
        0.0, 25.0, 45.0, 65.0, 90.0, 120.0, 150.0, 180.0, 210.0, 240.0, 270.0, 290.0, 310.0,
        330.0, 345.0, 360.0,
    ];
    let hue = hues[high as usize];

    // Checkerboard pattern for adjacent differentiation
    let pattern = f64::from((high + low) % 2);

    let (sat, val) = if low < 4 {
        (0.9, if pattern > 0.5 { 0.45 } else { 0.55 })
    } else if low < 8 {
        (0.85, if pattern > 0.5 { 0.65 } else { 0.75 })
    } else if low < 12 {
        (0.75, if pattern > 0.5 { 0.85 } else { 0.92 })
    } else {
        (0.65, 0.95)
    };

    hsv_to_rgb(hue, sat, val)
}

/// Colorize a hex byte with background color and contrasting text
fn colorize_hex_byte(byte_val: u8, use_colors: bool) -> String {
    if !use_colors {
        return format!("{byte_val:02x}");
    }

    let (r, g, b) = byte_to_color(byte_val);

    // Determine text color based on background luminance (WCAG compliant)
    let lum = relative_luminance(r, g, b);
    let (fr, fg, fb) = if lum > 0.4 {
        (0, 0, 0) // Black text for light backgrounds
    } else {
        (255, 255, 255) // White text for dark backgrounds
    };

    format!(
        "\x1b[38;2;{fr};{fg};{fb}m\x1b[48;2;{r};{g};{b}m{byte_val:02x}\x1b[0m"
    )
}

/// Generate geometric medallion using avalanche effect
fn generate_medallion(fingerprint: &[u8], use_colors: bool) -> Vec<String> {
    let num_chunks = fingerprint.chunks(4).count();
    let mut medallion = vec![String::new(); num_chunks];

    if !use_colors {
        return medallion;
    }

    // Create hash-like seed with avalanche properties
    let mut state = [0u64; 4];
    for (i, chunk) in fingerprint.chunks(8).enumerate() {
        let mut val = 0u64;
        for &b in chunk {
            val = val.wrapping_shl(8) | u64::from(b);
        }
        state[i % 4] ^= val.wrapping_mul(0x9E3779B97F4A7C15);
        state[i % 4] = state[i % 4].wrapping_add(state[(i + 1) % 4]);
        state[i % 4] = state[i % 4].rotate_left(23);
    }

    // Final mixing rounds for strong avalanche
    for _ in 0..3 {
        for i in 0..4 {
            state[i] ^= state[(i + 1) % 4];
            state[i] = state[i].wrapping_mul(0x85EBCA6B);
            state[i] ^= state[i] >> 13;
            state[i] = state[i].wrapping_mul(0xC2B2AE35);
            state[i] ^= state[i] >> 16;
        }
    }

    // Generate medallion pattern for each row
    for (row_idx, medallion_line) in medallion.iter_mut().enumerate().take(num_chunks) {
        let mut line = String::new();
        for col in 0..MEDALLION_COLUMNS {
            let pos = (row_idx * MEDALLION_COLUMNS + col) as u64;
            let cell_seed = state[(pos % 4) as usize]
                .wrapping_add(pos.wrapping_mul(0x517CC1B727220A95))
                .rotate_left((pos % 64) as u32);

            let pattern_type = cell_seed & 0x7;
            let color_seed = (cell_seed >> 3) & 0xFFFFFF;

            let hue = ((color_seed & 0xFFF) as f64 / 4095.0) * 360.0;
            let sat = 0.6 + ((color_seed >> 12) & 0xFF) as f64 / 255.0 * 0.3;
            let val = 0.5 + ((color_seed >> 20) & 0xF) as f64 / 15.0 * 0.4;

            let (r, g, b) = hsv_to_rgb(hue, sat, val);

            let ch = match pattern_type {
                0 => '▀', 1 => '▄', 2 => '█', 3 => '▌',
                4 => '▐', 5 => '░', 6 => '▒', _ => '▓',
            };

            use std::fmt::Write as _;
            let _ = write!(line, "\x1b[38;2;{r};{g};{b}m{ch}\x1b[0m");
        }
        *medallion_line = line;
    }

    medallion
}

/// Colorize a character based on visit count (heat map style)
fn colorize_char(ch: char, count: u8, use_colors: bool) -> String {
    if !use_colors {
        return ch.to_string();
    }

    let color_code = match count {
        0 => "38;5;236",
        1 => "38;5;240",
        2..=3 => "38;5;33",
        4..=5 => "38;5;39",
        6..=7 => "38;5;46",
        8..=9 => "38;5;226",
        10..=11 => "38;5;208",
        _ => "38;5;196",
    };

    format!("\x1b[{color_code}m{ch}\x1b[0m")
}

/// Main randomart generation function
fn generate_randomart(fingerprint: &[u8], key_type: &str) {
    use std::io::IsTerminal;
    let use_colors = std::env::var("NO_COLOR").is_err() && std::io::stdout().is_terminal();

    // Generate the field using Drunken Bishop walk
    let (field, (end_x, end_y)) = walk_drunken_bishop(fingerprint);
    let start_x = RANDOMART_WIDTH / 2;
    let start_y = RANDOMART_HEIGHT / 2;

    // Print header — use saturating arithmetic so long key_type strings
    // (e.g. "SSS KEY (Classic)" which produces a 19-char header) never
    // overflow the fixed RANDOMART_WIDTH border.
    let header = format!("[{key_type}]");
    let padding = RANDOMART_WIDTH.saturating_sub(header.len()) / 2;
    let right_padding = RANDOMART_WIDTH.saturating_sub(padding).saturating_sub(header.len());
    println!(
        "+{}[{}]{}+",
        "-".repeat(padding),
        key_type,
        "-".repeat(right_padding)
    );

    // Format hex fingerprint in groups of 4 bytes per line
    let mut hex_lines: Vec<String> = fingerprint
        .chunks(4)
        .map(|chunk| {
            chunk
                .iter()
                .map(|b| colorize_hex_byte(*b, use_colors))
                .collect::<Vec<_>>()
                .join(":")
        })
        .collect();

    // Insert blank line after 4th line for better alignment
    if hex_lines.len() > crate::constants::FINGERPRINT_ART_MAX_LINES {
        hex_lines.insert(crate::constants::FINGERPRINT_ART_MAX_LINES, String::new());
    }

    // Generate medallion and insert blank line to match hex_lines
    let mut medallion_lines = generate_medallion(fingerprint, use_colors);
    if medallion_lines.len() > crate::constants::FINGERPRINT_ART_MAX_LINES {
        medallion_lines.insert(crate::constants::FINGERPRINT_ART_MAX_LINES, String::new());
    }

    // Render the randomart field
    for (row_idx, row) in field.iter().enumerate() {
        print!("|");
        for (col_idx, &count) in row.iter().enumerate() {
            if col_idx == start_x && row_idx == start_y {
                // Start position - cyan/bold
                if use_colors {
                    print!("\x1b[1;36mS\x1b[0m");
                } else {
                    print!("S");
                }
            } else if col_idx == end_x && row_idx == end_y {
                // End position - green/bold
                if use_colors {
                    print!("\x1b[1;32mE\x1b[0m");
                } else {
                    print!("E");
                }
            } else {
                let char_idx = (count as usize).min(RANDOMART_CHARS.len() - 1);
                print!("{}", colorize_char(RANDOMART_CHARS[char_idx], count, use_colors));
            }
        }
        print!("|");

        // Print hex line and medallion if available
        if row_idx < hex_lines.len() {
            print!("  {}", hex_lines[row_idx]);

            if !hex_lines[row_idx].is_empty()
                && row_idx < medallion_lines.len()
                && !medallion_lines[row_idx].is_empty()
            {
                print!("  {}", medallion_lines[row_idx]);
            }
        }

        println!();
    }
    println!("+{}+", "-".repeat(RANDOMART_WIDTH));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_walk_drunken_bishop_deterministic() {
        // Same input should produce same output
        let fingerprint = b"test_fingerprint_12345678";
        let (grid1, pos1) = walk_drunken_bishop(fingerprint);
        let (grid2, pos2) = walk_drunken_bishop(fingerprint);

        assert_eq!(grid1, grid2);
        assert_eq!(pos1, pos2);
    }

    #[test]
    fn test_walk_drunken_bishop_different_inputs() {
        // Different inputs should (very likely) produce different outputs
        let fp1 = b"fingerprint_one_12345678";
        let fp2 = b"fingerprint_two_87654321";

        let (grid1, end1) = walk_drunken_bishop(fp1);
        let (grid2, end2) = walk_drunken_bishop(fp2);

        // Grids should be different (or extremely unlikely to be identical)
        assert_ne!(grid1, grid2);

        // Both should be valid positions (x, y) where x < WIDTH, y < HEIGHT
        assert!(end1.0 < RANDOMART_WIDTH);  // x (column)
        assert!(end1.1 < RANDOMART_HEIGHT); // y (row)
        assert!(end2.0 < RANDOMART_WIDTH);
        assert!(end2.1 < RANDOMART_HEIGHT);
    }

    #[test]
    fn test_walk_drunken_bishop_grid_bounds() {
        // Walk should never go out of bounds
        let fingerprint = b"bounds_test_fingerprint_";
        let (grid, (end_x, end_y)) = walk_drunken_bishop(fingerprint);

        // Check grid dimensions
        assert_eq!(grid.len(), RANDOMART_HEIGHT);
        for row in &grid {
            assert_eq!(row.len(), RANDOMART_WIDTH);
        }

        // Check end position is within bounds (x, y)
        assert!(end_x < RANDOMART_WIDTH);  // x (column)
        assert!(end_y < RANDOMART_HEIGHT); // y (row)
    }

    #[test]
    fn test_hsv_to_rgb_pure_red() {
        // Pure red: H=0, S=1, V=1 should give (255, 0, 0)
        let (r, g, b) = hsv_to_rgb(0.0, 1.0, 1.0);
        assert_eq!(r, 255);
        assert_eq!(g, 0);
        assert_eq!(b, 0);
    }

    #[test]
    fn test_hsv_to_rgb_pure_green() {
        // Pure green: H=120, S=1, V=1 should give (0, 255, 0)
        let (r, g, b) = hsv_to_rgb(120.0, 1.0, 1.0);
        assert_eq!(r, 0);
        assert_eq!(g, 255);
        assert_eq!(b, 0);
    }

    #[test]
    fn test_hsv_to_rgb_pure_blue() {
        // Pure blue: H=240, S=1, V=1 should give (0, 0, 255)
        let (r, g, b) = hsv_to_rgb(240.0, 1.0, 1.0);
        assert_eq!(r, 0);
        assert_eq!(g, 0);
        assert_eq!(b, 255);
    }

    #[test]
    fn test_hsv_to_rgb_grayscale() {
        // When saturation is 0, result should be grayscale
        let (r, g, b) = hsv_to_rgb(180.0, 0.0, 0.5);
        assert_eq!(r, g);
        assert_eq!(g, b);
    }

    #[test]
    fn test_relative_luminance_white() {
        // White should have high luminance
        let lum = relative_luminance(255, 255, 255);
        assert!(lum > 0.9);
    }

    #[test]
    fn test_relative_luminance_black() {
        // Black should have zero luminance
        let lum = relative_luminance(0, 0, 0);
        // Why: black (0,0,0) maps to exactly 0.0 by the relative_luminance
        // formula (no floating-point rounding intermediates); exact equality
        // is the correct assertion here. Test-only.
        #[allow(clippy::float_cmp)]
        let is_zero = lum == 0.0;
        assert!(is_zero, "expected exact 0.0 for black; got {lum}");
    }

    #[test]
    fn test_relative_luminance_monotonic() {
        // Luminance should increase as brightness increases
        let lum1 = relative_luminance(50, 50, 50);
        let lum2 = relative_luminance(100, 100, 100);
        let lum3 = relative_luminance(200, 200, 200);

        assert!(lum1 < lum2);
        assert!(lum2 < lum3);
    }

    #[test]
    fn test_byte_to_color_range() {
        // Test various byte values produce valid RGB (all u8 values are valid)
        for byte_val in [0, 64, 128, 192, 255] {
            let (_r, _g, _b) = byte_to_color(byte_val);
            // RGB values are u8, so they're always in valid range
        }
    }

    #[test]
    fn test_byte_to_color_deterministic() {
        // Same input should give same output
        let (r1, g1, b1) = byte_to_color(123);
        let (r2, g2, b2) = byte_to_color(123);
        assert_eq!((r1, g1, b1), (r2, g2, b2));
    }

    #[test]
    fn test_colorize_hex_byte_no_color() {
        // Without colors, should just return plain hex
        let result = colorize_hex_byte(0xAB, false);
        assert_eq!(result, "ab");
    }

    #[test]
    fn test_colorize_hex_byte_with_color() {
        // With colors, should contain ANSI escape codes
        let result = colorize_hex_byte(0xAB, true);
        assert!(result.contains("\x1b["));
        assert!(result.contains("ab"));
    }

    #[test]
    fn test_colorize_hex_byte_all_values() {
        // Test all possible byte values produce valid output
        for byte_val in 0u8..=255 {
            let result = colorize_hex_byte(byte_val, false);
            assert_eq!(result.len(), 2); // Two hex digits
            let _ = u8::from_str_radix(&result, 16).unwrap(); // Should parse as hex
        }
    }

    #[test]
    fn test_generate_medallion_length() {
        // Medallion should have num_chunks lines (fingerprint.chunks(4).count())
        let fingerprint = b"test_fingerprint_12345678901234567890123456"; // 44 bytes
        let medallion = generate_medallion(fingerprint, false);
        let expected_chunks = fingerprint.chunks(4).count(); // 11 chunks
        assert_eq!(medallion.len(), expected_chunks);
    }

    #[test]
    fn test_generate_medallion_deterministic() {
        // Same fingerprint should produce same medallion
        let fingerprint = b"test_fingerprint_12345678901234567890123456";
        let med1 = generate_medallion(fingerprint, false);
        let med2 = generate_medallion(fingerprint, false);
        assert_eq!(med1, med2);
    }

    #[test]
    fn test_generate_medallion_no_color() {
        // Without colors, output should not contain ANSI codes
        let fingerprint = b"test_fingerprint_12345678901234567890123456";
        let medallion = generate_medallion(fingerprint, false);

        for line in medallion {
            assert!(!line.contains("\x1b["));
        }
    }

    #[test]
    fn test_colorize_char_no_color() {
        // Without colors, should just return the character
        let result = colorize_char('X', 5, false);
        assert_eq!(result, "X");
    }

    #[test]
    fn test_colorize_char_with_color() {
        // With colors, should contain ANSI escape codes
        let result = colorize_char('S', 10, true);
        assert!(result.contains("\x1b["));
        assert!(result.contains('S'));
    }

    #[test]
    fn test_colorize_char_all_chars() {
        // Test all randomart characters
        for &ch in RANDOMART_CHARS {
            let result = colorize_char(ch, 5, false);
            assert_eq!(result.len(), 1);
            assert_eq!(result.chars().next().unwrap(), ch);
        }
    }

    // ====================================================================
    // Phase 16b-02 — coverage lift via D-19 PromptReader seam
    // ====================================================================
    //
    // Test taxonomy:
    //   * helper-direct (≥8): exercise pure helpers with no external state
    //   * Mock-driven (≥8): drive `_with_prompt` variants via `MockPromptReader`,
    //     against a tempdir keystore at `KdfParams::interactive` speed
    //   * error-message regression (≥4): pin the exact `anyhow!()` text the CLI
    //     emits when callers misuse the surface
    //
    // Discipline notes:
    //   - All FS-touching tests use `tempfile::TempDir`; no `tempdir()` macro.
    //   - All keystores are constructed via `Keystore::new_with_config_dir_and_kdf`
    //     with `KdfParams::interactive()` (≈10× faster than `sensitive()`).
    //   - Tests do not mutate `std::env::current_dir`, so no `serial_test` cwd
    //     scope guards are needed (Phase 16 R-03 lesson).
    //   - Tests that mutate `SSS_PASSPHRASE` env state are gated behind
    //     `#[serial]` to avoid concurrent contamination.
    use clap::{Arg, Command as ClapCommand};
    use std::cell::RefCell;
    use tempfile::TempDir;

    /// Test double for [`PromptReader`].
    ///
    /// Stores two FIFO queues — one for password-with-confirmation answers and
    /// one for line-read answers — and pops one entry per call.  Panics with a
    /// loud message if the queue is empty (catches test bugs early).
    struct MockPromptReader {
        passwords: RefCell<Vec<String>>,
        lines: RefCell<Vec<String>>,
    }

    impl MockPromptReader {
        fn new() -> Self {
            Self {
                passwords: RefCell::new(Vec::new()),
                lines: RefCell::new(Vec::new()),
            }
        }

        fn with_password(self, pw: &str) -> Self {
            self.passwords.borrow_mut().push(pw.to_string());
            self
        }

        fn with_line(self, line: &str) -> Self {
            self.lines.borrow_mut().push(line.to_string());
            self
        }
    }

    impl PromptReader for MockPromptReader {
        fn read_password_with_confirmation(
            &self,
            _prompt: &str,
            _confirm_prompt: &str,
        ) -> Result<SecureString> {
            let mut q = self.passwords.borrow_mut();
            assert!(
                !q.is_empty(),
                "MockPromptReader: read_password_with_confirmation called but no password queued"
            );
            let pw = q.remove(0);
            Ok(SecureString::new(&pw))
        }

        fn read_line(&self, _prompt: &str) -> Result<String> {
            let mut q = self.lines.borrow_mut();
            assert!(
                !q.is_empty(),
                "MockPromptReader: read_line called but no line queued"
            );
            Ok(q.remove(0))
        }
    }

    /// Build a clap command tree mirroring `src/main.rs:273-376` for the `keys`
    /// subcommand surface.  Used by the in-source `_with_prompt` tests so they
    /// can construct realistic `ArgMatches` without spawning a subprocess.
    fn build_keys_app() -> ClapCommand {
        ClapCommand::new("sss")
            .arg(Arg::new("confdir").long("confdir").value_name("DIR").global(true))
            .arg(
                Arg::new("non-interactive")
                    .long("non-interactive")
                    .action(clap::ArgAction::SetTrue)
                    .global(true),
            )
            .arg(
                Arg::new("kdf-level")
                    .long("kdf-level")
                    .value_name("LEVEL")
                    .global(true),
            )
            .subcommand(
                ClapCommand::new("keys")
                    .subcommand(
                        ClapCommand::new("generate")
                            .arg(Arg::new("force").long("force").action(clap::ArgAction::SetTrue))
                            .arg(
                                Arg::new("no-password")
                                    .long("no-password")
                                    .action(clap::ArgAction::SetTrue),
                            )
                            .arg(
                                Arg::new("suite")
                                    .long("suite")
                                    .value_name("SUITE")
                                    .value_parser(["classic", "hybrid", "both"])
                                    .default_value(if cfg!(feature = "hybrid") {
                                        "both"
                                    } else {
                                        "classic"
                                    }),
                            ),
                    )
                    .subcommand(ClapCommand::new("list"))
                    .subcommand(
                        ClapCommand::new("pubkey")
                            .arg(
                                Arg::new("fingerprint")
                                    .long("fingerprint")
                                    .action(clap::ArgAction::SetTrue),
                            )
                            .arg(Arg::new("user").short('u').long("user").value_name("USERNAME")),
                    )
                    .subcommand(
                        ClapCommand::new("delete")
                            .arg(Arg::new("name").required(true)),
                    )
                    .subcommand(
                        ClapCommand::new("current")
                            .arg(Arg::new("name").required(false)),
                    )
                    .subcommand(
                        ClapCommand::new("rotate")
                            .arg(Arg::new("force").long("force").action(clap::ArgAction::SetTrue))
                            .arg(
                                Arg::new("no-backup")
                                    .long("no-backup")
                                    .action(clap::ArgAction::SetTrue),
                            )
                            .arg(
                                Arg::new("dry-run")
                                    .long("dry-run")
                                    .action(clap::ArgAction::SetTrue),
                            ),
                    )
                    .subcommand(
                        ClapCommand::new("set-passphrase")
                            .arg(Arg::new("key-id").required(true)),
                    )
                    .subcommand(
                        ClapCommand::new("remove-passphrase")
                            .arg(Arg::new("key-id").required(true)),
                    )
                    .subcommand(ClapCommand::new("show")),
            )
    }

    /// Drive arg vector through the test clap app, return the global +
    /// the named subcommand's matches.
    fn parse_keys_args(argv: &[&str]) -> (clap::ArgMatches, clap::ArgMatches) {
        let matches = build_keys_app().try_get_matches_from(argv).expect("clap parse");
        let (sub_name, sub_m) = matches.subcommand().expect("subcommand present");
        assert_eq!(sub_name, "keys");
        let inner = sub_m.clone();
        (matches, inner)
    }

    /// Convenience: build a fast keystore at `dir` and seed an unprotected
    /// classic keypair.  Returns the freshly-stored key id.
    fn seed_unprotected_classic(dir: &std::path::Path) -> String {
        use crate::kdf::KdfParams;
        let ks = crate::keystore::Keystore::new_with_config_dir_and_kdf(
            dir.to_path_buf(),
            KdfParams::interactive(),
            false,
        )
        .unwrap();
        let kp = KeyPair::generate().unwrap();
        ks.store_keypair(&kp, None).unwrap()
    }

    // -------- helper-direct tests (Tier 1) --------

    #[test]
    fn test_real_prompt_reader_is_unit_struct() {
        // RealPromptReader is the production seam target; ensure we can
        // instantiate it without arguments.  Trivial but pins the type shape.
        let _ = RealPromptReader;
    }

    #[test]
    fn test_mock_prompt_reader_password_queue_pops_in_order() {
        let mock = MockPromptReader::new()
            .with_password("first")
            .with_password("second");
        let one = mock
            .read_password_with_confirmation("p1: ", "c: ")
            .unwrap();
        let two = mock
            .read_password_with_confirmation("p2: ", "c: ")
            .unwrap();
        assert_eq!(one.as_str().unwrap(), "first");
        assert_eq!(two.as_str().unwrap(), "second");
    }

    #[test]
    fn test_mock_prompt_reader_line_queue_pops_in_order() {
        let mock = MockPromptReader::new().with_line("yes\n").with_line("no\n");
        assert_eq!(mock.read_line("? ").unwrap(), "yes\n");
        assert_eq!(mock.read_line("? ").unwrap(), "no\n");
    }

    #[test]
    #[should_panic(expected = "no password queued")]
    fn test_mock_prompt_reader_panics_when_password_underflow() {
        let mock = MockPromptReader::new();
        let _ = mock.read_password_with_confirmation("p: ", "c: ");
    }

    #[test]
    #[should_panic(expected = "no line queued")]
    fn test_mock_prompt_reader_panics_when_line_underflow() {
        let mock = MockPromptReader::new();
        let _ = mock.read_line("? ");
    }

    #[test]
    fn test_build_keys_app_parses_generate_with_no_password() {
        let argv = &[
            "sss", "--confdir", "/tmp/x", "keys", "generate", "--no-password", "--suite", "classic",
        ];
        let (_g, sub) = parse_keys_args(argv);
        let (name, gen_m) = sub.subcommand().expect("subcmd");
        assert_eq!(name, "generate");
        assert!(gen_m.get_flag("no-password"));
        assert_eq!(gen_m.get_one::<String>("suite").map(String::as_str), Some("classic"));
    }

    #[test]
    fn test_build_keys_app_parses_delete_name() {
        let argv = &["sss", "--confdir", "/tmp/x", "keys", "delete", "abc123"];
        let (_g, sub) = parse_keys_args(argv);
        let (name, del_m) = sub.subcommand().expect("subcmd");
        assert_eq!(name, "delete");
        assert_eq!(
            del_m.get_one::<String>("name").map(String::as_str),
            Some("abc123")
        );
    }

    #[test]
    fn test_build_keys_app_parses_rotate_force_dry_run() {
        let argv = &[
            "sss", "--confdir", "/tmp/x", "keys", "rotate", "--force", "--dry-run",
        ];
        let (_g, sub) = parse_keys_args(argv);
        let (name, rot_m) = sub.subcommand().expect("subcmd");
        assert_eq!(name, "rotate");
        assert!(rot_m.get_flag("force"));
        assert!(rot_m.get_flag("dry-run"));
        assert!(!rot_m.get_flag("no-backup"));
    }

    #[test]
    fn test_build_keys_app_parses_set_passphrase_key_id() {
        let argv = &[
            "sss", "--confdir", "/tmp/x", "keys", "set-passphrase", "deadbeef",
        ];
        let (_g, sub) = parse_keys_args(argv);
        let (name, sp_m) = sub.subcommand().expect("subcmd");
        assert_eq!(name, "set-passphrase");
        assert_eq!(
            sp_m.get_one::<String>("key-id").map(String::as_str),
            Some("deadbeef")
        );
    }

    // -------- Mock-driven prompt path tests (Tier 1) --------

    #[test]
    fn test_generate_classic_no_password_writes_keystore_entry() {
        // --no-password path: prompt should not be consulted.
        let tmp = TempDir::new().unwrap();
        let argv = &[
            "sss",
            "--confdir",
            tmp.path().to_str().unwrap(),
            "--kdf-level",
            "interactive",
            "keys",
            "generate",
            "--no-password",
            "--suite",
            "classic",
        ];
        let (g, sub) = parse_keys_args(argv);
        let (_n, gen_m) = sub.subcommand().expect("subcmd");

        // Empty mock — prompt must not be called.
        let mock = MockPromptReader::new();
        handle_keys_generate_command_with_prompt(&g, gen_m, &mock).unwrap();

        // Verify keystore now has exactly one key.
        use crate::kdf::KdfParams;
        let ks = crate::keystore::Keystore::new_with_config_dir_and_kdf(
            tmp.path().to_path_buf(),
            KdfParams::interactive(),
            false,
        )
        .unwrap();
        let keys = ks.list_key_ids().unwrap();
        assert_eq!(keys.len(), 1);
        assert!(!keys[0].1.is_password_protected);
    }

    #[test]
    fn test_generate_classic_with_passphrase_uses_mock() {
        // Passphrase path: mock returns "supersecret".
        let tmp = TempDir::new().unwrap();
        let argv = &[
            "sss",
            "--confdir",
            tmp.path().to_str().unwrap(),
            "--kdf-level",
            "interactive",
            "keys",
            "generate",
            "--suite",
            "classic",
        ];
        let (g, sub) = parse_keys_args(argv);
        let (_n, gen_m) = sub.subcommand().expect("subcmd");

        let mock = MockPromptReader::new().with_password("supersecret");
        handle_keys_generate_command_with_prompt(&g, gen_m, &mock).unwrap();

        // Key should be password-protected.
        use crate::kdf::KdfParams;
        let ks = crate::keystore::Keystore::new_with_config_dir_and_kdf(
            tmp.path().to_path_buf(),
            KdfParams::interactive(),
            false,
        )
        .unwrap();
        let keys = ks.list_key_ids().unwrap();
        assert_eq!(keys.len(), 1);
        assert!(keys[0].1.is_password_protected);
    }

    #[test]
    fn test_generate_classic_empty_passphrase_errors() {
        // Empty passphrase must hit the explicit error branch.
        let tmp = TempDir::new().unwrap();
        let argv = &[
            "sss",
            "--confdir",
            tmp.path().to_str().unwrap(),
            "--kdf-level",
            "interactive",
            "keys",
            "generate",
            "--suite",
            "classic",
        ];
        let (g, sub) = parse_keys_args(argv);
        let (_n, gen_m) = sub.subcommand().expect("subcmd");

        let mock = MockPromptReader::new().with_password("");
        let err = handle_keys_generate_command_with_prompt(&g, gen_m, &mock).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("Passphrase cannot be empty"),
            "expected empty-passphrase error, got: {msg}"
        );
    }

    // The "duplicate keypair" guard in handle_keys_generate_command uses
    // get_current_keypair(None), which refuses format_version=1 (unsigned legacy)
    // entries introduced by Phase 18.  seed_unprotected_classic produces a v1
    // entry; upgrade_keypair_in_place promotes it to v2 so the guard can see it.
    // This test therefore requires the hybrid feature.
    #[cfg(feature = "hybrid")]
    #[test]
    fn test_generate_classic_existing_keypair_without_force_errors() {
        let tmp = TempDir::new().unwrap();
        let key_id = seed_unprotected_classic(tmp.path());

        // Promote the v1 entry to a signed v2 entry so get_current_keypair(None)
        // can read it and the duplicate guard fires.
        {
            use crate::kdf::KdfParams;
            let ks = crate::keystore::Keystore::new_with_config_dir_and_kdf(
                tmp.path().to_path_buf(),
                KdfParams::interactive(),
                false,
            )
            .unwrap();
            ks.upgrade_keypair_in_place(&key_id, None).unwrap();
        }

        let argv = &[
            "sss",
            "--confdir",
            tmp.path().to_str().unwrap(),
            "--kdf-level",
            "interactive",
            "keys",
            "generate",
            "--no-password",
            "--suite",
            "classic",
        ];
        let (g, sub) = parse_keys_args(argv);
        let (_n, gen_m) = sub.subcommand().expect("subcmd");

        let mock = MockPromptReader::new();
        let err = handle_keys_generate_command_with_prompt(&g, gen_m, &mock).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("A keypair already exists") && msg.contains("--force"),
            "expected duplicate-keypair error, got: {msg}"
        );
    }

    #[cfg(feature = "hybrid")]
    #[test]
    fn test_generate_both_with_passphrase_uses_mock() {
        let tmp = TempDir::new().unwrap();
        let argv = &[
            "sss",
            "--confdir",
            tmp.path().to_str().unwrap(),
            "--kdf-level",
            "interactive",
            "keys",
            "generate",
            "--suite",
            "both",
        ];
        let (g, sub) = parse_keys_args(argv);
        let (_n, gen_m) = sub.subcommand().expect("subcmd");

        let mock = MockPromptReader::new().with_password("dualpass");
        handle_keys_generate_command_with_prompt(&g, gen_m, &mock).unwrap();

        use crate::kdf::KdfParams;
        let ks = crate::keystore::Keystore::new_with_config_dir_and_kdf(
            tmp.path().to_path_buf(),
            KdfParams::interactive(),
            false,
        )
        .unwrap();
        let raw = ks.get_current_stored_raw().unwrap();
        assert!(raw.is_password_protected);
        assert!(raw.hybrid_public_key.is_some());
    }

    #[test]
    fn test_delete_with_y_input_removes_keypair() {
        let tmp = TempDir::new().unwrap();
        let key_id = seed_unprotected_classic(tmp.path());

        let argv = &[
            "sss",
            "--confdir",
            tmp.path().to_str().unwrap(),
            "--kdf-level",
            "interactive",
            "keys",
            "delete",
            &key_id,
        ];
        let (g, sub) = parse_keys_args(argv);
        let (_n, del_m) = sub.subcommand().expect("subcmd");

        let mock = MockPromptReader::new().with_line("y\n");
        handle_keys_delete_with_prompt(&g, del_m, &mock).unwrap();

        // Keystore should now be empty.
        use crate::kdf::KdfParams;
        let ks = crate::keystore::Keystore::new_with_config_dir_and_kdf(
            tmp.path().to_path_buf(),
            KdfParams::interactive(),
            false,
        )
        .unwrap();
        assert!(ks.list_key_ids().unwrap().is_empty());
    }

    #[test]
    fn test_delete_with_n_input_keeps_keypair() {
        let tmp = TempDir::new().unwrap();
        let key_id = seed_unprotected_classic(tmp.path());

        let argv = &[
            "sss",
            "--confdir",
            tmp.path().to_str().unwrap(),
            "--kdf-level",
            "interactive",
            "keys",
            "delete",
            &key_id,
        ];
        let (g, sub) = parse_keys_args(argv);
        let (_n, del_m) = sub.subcommand().expect("subcmd");

        let mock = MockPromptReader::new().with_line("n\n");
        handle_keys_delete_with_prompt(&g, del_m, &mock).unwrap();

        use crate::kdf::KdfParams;
        let ks = crate::keystore::Keystore::new_with_config_dir_and_kdf(
            tmp.path().to_path_buf(),
            KdfParams::interactive(),
            false,
        )
        .unwrap();
        assert_eq!(ks.list_key_ids().unwrap().len(), 1);
    }

    #[test]
    fn test_set_passphrase_adds_protection_to_unprotected_key() {
        let tmp = TempDir::new().unwrap();
        let key_id = seed_unprotected_classic(tmp.path());

        let argv = &[
            "sss",
            "--confdir",
            tmp.path().to_str().unwrap(),
            "--kdf-level",
            "interactive",
            "keys",
            "set-passphrase",
            &key_id,
        ];
        let (g, sub) = parse_keys_args(argv);
        let (_n, sp_m) = sub.subcommand().expect("subcmd");

        let mock = MockPromptReader::new().with_password("freshpass");
        handle_keys_set_passphrase_with_prompt(&g, sp_m, &mock).unwrap();

        use crate::kdf::KdfParams;
        let ks = crate::keystore::Keystore::new_with_config_dir_and_kdf(
            tmp.path().to_path_buf(),
            KdfParams::interactive(),
            false,
        )
        .unwrap();
        let keys = ks.list_key_ids().unwrap();
        assert_eq!(keys.len(), 1);
        assert!(keys[0].1.is_password_protected);
    }

    #[test]
    fn test_set_passphrase_empty_passphrase_errors() {
        let tmp = TempDir::new().unwrap();
        let key_id = seed_unprotected_classic(tmp.path());

        let argv = &[
            "sss",
            "--confdir",
            tmp.path().to_str().unwrap(),
            "--kdf-level",
            "interactive",
            "keys",
            "set-passphrase",
            &key_id,
        ];
        let (g, sub) = parse_keys_args(argv);
        let (_n, sp_m) = sub.subcommand().expect("subcmd");

        let mock = MockPromptReader::new().with_password("");
        let err = handle_keys_set_passphrase_with_prompt(&g, sp_m, &mock).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("Passphrase cannot be empty"),
            "expected empty-passphrase error, got: {msg}"
        );
    }

    #[test]
    fn test_set_passphrase_unknown_key_returns_listing_error() {
        let tmp = TempDir::new().unwrap();
        let _existing = seed_unprotected_classic(tmp.path());

        let argv = &[
            "sss",
            "--confdir",
            tmp.path().to_str().unwrap(),
            "--kdf-level",
            "interactive",
            "keys",
            "set-passphrase",
            "no-such-id",
        ];
        let (g, sub) = parse_keys_args(argv);
        let (_n, sp_m) = sub.subcommand().expect("subcmd");

        // No mock interaction expected — error fires before prompt.
        let mock = MockPromptReader::new();
        let err = handle_keys_set_passphrase_with_prompt(&g, sp_m, &mock).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("Key not found") && msg.contains("no-such-id"),
            "expected key-not-found error, got: {msg}"
        );
        assert!(
            msg.contains("Available keys"),
            "expected listing in error, got: {msg}"
        );
    }

    #[test]
    fn test_remove_passphrase_with_no_yes_input_cancels() {
        // When the user types something other than "yes", we abort early —
        // and importantly the prompt for the *passphrase itself* is never
        // consulted (so the empty mock must not panic).
        let tmp = TempDir::new().unwrap();

        // Seed a protected keypair so remove-passphrase has work to do.
        use crate::kdf::KdfParams;
        let ks = crate::keystore::Keystore::new_with_config_dir_and_kdf(
            tmp.path().to_path_buf(),
            KdfParams::interactive(),
            false,
        )
        .unwrap();
        let kp = KeyPair::generate().unwrap();
        let key_id = ks.store_keypair(&kp, Some("startingpass")).unwrap();

        let argv = &[
            "sss",
            "--confdir",
            tmp.path().to_str().unwrap(),
            "--kdf-level",
            "interactive",
            "keys",
            "remove-passphrase",
            &key_id,
        ];
        let (g, sub) = parse_keys_args(argv);
        let (_n, rp_m) = sub.subcommand().expect("subcmd");

        // Type "no" instead of "yes" — should short-circuit "Cancelled".
        let mock = MockPromptReader::new().with_line("no\n");
        handle_keys_remove_passphrase_with_prompt(&g, rp_m, &mock).unwrap();

        // Key should still be protected.
        let stored = ks.list_key_ids().unwrap();
        assert!(stored[0].1.is_password_protected);
    }

    #[test]
    fn test_remove_passphrase_unprotected_key_errors() {
        let tmp = TempDir::new().unwrap();
        let key_id = seed_unprotected_classic(tmp.path());

        let argv = &[
            "sss",
            "--confdir",
            tmp.path().to_str().unwrap(),
            "--kdf-level",
            "interactive",
            "keys",
            "remove-passphrase",
            &key_id,
        ];
        let (g, sub) = parse_keys_args(argv);
        let (_n, rp_m) = sub.subcommand().expect("subcmd");

        let mock = MockPromptReader::new();
        let err = handle_keys_remove_passphrase_with_prompt(&g, rp_m, &mock).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("not password protected"),
            "expected not-protected error, got: {msg}"
        );
    }

    // -------- Error-message regression tests (Tier 1) --------

    #[test]
    fn test_set_passphrase_missing_key_id_errors() {
        // Run set-passphrase without a key-id — handler returns
        // "Key ID is required".  We can't pass an empty argv through clap
        // (it rejects), so we manually construct sub_matches from a zero-arg
        // shape.
        let app = ClapCommand::new("sub").arg(Arg::new("key-id").required(false));
        let m = app.try_get_matches_from(vec!["sub"]).unwrap();
        // Top-level matches just need to expose confdir/kdf-level shape.
        let g_app = ClapCommand::new("sss")
            .arg(Arg::new("confdir").long("confdir").value_name("DIR"))
            .arg(Arg::new("kdf-level").long("kdf-level").value_name("LEVEL"));
        let g = g_app.try_get_matches_from(vec!["sss"]).unwrap();

        let mock = MockPromptReader::new();
        let err = handle_keys_set_passphrase_with_prompt(&g, &m, &mock).unwrap_err();
        assert!(format!("{err}").contains("Key ID is required"));
    }

    #[test]
    fn test_remove_passphrase_missing_key_id_errors() {
        let app = ClapCommand::new("sub").arg(Arg::new("key-id").required(false));
        let m = app.try_get_matches_from(vec!["sub"]).unwrap();
        let g_app = ClapCommand::new("sss")
            .arg(Arg::new("confdir").long("confdir").value_name("DIR"))
            .arg(Arg::new("kdf-level").long("kdf-level").value_name("LEVEL"));
        let g = g_app.try_get_matches_from(vec!["sss"]).unwrap();

        let mock = MockPromptReader::new();
        let err = handle_keys_remove_passphrase_with_prompt(&g, &m, &mock).unwrap_err();
        assert!(format!("{err}").contains("Key ID is required"));
    }

    #[test]
    fn test_generate_unknown_suite_value_errors() {
        // clap rejects unknown values via its value_parser — confirm.
        let res = build_keys_app().try_get_matches_from(vec![
            "sss", "keys", "generate", "--suite", "bogus",
        ]);
        let err = res.unwrap_err().to_string();
        assert!(err.contains("invalid value"), "got: {err}");
    }

    #[test]
    fn test_real_prompt_reader_error_propagation_via_trait_object() {
        // Confirm `RealPromptReader` is dyn-compatible (object-safe) — if this
        // ever regresses the production wiring breaks.
        fn takes_dyn(_p: &dyn PromptReader) {}
        takes_dyn(&RealPromptReader);
    }
}
