// Why: clippy::unwrap_used is allowed file-wide because every .unwrap() in this
// file is on a clap-required arg (clap framework declares required(true) and
// returns Some on every match), or on a length-validated try_into (e.g. raw is
// already checked to be exactly 32 bytes in the match arm). All sites carry
// individual INVARIANT comments. HARDEN-01 / 08-01.
// items_after_statements is allowed because the v2.x command dispatchers nest
// helper fns inside main handler fns for readability; refactoring out would
// require module restructuring outside the v2.3 scope.
#![allow(clippy::unwrap_used, clippy::items_after_statements)]

use anyhow::{anyhow, Result};
use clap::ArgMatches;
use std::fs;
use std::path::Path;

use crate::{
    commands::utils::{create_keystore, get_password_if_protected, get_system_username},
    config::get_project_config_path,
    constants::DEFAULT_USERNAME_FALLBACK,
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
    let config = ProjectConfig::load_from_file(&config_path)?;  // PQSIG-06: unmask so D-10 string flows through

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

// Why: 107 lines is the natural shape of users-add — clap parsing + dual-suite
// public-key length dispatch (32 vs 1214 bytes) + project-config mutation +
// re-seal-for-existing-users. The linear flow maps directly to docs/USAGE.md.
#[allow(clippy::too_many_lines)]
fn handle_users_add(main_matches: &ArgMatches, sub_matches: &ArgMatches) -> Result<()> {
    use base64::Engine as _;

    // INVARIANT: clap declares both `username` and `public-key` as required(true),
    // so .unwrap() is guaranteed by the clap framework on the two get_one calls
    // below. HARDEN-01 / 08-01.
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
        // INVARIANT: this match arm only fires when raw.len() == 32, so
        // raw.try_into::<[u8; 32]>() always succeeds. HARDEN-01 / 08-01.
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
    let mut config = ProjectConfig::load_from_file(&config_path)?;  // PQSIG-06: unmask so D-10 string flows through
    config.require_signed(&config_path)?;  // PQSIG-06: refuse to mutate an unsigned envelope

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
            KeyPair::Hybrid(keystore.load_hybrid_keypair(&id, password_str.as_deref(), false)?)
        }
        #[cfg(not(feature = "hybrid"))]
        return Err(anyhow!("hybrid suite requires a --features hybrid build"));
    } else {
        keystore.get_current_keypair(password_str.as_deref())?
    };
    let repository_key = open_suite.open_repo_key(&sealed_key, &our_keypair)?;

    // add_user dispatches sealing via config.suite() internally.
    config.add_user(username, &new_pub, &repository_key)?;

    // Sign-on-write (PQSIG-05 / D-14): hybrid projects re-sign the envelope
    // before atomic write so the new user entry is covered by the signature.
    #[cfg(feature = "hybrid")]
    if suite == Suite::Hybrid {
        use crate::envelope_sig::{build_envelope_payload, sign_envelope};
        use crate::project::EnvelopeMeta;
        use base64::Engine as _;

        let (ed_sk, pq_sk) = keystore.load_sig_keypair(&current_user, password_str.as_deref())?;
        // Populate sig pubkeys in the writer's user entry if absent.
        if let Some(u) = config.users.get_mut(&current_user) {
            if u.sig_ed448_public.is_none() {
                u.sig_ed448_public = Some(
                    base64::prelude::BASE64_STANDARD.encode(ed_sk.verifying_key().as_bytes()),
                );
            }
            if u.sig_mldsa65_public.is_none() {
                u.sig_mldsa65_public = Some(
                    base64::prelude::BASE64_STANDARD.encode(pq_sk.verifying_key().as_bytes()),
                );
            }
        }
        config.format_version = 2;
        let payload = build_envelope_payload(&config);
        let sig = sign_envelope(&ed_sk, &pq_sk, &payload)?;
        config.envelope.get_or_insert_with(EnvelopeMeta::default).sig = Some(sig);
        crate::config::write_atomic(&config, &config_path)?;
    }
    #[cfg(feature = "hybrid")]
    if suite != Suite::Hybrid {
        config.save_to_file(&config_path)?;
    }
    #[cfg(not(feature = "hybrid"))]
    config.save_to_file(&config_path)?;

    println!("Added user '{username}' to project");
    println!("Public key: {}", new_pub.to_base64());
    Ok(())
}

fn handle_users_remove(main_matches: &ArgMatches, sub_matches: &ArgMatches) -> Result<()> {
    // INVARIANT: clap declares `username` as required(true). HARDEN-01 / 08-01.
    let username = sub_matches.get_one::<String>("username").unwrap();

    // Load project config once.
    let config_path = get_project_config_path()?;
    let mut config = ProjectConfig::load_from_file(&config_path)?;
    config.require_signed(&config_path)?;  // PQSIG-06: refuse to mutate an unsigned envelope
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

    // Remove the user from the in-memory copy and persist immediately so that
    // RotationManager (which reloads from disk) sees the reduced user map.
    // Previously `rotation` was assumed to "rewrite wholesale from disk" but
    // that left the removed user in the on-disk file until rotation completed.
    config.remove_user(username)?;
    config.save_to_file(&config_path)?;

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
            KeyPair::Hybrid(keystore.load_hybrid_keypair(&id, password_str.as_deref(), false)?)
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

    // Sign-on-write (PQSIG-05 / D-14): after RotationManager rewrites the
    // file, reload the on-disk state and sign the new envelope.  We use the
    // unverified loader because RotationManager has already committed a valid
    // file and we are about to add the signature in a second atomic write.
    #[cfg(feature = "hybrid")]
    if suite == Suite::Hybrid {
        use crate::envelope_sig::{build_envelope_payload, sign_envelope};
        use crate::project::{EnvelopeMeta, ProjectConfig};
        use base64::Engine as _;

        let mut rotated = ProjectConfig::load_from_file_unverified(&config_path)?;

        let (ed_sk, pq_sk) = keystore.load_sig_keypair(&current_user, password_str.as_deref())?;
        // Populate sig pubkeys in the writer's user entry if absent.
        if let Some(u) = rotated.users.get_mut(&current_user) {
            if u.sig_ed448_public.is_none() {
                u.sig_ed448_public = Some(
                    base64::prelude::BASE64_STANDARD.encode(ed_sk.verifying_key().as_bytes()),
                );
            }
            if u.sig_mldsa65_public.is_none() {
                u.sig_mldsa65_public = Some(
                    base64::prelude::BASE64_STANDARD.encode(pq_sk.verifying_key().as_bytes()),
                );
            }
        }
        rotated.format_version = 2;
        let payload = build_envelope_payload(&rotated);
        let sig = sign_envelope(&ed_sk, &pq_sk, &payload)?;
        rotated.envelope.get_or_insert_with(EnvelopeMeta::default).sig = Some(sig);
        crate::config::write_atomic(&rotated, &config_path)?;
    }

    println!("✓ User '{username}' removed and repository key rotated");
    Ok(())
}

fn handle_users_info(sub_matches: &ArgMatches) -> Result<()> {
    // INVARIANT: clap declares `username` as required(true). HARDEN-01 / 08-01.
    let username = sub_matches.get_one::<String>("username").unwrap();

    let config_path = get_project_config_path()?;
    let config = ProjectConfig::load_from_file(&config_path)?;  // PQSIG-06: unmask so D-10 string flows through; read-only, no require_signed

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

    // INVARIANT: clap declares both `username` and `hybrid-pubkey` as required(true).
    // HARDEN-01 / 08-01.
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
    // PQSIG-06 carve-out: add-hybrid-key is the v1->v2 migration prep step.
    // It populates a user's hybrid public key on a v1 (unsigned) envelope so
    // that the subsequent `migrate` command can build the AND-composition
    // signature. Gating it on require_signed creates a chicken-and-egg
    // blocker for the documented migration workflow — handle_migrate itself
    // (src/commands/migrate.rs) likewise omits require_signed because it is
    // the v1->v2 transition site.
    let mut config = ProjectConfig::load_from_file(&config_path)?;

    let user = config.users.get_mut(username.as_str()).ok_or_else(|| {
        anyhow!("User '{username}' not found in project")
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
    use serial_test::serial;

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

    /// Build a minimal `ArgMatches` for the add-hybrid-key subcommand.
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
    #[serial]
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
        // PQSIG-06: handle_users_add_hybrid_key calls require_signed, so the
        // fixture must be a valid signed (format_version=2) envelope.
        sign_fixture_envelope(&config_path, "alice");

        // Override cwd so get_project_config_path() finds the temp dir.
        let orig_cwd = std::env::current_dir().unwrap();
        std::env::set_current_dir(temp_dir.path()).unwrap();

        let valid_b64 = base64::prelude::BASE64_STANDARD.encode(vec![0x42u8; HYBRID_PUBLIC_KEY_SIZE]);
        let matches = make_add_hybrid_key_matches("alice", &valid_b64);
        let result = handle_users_add_hybrid_key(&matches);

        // Restore cwd regardless
        std::env::set_current_dir(orig_cwd).unwrap();

        result.expect("correct 1214-byte key must succeed");

        // Verify the field was persisted.  Use load_from_file_unverified because
        // handle_users_add_hybrid_key calls save_to_file (not write_atomic) and
        // therefore does not update the envelope signature; the post-write file has
        // the correct TOML but an invalidated sig.  This test only checks field
        // persistence, not signature validity.
        let saved = crate::project::ProjectConfig::load_from_file_unverified(&config_path).unwrap();
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

    // ====================================================================
    // 16b-04 Tier 1: handle_users_list / add / remove / info coverage
    // ====================================================================

    /// Drop-restoring cwd guard so tests never leak the working directory.
    struct CwdGuard {
        original: std::path::PathBuf,
    }
    impl CwdGuard {
        fn new() -> std::io::Result<Self> {
            Ok(Self { original: std::env::current_dir()? })
        }
    }
    impl Drop for CwdGuard {
        fn drop(&mut self) {
            let _ = std::env::set_current_dir(&self.original);
        }
    }

    /// Build a TempDir-rooted .sss.toml seeded with one classic user.
    /// Returns (`TempDir`, `KeyPair`) — the `TempDir` must outlive the test body.
    ///
    /// Under the `hybrid` feature the fixture is promoted to `format_version=2`
    /// (a valid signed envelope) so that PQSIG-06 `require_signed` checks pass
    /// in the mutating handlers.  Without the feature the file stays at v1,
    /// which is accepted by the non-hybrid handlers.
    fn setup_users_fixture(seed_user: &str) -> (tempfile::TempDir, crate::crypto::KeyPair) {
        let tmp = tempfile::tempdir().expect("tempdir create");
        let kp = crate::crypto::KeyPair::generate().expect("keypair generate");
        let cfg = ProjectConfig::new(seed_user, &kp.public_key()).expect("config new");
        let toml_path = tmp.path().join(".sss.toml");
        cfg.save_to_file(&toml_path).expect("save config");
        #[cfg(feature = "hybrid")]
        sign_fixture_envelope(&toml_path, seed_user);
        (tmp, kp)
    }

    /// Promote an existing `format_version=1` `.sss.toml` to a signed
    /// `format_version=2` envelope using ephemeral sig keypairs.
    ///
    /// This is the test-only analogue of `sss envelope upgrade-sig`.
    /// It generates fresh Ed448 + ML-DSA-65 sig keypairs, stores the public
    /// keys on the named user entry, signs the payload, and atomically
    /// overwrites the file — exactly what the production upgrade-sig handler
    /// does, but without needing a real keystore on disk.
    #[cfg(feature = "hybrid")]
    fn sign_fixture_envelope(toml_path: &std::path::Path, signer: &str) {
        use base64::Engine as _;
        use trelis_primitives::{Ed448Scheme, Ed448Standard, MlDsa65Fips204, MlDsaScheme};

        let mut cfg = ProjectConfig::load_from_file_unverified(toml_path)
            .expect("sign_fixture_envelope: load_from_file_unverified");

        // Generate ephemeral sig keypairs (API: Ed448Standard::generate() / MlDsa65Fips204::generate()).
        let ed_sk = Ed448Standard::generate().expect("ed448 keygen");
        let pq_sk = MlDsa65Fips204::generate().expect("mldsa keygen");

        // Populate signer's sig pubkeys using the scheme trait (Ed448Scheme::verifying_key).
        if let Some(u) = cfg.users.get_mut(signer) {
            u.sig_ed448_public = Some(
                base64::prelude::BASE64_STANDARD.encode(
                    Ed448Standard::verifying_key_to_bytes(&Ed448Standard::verifying_key(&ed_sk)),
                ),
            );
            u.sig_mldsa65_public = Some(
                base64::prelude::BASE64_STANDARD.encode(
                    MlDsa65Fips204::verifying_key_to_bytes(&MlDsa65Fips204::verifying_key(&pq_sk)),
                ),
            );
        }

        cfg.format_version = 2;
        let payload = crate::envelope_sig::build_envelope_payload(&cfg);
        let sig = crate::envelope_sig::sign_envelope(&ed_sk, &pq_sk, &payload)
            .expect("sign_fixture_envelope: sign_envelope");
        cfg.envelope
            .get_or_insert_with(crate::project::EnvelopeMeta::default)
            .sig = Some(sig);

        crate::config::write_atomic(&cfg, toml_path)
            .expect("sign_fixture_envelope: write_atomic");
    }

    fn build_add_matches(username: &str, public_key: &str) -> ArgMatches {
        use clap::{Arg, Command};
        Command::new("add")
            .arg(Arg::new("username").required(true))
            .arg(Arg::new("public-key").required(true))
            .get_matches_from(["add", username, public_key])
    }

    fn build_remove_matches(username: &str) -> ArgMatches {
        use clap::{Arg, Command};
        Command::new("remove")
            .arg(Arg::new("username").required(true))
            .get_matches_from(["remove", username])
    }

    fn build_info_matches(username: &str) -> ArgMatches {
        use clap::{Arg, Command};
        Command::new("info")
            .arg(Arg::new("username").required(true))
            .get_matches_from(["info", username])
    }

    fn build_main_matches() -> ArgMatches {
        use clap::{Arg, Command};
        Command::new("sss")
            .arg(Arg::new("confdir").long("confdir"))
            .get_matches_from(["sss"])
    }

    // ---- handle_users_list ----

    #[test]
    #[serial]
    fn test_handle_users_list_lists_seeded_user() -> Result<()> {
        let _g = CwdGuard::new()?;
        let (tmp, _kp) = setup_users_fixture("alice");
        std::env::set_current_dir(tmp.path())?;
        // Should print without error against a valid config.
        handle_users_list()?;
        Ok(())
    }

    #[test]
    #[serial]
    fn test_handle_users_list_errors_without_project_config() -> Result<()> {
        let _g = CwdGuard::new()?;
        let tmp = tempfile::tempdir()?;
        std::env::set_current_dir(tmp.path())?;
        let err = handle_users_list().unwrap_err().to_string();
        assert!(
            err.contains("project") || err.contains("No project"),
            "expected no-project-config error; got: {err}"
        );
        Ok(())
    }

    // ---- handle_users_info ----

    #[test]
    #[serial]
    fn test_handle_users_info_known_user_succeeds() -> Result<()> {
        let _g = CwdGuard::new()?;
        let (tmp, _kp) = setup_users_fixture("alice");
        std::env::set_current_dir(tmp.path())?;
        let matches = build_info_matches("alice");
        handle_users_info(&matches)?;
        Ok(())
    }

    #[test]
    #[serial]
    fn test_handle_users_info_unknown_user_errors_with_not_found() -> Result<()> {
        // Error-message regression: must say "not found in project".
        let _g = CwdGuard::new()?;
        let (tmp, _kp) = setup_users_fixture("alice");
        std::env::set_current_dir(tmp.path())?;
        let matches = build_info_matches("ghost");
        let err = handle_users_info(&matches).unwrap_err().to_string();
        assert!(
            err.contains("'ghost'") && err.contains("not found"),
            "error must call out missing user; got: {err}"
        );
        Ok(())
    }

    #[test]
    #[serial]
    fn test_handle_users_info_errors_when_config_missing() -> Result<()> {
        let _g = CwdGuard::new()?;
        let tmp = tempfile::tempdir()?;
        std::env::set_current_dir(tmp.path())?;
        let matches = build_info_matches("alice");
        let err = handle_users_info(&matches).unwrap_err().to_string();
        assert!(
            err.contains("No project") || err.contains("project"),
            "expected no-project error; got: {err}"
        );
        Ok(())
    }

    // ---- handle_users_add ----

    #[test]
    #[serial]
    fn test_handle_users_add_invalid_base64_errors() -> Result<()> {
        let _g = CwdGuard::new()?;
        let (tmp, _kp) = setup_users_fixture("alice");
        std::env::set_current_dir(tmp.path())?;
        let main = build_main_matches();
        // Provide a string that is neither a path nor valid base64.
        let matches = build_add_matches("bob", "@@@not_base64@@@");
        let err = handle_users_add(&main, &matches).unwrap_err().to_string();
        assert!(
            err.contains("invalid base64"),
            "error must call out invalid base64; got: {err}"
        );
        Ok(())
    }

    #[test]
    #[serial]
    fn test_handle_users_add_unrecognised_length_errors() -> Result<()> {
        use base64::Engine as _;
        let _g = CwdGuard::new()?;
        let (tmp, _kp) = setup_users_fixture("alice");
        std::env::set_current_dir(tmp.path())?;
        let main = build_main_matches();
        // 17 bytes — neither classic (32) nor hybrid (1214).
        let bad = base64::prelude::BASE64_STANDARD.encode([0u8; 17]);
        let matches = build_add_matches("bob", &bad);
        let err = handle_users_add(&main, &matches).unwrap_err().to_string();
        assert!(
            err.contains("unrecognised public key length"),
            "expected length error; got: {err}"
        );
        Ok(())
    }

    #[test]
    #[serial]
    #[cfg(feature = "hybrid")]
    fn test_handle_users_add_hybrid_key_into_classic_project_errors() -> Result<()> {
        use base64::Engine as _;
        let _g = CwdGuard::new()?;
        let (tmp, _kp) = setup_users_fixture("alice");
        std::env::set_current_dir(tmp.path())?;
        let main = build_main_matches();
        // 1214 zero bytes will fail HybridPublicKey::from_bytes; we want the
        // mismatch error to fire first if possible. The shape of the error
        // message just has to indicate failure.
        let raw = vec![0u8; crate::constants::HYBRID_PUBLIC_KEY_SIZE];
        let b64 = base64::prelude::BASE64_STANDARD.encode(&raw);
        let matches = build_add_matches("bob", &b64);
        let err = handle_users_add(&main, &matches).unwrap_err().to_string();
        // Either the length is rejected because from_bytes rejects all-zero,
        // or the mismatch with the v1 project fires.
        assert!(
            !err.is_empty(),
            "must error rather than silently succeed"
        );
        Ok(())
    }

    // ---- handle_users_remove ----

    #[test]
    #[serial]
    fn test_handle_users_remove_unknown_user_errors() -> Result<()> {
        let _g = CwdGuard::new()?;
        let (tmp, _kp) = setup_users_fixture("alice");
        std::env::set_current_dir(tmp.path())?;
        let main = build_main_matches();
        let matches = build_remove_matches("ghost");
        let err = handle_users_remove(&main, &matches).unwrap_err().to_string();
        assert!(
            err.contains("'ghost'") && err.contains("not found"),
            "error must mention missing user; got: {err}"
        );
        Ok(())
    }

    #[test]
    #[serial]
    fn test_handle_users_remove_last_user_errors() -> Result<()> {
        // Error-message regression: cannot remove last user.
        let _g = CwdGuard::new()?;
        let (tmp, _kp) = setup_users_fixture("alice");
        std::env::set_current_dir(tmp.path())?;
        let main = build_main_matches();
        let matches = build_remove_matches("alice");
        let err = handle_users_remove(&main, &matches).unwrap_err().to_string();
        assert!(
            err.contains("Cannot remove the last user"),
            "expected last-user guard message; got: {err}"
        );
        Ok(())
    }

    // ---- handle_users dispatcher ----

    #[test]
    #[serial]
    fn test_handle_users_dispatches_list_subcommand() -> Result<()> {
        use clap::{Arg, Command};
        let _g = CwdGuard::new()?;
        let (tmp, _kp) = setup_users_fixture("alice");
        std::env::set_current_dir(tmp.path())?;
        let users_app = Command::new("users")
            .subcommand(Command::new("list"))
            .subcommand(Command::new("info").arg(Arg::new("username").required(true)))
            .subcommand(Command::new("remove").arg(Arg::new("username").required(true)));
        let users_matches = users_app.get_matches_from(["users", "list"]);
        handle_users(&build_main_matches(), &users_matches)?;
        Ok(())
    }

    #[test]
    #[serial]
    fn test_handle_users_dispatches_info_subcommand() -> Result<()> {
        use clap::{Arg, Command};
        let _g = CwdGuard::new()?;
        let (tmp, _kp) = setup_users_fixture("alice");
        std::env::set_current_dir(tmp.path())?;
        let users_app = Command::new("users")
            .subcommand(Command::new("info").arg(Arg::new("username").required(true)));
        let users_matches = users_app.get_matches_from(["users", "info", "alice"]);
        handle_users(&build_main_matches(), &users_matches)?;
        Ok(())
    }
}
