#![allow(clippy::missing_errors_doc)]
use anyhow::{anyhow, Result};
use clap::ArgMatches;

#[cfg(feature = "hybrid")]
use crate::{
    commands::utils::{create_keystore, get_password_if_protected},
    config::get_project_config_path,
    crypto::{ClassicSuite, CryptoSuite},
    project::ProjectConfig,
};

// ---- Core logic (testable without a keystore) ----------------------------

/// Core migration: re-seals K for every user under the hybrid suite.
///
/// Returns the list of (username, new_sealed_key_b64) computed, or an error.
/// When dry_run=false, also mutates config in memory (version + sealed_keys).
/// Does NOT touch disk — caller decides whether to save.
///
/// MIGRATE-02 invariant: only .sss.toml changes. In-file AEAD ciphertexts
/// (the .secrets files) are NEVER touched by this function or its callers.
#[cfg(feature = "hybrid")]
pub fn migrate_project_config(
    config: &mut ProjectConfig,
    repository_key: &crate::crypto::RepositoryKey,
    dry_run: bool,
) -> Result<Vec<(String, String)>> {
    use base64::Engine as _;
    use crate::crypto::{HybridCryptoSuite, HybridPublicKey, PublicKey};

    // 1. Early validation: all users must have hybrid_public set
    let mut missing: Vec<String> = config
        .users
        .iter()
        .filter(|(_, uc)| uc.hybrid_public.is_none())
        .map(|(name, _)| name.clone())
        .collect();
    missing.sort();

    if !missing.is_empty() {
        return Err(anyhow!(
            "the following users have no hybrid public key registered:\n  {}\n\
             Run `sss keygen --suite hybrid` on each user's machine then\n\
             `sss users add-hybrid-key <user> <pubkey>` to register it.",
            missing.join("\n  ")
        ));
    }

    // 2. Compute new sealed keys for every user (no disk writes yet)
    let mut new_sealed: Vec<(String, String)> = Vec::new();
    let mut usernames: Vec<String> = config.users.keys().cloned().collect();
    usernames.sort();

    for username in &usernames {
        let uc = config.users.get(username).unwrap();
        let hybrid_b64 = uc.hybrid_public.as_ref().unwrap();

        let raw = base64::prelude::BASE64_STANDARD
            .decode(hybrid_b64)
            .map_err(|e| anyhow!("invalid base64 hybrid public key for user '{username}': {e}"))?;

        let hpk = HybridPublicKey::from_bytes(&raw)
            .map_err(|e| anyhow!("invalid hybrid public key for user '{username}': {e}"))?;
        let pk = PublicKey::Hybrid(hpk);

        let sealed = HybridCryptoSuite.seal_repo_key(repository_key, &pk)?;
        new_sealed.push((username.clone(), sealed));
    }

    // 3. Dry-run: return results without mutating config
    if dry_run {
        return Ok(new_sealed);
    }

    // 4. Apply mutations in memory (all-or-nothing before save).
    //    Only sealed_key changes — `public` remains the classic identity anchor
    //    so that find_user_by_public_key continues to work via the classic keypair.
    for (username, sealed) in &new_sealed {
        config.users.get_mut(username).unwrap().sealed_key = sealed.clone();
    }
    config.version = "2.0".to_string();

    Ok(new_sealed)
}

// ---- CLI handler ---------------------------------------------------------

pub fn handle_migrate(main_matches: &ArgMatches, matches: &ArgMatches) -> Result<()> {
    #[cfg(not(feature = "hybrid"))]
    let _ = (main_matches, matches);
    // Feature gate: migrate is a no-op without hybrid support
    #[cfg(not(feature = "hybrid"))]
    return Err(anyhow!(
        "sss migrate requires a --features hybrid build"
    ));

    #[cfg(feature = "hybrid")]
    {
        let dry_run = matches.get_flag("dry-run");

        // Load config (v1 — we are migrating from classic to hybrid)
        let config_path = get_project_config_path()?;
        let mut config = ProjectConfig::load_from_file(&config_path)?;

        // Load caller's classic keypair to unseal K
        let keystore = create_keystore(main_matches)?;
        let password_str = get_password_if_protected(
            &keystore,
            "Enter your passphrase to unseal the repo key (or press Enter if none): ",
        )?;
        let our_keypair = keystore.get_current_keypair(password_str.as_deref())?;

        // Identify which user we are by matching the classic public key
        let caller = config
            .find_user_by_public_key(&our_keypair.public_key())
            .ok_or_else(|| anyhow!(
                "Your classic public key is not in this project.\n\
                 Your public key: {}\n\
                 Ask a project admin to add you first.",
                our_keypair.public_key().to_base64()
            ))?;

        // Unseal K using ClassicSuite (v1 sealed_key uses classic wrap)
        let sealed_key = config.get_sealed_key_for_user(&caller)?;
        let repository_key = ClassicSuite.open_repo_key(&sealed_key, &our_keypair)?;

        // Dry-run path: print plan without writing
        if dry_run {
            let mut usernames: Vec<String> = config.users.keys().cloned().collect();
            usernames.sort();
            println!("Migration plan (dry run):");
            println!("  version: {} -> 2.0", config.version);
            println!("  Users to re-seal ({}):", usernames.len());
            for u in &usernames {
                let uc = config.users.get(u).unwrap();
                let status = if uc.hybrid_public.is_some() { "ready" } else { "MISSING hybrid key" };
                println!("    {u}: {status}");
            }
            // Call the core fn with dry_run=true to trigger validation errors
            // (dry_run=true does not mutate config, so no clone needed)
            migrate_project_config(&mut config, &repository_key, true)
                .map_err(|e| anyhow!("Dry run detected issues:\n{e}"))?;
            println!("\nDry run complete. No changes written.");
            return Ok(());
        }

        // Execute migration
        migrate_project_config(&mut config, &repository_key, false)?;
        config.save_to_file(&config_path)?;

        let n = config.users.len();
        println!("Migrated {n} user(s) to hybrid suite. .sss.toml version bumped to \"2.0\".");
        Ok(())
    }
}

// ---- Tests ---------------------------------------------------------------
#[cfg(all(test, feature = "hybrid"))]
mod tests {
    use super::*;
    use crate::{
        crypto::{hybrid::HybridKeyPair, HybridCryptoSuite, CryptoSuite, KeyPair,
                 RepositoryKey},
        project::{ProjectConfig, UserConfig},
    };
    use base64::Engine as _;

    // Helper: build a minimal ProjectConfig with hybrid_public set for all users.
    // Accepts the RepositoryKey so tests can pass the SAME K to migrate_project_config
    // and verify byte-identical recovery after migration.
    fn make_config_with_hybrid(
        users: &[(&str, &HybridKeyPair)],
        repo_key: &RepositoryKey,
    ) -> ProjectConfig {
        use crate::crypto::ClassicSuite;
        let mut cfg = ProjectConfig::default();
        cfg.version = "1.0".to_string();
        for (username, hkp) in users {
            let classic_kp = crate::crypto::KeyPair::generate().unwrap();
            let classic_pk = classic_kp.public_key();
            // Seal the shared repo_key with the classic keypair (v1 pre-migration state)
            let sealed = ClassicSuite.seal_repo_key(repo_key, &classic_pk).unwrap();
            let hybrid_b64 = base64::prelude::BASE64_STANDARD.encode(hkp.public_key().as_bytes());
            cfg.users.insert(username.to_string(), UserConfig {
                public: classic_pk.to_base64(),
                sealed_key: sealed,
                added: "2026-01-01T00:00:00Z".to_string(),
                hybrid_public: Some(hybrid_b64),
            });
        }
        cfg
    }

    #[test]
    fn test_migrate_errors_without_hybrid_public_key() {
        let repo_key = RepositoryKey::new();
        let hkp = HybridKeyPair::generate().unwrap();
        let mut cfg = make_config_with_hybrid(&[("alice", &hkp)], &repo_key);
        // Add bob without hybrid_public
        let classic_kp = crate::crypto::KeyPair::generate().unwrap();
        cfg.users.insert("bob".to_string(), UserConfig {
            public: classic_kp.public_key().to_base64(),
            sealed_key: ClassicSuite.seal_repo_key(&repo_key, &classic_kp.public_key()).unwrap(),
            added: "2026-01-01T00:00:00Z".to_string(),
            hybrid_public: None,
        });

        let err = migrate_project_config(&mut cfg, &repo_key, false)
            .unwrap_err()
            .to_string();
        assert!(err.contains("bob"), "must name the missing user: {err}");
        assert!(err.contains("sss keygen --suite hybrid"), "must give remediation: {err}");
    }

    #[test]
    fn test_migrate_dry_run_does_not_mutate_config() {
        let repo_key = RepositoryKey::new();
        let hkp_a = HybridKeyPair::generate().unwrap();
        let hkp_b = HybridKeyPair::generate().unwrap();
        let mut cfg = make_config_with_hybrid(&[("alice", &hkp_a), ("bob", &hkp_b)], &repo_key);
        let original_version = cfg.version.clone();
        let original_alice_sealed = cfg.users.get("alice").unwrap().sealed_key.clone();

        migrate_project_config(&mut cfg, &repo_key, true).unwrap();

        // Dry run: config must not be mutated
        assert_eq!(cfg.version, original_version, "dry run must not change version");
        assert_eq!(
            cfg.users.get("alice").unwrap().sealed_key,
            original_alice_sealed,
            "dry run must not change sealed_key"
        );
    }

    #[test]
    fn test_migrate_rewrites_sealed_keys_and_version() {
        let repo_key = RepositoryKey::new();
        let hkp_a = HybridKeyPair::generate().unwrap();
        let hkp_b = HybridKeyPair::generate().unwrap();
        let mut cfg = make_config_with_hybrid(&[("alice", &hkp_a), ("bob", &hkp_b)], &repo_key);
        let old_alice_sealed = cfg.users.get("alice").unwrap().sealed_key.clone();
        let old_bob_sealed = cfg.users.get("bob").unwrap().sealed_key.clone();

        migrate_project_config(&mut cfg, &repo_key, false).unwrap();

        assert_eq!(cfg.version, "2.0", "version must be bumped to 2.0");
        assert_ne!(cfg.users.get("alice").unwrap().sealed_key, old_alice_sealed,
            "alice's sealed_key must change after migration");
        assert_ne!(cfg.users.get("bob").unwrap().sealed_key, old_bob_sealed,
            "bob's sealed_key must change after migration");
    }

    #[test]
    fn test_migrate_result_opens_with_hybrid_suite() {
        // MIGRATE-01 core invariant: the SAME K that went in must come back out.
        // Uses the shared repo_key passed to make_config_with_hybrid so there
        // is no ambiguity about which K was sealed into the entries.
        let repo_key = RepositoryKey::new();
        let hkp_a = HybridKeyPair::generate().unwrap();
        let hkp_b = HybridKeyPair::generate().unwrap();
        let mut cfg = make_config_with_hybrid(&[("alice", &hkp_a), ("bob", &hkp_b)], &repo_key);

        migrate_project_config(&mut cfg, &repo_key, false).unwrap();

        // Alice can unseal with her hybrid keypair and recovers the original K
        let alice_sealed = cfg.users.get("alice").unwrap().sealed_key.clone();
        let alice_kp = KeyPair::Hybrid(hkp_a);
        let alice_k = HybridCryptoSuite.open_repo_key(&alice_sealed, &alice_kp).unwrap();
        assert_eq!(repo_key.to_base64(), alice_k.to_base64(),
            "alice must recover the original K (byte-identical) after migration");

        // Bob can unseal with his hybrid keypair and recovers the original K
        let bob_sealed = cfg.users.get("bob").unwrap().sealed_key.clone();
        let bob_kp = KeyPair::Hybrid(hkp_b);
        let bob_k = HybridCryptoSuite.open_repo_key(&bob_sealed, &bob_kp).unwrap();
        assert_eq!(repo_key.to_base64(), bob_k.to_base64(),
            "bob must recover the original K (byte-identical) after migration");
    }

    #[test]
    fn test_caller_classic_pubkey_matches_stored_user() {
        // Covers the find_user_by_public_key caller-identification logic used in handle_migrate.
        // Ensures a classic KeyPair's public_key() is found by scanning config.users[*].public.
        let alice_kp = KeyPair::generate().unwrap();
        let repo_key = RepositoryKey::new();
        let mut cfg = ProjectConfig::default();
        cfg.version = "1.0".to_string();
        cfg.users.insert("alice".to_string(), UserConfig {
            public: alice_kp.public_key().to_base64(),
            sealed_key: ClassicSuite.seal_repo_key(&repo_key, &alice_kp.public_key()).unwrap(),
            added: "2026-01-01T00:00:00Z".to_string(),
            hybrid_public: None,
        });

        assert_eq!(
            cfg.find_user_by_public_key(&alice_kp.public_key()),
            Some("alice".to_string()),
            "find_user_by_public_key must return Some(\"alice\") when alice's classic pubkey matches"
        );
    }
}
