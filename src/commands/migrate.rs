// Why: every .unwrap() in this file is on a HashMap::get(k) where k was just
// sourced from .keys() in the surrounding loop, or on an Option<T> where the
// preceding validation pass guaranteed Some(_). All sites carry per-site
// INVARIANT comments. HARDEN-01 / 08-01.
#![allow(clippy::unwrap_used)]

use anyhow::{anyhow, Result};
#[cfg(feature = "hybrid")]
use base64::Engine as _;
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
/// Returns the list of (username, `new_sealed_key_b64`) computed, or an error.
/// When `dry_run=false`, also mutates config in memory (version + `sealed_keys`).
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
        // INVARIANT: `username` was sourced from config.users.keys() above
        // (line ~52), so config.users.get(username) is always Some. The
        // `hybrid_public.as_ref().unwrap()` is also sound because the early
        // validation pass (lines ~33-48) guarantees every user has
        // hybrid_public.is_some() before we reach this loop. HARDEN-01 / 08-01.
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
        // INVARIANT: every username in new_sealed originates from
        // config.users.keys() (see the loop at line ~55), so
        // config.users.get_mut(username) is always Some. HARDEN-01 / 08-01.
        config.users.get_mut(username).unwrap().sealed_key.clone_from(sealed);
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
                // INVARIANT: `u` was sourced from config.users.keys() above
                // (line ~130), so config.users.get(u) is always Some.
                // HARDEN-01 / 08-01.
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

        // Sign-on-write (PQSIG-05 / D-14): set format_version=2, build payload,
        // sign with both legs, write atomically. The caller's sig keypair is
        // loaded from the keystore under the username resolved above.
        let (ed_sk, pq_sk) = keystore.load_sig_keypair(&caller, password_str.as_deref())?;
        if let Some(u) = config.users.get_mut(&caller) {
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
        let payload = crate::envelope_sig::build_envelope_payload(&config);
        let sig = crate::envelope_sig::sign_envelope(&ed_sk, &pq_sk, &payload)?;
        config
            .envelope
            .get_or_insert_with(crate::project::EnvelopeMeta::default)
            .sig = Some(sig);
        crate::config::write_atomic(&config, &config_path)?;

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

    // Helper: build a minimal ProjectConfig with hybrid_public set for all users.
    // Accepts the RepositoryKey so tests can pass the SAME K to migrate_project_config
    // and verify byte-identical recovery after migration.
    fn make_config_with_hybrid(
        users: &[(&str, &HybridKeyPair)],
        repo_key: &RepositoryKey,
    ) -> ProjectConfig {
        use crate::crypto::ClassicSuite;
        let mut cfg = ProjectConfig { version: "1.0".to_string(), ..Default::default() };
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
                sig_ed448_public: None,
                sig_mldsa65_public: None,
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
            sig_ed448_public: None,
            sig_mldsa65_public: None,
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
        let mut cfg = ProjectConfig { version: "1.0".to_string(), ..Default::default() };
        cfg.users.insert("alice".to_string(), UserConfig {
            public: alice_kp.public_key().to_base64(),
            sealed_key: ClassicSuite.seal_repo_key(&repo_key, &alice_kp.public_key()).unwrap(),
            added: "2026-01-01T00:00:00Z".to_string(),
            hybrid_public: None,
            sig_ed448_public: None,
            sig_mldsa65_public: None,
        });

        assert_eq!(
            cfg.find_user_by_public_key(&alice_kp.public_key()),
            Some("alice".to_string()),
            "find_user_by_public_key must return Some(\"alice\") when alice's classic pubkey matches"
        );
    }

    /// TEST-11 / 16-03: regression anchor for the base64-decode error arm in
    /// `migrate_project_config` (src/commands/migrate.rs:64-66). Verifies that a
    /// malformed base64 `hybrid_public` value produces a user-named anyhow error
    /// containing the substring "invalid base64 hybrid public key for user
    /// '<username>'" verbatim from the `anyhow!` call at line 66.
    ///
    /// Note: the survey in 16-01-SUMMARY.md classifies the targeted line range
    /// (64-66) as already green — the existing tests
    /// (`test_migrate_errors_without_hybrid_public_key`,
    /// `test_migrate_rewrites_sealed_keys_and_version`, the proptest blocks)
    /// transitively exercise the success path through this `?`. This test is
    /// retained as a documentation-grade regression anchor that pins the user-
    /// named error message format so a future refactor cannot accidentally
    /// silently widen this arm.
    #[test]
    fn test_migrate_errors_on_invalid_base64_hybrid_public_key() {
        let repo_key = RepositoryKey::new();
        let hkp = HybridKeyPair::generate().unwrap();
        let mut cfg = make_config_with_hybrid(&[("alice", &hkp)], &repo_key);

        // Inject a deliberately malformed base64 value. The "!!!" / spaces
        // characters fail base64 decoding before `HybridPublicKey::from_bytes`
        // is ever called, isolating the FIRST error arm (lines 64-66).
        cfg.users
            .get_mut("alice")
            .unwrap()
            .hybrid_public = Some("!!! not valid base64 !!!".to_string());

        let err = migrate_project_config(&mut cfg, &repo_key, false)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("invalid base64 hybrid public key for user 'alice'"),
            "must surface the verbatim base64-decode error message: {err}"
        );
        assert!(
            err.contains("alice"),
            "must name the failing user for diagnosability: {err}"
        );
    }

    /// TEST-11 / 16-03: regression anchor for the `HybridPublicKey::from_bytes`
    /// length-check error arm in `migrate_project_config`
    /// (src/commands/migrate.rs:68-69). Verifies that a well-formed-but-wrong-
    /// length input produces a user-named anyhow error containing the
    /// substring "invalid hybrid public key for user '<username>'" verbatim
    /// from the `anyhow!` call at line 69.
    ///
    /// Note: the survey in 16-01-SUMMARY.md classifies the targeted line range
    /// (68-69) as already green. This test is retained as a documentation-grade
    /// regression anchor; the NOT-contains assertion on "invalid base64" proves
    /// we hit the SECOND error arm (length check) and not the first
    /// (base64 decode), which is the discriminator a future refactor could
    /// accidentally lose.
    #[test]
    fn test_migrate_errors_on_wrong_length_hybrid_public_key() {
        let repo_key = RepositoryKey::new();
        let hkp = HybridKeyPair::generate().unwrap();
        let mut cfg = make_config_with_hybrid(&[("alice", &hkp)], &repo_key);

        // Inject a well-formed-but-too-short base64 payload. `b"too-short"`
        // is 9 bytes — the base64 encoding decodes cleanly but is far shorter
        // than the real concatenated classic+ML-KEM-768 public-key length, so
        // `HybridPublicKey::from_bytes` rejects it. This isolates the SECOND
        // error arm (lines 68-69) cleanly from the first.
        cfg.users
            .get_mut("alice")
            .unwrap()
            .hybrid_public = Some(base64::prelude::BASE64_STANDARD.encode(b"too-short"));

        let err = migrate_project_config(&mut cfg, &repo_key, false)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("invalid hybrid public key for user 'alice'"),
            "must surface the verbatim hybrid-public-key error message: {err}"
        );
        assert!(
            !err.contains("invalid base64"),
            "must NOT surface the base64-decode message — that would mean the \
             test is hitting the first arm instead of the second: {err}"
        );
    }

    // -------------------------------------------------------------------------
    // TEST-08: Property-based migration tests (Phase 14 / Plan 14-03 / D-04)
    //
    // Placed inline (not in tests/cross_suite_property_test.rs) because
    // UserConfig and ProjectConfig live in pub(crate) mod project, making
    // them unreachable from integration-test crates. The inline mod uses
    // `use super::*` which brings them in scope without widening any public API.
    // -------------------------------------------------------------------------

    /// Deep-copy a `ProjectConfig` via TOML round-trip. `ProjectConfig` does not
    /// derive Clone (it has no need to outside of tests), so we serialise and
    /// deserialise to get an independent copy. Panics on serialisation failure.
    fn clone_project_config(cfg: &ProjectConfig) -> ProjectConfig {
        let toml_str = crate::toml_helpers::serialize_toml(cfg, "test config")
            .expect("serialise ProjectConfig for clone");
        crate::toml_helpers::parse_toml(&toml_str, "test config")
            .expect("parse ProjectConfig clone")
    }

    /// Strategy: a v1 `ProjectConfig` with N (1..=4) users. Each user has a fresh
    /// classic public key and a fresh hybrid public key, so `migrate_project_config`
    /// has all the material it needs to seal new hybrid entries.
    ///
    /// Placed outside the proptest! blocks so the Strategy trait import is
    /// available.
    fn v1_project_config_strategy()
        -> impl proptest::strategy::Strategy<Value = ProjectConfig>
    {
        use proptest::strategy::Strategy as _;
        (1usize..=4).prop_map(|n_users| {
            use crate::crypto::ClassicSuite;
            let repo_key = RepositoryKey::new();
            let mut cfg = ProjectConfig { version: "1.0".to_string(), ..Default::default() };
            for i in 0..n_users {
                let classic_kp = KeyPair::generate().expect("classic kp");
                let hybrid_kp = HybridKeyPair::generate().expect("hybrid kp");
                let hybrid_b64 = base64::prelude::BASE64_STANDARD
                    .encode(hybrid_kp.public_key().as_bytes());
                let classic_pk = classic_kp.public_key();
                let sealed = ClassicSuite
                    .seal_repo_key(&repo_key, &classic_pk)
                    .expect("seal v1 key");
                cfg.users.insert(format!("user{i}"), UserConfig {
                    public: classic_pk.to_base64(),
                    sealed_key: sealed,
                    added: "2026-01-01T00:00:00Z".to_string(),
                    hybrid_public: Some(hybrid_b64),
                    sig_ed448_public: None,
                    sig_mldsa65_public: None,
                });
            }
            cfg
        })
    }

    proptest::proptest! {
        #![proptest_config(proptest::test_runner::Config {
            cases: 30,
            failure_persistence: None,
            ..proptest::test_runner::Config::default()
        })]

        /// TEST-08: migration idempotency property. After running
        /// `migrate_project_config(false)` twice on the same input vs once on a
        /// clone, the deterministic surface (version, user set, hybrid_public per
        /// user) is identical. Sealed_key BYTES differ across calls because the
        /// hybrid AEAD seal uses a random nonce (src/crypto/hybrid.rs:170-176),
        /// so the property compares structure, not bytes.
        ///
        /// Phase 14 / Plan 14-03 / D-04. Why: catches regressions in the
        /// user-loop ordering, the version field mutation, or a hypothetical
        /// "already-migrated guard" that would prevent re-migration from
        /// working, which would surface as semantic drift across repeated runs.
        #[test]
        fn prop_migrate_idempotent(cfg in v1_project_config_strategy()) {
            let repo_key = RepositoryKey::new();
            let mut cfg1 = clone_project_config(&cfg);
            let mut cfg2 = clone_project_config(&cfg);

            // First migration on cfg1
            migrate_project_config(&mut cfg1, &repo_key, false)
                .expect("first migrate");
            proptest::prop_assert_eq!(
                cfg1.version.as_str(), "2.0",
                "after migration, version must be 2.0"
            );

            // Second migration on the already-migrated cfg1 (re-seal allowed —
            // validate+seal loop does not reject version=="2.0" configs;
            // it only checks that every user has hybrid_public set).
            migrate_project_config(&mut cfg1, &repo_key, false)
                .expect("second migrate (re-seal allowed)");
            proptest::prop_assert_eq!(
                cfg1.version.as_str(), "2.0",
                "after re-migration, version must still be 2.0"
            );

            // Reference: single migration on cfg2
            migrate_project_config(&mut cfg2, &repo_key, false)
                .expect("reference migrate");

            // Structural equivalence: same user set, every user has a non-empty
            // sealed_key after migration, every user's hybrid_public is preserved.
            // Sealed_key BYTES differ (random nonce per seal — not a bug).
            let users1: std::collections::BTreeSet<&String> =
                cfg1.users.keys().collect();
            let users2: std::collections::BTreeSet<&String> =
                cfg2.users.keys().collect();
            proptest::prop_assert_eq!(
                users1, users2,
                "user set must be invariant under re-migration"
            );

            for (uname, uc) in &cfg1.users {
                proptest::prop_assert!(
                    !uc.sealed_key.is_empty(),
                    "user {} sealed_key must be non-empty after migration", uname
                );
                proptest::prop_assert!(
                    uc.hybrid_public.is_some(),
                    "user {} hybrid_public must be preserved after migration", uname
                );
            }
        }

        /// TEST-08: --dry-run determinism property. Two dry-run invocations on
        /// the same input ProjectConfig + same RepositoryKey produce identical
        /// (username order + count) outputs, and the input config is unchanged.
        ///
        /// Phase 14 / Plan 14-03 / D-04. Why: dry-run is the user-facing preview
        /// of `sss migrate`; non-determinism in the username order would make the
        /// preview misleading. The sealed_key BYTES differ between calls because
        /// the hybrid AEAD seal uses a random nonce (src/crypto/hybrid.rs:170-176)
        /// — that is the documented contract, not a bug. The property checks the
        /// deterministic surface only: username order + count.
        #[test]
        fn prop_migrate_dry_run_deterministic(cfg in v1_project_config_strategy()) {
            let repo_key = RepositoryKey::new();
            let original_version = cfg.version.clone();
            let original_user_count = cfg.users.len();
            let mut cfg_mut = clone_project_config(&cfg);

            let result1 = migrate_project_config(&mut cfg_mut, &repo_key, true)
                .expect("first dry-run");
            let result2 = migrate_project_config(&mut cfg_mut, &repo_key, true)
                .expect("second dry-run");

            // Dry-run promise: input is unchanged.
            proptest::prop_assert_eq!(
                cfg_mut.version, original_version,
                "dry-run must not mutate config.version"
            );
            proptest::prop_assert_eq!(
                cfg_mut.users.len(), original_user_count,
                "dry-run must not change user count"
            );

            // Determinism over the deterministic surface:
            // username order (sorted at line 53) and entry count.
            proptest::prop_assert_eq!(
                result1.len(), result2.len(),
                "dry-run output count must be invariant across two calls"
            );
            let names1: Vec<&String> = result1.iter().map(|(u, _)| u).collect();
            let names2: Vec<&String> = result2.iter().map(|(u, _)| u).collect();
            proptest::prop_assert_eq!(
                names1, names2,
                "dry-run username order must be deterministic (sorted)"
            );
        }
    }
}
