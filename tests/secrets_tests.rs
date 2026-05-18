// Why: integration tests use .unwrap()/.expect()/panic! freely; test code is exempt
// from the panic-surface lint policy per CONTEXT.md Area 1 carve-out.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Phase 16 Plan 04 — D-07.3 candidate-pool branch coverage for `src/secrets.rs`.
//!
//! Targets two reachable error arms in `SecretsCache::lookup_secret_with_ops` that
//! survey-uncovered ranges flagged in `coverage-before.txt`. Both tests exercise the
//! public API directly via `SecretsCache::lookup_secret`.
//!
//! Allowed file (per 16-04 plan whitelist).

use std::fs;
use anyhow::Result;
use tempfile::TempDir;

use sss::crypto::{encrypt_to_base64, RepositoryKey};
use sss::secrets::SecretsCache;

/// SECRETS-01: src/secrets.rs:248 — encrypted secrets file but no repository key in cache.
///
/// Trigger: write a `secrets` file whose content is wrapped in the `⊠{...}` encrypted
/// marker, then look up against a default `SecretsCache::new()` (no `repository_key`).
/// The encrypted-prefix branch at line 244 fires; `self.repository_key.is_none()`, so
/// the `else` arm at line 248 returns `anyhow!("Secrets file is encrypted but no
/// repository key provided")`.
#[test]
fn secrets_01_encrypted_file_without_repository_key_errors() -> Result<()> {
    let temp = TempDir::new()?;
    let project_root = temp.path();

    // Build an actually-encrypted secrets file using a real repository key so that
    // the ⊠{ prefix is genuine. The cache being tested has NO key, so it won't decrypt.
    let real_key = RepositoryKey::new();
    let plaintext = "api_token: hunter2\n";
    let sealed = encrypt_to_base64(plaintext, &real_key)?;
    let secrets_content = format!("⊠{{{sealed}}}\n");

    let secrets_file = project_root.join("secrets");
    fs::write(&secrets_file, &secrets_content)?;

    // The file we're "looking up against" lives in the same project root so the
    // upward-search hits the secrets file.
    let target_file = project_root.join("config.yaml");
    fs::write(&target_file, "x: y\n")?;

    let mut cache = SecretsCache::new(); // <-- NO repository key.
    let err = cache
        .lookup_secret("api_token", &target_file, project_root)
        .expect_err("expected error: encrypted file with no key");

    let msg = format!("{err}");
    assert!(
        msg.contains("Secrets file is encrypted but no repository key provided"),
        "unexpected error message: {msg}"
    );
    Ok(())
}

/// SECRETS-02: src/secrets.rs:262-267 — secret name not present in plaintext secrets file.
///
/// Trigger: write a plaintext `secrets` file with one key, then look up a different
/// name. Hits the parse-then-not-found path at lines 258-267, returning
/// `anyhow!("Secret '{}' not found in {}")`.
#[test]
fn secrets_02_missing_secret_name_errors() -> Result<()> {
    let temp = TempDir::new()?;
    let project_root = temp.path();

    let secrets_file = project_root.join("secrets");
    fs::write(&secrets_file, "present_secret: present_value\n")?;

    let target_file = project_root.join("config.yaml");
    fs::write(&target_file, "x: y\n")?;

    let mut cache = SecretsCache::new();
    let err = cache
        .lookup_secret("absent_secret", &target_file, project_root)
        .expect_err("expected error: secret name not in file");

    let msg = format!("{err}");
    assert!(
        msg.contains("Secret 'absent_secret' not found"),
        "unexpected error message: {msg}"
    );
    Ok(())
}
