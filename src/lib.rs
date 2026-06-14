// Why: panic-surface test suites use .unwrap()/.expect()/panic!() freely per CONTEXT.md Area 1; one crate-root carve-out is the audit-discoverable policy site.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]
//! sss — Secret String Substitution.
//!
//! Transparent encryption of secrets within files using XChaCha20-Poly1305,
//! with multi-user key management and git integration. Supports two crypto
//! suites: Classic (libsodium `crypto_box_seal`, default) and Hybrid (trelis
//! X448 + sntrup761 + BLAKE3, `feature = "hybrid"`).
//!
//! # Module structure
//!
//! Core pipeline (publicly visible — see the listed `pub mod` and
//! `pub use` items below):
//! - [`crypto`] — cryptographic primitives (Classic / Hybrid suites; FFI)
//! - [`keystore`] — local encrypted keystore; Classic + Hybrid keypairs
//! - [`processor`] — marker detection and transformation pipeline
//! - [`marker_inference`] — placeholder marker resolution
//!
//! Crate-internal pipeline (now `pub(crate)` after CLEAN-03 — addressable from
//! within the crate but not part of the published API):
//! - `kdf` — Argon2id key derivation
//! - `scanner` — project directory scanner with ignore patterns
//! - `secrets` — secret extraction / substitution helpers
//! - `merge` — content reconciliation between encrypted-on-disk and edited
//! - `secure_memory` — zeroising memory primitives
//! - `rate_limiter` — token-bucket rate limiting (agent path)
//!
//! Configuration / project surface:
//! - [`config`] — `.sss.toml` parsing + `load_key` family (public)
//! - [`config_manager`] — user-settings layer (public, orthogonal to `config`)
//! - `project` — `ProjectConfig` and project-root discovery (re-export
//!   `ProjectConfig` is public)
//! - `constants` — crate-wide constant table (`pub(crate)`)
//! - `toml_helpers` — TOML serialisation helpers (`pub(crate)`)
//! - `error` / `error_helpers` — error types and conversions (re-exports
//!   `Result` / `SssError` are public; modules are `pub(crate)`)
//! - `validation` — input validation helpers (`pub(crate)`)
//! - `editor` — editor invocation helpers (`pub(crate)`)
//!
//! Daemon / interactive surface:
//! - [`agent`] — agent client / protocol / policy (directory-module: `client`,
//!   `policy`, `protocol`)
//! - [`askpass`] — askpass dialog plumbing
//! - [`audit_log`] — agent audit logging
//! - [`commands`] — CLI subcommand implementations
//! - `rotation` — repository-key rotation (`pub(crate)`)
//! - `keyring_manager` / `keyring_support` — OS keyring integration
//!   (`pub(crate)`; the re-export `KeyringManager` is public)
//!
//! Filesystem surface (platform-gated):
//! - `fuse` — FUSE filesystem (Linux/macOS, `feature = "fuse"`, `pub(crate)`);
//!   the directory-module hosts `fs` (top-level `SssFS`), `inode_manager`,
//!   `file_cache`, `virtual_fs`
//! - `winfsp_fs` — `WinFSP` filesystem (Windows, `feature = "winfsp"`,
//!   `pub(crate)`)
//! - `ninep_fs` — 9P server (`feature = "ninep"`, `pub(crate)`; the re-export
//!   `SssNinepFS` is public — only reachable under `feature = "ninep"`)
//! - [`filesystem_common`] — cross-backend filesystem helpers (public; reached
//!   by `benches/fuse_read_latency.rs`)
//!
//! # Public API
//!
//! The curated public surface is the re-export block below: [`Config`],
//! [`KeyPair`], [`RepositoryKey`], [`SssError`] / [`Result`],
//! [`KeyringManager`], [`Keystore`], [`Processor`], [`ProjectConfig`], plus
//! `SssNinepFS` (cfg-gated, `feature = "ninep"`). The 11 `pub mod` declarations (`agent`,
//! `askpass`, `audit_log`, `commands`, `config`, `config_manager`, `crypto`,
//! `filesystem_common`, `keystore`, `marker_inference`, `processor`)
//! constitute the additional reachable module surface (consumed by binaries
//! and benches; verified via `tests/public_api_panic_surface.rs`). Internal
//! items that are only needed crate-internally are `pub(crate)` (CLEAN-03
//! visibility narrowing — Plan 11-04).
//!
//! # References
//!
//! - `docs/CRYPTOGRAPHY.md` — crypto suite design and primitives
//! - `docs/security-model.md` — trust boundaries and threat model
//! - `.planning/phases/11-code-cleanup/11-03-SUMMARY.md` — module-structure
//!   audit (CLEAN-04, D-14 / D-15 / D-16 / D-17)
//! - `.planning/phases/11-code-cleanup/11-04-SUMMARY.md` — public-API surface
//!   review (CLEAN-03, D-09 / D-10 / D-11 / D-13)

/// Agent client, protocol and policy plumbing for the local sss-agent daemon.
///
/// Use this module from the `sss-agent` binary (and from in-tree integration
/// tests that exercise the agent socket) to obtain `AgentClient`,
/// `PolicyManager`, and the request/response message types defined in
/// `agent::protocol`. The directory-module hosts three sub-modules: `client`
/// (Unix-socket connection management), `policy` (passphrase-prompt
/// authorisation rules), and `protocol` (wire-format codec).
///
/// Available unconditionally — agent functionality is always compiled in,
/// though socket binding is the agent binary's responsibility, not this
/// crate's. See `docs/security-model.md` for the agent trust boundary.
pub mod agent;

/// Askpass dialog plumbing — TTY-driven passphrase prompts.
///
/// Use this module to invoke an askpass-style dialog when the agent path needs
/// to prompt the user for a passphrase that is not present in
/// `SSS_PASSPHRASE` and is not cached by an earlier policy decision. The
/// `AskpassConfig` struct controls prompt text and timeout; `prompt_user`
/// returns the entered passphrase wrapped in zeroising storage.
///
/// Public because consumed by the `sss-agent` binary at
/// `src/bin/sss-agent.rs:16`.
pub mod askpass;

/// Audit logging for the agent path — append-only event log of policy
/// decisions, key access, and rate-limit events.
///
/// Use this module to record every authorisation outcome (`PolicyDecision`)
/// and every passphrase-prompt event for forensic auditability. The log is
/// rotated by the agent on size threshold; see `docs/security-model.md` for
/// the audit-log threat-model treatment (information disclosure on disk is
/// mitigated by appropriate `umask`).
///
/// Public because consumed by the `sss-agent` binary at
/// `src/bin/sss-agent.rs:17` (`AuditEvent`, `AuditLogger`, `RateLimiter`).
pub mod audit_log;

/// CLI subcommand implementations — one module per top-level `sss <verb>`.
///
/// Use this module from `src/main.rs` to dispatch parsed clap arguments to
/// the corresponding handler (`handle_init`, `handle_encrypt`, `handle_show`,
/// `handle_keys_*`, `handle_users_*`, etc.). Each subcommand's contract
/// (panic / error semantics, expected files, `.sss.toml` requirements) is
/// documented in the per-command module's rustdoc.
///
/// Public because the binary `src/main.rs` consumes virtually every
/// `commands::handle_*` function.
pub mod commands;

/// `.sss.toml` parsing and the `load_key` family — primary user-facing
/// configuration entrypoint.
///
/// Use this module to load a project's `.sss.toml`, retrieve a user's wrapped
/// repository key (`load_key` / `load_key_for_user`), and obtain a `Config`
/// struct for in-place inspection. The crypto-suite version field is parsed
/// here and dispatched via `ProjectConfig::suite()`.
///
/// Public because reached by `tests/public_api_panic_surface.rs:29`
/// (HARDEN-05 baseline) and exposed via the `Config`, `load_key`,
/// `load_key_for_user` re-exports below.
pub mod config;

/// User-settings layer — orthogonal to `config` (`.sss.toml`-side, repo-local)
/// and to `keyring_*` (OS keyring side, machine-local).
///
/// Use this module for cross-cutting user preferences (editor choice, default
/// suite, rate-limit defaults) that are NOT part of repo configuration and
/// NOT secret material. Settings are persisted under the user's
/// platform-appropriate config dir.
///
/// Public because consumed by `commands::settings`; the downgrade probe
/// failed because `SystemSettings.max_file_size` would be flagged dead.
pub mod config_manager;

pub mod constants;

/// Vault integration — offline grammar, reference parser, and (Phase 47+) resolution.
///
/// This module is NOT feature-gated: the `⊳{}` marker constants, the interpolation
/// regex, and `parse_vault_reference` must compile in every build so that peers
/// without `--features vault` can recognise and preserve vault reference markers
/// byte-for-byte through `seal` and `open` (R4 / VREF-01).
///
/// Currently provides: `VAULT_INTERPOLATION_REGEX`, `VaultReference`,
/// `VaultRefError`, `parse_vault_reference`, and `interpolate_vault_refs`
/// (identity stub in Phase 46; wired in Phase 47).
pub mod vault;

/// Cryptographic primitives — Classic (libsodium-backed) and Hybrid
/// post-quantum suites; FFI surface fully audited under HARDEN-03 (see
/// `08-03-SUMMARY.md`).
///
/// Use this module to obtain a `CryptoSuite` implementation matching the
/// `Suite` selector returned by `ProjectConfig::suite()`. The classic suite
/// is always available (libsodium `crypto_box_seal` for repo-key wrap,
/// XChaCha20-Poly1305 for content); the hybrid suite requires the `hybrid`
/// feature and uses vendored trelis primitives (X448 + sntrup761 + BLAKE3).
///
/// See `docs/CRYPTOGRAPHY.md` for the suite contract, deterministic-nonce
/// derivation, and the byte-identical-ciphertext invariant across suites.
pub mod crypto;

pub(crate) mod editor;
pub(crate) mod error;
pub(crate) mod error_helpers;

/// Cross-backend filesystem helpers — marker detection on raw bytes, path
/// canonicalisation, and inode-stable identity helpers shared by `fuse`,
/// `winfsp_fs`, and `ninep_fs`.
///
/// Use `has_any_markers_bytes` to do a fast pre-check before invoking the
/// full processor pipeline (the marker scan is the hot path in FUSE-style
/// reads — see `benches/fuse_read_latency.rs:29`).
///
/// Public because consumed by `benches/fuse_read_latency.rs:29` outside the
/// `fuse` feature gate (the bench compiles unconditionally; the marker-bytes
/// check is feature-independent).
pub mod filesystem_common;

pub(crate) mod toml_helpers;
#[cfg(all(any(target_os = "linux", target_os = "macos"), feature = "fuse"))]
pub(crate) mod fuse;
#[cfg(all(target_os = "windows", feature = "winfsp"))]
pub(crate) mod winfsp_fs;
#[cfg(feature = "ninep")]
pub(crate) mod ninep_fs;
// Restored to `pub mod` after the Phase 11-04 visibility downgrade left
// integration tests silently uncompilable. The CLEAN-03 gate set
// (cargo check + build --bins + public_api_panic_surface + lib --no-run +
// bench --no-run) did not include `cargo build --tests`, so consumers in
// `tests/` were not seen. Phase 14 restores the modules used by those tests.
pub mod kdf;
pub(crate) mod keyring_manager;
pub(crate) mod keyring_support;

/// Local on-disk encrypted keystore — stores Classic and (with `hybrid`
/// feature) Hybrid keypairs under per-user Argon2id-protected envelopes.
///
/// Use this module to load a keypair from disk (`Keystore::load_keypair`),
/// generate a new pair (`Keystore::generate_classic` / `_hybrid` /
/// `_dual`), or obtain a passphrase via the `SSS_PASSPHRASE` env-var-or-prompt
/// helper (`get_passphrase_or_prompt`). Loaded secret keys are wrapped in
/// `Zeroizing<...>` storage per the HARDEN-04 zeroisation audit.
///
/// Public because consumed by `tests/public_api_panic_surface.rs:32`
/// (HARDEN-05 baseline assert_type entries) and `src/bin/sss-agent.rs:19`
/// (`get_passphrase_or_prompt`, `Keystore`).
pub mod keystore;

/// Hybrid AND-composition signing/verification primitives for the `.sss.toml`
/// envelope (Phase 19, PQSIG-04).
///
/// Exposes `ENVELOPE_SIG_CONTEXT`, `build_envelope_payload`, `sign_envelope`,
/// `verify_envelope`, and `verify_envelope_signature`. Consumed by
/// `ProjectConfig::load_from_file` (verify-on-read, plan 19-03) and the four
/// envelope-mutating commands (sign-on-write, plan 19-02).
///
/// Gated on `hybrid` feature (`#![cfg(feature = "hybrid")]` at module top).
#[cfg(feature = "hybrid")]
pub mod envelope_sig;

/// Marker-inference helpers — heuristic resolution of placeholder markers
/// (`⊕{...}` / `O+{...}`) in mixed-content files.
///
/// Use `infer_markers` to attempt inference of marker locations for a file
/// where the marker syntax is partial (e.g. user-edited content where one
/// half of the marker pair was deleted). Heuristic-driven; not part of the
/// canonical encryption pipeline.
///
/// Public because consumed by `benches/marker_inference.rs:4`.
pub mod marker_inference;

pub(crate) mod merge;
pub use merge::smart_reconstruct;

/// Marker detection and transformation pipeline — the canonical
/// encrypt/decrypt entry point for in-content secret substitution.
///
/// Use `Processor::new_with_context` to construct a processor bound to a
/// repository key and a path/timestamp context (the context drives the
/// deterministic-nonce derivation per `docs/CRYPTOGRAPHY.md`); then call
/// `process_content` (auto-detect direction), `encrypt_content`, or
/// `decrypt_content`. The pipeline is byte-identical across suites for
/// matching plaintexts because the per-secret nonce derivation is suite-
/// independent.
///
/// Public because consumed by `tests/public_api_panic_surface.rs:31`
/// (HARDEN-05 baseline) and reachable from binaries via `crate::Processor`
/// at `src/commands/process.rs:21`.
pub mod processor;

pub mod project;
pub mod rate_limiter;
pub mod rotation;
pub mod scanner;
pub mod secrets;
pub mod secure_memory;
pub mod validation;

/// Re-exports the user-facing configuration entry points — the parsed
/// `.sss.toml` struct (`Config`) plus the two passphrase-aware key-load
/// helpers (`load_key`, `load_key_for_user`).
///
/// Use these when the caller only needs to read repository configuration and
/// fetch a wrapped repo key without depending on the `config` module path
/// directly. `load_key` reads the current user's wrapped key (resolving the
/// system username via `commands::utils::get_system_username`);
/// `load_key_for_user` lets the caller specify a username for multi-user
/// scripts. Both return `SssError::Config` on missing `.sss.toml`,
/// `SssError::KeyDerivation` on Argon2id failure, and `SssError::Crypto` on
/// envelope-unwrap failure. These re-exports are also referenced by the
/// in-file `#[cfg(test)] mod tests::test_load_key_functions` at the bottom
/// of this file.
pub use config::{load_key, load_key_for_user, Config};

/// Re-exports the two crypto types used at every public API boundary —
/// `KeyPair` (the per-user public/secret pair, suite-aware enum) and
/// `RepositoryKey` (the per-repo symmetric key wrapped by recipient public
/// keys for content encryption).
///
/// Use `KeyPair::generate()` when bootstrapping a new user; the returned
/// secret-key half is wrapped in zeroising storage per HARDEN-04.
/// `RepositoryKey::new()` generates a fresh repo key; `to_base64` /
/// `from_base64` round-trip via the wire format used in `.sss.toml`. See
/// `docs/CRYPTOGRAPHY.md` for the deterministic-nonce derivation contract.
pub use crypto::{KeyPair, RepositoryKey};

/// Re-exports the crate-wide error type and the matching `Result` alias
/// (`std::result::Result<T, SssError>`).
///
/// Use `SssError` for all fallible-API surfaces that this crate exposes; the
/// `Result` alias avoids the `Result<T, sss::SssError>` long form throughout
/// the public API and the panic-surface regression tests
/// (`tests/public_api_panic_surface.rs:540` references
/// `assert_type::<sss::Result<()>>()`). `SssError` is non-exhaustive — match
/// arms must include a wildcard. See `docs/security-model.md` for the
/// information-disclosure threat-model: error messages are user-facing and
/// must not leak passphrase / secret material.
pub use error::{Result, SssError};

/// Re-exports the OS-keyring integration entry point — store and retrieve
/// per-user passphrases and keypair material from the platform keyring
/// (Secret Service on Linux, Keychain on macOS, Credential Manager on
/// Windows).
///
/// Use `KeyringManager::new()` to obtain a manager (returns Result), then
/// `store_passphrase` / `get_passphrase` / `delete_passphrase` for
/// passphrase-side operations. The keyring is the only persistence path for
/// secret material outside the on-disk encrypted keystore, so callers MUST
/// handle "key not found" errors as recoverable (the user may not have
/// stored the passphrase yet) rather than fatal.
pub use keyring_manager::KeyringManager;

/// Re-exports the on-disk encrypted keystore — the canonical persistence
/// path for Classic and (with `hybrid` feature) Hybrid keypairs.
///
/// Use `Keystore::new()` to bind to a path; then `load_keypair` / `_with_id`
/// to read a keypair (with passphrase prompt or env-var fallback) or
/// `generate_classic` / `_hybrid` / `_dual` to create one. Loaded secret-key
/// material is wrapped in `Zeroizing<...>` storage. The keystore file format
/// is Argon2id-derived envelope per HARDEN-02 / HARDEN-04.
pub use keystore::Keystore;

/// Re-exports the marker-detection and transformation pipeline entry point.
///
/// Use `Processor::new_with_context(repo_key, path, timestamp)` to bind a
/// processor instance; then call `process_content` to auto-detect direction
/// (encrypt or decrypt based on marker state), `encrypt_content` to force
/// encryption, or `decrypt_content` to force decryption. Output is
/// byte-identical across suites for matching plaintexts because the per-
/// secret nonce derivation is suite-independent — see
/// `docs/CRYPTOGRAPHY.md`. Reachable internally as `crate::Processor` at
/// `src/commands/process.rs:21`.
pub use processor::Processor;

/// Re-exports the canonical project-configuration struct — layered over
/// `Config` (which is the raw `.sss.toml` parse) with project-root discovery
/// + crypto-suite dispatch.
///
/// Use `ProjectConfig::load_from_file(path)` to load (with the version-gate
/// check applied — v1.0 stays Classic, v2.0 routes to Hybrid via
/// `resolve_suite_from_version`); `ProjectConfig::suite()` returns the
/// matching `Suite` enum for downstream `CryptoSuite` dispatch. See
/// `docs/CRYPTOGRAPHY.md` for the suite-version dispatch contract.
pub use project::ProjectConfig;

/// Re-exports the key-rotation API: the manager that drives the rotate
/// workflow, the options struct (backup / force / dry-run / progress), and
/// the reason enum used in the audit log.
///
/// These three types are the complete public surface of `sss::rotation`
/// required by integration tests (`tests/rotation_security.rs`,
/// `tests/multi_user_e2e.rs`). They were inadvertently hidden by the
/// Phase 11-04 `pub(crate)` downgrade, which only validated the gate set
/// `{public_api_panic_surface, lib --no-run, bench --no-run}` — neither
/// integration-test file was in that gate. Re-exported here to restore the
/// test surface without widening any other `rotation::` internals.
pub use rotation::{RotationManager, RotationOptions, RotationReason};

/// Re-exports the 9P-protocol filesystem server (`feature = "ninep"`).
///
/// Use `SssNinepFS::new(...)` from the `sss 9p` subcommand to mount a 9P
/// endpoint that exposes the project's marker-decrypted view to 9P clients
/// (Plan 9 / styx-style mounts; complementary to the `fuse` and `winfsp_fs`
/// alternatives). Available only when compiled with `--features ninep` —
/// the cfg attribute below gates the re-export so non-ninep builds do not
/// expose the symbol. Reachable internally as `crate::SssNinepFS` at
/// `src/commands/ninep.rs:117`.
#[cfg(feature = "ninep")]
pub use ninep_fs::SssNinepFS;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_public_api_visibility() {
        // Test that all public exports are accessible
        // This serves as a compile-time test for the public API

        // Test Config can be created with user and key
        let keypair = KeyPair::generate().unwrap();
        let config = Config::new("testuser", &keypair.public_key()).unwrap();
        assert!(config.users.contains_key("testuser"));

        // Test RepositoryKey can be created and converted
        let key = RepositoryKey::new();
        let encoded = key.to_base64();
        assert!(!encoded.is_empty());

        // Test RepositoryKey can be round-tripped
        let decoded_key = RepositoryKey::from_base64(&encoded).unwrap();
        assert_eq!(key.to_base64(), decoded_key.to_base64());

        // Test KeyringManager can be created
        let _keyring_manager = KeyringManager::new();

        // Test Processor can be created
        let processor = Processor::new_with_context(key, std::path::PathBuf::from("."), "2025-01-01T00:00:00Z".to_string()).unwrap();

        // Test basic processor functionality
        let test_content = "No secrets here";
        let result = processor.process_content(test_content).unwrap();
        assert_eq!(result, test_content);
    }

    #[test]
    fn test_module_exports() {
        // Verify that all expected modules are public
        use crate::config;
        use crate::crypto;
        use crate::keyring_manager;
        use crate::processor;

        // These imports should compile if modules are properly exported
        let keypair = crypto::KeyPair::generate().unwrap();
        let _config_module = config::Config::new("testuser", &keypair.public_key()).unwrap();
        let _crypto_key = crypto::RepositoryKey::new();
        let _keyring = keyring_manager::KeyringManager::new();
        let key = crypto::RepositoryKey::new();
        let _processor = processor::Processor::new_with_context(key, std::path::PathBuf::from("."), "2025-01-01T00:00:00Z".to_string()).unwrap();
    }

    #[test]
    fn test_re_exports_accessibility() {
        // Test that re-exported items can be used without module qualifiers
        let keypair = KeyPair::generate().unwrap();
        let config = Config::new("testuser", &keypair.public_key()).unwrap();
        let key = RepositoryKey::new();
        let keyring_manager = KeyringManager::new();
        let processor = Processor::new_with_context(key, std::path::PathBuf::from("."), "2025-01-01T00:00:00Z".to_string()).unwrap();

        // Verify these work as expected
        assert!(config.users.contains_key("testuser"));
        assert!(keyring_manager.list_users().is_ok());
        assert!(processor.process_content("test").is_ok());
    }

    #[test]
    fn test_load_key_functions() {
        // Test that load_key functions are properly exported
        // Note: These functions check for .sss.toml in current directory
        // In the project root, this file exists, so load_key may succeed.
        // The important thing is that the functions compile and are callable.

        let result = load_key();
        // Could succeed (if .sss.toml exists) or fail (if not) - both are valid
        let _is_ok = result.is_ok();

        let result = load_key_for_user("test_user");
        // Could succeed (if .sss.toml exists) or fail (if not) - both are valid
        let _is_ok = result.is_ok();

        // The key test is that these functions exist and can be called
        // Actual success/failure depends on the environment
    }

    #[test]
    fn test_api_consistency() {
        // Test that the API maintains consistency across different usage patterns
        let key1 = RepositoryKey::new();
        let key2 = RepositoryKey::from_base64(&key1.to_base64()).unwrap();

        let processor1 = Processor::new_with_context(key1, std::path::PathBuf::from("."), "2025-01-01T00:00:00Z".to_string()).unwrap();
        let processor2 = Processor::new_with_context(key2, std::path::PathBuf::from("."), "2025-01-01T00:00:00Z".to_string()).unwrap();

        let test_text = "Test ⊕{secret} content";
        let encrypted1 = processor1.encrypt_content(test_text).unwrap();
        let encrypted2 = processor2.encrypt_content(test_text).unwrap();

        // With deterministic nonces and same context, same secrets should produce SAME ciphertext
        assert_eq!(encrypted1, encrypted2);

        // But both should decrypt back to the same plaintext with either processor
        let decrypted1_1 = processor1.decrypt_content(&encrypted1).unwrap();
        let decrypted1_2 = processor2.decrypt_content(&encrypted1).unwrap();
        let decrypted2_1 = processor1.decrypt_content(&encrypted2).unwrap();
        let decrypted2_2 = processor2.decrypt_content(&encrypted2).unwrap();

        assert_eq!(decrypted1_1, test_text);
        assert_eq!(decrypted1_2, test_text);
        assert_eq!(decrypted2_1, test_text);
        assert_eq!(decrypted2_2, test_text);
    }
}
