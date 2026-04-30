//! sss — Secret String Substitution.
//!
//! Transparent encryption of secrets within files using XChaCha20-Poly1305,
//! with multi-user key management and git integration. Supports two crypto
//! suites: Classic (libsodium `crypto_box_seal`, default) and Hybrid (trelis
//! X448 + sntrup761 + BLAKE3, `feature = "hybrid"`).
//!
//! # Module structure
//!
//! Core pipeline:
//! - [`crypto`] — cryptographic primitives (Classic / Hybrid suites; FFI)
//! - [`kdf`] — Argon2id key derivation
//! - [`keystore`] — local encrypted keystore; Classic + Hybrid keypairs
//! - [`processor`] — marker detection and transformation pipeline
//! - [`scanner`] — project directory scanner with ignore patterns
//! - [`secrets`] — secret extraction / substitution helpers
//! - [`merge`] — content reconciliation between encrypted-on-disk and edited
//! - [`marker_inference`] — placeholder marker resolution
//! - [`secure_memory`] — zeroising memory primitives
//! - [`rate_limiter`] — token-bucket rate limiting (agent path)
//!
//! Configuration / project surface:
//! - [`config`] — `.sss.toml` parsing + load_key family
//! - [`config_manager`] — user-settings layer (orthogonal to `config`)
//! - [`project`] — `ProjectConfig` and project root discovery
//! - [`constants`] — crate-wide constant table
//! - [`toml_helpers`] — TOML serialisation helpers
//! - [`error`] / [`error_helpers`] — error types and conversions
//! - [`validation`] — input validation helpers
//! - [`editor`] — editor invocation helpers
//!
//! Daemon / interactive surface:
//! - [`agent`] — agent client / protocol / policy (directory-module: `client`,
//!   `policy`, `protocol`)
//! - [`askpass`] — askpass dialog plumbing
//! - [`audit_log`] — agent audit logging
//! - [`commands`] — CLI subcommand implementations
//! - [`rotation`] — repository-key rotation
//! - [`keyring_manager`] / [`keyring_support`] — OS keyring integration
//!   (orthogonal: `support` is independently consumed by `keystore` and
//!   `commands::settings`; intentional flat split, see Plan 11-03 SUMMARY)
//!
//! Filesystem surface (platform-gated):
//! - [`fuse`] — FUSE filesystem (Linux/macOS, `feature = "fuse"`); the
//!   directory-module hosts `fs` (top-level `SssFS`), `inode_manager`,
//!   `file_cache`, `virtual_fs`
//! - [`winfsp_fs`] — WinFSP filesystem (Windows, `feature = "winfsp"`)
//! - [`ninep_fs`] — 9P server (`feature = "ninep"`)
//! - [`filesystem_common`] — cross-backend filesystem helpers
//!
//! # Public API
//!
//! The curated public surface is the re-export block below: [`Config`],
//! [`KeyPair`], [`RepositoryKey`], [`SssError`] / [`Result`],
//! [`KeyringManager`], [`Keystore`], [`Processor`], [`ProjectConfig`], plus
//! [`SssNinepFS`] (cfg-gated). Internal items that are only needed
//! crate-internally are `pub(crate)` (visibility tightening tracked in
//! Plan 11-04 / CLEAN-03).
//!
//! # References
//!
//! - `docs/CRYPTOGRAPHY.md` — crypto suite design and primitives
//! - `docs/security-model.md` — trust boundaries and threat model
//! - `.planning/phases/11-code-cleanup/11-03-SUMMARY.md` — module-structure
//!   audit (CLEAN-04, D-14 / D-15 / D-16 / D-17)

pub mod agent;
pub mod askpass;
pub mod audit_log;
pub mod commands;
pub mod config;
pub mod config_manager;
pub mod constants;
pub mod crypto;
pub mod editor;
pub mod error;
pub mod error_helpers;
pub mod filesystem_common;
pub mod toml_helpers;
#[cfg(all(any(target_os = "linux", target_os = "macos"), feature = "fuse"))]
pub mod fuse;
#[cfg(all(target_os = "windows", feature = "winfsp"))]
pub mod winfsp_fs;
#[cfg(feature = "ninep")]
pub mod ninep_fs;
pub mod kdf;
pub mod keyring_manager;
pub mod keyring_support;
pub mod keystore;
pub mod marker_inference;
pub mod merge;
pub mod processor;
pub mod project;
pub mod rate_limiter;
pub mod rotation;
pub mod scanner;
pub mod secrets;
pub mod secure_memory;
pub mod validation;

pub use config::{load_key, load_key_for_user, Config};
pub use crypto::{KeyPair, RepositoryKey};
pub use error::{Result, SssError};
pub use keyring_manager::KeyringManager;
pub use keystore::Keystore;
pub use processor::Processor;
pub use project::ProjectConfig;

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
