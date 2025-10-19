pub mod agent;
pub mod agent_policy;
pub mod agent_protocol;
pub mod askpass;
pub mod audit_log;
pub mod commands;
pub mod config;
pub mod config_manager;
pub mod constants;
pub mod crypto;
pub mod editor;
pub mod error;
#[cfg(all(any(target_os = "linux", target_os = "macos"), feature = "fuse"))]
pub mod fuse_fs;
#[cfg(all(target_os = "windows", feature = "winfsp"))]
pub mod winfsp_fs;
#[cfg(feature = "ninep")]
pub mod ninep_fs;
pub mod kdf;
pub mod keyring_manager;
pub mod keystore;
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
        let config = Config::new("testuser", &keypair.public_key).unwrap();
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
        let _config_module = config::Config::new("testuser", &keypair.public_key).unwrap();
        let _crypto_key = crypto::RepositoryKey::new();
        let _keyring = keyring_manager::KeyringManager::new();
        let key = crypto::RepositoryKey::new();
        let _processor = processor::Processor::new_with_context(key, std::path::PathBuf::from("."), "2025-01-01T00:00:00Z".to_string()).unwrap();
    }

    #[test]
    fn test_re_exports_accessibility() {
        // Test that re-exported items can be used without module qualifiers
        let keypair = KeyPair::generate().unwrap();
        let config = Config::new("testuser", &keypair.public_key).unwrap();
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
        // These will fail in test environment but should compile
        let result = load_key();
        // We expect this to fail in test environment (no keys set up)
        assert!(result.is_err());

        let result = load_key_for_user("test_user");
        // We expect this to fail in test environment (no keys set up)
        assert!(result.is_err());
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
