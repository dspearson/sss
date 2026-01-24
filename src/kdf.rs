#![allow(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::cast_possible_wrap, // sodium algorithm constants fit in i32 by libsodium guarantee
)]

use anyhow::{anyhow, Result};
use zeroize::{Zeroize, ZeroizeOnDrop};

// libsodium bindings for Argon2id
use libsodium_sys as sodium;

const SALT_SIZE: usize = sodium::crypto_pwhash_SALTBYTES as usize;
const KEY_SIZE: usize = 32; // 256-bit key

/// A salt for key derivation
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct Salt([u8; SALT_SIZE]);

impl Salt {
    /// Generate a new cryptographically secure random salt
    #[must_use] 
    pub fn new() -> Self {
        ensure_sodium_init();
        let mut salt = [0u8; SALT_SIZE];
        unsafe {
            sodium::randombytes_buf(salt.as_mut_ptr().cast::<std::ffi::c_void>(), SALT_SIZE);
        }
        Self(salt)
    }

    /// Create salt from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != SALT_SIZE {
            return Err(anyhow!(
                "Invalid salt size: {} bytes (expected {})",
                bytes.len(),
                SALT_SIZE
            ));
        }
        let mut salt = [0u8; SALT_SIZE];
        salt.copy_from_slice(bytes);
        Ok(Self(salt))
    }

    /// Get salt as bytes
    #[must_use] 
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Convert to base64 for storage
    #[must_use] 
    pub fn to_base64(&self) -> String {
        use base64::prelude::*;
        BASE64_STANDARD.encode(self.0)
    }

    /// Create from base64
    pub fn from_base64(encoded: &str) -> Result<Self> {
        use base64::prelude::*;
        let bytes = BASE64_STANDARD
            .decode(encoded)
            .map_err(|e| anyhow!("Invalid base64 salt: {e}"))?;
        Self::from_bytes(&bytes)
    }
}

impl Default for Salt {
    fn default() -> Self {
        Self::new()
    }
}

/// A key derived from a passphrase
#[derive(Debug, Zeroize, ZeroizeOnDrop)]
pub struct DerivedKey([u8; KEY_SIZE]);

impl DerivedKey {
    /// Derive a key from a passphrase and salt using Argon2id with default (sensitive) parameters
    pub fn derive(passphrase: &str, salt: &Salt) -> Result<Self> {
        Self::derive_with_params(passphrase, salt, &KdfParams::sensitive())
    }

    /// Derive a key from a passphrase and salt using Argon2id with custom parameters
    pub fn derive_with_params(passphrase: &str, salt: &Salt, params: &KdfParams) -> Result<Self> {
        ensure_sodium_init();

        let mut key = [0u8; KEY_SIZE];

        unsafe {
            let ret = sodium::crypto_pwhash(
                key.as_mut_ptr(),                          // output key
                KEY_SIZE as u64,                           // key length
                passphrase.as_ptr().cast::<libc::c_char>(), // passphrase
                passphrase.len() as u64,                   // passphrase length
                salt.0.as_ptr(),                           // salt
                params.ops_limit,                          // ops limit (from params)
                params.mem_limit,                          // memory limit (from params)
                params.algorithm,                          // algorithm (Argon2id)
            );

            if ret != 0 {
                return Err(anyhow!("Key derivation failed"));
            }
        }

        Ok(Self(key))
    }

    /// Get key as bytes
    #[must_use] 
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Convert to our `RepositoryKey` type for encryption
    #[must_use] 
    pub fn to_encryption_key(&self) -> crate::crypto::RepositoryKey {
        // This is safe because both are 32-byte arrays
        crate::crypto::RepositoryKey::from_bytes(&self.0)
            .expect("DerivedKey should always be valid RepositoryKey")
    }
}

/// Ensure libsodium is initialised
fn ensure_sodium_init() {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| unsafe {
        assert!(sodium::sodium_init() >= 0, "Failed to initialise libsodium");
    });
}

/// Parameters for key derivation
#[derive(Debug, Clone)]
pub struct KdfParams {
    pub ops_limit: u64,
    pub mem_limit: usize,
    pub algorithm: i32,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            ops_limit: u64::from(sodium::crypto_pwhash_OPSLIMIT_INTERACTIVE),
            mem_limit: sodium::crypto_pwhash_MEMLIMIT_INTERACTIVE as usize,
            algorithm: sodium::crypto_pwhash_ALG_ARGON2ID13 as i32,
        }
    }
}

impl KdfParams {
    /// Sensitive parameters (higher security, slower) - Recommended for key protection
    /// - Iterations: ~4
    /// - Memory: 256 MiB
    /// - Time: ~2 seconds on modern CPUs
    #[must_use] 
    pub fn sensitive() -> Self {
        Self {
            ops_limit: u64::from(sodium::crypto_pwhash_OPSLIMIT_SENSITIVE),
            mem_limit: sodium::crypto_pwhash_MEMLIMIT_SENSITIVE as usize,
            algorithm: sodium::crypto_pwhash_ALG_ARGON2ID13 as i32,
        }
    }

    /// Moderate parameters (balanced security and performance)
    /// - Iterations: ~3
    /// - Memory: 128 MiB
    /// - Time: ~1 second on modern CPUs
    #[must_use] 
    pub fn moderate() -> Self {
        Self {
            ops_limit: u64::from(sodium::crypto_pwhash_OPSLIMIT_MODERATE),
            mem_limit: sodium::crypto_pwhash_MEMLIMIT_MODERATE as usize,
            algorithm: sodium::crypto_pwhash_ALG_ARGON2ID13 as i32,
        }
    }

    /// Interactive parameters (lowest security, fastest) - Not recommended for production
    /// - Iterations: ~2
    /// - Memory: 64 MiB
    /// - Time: ~0.5 seconds on modern CPUs
    #[must_use] 
    pub fn interactive() -> Self {
        Self::default()
    }

    /// Parse KDF level from string
    pub fn from_level(level: &str) -> Result<Self> {
        match level.to_lowercase().as_str() {
            "sensitive" | "high" => Ok(Self::sensitive()),
            "moderate" | "medium" | "balanced" => Ok(Self::moderate()),
            "interactive" | "low" | "fast" => Ok(Self::interactive()),
            _ => Err(anyhow!(
                "Invalid KDF level '{level}'. Valid options: sensitive, moderate, interactive"
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_salt_generation() {
        let salt1 = Salt::new();
        let salt2 = Salt::new();

        // Salts should be different
        assert_ne!(salt1.as_bytes(), salt2.as_bytes());
        assert_eq!(salt1.as_bytes().len(), SALT_SIZE);
    }

    #[test]
    fn test_salt_base64_roundtrip() {
        let salt = Salt::new();
        let encoded = salt.to_base64();
        let decoded = Salt::from_base64(&encoded).unwrap();

        assert_eq!(salt.as_bytes(), decoded.as_bytes());
    }

    #[test]
    fn test_key_derivation_deterministic() {
        let salt = Salt::new();
        let passphrase = "test password 123";

        let key1 = DerivedKey::derive(passphrase, &salt).unwrap();
        let key2 = DerivedKey::derive(passphrase, &salt).unwrap();

        // Same passphrase + salt should produce same key
        assert_eq!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn test_key_derivation_different_salts() {
        let salt1 = Salt::new();
        let salt2 = Salt::new();
        let passphrase = "test password 123";

        let key1 = DerivedKey::derive(passphrase, &salt1).unwrap();
        let key2 = DerivedKey::derive(passphrase, &salt2).unwrap();

        // Different salts should produce different keys
        assert_ne!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn test_key_derivation_different_passphrases() {
        let salt = Salt::new();

        let key1 = DerivedKey::derive("password1", &salt).unwrap();
        let key2 = DerivedKey::derive("password2", &salt).unwrap();

        // Different passphrases should produce different keys
        assert_ne!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn test_key_size() {
        let salt = Salt::new();
        let key = DerivedKey::derive("test", &salt).unwrap();

        assert_eq!(key.as_bytes().len(), KEY_SIZE);
    }

    #[test]
    fn test_salt_invalid_size() {
        let short_bytes = vec![0u8; SALT_SIZE - 1];
        let long_bytes = vec![0u8; SALT_SIZE + 1];

        assert!(Salt::from_bytes(&short_bytes).is_err());
        assert!(Salt::from_bytes(&long_bytes).is_err());
    }

    #[test]
    fn test_salt_invalid_base64() {
        assert!(Salt::from_base64("invalid base64!!!").is_err());
        assert!(Salt::from_base64("dG9vIHNob3J0").is_err()); // "too short" in base64
    }
}
