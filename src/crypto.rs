use anyhow::{anyhow, Result};
use zeroize::{Zeroize, ZeroizeOnDrop};

// libsodium bindings
use libsodium_sys as sodium;

// Symmetric encryption constants (for repository data)
const SYMMETRIC_KEY_SIZE: usize = sodium::crypto_secretbox_xchacha20poly1305_KEYBYTES as usize;
const SYMMETRIC_NONCE_SIZE: usize = sodium::crypto_secretbox_xchacha20poly1305_NONCEBYTES as usize;
const SYMMETRIC_MAC_SIZE: usize = sodium::crypto_secretbox_xchacha20poly1305_MACBYTES as usize;

// Asymmetric encryption constants (for key wrapping)
const PUBLIC_KEY_SIZE: usize = sodium::crypto_box_PUBLICKEYBYTES as usize;
const SECRET_KEY_SIZE: usize = sodium::crypto_box_SECRETKEYBYTES as usize;
const SEALED_BOX_OVERHEAD: usize = sodium::crypto_box_SEALBYTES as usize;

// BLAKE2b constants (for deterministic nonce derivation)
const BLAKE2B_PERSONALBYTES: usize = sodium::crypto_generichash_blake2b_PERSONALBYTES as usize;

// Ensure libsodium is initialised
fn ensure_sodium_init() {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| unsafe {
        if sodium::sodium_init() < 0 {
            panic!("Failed to initialise libsodium");
        }
    });
}

/// Validate and decode base64 string with common checks
fn validate_and_decode_base64(
    encoded: &str,
    expected_len: usize,
    key_type: &str,
) -> Result<Vec<u8>> {
    use base64::prelude::*;

    if encoded.len() > crate::constants::MAX_BASE64_KEY_LENGTH {
        return Err(anyhow!(
            "Base64 encoded {} too long: {} characters (max: {})",
            key_type,
            encoded.len(),
            crate::constants::MAX_BASE64_KEY_LENGTH
        ));
    }

    if !encoded
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
    {
        return Err(anyhow!("Invalid characters in Base64 encoded {}", key_type));
    }

    let decoded = BASE64_STANDARD
        .decode(encoded)
        .map_err(|e| anyhow!("Failed to decode base64 {}: {}", key_type, e))?;

    if decoded.len() != expected_len {
        return Err(anyhow!(
            "Invalid {} length: expected {}, got {}",
            key_type,
            expected_len,
            decoded.len()
        ));
    }

    Ok(decoded)
}

/// Symmetric key for repository encryption
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct RepositoryKey([u8; SYMMETRIC_KEY_SIZE]);

impl Default for RepositoryKey {
    fn default() -> Self {
        Self::new()
    }
}

impl RepositoryKey {
    pub fn new() -> Self {
        ensure_sodium_init();
        let mut key = [0u8; SYMMETRIC_KEY_SIZE];
        unsafe {
            sodium::randombytes_buf(
                key.as_mut_ptr() as *mut std::ffi::c_void,
                SYMMETRIC_KEY_SIZE,
            );
        }
        Self(key)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != SYMMETRIC_KEY_SIZE {
            return Err(anyhow!(
                "Invalid key size: {} bytes (expected: {})",
                bytes.len(),
                SYMMETRIC_KEY_SIZE
            ));
        }
        let mut key = [0u8; SYMMETRIC_KEY_SIZE];
        key.copy_from_slice(bytes);
        Ok(Self(key))
    }

    pub fn from_base64(encoded: &str) -> Result<Self> {
        let decoded = validate_and_decode_base64(encoded, SYMMETRIC_KEY_SIZE, "key")?;
        let mut key_bytes = [0u8; SYMMETRIC_KEY_SIZE];
        key_bytes.copy_from_slice(&decoded);
        Ok(Self(key_bytes))
    }

    pub fn to_base64(&self) -> String {
        use base64::prelude::*;
        BASE64_STANDARD.encode(self.0)
    }

    /// Generate a new repository key for rotation
    /// Returns a tuple of (old_key, new_key) where old_key is a copy of self
    pub fn rotate(&self) -> (RepositoryKey, RepositoryKey) {
        let old_key = RepositoryKey(self.0);
        let new_key = RepositoryKey::new();
        (old_key, new_key)
    }
}

/// User's public key (for sealing repository keys)
#[derive(Debug, Clone)]
pub struct PublicKey([u8; PUBLIC_KEY_SIZE]);

impl PublicKey {
    pub fn from_base64(encoded: &str) -> Result<Self> {
        let decoded = validate_and_decode_base64(encoded, PUBLIC_KEY_SIZE, "public key")?;
        let mut key_bytes = [0u8; PUBLIC_KEY_SIZE];
        key_bytes.copy_from_slice(&decoded);
        Ok(Self(key_bytes))
    }

    pub fn to_base64(&self) -> String {
        use base64::prelude::*;
        BASE64_STANDARD.encode(self.0)
    }
}

/// User's secret key (for opening sealed repository keys)
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretKey([u8; SECRET_KEY_SIZE]);

impl SecretKey {
    pub fn from_base64(encoded: &str) -> Result<Self> {
        use base64::prelude::*;

        let decoded = BASE64_STANDARD
            .decode(encoded)
            .map_err(|e| anyhow!("Failed to decode base64 secret key: {}", e))?;

        if decoded.len() != SECRET_KEY_SIZE {
            return Err(anyhow!(
                "Invalid secret key length: expected {}, got {}",
                SECRET_KEY_SIZE,
                decoded.len()
            ));
        }

        let mut key_bytes = [0u8; SECRET_KEY_SIZE];
        key_bytes.copy_from_slice(&decoded);
        Ok(Self(key_bytes))
    }

    pub fn to_base64(&self) -> String {
        use base64::prelude::*;
        BASE64_STANDARD.encode(self.0)
    }
}

/// User's keypair (public + secret)
#[derive(Debug)]
pub struct KeyPair {
    pub public_key: PublicKey,
    pub secret_key: SecretKey,
}

impl KeyPair {
    pub fn generate() -> Result<Self> {
        ensure_sodium_init();

        let mut public_key = [0u8; PUBLIC_KEY_SIZE];
        let mut secret_key = [0u8; SECRET_KEY_SIZE];

        unsafe {
            let ret = sodium::crypto_box_keypair(public_key.as_mut_ptr(), secret_key.as_mut_ptr());
            if ret != 0 {
                return Err(anyhow!("Failed to generate keypair"));
            }
        }

        Ok(Self {
            public_key: PublicKey(public_key),
            secret_key: SecretKey(secret_key),
        })
    }

    pub fn from_seed(seed: &[u8]) -> Result<Self> {
        ensure_sodium_init();

        if seed.len() != sodium::crypto_box_SEEDBYTES as usize {
            return Err(anyhow!(
                "Invalid seed length: expected {}, got {}",
                sodium::crypto_box_SEEDBYTES,
                seed.len()
            ));
        }

        let mut public_key = [0u8; PUBLIC_KEY_SIZE];
        let mut secret_key = [0u8; SECRET_KEY_SIZE];

        unsafe {
            let ret = sodium::crypto_box_seed_keypair(
                public_key.as_mut_ptr(),
                secret_key.as_mut_ptr(),
                seed.as_ptr(),
            );
            if ret != 0 {
                return Err(anyhow!("Failed to generate keypair from seed"));
            }
        }

        Ok(Self {
            public_key: PublicKey(public_key),
            secret_key: SecretKey(secret_key),
        })
    }
}

// Legacy Key type for backwards compatibility
// Constants for backward compatibility in tests
#[cfg(test)]
const KEY_SIZE: usize = SYMMETRIC_KEY_SIZE;
#[cfg(test)]
const NONCE_SIZE: usize = SYMMETRIC_NONCE_SIZE;

pub type Key = RepositoryKey;

/// Seal a repository key for a user (using crypto_box_seal)
pub fn seal_repository_key(
    repo_key: &RepositoryKey,
    user_public_key: &PublicKey,
) -> Result<String> {
    ensure_sodium_init();
    use base64::prelude::*;

    let repo_key_bytes = repo_key.to_base64().into_bytes();
    let mut sealed = vec![0u8; repo_key_bytes.len() + SEALED_BOX_OVERHEAD];

    unsafe {
        let ret = sodium::crypto_box_seal(
            sealed.as_mut_ptr(),
            repo_key_bytes.as_ptr(),
            repo_key_bytes.len() as u64,
            user_public_key.0.as_ptr(),
        );
        if ret != 0 {
            return Err(anyhow!("Failed to seal repository key"));
        }
    }

    Ok(BASE64_STANDARD.encode(sealed))
}

/// Open a sealed repository key (using crypto_box_seal_open)
pub fn open_repository_key(sealed_key: &str, user_keypair: &KeyPair) -> Result<RepositoryKey> {
    ensure_sodium_init();
    use base64::prelude::*;

    let sealed_bytes = BASE64_STANDARD
        .decode(sealed_key)
        .map_err(|e| anyhow!("Failed to decode sealed key: {}", e))?;

    if sealed_bytes.len() < SEALED_BOX_OVERHEAD {
        return Err(anyhow!("Sealed key too short"));
    }

    let mut opened = vec![0u8; sealed_bytes.len() - SEALED_BOX_OVERHEAD];

    unsafe {
        let ret = sodium::crypto_box_seal_open(
            opened.as_mut_ptr(),
            sealed_bytes.as_ptr(),
            sealed_bytes.len() as u64,
            user_keypair.public_key.0.as_ptr(),
            user_keypair.secret_key.0.as_ptr(),
        );
        if ret != 0 {
            return Err(anyhow!("Failed to open sealed repository key"));
        }
    }

    let repo_key_b64 =
        String::from_utf8(opened).map_err(|e| anyhow!("Invalid UTF-8 in opened key: {}", e))?;

    RepositoryKey::from_base64(&repo_key_b64)
}

/// Derive a deterministic nonce using BLAKE2b
///
/// The nonce is derived from:
/// - Project creation timestamp (ensures per-project uniqueness)
/// - File path relative to project root (ensures per-file uniqueness)
/// - Plaintext content (ensures different secrets get different nonces)
/// - Project key (used as BLAKE2b key parameter for additional security)
///
/// This ensures:
/// - Same secret in same file → same nonce → same ciphertext (deterministic, clean git diffs)
/// - Different secrets → different nonces → no plaintext disclosure
/// - Different files → different nonces (file path in derivation)
/// - Different projects → different nonces (unique timestamps)
fn derive_nonce(
    project_timestamp: &str,
    file_path: &str,
    plaintext: &[u8],
    key: &Key,
) -> Result<[u8; SYMMETRIC_NONCE_SIZE]> {
    ensure_sodium_init();

    // Personal parameter for domain separation
    let personal = b"sss_autononce_v1";
    if personal.len() > BLAKE2B_PERSONALBYTES {
        return Err(anyhow!("Personal parameter too long"));
    }
    let mut personal_padded = [0u8; BLAKE2B_PERSONALBYTES];
    personal_padded[..personal.len()].copy_from_slice(personal);

    // Concatenate inputs: timestamp || filepath || plaintext
    let mut input = Vec::with_capacity(
        project_timestamp.len() + 1 + file_path.len() + 1 + plaintext.len(),
    );
    input.extend_from_slice(project_timestamp.as_bytes());
    input.push(0); // Null separator
    input.extend_from_slice(file_path.as_bytes());
    input.push(0); // Null separator
    input.extend_from_slice(plaintext);

    let mut nonce = [0u8; SYMMETRIC_NONCE_SIZE];

    unsafe {
        let ret = sodium::crypto_generichash_blake2b_salt_personal(
            nonce.as_mut_ptr(),                      // output
            SYMMETRIC_NONCE_SIZE,                    // output length (24 bytes)
            input.as_ptr(),                          // input data
            input.len() as u64,                      // input length
            key.0.as_ptr(),                          // key (project key)
            key.0.len(),                             // key length
            std::ptr::null(),                        // salt (unused)
            personal_padded.as_ptr(),                // personal parameter
        );

        if ret != 0 {
            return Err(anyhow!("BLAKE2b nonce derivation failed"));
        }
    }

    Ok(nonce)
}

/// Internal encrypt function with random nonce (for key encryption, not file secrets)
/// This is pub(crate) so it can be used by keystore and other internal modules
pub(crate) fn encrypt_internal(plaintext: &[u8], key: &Key) -> Result<Vec<u8>> {
    ensure_sodium_init();

    // Generate cryptographically secure random nonce (192 bits)
    let mut nonce = [0u8; SYMMETRIC_NONCE_SIZE];
    unsafe {
        sodium::randombytes_buf(
            nonce.as_mut_ptr() as *mut std::ffi::c_void,
            SYMMETRIC_NONCE_SIZE,
        );
    }

    // Allocate space for nonce + ciphertext + MAC
    let mut result = vec![0u8; SYMMETRIC_NONCE_SIZE + plaintext.len() + SYMMETRIC_MAC_SIZE];

    // Store nonce at beginning
    result[0..SYMMETRIC_NONCE_SIZE].copy_from_slice(&nonce);

    unsafe {
        let ret = sodium::crypto_secretbox_xchacha20poly1305_easy(
            result.as_mut_ptr().add(SYMMETRIC_NONCE_SIZE), // ciphertext output (after nonce)
            plaintext.as_ptr(),                            // plaintext input
            plaintext.len() as u64,                        // plaintext length
            nonce.as_ptr(),                                // nonce
            key.0.as_ptr(),                                // key
        );

        if ret != 0 {
            return Err(anyhow!("Encryption failed"));
        }
    }

    Ok(result)
}

/// Encrypt plaintext with deterministic nonce derived from context
///
/// The nonce is deterministically derived from project timestamp, file path, and plaintext.
/// This ensures:
/// - Same secret in same file → same ciphertext (clean git diffs)
/// - Different secrets → different ciphertexts (no plaintext disclosure)
pub fn encrypt(
    plaintext: &[u8],
    key: &Key,
    project_timestamp: &str,
    file_path: &str,
) -> Result<Vec<u8>> {
    ensure_sodium_init();

    // Derive deterministic nonce from context
    let nonce = derive_nonce(project_timestamp, file_path, plaintext, key)?;

    // Allocate space for nonce + ciphertext + MAC
    let mut result = vec![0u8; SYMMETRIC_NONCE_SIZE + plaintext.len() + SYMMETRIC_MAC_SIZE];

    // Store nonce at beginning
    result[0..SYMMETRIC_NONCE_SIZE].copy_from_slice(&nonce);

    unsafe {
        let ret = sodium::crypto_secretbox_xchacha20poly1305_easy(
            result.as_mut_ptr().add(SYMMETRIC_NONCE_SIZE), // ciphertext output (after nonce)
            plaintext.as_ptr(),                            // plaintext input
            plaintext.len() as u64,                        // plaintext length
            nonce.as_ptr(),                                // nonce
            key.0.as_ptr(),                                // key
        );

        if ret != 0 {
            return Err(anyhow!("Encryption failed"));
        }
    }

    Ok(result)
}

pub fn decrypt(ciphertext_with_nonce: &[u8], key: &Key) -> Result<Vec<u8>> {
    ensure_sodium_init();

    if ciphertext_with_nonce.len() < SYMMETRIC_NONCE_SIZE + SYMMETRIC_MAC_SIZE {
        return Err(anyhow!("Ciphertext too short"));
    }

    // Extract nonce from beginning
    let nonce = &ciphertext_with_nonce[0..SYMMETRIC_NONCE_SIZE];
    let ciphertext = &ciphertext_with_nonce[SYMMETRIC_NONCE_SIZE..];

    // Allocate space for plaintext (ciphertext length minus MAC)
    let mut plaintext = vec![0u8; ciphertext.len() - SYMMETRIC_MAC_SIZE];

    unsafe {
        let ret = sodium::crypto_secretbox_xchacha20poly1305_open_easy(
            plaintext.as_mut_ptr(),  // plaintext output
            ciphertext.as_ptr(),     // ciphertext input
            ciphertext.len() as u64, // ciphertext length
            nonce.as_ptr(),          // nonce
            key.0.as_ptr(),          // key
        );

        if ret != 0 {
            return Err(anyhow!("Failed to decrypt: invalid ciphertext or key"));
        }
    }

    Ok(plaintext)
}

/// Encrypt to base64 with random nonce (for key encryption, internal use)
pub fn encrypt_to_base64(plaintext: &str, key: &Key) -> Result<String> {
    use base64::prelude::*;

    // Validate input size to prevent DoS (max 10KB plaintext)
    if plaintext.len() > crate::constants::MAX_MARKER_CONTENT_SIZE {
        return Err(anyhow!(
            "Plaintext too long: {} bytes (max: {})",
            plaintext.len(),
            crate::constants::MAX_MARKER_CONTENT_SIZE
        ));
    }

    let encrypted = encrypt_internal(plaintext.as_bytes(), key)?;
    Ok(BASE64_STANDARD.encode(&encrypted))
}

/// Encrypt to base64 with deterministic nonce (for file secrets, clean git diffs)
pub fn encrypt_to_base64_deterministic(
    plaintext: &str,
    key: &Key,
    project_timestamp: &str,
    file_path: &str,
) -> Result<String> {
    use base64::prelude::*;

    // Validate input size to prevent DoS (max 10KB plaintext)
    if plaintext.len() > crate::constants::MAX_MARKER_CONTENT_SIZE {
        return Err(anyhow!(
            "Plaintext too long: {} bytes (max: {})",
            plaintext.len(),
            crate::constants::MAX_MARKER_CONTENT_SIZE
        ));
    }

    let encrypted = encrypt(plaintext.as_bytes(), key, project_timestamp, file_path)?;
    Ok(BASE64_STANDARD.encode(&encrypted))
}

pub fn decrypt_from_base64(encoded_ciphertext: &str, key: &Key) -> Result<String> {
    use base64::prelude::*;

    // Validate input size to prevent DoS (max ~14KB encrypted gives ~19KB Base64)
    if encoded_ciphertext.len() > crate::constants::MAX_BASE64_CIPHERTEXT_LENGTH {
        return Err(anyhow!(
            "Base64 encoded ciphertext too long: {} characters (max: {})",
            encoded_ciphertext.len(),
            crate::constants::MAX_BASE64_CIPHERTEXT_LENGTH
        ));
    }

    // Validate Base64 character set (Base64 uses A-Z, a-z, 0-9, +, /, =)
    if !encoded_ciphertext
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
    {
        return Err(anyhow!("Invalid characters in Base64 encoded ciphertext"));
    }

    let ciphertext = BASE64_STANDARD
        .decode(encoded_ciphertext)
        .map_err(|e| anyhow!("Failed to decode base64 ciphertext: {}", e))?;

    let plaintext_bytes = decrypt(&ciphertext, key)?;
    String::from_utf8(plaintext_bytes)
        .map_err(|e| anyhow!("Decrypted data is not valid UTF-8: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deterministic_nonce_generation() {
        let key = Key::new();
        let timestamp = "2025-01-01T00:00:00Z";
        let filepath = "./config.yml";
        let plaintext = b"secret123";

        // Generate nonce twice with same inputs
        let nonce1 = derive_nonce(timestamp, filepath, plaintext, &key).unwrap();
        let nonce2 = derive_nonce(timestamp, filepath, plaintext, &key).unwrap();

        // Should be identical (deterministic)
        assert_eq!(nonce1, nonce2);
    }

    #[test]
    fn test_deterministic_nonce_different_plaintexts() {
        let key = Key::new();
        let timestamp = "2025-01-01T00:00:00Z";
        let filepath = "./config.yml";

        let nonce1 = derive_nonce(timestamp, filepath, b"secret1", &key).unwrap();
        let nonce2 = derive_nonce(timestamp, filepath, b"secret2", &key).unwrap();

        // Different plaintexts should produce different nonces
        assert_ne!(nonce1, nonce2);
    }

    #[test]
    fn test_deterministic_nonce_different_files() {
        let key = Key::new();
        let timestamp = "2025-01-01T00:00:00Z";
        let plaintext = b"secret";

        let nonce1 = derive_nonce(timestamp, "./file1.yml", plaintext, &key).unwrap();
        let nonce2 = derive_nonce(timestamp, "./file2.yml", plaintext, &key).unwrap();

        // Different files should produce different nonces
        assert_ne!(nonce1, nonce2);
    }

    #[test]
    fn test_deterministic_nonce_different_timestamps() {
        let key = Key::new();
        let filepath = "./config.yml";
        let plaintext = b"secret";

        let nonce1 = derive_nonce("2025-01-01T00:00:00Z", filepath, plaintext, &key).unwrap();
        let nonce2 = derive_nonce("2025-01-02T00:00:00Z", filepath, plaintext, &key).unwrap();

        // Different timestamps should produce different nonces
        assert_ne!(nonce1, nonce2);
    }

    #[test]
    fn test_deterministic_encryption() {
        let key = Key::new();
        let timestamp = "2025-01-01T00:00:00Z";
        let filepath = "./config.yml";
        let plaintext = "mysecret";

        // Encrypt same plaintext twice
        let encrypted1 = encrypt_to_base64_deterministic(plaintext, &key, timestamp, filepath).unwrap();
        let encrypted2 = encrypt_to_base64_deterministic(plaintext, &key, timestamp, filepath).unwrap();

        // Should produce identical ciphertext (deterministic)
        assert_eq!(encrypted1, encrypted2);

        // But different plaintexts should produce different ciphertexts
        let encrypted3 = encrypt_to_base64_deterministic("differentsecret", &key, timestamp, filepath).unwrap();
        assert_ne!(encrypted1, encrypted3);
    }

    #[test]
    fn test_key_roundtrip() {
        let key = Key::new();
        let encoded = key.to_base64();
        let decoded = Key::from_base64(&encoded).unwrap();
        assert_eq!(key.0, decoded.0);
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = Key::new();
        let timestamp = "2025-01-01T00:00:00Z";
        let filepath = "./test.yml";
        let plaintext = "Hello, world!";

        let encrypted = encrypt_to_base64_deterministic(plaintext, &key, timestamp, filepath).unwrap();
        let decrypted = decrypt_from_base64(&encrypted, &key).unwrap();

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_deterministic_behavior_same_inputs() {
        let key = Key::new();
        let timestamp = "2025-01-01T00:00:00Z";
        let filepath = "./test.yml";
        let plaintext = "repeated message";

        // Same inputs should produce same ciphertext (deterministic)
        let encrypted1 = encrypt_to_base64_deterministic(plaintext, &key, timestamp, filepath).unwrap();
        let encrypted2 = encrypt_to_base64_deterministic(plaintext, &key, timestamp, filepath).unwrap();

        assert_eq!(encrypted1, encrypted2);

        let decrypted1 = decrypt_from_base64(&encrypted1, &key).unwrap();
        let decrypted2 = decrypt_from_base64(&encrypted2, &key).unwrap();

        assert_eq!(decrypted1, plaintext);
        assert_eq!(decrypted2, plaintext);
    }

    #[test]
    fn test_invalid_ciphertext() {
        let key = Key::new();
        let result = decrypt_from_base64("invalid", &key);
        assert!(result.is_err());
    }

    #[test]
    fn test_oversized_key_input() {
        // Test that overly long Base64 key input is rejected
        let long_key = "A".repeat(200);
        let result = Key::from_base64(&long_key);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too long"));
    }

    #[test]
    fn test_invalid_key_characters() {
        // Test that invalid Base64 characters are rejected
        let invalid_key = "ABC{}DEF"; // braces are not valid Base64
        let result = Key::from_base64(invalid_key);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Invalid characters"));
    }

    #[test]
    fn test_oversized_plaintext() {
        let key = Key::new();
        // MAX_MARKER_CONTENT_SIZE is 100MB, use 101MB to exceed limit
        let large_plaintext = "A".repeat(101 * 1024 * 1024);
        let result = encrypt_to_base64_deterministic(&large_plaintext, &key, "2025-01-01T00:00:00Z", "./test.yml");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too long"));
    }

    #[test]
    fn test_oversized_ciphertext() {
        let key = Key::new();
        // MAX_BASE64_CIPHERTEXT_LENGTH is 140M chars, use 141M to exceed limit
        let large_ciphertext = "A".repeat(141_000_000);
        let result = decrypt_from_base64(&large_ciphertext, &key);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too long"));
    }

    #[test]
    fn test_invalid_ciphertext_characters() {
        let key = Key::new();
        let invalid_ciphertext = "ABC{}DEF"; // braces are not valid Base64
        let result = decrypt_from_base64(invalid_ciphertext, &key);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Invalid characters"));
    }

    #[test]
    fn test_libsodium_constants() {
        // Verify we're using the correct libsodium constants
        assert_eq!(KEY_SIZE, 32);
        assert_eq!(NONCE_SIZE, 24);
        assert_eq!(
            KEY_SIZE,
            sodium::crypto_secretbox_xchacha20poly1305_KEYBYTES as usize
        );
        assert_eq!(
            NONCE_SIZE,
            sodium::crypto_secretbox_xchacha20poly1305_NONCEBYTES as usize
        );

        // Verify MAC size is correct
        assert_eq!(sodium::crypto_secretbox_xchacha20poly1305_MACBYTES, 16);
    }

    #[test]
    fn test_libsodium_initialization() {
        // Test that libsodium initialises correctly
        ensure_sodium_init(); // Should not panic

        // Test multiple calls are safe
        ensure_sodium_init();
        ensure_sodium_init();
    }

    #[test]
    fn test_libsodium_wire_format_compatibility() {
        let key = Key::new();
        let plaintext = "test message for libsodium compatibility";

        // Encrypt with our implementation
        let encrypted = encrypt(plaintext.as_bytes(), &key, "2025-01-01T00:00:00Z", "./test.yml").unwrap();

        // Verify structure: nonce (24 bytes) + ciphertext + MAC (16 bytes)
        assert!(encrypted.len() >= NONCE_SIZE + plaintext.len() + 16);
        assert_eq!(encrypted.len(), NONCE_SIZE + plaintext.len() + 16);

        // Extract nonce and verify it's 24 bytes
        let nonce = &encrypted[0..NONCE_SIZE];
        assert_eq!(nonce.len(), 24);

        // Decrypt and verify roundtrip
        let decrypted = decrypt(&encrypted, &key).unwrap();
        assert_eq!(decrypted, plaintext.as_bytes());
    }

    #[test]
    fn test_deterministic_same_ciphertexts() {
        let key = Key::new();
        let plaintext = "same message";

        // Encrypt the same message multiple times with same context
        let encrypted1 = encrypt(plaintext.as_bytes(), &key, "2025-01-01T00:00:00Z", "./test.yml").unwrap();
        let encrypted2 = encrypt(plaintext.as_bytes(), &key, "2025-01-01T00:00:00Z", "./test.yml").unwrap();
        let encrypted3 = encrypt(plaintext.as_bytes(), &key, "2025-01-01T00:00:00Z", "./test.yml").unwrap();

        // With deterministic nonces, same inputs should produce SAME ciphertext
        assert_eq!(encrypted1, encrypted2);
        assert_eq!(encrypted2, encrypted3);
        assert_eq!(encrypted1, encrypted3);

        // All should decrypt to the same plaintext
        assert_eq!(decrypt(&encrypted1, &key).unwrap(), plaintext.as_bytes());
        assert_eq!(decrypt(&encrypted2, &key).unwrap(), plaintext.as_bytes());
        assert_eq!(decrypt(&encrypted3, &key).unwrap(), plaintext.as_bytes());
    }

    #[test]
    fn test_libsodium_stress_test() {
        let key = Key::new();

        // Test various message sizes
        for size in [0, 1, 15, 16, 17, 255, 256, 1000] {
            let plaintext = "A".repeat(size);
            let encrypted = encrypt(plaintext.as_bytes(), &key, "2025-01-01T00:00:00Z", "./test.yml").unwrap();
            let decrypted = decrypt(&encrypted, &key).unwrap();
            assert_eq!(decrypted, plaintext.as_bytes(), "Failed at size {}", size);
        }

        // Test with binary data
        let binary_data = (0..256).map(|i| i as u8).collect::<Vec<u8>>();
        let encrypted = encrypt(&binary_data, &key, "2025-01-01T00:00:00Z", "./test.yml").unwrap();
        let decrypted = decrypt(&encrypted, &key).unwrap();
        assert_eq!(decrypted, binary_data);
    }

    #[test]
    fn test_libsodium_ciphertext_tampering() {
        let key = Key::new();
        let plaintext = "important message";
        let mut encrypted = encrypt(plaintext.as_bytes(), &key, "2025-01-01T00:00:00Z", "./test.yml").unwrap();

        // Tamper with different parts of the ciphertext

        // Tamper with nonce
        let original_byte = encrypted[0];
        encrypted[0] = encrypted[0].wrapping_add(1);
        assert!(decrypt(&encrypted, &key).is_err());
        encrypted[0] = original_byte; // restore

        // Tamper with ciphertext
        let tamper_pos = NONCE_SIZE + 1;
        let original_byte = encrypted[tamper_pos];
        encrypted[tamper_pos] = encrypted[tamper_pos].wrapping_add(1);
        assert!(decrypt(&encrypted, &key).is_err());
        encrypted[tamper_pos] = original_byte; // restore

        // Tamper with MAC
        let mac_pos = encrypted.len() - 1;
        let original_byte = encrypted[mac_pos];
        encrypted[mac_pos] = encrypted[mac_pos].wrapping_add(1);
        assert!(decrypt(&encrypted, &key).is_err());
        encrypted[mac_pos] = original_byte; // restore

        // Should decrypt successfully after restoring
        assert!(decrypt(&encrypted, &key).is_ok());
    }

    #[test]
    fn test_libsodium_empty_message() {
        let key = Key::new();
        let empty_message = b"";

        let encrypted = encrypt(empty_message, &key, "2025-01-01T00:00:00Z", "./test.yml").unwrap();
        // Empty message should still have nonce + MAC
        assert_eq!(encrypted.len(), NONCE_SIZE + 16);

        let decrypted = decrypt(&encrypted, &key).unwrap();
        assert_eq!(decrypted, empty_message);
    }

    #[test]
    fn test_base64_no_braces_security() {
        // Critical security test: ensure Base64 never produces { or } characters
        // that could break our parser
        let key = Key::new();

        // Test with many different inputs to ensure no Base64 output contains braces
        let large_a = "A".repeat(1000);
        let large_braces = "{}".repeat(500);
        let test_cases = vec![
            "test",
            "{}{}{}",
            "brace content",
            &large_a,
            &large_braces,
            "mixed{content}with{braces}",
        ];

        for plaintext in test_cases {
            let encrypted = encrypt_to_base64_deterministic(plaintext, &key, "2025-01-01T00:00:00Z", "./test.yml").unwrap();

            // Critical: Base64 output must never contain { or }
            assert!(
                !encrypted.contains('{'),
                "Base64 output contains '{{': {}",
                encrypted
            );
            assert!(
                !encrypted.contains('}'),
                "Base64 output contains '}}': {}",
                encrypted
            );

            // Verify it still decrypts correctly
            let decrypted = decrypt_from_base64(&encrypted, &key).unwrap();
            assert_eq!(decrypted, plaintext);
        }
    }

    #[test]
    fn test_base64_character_set_security() {
        // Verify Base64 only uses safe characters: A-Z, a-z, 0-9, +, /, =
        let key = Key::new();
        let encrypted = encrypt_to_base64_deterministic("test content", &key, "2025-01-01T00:00:00Z", "./test.yml").unwrap();

        for ch in encrypted.chars() {
            assert!(
                ch.is_ascii_alphanumeric() || ch == '+' || ch == '/' || ch == '=',
                "Base64 output contains unsafe character: '{}'",
                ch
            );
        }
    }

}
