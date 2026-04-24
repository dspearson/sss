#![allow(clippy::missing_errors_doc, clippy::items_after_statements)]

use anyhow::{anyhow, Result};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error_helpers;

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
pub(crate) fn ensure_sodium_init() {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| unsafe {
        assert!(sodium::sodium_init() >= 0, "Failed to initialise libsodium");
    });
}

/// Validate and decode base64 string with common checks
fn validate_and_decode_base64(
    encoded: &str,
    expected_len: usize,
    key_type: &str,
) -> Result<Vec<u8>> {


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
        return Err(anyhow!("Invalid characters in Base64 encoded {key_type}"));
    }

    let decoded = error_helpers::decode_base64(encoded, key_type)?;

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
    #[must_use]
    pub fn new() -> Self {
        ensure_sodium_init();
        let mut key = [0u8; SYMMETRIC_KEY_SIZE];
        unsafe {
            sodium::randombytes_buf(
                key.as_mut_ptr().cast::<std::ffi::c_void>(),
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

    /// Direct-copy 32-byte array accessor. Used by the hybrid suite's AEAD
    /// seal path (which wants the raw key bytes as the plaintext) without
    /// going through the `to_base64` allocation.
    #[cfg(feature = "hybrid")]
    #[must_use]
    pub(crate) fn to_bytes(&self) -> [u8; SYMMETRIC_KEY_SIZE] {
        self.0
    }

    pub fn from_base64(encoded: &str) -> Result<Self> {
        let decoded = validate_and_decode_base64(encoded, SYMMETRIC_KEY_SIZE, "key")?;
        let mut key_bytes = [0u8; SYMMETRIC_KEY_SIZE];
        key_bytes.copy_from_slice(&decoded);
        Ok(Self(key_bytes))
    }

    #[must_use]
    pub fn to_base64(&self) -> String {
        use base64::prelude::*;
        BASE64_STANDARD.encode(self.0)
    }

    /// Generate a new repository key for rotation
    /// Returns a tuple of (`old_key`, `new_key`) where `old_key` is a copy of self
    #[must_use]
    pub fn rotate(&self) -> (RepositoryKey, RepositoryKey) {
        let old_key = RepositoryKey(self.0);
        let new_key = RepositoryKey::new();
        (old_key, new_key)
    }
}

/// User's public key (for sealing repository keys).
///
/// Phase 2 widens this from a flat 32-byte newtype to a suite-aware enum.
/// The `Classic` variant is always compiled and carries the legacy 32-byte
/// X25519 payload. The `Hybrid` variant is gated behind the `hybrid` feature
/// and carries the concatenated X448 + sntrup761 wire bytes.
#[derive(Debug, Clone)]
pub enum PublicKey {
    Classic([u8; PUBLIC_KEY_SIZE]),
    #[cfg(feature = "hybrid")]
    Hybrid(crate::crypto::hybrid::HybridPublicKey),
}

impl PublicKey {
    /// Decode a base64 public key. Classic-only path (32-byte payload) —
    /// preserves the pre-Phase-2 API used by external integration tests
    /// and keystore (classic keystore entries are always 32 bytes).
    ///
    /// For suite-aware decoding (that may produce `PublicKey::Hybrid`),
    /// use [`PublicKey::decode_base64_for_suite`] instead.
    pub fn from_base64(encoded: &str) -> Result<Self> {
        let decoded = validate_and_decode_base64(encoded, PUBLIC_KEY_SIZE, "public key")?;
        let mut key_bytes = [0u8; PUBLIC_KEY_SIZE];
        key_bytes.copy_from_slice(&decoded);
        Ok(Self::Classic(key_bytes))
    }

    /// Suite-aware decoder — classic length -> `Classic`, hybrid length -> `Hybrid`.
    ///
    /// The repository `version` field drives this dispatch; see
    /// `ProjectConfig::get_user_public_key` for the production caller. A
    /// `version = "2.0"` config with a 32-byte payload is treated as a
    /// possible downgrade attempt and rejected with an actionable error.
    pub fn decode_base64_for_suite(
        encoded: &str,
        suite: crate::crypto::Suite,
    ) -> Result<Self> {
        match suite {
            crate::crypto::Suite::Classic => Self::from_base64(encoded),
            #[cfg(feature = "hybrid")]
            crate::crypto::Suite::Hybrid => {
                use base64::prelude::*;
                let bytes = BASE64_STANDARD.decode(encoded).map_err(|e| {
                    anyhow!("Failed to decode base64 hybrid public key: {e}")
                })?;
                // Downgrade-attempt guard: a classic-length payload inside a
                // v2.0 config is rejected with an actionable error before
                // the length-checking constructor runs.
                if bytes.len() == PUBLIC_KEY_SIZE {
                    return Err(anyhow!(
                        "hybrid public key decoded to classic length ({} bytes) — \
                         .sss.toml claims version = \"2.0\" but this user entry \
                         looks classic; possible downgrade attempt?",
                        bytes.len()
                    ));
                }
                Ok(Self::Hybrid(
                    crate::crypto::hybrid::HybridPublicKey::from_bytes(&bytes)?,
                ))
            }
            #[cfg(not(feature = "hybrid"))]
            crate::crypto::Suite::Hybrid => Err(anyhow!(
                "hybrid suite requires the `hybrid` feature — rebuild with --features hybrid"
            )),
        }
    }

    /// Base64-encode the wire bytes for this public key. Classic variant
    /// returns exactly the pre-Phase-2 32-byte base64; hybrid variant
    /// returns the concatenated X448||sntrup761 base64.
    #[must_use]
    pub fn to_base64(&self) -> String {
        use base64::prelude::*;
        match self {
            PublicKey::Classic(bytes) => BASE64_STANDARD.encode(bytes),
            #[cfg(feature = "hybrid")]
            PublicKey::Hybrid(h) => BASE64_STANDARD.encode(h.as_bytes()),
        }
    }
}

/// Ergonomic construction — preserves tests that already build a `PublicKey`
/// from a raw 32-byte array.
impl From<[u8; PUBLIC_KEY_SIZE]> for PublicKey {
    fn from(bytes: [u8; PUBLIC_KEY_SIZE]) -> Self {
        PublicKey::Classic(bytes)
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
            .map_err(|e| anyhow!("Failed to decode base64 secret key: {e}"))?;

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

    #[must_use]
    pub fn to_base64(&self) -> String {
        use base64::prelude::*;
        BASE64_STANDARD.encode(self.0)
    }
}

/// Classic X25519 keypair material.
///
/// Renamed from the former `KeyPair` struct body. The field `public_key`
/// refers to the widened `PublicKey` enum; for classic-variant instances
/// it always holds `PublicKey::Classic(..)`. This preserves field-style
/// access (`cpair.public_key`, `cpair.secret_key`) at every internal site
/// that operates on a known-classic keypair.
#[derive(Debug, Clone)]
pub struct ClassicKeyPair {
    pub public_key: PublicKey,
    pub secret_key: SecretKey,
}

impl ClassicKeyPair {
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
            public_key: PublicKey::Classic(public_key),
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
            public_key: PublicKey::Classic(public_key),
            secret_key: SecretKey(secret_key),
        })
    }
}

/// User's keypair (public + secret) — Phase 2 suite-aware enum.
///
/// The `Classic` variant wraps `ClassicKeyPair` (the legacy X25519 material).
/// The `Hybrid` variant is gated behind the `hybrid` feature and wraps a
/// `HybridKeyPair` (X448 + sntrup761 secret material, `ZeroizeOnDrop`).
///
/// The `KeyPair::generate()` constructor remains API-compatible and always
/// returns `KeyPair::Classic(..)`; hybrid keypair construction lands in
/// Phase 3 as part of the keystore dual-suite work.
#[derive(Debug, Clone)]
pub enum KeyPair {
    Classic(ClassicKeyPair),
    #[cfg(feature = "hybrid")]
    Hybrid(crate::crypto::hybrid::HybridKeyPair),
}

impl KeyPair {
    /// Generate a classic X25519 keypair. Alias for
    /// `ClassicKeyPair::generate()` wrapped in `KeyPair::Classic(..)`.
    /// Preserves the pre-Phase-2 `KeyPair::generate()?` API so every
    /// existing call site keeps compiling.
    pub fn generate() -> Result<Self> {
        Ok(Self::Classic(ClassicKeyPair::generate()?))
    }

    /// Generate from a seed (classic only; hybrid equivalent ships in Phase 3).
    pub fn from_seed(seed: &[u8]) -> Result<Self> {
        Ok(Self::Classic(ClassicKeyPair::from_seed(seed)?))
    }

    /// Borrow the contained public key. For classic variants, returns a
    /// reference to the inner `PublicKey::Classic(..)`; for hybrid, the
    /// accessor constructs a fresh `PublicKey::Hybrid(..)` since the
    /// hybrid keypair stores raw bytes rather than a ready `PublicKey`.
    ///
    /// Call sites migrate from field access `kp.public_key` to method
    /// access `kp.public_key()` — field access on an enum is not legal.
    #[must_use]
    pub fn public_key(&self) -> PublicKey {
        match self {
            KeyPair::Classic(cp) => cp.public_key.clone(),
            #[cfg(feature = "hybrid")]
            KeyPair::Hybrid(hp) => PublicKey::Hybrid(hp.public_key()),
        }
    }

    /// Borrow the contained classic secret key. Returns an actionable error
    /// for hybrid variants — the keystore serialisation path in this plan
    /// only handles classic secret material (dual-suite keystore is Phase 3).
    ///
    /// Call sites migrate from field access `kp.secret_key` to method
    /// access `kp.secret_key()`.
    pub fn secret_key(&self) -> Result<&SecretKey> {
        match self {
            KeyPair::Classic(cp) => Ok(&cp.secret_key),
            #[cfg(feature = "hybrid")]
            KeyPair::Hybrid(_) => Err(anyhow!(
                "hybrid keypair has no classic SecretKey — dual-suite keystore support is Phase 3"
            )),
        }
    }
}

// Legacy Key type for backwards compatibility
// Constants for backward compatibility in tests
#[cfg(test)]
const KEY_SIZE: usize = SYMMETRIC_KEY_SIZE;
#[cfg(test)]
const NONCE_SIZE: usize = SYMMETRIC_NONCE_SIZE;

pub type Key = RepositoryKey;

/// Seal a repository key for a user (using `crypto_box_seal`).
///
/// Classic-only path: accepts only `PublicKey::Classic(..)` and returns an
/// actionable error for hybrid variants. Wire format is bit-for-bit
/// identical to pre-Phase-2 output for classic inputs.
#[deprecated(
    since = "2.0.0",
    note = "use `ClassicSuite.seal_repo_key(...)` via the `CryptoSuite` trait. This free function is retained for existing integration tests that assert wire-format compatibility; new code must go through the trait so Phase 2's hybrid suite can plug in without source edits."
)]
pub fn seal_repository_key(
    repo_key: &RepositoryKey,
    user_public_key: &PublicKey,
) -> Result<String> {
    let pk_bytes = match user_public_key {
        PublicKey::Classic(b) => b,
        #[cfg(feature = "hybrid")]
        PublicKey::Hybrid(_) => {
            return Err(anyhow!(
                "classic free function cannot seal for a hybrid public key — use CryptoSuite trait dispatch (ClassicSuite or HybridCryptoSuite) so version routing handles both suites"
            ));
        }
    };

    ensure_sodium_init();
    use base64::prelude::*;

    let repo_key_bytes = repo_key.to_base64().into_bytes();
    let mut sealed = vec![0u8; repo_key_bytes.len() + SEALED_BOX_OVERHEAD];

    unsafe {
        let ret = sodium::crypto_box_seal(
            sealed.as_mut_ptr(),
            repo_key_bytes.as_ptr(),
            repo_key_bytes.len() as u64,
            pk_bytes.as_ptr(),
        );
        if ret != 0 {
            return Err(anyhow!("Failed to seal repository key"));
        }
    }

    Ok(BASE64_STANDARD.encode(sealed))
}

/// Open a sealed repository key (using `crypto_box_seal_open`).
///
/// Classic-only path: accepts only `KeyPair::Classic(..)` and returns an
/// actionable error for hybrid variants.
#[deprecated(
    since = "2.0.0",
    note = "use `ClassicSuite.open_repo_key(...)` via the `CryptoSuite` trait. This free function is retained for existing integration tests that assert wire-format compatibility; new code must go through the trait so Phase 2's hybrid suite can plug in without source edits."
)]
pub fn open_repository_key(sealed_key: &str, user_keypair: &KeyPair) -> Result<RepositoryKey> {
    let classic = match user_keypair {
        KeyPair::Classic(cp) => cp,
        #[cfg(feature = "hybrid")]
        KeyPair::Hybrid(_) => {
            return Err(anyhow!(
                "classic free function cannot open with a hybrid keypair — use CryptoSuite trait dispatch so version routing handles both suites"
            ));
        }
    };
    let pk_bytes = match &classic.public_key {
        PublicKey::Classic(b) => b,
        #[cfg(feature = "hybrid")]
        PublicKey::Hybrid(_) => {
            return Err(anyhow!(
                "classic free function cannot open: ClassicKeyPair held an unexpected PublicKey::Hybrid variant (should be unreachable — report as bug)"
            ));
        }
    };

    ensure_sodium_init();
    use base64::prelude::*;

    let sealed_bytes = BASE64_STANDARD
        .decode(sealed_key)
        .map_err(|e| anyhow!("Failed to decode sealed key: {e}"))?;

    if sealed_bytes.len() < SEALED_BOX_OVERHEAD {
        return Err(anyhow!("Sealed key too short"));
    }

    let mut opened = vec![0u8; sealed_bytes.len() - SEALED_BOX_OVERHEAD];

    unsafe {
        let ret = sodium::crypto_box_seal_open(
            opened.as_mut_ptr(),
            sealed_bytes.as_ptr(),
            sealed_bytes.len() as u64,
            pk_bytes.as_ptr(),
            classic.secret_key.0.as_ptr(),
        );
        if ret != 0 {
            return Err(anyhow!("Failed to open sealed repository key"));
        }
    }

    let repo_key_b64 = error_helpers::utf8_from_bytes(opened, "opened key")?;

    RepositoryKey::from_base64(&repo_key_b64)
}

/// Derive a deterministic nonce using `BLAKE2b`
///
/// The nonce is derived from:
/// - Project creation timestamp (ensures per-project uniqueness)
/// - File path relative to project root (ensures per-file uniqueness)
/// - Plaintext content (ensures different secrets get different nonces)
/// - Project key (used as `BLAKE2b` key parameter for additional security)
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
            nonce.as_mut_ptr().cast::<std::ffi::c_void>(),
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
        .map_err(|e| anyhow!("Failed to decode base64 ciphertext: {e}"))?;

    let plaintext_bytes = decrypt(&ciphertext, key)?;
    String::from_utf8(plaintext_bytes)
        .map_err(|e| anyhow!("Decrypted data is not valid UTF-8: {e}"))
}

// =========================================================================
// ClassicSuite: CryptoSuite impl for the libsodium crypto_box_seal path
// =========================================================================

use crate::crypto::suite::CryptoSuite;

/// Classic suite — libsodium `crypto_box_seal` / `crypto_box_seal_open`.
///
/// Wraps the repository key `K` for a user's X25519 public key using
/// anonymous authenticated public-key encryption. This is the v1.0 default.
#[derive(Debug, Default, Clone, Copy)]
pub struct ClassicSuite;

impl CryptoSuite for ClassicSuite {
    // Delegates to the free function by design; the free function is the
    // canonical byte-for-byte reference for wire compatibility with
    // pre-v2 .sss.toml files. The free function carries `#[deprecated]`
    // to nudge new callers to the trait — but this delegation is the
    // reason that deprecation note exists, so we silence the lint here.
    fn seal_repo_key(
        &self,
        repo_key: &RepositoryKey,
        user_public_key: &PublicKey,
    ) -> Result<String> {
        match user_public_key {
            PublicKey::Classic(_) => {
                // Delegates to the existing free function so byte-for-byte
                // output is guaranteed identical to pre-refactor. The free
                // function stays exported for test compatibility
                // (tests/multi_user_e2e.rs etc.).
                #[allow(deprecated)]
                seal_repository_key(repo_key, user_public_key)
            }
            #[cfg(feature = "hybrid")]
            PublicKey::Hybrid(_) => Err(anyhow!(
                "classic suite cannot seal for a hybrid public key — version mismatch (.sss.toml version = \"2.0\" requires HybridCryptoSuite dispatch; rebuild with --features hybrid and route via suite_for(Suite::Hybrid))"
            )),
        }
    }

    fn open_repo_key(
        &self,
        sealed_key: &str,
        user_keypair: &KeyPair,
    ) -> Result<RepositoryKey> {
        match user_keypair {
            KeyPair::Classic(_) => {
                #[allow(deprecated)]
                open_repository_key(sealed_key, user_keypair)
            }
            #[cfg(feature = "hybrid")]
            KeyPair::Hybrid(_) => Err(anyhow!(
                "classic suite cannot open a hybrid-sealed key — version mismatch (.sss.toml version = \"2.0\" requires HybridCryptoSuite; rebuild with --features hybrid)"
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(deprecated)] // Tests deliberately exercise the deprecated free
                          // seal/open functions to lock in wire-format
                          // compatibility — this is the byte-for-byte anchor.
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

    // =========================================================================
    // Multi-user seal/open tests (CORR-09)
    // =========================================================================

    /// Test: user B can open a repository key sealed by user A's public key,
    /// using user B's own keypair — provided they share the same repository key.
    ///
    /// This models the shared-repository-key distribution pattern: user A seals
    /// the repo key for user B's public key; user B opens it with their secret key.
    #[test]
    fn test_multi_user_seal_and_open_repository_key() {
        // Generate two independent keypairs (user A and user B)
        let keypair_a = KeyPair::generate().unwrap();
        let keypair_b = KeyPair::generate().unwrap();

        // Repository key shared across users
        let repo_key = Key::new();

        // Seal the repository key for user B (using B's public key)
        let sealed_for_b = seal_repository_key(&repo_key, &keypair_b.public_key()).unwrap();

        // User B opens the sealed repository key with their keypair
        let opened_by_b = open_repository_key(&sealed_for_b, &keypair_b).unwrap();

        // Opened key must match original
        assert_eq!(
            repo_key.to_base64(),
            opened_by_b.to_base64(),
            "user B must recover the same repository key"
        );

        // User A cannot open a key sealed for user B (different keypair)
        let open_by_a = open_repository_key(&sealed_for_b, &keypair_a);
        assert!(
            open_by_a.is_err(),
            "user A must not be able to open a repository key sealed for user B"
        );
    }

    /// Test: content sealed by user A (using shared repo key) can be opened by
    /// user B after user B recovers the repository key from the sealed key bundle.
    #[test]
    fn test_multi_user_content_round_trip() {
        use crate::processor::Processor;
        use std::path::PathBuf;

        let keypair_b = KeyPair::generate().unwrap();
        let repo_key = Key::new();

        // Seal the repository key for user B
        let sealed_repo_key = seal_repository_key(&repo_key, &keypair_b.public_key()).unwrap();

        // User A creates content using the shared repo key
        let processor_a = Processor::new_with_context(
            repo_key,
            PathBuf::from("."),
            "2025-06-01T00:00:00Z".to_string(),
        )
        .unwrap();

        let plaintext = "api_key = ⊕{shared_secret_value}\nenv = production\n";
        let sealed_content = processor_a
            .seal_content_with_path(plaintext, std::path::Path::new("config.txt"))
            .unwrap();

        // User B recovers the repository key using their keypair
        let recovered_key = open_repository_key(&sealed_repo_key, &keypair_b).unwrap();

        // User B creates their own processor with the recovered key
        let processor_b = Processor::new_with_context(
            recovered_key,
            PathBuf::from("."),
            "2025-06-01T00:00:00Z".to_string(),
        )
        .unwrap();

        // User B opens the content sealed by user A
        let opened_by_b = processor_b
            .open_content_with_path(&sealed_content, std::path::Path::new("config.txt"))
            .unwrap();

        assert_eq!(
            opened_by_b, plaintext,
            "user B must recover the same plaintext sealed by user A"
        );
    }

    /// Test: repository key sealed for multiple users — each user can independently
    /// open their own copy of the sealed key and decrypt shared content.
    #[test]
    fn test_multi_user_multiple_recipients() {
        let keypair_a = KeyPair::generate().unwrap();
        let keypair_b = KeyPair::generate().unwrap();
        let keypair_c = KeyPair::generate().unwrap();

        let repo_key = Key::new();

        // Seal the repo key once for each user
        let sealed_for_a = seal_repository_key(&repo_key, &keypair_a.public_key()).unwrap();
        let sealed_for_b = seal_repository_key(&repo_key, &keypair_b.public_key()).unwrap();
        let sealed_for_c = seal_repository_key(&repo_key, &keypair_c.public_key()).unwrap();

        // Each user independently recovers the repository key
        let key_a = open_repository_key(&sealed_for_a, &keypair_a).unwrap();
        let key_b = open_repository_key(&sealed_for_b, &keypair_b).unwrap();
        let key_c = open_repository_key(&sealed_for_c, &keypair_c).unwrap();

        // All recovered keys are identical
        assert_eq!(repo_key.to_base64(), key_a.to_base64(), "user A key mismatch");
        assert_eq!(repo_key.to_base64(), key_b.to_base64(), "user B key mismatch");
        assert_eq!(repo_key.to_base64(), key_c.to_base64(), "user C key mismatch");

        // Cross-opens fail (user A's sealed key cannot be opened by user B)
        assert!(
            open_repository_key(&sealed_for_a, &keypair_b).is_err(),
            "user B must not open user A's sealed key"
        );
        assert!(
            open_repository_key(&sealed_for_b, &keypair_c).is_err(),
            "user C must not open user B's sealed key"
        );
    }

}

#[cfg(test)]
mod classic_suite_tests {
    #![allow(deprecated)] // test_classic_suite_seal_free_outputs_round_trip_equivalently
                          // deliberately invokes the deprecated free function
                          // to prove the trait impl round-trips to the same
                          // repo key (byte-identity is impossible because
                          // crypto_box_seal randomises the ephemeral keypair;
                          // the wire-format anchor lives in
                          // config.rs::test_load_via_classic_suite_reads_legacy_free_function_output).
    use super::*;
    use crate::crypto::suite::CryptoSuite;

    #[test]
    fn test_classic_suite_seal_open_round_trips_repo_key() {
        let kp = KeyPair::generate().unwrap();
        let repo_key = RepositoryKey::new();
        let suite = ClassicSuite;
        let sealed = suite.seal_repo_key(&repo_key, &kp.public_key()).unwrap();
        let opened = suite.open_repo_key(&sealed, &kp).unwrap();
        assert_eq!(repo_key.to_base64(), opened.to_base64());
    }

    #[test]
    fn test_classic_suite_wrong_keypair_errors() {
        let kp1 = KeyPair::generate().unwrap();
        let kp2 = KeyPair::generate().unwrap();
        let repo_key = RepositoryKey::new();
        let suite = ClassicSuite;
        let sealed = suite.seal_repo_key(&repo_key, &kp1.public_key()).unwrap();
        assert!(suite.open_repo_key(&sealed, &kp2).is_err());
    }

    #[test]
    fn test_classic_suite_seal_free_outputs_round_trip_equivalently() {
        // Byte-identity is impossible: `crypto_box_seal` randomises the
        // ephemeral keypair on every call, so successive seals of the same
        // inputs will DIFFER. We prove open-equivalence instead: both the
        // trait and the free function produce ciphertexts that open to the
        // same repo key under the recipient's keypair.
        //
        // The true wire-format anchor — that a *prior-format* ciphertext
        // produced by the deprecated free function opens under the trait —
        // lives in
        // config.rs::test_load_via_classic_suite_reads_legacy_free_function_output.
        let kp = KeyPair::generate().unwrap();
        let repo_key = RepositoryKey::new();
        let via_trait = ClassicSuite.seal_repo_key(&repo_key, &kp.public_key()).unwrap();
        let via_free = seal_repository_key(&repo_key, &kp.public_key()).unwrap();
        let opened_trait = ClassicSuite.open_repo_key(&via_trait, &kp).unwrap();
        let opened_free = ClassicSuite.open_repo_key(&via_free, &kp).unwrap();
        assert_eq!(opened_trait.to_base64(), opened_free.to_base64());
        assert_eq!(opened_trait.to_base64(), repo_key.to_base64());
    }

    // =========================================================================
    // Phase 2 Plan 02-02: enum-widening tests
    // =========================================================================

    #[test]
    fn test_public_key_classic_from_base64_returns_classic_variant() {
        let kp = KeyPair::generate().unwrap();
        let pk = kp.public_key();
        let b64 = pk.to_base64();
        let decoded = PublicKey::from_base64(&b64).unwrap();
        match decoded {
            PublicKey::Classic(_) => (),
            #[cfg(feature = "hybrid")]
            PublicKey::Hybrid(_) => {
                panic!("from_base64 must return Classic for a 32-byte payload");
            }
        }
    }

    #[test]
    fn test_keypair_public_key_accessor_returns_classic_variant() {
        let kp = KeyPair::generate().unwrap();
        let pk = kp.public_key();
        match pk {
            PublicKey::Classic(_) => (),
            #[cfg(feature = "hybrid")]
            PublicKey::Hybrid(_) => {
                panic!("KeyPair::generate must produce Classic public key");
            }
        }
    }

    #[test]
    fn test_from_bytes_for_public_key_yields_classic() {
        let bytes = [0u8; PUBLIC_KEY_SIZE];
        let pk: PublicKey = bytes.into();
        match pk {
            PublicKey::Classic(_) => (),
            #[cfg(feature = "hybrid")]
            PublicKey::Hybrid(_) => panic!("From<[u8; 32]> must yield Classic"),
        }
    }

    #[cfg(feature = "hybrid")]
    #[test]
    fn test_classic_suite_rejects_hybrid_public_key() {
        use crate::constants::HYBRID_PUBLIC_KEY_SIZE;
        use crate::crypto::hybrid::HybridPublicKey;
        let repo_key = RepositoryKey::new();
        let hybrid_pk = PublicKey::Hybrid(
            HybridPublicKey::from_bytes_unchecked(vec![0u8; HYBRID_PUBLIC_KEY_SIZE]),
        );
        let err = ClassicSuite.seal_repo_key(&repo_key, &hybrid_pk).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("classic suite cannot seal for a hybrid"),
            "expected actionable error, got: {msg}"
        );
    }

    #[cfg(feature = "hybrid")]
    #[test]
    fn test_classic_suite_rejects_hybrid_keypair() {
        use crate::constants::{HYBRID_PUBLIC_KEY_SIZE, HYBRID_SECRET_KEY_SIZE};
        use crate::crypto::hybrid::HybridKeyPair;
        use zeroize::Zeroizing;
        let kp = KeyPair::Hybrid(HybridKeyPair {
            public_bytes: [0u8; HYBRID_PUBLIC_KEY_SIZE],
            secret_bytes: Zeroizing::new([0u8; HYBRID_SECRET_KEY_SIZE]),
        });
        let err = ClassicSuite.open_repo_key("AAAAAAAAAAAAAA==", &kp).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("classic suite cannot open a hybrid"),
            "expected actionable error, got: {msg}"
        );
    }

    #[cfg(feature = "hybrid")]
    #[test]
    fn test_decode_base64_for_suite_hybrid_rejects_classic_length() {
        use crate::crypto::Suite;
        use base64::prelude::*;
        // 32-byte payload encoded base64
        let b64 = BASE64_STANDARD.encode([0u8; 32]);
        let err = PublicKey::decode_base64_for_suite(&b64, Suite::Hybrid).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("hybrid public key decoded to classic length"),
            "expected downgrade-attempt error, got: {msg}"
        );
    }

    #[cfg(not(feature = "hybrid"))]
    #[test]
    fn test_decode_base64_for_suite_hybrid_requires_feature() {
        use crate::crypto::Suite;
        use base64::prelude::*;
        let b64 = BASE64_STANDARD.encode([0u8; 32]);
        let err = PublicKey::decode_base64_for_suite(&b64, Suite::Hybrid).unwrap_err();
        assert!(err.to_string().contains("hybrid suite requires the `hybrid` feature"));
    }
}
