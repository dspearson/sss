/// Application constants for SSS
// File and configuration constants
pub const CONFIG_FILE_NAME: &str = ".sss.toml";

// Encryption markers
pub const MARKER_PLAINTEXT_UTF8: &str = "⊕";
pub const MARKER_PLAINTEXT_ASCII: &str = "o+";
pub const MARKER_CIPHERTEXT: &str = "⊠";

// Security limits to prevent DoS attacks
pub const MAX_FILE_SIZE: usize = 100 * 1024 * 1024; // 100MB
pub const MAX_MARKER_CONTENT_SIZE: usize = 100 * 1024 * 1024; // 100MB per marker
pub const MAX_BASE64_KEY_LENGTH: usize = 100; // Max characters for base64 encoded keys
pub const MAX_BASE64_CIPHERTEXT_LENGTH: usize = 140_000_000; // Max characters for base64 ciphertext (~100MB encrypted)

// Editor fallbacks in order of preference
pub const EDITOR_FALLBACKS: &[&str] = &["nano", "vim", "emacs", "vi"];

// Default values
pub const DEFAULT_EDITOR: &str = "nano";
pub const DEFAULT_USERNAME_FALLBACK: &str = "unknown";

// Key rotation constants
pub const ROTATION_BACKUP_PREFIX: &str = ".sss_backup_";
pub const ROTATION_PROGRESS_UPDATE_INTERVAL: usize = 10; // Update progress every N files
pub const ROTATION_MAX_CONCURRENT_FILES: usize = 100; // Max files to process in parallel

// Display formatting
pub const KEY_ID_DISPLAY_LENGTH: usize = 8; // Length of key ID prefix to display
pub const FINGERPRINT_ART_MAX_LINES: usize = 4; // Max lines to show in fingerprint visualization

// Common error messages
pub const ERR_NO_PROJECT_CONFIG: &str = "No project configuration found. Run 'sss init' first.";
pub const ERR_NO_KEYPAIR: &str = "No keypair found. Run 'sss keys generate' first.";
pub const ERR_NO_KEYPAIR_INIT: &str = "No keypair found.\nGenerate a keypair first with: sss keys generate\nOr for passwordless keys: sss keys generate --no-password";
pub const ERR_INCORRECT_PASSPHRASE: &str = "Incorrect passphrase or no keypair found.\nGenerate a keypair first with: sss keys generate\nOr for passwordless keys: sss keys generate --no-password";
pub const ERR_USERNAME_REQUIRED: &str = "Could not determine username. Please provide one: sss init <username>";
pub const ERR_STDIN_IN_PLACE: &str = "Cannot use --in-place with stdin";
pub const ERR_STDIN_EDIT: &str = "Cannot use edit mode with stdin";
pub const ERR_FILE_NOT_FOUND: &str = "File does not exist";
pub const ERR_KEYPAIR_EXISTS: &str = "A keypair already exists. Use --force to overwrite.";
pub const ERR_EDITOR_FAILED: &str = "Editor exited with non-zero status";

// Helper function for user not found error
#[must_use]
pub fn err_user_not_found(username: &str) -> String {
    format!("User '{username}' not found in project")
}

// ----------------------------------------------------------------------
// Hybrid post-quantum KEM sizes (feature = "hybrid").
// Source: trelis-hybrid pinned at commit
//   5374dff482ba94a94695794b5e4554f908eb0d4d
// (see Cargo.toml banner + .planning/phases/02-hybrid-suite/02-CONTEXT.md).
// ----------------------------------------------------------------------

/// Concatenated X448 public scalar || sntrup761 public key size, in bytes.
/// Resolved from `trelis_hybrid::kem::PUBLIC_KEY_SIZE` (56 + 1158 = 1214).
#[cfg(feature = "hybrid")]
pub const HYBRID_PUBLIC_KEY_SIZE: usize = 1214;

/// Concatenated X448 secret scalar || sntrup761 secret key size, in bytes.
/// Resolved from `trelis_hybrid::kem::SECRET_KEY_SIZE` (56 + 1763 = 1819).
#[cfg(feature = "hybrid")]
pub const HYBRID_SECRET_KEY_SIZE: usize = 1819;

/// Concatenated KEM encapsulation size, in bytes (X448 ephemeral || sntrup761 ciphertext).
/// Resolved from `trelis_hybrid::kem::ENCAPSULATION_SIZE` (56 + 1039 = 1095).
#[cfg(feature = "hybrid")]
pub const HYBRID_ENCAPSULATION_SIZE: usize = 1095;

/// libsodium XChaCha20-Poly1305 nonce size (24 bytes).
#[cfg(feature = "hybrid")]
pub const HYBRID_SEALED_KEY_NONCE_SIZE: usize = 24;

/// libsodium XChaCha20-Poly1305 authenticator tag size (16 bytes, Poly1305).
#[cfg(feature = "hybrid")]
pub const HYBRID_SEALED_KEY_TAG_SIZE: usize = 16;

/// BLAKE3 KDF context string for deriving the AEAD key from the KEM shared secret.
/// Stable wire-format identifier — if this string changes, existing hybrid sealed
/// keys become unopenable. Do NOT edit without a migration plan.
#[cfg(feature = "hybrid")]
pub const HYBRID_KEM_CONTEXT: &str = "sss-hybrid-kem-v1";
