//! System keyring integration for secure passwordless key storage
//!
//! This module provides optional integration with the OS keyring (macOS Keychain,
//! Windows Credential Manager, Linux Secret Service) for storing private keys
//! without password protection while maintaining security.
#![allow(clippy::missing_errors_doc)]

use anyhow::{anyhow, Result};
use keyring::Entry;

/// Service name used for keyring entries
const SERVICE_NAME: &str = "sss";

/// Check if system keyring is available
///
/// This function attempts to create a test entry to verify the keyring is accessible.
/// Returns true if keyring operations are supported on this system.
#[must_use]
pub fn is_keyring_available() -> bool {
    // Try to create a test entry
    match Entry::new(SERVICE_NAME, "availability_test") {
        Ok(entry) => {
            // Try to set and delete a test value
            if entry.set_password("test").is_ok() {
                let _ = entry.delete_credential();
                true
            } else {
                false
            }
        }
        Err(_) => false,
    }
}

/// Store a secret key in the system keyring
///
/// # Arguments
/// * `key_id` - Unique identifier for the key
/// * `secret_key` - The secret key to store (base64 encoded)
///
/// # Returns
/// Ok(()) if stored successfully, Err if keyring is unavailable or storage fails
pub fn store_key_in_keyring(key_id: &str, secret_key: &str) -> Result<()> {
    let entry = Entry::new(SERVICE_NAME, key_id)
        .map_err(|e| anyhow!("Failed to create keyring entry: {e}"))?;

    entry
        .set_password(secret_key)
        .map_err(|e| anyhow!("Failed to store key in keyring: {e}"))?;

    Ok(())
}

/// Retrieve a secret key from the system keyring
///
/// # Arguments
/// * `key_id` - Unique identifier for the key
///
/// # Returns
/// The secret key (base64 encoded) if found, error if not found or keyring unavailable
pub fn get_key_from_keyring(key_id: &str) -> Result<String> {
    let entry = Entry::new(SERVICE_NAME, key_id)
        .map_err(|e| anyhow!("Failed to create keyring entry: {e}"))?;

    entry
        .get_password()
        .map_err(|e| anyhow!("Failed to retrieve key from keyring: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keyring_availability() {
        // Just verify the function doesn't panic
        let _available = is_keyring_available();
        // Can't assert true/false since it depends on the test environment
    }

    #[test]
    fn test_key_not_found() {
        if !is_keyring_available() {
            return;
        }

        let nonexistent_key = "this_key_definitely_does_not_exist_12345";
        let result = get_key_from_keyring(nonexistent_key);
        assert!(result.is_err());
    }
}
