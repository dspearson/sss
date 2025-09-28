use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A secure string that automatically zeroes its contents when dropped
#[derive(Clone, ZeroizeOnDrop)]
pub struct SecureString {
    data: Vec<u8>,
}

impl SecureString {
    /// Create a new secure string from a regular string
    pub fn new(s: &str) -> Self {
        Self {
            data: s.as_bytes().to_vec(),
        }
    }

    /// Create a new secure string from bytes
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self { data: bytes }
    }

    /// Create an empty secure string with the given capacity
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            data: Vec::with_capacity(capacity),
        }
    }

    /// Get the string as a slice (use with caution)
    pub fn as_str(&self) -> Result<&str, std::str::Utf8Error> {
        std::str::from_utf8(&self.data)
    }

    /// Get the bytes (use with caution)
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Get the length in bytes
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if the string is empty
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Append to the secure string
    pub fn push_str(&mut self, s: &str) {
        self.data.extend_from_slice(s.as_bytes());
    }

    /// Clear the contents (automatically zeroed)
    pub fn clear(&mut self) {
        self.data.zeroize();
        self.data.clear();
    }

    /// Compare with a regular string in constant time
    pub fn constant_time_eq(&self, other: &str) -> bool {
        use subtle::ConstantTimeEq;

        let other_bytes = other.as_bytes();
        if self.data.len() != other_bytes.len() {
            return false;
        }

        self.data.ct_eq(other_bytes).into()
    }
}

impl fmt::Debug for SecureString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecureString([REDACTED {} bytes])", self.data.len())
    }
}

impl Zeroize for SecureString {
    fn zeroize(&mut self) {
        self.data.zeroize();
    }
}

impl From<String> for SecureString {
    fn from(s: String) -> Self {
        // The original string is moved, so we don't need to worry about it
        Self::from_bytes(s.into_bytes())
    }
}

impl From<&str> for SecureString {
    fn from(s: &str) -> Self {
        Self::new(s)
    }
}

/// A secure buffer for handling temporary cryptographic material
#[derive(ZeroizeOnDrop)]
pub struct SecureBuffer {
    data: Vec<u8>,
}

impl SecureBuffer {
    /// Create a new secure buffer with the given capacity
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            data: Vec::with_capacity(capacity),
        }
    }

    /// Create a new secure buffer from existing bytes
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self { data: bytes }
    }

    /// Get the bytes as a slice
    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    /// Get the bytes as a mutable slice
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }

    /// Get the length
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Extend with additional bytes
    pub fn extend_from_slice(&mut self, other: &[u8]) {
        self.data.extend_from_slice(other);
    }

    /// Resize the buffer
    pub fn resize(&mut self, new_len: usize, value: u8) {
        self.data.resize(new_len, value);
    }

    /// Clear the buffer (automatically zeroed)
    pub fn clear(&mut self) {
        self.data.zeroize();
        self.data.clear();
    }
}

impl fmt::Debug for SecureBuffer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecureBuffer([REDACTED {} bytes])", self.data.len())
    }
}

impl Zeroize for SecureBuffer {
    fn zeroize(&mut self) {
        self.data.zeroize();
    }
}

/// Utilities for secure password reading
pub mod password {
    use super::SecureString;
    use std::io::{self, Write};

    /// Read a password securely from stdin with a prompt
    pub fn read_password(prompt: &str) -> Result<SecureString, io::Error> {
        // Check for test mode
        if std::env::var("SSS_TEST_MODE").is_ok() {
            let test_password = std::env::var("SSS_TEST_PASSWORD").unwrap_or_default();
            return Ok(SecureString::new(&test_password));
        }

        print!("{}", prompt);
        io::stdout().flush()?;

        let password = rpassword::read_password()?;
        Ok(SecureString::new(&password))
    }

    /// Read a password securely with confirmation
    pub fn read_password_with_confirmation(
        prompt: &str,
        confirm_prompt: &str,
    ) -> std::result::Result<SecureString, std::io::Error> {
        let password = read_password(prompt)?;
        let confirm = read_password(confirm_prompt)?;

        match (password.as_str(), confirm.as_str()) {
            (Ok(_), Ok(c)) if password.constant_time_eq(c) => Ok(password),
            (Ok(_), Ok(_)) => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Passwords do not match",
            )),
            (Err(_), _) | (_, Err(_)) => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid UTF-8 in password",
            )),
        }
    }
}

/// A trait for types that can be securely cleared
pub trait SecureClear {
    /// Securely clear the contents of this type
    fn secure_clear(&mut self);
}

impl SecureClear for String {
    fn secure_clear(&mut self) {
        unsafe {
            let bytes = self.as_bytes_mut();
            bytes.zeroize();
        }
        self.clear();
    }
}

impl SecureClear for Vec<u8> {
    fn secure_clear(&mut self) {
        self.zeroize();
        self.clear();
    }
}

impl<const N: usize> SecureClear for [u8; N] {
    fn secure_clear(&mut self) {
        self.zeroize();
    }
}

/// A wrapper that ensures a closure runs with secure cleanup
pub fn with_secure_temp<T, F, R>(mut data: T, f: F) -> R
where
    T: SecureClear,
    F: FnOnce(&mut T) -> R,
{
    let result = f(&mut data);
    data.secure_clear();
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_string_basic() {
        let mut s = SecureString::new("test");
        assert_eq!(s.as_str().unwrap(), "test");
        assert_eq!(s.len(), 4);
        assert!(!s.is_empty());

        s.push_str(" data");
        assert_eq!(s.as_str().unwrap(), "test data");

        s.clear();
        assert!(s.is_empty());
    }

    #[test]
    fn test_secure_string_constant_time_eq() {
        let s = SecureString::new("secret");
        assert!(s.constant_time_eq("secret"));
        assert!(!s.constant_time_eq("public"));
        assert!(!s.constant_time_eq("secret_longer"));
    }

    #[test]
    fn test_secure_buffer() {
        let mut buf = SecureBuffer::with_capacity(10);
        buf.extend_from_slice(b"test");
        assert_eq!(buf.as_slice(), b"test");
        assert_eq!(buf.len(), 4);

        buf.clear();
        assert!(buf.is_empty());
    }

    #[test]
    fn test_secure_clear_trait() {
        let mut s = String::from("sensitive");
        s.secure_clear();
        assert!(s.is_empty());

        let mut v = vec![1u8, 2, 3, 4];
        v.secure_clear();
        assert!(v.is_empty());

        let mut arr = [1u8, 2, 3, 4];
        arr.secure_clear();
        assert_eq!(arr, [0u8; 4]);
    }

    #[test]
    fn test_with_secure_temp() {
        let result = with_secure_temp(String::from("temp"), |s| {
            s.push_str(" data");
            s.len()
        });
        assert_eq!(result, 9); // "temp data".len()
    }

    #[test]
    fn test_debug_redaction() {
        let s = SecureString::new("secret");
        let debug_str = format!("{:?}", s);
        assert!(debug_str.contains("REDACTED"));
        assert!(!debug_str.contains("secret"));

        let buf = SecureBuffer::from_bytes(vec![1, 2, 3, 4]);
        let debug_str = format!("{:?}", buf);
        assert!(debug_str.contains("REDACTED"));
    }
}