#![allow(clippy::missing_errors_doc, clippy::missing_panics_doc)]
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A secure string that automatically zeroes its contents when dropped
#[derive(Clone, ZeroizeOnDrop)]
pub struct SecureString {
    data: Vec<u8>,
}

impl SecureString {
    /// Create a new secure string from a regular string
    #[must_use] 
    pub fn new(s: &str) -> Self {
        Self {
            data: s.as_bytes().to_vec(),
        }
    }

    /// Create a new secure string from bytes
    #[must_use] 
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self { data: bytes }
    }

    /// Create an empty secure string with the given capacity
    #[must_use] 
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
    #[must_use] 
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Get the length in bytes
    #[must_use] 
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if the string is empty
    #[must_use] 
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
    #[must_use] 
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
    #[must_use] 
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            data: Vec::with_capacity(capacity),
        }
    }

    /// Create a new secure buffer from existing bytes
    #[must_use] 
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self { data: bytes }
    }

    /// Get the bytes as a slice
    #[must_use] 
    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    /// Get the bytes as a mutable slice
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }

    /// Get the length
    #[must_use] 
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if empty
    #[must_use] 
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

    /// Password strength levels
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
    pub enum PasswordStrength {
        VeryWeak,
        Weak,
        Moderate,
        Strong,
        VeryStrong,
    }

    impl PasswordStrength {
        /// Get a color code for terminal display
        #[must_use] 
        pub fn color_code(&self) -> &'static str {
            match self {
                PasswordStrength::VeryWeak => "\x1b[91m",   // Bright red
                PasswordStrength::Weak => "\x1b[31m",       // Red
                PasswordStrength::Moderate => "\x1b[33m",   // Yellow
                PasswordStrength::Strong => "\x1b[32m",     // Green
                PasswordStrength::VeryStrong => "\x1b[92m", // Bright green
            }
        }

        /// Get a display name
        #[must_use] 
        pub fn display_name(&self) -> &'static str {
            match self {
                PasswordStrength::VeryWeak => "Very Weak",
                PasswordStrength::Weak => "Weak",
                PasswordStrength::Moderate => "Moderate",
                PasswordStrength::Strong => "Strong",
                PasswordStrength::VeryStrong => "Very Strong",
            }
        }

        /// Get a recommendation message
        #[must_use] 
        pub fn recommendation(&self) -> Option<&'static str> {
            match self {
                PasswordStrength::VeryWeak => Some("Consider using at least 12 characters with mixed case, numbers, and symbols"),
                PasswordStrength::Weak => Some("Add more character variety (uppercase, numbers, symbols)"),
                PasswordStrength::Moderate => Some("Consider adding more characters for better security"),
                PasswordStrength::Strong | PasswordStrength::VeryStrong => None,
            }
        }
    }

    /// Analyze password strength
    #[must_use] 
    pub fn analyze_password_strength(password: &str) -> PasswordStrength {
        let len = password.len();
        let has_lowercase = password.chars().any(char::is_lowercase);
        let has_uppercase = password.chars().any(char::is_uppercase);
        let has_digit = password.chars().any(char::is_numeric);
        let has_symbol = password.chars().any(|c| !c.is_alphanumeric());

        let char_variety = [has_lowercase, has_uppercase, has_digit, has_symbol]
            .iter()
            .filter(|&&x| x)
            .count();

        // Calculate score based on length and character variety
        let mut score: i32 = 0;

        // Length scoring
        if len >= 20 {
            score += 4;
        } else if len >= 16 {
            score += 3;
        } else if len >= 12 {
            score += 2;
        } else if len >= 8 {
            score += 1;
        }

        // Character variety scoring
        match char_variety {
            4 => score += 4,
            3 => score += 3,
            2 => score += 2,
            1 => score += 1,
            _ => {}
        }

        // Check for common patterns (weak)
        let has_repeated = password.chars().collect::<Vec<_>>().windows(3).any(|w| w[0] == w[1] && w[1] == w[2]);
        let has_sequential = password.chars().collect::<Vec<_>>().windows(3).any(|w| {
            (w[0] as u32 + 1 == w[1] as u32) && (w[1] as u32 + 1 == w[2] as u32)
        });

        if has_repeated || has_sequential {
            score = score.saturating_sub(2);
        }

        // Map score to strength level
        match score {
            0..=2 => PasswordStrength::VeryWeak,
            3..=4 => PasswordStrength::Weak,
            5..=6 => PasswordStrength::Moderate,
            7..=8 => PasswordStrength::Strong,
            _ => PasswordStrength::VeryStrong,
        }
    }

    /// Display password strength indicator
    fn display_strength_indicator(strength: PasswordStrength) {
        let color = strength.color_code();
        let name = strength.display_name();
        let reset = "\x1b[0m";

        eprintln!("\nPassword strength: {color}{name}{reset}");

        if let Some(recommendation) = strength.recommendation() {
            eprintln!("💡 Tip: {recommendation}");
        }
    }

    /// Read a password securely from stdin with a prompt
    pub fn read_password(prompt: &str) -> Result<SecureString, io::Error> {
        // Check for SSS_PASSPHRASE environment variable (used in production and tests)
        if let Ok(passphrase) = std::env::var("SSS_PASSPHRASE") {
            return Ok(SecureString::new(&passphrase));
        }

        print!("{prompt}");
        io::stdout().flush()?;

        let password = rpassword::read_password()?;
        Ok(SecureString::new(&password))
    }

    /// Read a password securely with confirmation and strength analysis
    pub fn read_password_with_confirmation(
        prompt: &str,
        confirm_prompt: &str,
    ) -> std::result::Result<SecureString, std::io::Error> {
        read_password_with_confirmation_and_strength(prompt, confirm_prompt, true)
    }

    /// Read a password securely with confirmation, optionally showing strength
    pub fn read_password_with_confirmation_and_strength(
        prompt: &str,
        confirm_prompt: &str,
        show_strength: bool,
    ) -> std::result::Result<SecureString, std::io::Error> {
        let password = read_password(prompt)?;

        // Analyze and display strength for new passwords
        if show_strength
            && let Ok(pwd_str) = password.as_str() {
                let strength = analyze_password_strength(pwd_str);
                display_strength_indicator(strength);

                // Warn if password is too weak
                if strength < PasswordStrength::Moderate {
                    eprintln!("\n⚠️  WARNING: Weak passwords can be cracked with brute-force attacks.");
                    eprintln!("   For production use, choose a strong password (12+ characters).");
                }
            }

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

    /// Read a new password with strength requirements
    ///
    /// This function enforces minimum password strength and provides guidance.
    /// Will loop until a password meeting minimum requirements is provided.
    pub fn read_new_password_with_requirements(
        min_strength: PasswordStrength,
        allow_weak: bool,
    ) -> std::result::Result<SecureString, std::io::Error> {
        loop {
            let password = read_password("Enter new password: ")?;

            // Analyze strength
            let strength = if let Ok(pwd_str) = password.as_str() {
                analyze_password_strength(pwd_str)
            } else {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Invalid UTF-8 in password",
                ));
            };

            display_strength_indicator(strength);

            // Check if meets minimum requirements
            if strength < min_strength {
                if allow_weak {
                    eprintln!("\n⚠️  This password is weaker than recommended ({}).", min_strength.display_name());
                    print!("Continue with this password anyway? [y/N]: ");
                    io::stdout().flush()?;

                    let mut response = String::new();
                    io::stdin().read_line(&mut response)?;
                    if !response.trim().eq_ignore_ascii_case("y") {
                        eprintln!("\nPlease try again with a stronger password.");
                        continue;
                    }
                } else {
                    eprintln!("\n❌ Password must be at least {} strength.", min_strength.display_name());
                    eprintln!("   Please try again.");
                    continue;
                }
            }

            // Confirm password
            let confirm = read_password("\nConfirm password: ")?;

            match (password.as_str(), confirm.as_str()) {
                (Ok(_), Ok(c)) if password.constant_time_eq(c) => {
                    eprintln!("✓ Password set successfully\n");
                    return Ok(password);
                }
                (Ok(_), Ok(_)) => {
                    eprintln!("\n❌ Passwords do not match. Please try again.\n");
                }
                (Err(_), _) | (_, Err(_)) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Invalid UTF-8 in password",
                    ));
                }
            }
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
        // SAFETY: `as_bytes_mut` is safe here because we own the String exclusively
        // (exclusive &mut reference), and `zeroize` writes zeros in-place without
        // changing the length or capacity. The String is then cleared so the zeroed
        // bytes are never exposed as valid UTF-8 content.
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
