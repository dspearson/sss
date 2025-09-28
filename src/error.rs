use std::fmt;

/// Custom error types for SSS
#[derive(Debug)]
pub enum SssError {
    /// Cryptographic operation failed
    Crypto(String),
    /// Keystore operation failed
    Keystore(String),
    /// File I/O operation failed
    Io(std::io::Error),
    /// Configuration error
    Config(String),
    /// User input validation error
    Validation(String),
    /// Project management error
    Project(String),
    /// Authentication/authorization error
    Auth(String),
    /// File processing error
    Processing(String),
    /// Editor operation failed
    Editor(String),
    /// Network operation failed
    Network(String),
}

impl fmt::Display for SssError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SssError::Crypto(msg) => write!(f, "Cryptographic error: {}", msg),
            SssError::Keystore(msg) => write!(f, "Keystore error: {}", msg),
            SssError::Io(err) => write!(f, "I/O error: {}", err),
            SssError::Config(msg) => write!(f, "Configuration error: {}", msg),
            SssError::Validation(msg) => write!(f, "Validation error: {}", msg),
            SssError::Project(msg) => write!(f, "Project error: {}", msg),
            SssError::Auth(msg) => write!(f, "Authentication error: {}", msg),
            SssError::Processing(msg) => write!(f, "Processing error: {}", msg),
            SssError::Editor(msg) => write!(f, "Editor error: {}", msg),
            SssError::Network(msg) => write!(f, "Network error: {}", msg),
        }
    }
}

impl std::error::Error for SssError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            SssError::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl From<std::io::Error> for SssError {
    fn from(err: std::io::Error) -> Self {
        SssError::Io(err)
    }
}

impl From<toml::de::Error> for SssError {
    fn from(err: toml::de::Error) -> Self {
        SssError::Config(format!("TOML parsing error: {}", err))
    }
}

impl From<toml::ser::Error> for SssError {
    fn from(err: toml::ser::Error) -> Self {
        SssError::Config(format!("TOML serialization error: {}", err))
    }
}

impl From<base64::DecodeError> for SssError {
    fn from(err: base64::DecodeError) -> Self {
        SssError::Validation(format!("Base64 decode error: {}", err))
    }
}

impl From<regex::Error> for SssError {
    fn from(err: regex::Error) -> Self {
        SssError::Processing(format!("Regex error: {}", err))
    }
}

impl From<uuid::Error> for SssError {
    fn from(err: uuid::Error) -> Self {
        SssError::Validation(format!("UUID error: {}", err))
    }
}

impl From<std::str::Utf8Error> for SssError {
    fn from(err: std::str::Utf8Error) -> Self {
        SssError::Processing(format!("UTF-8 encoding error: {}", err))
    }
}

/// Result type alias using our custom error type
pub type Result<T> = std::result::Result<T, SssError>;

/// Helper macros for creating specific error types
#[macro_export]
macro_rules! crypto_error {
    ($msg:expr) => {
        $crate::error::SssError::Crypto($msg.to_string())
    };
    ($fmt:expr, $($arg:tt)*) => {
        $crate::error::SssError::Crypto(format!($fmt, $($arg)*))
    };
}

#[macro_export]
macro_rules! keystore_error {
    ($msg:expr) => {
        $crate::error::SssError::Keystore($msg.to_string())
    };
    ($fmt:expr, $($arg:tt)*) => {
        $crate::error::SssError::Keystore(format!($fmt, $($arg)*))
    };
}

#[macro_export]
macro_rules! config_error {
    ($msg:expr) => {
        $crate::error::SssError::Config($msg.to_string())
    };
    ($fmt:expr, $($arg:tt)*) => {
        $crate::error::SssError::Config(format!($fmt, $($arg)*))
    };
}

#[macro_export]
macro_rules! validation_error {
    ($msg:expr) => {
        $crate::error::SssError::Validation($msg.to_string())
    };
    ($fmt:expr, $($arg:tt)*) => {
        $crate::error::SssError::Validation(format!($fmt, $($arg)*))
    };
}

#[macro_export]
macro_rules! project_error {
    ($msg:expr) => {
        $crate::error::SssError::Project($msg.to_string())
    };
    ($fmt:expr, $($arg:tt)*) => {
        $crate::error::SssError::Project(format!($fmt, $($arg)*))
    };
}

#[macro_export]
macro_rules! auth_error {
    ($msg:expr) => {
        $crate::error::SssError::Auth($msg.to_string())
    };
    ($fmt:expr, $($arg:tt)*) => {
        $crate::error::SssError::Auth(format!($fmt, $($arg)*))
    };
}

#[macro_export]
macro_rules! processing_error {
    ($msg:expr) => {
        $crate::error::SssError::Processing($msg.to_string())
    };
    ($fmt:expr, $($arg:tt)*) => {
        $crate::error::SssError::Processing(format!($fmt, $($arg)*))
    };
}

#[macro_export]
macro_rules! editor_error {
    ($msg:expr) => {
        $crate::error::SssError::Editor($msg.to_string())
    };
    ($fmt:expr, $($arg:tt)*) => {
        $crate::error::SssError::Editor(format!($fmt, $($arg)*))
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let crypto_err = SssError::Crypto("encryption failed".to_string());
        assert_eq!(
            crypto_err.to_string(),
            "Cryptographic error: encryption failed"
        );

        let io_err = SssError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "file not found",
        ));
        assert!(io_err.to_string().contains("I/O error"));
    }

    #[test]
    fn test_error_conversions() {
        let io_error = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "access denied");
        let sss_error = SssError::from(io_error);

        match sss_error {
            SssError::Io(_) => (),
            _ => panic!("Expected Io variant"),
        }
    }

    #[test]
    fn test_error_macros() {
        let err = crypto_error!("test error");
        match err {
            SssError::Crypto(msg) => assert_eq!(msg, "test error"),
            _ => panic!("Expected Crypto variant"),
        }

        let err = crypto_error!("formatted error: {}", 42);
        match err {
            SssError::Crypto(msg) => assert_eq!(msg, "formatted error: 42"),
            _ => panic!("Expected Crypto variant"),
        }
    }
}
