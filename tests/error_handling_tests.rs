//! Comprehensive error handling tests for SssError types
//!
//! This test suite covers error type behavior:
//! - Display formatting
//! - Error source chains
//! - Conversion from other error types
//! - Error propagation
//! - Error matching and recovery

use sss::error::SssError;
use std::error::Error;
use std::io;

#[test]
fn test_crypto_error_display() {
    let error = SssError::Crypto("encryption failed".to_string());
    assert_eq!(error.to_string(), "Cryptographic error: encryption failed");
}

#[test]
fn test_keystore_error_display() {
    let error = SssError::Keystore("key not found".to_string());
    assert_eq!(error.to_string(), "Keystore error: key not found");
}

#[test]
fn test_io_error_display() {
    let io_error = io::Error::new(io::ErrorKind::NotFound, "file not found");
    let error = SssError::Io(io_error);
    assert!(error.to_string().contains("I/O error"));
    assert!(error.to_string().contains("file not found"));
}

#[test]
fn test_config_error_display() {
    let error = SssError::Config("invalid format".to_string());
    assert_eq!(error.to_string(), "Configuration error: invalid format");
}

#[test]
fn test_validation_error_display() {
    let error = SssError::Validation("password too weak".to_string());
    assert_eq!(error.to_string(), "Validation error: password too weak");
}

#[test]
fn test_project_error_display() {
    let error = SssError::Project("project not initialized".to_string());
    assert_eq!(error.to_string(), "Project error: project not initialized");
}

#[test]
fn test_auth_error_display() {
    let error = SssError::Auth("invalid credentials".to_string());
    assert_eq!(error.to_string(), "Authentication error: invalid credentials");
}

#[test]
fn test_processing_error_display() {
    let error = SssError::Processing("failed to process file".to_string());
    assert_eq!(error.to_string(), "Processing error: failed to process file");
}

#[test]
fn test_editor_error_display() {
    let error = SssError::Editor("editor not available".to_string());
    assert_eq!(error.to_string(), "Editor error: editor not available");
}

#[test]
fn test_network_error_display() {
    let error = SssError::Network("connection timeout".to_string());
    assert_eq!(error.to_string(), "Network error: connection timeout");
}

#[test]
fn test_error_source_for_io() {
    let io_error = io::Error::new(io::ErrorKind::PermissionDenied, "access denied");
    let error = SssError::Io(io_error);

    // Should have source for IO errors
    assert!(error.source().is_some());
}

#[test]
fn test_error_source_for_others() {
    // Other error types should not have source
    assert!(SssError::Crypto("test".to_string()).source().is_none());
    assert!(SssError::Keystore("test".to_string()).source().is_none());
    assert!(SssError::Config("test".to_string()).source().is_none());
    assert!(SssError::Validation("test".to_string()).source().is_none());
    assert!(SssError::Project("test".to_string()).source().is_none());
    assert!(SssError::Auth("test".to_string()).source().is_none());
    assert!(SssError::Processing("test".to_string()).source().is_none());
    assert!(SssError::Editor("test".to_string()).source().is_none());
    assert!(SssError::Network("test".to_string()).source().is_none());
}

#[test]
fn test_io_error_conversion() {
    let io_error = io::Error::new(io::ErrorKind::NotFound, "test");
    let sss_error = SssError::Io(io_error);

    match sss_error {
        SssError::Io(ref e) => {
            assert_eq!(e.kind(), io::ErrorKind::NotFound);
        }
        _ => panic!("Expected IO error"),
    }
}

#[test]
fn test_error_debug_output() {
    let error = SssError::Crypto("test".to_string());
    let debug_str = format!("{:?}", error);
    assert!(debug_str.contains("Crypto"));
    assert!(debug_str.contains("test"));
}

#[test]
fn test_multiple_error_types_in_result() {
    fn test_function(error_type: &str) -> Result<(), SssError> {
        match error_type {
            "crypto" => Err(SssError::Crypto("test".to_string())),
            "keystore" => Err(SssError::Keystore("test".to_string())),
            "config" => Err(SssError::Config("test".to_string())),
            _ => Ok(()),
        }
    }

    assert!(matches!(test_function("crypto"), Err(SssError::Crypto(_))));
    assert!(matches!(test_function("keystore"), Err(SssError::Keystore(_))));
    assert!(matches!(test_function("config"), Err(SssError::Config(_))));
    assert!(test_function("ok").is_ok());
}

#[test]
fn test_error_messages_with_special_characters() {
    let error = SssError::Validation("Password must contain: !@#$%^&*()".to_string());
    assert!(error.to_string().contains("!@#$%^&*()"));
}

#[test]
fn test_error_messages_with_unicode() {
    let error = SssError::Project("项目错误: 无效的配置".to_string());
    assert!(error.to_string().contains("项目错误"));
}

#[test]
fn test_empty_error_messages() {
    let error = SssError::Crypto("".to_string());
    assert_eq!(error.to_string(), "Cryptographic error: ");
}

#[test]
fn test_very_long_error_messages() {
    let long_msg = "x".repeat(10000);
    let error = SssError::Processing(long_msg.clone());
    assert!(error.to_string().contains(&long_msg));
}

#[test]
fn test_error_equality_and_matching() {
    fn check_error_type(error: &SssError) -> &str {
        match error {
            SssError::Crypto(_) => "crypto",
            SssError::Keystore(_) => "keystore",
            SssError::Io(_) => "io",
            SssError::Config(_) => "config",
            SssError::Validation(_) => "validation",
            SssError::Project(_) => "project",
            SssError::Auth(_) => "auth",
            SssError::Processing(_) => "processing",
            SssError::Editor(_) => "editor",
            SssError::Network(_) => "network",
        }
    }

    assert_eq!(check_error_type(&SssError::Crypto("test".to_string())), "crypto");
    assert_eq!(check_error_type(&SssError::Keystore("test".to_string())), "keystore");
    assert_eq!(check_error_type(&SssError::Config("test".to_string())), "config");
}

#[test]
fn test_error_with_newlines_in_message() {
    let error = SssError::Processing("Line 1\nLine 2\nLine 3".to_string());
    let display = error.to_string();
    assert!(display.contains("Line 1"));
    assert!(display.contains("Line 2"));
    assert!(display.contains("Line 3"));
}

#[test]
fn test_error_with_formatting_characters() {
    let error = SssError::Validation("Expected {}, got {}".to_string());
    assert!(error.to_string().contains("Expected {}, got {}"));
}

#[test]
fn test_nested_io_error_kinds() {
    let test_cases = vec![
        io::ErrorKind::NotFound,
        io::ErrorKind::PermissionDenied,
        io::ErrorKind::ConnectionRefused,
        io::ErrorKind::AlreadyExists,
        io::ErrorKind::InvalidInput,
        io::ErrorKind::TimedOut,
    ];

    for kind in test_cases {
        let io_error = io::Error::new(kind, "test");
        let sss_error = SssError::Io(io_error);

        if let SssError::Io(ref e) = sss_error {
            assert_eq!(e.kind(), kind);
        } else {
            panic!("Expected IO error");
        }
    }
}
