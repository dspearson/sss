//! TOML serialization/deserialization helper functions
//!
//! This module provides consistent error handling for TOML operations
//! used throughout the SSS codebase.

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};

/// Parse TOML string into typed structure
///
/// # Examples
///
/// ```
/// use serde::Deserialize;
/// use sss::toml_helpers::parse_toml;
///
/// #[derive(Deserialize)]
/// struct Config {
///     name: String,
/// }
///
/// let toml_str = r#"name = "test""#;
/// let config: Config = parse_toml(toml_str, "test config").unwrap();
/// assert_eq!(config.name, "test");
/// ```
pub fn parse_toml<T: for<'de> Deserialize<'de>>(content: &str, file_type: &str) -> Result<T> {
    toml::from_str(content).map_err(|e| anyhow!("Failed to parse {} config file: {}", file_type, e))
}

/// Serialize structure to pretty TOML string
///
/// # Examples
///
/// ```
/// use serde::Serialize;
/// use sss::toml_helpers::serialize_toml;
///
/// #[derive(Serialize)]
/// struct Config {
///     name: String,
/// }
///
/// let config = Config { name: "test".to_string() };
/// let toml_str = serialize_toml(&config, "test config").unwrap();
/// assert!(toml_str.contains("name"));
/// ```
pub fn serialize_toml<T: Serialize>(value: &T, config_type: &str) -> Result<String> {
    toml::to_string_pretty(value)
        .map_err(|e| anyhow!("Failed to serialise {}: {}", config_type, e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct TestConfig {
        name: String,
        value: i32,
    }

    #[test]
    fn test_parse_toml() {
        let toml_str = r#"
            name = "test"
            value = 42
        "#;
        let config: TestConfig = parse_toml(toml_str, "test").unwrap();
        assert_eq!(config.name, "test");
        assert_eq!(config.value, 42);
    }

    #[test]
    fn test_parse_toml_invalid() {
        let result: Result<TestConfig> = parse_toml("invalid toml {", "test");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Failed to parse"));
    }

    #[test]
    fn test_serialize_toml() {
        let config = TestConfig {
            name: "test".to_string(),
            value: 42,
        };
        let toml_str = serialize_toml(&config, "test").unwrap();
        assert!(toml_str.contains("name"));
        assert!(toml_str.contains("test"));
        assert!(toml_str.contains("value"));
        assert!(toml_str.contains("42"));
    }

    #[test]
    fn test_round_trip() {
        let original = TestConfig {
            name: "roundtrip".to_string(),
            value: 123,
        };
        let serialized = serialize_toml(&original, "test").unwrap();
        let deserialized: TestConfig = parse_toml(&serialized, "test").unwrap();
        assert_eq!(original, deserialized);
    }
}
