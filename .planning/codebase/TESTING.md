# Testing Patterns

**Analysis Date:** 2026-02-21

## Test Framework

**Runner:**
- Built-in Rust test harness (no external test runner)
- Cargo test execution: `cargo test`
- No test configuration file (uses Cargo defaults)

**Assertion Library:**
- Standard Rust `assert!()`, `assert_eq!()`, `assert_ne!()` macros
- `proptest` for property-based testing (version 1.5 in Cargo.toml)
- Custom `prop_assert!()` within proptest blocks

**Run Commands:**
```bash
cargo test              # Run all tests
cargo test --lib       # Run library unit tests only
cargo test --test '*'  # Run integration tests
cargo test -- --nocapture  # Show println output
cargo test -- --test-threads=1  # Run serially (for shared state tests)
```

## Test File Organization

**Location:**
- Integration tests: `tests/` directory (separate from source)
- Unit tests: Co-located with source code using `#[cfg(test)]` modules
- Benchmarks: `benches/marker_inference.rs`
- Test submodules: `tests/marker_inference/` organization with helper modules

**Naming:**
- Integration test files follow pattern: `*_tests.rs` or `*_integration.rs`
- Security-focused tests: `*_security_tests.rs` (e.g., `crypto_security_tests.rs`)
- Feature tests: `*_integration.rs` (e.g., `command_integration.rs`)
- Edge case tests: `*_edge_cases.rs` (e.g., `processor_edge_cases.rs`, `scanner_edge_cases.rs`)

**Structure:**
```
tests/
├── command_integration.rs
├── crypto_security_tests.rs
├── error_handling_tests.rs
├── keystore_security_tests.rs
├── marker_inference_tests.rs
├── merge_integration_tests.rs
├── processor_edge_cases.rs
├── scanner_edge_cases.rs
├── scanner_integration_tests.rs
├── validation_security_tests.rs
├── verb_commands.rs
└── marker_inference/
    ├── mod.rs
    ├── properties.rs
    ├── edge_cases.rs
    ├── integration.rs
    └── spec_compliance.rs
```

## Test Structure

**Suite Organization:**
```rust
// error_handling_tests.rs pattern - flat test functions
/// Comprehensive error handling tests for SssError types
///
/// This test suite covers error type behavior:
/// - Display formatting
/// - Error source chains
/// - Conversion from other error types
/// - Error propagation
/// - Error matching and recovery

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
```

**Patterns:**
- Each `#[test]` function is independent and self-contained
- Descriptive test names starting with `test_` prefix
- Module-level doc comments describing test suite purpose
- Use of helper functions for common setup (e.g., `with_temp_dir()`)
- Serial test execution using `#[serial]` attribute from `serial_test` crate for tests with shared state

**Example Setup Pattern from command_integration.rs:**
```rust
/// Test helper to set up a temporary directory as current working directory
fn with_temp_dir<F>(test: F)
where
    F: FnOnce(&Path),
{
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let original_dir = env::current_dir().expect("Failed to get current dir");

    env::set_current_dir(temp_dir.path()).expect("Failed to change to temp dir");

    test(temp_dir.path());

    env::set_current_dir(original_dir).expect("Failed to restore original dir");
}

#[test]
#[serial]
fn test_validation_module_integration() {
    use sss::validation::{validate_base64, validate_file_path, validate_username};

    // Test username validation
    assert!(validate_username("valid_user").is_ok());
    assert!(validate_username("admin").is_err()); // Reserved name
    assert!(validate_username("user@invalid").is_err()); // Invalid character

    // Test file path validation
    with_temp_dir(|temp_path| {
        // Create a test file
        let test_file = temp_path.join("test.txt");
        fs::write(&test_file, "test content").expect("Failed to write test file");

        // Valid relative path
        assert!(validate_file_path("test.txt").is_ok());
    });
}
```

## Mocking

**Framework:**
- No external mocking library (proptest used for property-based testing only)
- Custom trait implementations for testing (e.g., `StdFileSystemOps`, `SecretsCache`)
- Test doubles created with minimal boilerplate

**Patterns:**
```rust
// From integration_qa_refactoring.rs - trait-based abstraction
use sss::secrets::{interpolate_secrets, FileSystemOps, SecretsCache, StdFileSystemOps};

/// Test that StdFileSystemOps correctly implements FileSystemOps
#[test]
fn test_std_filesystem_ops_implementation() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let test_file = temp_dir.path().join("test.txt");

    // Create a test file
    fs::write(&test_file, "test content")?;

    let fs_ops = StdFileSystemOps;

    // Test file_exists
    assert!(fs_ops.file_exists(&test_file));
    assert!(!fs_ops.file_exists(&temp_dir.path().join("nonexistent.txt")));

    // Test read_file
    let content = fs_ops.read_file(&test_file)?;
    assert_eq!(content, b"test content");

    // Test read_file error handling
    let result = fs_ops.read_file(&temp_dir.path().join("nonexistent.txt"));
    assert!(result.is_err());

    Ok(())
}
```

**What to Mock:**
- Filesystem operations via trait abstraction (`FileSystemOps`)
- Temporary directories using `tempfile` crate
- Custom rate limiters instantiated with test parameters
- Cryptographic keys generated fresh for each test

**What NOT to Mock:**
- Actual cryptographic operations (test real security properties)
- Core business logic (processor, scanner, merge algorithms)
- Configuration loading (test with real files)
- Error types (test actual error propagation)

## Fixtures and Factories

**Test Data:**
```rust
// crypto_security_tests.rs pattern - simple inline data
#[test]
fn test_nonce_uniqueness_for_different_content() {
    // Verify that different plaintext produces different nonces (via different ciphertext)
    let key = RepositoryKey::new();
    let timestamp = "2025-01-01T00:00:00Z";
    let file_path = "test.txt";

    let plaintext1 = "secret1";
    let plaintext2 = "secret2";

    let encrypted1 = crypto::encrypt(plaintext1.as_bytes(), &key, timestamp, file_path).unwrap();
    let encrypted2 = crypto::encrypt(plaintext2.as_bytes(), &key, timestamp, file_path).unwrap();

    // Different plaintexts should produce different ciphertexts
    assert_ne!(encrypted1, encrypted2);
}

// marker_inference/properties.rs pattern - property-based generators
proptest! {
    #![proptest_config(proptest_config())]
    /// Property: Applying inference twice should give the same result (idempotence)
    #[test]
    fn prop_idempotence(source in "[a-z ]{0,100}", edited in "[a-z ]{0,100}") {
        if let Ok(result1) = infer_markers(&source, &edited) {
            // Applying again should give same result
            if let Ok(result2) = infer_markers(&result1.output, &edited) {
                prop_assert_eq!(result1.output, result2.output);
            }
        }
    }
}
```

**Location:**
- Inline in test functions (no separate fixture files)
- `tempfile::TempDir` for filesystem fixtures
- Custom builders for complex objects (`RepositoryKey::new()`, `Keystore::new_with_*()`)
- Proptest generators for property-based testing

## Coverage

**Requirements:** Not enforced. No COVERAGESPEC or coverage targets defined

**View Coverage:**
```bash
# Generate coverage reports (requires cargo-tarpaulin or llvm-cov)
cargo tarpaulin --out Html
cargo llvm-cov --html
```

**Coverage Strategy:**
- Focus on critical security operations (cryptography, keystore, validation)
- Edge case testing via property-based tests
- Error paths tested explicitly
- Integration tests validate end-to-end workflows

## Test Types

**Unit Tests:**
- Scope: Individual functions and modules (error handling, validation, crypto operations)
- Approach: Direct function calls with known inputs/outputs
- Location: Co-located in source files with `#[cfg(test)]` modules or separate unit test files
- Example: `error_handling_tests.rs` tests each `SssError` variant display and conversion

**Integration Tests:**
- Scope: Multi-component workflows (file scanning, processing, keystore operations)
- Approach: Set up temporary directories, create files, invoke components in sequence
- Location: `tests/` directory with `_integration.rs` suffix
- Example: `command_integration.rs` tests validation module, rate limiter, and config manager together
- Span ~15,000+ lines of test code across 30+ test files

**Property-Based Tests:**
- Framework: `proptest` (version 1.5)
- Scope: Algorithm invariants and behavioral properties
- Approach: Generate random inputs, verify properties hold
- Example from `marker_inference/properties.rs`:
```rust
proptest! {
    #![proptest_config(proptest_config())]
    /// Property: Content preservation - rendered output should match edited text
    #[test]
    fn prop_content_preservation(
        content in "[a-z0-9 ]{1,50}"
    ) {
        let source = format!("o+{{{}}}", content);
        let edited = content.clone();

        if let Ok(result) = infer_markers(&source, &edited) {
            // Remove all markers from output
            let rendered = get_rendered(&result.output);
            prop_assert_eq!(rendered.trim(), edited.trim());
        }
    }
}
```

**Performance Benchmarks:**
- Framework: `criterion` (version 0.5)
- Location: `benches/marker_inference.rs`
- Approach: Micro-benchmarks of critical code paths
- Example:
```rust
fn bench_small_file(c: &mut Criterion) {
    let source = "password: o+{secret123}";
    let edited = "password: newsecret456";

    c.bench_function("infer_small", |b| {
        b.iter(|| infer_markers(black_box(source), black_box(edited)))
    });
}
```

## Common Patterns

**Async Testing:**
- No async code in codebase; not applicable

**Error Testing:**
```rust
// From error_handling_tests.rs - error type conversions
#[test]
fn test_io_error_conversion() {
    let io_error = io::Error::new(io::ErrorKind::NotFound, "file not found");
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
}
```

**Cryptographic Testing:**
```rust
// From crypto_security_tests.rs - testing deterministic properties
#[test]
fn test_deterministic_encryption_same_inputs() {
    // Verify that same inputs produce same output (for git-friendly diffs)
    let key = RepositoryKey::new();
    let timestamp = "2025-01-01T00:00:00Z";
    let file_path = "test.txt";
    let plaintext = "my_secret";

    let encrypted1 = crypto::encrypt(plaintext.as_bytes(), &key, timestamp, file_path).unwrap();
    let encrypted2 = crypto::encrypt(plaintext.as_bytes(), &key, timestamp, file_path).unwrap();

    // Same inputs should produce identical output
    assert_eq!(encrypted1, encrypted2);
}

// Testing nonce uniqueness across large datasets
#[test]
fn test_no_nonce_reuse_across_large_dataset() {
    // Generate many nonces and ensure no duplicates
    let key = RepositoryKey::new();
    let timestamp = "2025-01-01T00:00:00Z";

    let mut nonces = HashSet::new();

    for i in 0..1000 {
        let plaintext = format!("secret_{}", i);
        let encrypted = crypto::encrypt(plaintext.as_bytes(), &key, timestamp, "test.txt").unwrap();
        let nonce = encrypted[0..24].to_vec();

        // Each nonce should be unique
        assert!(nonces.insert(nonce), "Nonce reuse detected at iteration {}", i);
    }

    // Verify we got 1000 unique nonces
    assert_eq!(nonces.len(), 1000);
}
```

**Serial Test Execution:**
```rust
// From command_integration.rs - using serial_test for shared state
use serial_test::serial;

#[test]
#[serial]
fn test_validation_module_integration() {
    use sss::validation::{validate_base64, validate_file_path, validate_username};

    // Test body with shared global state
    // ...
}
```

**Proptest Configuration:**
```rust
// From marker_inference/properties.rs - disable file persistence for parallel execution
fn proptest_config() -> Config {
    Config {
        // Disable file persistence to avoid race conditions in parallel test execution
        failure_persistence: None,
        ..Config::default()
    }
}

proptest! {
    #![proptest_config(proptest_config())]
    // ... property tests
}
```

## Dependencies for Testing

**Core Testing:**
- `tempfile` 3.21.0 - Temporary file/directory creation
- `proptest` 1.5 - Property-based testing framework
- `serial_test` 3.0 - Serial test execution (for tests with shared state)
- `criterion` 0.5 - Performance benchmarking

**Test Organization:**
- 30+ integration test files with ~15,900 total lines
- Comprehensive coverage of security operations, edge cases, and error handling
- Recent additions: Security test suites, comprehensive integration tests (81 tests added)

---

*Testing analysis: 2026-02-21*
