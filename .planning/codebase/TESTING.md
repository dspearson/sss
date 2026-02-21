# Testing Patterns

**Analysis Date:** 2026-02-21

## Test Framework

**Language: Rust**

**Runner:**
- Built-in `cargo test` with Cargo.toml integration
- Config file: `Cargo.toml` (no separate test config)
- Test binary locations: `tests/` directory (integration tests), embedded in `src/` (unit tests)

**Dev Dependencies:**
- `proptest = "1.5"` - Property-based testing
- `criterion = "0.5"` - Benchmarking and performance testing
- `serial_test = "3.0"` - Serial test execution (for tests requiring isolated environments)
- `tempfile = "3.21.0"` - Temporary directories/files for test isolation

**Run Commands:**
```bash
cargo test                    # Run all tests
cargo test --lib             # Unit tests only (src/ level #[test])
cargo test --test '*'        # Integration tests only (tests/ directory)
cargo test -- --nocapture    # Show println! output
cargo test -- --test-threads=1  # Run serially
cargo test --release         # Run with optimizations
cargo bench                   # Run benchmarks with criterion
```

**Assertion Library:**
- Standard Rust `assert!`, `assert_eq!`, `assert_ne!`
- Custom matchers via pattern matching on `Result` types
- No external assertion library (unwrap and explicit pattern matching instead)

---

## Test File Organization

**Location - Unit Tests:**
- **Co-located** in same file as implementation code, within `#[cfg(test)]` modules
- Example: `src/error.rs` contains both error type and test module at end
- Example: `src/editor.rs` has `#[cfg(test)] mod tests { ... }`

**Location - Integration Tests:**
- **Separate directory**: `tests/` at project root
- Files: 35 integration/system test files
- Example files:
  - `tests/crypto_security_tests.rs` - Cryptographic operations
  - `tests/fuse_integration.rs` - FUSE filesystem integration
  - `tests/command_integration.rs` - Command-line interface
  - `tests/marker_inference_tests.rs` - Marker inference specification compliance

**Naming Convention:**
- Files: `snake_case_tests.rs` or `snake_case_integration.rs`
- Test functions: `test_description_with_underscores()`
- Descriptive names that read as specifications:
  - `test_nonce_uniqueness_for_different_content()`
  - `test_section_8_3_example_1_consistent_marking()`
  - `test_validation_module_integration()`

**Directory Structure:**
```
tests/
├── crypto_security_tests.rs       # Crypto operations
├── crypto_properties.rs            # Property-based crypto tests
├── fuse_integration.rs             # FUSE filesystem mount tests
├── command_integration.rs          # CLI command tests
├── marker_inference_tests.rs       # Specification compliance
├── marker_inference/               # Submodule for marker tests
│   ├── mod.rs
│   ├── edge_cases.rs
│   ├── integration.rs
│   ├── spec_compliance.rs
│   └── properties.rs
├── keystore_integration_tests.rs   # Keystore operations
├── error_handling_tests.rs         # Error scenarios
├── command_username_resolution.rs  # Username handling
└── [20+ other integration tests]
```

---

## Test Structure

### Unit Test Pattern

**Basic test module (in source file):**
```rust
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
    }

    #[test]
    fn test_error_conversions() {
        let io_error = std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "access denied"
        );
        let sss_error = SssError::from(io_error);
        match sss_error {
            SssError::Io(_) => (),
            _ => panic!("Expected Io variant"),
        }
    }
}
```

### Integration Test Pattern

**Setup and teardown with temporary directories:**
```rust
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
fn test_validation_module_integration() {
    with_temp_dir(|temp_path| {
        // Create test file
        let test_file = temp_path.join("test.txt");
        fs::write(&test_file, "test content").expect("Failed to write test file");

        // Test assertions
        assert!(validate_file_path("test.txt").is_ok());
    });
}
```

### FUSE Integration Test Pattern

**Multi-step project setup:**
```rust
struct TestProject {
    source_dir: TempDir,
    mount_dir: TempDir,
    home_dir: TempDir,
    mount_process: Option<std::process::Child>,
}

impl TestProject {
    fn new() -> anyhow::Result<Self> {
        let source_dir = TempDir::new()?;
        let home_dir = TempDir::new()?;

        // Generate keypair in temp HOME
        let keygen_output = Command::new(env!("CARGO_BIN_EXE_sss"))
            .arg("keys")
            .arg("generate")
            .arg("--no-password")
            .arg("--force")
            .env("HOME", home_dir.path())
            .output()?;

        if !keygen_output.status.success() {
            anyhow::bail!("Failed to generate keypair");
        }

        // Initialize SSS project
        let output = Command::new(env!("CARGO_BIN_EXE_sss"))
            .arg("init")
            .arg("testuser")
            .env("HOME", home_dir.path())
            .current_dir(source_dir.path())
            .output()?;

        Ok(Self {
            source_dir,
            mount_dir,
            home_dir,
            mount_process: None,
        })
    }

    fn source_path(&self) -> &Path {
        self.source_dir.path()
    }
}
```

### Specification Compliance Test Pattern

**Section-by-section testing with documented examples:**
```rust
/// Section 8.3 Example 1: Consistent Marking
///
/// Spec quote: "Both quotes outside marker, content inside marked"
///
/// Source:  key: "o+{value}"
/// Edited:  key: "newvalue"
/// Result:  key: "⊕{newvalue}"
#[test]
fn test_section_8_3_example_1_consistent_marking() {
    let source = r#"key: "o+{value}""#;
    let edited = r#"key: "newvalue""#;

    let result = infer_markers(source, edited).expect("Inference should succeed");

    // Verify quotes are OUTSIDE the marker
    assert!(
        result.output.contains(r#"key: "⊕{newvalue}""#)
            || result.output.contains(r#"key: "o+{newvalue}""#),
        "Delimiters should be outside marker. Got: {}",
        result.output
    );

    // Ensure quotes are NOT inside the marker
    assert!(
        !result.output.contains(r#"⊕{"newvalue"}"#)
            && !result.output.contains(r#"o+{"newvalue"}"#),
        "Delimiters should NOT be inside marker. Got: {}",
        result.output
    );
}
```

### Serial Execution Pattern

**For tests requiring isolated test environment:**
```rust
use serial_test::serial;

#[test]
#[serial]
fn test_validation_module_integration() {
    use sss::validation::{validate_base64, validate_file_path};
    // Test that requires no concurrent execution
}
```

---

## Mocking

**Framework:** Rust standard library only - no external mocking framework used

**Patterns:**

**1. Temporary File/Directory Mocking:**
```rust
use tempfile::TempDir;

let temp_dir = TempDir::new()?;
let test_file = temp_dir.path().join("test.txt");
fs::write(&test_file, b"content")?;
```

**2. Subprocess Mocking:**
```rust
let output = Command::new(env!("CARGO_BIN_EXE_sss"))
    .arg("init")
    .arg("testuser")
    .env("HOME", home_dir.path())
    .current_dir(source_dir.path())
    .output()?;

assert!(output.status.success());
```

**3. Test-specific Initialization:**
```rust
#[test]
fn test_crypto_deterministic() {
    let key = RepositoryKey::new();
    let plaintext = "my_secret";

    let encrypted1 = crypto::encrypt(plaintext.as_bytes(), &key, "2025-01-01T00:00:00Z", "file.txt")?;
    let encrypted2 = crypto::encrypt(plaintext.as_bytes(), &key, "2025-01-01T00:00:00Z", "file.txt")?;

    assert_eq!(encrypted1, encrypted2);
}
```

**4. Error Simulation:**
```rust
let io_error = std::io::Error::new(
    std::io::ErrorKind::PermissionDenied,
    "access denied"
);
let sss_error = SssError::from(io_error);
match sss_error {
    SssError::Io(_) => assert!(true),
    _ => panic!("Expected Io variant"),
}
```

**What to Mock:**
- Filesystem operations (via `tempfile` crate)
- Subprocess calls (via `std::process::Command`)
- Cryptographic operations (create fresh keys per test)
- Time/timestamps (pass as arguments, not system time)

**What NOT to Mock:**
- Core cryptographic primitives (test actual encryption)
- Configuration parsing (test with real TOML)
- Validation logic (test with real data patterns)
- Error type conversions (test actual From implementations)

---

## Fixtures and Factories

**Test Data Pattern:**
```rust
#[test]
fn test_nonce_uniqueness_for_different_content() {
    let key = RepositoryKey::new();          // Fresh key per test
    let timestamp = "2025-01-01T00:00:00Z";  // Fixed timestamp
    let file_path = "test.txt";               // Consistent path

    let plaintext1 = "secret1";
    let plaintext2 = "secret2";

    let encrypted1 = crypto::encrypt(plaintext1.as_bytes(), &key, timestamp, file_path)?;
    let encrypted2 = crypto::encrypt(plaintext2.as_bytes(), &key, timestamp, file_path)?;

    assert_ne!(encrypted1, encrypted2);
}
```

**Location:**
- Fixtures defined inline in test functions (small, focused tests)
- Helper structs in same test file (e.g., `TestProject` in `fuse_integration.rs`)
- No separate fixtures directory (data embedded in tests)

**Factory Pattern:**
```rust
impl TestProject {
    fn new() -> anyhow::Result<Self> {
        // Initialize complete test environment
    }

    fn source_path(&self) -> &Path {
        self.source_dir.path()
    }

    fn mount_path(&self) -> &Path {
        self.mount_dir.path()
    }
}
```

---

## Coverage

**Requirements:** Not enforced by tooling (no coverage target enforced in CI)

**View Coverage:**
```bash
# Requires tarpaulin or llvm-cov installation
cargo tarpaulin --out Html  # HTML report
# or
cargo llvm-cov             # Requires Rust 1.70+
```

**Coverage Areas:**
- Core cryptographic operations: extensive
- CLI command handling: partial (some commands tested via integration tests)
- FUSE filesystem: extensive (fuse_integration.rs covers mount/unmount/file operations)
- Error handling: extensive (crypto_security_tests.rs, error_handling_tests.rs)
- Marker inference: extensive (marker_inference_tests.rs with spec-based examples)

**Coverage Gaps:**
- Some edge cases in WinFSP (Windows filesystem) implementation
- Stress testing under high concurrency not comprehensive
- Some interactive TTY features in askpass binaries

---

## Test Types

### Unit Tests

**Scope:** Single function or small module
**Approach:** Isolated logic, in-process execution

**Examples:**
- `src/error.rs`: Error type conversions and Display impl
- `src/editor.rs`: Editor path resolution
- `src/keyring_manager.rs`: Keyring operations

**Pattern:**
```rust
#[test]
fn test_error_macros() {
    let err = crypto_error!("test error");
    match err {
        SssError::Crypto(msg) => assert_eq!(msg, "test error"),
        _ => panic!("Expected Crypto variant"),
    }
}
```

### Integration Tests

**Scope:** Multiple modules working together, filesystem or subprocess calls
**Approach:** Real environment setup (temp directories, subprocess execution)

**Examples:**
- `tests/command_integration.rs` - Full CLI command workflows
- `tests/keystore_integration_tests.rs` - Keystore + crypto + config
- `tests/fuse_integration.rs` - Mount, render, unmount cycle

**Pattern:**
```rust
#[test]
#[serial]
fn test_validation_module_integration() {
    with_temp_dir(|temp_path| {
        fs::write(temp_path.join("test.txt"), "content")?;
        assert!(validate_file_path("test.txt").is_ok());
    });
}
```

### Property-Based Tests

**Framework:** `proptest = "1.5"`
**Files:** `tests/crypto_properties.rs`, `tests/marker_inference/properties.rs`

**Pattern:**
```rust
use proptest::prelude::*;

proptest! {
    #[test]
    fn test_deterministic_for_same_inputs(content in ".*") {
        let key = RepositoryKey::new();

        let enc1 = crypto::encrypt(content.as_bytes(), &key, "2025-01-01T00:00:00Z", "test.txt")?;
        let enc2 = crypto::encrypt(content.as_bytes(), &key, "2025-01-01T00:00:00Z", "test.txt")?;

        prop_assert_eq!(enc1, enc2);
    }
}
```

### Benchmarks

**Framework:** `criterion = "0.5"`
**Benchmark file:** `benches/marker_inference.rs`
**Target:** Marker inference performance

**Run:**
```bash
cargo bench                          # Run all benchmarks
cargo bench --bench marker_inference # Specific benchmark
```

**Pattern:**
```rust
use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn marker_inference_benchmark(c: &mut Criterion) {
    c.bench_function("infer_markers_simple", |b| {
        b.iter(|| infer_markers(
            black_box(source),
            black_box(edited)
        ))
    });
}
```

### E2E Tests

**Scope:** Complete workflows from CLI entry to filesystem result
**Files:** `tests/fuse_integration.rs` (primary E2E test)

**Pattern:**
1. Create temp directories for source/mount/HOME
2. Generate cryptographic keypair
3. Initialize SSS project
4. Create/modify encrypted files
5. Mount FUSE filesystem
6. Verify file rendering
7. Verify marker inference
8. Unmount and cleanup

---

## Common Patterns

### Async Testing

**Status:** Not used (codebase is synchronous)

Optional async support via `#[tokio::test]` for features using tokio (e.g., 9P server):
- `tests/ninep_integration.rs` would use async patterns if fully implemented
- Current 9P support is feature-gated and not heavily tested

### Error Testing

**Pattern - Testing error types:**
```rust
#[test]
fn test_error_conversions() {
    let io_error = std::io::Error::new(
        std::io::ErrorKind::PermissionDenied,
        "access denied"
    );
    let sss_error = SssError::from(io_error);

    match sss_error {
        SssError::Io(_) => (),
        _ => panic!("Expected Io variant"),
    }
}
```

**Pattern - Testing error messages:**
```rust
#[test]
fn test_error_display() {
    let crypto_err = SssError::Crypto("encryption failed".to_string());
    assert_eq!(
        crypto_err.to_string(),
        "Cryptographic error: encryption failed"
    );
}
```

**Pattern - Testing invalid inputs:**
```rust
#[test]
fn test_validation_rejects_invalid_characters() {
    assert!(validate_username("user@invalid").is_err());
    assert!(validate_username("user\0invalid").is_err());
}
```

### Cryptographic Testing

**Pattern - Determinism verification:**
```rust
#[test]
fn test_deterministic_encryption_same_inputs() {
    let key = RepositoryKey::new();
    let encrypted1 = crypto::encrypt(plaintext.as_bytes(), &key, timestamp, file_path)?;
    let encrypted2 = crypto::encrypt(plaintext.as_bytes(), &key, timestamp, file_path)?;

    assert_eq!(encrypted1, encrypted2);
}
```

**Pattern - Nonce verification:**
```rust
#[test]
fn test_nonce_changes_with_file_path() {
    let key = RepositoryKey::new();
    let enc1 = crypto::encrypt(plaintext.as_bytes(), &key, timestamp, "file1.txt")?;
    let enc2 = crypto::encrypt(plaintext.as_bytes(), &key, timestamp, "file2.txt")?;

    assert_ne!(enc1, enc2);  // Different nonces
}
```

---

## Emacs Lisp Testing

**Status:** No automated test framework in use

**Manual Testing Patterns:**
- Interactive testing via `M-x load-file`
- Evaluation of test forms via `eval-after-load`
- Temporary buffer creation for testing
- No test runners or CI integration

**Examples from code:**
```elisp
(defun sss-pattern-at-point ()
  "Return SSS pattern at point, or nil if none found."
  (save-excursion
    (let ((original-point (point)))
      ;; Implementation tested via:
      ;; 1. Create buffer with SSS pattern
      ;; 2. Position point inside pattern
      ;; 3. Call function interactively
      ;; 4. Verify return value
      )))
```

**Recommendation for future:** Consider `buttercup` (Emacs testing framework) or `ert` (built-in) for automated testing.

---

## Summary

**Rust Testing:**
- Comprehensive test coverage with 35+ integration test files
- Unit tests co-located in source files, integration tests in `tests/` directory
- Heavy use of temporary directories and subprocess execution for realistic scenarios
- Property-based testing for cryptographic operations
- Specification-compliance testing with documented examples
- No external mocking framework - uses standard library patterns

**Emacs Lisp Testing:**
- Manual interactive testing only
- No automated test framework integrated
- Future: Consider `buttercup` or `ert` for automation

**Key Strengths:**
- Clear, descriptive test names that read as specifications
- Comprehensive FUSE integration testing with real mount/unmount cycles
- Security-focused tests (nonce verification, determinism, timing)
- Specification-driven tests with direct quotes from design docs

---

*Testing analysis: 2026-02-21*
