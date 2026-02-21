# Coding Conventions

**Analysis Date:** 2026-02-21

## Naming Patterns

**Files:**
- Lowercase with underscores: `scanner.rs`, `config_manager.rs`, `marker_inference.rs`
- Modules grouped by functionality: `commands/`, `marker_inference/`, `processor/`, `fuse/`
- Specialized modules (platform-specific) use platform suffix: `winfsp_fs.rs`, `ninep_fs.rs`, `fuse_fs.rs`

**Functions:**
- Snake case throughout: `scan_directory`, `validate_username`, `ensure_sodium_init`
- Constructors use `new()` or `new_with_*()` pattern: `FileScanner::new()`, `Keystore::new_with_config_dir()`
- Builder methods use fluent pattern: `.with_project_boundaries(bool)` returning `Self`
- Handler functions in commands follow pattern: `handle_*`: `handle_init`, `handle_keys`, `handle_mount`
- Getter/setter methods: `get_*()` or `set_*()`: `get_keys_directory()`, `set_ignore_patterns()`

**Variables:**
- Snake case for all variables: `allowed_extensions`, `ignore_patterns`, `negation_patterns`, `keys_dir`
- Mutable bindings explicitly marked: `let mut scanner`, `let mut files_with_patterns`
- Constants in SCREAMING_SNAKE_CASE: `MAX_USERNAME_LENGTH`, `MAX_KEY_SIZE`, `MAX_FILE_SIZE`

**Types:**
- PascalCase for structs: `FileScanner`, `RepositoryKey`, `Keystore`, `Processor`, `ProjectConfig`
- PascalCase for enums: `SssError`, `KdfParams`, `StoredKeyPair`
- Enum variants include doc comments: See `SssError` with variants like `Crypto(String)`, `Keystore(String)`, `Auth(String)`

## Code Style

**Formatting:**
- Standard Rust formatting conventions (4-space indents)
- No custom rustfmt.toml found; uses Rust default conventions
- Module-level comments with `//!` for documentation
- Inline comments use `//` for implementation details

**Linting:**
- Leverages Cargo default clippy rules (no clippy.toml detected)
- Error handling uses explicit result types throughout
- No unsafe code unless necessary (e.g., libsodium FFI calls in `crypto.rs`)

## Import Organization

**Order:**
1. Standard library imports (`use std::*`)
2. External crate imports (`use anyhow::*`, `use serde::*`)
3. Internal crate imports (`use crate::*`)
4. Conditional imports with `#[cfg(...)]` for platform-specific code

**Examples from codebase:**
```rust
// crypto.rs pattern
use anyhow::{anyhow, Result};
use zeroize::{Zeroize, ZeroizeOnDrop};
use crate::error_helpers;
use libsodium_sys as sodium;

// scanner.rs pattern
use anyhow::{anyhow, Result};
use globset::GlobSet;
use regex::Regex;
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use crate::constants::MAX_FILE_SIZE;
```

**Path Aliases:**
- No custom path aliases configured in Cargo.toml
- Uses standard crate paths: `crate::crypto`, `crate::error_helpers`, `crate::constants`

## Error Handling

**Patterns:**
- Custom error type: `SssError` enum in `src/error.rs` with variants for each error domain
- Uses `anyhow::Result<T>` for most fallible operations
- Custom error variants include doc comments describing the context
- Error types implement `Display`, `std::error::Error`, and conversions from standard errors

**Error Types by Domain:**
- `Crypto(String)` - Cryptographic operation failures
- `Keystore(String)` - Keystore/key management failures
- `Io(std::io::Error)` - File I/O operations with source chain
- `Config(String)` - Configuration parsing errors
- `Validation(String)` - Input validation failures
- `Project(String)` - Project management issues
- `Auth(String)` - Authentication/authorization failures
- `Processing(String)` - File/data processing errors
- `Editor(String)` - Editor integration failures
- `Network(String)` - Network operation failures

**From Implementations:**
```rust
// Automatic conversion from standard error types
impl From<std::io::Error> for SssError
impl From<toml::de::Error> for SssError
impl From<toml::ser::Error> for SssError
impl From<base64::DecodeError> for SssError
impl From<regex::Error> for SssError
```

**Error Propagation:**
- Uses `?` operator for short-circuiting on Result types
- `anyhow!(msg)` macro for creating ad-hoc errors with context
- `validation_error!` macro for validation failures (custom macro pattern)

## Logging

**Framework:** No explicit logging framework. Uses `eprintln!()` for stderr output

**Patterns:**
- Warning output: `eprintln!("⚠️  WARNING: ...")` in `keystore.rs`
- Errors printed to stderr at caller level, not in library code
- No log levels; relies on eprintln for direct user feedback

**Example from keystore.rs:**
```rust
if use_keyring && !keyring_support::is_keyring_available() {
    eprintln!("⚠️  WARNING: System keyring requested but not available!");
    eprintln!("   Falling back to file-based storage.");
    eprintln!("   Keys will be stored without password protection.");
}
```

## Comments

**When to Comment:**
- Module-level documentation with `//!` required for public modules
- Public items require `///` doc comments explaining purpose
- Complex algorithms include implementation notes with `//`
- Invariants and preconditions documented in function docs

**JSDoc/TSDoc:**
- Uses Rust doc comment style `///` with markdown
- Doc comments include examples in triple-backtick blocks
- Includes "# Arguments" sections for parameters
- Includes "# Examples" sections for usage

**Example from scanner.rs:**
```rust
/// Set gitignore-style patterns for files to ignore
///
/// # Arguments
///
/// * `ignore_set` - GlobSet containing patterns for files to ignore
/// * `negation_set` - GlobSet containing negation patterns (files that should NOT be ignored)
///
/// # Examples
///
/// ```
/// use sss::scanner::FileScanner;
/// use sss::project::ProjectConfig;
/// ...
/// ```
pub fn set_ignore_patterns(&mut self, ignore_set: GlobSet, negation_set: GlobSet) {
    self.ignore_patterns = Some(ignore_set);
    self.negation_patterns = Some(negation_set);
}
```

## Function Design

**Size:**
- Typical functions 20-50 lines, with some reaching 100+ for complex operations
- Large functions like `scan_directory()` in `scanner.rs` decomposed into logical sections with comments

**Parameters:**
- Explicit `&self` or `&mut self` for methods
- Generic parameters used for flexibility: `impl Into<String>`, `P: AsRef<Path>`
- Result-returning functions prefer `Result<T>` over Option for detailed error context
- Path parameters accept trait objects: `pub fn scan_directory<P: AsRef<Path>>(&self, root: P)`

**Return Values:**
- Functions returning fallible operations: `Result<T>` from `anyhow`
- Constructors return `Result<Self>` for initialization that may fail
- Builder methods return `Self` for method chaining
- Predicates return `bool`: `is_keyring_available()`, `file_exists()`

## Module Design

**Exports:**
- Main `lib.rs` re-exports public API with `pub use` statements
- Command handlers exposed through `commands/mod.rs`
- Core types available at crate root: `pub use crypto::KeyPair`, `pub use error::Result`

**Barrel Files:**
- `src/lib.rs` aggregates all public modules and exports
- `src/commands/mod.rs` re-exports all command handlers
- `src/processor/mod.rs` aggregates processor components
- Submodules grouped by functionality: `marker_inference/`, `fuse/`, `processor/`

**Feature-Gated Modules:**
- Platform-specific modules behind `#[cfg(...)]` attributes
- FUSE-specific: `#[cfg(all(any(target_os = "linux", target_os = "macos"), feature = "fuse"))]`
- Windows-specific: `#[cfg(all(target_os = "windows", feature = "winfsp"))]`
- 9P protocol: `#[cfg(feature = "ninep")]`

**Example from lib.rs:**
```rust
#[cfg(all(any(target_os = "linux", target_os = "macos"), feature = "fuse"))]
pub mod fuse;
#[cfg(all(any(target_os = "linux", target_os = "macos"), feature = "fuse"))]
pub mod fuse_fs;

pub use config::{load_key, load_key_for_user, Config};
pub use crypto::{KeyPair, RepositoryKey};
pub use error::{Result, SssError};
pub use keystore::Keystore;
pub use processor::Processor;
```

## Unsafe Code

**Policy:**
- Minimal unsafe code; restricted to FFI boundaries
- Libsodium calls wrapped in unsafe blocks with `// SAFETY:` comments
- Example in `crypto.rs`:
```rust
fn ensure_sodium_init() {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| unsafe {
        if sodium::sodium_init() < 0 {
            panic!("Failed to initialise libsodium");
        }
    });
}
```

## Security Practices

**Sensitive Data:**
- `Zeroize` and `ZeroizeOnDrop` traits used for cryptographic keys
- Base64-encoded keys stored separately from secrets
- No plaintext secrets cached in memory (See recent commit "security: Remove plaintext secret caching")
- Environment validation rather than hardcoded configuration

---

*Convention analysis: 2026-02-21*
