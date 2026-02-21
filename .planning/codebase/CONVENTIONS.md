# Coding Conventions

**Analysis Date:** 2026-02-21

## Language Overview

This codebase uses **Rust** as the primary language (67 source files in `src/`, 35 test files) with **Emacs Lisp** integrations in two locations:
- `emacs/sss-mode.el` - Single-file v1.0 mode (354 lines)
- `plugins/emacs/` - Multi-file implementation (2318 lines across 7 files)

---

## RUST CONVENTIONS

### Naming Patterns

**Files:**
- snake_case for module files: `src/config.rs`, `src/scanner.rs`, `src/processor/core.rs`
- Organized in logical directories: `src/commands/`, `src/bin/`, `src/processor/`, `src/fuse/`
- Multi-binary pattern: `src/bin/sss-agent.rs`, `src/bin/sss-askpass-tty.rs`

**Functions:**
- snake_case throughout: `find_project_root_from()`, `validate_username()`, `encrypt_to_base64()`
- Private functions prefixed with underscores where appropriate: `_ensure_sodium_init()`
- Descriptive, action-oriented names: `load_processor_for_source()`, `find_balanced_markers()`

**Types and Structs:**
- PascalCase for structs: `FileScanner`, `ProjectConfig`, `UserConfig`, `SssError`, `RepositoryKey`
- Type aliases with explicit intent: `pub type Result<T> = std::result::Result<T, SssError>;`

**Variables:**
- snake_case throughout: `file_path`, `temp_dir`, `pattern_regex`, `ignore_patterns`
- Constants in UPPER_SNAKE_CASE: `MAX_FILE_SIZE`, `DEFAULT_CONFIG_FILE`, `SYMMETRIC_KEY_SIZE`

### Code Style

**Formatting:**
- Standard Rust formatting with 4-space indentation
- No .rustfmt.toml or rustfmt config found - uses default Rust conventions
- Line width follows Rust defaults (typically 99-100 chars, pragmatically enforced)

**Linting:**
- No clippy.toml found, uses default clippy checks
- Code follows idiomatic Rust patterns

**Imports:**
- Organized in groups:
  1. `use std::*;` (standard library)
  2. External crates: `use anyhow::{anyhow, Result};`, `use clap::{Arg, Command};`
  3. Internal modules: `use crate::scanner::FileScanner;`
  4. Conditional imports with feature gates: `#[cfg(feature = "fuse")]`

**Path aliases:**
- Use full `crate::` paths for internal imports
- No path aliases configured in Cargo.toml

### Error Handling

**Custom Error Type:**
- Centralized `SssError` enum in `src/error.rs` with domain-specific variants:
  - `Crypto(String)` - Cryptographic operations
  - `Keystore(String)` - Keystore operations
  - `Config(String)` - Configuration parsing
  - `Validation(String)` - User input validation
  - `Processing(String)` - File/content processing
  - `Auth(String)` - Authentication/authorization
  - `Network(String)` - Network operations

**Error Conversion:**
- `From` trait implementations for common error types:
  ```rust
  impl From<std::io::Error> for SssError { ... }
  impl From<toml::de::Error> for SssError { ... }
  impl From<base64::DecodeError> for SssError { ... }
  ```

**Error Macros:**
- Domain-specific macros for creating typed errors with optional formatting:
  ```rust
  crypto_error!("message")
  crypto_error!("formatted: {}", value)
  keystore_error!("keystore operation failed")
  validation_error!("invalid input")
  ```

**Result Type:**
- Use `crate::error::Result<T>` alias throughout (not `anyhow::Result`)
- However, `anyhow::Result` used in some command handlers for simplicity

**Error Display:**
- Implement `fmt::Display` with user-friendly messages
- Chain via `Error` trait implementation for `Io` errors

### Logging

**Framework:** No structured logging framework - uses `println!`, `eprintln!`, and `stderr` output

**Patterns:**
- Status messages via `println!` to stdout
- Errors to stderr: `eprintln!(...)`
- Verbose output controlled via command-line flags (typical `--verbose` pattern)
- Test output suppressed unless `--nocapture` flag in tests

### Comments

**When to Comment:**
- Doc comments (`///`) for all public items (functions, structs, modules)
- Line comments (`//`) for complex logic within functions
- No over-commenting simple, self-documenting code

**Doc Comments - Triple slash (`///`):**
- Required on all public functions with examples where appropriate:
  ```rust
  /// Find SSS project root by searching upward from a specific directory
  pub fn find_project_root_from(start_dir: &Path) -> Result<PathBuf> { }
  ```
- Struct field documentation:
  ```rust
  /// Regex for detecting SSS patterns in files
  pattern_regex: Regex,
  ```
- Section comments for logical blocks within test suites

**Test Documentation:**
- Test names describe exactly what is being tested: `test_nonce_uniqueness_for_different_content()`
- Comments above test with context from specification:
  ```rust
  /// Section 8.3 Example 1: Consistent Marking
  /// Spec quote: "Both quotes outside marker, content inside marked"
  #[test]
  fn test_section_8_3_example_1_consistent_marking() { }
  ```

### Function Design

**Size:**
- Generally 20-100 lines per function
- Larger functions split into logical helpers (e.g., `src/fuse_fs.rs` has 133KB but well-structured)
- Complex cryptographic operations documented with high-level flow

**Parameters:**
- Prefer explicit parameters over config structs for simple functions
- Use builder pattern or context structs for operations with many options
- Owned types (`String`, `Vec<T>`) for simple APIs; references (`&str`, `&[T]`) internally

**Return Values:**
- Use `Result<T>` for fallible operations
- Return wrapped/owned types: `Result<Vec<PathBuf>>`, `Result<ProjectConfig>`
- For utilities, return `Option<T>` when absence is normal

### Module Design

**Exports:**
- Private by default, `pub` explicitly on intended-public items
- Re-exports for convenience: `pub use crate::project::ProjectConfig;`
- Feature-gated exports: `#[cfg(feature = "fuse")] pub fn handle_mount(...)`

**Barrel Files:**
- `src/commands/mod.rs` - Central command re-export point
- `src/processor/mod.rs` - Processor module re-exports
- `src/bin/` - Separate binaries with isolated concerns

### Security Patterns

**Sensitive Data:**
- Use `#[derive(Zeroize, ZeroizeOnDrop)]` for cryptographic keys:
  ```rust
  #[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
  pub struct RepositoryKey([u8; SYMMETRIC_KEY_SIZE]);
  ```
- Wrap passphrases in types that zeroize on drop
- Clear sensitive buffers explicitly when not automatic

**Cryptographic Constants:**
- Define once in constants module: `SYMMETRIC_KEY_SIZE`, `PUBLIC_KEY_SIZE`
- Use in function signatures and validations

---

## EMACS LISP CONVENTIONS

### File Organization

**Single-file mode (`emacs/sss-mode.el`):**
- Self-contained 354-line implementation
- Single feature: transparent decrypt-on-open, encrypt-on-save
- Simple, direct command-line invocation model

**Multi-file plugin suite (`plugins/emacs/`):**
- Modular design across 7 files (~330 lines avg per file)
- **sss.el** (912 lines) - Main interface and command implementations
- **sss-mode.el** (242 lines) - Minor mode with syntax highlighting
- **sss-utils.el** (334 lines) - Pattern detection and buffer utilities
- **sss-project.el** (274 lines) - Project detection and management
- **sss-ui.el** (360 lines) - Transient menus and UI components
- **sss-doom.el** (196 lines) - Doom Emacs integration
- Heavy use of `require` and `declare-function` for dependency management

### Naming Patterns

**Files:**
- kebab-case: `sss-mode.el`, `sss-utils.el`, `sss-project.el`
- Prefix with `sss-` for all files in the package

**Functions:**
- Public functions: `sss-encrypt-region()`, `sss-process-file()`, `sss-list-users()`
- Private (internal) functions: `sss--get-username()`, `sss--run-command()`, `sss--build-command-args()`
  - Double hyphen prefix convention strictly followed
- Predicate functions: `sss-in-project-p()`, `sss--executable-available-p()` (end with `-p`)

**Variables:**
- Custom variables (defcustom): `sss-executable`, `sss-default-username`, `sss-auto-decrypt-on-open`
- Internal state (defvar): `sss--password-cache`, `sss--current-username`
- Constants (defconst): `sss--sealed-marker`, `sss-plaintext-pattern`, `sss-any-pattern`

**Keybindings:**
- Prefix-based: `C-c s` (customizable via `sss-keybinding-prefix`)
- Evil integration: `ge` (encrypt), `gd` (decrypt), `gt` (toggle)
- Doom integration: `<leader>e` for encryption operations

### Code Style

**Formatting:**
- 2-space indentation (standard Emacs Lisp convention)
- lexical-binding enabled: `;;; -*- lexical-binding: t; -*-`
- Each file header with copyright, version, package requirements

**Header Template:**
```elisp
;;; sss-mode.el --- Description -*- lexical-binding: t; -*-

;; Author: Dominic Pearson <dsp@technoanimal.net>
;; Keywords: encryption, security, files
;; Version: 1.0
;; Package-Requires: ((emacs "30.1"))

;;; Commentary:
;; [Purpose and usage]

;;; Code:
```

**Conditionals and Feature Detection:**
```elisp
(when (featurep 'transient)
  ;; Use transient if available
  )

(unless (featurep 'transient)
  ;; Fallback implementation
  )
```

### Import Organization

**Module loading order:**
1. Standard library: `(require 'cl-lib)`, `(require 'auth-source')`
2. Internal modules: `(require 'sss-mode)`, `(require 'sss-utils')`
3. Optional features: `(when (or (featurep 'transient) ...) ...)`

**Declarations:**
- Forward declarations for functions from other modules:
  ```elisp
  (declare-function sss-encrypt-region "sss")
  (declare-function sss-decrypt-region "sss")
  ```

### Comments

**File-level Documentation:**
```elisp
;;; Commentary:
;; [Purpose]
;; Usage: [how to use]
;; Features:
;; - Feature 1
;; - Feature 2
```

**Function Documentation:**
```elisp
(defun sss--run-command (args &optional input)
  "Run SSS command with ARGS and optional INPUT.
Returns (exit-code . output)."
  ...)
```

**Inline Comments:**
- Describe *why*, not what: `; Separate HOME for keys`
- Used sparingly, only for non-obvious logic

### Function Design

**Pattern - Command Execution:**
```elisp
(defun sss--run-command (args &optional input)
  "Run SSS command, return (exit-code . output)."
  (with-temp-buffer
    (if input (insert input))
    (let ((exit-code
           (apply #'call-process sss-executable nil ...)))
      (cons exit-code (buffer-string)))))
```

**Pattern - Interactive Commands:**
```elisp
(defun sss-encrypt-region (start end &optional username)
  "Encrypt region from START to END for USERNAME."
  (interactive "r")  ; r = region
  ...)
```

**Parameters:**
- Use `&optional` for optional arguments with sensible defaults
- Use `&rest` for variable argument lists (e.g., `(defun sss--run-command (args)...`))

### Variables and State

**Customizable Variables:**
```elisp
(defcustom sss-auto-decrypt-on-open t
  "Automatically decrypt SSS files when opening."
  :type 'boolean
  :group 'sss)
```

**Local Variables:**
```elisp
(defvar-local sss--state nil
  "Current state of this sss buffer.
Value is the symbol ='sealed or ='open.")
```

**Hash Tables for Caching:**
```elisp
(defvar sss--password-cache (make-hash-table :test 'equal)
  "Cache for passwords to avoid repeated prompts.")
```

### Regex and Pattern Matching

**Pattern Constants:**
```elisp
(defconst sss-plaintext-pattern "\\(?:⊕\\|o\\+\\){"
  "Regex pattern for SSS plaintext markers.")

(defconst sss-any-pattern "\\(?:⊕\\|o\\+\\|⊠\\){[^}]*}"
  "Regex pattern for any SSS marker.")
```

**Pattern Usage:**
```elisp
(when (string-match "\\(?:⊕\\|o\\+\\|⊠\\){\\([^}]*\\)}" text)
  (match-string 1 text))

(while (re-search-forward sss-plaintext-pattern nil t)
  (cl-incf plaintext-count))
```

### Interactive Features

**Faces (Syntax Highlighting):**
```elisp
(defface sss-open-face
  '((((class color) (background light))
     :background "LightGoldenrod1" :foreground "DarkGreen" :weight bold)
    (((class color) (background dark))
     :background "dark olive green" :foreground "LightYellow" :weight bold)
    (t :inverse-video t))
  "Face for open SSS markers."
  :group 'sss)
```

**Font-lock Keywords:**
```elisp
(defvar sss-font-lock-keywords
  `((sss-plaintext-face
     ("\\(⊕\\|o\\+\\)\\({\\)\\([^}]*\\)\\(}\\)"
      (1 'sss-plaintext-face)
      (2 'sss-braces-face)
      (3 'sss-content-face)
      (4 'sss-braces-face)))
    ...)
  "Font-lock keywords for SSS patterns.")
```

**Transient Menus:**
```elisp
(transient-define-prefix sss-menu ()
  "Main SSS menu."
  :man-page "sss"
  ["Text Operations"
   ("e" "Encrypt region" sss-encrypt-region)
   ("d" "Decrypt region" sss-decrypt-region)])
```

### Error Handling

**Pattern - Command Execution with Status Check:**
```elisp
(let* ((result (sss--run-command args))
       (exit-code (car result))
       (output (cdr result)))
  (unless (zerop exit-code)
    (error "SSS command failed: %s" output)))
```

**Message and User Feedback:**
```elisp
(message "SSS: Pattern %s -> %s" old-pattern new-pattern)
(user-error "Not in an SSS project (no .sss.toml found)")
```

---

## Cross-Language Patterns

### Command/CLI Design

**Rust (`src/main.rs`):**
- Use clap for argument parsing with derive macros
- Feature-gated subcommands: FUSE mount, 9P server
- Conditional command registration based on platform/features

**Emacs Lisp:**
- Wrapper functions call Rust CLI with `--non-interactive` flag
- Parse text output and error codes
- Cache results to avoid repeated CLI calls

### File Path Handling

**Rust:**
- Use `PathBuf` and `Path` throughout
- Canonicalize paths before use
- Validate and resolve relative paths early

**Emacs Lisp:**
- Use `expand-file-name()` for path expansion
- `locate-dominating-file()` for project root detection
- `file-exists-p()`, `directory-files()` for checks

### Data Structures

**Rust:**
- Custom structs with serde Serialize/Deserialize
- TOML for project configuration via `toml` crate
- JSON via `serde_json`

**Emacs Lisp:**
- Alists for structured data: `'((key1 . value1) (key2 . value2))`
- Hash tables for efficient lookups: `(make-hash-table :test 'equal)`
- Plist (property lists) for options: `'(key1 value1 key2 value2)`

---

## Summary

**Rust:** Idiomatic, type-safe, with comprehensive error handling via custom `SssError` enum. Strong emphasis on security (zeroization), clear module organization, and extensive use of result types.

**Emacs Lisp:** Pragmatic, interactive-first design. Uses double-hyphen naming convention for private items. Heavy reliance on optional features (transient, evil) with graceful fallbacks. Command-line integration via subprocess calls with output parsing.

Both languages prioritize readability and clarity over brevity.

---

*Convention analysis: 2026-02-21*
