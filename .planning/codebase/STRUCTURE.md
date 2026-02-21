# Codebase Structure

**Analysis Date:** 2026-02-21

## Directory Layout

```
sss/
├── src/                          # Primary Rust source
│   ├── bin/                      # Binary entry points (sss-agent, sss-askpass-*)
│   ├── commands/                 # Command handlers (mount, init, keys, seal, render, etc.)
│   ├── fuse/                     # FUSE filesystem components (Linux/macOS)
│   ├── marker_inference/         # Marker preservation and inference algorithm
│   ├── processor/                # Content encryption/decryption pipeline
│   ├── main.rs                   # CLI entry point, command routing
│   ├── lib.rs                    # Library exports and module declarations
│   ├── crypto.rs                 # libsodium bindings, KeyPair, RepositoryKey
│   ├── scanner.rs                # File scanning with pattern detection
│   ├── project.rs                # ProjectConfig, user management, TOML serialization
│   ├── config.rs                 # Configuration loading, project root finding
│   ├── keystore.rs               # Persistent key storage, password protection
│   ├── kdf.rs                    # Key derivation functions (KDF parameters)
│   ├── error.rs                  # Error types and conversions
│   ├── validation.rs             # Input validation functions
│   ├── constants.rs              # Constants (max file size, base64 length, etc.)
│   └── [other modules]           # Support modules (agent, audit_log, editor, etc.)
├── tests/                        # Integration tests
├── Cargo.toml                    # Manifest with features (fuse, ninep, winfsp)
├── README.md                     # Project documentation
├── ARCHITECTURE.md               # Existing architecture notes
├── .sss.toml                     # Project configuration (if initialized)
└── docs/                         # Additional documentation

Key subdirectories by layer:
├── src/fuse/                     # FUSE-specific code
│   ├── inode_manager.rs          # Inode allocation and mapping
│   ├── file_cache.rs             # Content caching and handles
│   └── virtual_fs.rs             # Virtual path resolution
├── src/marker_inference/         # Marker algorithm
│   ├── diff.rs                   # Change detection
│   ├── mapper.rs                 # Position mapping
│   ├── propagator.rs             # Duplicate marking
│   ├── validator.rs              # Delimiter validation
│   └── [others]                  # Supporting stages
└── src/processor/                # Processing pipeline
    ├── core.rs                   # Main Processor implementation
    └── marker_parser.rs          # Marker finding and parsing
```

## Directory Purposes

**src:**
- Purpose: All Rust source code
- Contains: Main library code, binaries, command implementations
- Key files: `main.rs` (entry point), `lib.rs` (module exports), `crypto.rs` (cryptography core)

**src/commands:**
- Purpose: Individual command handlers
- Contains: Implementation of each CLI subcommand
- Key files: `init.rs` (initialization), `keys.rs` (key management), `mount.rs` (FUSE mount), `process.rs` (seal/open/render/edit), `project.rs` (project settings)

**src/fuse:**
- Purpose: FUSE filesystem implementation (Linux/macOS only)
- Contains: Inode management, file caching, virtual filesystem operations
- Key files: `inode_manager.rs` (inode allocation), `file_cache.rs` (content cache), `virtual_fs.rs` (path translation)

**src/marker_inference:**
- Purpose: Intelligent marker preservation algorithm
- Contains: 8-step marker inference process for edits
- Key files: `diff.rs` (change detection), `mapper.rs` (position mapping), `propagator.rs` (propagate markers to duplicates), `validator.rs` (validate paired delimiters)

**src/processor:**
- Purpose: Content encryption/decryption with marker handling
- Contains: Processor implementation, marker parsing
- Key files: `core.rs` (main Processor), `marker_parser.rs` (find balanced markers)

**tests:**
- Purpose: Integration and unit tests
- Contains: Test suites for various modules
- Patterns: `*_tests.rs`, `*_edge_cases.rs`, `*_integration.rs` files

**docs:**
- Purpose: Additional documentation
- Contains: System documentation, progress notes, test coverage reports

## Key File Locations

**Entry Points:**
- `src/main.rs`: CLI entry point, command creation, routing to handlers
- `src/bin/sss-agent.rs`: Agent daemon binary
- `src/bin/sss-askpass-tty.rs`: TTY password prompt binary
- `src/bin/sss-askpass-gui.rs`: GUI password prompt binary

**Configuration:**
- `src/config.rs`: Config loading, project root finding, default config paths
- `src/config_manager.rs`: User settings management
- `src/project.rs`: ProjectConfig TOML structure, user enrollment
- `.sss.toml`: Project configuration file (created during init)
- `~/.config/sss/settings.toml`: User settings (keyring preference, default username, editor, etc.)

**Core Logic:**
- `src/crypto.rs`: Cryptographic operations, libsodium bindings
- `src/processor/core.rs`: Main Processor, encrypt/decrypt pipeline
- `src/scanner.rs`: File scanning with SSS pattern detection
- `src/keystore.rs`: Key storage and management
- `src/kdf.rs`: Key derivation parameters and functions

**Testing:**
- `tests/`: All test files
- `tests/*_tests.rs`: Unit/integration test suites
- `tests/*_edge_cases.rs`: Edge case testing
- `tests/*_integration.rs`: End-to-end integration tests

## Naming Conventions

**Files:**
- `*.rs`: Rust source files
- Command handlers: `src/commands/{command}.rs` (e.g., `mount.rs`, `keys.rs`)
- Test files: `tests/{module}_{type}.rs` (e.g., `scanner_edge_cases.rs`, `processor_integration.rs`)
- Binary entry points: `src/bin/{binary_name}.rs` (e.g., `sss-agent.rs`)

**Directories:**
- Module directories: Lowercase with underscores (e.g., `marker_inference`, `src/commands`)
- Subdirectories within modules: Logical grouping (e.g., `src/fuse/` contains FUSE-specific code)

**Modules:**
- Snake_case: All Rust modules and files use lowercase with underscores
- Public modules: Declared in `mod.rs` or parent module with `pub mod`
- Re-exports: Main modules re-export public types in `lib.rs` and submodule `mod.rs`

**Structures/Types:**
- PascalCase: All public structs, enums, traits use PascalCase
- Examples: `ProjectConfig`, `RepositoryKey`, `KeyPair`, `FileScanner`, `Processor`

**Functions:**
- snake_case: All functions use lowercase with underscores
- Command handlers: `handle_{command}` (e.g., `handle_init`, `handle_mount`)
- Builders/constructors: `new`, `new_with_*`, `default`

**Constants:**
- SCREAMING_SNAKE_CASE: All constants use uppercase with underscores
- Examples: `MAX_FILE_SIZE`, `DEFAULT_CONFIG_FILE`, `SYMMETRIC_KEY_SIZE`

## Where to Add New Code

**New Feature:**
- Primary code: Create in appropriate `src/` module or extend existing
  - If filesystem-related: `src/fuse/` (or `src/winfsp_fs.rs` for Windows)
  - If cryptography-related: `src/crypto.rs` or new `src/crypto_*.rs` module
  - If processing-related: `src/processor/` subdirectory
  - If command-related: `src/commands/{command}.rs`
- Tests: `tests/{feature}_tests.rs` or extend existing test file
- Documentation: Add to code comments, update ARCHITECTURE.md if architecture changes

**New Command:**
- Implementation: `src/commands/{command}.rs`
- Handler function: `pub fn handle_{command}(main_matches: &ArgMatches, sub_matches: &ArgMatches) -> Result<()>`
- Registration: Add to `src/commands/mod.rs` exports
- CLI parsing: Add subcommand builder in `src/main.rs` `create_cli_app()` function
- Feature gates: Use `#[cfg(feature = "...")]` if platform-specific

**New Component/Module:**
- Implementation: Create `src/{module_name}/mod.rs` (if submodule) or `src/{module_name}.rs` (if single file)
- Subcomponents: Add to `src/{module_name}/mod.rs` as separate files
- Exports: Re-export public types in `src/{module_name}/mod.rs`
- Library export: Add to `src/lib.rs` if public API

**Utilities:**
- Shared helpers: `src/validation.rs` (validation), `src/error_helpers.rs` (error conversion), `src/toml_helpers.rs` (TOML parsing)
- Constants: `src/constants.rs`
- New utility module: Create `src/{util_name}.rs` if significant size

**Tests:**
- Unit tests: Inline in module (`#[cfg(test)] mod tests { ... }`)
- Integration tests: `tests/{module}_tests.rs` or `tests/{feature}_integration.rs`
- Test fixtures: Store test data in `tests/fixtures/` if needed

## Special Directories

**src/bin:**
- Purpose: Binary entry points (separate from main library binary)
- Generated: No
- Committed: Yes
- Contains: sss-agent, sss-askpass-tty, sss-askpass-gui with separate main() functions

**vendor/rust-9p:**
- Purpose: Vendored 9P library for ninep feature
- Generated: No
- Committed: Yes
- Notes: Included because custom modifications or pinned version needed

**tests:**
- Purpose: Integration and end-to-end tests
- Generated: No (created by developers)
- Committed: Yes
- Patterns: Tests use temporary directories and cleanup after completion

**target:**
- Purpose: Build artifacts
- Generated: Yes (by `cargo build`)
- Committed: No (listed in .gitignore)
- Contains: Compiled binaries, intermediate files, test binaries

**.sss.toml:**
- Purpose: Project configuration (created during `sss init`)
- Generated: Yes (by `sss init`)
- Committed: Yes (safe for git; no secrets stored)
- Contains: Users, key rotation metadata, hooks configuration, ignore patterns

**~/.config/sss/**
- Purpose: User settings and keystore
- Generated: Yes (by first `sss` command or `sss init`)
- Committed: No (user-local)
- Contains: `settings.toml`, `keys/` subdirectory with encrypted key files

## Shared Patterns

**Module Organization:**
- Large modules get a directory with `mod.rs` + component files
- Example: `src/fuse/mod.rs` declares submodules `inode_manager`, `file_cache`, `virtual_fs`
- Small modules stay as single `.rs` files (e.g., `src/crypto.rs`)

**Error Handling:**
- All functions return `anyhow::Result<T>` for flexibility
- Custom `SssError` enum used for specific error categorization
- Context added with `.context()` for user-friendly messages

**Feature Gating:**
- FUSE commands: `#[cfg(all(any(target_os = "linux", target_os = "macos"), feature = "fuse"))]`
- 9P commands: `#[cfg(feature = "ninep")]`
- WinFSP: `#[cfg(all(target_os = "windows", feature = "winfsp"))]`
- Check `Cargo.toml` for feature definitions

**Zeroization:**
- Sensitive types: `#[derive(Zeroize, ZeroizeOnDrop)]`
- Sensitive fields: Explicitly zeroized before drop
- Examples: `RepositoryKey`, `SecretKey`, `DerivedKey`

---

*Structure analysis: 2026-02-21*
