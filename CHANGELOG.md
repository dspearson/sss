# Changelog

All notable changes to sss (Secret String Substitution) will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2026-04-26

### Added
- **Hybrid Post-Quantum Suite (opt-in)**: opt-in KEM for per-user repository-key wrapping
  - trelis (X448 + sntrup761) KEM → BLAKE3 KDF → XChaCha20-Poly1305 AEAD seals the repo key per user
  - `sss init --crypto <classic|hybrid>` selects the cryptographic suite at project creation; `classic` is the default
  - In-file AEAD ciphertexts (`⊠{...}` markers) are byte-identical regardless of suite — only `.sss.toml` per-user entries differ
  - `hybrid` Cargo feature flag gates all trelis code; default build links only libsodium
- **Keystore dual-suite support**: per-user keystore holds classic and hybrid keypairs side-by-side
  - `sss keys generate --suite <classic|hybrid|both>` — `--suite` is required; no default
  - Upgrading an existing keystore never destroys the classic keypair
  - Argon2id passphrase-wrapping covers both suite's private keys via the same KDF path
- **Migration command** (`sss migrate`): upgrades a v1.0 classic repo to v2.0 hybrid
  - Re-wraps the repository key for every user under the hybrid KEM; bumps `.sss.toml` version
  - Exits non-zero with a user list if any user lacks a hybrid public key, preventing partial writes
  - `sss migrate --dry-run` prints the full plan without touching disk
- **User hybrid-key registration** (`sss users add-hybrid-key <user> <pubkey>`): records a user's hybrid public key in `.sss.toml` as a prerequisite for migration
- **Suite-aware type system**: `PublicKey`, `KeyPair` widened to suite-aware enums; cross-suite operation attempts fail loudly

### Security
- **EXPERIMENTAL — trelis is unaudited**: the hybrid KEM (trelis X448 + sntrup761) has not undergone a formal third-party security audit; hybrid is opt-in and disabled by default; classic (libsodium) remains the recommended default
- Hybrid secret key material zeroised on drop via `ZeroizeOnDrop`; no plaintext K material persists in hybrid wrap/unwrap types after use
- v1 binary emits a clear, actionable error when pointed at a v2.0 `.sss.toml` (no silent corruption, no panic)

### Changed
- `.sss.toml` `version` field now dispatches cryptographic suite: `"1.0"` → classic, `"2.0"` → hybrid
- Per-user `sealed_key` entries in `.sss.toml` are approximately 1448 base64 characters larger in v2.0 (1167 bytes raw vs 80 bytes raw)

### Fixed
- Key fingerprint display: box header labels shortened to `[CLASSIC]` and `[PQCRYPT]` — both 7 chars, giving symmetric 4-dash padding on each side; previously `[SSS KEY (Classic)]` overflowed the 17-char box interior by 2 chars
- Redundant `Classic keypair:` / `Hybrid keypair:` prefix lines removed; the box label is self-describing

## [1.2.0] - 2025-03-15

### Added
- **Security Hardening**: Strengthened key derivation and password protection
  - Default KDF security level upgraded from `interactive` to `sensitive` (4 iterations, 256 MiB RAM)
  - Configurable KDF levels: `sensitive` (default), `moderate`, `interactive`
  - Global `--kdf-level` CLI flag for all commands
  - `SSS_KDF_LEVEL` environment variable support
  - User settings for KDF level via `~/.config/sss/settings.toml`
- **System Keyring Integration**: Native OS credential storage
  - macOS Keychain, Windows Credential Manager, Linux Secret Service (gnome-keyring, kwallet)
  - Automatic keyring availability detection with graceful fallback
  - `SSS_USE_KEYRING` environment variable to enable keyring storage
  - User settings for keyring via configuration
  - Keys stored with format: `STORED_IN_KEYRING` in TOML when using keyring
- **Password Strength Analysis**: Real-time password security feedback
  - Visual strength indicators with color coding (Very Weak to Very Strong)
  - Character variety analysis (length, uppercase, lowercase, numbers, symbols)
  - Pattern detection (repeated characters, sequential characters)
  - Strength-based recommendations and warnings
  - New `read_new_password_with_requirements()` function for enforcing minimum strength
  - Automatic strength display during password creation
- **Settings Commands for Security**:
  - `sss settings set --kdf-level <LEVEL>`: Configure KDF security level
  - `sss settings set --use-keyring <true|false>`: Enable/disable system keyring
  - `sss settings show`: Display current KDF level and keyring status
  - Keyring availability checking with helpful error messages
- **Security Warnings**: Enhanced user feedback for security decisions
  - Prominent warnings when storing keys without password protection
  - Recommendations for password protection vs system keyring
  - File path disclosure in warnings for easier troubleshooting
  - Keyring unavailability warnings with platform-specific guidance
- **Comprehensive Security Documentation**:
  - `docs/SECURITY.md`: Complete threat model, security architecture, and best practices
    - Detailed threat analysis (T1-T6) with mitigations
    - Cryptographic architecture overview
    - Key management hierarchy and storage options
    - Security features (AEAD, memory safety, constant-time operations)
    - Known limitations and security audit history
  - `docs/CRYPTOGRAPHY.md`: In-depth cryptographic implementation details
    - Algorithm specifications (XChaCha20-Poly1305, X25519, Argon2id, BLAKE2b)
    - Nonce derivation mechanism explanation
    - Key derivation flows and cost estimates
    - Memory safety patterns and implementation details
    - Code examples for complete encryption/decryption flows
  - `docs/KEY_MANAGEMENT.md`: Practical key management guide
    - Complete key lifecycle documentation
    - Team key management workflows
    - Backup and recovery procedures
    - Security best practices for individuals, teams, and CI/CD
    - Troubleshooting common issues
- **Security Test Suites**: 50 new security-focused tests
  - `tests/crypto_security_tests.rs`: 17 tests for cryptographic security
    - Nonce uniqueness and determinism validation
    - Decryption failure tests (wrong key, tampered ciphertext)
    - KDF timing consistency checks
    - Keypair and salt randomness verification
  - `tests/kdf_security_tests.rs`: 20 tests for KDF security
    - Parameter validation for all security levels
    - Salt uniqueness testing (1000 salts)
    - Password handling (empty, Unicode, long passwords)
    - Output randomness and distribution checks
  - `tests/keystore_integration_tests.rs`: 13 tests for key lifecycle
    - Password-protected and passwordless key storage
    - Passphrase changes and removal
    - Multiple keys with different passwords
    - Current key management and deletion
- `SSS_PASSPHRASE` environment variable for non-interactive password entry
  - Works with password-protected private keys
  - Useful for automation and VS Code extension integration
  - Replaces separate test mode environment variables
- `SSS_PROJECT_OPEN` environment variable to bypass project-wide open permission checks
  - Set to `true` or `1` to enable
  - Allows `sss open --project` in automation contexts
- `SSS_PROJECT_RENDER` environment variable to bypass project-wide render permission checks
  - Set to `true` or `1` to enable
  - Allows `sss render --project` in automation contexts
- `sss keys set-passphrase <key-id>` command for passphrase management
  - Add passphrase protection to unprotected keys
  - Change existing passphrase
  - Re-encrypts private key without generating new key
- `sss keys remove-passphrase <key-id>` command to remove passphrase protection
  - Converts password-protected key to unprotected storage
  - Displays security warning about storing unencrypted keys
- Multi-key matching fallback in project configuration loading
  - Automatically tries all available keypairs when current key doesn't match project
  - Displays helpful messages when matching alternative keys
  - Provides clear error messages listing available project users when no keys match
- Comprehensive test suite for multi-key matching scenarios
- YAML-style multi-line value support in `.secrets` files
  - Use pipe indicator syntax: `key: |` followed by indented lines
  - Preserves empty lines within multi-line values
  - Maintains relative indentation for nested structures (JSON, YAML, etc.)
  - Backward compatible with existing single-line `key: value` format
  - Supports quoted keys with multi-line values
  - Ideal for SSH keys, certificates, database connection strings, and JSON configs
- Configurable secrets file names and suffixes
  - Project-level configuration via `.sss.toml`: `secrets_filename` and `secrets_suffix` fields
  - Global user configuration via `~/.config/sss/settings.toml`: same fields
  - Project config takes precedence over user config, which takes precedence over defaults
  - Default filename: `"secrets"`, default suffix: `".secrets"`
  - Examples: Use `".sealed"` suffix for `config.yaml.sealed` secrets files
  - Or use custom filename like `"passwords"` for centralized secrets file
- SECURITY.md for security policy and vulnerability disclosure
- CONTRIBUTING.md for contribution guidelines
- CHANGELOG.md for tracking version history

### Changed
- **BREAKING (Behavioral)**: Default KDF security level changed from `interactive` to `sensitive`
  - New keys generated with ~2 second derivation time (vs ~0.5 seconds)
  - Provides stronger protection against brute-force attacks (256 MiB RAM, 4 iterations)
  - Backward compatible: existing keys retain their original KDF parameters
  - Can be overridden with `--kdf-level interactive` for faster generation
- Enhanced `Keystore` to accept configurable KDF parameters and keyring preference
  - Added `kdf_params` field to store KDF configuration
  - Added `use_keyring` field for keyring integration
  - Multiple constructors: `new()`, `new_with_kdf_params()`, `new_with_config_dir_and_kdf()`
- Updated password confirmation flow to show strength indicators by default
  - `read_password_with_confirmation()` now displays strength and warnings
  - Backward compatible with explicit `read_password_with_confirmation_and_strength()`
- Improved security warnings with clearer messaging and actionable recommendations
  - File paths shown in warnings for better user guidance
  - Platform-specific keyring installation instructions
- Updated test helpers to use `interactive` KDF for faster test execution
  - All security properties maintained, only affects test speed
- Updated .gitignore to exclude build artifacts and temporary files
- Unified test and production password handling to use `SSS_PASSPHRASE`
- Enhanced `load_project_config_internal()` to support fallback key matching
- Added `Clone` derive to `KeyPair` struct for multi-key matching support

### Fixed
- Removed unused `extract_base_from_protocol` function in ninep_fs.rs
- Fixed all clippy warnings (5 warnings resolved)
- Added `.truncate(true)` to file creation in 9P server

### Removed
- Old backup directories (sss-old, sss-master)
- Temporary build artifacts and documentation files
- `SSS_TEST_MODE` and `SSS_TEST_PASSWORD` environment variables (replaced by `SSS_PASSPHRASE`)

## [1.1.1] - 2025-01-19

### Changed
- Refactored codebase for improved maintainability
- Enhanced documentation coverage
- Improved test isolation with RAII guards

### Fixed
- Test directory restoration issues
- Clippy warnings for unused variables
- Rustdoc link resolution issues

## [1.1.0] - 2025-01-15

### Added
- 9P server support for cross-platform network-transparent file access
  - pfpacket/rust-9p implementation with auto-clone build system
  - Automatic nix 0.26 compatibility patching
  - File access modes: .open (editable), .sealed (raw), default (rendered)
  - TCP and Unix socket server support
- Auto-clone build system for 9P dependencies
- Virtual filesystem with transparent decrypt-on-read
- Smart reconstruction algorithm for writes

### Changed
- Switched from google/rust-9p to pfpacket/rust-9p for better virtual filesystem support
- Improved 9P documentation in ARCHITECTURE.md

### Removed
- Shadow directory architecture for 9P (replaced with virtual filesystem)

## [1.0.0] - 2025-01-01

### Added
- Multi-user architecture with asymmetric + symmetric encryption
- XChaCha20-Poly1305 authenticated encryption
- Deterministic nonce generation via BLAKE2b for clean git diffs
- Argon2id key derivation for password-protected keys
- Ed25519 keypairs for user identity
- Project-based key management with sealed keys per user
- Key rotation with automatic re-encryption
- Git hooks for automatic seal/open operations
- Smart merge algorithm for rendered files
- Secrets file support with interpolation
- FUSE filesystem support (Linux/macOS)
- Per-project permission settings
- Ignore patterns for project-wide operations
- Rate limiting for password attempts
- Comprehensive test suite (187 tests)
- Property-based testing with proptest
- Memory protection with zeroization
- Secure temporary file handling
- Input validation with DoS protection
- Custom error types for better error handling
- System keyring integration
- Editor integration (ssse command)
- ASCII alternatives for UTF-8 markers
- Verb-based command interface (seal/open/render/edit)
- Username resolution from environment variables
- Support for both ed25519 and curve25519 keys
- Comprehensive ARCHITECTURE.md documentation
- Man pages for all commands

### Security
- Authenticated encryption with integrity verification
- No nonce reuse (deterministic but unique per plaintext)
- Forward security via key rotation
- Memory zeroization for sensitive data
- Constant-time comparison for secrets
- Path traversal protection
- Size limits for DoS prevention
- No secret leakage in error messages

## [0.9.0] - 2024-12-01 (Beta)

### Added
- Initial beta release
- Basic encryption/decryption functionality
- Single-user support
- Manual seal/open operations

### Known Issues
- No multi-user support
- Manual key management
- Limited git integration

---

## Version Naming Convention

- **Major** (X.0.0): Breaking changes, major new features
- **Minor** (1.X.0): New features, backward compatible
- **Patch** (1.1.X): Bug fixes, minor improvements

## Categories

### Added
New features and capabilities

### Changed
Changes in existing functionality

### Deprecated
Features that will be removed in future versions

### Removed
Features that have been removed

### Fixed
Bug fixes

### Security
Security-related changes and fixes

---

## Links

- [Repository](https://github.com/OWNER/sss)
- [Issue Tracker](https://github.com/OWNER/sss/issues)
- [Security Policy](SECURITY.md)
- [Contributing Guidelines](CONTRIBUTING.md)

---

For detailed technical documentation, see [ARCHITECTURE.md](ARCHITECTURE.md).
