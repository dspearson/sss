# Changelog

All notable changes to sss (Secret String Substitution) will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- SECURITY.md for security policy and vulnerability disclosure
- CONTRIBUTING.md for contribution guidelines
- CHANGELOG.md for tracking version history

### Changed
- Updated .gitignore to exclude build artifacts and temporary files

### Fixed
- Removed unused `extract_base_from_protocol` function in ninep_fs.rs
- Fixed all clippy warnings (5 warnings resolved)
- Added `.truncate(true)` to file creation in 9P server

### Removed
- Old backup directories (sss-old, sss-master)
- Temporary build artifacts and documentation files

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
