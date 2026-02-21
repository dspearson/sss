# Technology Stack

**Analysis Date:** 2026-02-21

## Languages

**Primary:**
- Rust 2024 edition - Core application (`src/`) - encryption, filesystem operations, project management
- Emacs Lisp - Emacs integration (two locations: `emacs/sss-mode.el` v0.1.0 and `plugins/emacs/` multi-file implementation v1.0)
- Shell/Bash - Build scripts and RPM packaging (`rpm-build/`)

## Runtime

**Environment:**
- Linux (primary) - FUSE/macFUSE support, 9P protocol support
- macOS - FUSE (macFUSE), 9P protocol support
- Windows - WinFSP support via `winfsp` feature
- Emacs - Version 27.1+ (new mode) and 30.1+ (multi-file plugin)

**Package Manager:**
- Cargo - Rust package management (version 1.1.9)
- Emacs Package System - Emacs Lisp dependencies via `package-requires`

## Frameworks

**Core:**
- Clap 4.5.47 - CLI argument parsing and command structure
- Tokio 1.x - Async runtime (optional, for `ninep` feature)
- TOML 0.8 - Configuration file parsing

**Filesystem:**
- FUSE 0.14 (fuser crate) - FUSE filesystem on Linux/macOS (`fuse` feature, optional)
- WinFSP 0.12 - Windows filesystem driver support (`winfsp` feature, optional)
- 9P protocol (rs9p/rust-9p) - Plan 9 network filesystem (`ninep` feature, optional)

**Cryptography:**
- libsodium-sys 0.2 - FFI to libsodium C library for encryption
- Zeroize 1.8 - Secure memory wiping (derives ZeroizeOnDrop)

**Testing:**
- Proptest 1.5 - Property-based testing
- Criterion 0.5 - Benchmarking framework
- Serial Test 3.0 - Sequential test execution
- Tempfile 3.21.0 - Temporary file/directory creation

**Build/Dev:**
- Cargo (cross-compilation support) - Multiple target architectures configured in `.cargo/config.toml`
- RPM build toolchain - Fedora/RHEL package generation
- Emacs bytecode compilation - `.elc` files for Emacs Lisp

## Key Dependencies

**Critical:**
- libsodium-sys 0.2 - Core cryptographic primitive provider (XChaCha20-Poly1305, BLAKE2b, curve25519)
- keyring 3.2 - OS keyring/credential manager integration (macOS Keychain, Windows Credential Manager, Linux Secret Service)
- zeroize 1.8 - Memory zeroing to prevent key leaks

**Infrastructure:**
- Serde 1.0 - Serialization/deserialization (TOML, JSON)
- Anyhow 1.0.99 - Error handling
- Chrono 0.4 - Timestamp handling
- UUID 1.6 - Unique identifier generation
- Base64 0.22 - Encoding/decoding
- Regex 1.10 - Pattern matching for ignore patterns, marker detection
- Globset 0.4 - Gitignore-style pattern matching
- Walkdir 2.4 - Directory traversal
- Aho-Corasick 1.1 - Pattern matching optimization
- Shell-escape 0.1 - Shell argument escaping
- Rpassword 7.3 - Interactive password prompting
- Directories 5.0, Dirs 5.0 - Platform-specific directory paths
- Thiserror 1.0 - Error trait derivation
- Once-cell 1.20 - Lazy static initialization
- Libc 0.2.177 - System calls
- Subtle 2.5 - Constant-time comparison (for cryptographic verification)
- Atty 0.2 - TTY detection
- Ctrlc 3.4 - Signal handling (Ctrl-C)
- Similar 2.3 - Diff calculation for merge operations
- Tempfile 3.21.0 - Temporary file management

**Emacs Lisp (plugins/emacs):**
- auth-source (Emacs 30.1+) - Password caching and credential management
- cl-lib - Common Lisp compatibility
- subr-x - Extended subroutine library
- sss-mode - Core mode support
- transient - Optional UI transient menus for Doom integration

**Emacs Lisp (emacs/sss-mode.el):**
- Emacs 27.1+ built-ins: find-file-hook, write-contents-functions, font-lock
- No external dependencies

## Configuration

**Environment:**
- `.sss.toml` - Project-level configuration (users, hooks, rotation metadata, ignore patterns)
- `~/.config/sss/` - User configuration directory (platform-specific via `directories` crate)
- `.cargo/config.toml` - Cross-compilation targets:
  - `x86_64-unknown-linux-musl` (musl libc)
  - `aarch64-unknown-linux-musl`
  - `armv7-unknown-linux-musleabihf`
  - `x86_64-pc-windows-gnu`
  - `aarch64-apple-darwin`
  - `x86_64-apple-darwin`
- Emacs customization:
  - `sss-executable` - Path to sss binary (absolute path for daemon mode)
  - `sss-config-directory` - Override SSS config location
  - `sss-password-cache-timeout` - Cache duration (default 300s)
  - `sss-highlight-patterns` - Syntax highlighting toggle
  - `sss-fancy-mode` - Visual rendering mode

**Build:**
- `Cargo.toml` - Package manifest with conditional features (`fuse`, `winfsp`, `ninep`)
- `rpm-build/sss.spec` - RPM package specification
- `rpm-build/build-rpm.sh` - RPM build automation
- `rpm-build/Dockerfile.*` - Container builds for RHEL8, RHEL9, RHEL10, Fedora42

## Platform Requirements

**Development:**
- Rust toolchain (edition 2024) with Cargo
- libsodium-devel (>= 1.0.14) - Development headers
- Emacs 27.1+ (for new mode) or 30.1+ (for multi-file plugin)
- Optional: FUSE3 development headers (for `fuse` feature)
- Optional: Docker - For RPM container builds
- Optional: Doom Emacs - For `sss-doom.el` integration

**Production:**
- Linux, macOS, or Windows system
- libsodium >= 1.0.14 (runtime)
- FUSE3 (Linux/macOS, if using `mount` command)
- WinFSP (Windows, if using `mount` command)
- Emacs 27.1+ (for Emacs integration)

---

*Stack analysis: 2026-02-21*
