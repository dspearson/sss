# Technology Stack

**Analysis Date:** 2026-02-21

## Languages

**Primary:**
- Rust 2024 edition - Core CLI application with strong type safety and memory safety guarantees
- Shell (Bash) - Git hooks and installation scripts

**Secondary:**
- Binary protocols (9P, FUSE) - Filesystem-level interactions

## Runtime

**Environment:**
- Cargo-based Rust build system (1.70+ minimum for edition 2024)
- Standalone compiled binaries (no JVM, no runtime dependency)

**Package Manager:**
- Cargo - Rust package manager
- Lockfile: `Cargo.lock` present at `/zpool/94c687ec-4c9c-45fe-90f2-3ab8ae2c309f/sss/Cargo.lock`

## Frameworks

**Core:**
- `clap` 4.5.47 - Command-line argument parsing with derive macros
- `anyhow` 1.0.99 - Error handling and context propagation

**Cryptography & Security:**
- `libsodium-sys` 0.2 - FFI bindings to libsodium (XChaCha20-Poly1305, BLAKE2b, Argon2id)
- `zeroize` 1.8 with derive feature - Memory zeroization for sensitive data
- `base64` 0.22 - Base64 encoding/decoding for key material

**Filesystem Operations:**
- `fuser` 0.14 (optional, Linux/macOS) - FUSE v3 filesystem bindings
- `rs9p` (vendored from pfpacket/rust-9p, optional) - 9P2000.L protocol implementation
- `parking_lot` 0.12 (optional) - High-performance synchronization primitives for FUSE/9P
- `walkdir` 2.4 - Recursive directory traversal
- `globset` 0.4 - .gitignore-style glob pattern matching

**Windows (optional):**
- `winfsp` 0.12 (optional, Windows only) - Windows filesystem extension
- `widestring` 1.1 (optional, Windows only) - Wide string utilities for Windows APIs
- `winapi` 0.3 (optional, Windows only) - Windows API bindings

**Async Runtime (9P server only):**
- `tokio` 1.x with "full" features (optional) - Async runtime for serve9p
- `tokio-stream` 0.1 (optional) - Stream extensions for async I/O
- `async-trait` 0.1 (optional) - Async trait support
- `nix` 0.26 (optional) - Unix system call bindings

**Serialization:**
- `serde` 1.0 with derive feature - Data serialization framework
- `serde_json` 1.0 - JSON serialization
- `toml` 0.8 - TOML configuration parsing

**Utilities:**
- `chrono` 0.4 with serde feature - DateTime handling
- `uuid` 1.6 with v4 feature - UUID generation
- `regex` 1.10 - Regular expression matching for marker detection
- `similar` 2.3 - Diffing algorithm for merge operations
- `aho-corasick` 1.1 - Fast multi-pattern string searching
- `tempfile` 3.21.0 - Temporary file/directory creation
- `which` 4.4 - Locate executables in PATH
- `shell-escape` 0.1 - Shell argument escaping
- `keyring` 3.2 - System keyring access (macOS Keychain, Windows Credential Manager, Linux Secret Service)
- `rpassword` 7.3 - Secure password input from terminal
- `directories` 5.0 - XDG/platform-specific directory paths
- `ctrlc` 3.4 - Signal handling for graceful shutdown
- `atty` 0.2 - TTY detection
- `thiserror` 1.0 - Error type macro derivation
- `subtle` 2.5 - Constant-time comparison (for cryptographic operations)
- `once_cell` 1.20 - Lazy static initialization
- `libc` 0.2.177 - C library bindings
- `dirs` 5.0 - User directory resolution

**Testing (dev-dependencies):**
- `tempfile` 3.21.0 - Temporary file fixtures
- `proptest` 1.5 - Property-based testing
- `criterion` 0.5 - Micro-benchmarking framework
- `serial_test` 3.0 - Sequential test execution (prevents race conditions)

## Key Dependencies

**Critical:**
- `libsodium-sys` 0.2 - Provides cryptographic primitives (XChaCha20-Poly1305, BLAKE2b, Argon2id). Must be stable and well-maintained. Linked to native libsodium C library.
- `zeroize` 1.8 - Essential for clearing sensitive data from memory. Non-negotiable for crypto operations.
- `walkdir` 2.4 - Core dependency for file system traversal during sealing/opening operations
- `globset` 0.4 - Critical for ignore pattern matching (.sss.toml patterns)

**Infrastructure:**
- `fuser` 0.14 - FUSE v3 bindings (Linux/macOS only). Enables transparent file rendering via filesystem mount
- `tokio` 1.x - Async runtime (only when ninep feature enabled). Powers 9P2000.L network filesystem
- `keyring` 3.2 - System credential storage integration. Platform-dependent availability

## Configuration

**Environment:**
- No environment variables required for basic operation
- `SSS_FUSE_DEBUG=1` - Optional debug logging for FUSE operations (checked at runtime in `fuse_fs.rs:38`)
- Platform detection: Rust cfg attributes handle Linux/macOS/Windows at compile time

**Build:**
- `.cargo/config.toml` - Cross-compilation targets configured (MUSL, ARM, macOS, Windows)
- `build.rs` - Vendored rust-9p setup: auto-clones and patches vendor/rust-9p for nix 0.26 compatibility

**Feature Flags:**
- `fuse` - Enables FUSE filesystem support (requires libfuse3-dev). Adds `fuser`, `parking_lot`
- `winfsp` - Enables Windows filesystem support. Adds `winfsp`, `widestring`, `winapi`
- `ninep` - Enables 9P server (serve9p command). Adds `rs9p` (vendored), `tokio`, `tokio-stream`, `async-trait`, `nix`

## Platform Requirements

**Development:**
- Rust 1.70+ with edition 2024 support
- Cargo
- For FUSE support: libfuse3-dev (Linux) or macFUSE (macOS)
- libsodium development libraries (libsodium-dev or equivalent)
- C compiler (gcc/clang)
- GNU make

**Production:**
- Linux (x86_64, ARM64, ARMv7) or macOS (x86_64, ARM64) or Windows
- libsodium installed (or statically linked)
- Optional: FUSE v3 kernel support (for mount subcommand)
- Optional: System keyring daemon (D-Bus service for Linux)

**Distribution Targets:**
- Debian/Ubuntu (.deb via debian/build-deb.sh)
- RHEL/CentOS 8+ (RPM via build-rhel8.sh / build-rhel9.sh)
- Alpine/musl (Static binary via Dockerfile.alpine)
- macOS (Cross-compilation scripts: build-macos-cross.sh, build-macos-static.sh)

---

*Stack analysis: 2026-02-21*
