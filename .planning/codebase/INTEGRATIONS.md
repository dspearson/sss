# External Integrations

**Analysis Date:** 2026-02-21

## APIs & External Services

**Editor Integration:**
- Text editor (user-selected) - Spawned for editing encrypted/rendered files via `sss edit`
  - SDK/Client: `std::process::Command` (generic shell execution)
  - Source: `src/editor.rs:13` - Launches $EDITOR environment variable
  - Communication: File path passed as argument; read/write file contents directly

**File System Protocols:**
- FUSE v3 (Linux/macOS) - Transparent filesystem mounting
  - SDK/Client: `fuser` crate 0.14
  - Source: `src/fuse_fs.rs`, `src/commands/mount.rs`
  - Protocol: FUSE protocol v7.23+ over /dev/fuse kernel interface
  - Purpose: Mount sss project at mountpoint with transparent rendering

- 9P2000.L Network Filesystem (cross-platform)
  - SDK/Client: `rs9p` (rust-9p) from vendor directory
  - Source: `src/ninep_fs.rs`, `src/commands/ninep.rs`
  - Protocol: 9P2000.L over TCP or Unix socket
  - Purpose: Network-transparent encrypted filesystem access
  - Address formats: `tcp:host:port` or `unix:path`

**Git Integration:**
- Git hooks (pre-commit, post-merge, post-checkout)
  - Implementation: Shell scripts embedded at compile time
  - Source: `src/commands/hooks.rs:8-10` - Include hook files from `githooks/` directory
  - Communication: Spawned via git hook mechanism; operates on staged files
  - Patterns: Multiplexed hook wrapper (executes hook.d/*.sh in sorted order)

## Data Storage

**Databases:**
- None - This is a stateless CLI tool with no database backend

**File Storage:**
- Local filesystem only
  - Home directory config: `~/.config/sss/` (XDG-compliant via `directories` crate)
  - Keys directory: `~/.config/sss/keys/` (Unix) or platform-specific equivalents
  - Keystore format: JSON files for encrypted keypair metadata
  - Source: `src/keystore.rs:29-55` - Directory management and permissions (0o700)
  - Permissions: Strict (owner read/write/execute only)

**Caching:**
- In-memory secrets cache (encrypted)
  - Implementation: `SecretsCache` struct in `src/secrets.rs`
  - Type: Thread-safe caching for interpolated secrets
  - Lifecycle: Per-process; cleared on program exit

- FUSE metadata caching
  - TTL: 1 second (normal files), 0 seconds (passthrough overlay)
  - Source: `src/fuse_fs.rs:43-44`

## Authentication & Identity

**Auth Provider:**
- Custom asymmetric + symmetric hybrid
  - Public-key cryptography: Ed25519 (Twisted Edwards curve)
  - Symmetric encryption: XChaCha20-Poly1305 (authenticated)
  - Key derivation: Argon2id (password-based)
  - Source: `src/crypto.rs` - libsodium FFI bindings

**Key Management:**
- System Keyring Integration (optional)
  - Providers: macOS Keychain, Windows Credential Manager, Linux Secret Service (D-Bus)
  - SDK/Client: `keyring` crate 3.2
  - Source: `src/keyring_manager.rs`, `src/keyring_support.rs`
  - Service name: "sss"
  - Fallback: File-based storage if keyring unavailable

- Password Input
  - TTY password prompt: `rpassword` crate 7.3
  - GUI askpass: Platform-specific (zenity/kdialog on Linux, osascript on macOS)
  - Source: `src/askpass.rs` - Spawns sss-askpass-tty or sss-askpass-gui binaries

**Credential Files:**
- Project configuration: `.sss.toml` (TOML format)
  - Location: Project root directory
  - Contains: Repository key, user public keys, git hook settings, ignore patterns
  - Source: `src/project.rs`, `src/config.rs`

## Monitoring & Observability

**Error Tracking:**
- None - Application returns errors to CLI (stdout/stderr)

**Logs:**
- Approach: Debug logging via environment variable
  - `SSS_FUSE_DEBUG=1` enables FUSE operation tracing (eprintln!)
  - Source: `src/fuse_fs.rs:22-31` - Conditional debug! macro
  - No structured logging framework

**Audit Logging:**
- Audit log file storage (experimental)
  - Implementation: `src/audit_log.rs`
  - Format: JSON with timestamps
  - Scope: Tracks crypto operations, key access, file operations

## CI/CD & Deployment

**Hosting:**
- None (CLI tool, not a server)
- Distribution: Package repositories or direct binary downloads

**CI Pipeline:**
- GitHub Actions (inferred from repo structure)
  - Location: `.github/workflows/` directory
  - Triggers: Likely on push/PR for testing and binary builds

**Build Artifacts:**
- Debian packages: `debian/build-deb.sh`
- RPM packages: `build-rhel8.sh`, `build-rhel9.sh`
- Alpine/musl static binary: `Dockerfile.alpine`
- macOS cross-compilation: `build-macos-cross.sh`, `build-macos-static.sh`

## Environment Configuration

**Required env vars:**
- None mandatory (feature-complete without environment variables)

**Optional env vars:**
- `EDITOR` - Text editor to use for `sss edit` (default: vi/nano/code detection)
- `SSH_ASKPASS` - Custom askpass program for password prompts
- `SSS_FUSE_DEBUG` - Enable FUSE debug logging (set to "1" or "true")
- Home directory resolution: Inferred from platform (XDG_CONFIG_HOME, APPDATA, Library/Application Support)

**Secrets location:**
- System keyring (macOS/Windows/Linux with Secret Service)
- Local encrypted files: `~/.config/sss/keys/*.json`
- Per-project keys: Stored in `.sss.toml` (base64-encoded symmetric key)

**No .env file support** - Configuration purely via CLI flags, TOML files, and environment variables

## Webhooks & Callbacks

**Incoming:**
- None - This is a CLI tool, not a server

**Outgoing:**
- Git hooks (local only)
  - pre-commit: Seals files before commit
  - post-merge: Renders files after merge/pull
  - post-checkout: Renders files after checkout
  - Source: `src/commands/hooks.rs` - Embedded hook scripts executed by git

- Agent daemon (experimental)
  - IPC: Unix socket communication
  - Source: `src/bin/sss-agent.rs` - Daemon process with policy-based access control
  - Protocol: Custom JSON protocol over socket
  - Purpose: Centralized key management with policy enforcement

## System Calls & Integrations

**Process Management:**
- `std::process::Command` - Generic process spawning
  - Editor launch: `src/editor.rs:13`
  - Askpass helper: `src/askpass.rs:55-60`
  - GUI dialogs: `src/bin/sss-askpass-gui.rs` (zenity/kdialog/osascript)
  - Git passthrough: `src/commands/git.rs`

**Filesystem Operations:**
- `std::fs` - Standard file I/O
  - Read/write project files
  - Directory traversal with `walkdir` 2.4
  - Symlink handling (if not excluded)

- FUSE kernel interface (optional)
  - Source: `src/fuse_fs.rs` - Direct FUSE v3 protocol via /dev/fuse
  - Operations: lookup, getattr, read, write, mkdir, unlink, etc.
  - Inode caching with synthetic inodes for virtual files

- 9P kernel interface (optional)
  - Source: `src/ninep_fs.rs` - 9P2000.L protocol server
  - Async I/O via tokio

**Terminal I/O:**
- TTY detection: `atty` 0.2 - Detects if output is interactive
- Signal handling: `ctrlc` 3.4 - Graceful shutdown on Ctrl-C

**Cryptographic Libraries:**
- libsodium (system or statically linked)
  - FFI bindings: `libsodium-sys` 0.2
  - Source: `src/crypto.rs` - Direct C library calls
  - Functions: crypto_secretbox, crypto_box, crypto_sign, crypto_pwhash, crypto_generichash

**Memory Operations:**
- Zeroization: `zeroize` crate
  - Applied to: Passwords, plaintext secrets, derived keys
  - Source: `src/crypto.rs`, `src/secure_memory.rs`
  - Prevents data leakage in memory dumps

## Platform-Specific Integrations

**Linux:**
- FUSE v3 kernel interface
- D-Bus Secret Service (via `keyring` crate) for credential storage
- systemd-style installation paths (XDG_CONFIG_HOME)

**macOS:**
- macFUSE or fuse-t FUSE implementation
- Keychain credential storage (via `keyring` crate)
- osascript for GUI password prompts

**Windows:**
- WinFSP filesystem extension (optional)
- Windows Credential Manager (via `keyring` crate)
- kdialog or custom GUI for password prompts

---

*Integration audit: 2026-02-21*
