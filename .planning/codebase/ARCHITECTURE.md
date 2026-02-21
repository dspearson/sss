# Architecture

**Analysis Date:** 2026-02-21

## Pattern Overview

**Overall:** Layered command-driven encryption service with transparent filesystem abstraction

**Key Characteristics:**
- CLI-driven architecture with modular command handlers
- Content-agnostic encryption/decryption with marker-based detection
- Multi-layer processing: parsing → marker detection → encryption → rendering
- Pluggable filesystem backends (FUSE on Linux/macOS, 9P protocol, WinFSP on Windows)
- Editor integration via Emacs modes (two independent implementations)
- Deterministic encryption for reproducible sealed content

## Layers

**CLI & Command Routing:**
- Purpose: Parse arguments and dispatch to command handlers
- Location: `src/main.rs` (CLI app creation, routing)
- Contains: clap-based argument parsing, feature-gated command registration
- Depends on: `src/commands/*` modules
- Used by: Entry point for all user interactions

**Commands Layer:**
- Purpose: Handle specific operations (init, keys, project, encrypt/decrypt)
- Location: `src/commands/` (20+ files: init.rs, keys.rs, process.rs, mount.rs, etc.)
- Contains: CLI handlers that orchestrate multi-step workflows
- Depends on: Processor, Config, ProjectConfig, Keystore, Keyring
- Used by: main.rs dispatcher

**Processor Core:**
- Purpose: Content transformation (encrypt plaintext markers, decrypt sealed content, render to raw)
- Location: `src/processor/core.rs` (main Processor impl, 500+ lines)
- Contains: `encrypt_content()`, `decrypt_content()`, `process_content()`, `render_content()`
- Depends on: crypto module, secrets module, marker_inference
- Used by: Command handlers, FUSE/9P filesystem layers

**Marker Detection & Parsing:**
- Purpose: Identify and extract content between `⊕{}`, `o+{}`, `⊠{}` delimiters with balanced brace counting
- Location: `src/processor/marker_parser.rs`, `src/marker_inference/` (9 files)
- Contains: balanced brace counter, marker type detection (plaintext vs ciphertext)
- Depends on: None (pure string algorithms)
- Used by: Processor, marker_inference pipeline

**Marker Inference (Smart Preservation):**
- Purpose: Preserve encryption markers during file edits (user edits plaintext rendering, system determines what to re-mark)
- Location: `src/marker_inference/mod.rs` (8 files: diff.rs, expander.rs, mapper.rs, propagator.rs, reconstructor.rs, parser.rs, validator.rs)
- Contains: Diff computation, expansion rules, delimiter validation, propagation logic
- Depends on: similar crate (diff algorithm), marker_parser
- Used by: edit command, marker inference pipelines

**Secrets Interpolation:**
- Purpose: Replace `⊲{secret}` or `<{secret}` markers with values from project secrets file
- Location: `src/secrets.rs` (300+ lines)
- Contains: SecretsCache, `interpolate_secrets()`, file system trait for secrets lookup
- Depends on: None (optional feature)
- Used by: Processor during rendering

**Cryptography:**
- Purpose: XChaCha20-Poly1305 encryption/decryption with deterministic nonces
- Location: `src/crypto.rs` (300+ lines)
- Contains: `KeyPair`, `RepositoryKey`, `encrypt_to_base64()`, `decrypt_from_base64()`
- Depends on: libsodium-sys, base64
- Used by: Processor, key management commands

**Key Management:**
- Purpose: Generate, store, rotate, and retrieve keypairs
- Location: `src/keystore.rs` (400+ lines), `src/keyring_manager.rs`, `src/keyring_support.rs`
- Contains: KDF (Argon2), passphrase-protected key storage, system keyring integration
- Depends on: keyring crate (macOS Keychain, Windows Credential Manager, Linux Secret Service)
- Used by: commands/keys.rs, config loading

**Configuration Management:**
- Purpose: Load/save project config (.sss.toml), user settings (~/.config/sss/)
- Location: `src/config.rs`, `src/config_manager.rs`, `src/project.rs`
- Contains: ProjectConfig (users, sealed keys), user keypairs, ignore patterns, settings
- Depends on: toml, serde, globset
- Used by: All command handlers

**Filesystem Abstraction (FUSE):**
- Purpose: Provide transparent decryption on file read, encryption on file write via mounted filesystem
- Location: `src/fuse_fs.rs` (800+ lines), `src/fuse/` (4 files: mod.rs, inode_manager.rs, file_cache.rs, virtual_fs.rs)
- Contains: FUSE filesystem implementation with file handle tracking, inode management, mode dispatch
- Depends on: fuser crate, processor
- Used by: mount command (Linux/macOS only)
- Modes: Rendered (fully decrypted), Opened (⊕{} markers visible), Sealed (⊠{} markers on disk)

**9P Protocol (Network Filesystem):**
- Purpose: Expose encrypted project over network via 9P protocol (Plan 9 file service)
- Location: `src/ninep_fs.rs` (600+ lines)
- Contains: 9P server, message handling, authentication
- Depends on: rs9p (vendor/rust-9p), tokio, async-trait
- Used by: serve9p command (experimental)

**Windows Filesystem (WinFSP):**
- Purpose: Windows equivalent of FUSE filesystem
- Location: `src/winfsp_fs.rs`
- Contains: WinFSP service implementation
- Depends on: winfsp crate
- Used by: mount command (Windows only, feature-gated)

**Audit & Logging:**
- Purpose: Track operations for compliance and debugging
- Location: `src/audit_log.rs`
- Contains: Operation logging, timestamp recording
- Depends on: Standard IO
- Used by: Command handlers

**File Scanning & Validation:**
- Purpose: Recursively find files with SSS patterns, validate ignore patterns
- Location: `src/scanner.rs` (200+ lines), `src/validation.rs`
- Contains: FileScanner with globset-based filtering, pattern validation
- Depends on: walkdir, globset, regex
- Used by: seal/open commands with --project flag

## Data Flow

**Encryption Flow (Plaintext → Sealed):**

1. User calls `sss seal file.txt` (or auto-triggered on save in FUSE)
2. Command handler loads ProjectConfig (.sss.toml) → gets RepositoryKey
3. Processor.seal() called with file content
4. Processor finds all plaintext markers: `⊕{...}` or `o+{...}`
5. For each marker: extract content → encrypt with RepositoryKey (deterministic nonce) → base64
6. Replace marker: `⊕{plaintext}` → `⊠{base64ciphertext}`
7. Write sealed content to file
8. FUSE: Store to backing store, return rendered view

**Decryption Flow (Sealed → Plaintext):**

1. User calls `sss open file.txt` (or auto-triggered on open in FUSE/Emacs)
2. Processor finds all sealed markers: `⊠{base64ciphertext}`
3. For each marker: extract base64 → decrypt with RepositoryKey → validate plaintext
4. Replace marker: `⊠{ciphertext}` → `⊕{plaintext}`
5. Return plaintext-marked content (markers still visible)

**Rendering Flow (Any → Raw Text):**

1. User calls `sss render file.txt`
2. Processor finds all markers (both `⊕{}` and `⊠{}`)
3. For each marker: extract content, decrypt if `⊠{}`, interpolate if `⊲{}`
4. Remove all marker syntax: `⊕{password}` → `password`
5. Return raw plaintext with all markers stripped

**Edit Flow (Roundtrip with Marker Preservation):**

1. User calls `sss edit file.txt` or edits in FUSE mount
2. Processor.render() → show plaintext without markers to user
3. User edits content
4. Processor.infer_markers() computes:
   - Parse original markers from sealed file
   - Diff: compare rendered original vs user's edited version
   - Apply 5 expansion rules to determine new marker positions
   - Propagate markers to duplicates of edited content
   - Validate paired delimiters (e.g., JSON braces)
5. Reconstruct file with new marker positions
6. Encrypt with seal step

**State Management:**

- Project-wide: `.sss.toml` TOML file (git-safe, contains users and sealed repository keys)
- User-specific: `~/.config/sss/keys` directory (private keypair + settings)
- Secrets: `secrets` or custom filename in project root (plaintext key=value pairs, git-ignored)
- Transient: Processor caches SecretsCache for interpolation during single operation

## Key Abstractions

**Processor:**
- Purpose: Encapsulates content transformation logic
- Examples: `src/processor/core.rs`, public API: `encrypt_content()`, `decrypt_content()`, `process_content()`, `render_content()`, `infer_markers()`
- Pattern: Pass repository key + project context at creation, stateless content transformation

**ProjectConfig:**
- Purpose: Represents .sss.toml metadata
- Examples: `src/project.rs` — contains users map, sealed repository key per user, ignore patterns, rotation metadata
- Pattern: Loaded from TOML, serialized via serde

**RepositoryKey:**
- Purpose: Symmetric key shared across project (sealed in .sss.toml for each user)
- Examples: `src/crypto.rs` — 32-byte ChaCha20 key
- Pattern: Deterministic encryption when paired with context (file path + timestamp)

**KeyPair:**
- Purpose: User's asymmetric cryptographic identity
- Examples: `src/crypto.rs` — Ed25519 keypair, stored in keystore with optional passphrase
- Pattern: Generate once, use to seal/unseal repository key per project

**FileScanner:**
- Purpose: Recursively locate files containing SSS patterns with gitignore-style filtering
- Examples: `src/scanner.rs` — uses globset for ignore patterns, respects .git/.cargo/target
- Pattern: Builder pattern for configuration, returns Vec<PathBuf>

**Marker Inference Pipeline:**
- Purpose: Multi-step algorithm for smart marker preservation
- Examples: `src/marker_inference/` — 8 modules (parser, diff, mapper, expander, propagator, reconstructor, validator, delimiter)
- Pattern: Each step adds information; final reconstruction outputs with canonical `⊕{}` format

## Entry Points

**CLI Entry:**
- Location: `src/main.rs:main()`
- Triggers: Binary execution `sss [command] [args]`
- Responsibilities: CLI parsing, feature-gated command registration, command dispatching

**Editor Integration Entry:**
- Location: `src/main.rs:main()` (special case when binary called as `ssse`)
- Triggers: `ssse file.txt` symlink or renamed binary
- Responsibilities: Shortcut for edit workflow without full CLI

**Init Command:**
- Location: `src/commands/init.rs`
- Triggers: `sss init [username]`
- Responsibilities: Create .sss.toml, generate repository key, prompt for keypair creation

**Process/Seal Command:**
- Location: `src/commands/process.rs`
- Triggers: `sss seal file.txt`, `sss seal --project`
- Responsibilities: Find plaintext markers, encrypt, write sealed content

**Mount Command:**
- Location: `src/commands/mount.rs` (Linux/macOS with FUSE feature)
- Triggers: `sss mount source /mnt/decrypted`
- Responsibilities: Start FUSE daemon, handle decryption on read, encryption on write

**Serve9P Command:**
- Location: `src/commands/ninep.rs`
- Triggers: `sss serve9p tcp:0.0.0.0:564`
- Responsibilities: Start 9P protocol server for network filesystem access

## Error Handling

**Strategy:** Layered error recovery with warnings rather than hard failures

**Patterns:**
- Large files (>100MB): Skip with warning, continue processing
- Oversized markers (>1MB): Skip encryption, keep original
- Decryption failures: Log warning, return original ciphertext unchanged
- Missing secrets: Log warning, leave `⊲{secret}` intact
- Path canonicalization: Fallback to as-is path if canonicalize fails

**Error Types:**
- `SssError` enum in `src/error.rs` — domain-specific errors
- `anyhow::Result<T>` for propagation with context
- Command handlers return `Result<()>` for CLI

## Cross-Cutting Concerns

**Logging:**
- stderr output from Processor (warnings, debug messages)
- FUSE_DEBUG environment variable enables verbose FUSE logging
- SSS_FUSE_DEBUG=1 flag

**Validation:**
- Marker syntax validation in parser (balanced braces)
- Ciphertext base64 validation on decrypt
- Plaintext UTF-8 validation
- File size limits (MAX_FILE_SIZE 100MB, MAX_MARKER_CONTENT_SIZE 1MB)

**Authentication:**
- Passphrase prompt via rpassword (interactive) or SSS_PASSPHRASE env var (non-interactive)
- KDF: Argon2id with configurable security levels (sensitive, moderate, interactive)
- System keyring caching optional

**Security:**
- Zeroization of passphrases and keys in memory (zeroize crate)
- Deterministic encryption (same plaintext + context → same ciphertext)
- Secure memory: zeroize buffers after use
- No plaintext written to disk in FUSE (except brief window during edit in memory)

---

*Architecture analysis: 2026-02-21*
