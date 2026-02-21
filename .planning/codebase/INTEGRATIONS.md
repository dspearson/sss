# External Integrations

**Analysis Date:** 2026-02-21

## APIs & External Services

**None detected** - This is a standalone encryption tool with no external API dependencies.

## Data Storage

**Databases:**
- No database system (SQL or NoSQL) used
- File-based configuration: `.sss.toml` (TOML format)
- User local storage:
  - Config directory: `~/.config/sss/` (Unix) or platform-equivalent via `directories` crate
  - Keystore files stored locally in project `.sss` metadata directory
  - Private keys stored in OS keyring or local config

**File Storage:**
- Local filesystem only
- FUSE mount support for transparent decryption (`src/fuse_fs.rs`)
- WinFSP support for Windows transparent filesystem (`src/winfsp_fs.rs`)
- 9P protocol server support for Plan 9 filesystem access (`src/ninep_fs.rs`)

**Caching:**
- Emacs: In-memory password cache via `sss--password-cache` hash table (configurable timeout, default 300s)
- No server-side caching

## Authentication & Identity

**Auth Provider:**
- Custom - No external auth provider
- Asymmetric key-based (ED25519 Curve25519 via libsodium)
- Per-user private key management
- OS keyring integration:
  - macOS: Keychain
  - Windows: Credential Manager
  - Linux: Secret Service
  - Via `keyring` crate 3.2 (`src/keyring_support.rs`)

**Implementation:**
- `src/crypto.rs` - XChaCha20-Poly1305 encryption, key derivation, sealed boxes
- `src/keystore.rs` - Key storage and retrieval with encryption
- `src/keyring_manager.rs` - Keyring abstraction layer
- User authentication via interactive password prompts (`rpassword` crate)
- Agent-based passwordless key access via `src/commands/agent.rs` and `src/agent_protocol.rs`

## Monitoring & Observability

**Error Tracking:**
- None - Error reporting via CLI output and Emacs minibuffer
- Audit logging: `src/audit_log.rs` - Logs operations to local audit trail

**Logs:**
- Approach: File-based audit logs (project-specific)
- Log location: Within project `.sss/` metadata directory
- No centralized logging service

## CI/CD & Deployment

**Hosting:**
- Not applicable - Standalone CLI tool + Emacs plugin
- Distribution: Source via Git, pre-built binaries, RPM packages

**CI Pipeline:**
- None detected in `.github/` or similar - likely managed externally
- RPM builds: `rpm-build/build-rpm.sh` automates Fedora/RHEL packaging
- Docker containers for build environments: `rpm-build/Dockerfile.*`
- Cross-compilation support via Cargo targets in `.cargo/config.toml`

## Environment Configuration

**Required env vars:**
- None mandatory for basic operation
- Optional: `SSS_CONFIG_DIR` - Override default config directory
- Optional: `SSS_KEYRING_DISABLED` - Disable OS keyring integration
- Emacs-specific:
  - `sss-executable` - Custom path to sss binary
  - `sss-config-directory` - Override config location
  - `sss-default-username` - Default user for operations

**Secrets location:**
- `.sss.toml` - Project users and sealed keys (safe to commit)
- User private keys: OS keyring (preferred) or `~/.config/sss/keys/` (local filesystem)
- Never stored in plaintext `.env` files - File encryption enforced

## Webhooks & Callbacks

**Incoming:**
- Git hooks support: `src/commands/hooks.rs`
  - `pre-commit` - Seal pending changes
  - `post-commit` - Verify sealed state
  - Custom hook configuration in `.sss.toml`

**Outgoing:**
- None detected - Tool operates on local files only

## Git Integration

**Provider:** Git hooks only
- `src/commands/git.rs` - Git repository integration
- Hook automation: `src/commands/hooks.rs` (16KB implementation)
- `.git/hooks/` integration for automatic file sealing before commits
- No GitHub Actions or external CI/CD integration detected

## Emacs Integration Points

**Version 0.1.0 (Modern, `emacs/sss-mode.el`):**
- **Transparent decryption**: `find-file-hook` for auto-decrypt on open
- **Transparent sealing**: `write-contents-functions` for auto-seal on save
- **Marker highlighting**: Font-lock syntax highlighting (⊕{} and ⊠{} patterns)
- **Auto-save disable**: Security feature to prevent plaintext leaks
- **CLI integration**: Direct invocation of sss binary via `call-process`
- **Key bindings**: `C-c C-o` (open), `C-c C-s` (seal), `C-c C-r` (render), etc.
- Entry point: `magic-mode-alist` detection of sealed file marker (`\xe2\x8a\xa0{`)

**Version 1.0 (Multi-file, `plugins/emacs/`):**
- Files: `sss.el`, `sss-mode.el`, `sss-project.el`, `sss-utils.el`, `sss-ui.el`, `sss-doom.el`
- **Region encryption/decryption**: Interactive region operations
- **Project detection**: `.sss.toml` project root discovery
- **Transient menus**: Optional UI via `transient` package (if available)
- **Doom Emacs support**: Evil operator bindings and leader key integration
- **Auth-source integration**: Password caching via `auth-source` (Emacs 30.1+)
- **Advanced features**:
  - Buffer processing
  - File rendering (plaintext extraction)
  - User and key management
  - Pattern navigation
  - Fancy visual mode (encrypted as black bars)

## Security & Key Management

**Key Operations:**
- `src/commands/keys.rs` - Key generation, listing, deletion
- `src/kdf.rs` - Key derivation function (Argon2 via libsodium)
- User keys sealed with ED25519 public keys (asymmetric wrapping)
- Repository symmetric key (XChaCha20-Poly1305) per-user sealed copy

**Key Rotation:**
- `src/rotation.rs` - Key rotation metadata and lifecycle
- Rotation metadata stored in `.sss.toml` under `[rotation]` section

---

*Integration audit: 2026-02-21*
