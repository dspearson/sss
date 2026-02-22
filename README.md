# sss - Secret String Substitution

Transparent encryption of secrets within files using XChaCha20-Poly1305, with multi-user key management and git integration.

## Features

- **Marker-based encryption** -- wrap secrets with `⊕{secret}` or `o+{secret}`; sss seals them in-place
- **Multi-user architecture** -- hybrid X25519 + XChaCha20-Poly1305 encryption; each user holds their own keypair
- **Git integration** -- pre-commit, post-merge, and post-checkout hooks maintain sealed state automatically
- **Key derivation** -- Argon2id with configurable security levels (sensitive / moderate / interactive)
- **Deterministic nonces** -- BLAKE2b-derived nonces produce clean git diffs
- **Marker inference** -- intelligent marker preservation when editing rendered files
- **Secrets files** -- interpolation from `.secrets` files with YAML-style multi-line values
- **System keyring** -- native OS credential storage (macOS Keychain, Windows Credential Manager, Linux Secret Service)
- **Emacs integration** -- `sss-mode` provides transparent decrypt-on-open and re-seal-on-save
- **FUSE filesystem** -- mount a project with transparent rendering (Linux/macOS, optional)
- **WinFSP filesystem** -- mount a project with transparent rendering (Windows, optional)
- **9P server** -- network-transparent file access (optional)
- **Agent daemon** -- key caching with policy-based access control (experimental)
- **Password strength analysis** -- real-time feedback during key generation with pattern detection
- **Ignore patterns** -- gitignore-style pattern matching for project-wide operations
- **Secrets interpolation** -- reference named secrets from external files with `⊲{name}` syntax
- **Editor integration** -- `ssse` symlink provides transparent edit-in-place from any editor

## Installation

### Build from Source

```bash
git clone <repository-url>
cd sss
cargo build --release
# Binaries are in target/release/
```

### Optional Features

Build with FUSE support (Linux/macOS):

```bash
# Debian/Ubuntu
sudo apt-get install libfuse3-dev fuse3
# Fedora/RHEL
sudo dnf install fuse3-devel fuse3
# macOS: install macFUSE from https://osxfuse.github.io/

cargo build --features fuse --release
```

Build with WinFSP support (Windows):

```bash
# Install WinFSP from https://winfsp.dev/
cargo build --features winfsp --release
```

Build with 9P server support:

```bash
cargo build --features ninep --release
```

Build with all optional features (Linux/macOS):

```bash
cargo build --features fuse,ninep --release
```

### Pre-built Packages

Pre-built packages are available via build scripts:

- **Debian/Ubuntu** -- `debian/build-deb.sh`
- **RHEL/CentOS** -- `rpm-build/build-rpm.sh`
- **Alpine/musl** -- `Dockerfile.alpine`

See [docs/INSTALLATION.md](docs/INSTALLATION.md) for platform-specific instructions including macOS cross-compilation and development environment setup.

## Quick Start

1. **Generate a keypair**

   ```bash
   sss keys generate
   ```

   You will be prompted for a passphrase to protect your private key. A password strength indicator provides real-time feedback.

2. **Initialise a project**

   ```bash
   sss init alice
   ```

   This creates `.sss.toml` in the current directory and adds you as the first user.

3. **Mark secrets in a file**

   ```bash
   echo "password=⊕{my-secret-password}" > config.txt
   ```

4. **Seal the file**

   ```bash
   sss seal -x config.txt
   # config.txt now contains: password=⊠{base64-ciphertext}
   ```

5. **Open the file**

   ```bash
   sss open config.txt
   # Outputs: password=⊕{my-secret-password}
   ```

## String Patterns

| Marker | Type | Description |
|--------|------|-------------|
| `⊕{content}` | Plaintext | UTF-8 marker (U+2295) |
| `o+{content}` | Plaintext | ASCII alternative |
| `⊠{content}` | Ciphertext | Sealed form (U+22A0), always UTF-8 |
| `⊲{name}` | Interpolation | Reference a named secret from a secrets file (U+22B2) |

The `⊕` and `o+` forms are interchangeable on input. After sealing, all markers become `⊠{...}`.

See [docs/marker-format.md](docs/marker-format.md) for the complete syntax reference including BNF grammar and ciphertext payload layout.

## Command Reference

### Global Flags

These flags can be used with any command:

```bash
sss --confdir <DIR> ...        # Override config directory location
sss --non-interactive ...      # Fail if passphrase not in SSS_PASSPHRASE env var
sss --kdf-level <LEVEL> ...    # KDF security level: sensitive (default), moderate, interactive
```

### File Operations

```bash
sss seal <file>          # Seal plaintext markers (output to stdout)
sss seal -x <file>       # Seal in-place
sss seal --project       # Seal all files in project
sss open <file>          # Unseal to plaintext markers (output to stdout)
sss open -x <file>       # Unseal in-place
sss open --project       # Unseal all files (requires project permission)
sss render <file>        # Unseal and strip markers (bare secret values)
sss render -x <file>     # Render in-place
sss render --project     # Render all files (requires project permission)
sss edit <file>          # Unseal, open in $EDITOR, re-seal on save
sss status               # Show project root path
```

All file commands accept `-` to read from stdin.

### Key Management

```bash
sss keys generate                    # Generate new keypair (with passphrase prompt)
sss keys generate --no-password      # Generate keypair without passphrase
sss keys list                        # List private keys
sss keys pubkey                      # Show your public key
sss keys pubkey --fingerprint        # Show key fingerprint only
sss keys pubkey --user <name>        # Show another user's public key
sss keys current                     # Show which key is active
sss keys current <key-id>            # Set active key by ID or partial ID
sss keys delete <key-id>             # Delete a keypair
sss keys set-passphrase <key-id>     # Set or change passphrase on a key
sss keys remove-passphrase <key-id>  # Remove passphrase protection from a key
sss keys rotate                      # Rotate project key (re-encrypts all files)
sss keys rotate --force              # Skip confirmation prompt
sss keys rotate --dry-run            # Preview what would be changed
sss keys rotate --no-backup          # Skip creating backup copies
```

### User Management

Users can be managed via `sss users` or `sss project users` (equivalent):

```bash
sss users list                       # List project users
sss users add <user> <pubkey>        # Add user (file or base64 public key)
sss users remove <user>              # Remove user (triggers key rotation)
sss users info <user>                # Show information about a user
```

### Project Management

```bash
sss init [username]                  # Initialise project
sss project show                     # Show settings for current project
sss project list                     # List all configured projects
sss project enable <feature>         # Enable render or open for project-wide ops
sss project disable <feature>        # Disable render or open
sss project remove [path]            # Remove project from settings
```

**Ignore patterns** (control which files are processed by `--project` operations):

```bash
sss project ignore list              # Show all ignore patterns
sss project ignore add <pattern>     # Add a glob pattern (e.g., '*.log', 'build/**')
sss project ignore remove <pattern>  # Remove a pattern
```

**Secrets file configuration:**

```bash
sss project secrets-file show        # Show configured secrets filename
sss project secrets-file set <name>  # Set custom secrets filename
sss project secrets-file clear       # Revert to default ("secrets")
```

### Settings

```bash
sss settings show                    # Show current settings
sss settings location                # Show config file locations
sss settings set --username <name>   # Set default username
sss settings set --editor <editor>   # Set preferred editor
sss settings set --coloured <bool>   # Enable/disable coloured output
sss settings set --kdf-level <level> # Set KDF security level for new keys
sss settings set --use-keyring <bool> # Enable/disable system keyring
sss settings set --secrets-filename <name>   # Set default secrets filename
sss settings set --secrets-suffix <suffix>   # Set default secrets file suffix
sss settings reset --confirm         # Reset all settings to defaults
```

### Git Hooks

```bash
sss hooks install                    # Install hooks into current repo
sss hooks install --multiplex        # Use multiplexed hook structure (.d/ directories)
sss hooks install --template         # Install to git template directory
sss hooks list                       # List available hooks
sss hooks show <hook>                # Show contents of a specific hook
sss hooks export                     # Export hooks to ~/.config/sss/hooks/
```

See [docs/usage-guide.md](docs/usage-guide.md) for complete workflow documentation.

## Multi-User Collaboration

1. Each user generates their own keypair with `sss keys generate`
2. Each user shares their public key: `sss keys pubkey > username.pub`
3. The project owner adds each user: `sss users add <username> <pubkey-file>`

All users can then seal and open files independently using their own private key. When a user is removed, key rotation is automatically triggered -- the project key is regenerated and all sealed files are re-encrypted so the removed user can no longer decrypt anything.

See [docs/usage-guide.md](docs/usage-guide.md#team-collaboration) for the full team collaboration workflow.

## Secrets Files

Secrets files hold named values that can be interpolated into sealed files using the `⊲{name}` syntax:

```
# .secrets file
database_password: hunter2
api_token: sk-abcdef1234567890

# Multi-line value (YAML-style pipe)
ssh_private_key: |
  -----BEGIN OPENSSH PRIVATE KEY-----
  b3BlbnNzaC1rZXktdjEAAAA...
  -----END OPENSSH PRIVATE KEY-----
```

Reference a secret by name in any file:

```
DATABASE_URL=postgres://admin:⊲{database_password}@localhost/app
```

See [docs/SECRETS_FILE_FORMAT.md](docs/SECRETS_FILE_FORMAT.md) for the format specification and [docs/SECRETS_PARSING_GUIDE.md](docs/SECRETS_PARSING_GUIDE.md) for integration guidance.

## Environment Variables

| Variable | Purpose |
|----------|---------|
| `SSS_PASSPHRASE` | Non-interactive passphrase entry (automation, CI/CD) |
| `SSS_KDF_LEVEL` | Override KDF security level (sensitive/moderate/interactive) |
| `SSS_USE_KEYRING` | Enable system keyring for key storage (true/false) |
| `SSS_USER` | Override username for project operations |
| `SSS_PROJECT_OPEN` | Bypass project-wide open permission check (true/1) |
| `SSS_PROJECT_RENDER` | Bypass project-wide render permission check (true/1) |
| `SSS_DEVEL_MODE` | Enable experimental features (agent daemon) |
| `EDITOR` / `VISUAL` | Preferred editor for `sss edit` |

See [docs/configuration.md](docs/configuration.md) for the full configuration reference.

## Security

Cryptographic primitives:

| Purpose | Algorithm |
|---------|-----------|
| Authenticated encryption | XChaCha20-Poly1305 (via libsodium) |
| Key derivation | Argon2id |
| Key exchange | X25519 (crypto_box_seal) |
| Identity | Ed25519 |
| Nonce derivation | BLAKE2b keyed hash |

**What is encrypted:** the content inside `⊕{...}` / `o+{...}` markers only. File structure, key names, and surrounding text are not encrypted.

**Nonce design:** nonces are derived deterministically from the plaintext and key, which produces clean git diffs but reveals when a secret value changes.

**Memory protection:** decrypted key material is zeroised on drop via the `zeroize` crate.

**Rate limiting:** authentication attempts are rate-limited to mitigate brute-force attacks.

See [docs/security-model.md](docs/security-model.md) for the full security model including Argon2id parameter levels, threat model, and key hierarchy. See [docs/CRYPTOGRAPHY.md](docs/CRYPTOGRAPHY.md) for detailed cryptographic implementation notes.

## Emacs Integration

`emacs/sss-mode.el` (v1.1) is a single-file Emacs package providing transparent encryption for sss-sealed files.

**Core behaviour** (unchanged from v1.0):

- Sealed files (`⊠{...}`) are automatically decrypted on open -- plaintext `⊕{...}` markers are visible for editing
- Re-sealed on save -- plaintext never touches disk
- Font-lock highlighting for open and sealed marker forms
- Mode-line indicator (`SSS[open]` / `SSS[sealed]`)

**New in v1.1:**

- Region encrypt/decrypt: `C-c C-e` / `C-c C-d`
- Toggle marker state at point: `C-c C-t`
- Preview decrypted secret at point (transient overlay): `C-c C-v`
- Overlay mode for visual marker highlighting (`sss-toggle-overlay-mode`)
- Auth-source integration -- passphrase cached via `~/.authinfo` (no repeated prompts)
- Transient command menu with `completing-read` fallback: `C-c C-m`

**Evil integration** (when `evil` is loaded, sss-mode buffers only):

- `ge` / `gd` / `gt` -- encrypt / decrypt / toggle operators (compose with any motion)
- `is` / `as` -- inner / outer SSS text objects (use with `v`, `d`, `c`, etc.)

**Doom Emacs** (when Doom is detected):

- `SPC e` -- global leader prefix for encryption commands
- `, e` -- localleader prefix for sss-mode buffers

**Installation (vanilla Emacs):**

```elisp
(add-to-list 'load-path "/path/to/sss/emacs/")
(require 'sss-mode)
```

**Doom Emacs setup:** Copy `emacs/sss-mode.el` to `~/.config/doom/lisp/`, then add to `config.el`:

```elisp
(load! "lisp/sss-mode")
```

See [docs/sss-mode-guide.md](docs/sss-mode-guide.md) for full installation options, daemon-mode configuration, key binding reference, and troubleshooting.

## Optional Features

### FUSE Filesystem (Linux/macOS)

Mount a project directory with transparent rendering -- all files appear as plain text, git operations see the sealed originals.

```bash
sss mount <source-dir> <mountpoint>
sss mount --in-place                   # Overlay mount on current directory
sss mount --foreground <src> <mnt>     # Run in foreground (don't daemonise)
sss mount --read-only <src> <mnt>      # Read-only mount
```

Use `sss git` from within a FUSE mount to run git commands against the underlying (sealed) directory:

```bash
sss git status
sss git commit -m "Update secrets"
```

### WinFSP Filesystem (Windows)

On Windows with [WinFSP](https://winfsp.dev/) installed, the `mount` command provides the same transparent rendering:

```bash
sss mount <source-dir> <mountpoint>
```

Build with `cargo build --features winfsp --release`.

### 9P Server

Serve a project over a 9P network socket for cross-platform access.

```bash
sss serve9p tcp:0.0.0.0:564
sss serve9p unix:/tmp/sss-9p.sock
sss serve9p tcp:localhost:5640 -d /path/to/project -u alice
```

File access modes via the 9P server:

| Path | View |
|------|------|
| `file` | Rendered (fully decrypted, markers stripped) |
| `file.open` | Opened (with `⊕{...}` markers) |
| `file.sealed` | Sealed (with `⊠{...}` markers, raw) |

### Agent Daemon (Experimental)

`sss-agent` caches decrypted keys in memory with policy-based access control. Requires `SSS_DEVEL_MODE=1`.

```bash
export SSS_DEVEL_MODE=1
sss agent start                        # Start the agent daemon
sss agent start --foreground           # Run in foreground
sss agent start --key-id <id>          # Load a specific key
sss agent status                       # Check agent status
sss agent lock                         # Lock agent (deny all requests)
sss agent unlock                       # Unlock agent
sss agent stop                         # Stop the agent daemon
```

Policy management:

```bash
sss agent policies list                # List all policies
sss agent policies add <hostname>      # Allow a host
sss agent policies add <host> --project <path>  # Restrict to a project
sss agent policies remove <hostname>   # Remove a host
sss agent policies clear               # Clear all policies
```

### Editor Symlink (ssse)

Symlink or copy the `sss` binary as `ssse` to get a transparent edit command. When invoked as `ssse <file>`, it automatically opens the file, launches your editor, and re-seals on save -- equivalent to `sss edit <file>`.

```bash
ln -s /path/to/sss /usr/local/bin/ssse
ssse config.txt
```

## Building and Development

**Requirements:** Rust 2024 edition (1.85+), libsodium (linked automatically by `libsodium-sys`)

```bash
cargo test                                   # Run all tests
cargo test --lib                             # Unit tests only
cargo clippy -- -D warnings                  # Linting
```

**Binaries produced:**

| Binary | Description |
|--------|-------------|
| `sss` | Main CLI tool |
| `sss-agent` | Key management daemon (Unix) |
| `sss-askpass-tty` | TTY confirmation helper for agent |
| `sss-askpass-gui` | GUI confirmation helper for agent |

### Source Layout

| Path | Description |
|------|-------------|
| `src/main.rs` | CLI definition and command routing |
| `src/lib.rs` | Library root |
| `src/crypto.rs` | Core cryptographic operations (libsodium bindings) |
| `src/processor/` | Marker detection and transformation pipeline |
| `src/marker_inference/` | Intelligent marker preservation for edited files |
| `src/commands/` | CLI command handlers |
| `src/config.rs` | Project configuration (.sss.toml) |
| `src/config_manager.rs` | User settings management |
| `src/keystore.rs` | Local encrypted key storage |
| `src/keyring_support.rs` | System keyring integration |
| `src/secrets.rs` | Secrets file parsing and interpolation |
| `src/scanner.rs` | Project directory scanner with ignore patterns |
| `src/rotation.rs` | Key rotation and file re-encryption |
| `src/merge.rs` | Smart merge algorithm for marker inference |
| `src/validation.rs` | Input validation and DoS protection |
| `src/secure_memory.rs` | Memory protection and zeroisation |
| `src/editor.rs` | Editor integration for `sss edit` |
| `src/fuse_fs.rs` | FUSE filesystem implementation |
| `src/winfsp_fs.rs` | WinFSP filesystem implementation |
| `src/ninep_fs.rs` | 9P server implementation |
| `src/agent.rs` | Agent daemon core |
| `src/agent_protocol.rs` | Agent wire protocol |
| `src/agent_policy.rs` | Agent policy engine |
| `src/audit_log.rs` | Agent audit logging |
| `src/rate_limiter.rs` | Authentication rate limiting |
| `src/kdf.rs` | Key derivation function parameters |
| `emacs/sss-mode.el` | Emacs integration package |

## Documentation

| Document | Description |
|----------|-------------|
| [docs/usage-guide.md](docs/usage-guide.md) | Common workflows: setup, seal/open/edit/render, key management, team collaboration, git hooks |
| [docs/configuration.md](docs/configuration.md) | Configuration reference: .sss.toml, settings.toml, environment variables |
| [docs/security-model.md](docs/security-model.md) | Security model: algorithms, key hierarchy, threat model |
| [docs/marker-format.md](docs/marker-format.md) | Marker syntax reference: BNF grammar, ciphertext payload format |
| [docs/architecture.md](docs/architecture.md) | Technical architecture: processor pipeline, marker inference, FUSE, 9P |
| [docs/sss-mode-guide.md](docs/sss-mode-guide.md) | Emacs sss-mode installation and usage |
| [docs/INSTALLATION.md](docs/INSTALLATION.md) | Detailed installation and development environment guide |
| [docs/CRYPTOGRAPHY.md](docs/CRYPTOGRAPHY.md) | Cryptographic implementation details |
| [docs/KEY_MANAGEMENT.md](docs/KEY_MANAGEMENT.md) | Key management guide |
| [docs/SECRETS_FILE_FORMAT.md](docs/SECRETS_FILE_FORMAT.md) | Secrets file specification |
| [docs/SECRETS_PARSING_GUIDE.md](docs/SECRETS_PARSING_GUIDE.md) | Secrets file parsing and integration guide |
| [docs/IGNORE_PATTERNS.md](docs/IGNORE_PATTERNS.md) | Ignore pattern syntax and behaviour |
| [ARCHITECTURE.md](ARCHITECTURE.md) | Protocol specification |
| [SECURITY.md](SECURITY.md) | Security policy and vulnerability disclosure |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Contribution guidelines |
| [CHANGELOG.md](CHANGELOG.md) | Version history |
| [LICENCE](LICENCE) | ISC licence |

### Tutorials

Step-by-step guides for common scenarios:

| Tutorial | Description |
|----------|-------------|
| [docs/tutorials/01-getting-started.md](docs/tutorials/01-getting-started.md) | First-time setup and basic seal/open workflow |
| [docs/tutorials/02-team-collaboration.md](docs/tutorials/02-team-collaboration.md) | Adding team members and sharing secrets |
| [docs/tutorials/03-git-integration.md](docs/tutorials/03-git-integration.md) | Git hooks and version control workflow |
| [docs/tutorials/04-editor-workflow.md](docs/tutorials/04-editor-workflow.md) | Editor integration (Emacs, ssse, $EDITOR) |
| [docs/tutorials/05-fuse-mounting.md](docs/tutorials/05-fuse-mounting.md) | FUSE filesystem transparent rendering |
| [docs/tutorials/06-project-configuration.md](docs/tutorials/06-project-configuration.md) | Project settings, ignore patterns, secrets files |

## Licence

ISC -- see the [LICENCE](LICENCE) file for details.

## Acknowledgements

- Built with [libsodium](https://libsodium.gitbook.io/) for cryptographic operations
- FUSE support via [fuser](https://github.com/cberner/fuser)
- WinFSP support via [winfsp-rs](https://crates.io/crates/winfsp)
- 9P server via [pfpacket/rust-9p](https://github.com/pfpacket/rust-9p)
- Diff algorithm via [similar](https://github.com/mitsuhiko/similar)
- Multi-pattern matching via [aho-corasick](https://github.com/BurntSushi/aho-corasick)
