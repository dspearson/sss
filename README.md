# sss - Secret String Substitution

Transparent encryption of secrets within files using XChaCha20-Poly1305, with multi-user key management and git integration.

## Features

- **Marker-based encryption** — wrap secrets with `⊕{secret}` or `o+{secret}`; sss seals them in-place
- **Multi-user architecture** — hybrid X25519 + XChaCha20-Poly1305 encryption; each user holds their own keypair
- **Git integration** — pre-commit, post-merge, and post-checkout hooks maintain sealed state automatically
- **Key derivation** — Argon2id with configurable security levels (sensitive / moderate / interactive)
- **Deterministic nonces** — BLAKE2b-derived nonces produce clean git diffs
- **Marker inference** — intelligent marker preservation when editing rendered files
- **Secrets files** — interpolation from `.secrets` files with YAML-style multi-line values
- **System keyring** — native OS credential storage (macOS Keychain, Windows Credential Manager, Linux Secret Service)
- **Emacs integration** — `sss-mode` provides transparent decrypt-on-open and re-seal-on-save
- **FUSE filesystem** — mount a project with transparent rendering (Linux/macOS, optional)
- **9P server** — network-transparent file access (optional)
- **Agent daemon** — key caching with policy-based access control (experimental)

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

Build with 9P server support:

```bash
cargo build --features ninep --release
```

### Pre-built Packages

Pre-built packages are available via build scripts:

- **Debian/Ubuntu** — `debian/build-deb.sh`
- **RHEL/CentOS** — `rpm-build/build-rpm.sh`
- **Alpine/musl** — `Dockerfile.alpine`

See [docs/INSTALLATION.md](docs/INSTALLATION.md) for platform-specific instructions including macOS cross-compilation.

## Quick Start

1. **Generate a keypair**

   ```bash
   sss keys generate
   ```

   You will be prompted for a passphrase to protect your private key.

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

The `⊕` and `o+` forms are interchangeable on input. After sealing, all markers become `⊠{…}`.

See [docs/marker-format.md](docs/marker-format.md) for the complete syntax reference including BNF grammar and ciphertext payload layout.

## Core Commands

### File Operations

```bash
sss seal <file>          # Seal plaintext markers (output to stdout)
sss seal -x <file>       # Seal in-place
sss open <file>          # Unseal to plaintext markers (output to stdout)
sss open -x <file>       # Unseal in-place
sss render <file>        # Unseal and strip markers (bare secret values)
sss edit <file>          # Unseal, open in $EDITOR, re-seal on save
```

### Project

```bash
sss init [username]                          # Initialise project
sss status                                   # Show project root
sss seal --project                           # Seal all files in project
sss open --project                           # Unseal all files
sss render --project                         # Render all files
```

### Key Management

```bash
sss keys generate                            # Generate new keypair
sss keys list                                # List private keys
sss keys pubkey                              # Show your public key
sss keys rotate                              # Rotate project key (re-encrypts all files)
```

### Users

```bash
sss project users list                       # List project users
sss project users add <user> <pubkey>        # Add user (file or base64)
sss project users remove <user>              # Remove user (triggers rotation)
```

### Git Hooks

```bash
sss hooks install                            # Install hooks into current repo
sss hooks list                               # Show available hooks
```

See [docs/usage-guide.md](docs/usage-guide.md) for complete workflow documentation.

## Multi-User Collaboration

1. Each user generates their own keypair with `sss keys generate`
2. Each user shares their public key: `sss keys pubkey > username.pub`
3. The project owner adds each user: `sss project users add <username> <pubkey-file>`

All users can then seal and open files independently using their own private key.

See [docs/usage-guide.md](docs/usage-guide.md#team-collaboration) for the full team collaboration workflow.

## Security

Cryptographic primitives:

| Purpose | Algorithm |
|---------|-----------|
| Authenticated encryption | XChaCha20-Poly1305 (via libsodium) |
| Key derivation | Argon2id |
| Key exchange | X25519 (crypto_box_seal) |
| Identity | Ed25519 |
| Nonce derivation | BLAKE2b keyed hash |

**What is encrypted:** the content inside `⊕{…}` / `o+{…}` markers only. File structure, key names, and surrounding text are not encrypted.

**Nonce design:** nonces are derived deterministically from the plaintext and key, which produces clean git diffs but reveals when a secret value changes.

**Memory protection:** decrypted key material is zeroised on drop via the `zeroize` crate.

See [docs/security-model.md](docs/security-model.md) for the full security model including Argon2id parameter levels, threat model, and key hierarchy.

## Emacs Integration

`emacs/sss-mode.el` (v1.1) is a single-file Emacs package providing transparent encryption for sss-sealed files.

**Core behaviour** (unchanged from v1.0):

- Sealed files (`⊠{…}`) are automatically decrypted on open — plaintext `⊕{…}` markers are visible for editing
- Re-sealed on save — plaintext never touches disk
- Font-lock highlighting for open and sealed marker forms
- Mode-line indicator (`SSS[open]` / `SSS[sealed]`)

**New in v1.1:**

- Region encrypt/decrypt: `C-c C-e` / `C-c C-d`
- Toggle marker state at point: `C-c C-t`
- Preview decrypted secret at point (transient overlay): `C-c C-v`
- Overlay mode for visual marker highlighting (`sss-toggle-overlay-mode`)
- Auth-source integration — passphrase cached via `~/.authinfo` (no repeated prompts)
- Transient command menu with `completing-read` fallback: `C-c C-m`

**Evil integration** (when `evil` is loaded, sss-mode buffers only):

- `ge` / `gd` / `gt` — encrypt / decrypt / toggle operators (compose with any motion)
- `is` / `as` — inner / outer SSS text objects (use with `v`, `d`, `c`, etc.)

**Doom Emacs** (when Doom is detected):

- `SPC e` — global leader prefix for encryption commands
- `, e` — localleader prefix for sss-mode buffers

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

Mount a project directory with transparent rendering — all files appear as plain text, git operations see the sealed originals.

```bash
sss mount <source-dir> <mountpoint>
```

### 9P Server

Serve a project over a 9P network socket for cross-platform access.

```bash
sss serve9p tcp:0.0.0.0:564
```

### Agent Daemon (Experimental)

`sss-agent` caches decrypted keys in memory with policy-based access control. Requires `SSS_DEVEL_MODE=1`.

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

## Documentation

| Document | Description |
|----------|-------------|
| [docs/usage-guide.md](docs/usage-guide.md) | Common workflows: setup, seal/open/edit/render, key management, team collaboration, git hooks |
| [docs/configuration.md](docs/configuration.md) | Configuration reference: .sss.toml, settings.toml, environment variables |
| [docs/security-model.md](docs/security-model.md) | Security model: algorithms, key hierarchy, threat model |
| [docs/marker-format.md](docs/marker-format.md) | Marker syntax reference: BNF grammar, ciphertext payload format |
| [docs/architecture.md](docs/architecture.md) | Technical architecture: processor pipeline, marker inference, FUSE, 9P |
| [docs/sss-mode-guide.md](docs/sss-mode-guide.md) | Emacs sss-mode installation and usage |
| [ARCHITECTURE.md](ARCHITECTURE.md) | Protocol specification |
| [SECURITY.md](SECURITY.md) | Security policy and vulnerability disclosure |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Contribution guidelines |
| [CHANGELOG.md](CHANGELOG.md) | Version history |
| [LICENCE](LICENCE) | ISC licence |
| [docs/CRYPTOGRAPHY.md](docs/CRYPTOGRAPHY.md) | Cryptographic implementation details |
| [docs/KEY_MANAGEMENT.md](docs/KEY_MANAGEMENT.md) | Key management guide |
| [docs/SECRETS_FILE_FORMAT.md](docs/SECRETS_FILE_FORMAT.md) | Secrets file specification |
| [docs/INSTALLATION.md](docs/INSTALLATION.md) | Detailed installation guide |

## Licence

ISC — see the [LICENCE](LICENCE) file for details.

## Acknowledgements

- Built with [libsodium](https://libsodium.gitbook.io/) for cryptographic operations
- FUSE support via [fuser](https://github.com/cberner/fuser)
- 9P server via [pfpacket/rust-9p](https://github.com/pfpacket/rust-9p)
- Diff algorithm via [similar](https://github.com/mitsuhiko/similar)
- Multi-pattern matching via [aho-corasick](https://github.com/BurntSushi/aho-corasick)
