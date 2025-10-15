# SSS - Secret String Substitution

SSS is a command-line tool for transparent encryption and decryption of text within files using XChaCha20-Poly1305 with a modern multi-user architecture. It enables seamless protection of sensitive data embedded in configuration files, scripts, and other text documents.

## Quick Start

### Installation

#### Build from Source

```bash
git clone https://github.com/dspearson/sss.git
cd sss
cargo build --release
```

### Basic Usage

1. **Generate a keypair** (if needed):
   ```bash
   sss keys generate
   # Creates a new keypair encrypted with your passphrase
   ```

2. **Initialise a new project**:
   ```bash
   sss init
   ```

3. **Encrypt sensitive data in a file**:
   ```bash
   # Mark sensitive data with ⊕{content} or o+{content}
   echo "password=⊕{my-secret-password}" > config.txt

   # Encrypt marked content
   sss seal config.txt > config.encrypted.txt
   ```

4. **Decrypt for viewing**:
   ```bash
   sss open config.encrypted.txt
   ```

5. **Edit files with automatic encryption/decryption**:
   ```bash
   sss edit config.encrypted.txt
   ```

## String Patterns

- **Plaintext markers**:
  - `⊕{content}` - UTF-8 marker (default output)
  - `o+{content}` - ASCII alternative for compatibility
- **Ciphertext marker**: `⊠{content}` - Indicates encrypted content (always UTF-8)

## Multi-User Architecture

### Team Collaboration Workflow

1. **Project Owner** initialises project:
   ```bash
   sss init alice
   # Creates project with alice as initial user
   ```

2. **Add team members**:
   ```bash
   # Bob generates his keypair
   sss keys generate
   sss keys pubkey > bob-pubkey.txt

   # Alice adds Bob to the project
   sss users add bob bob-pubkey.txt
   ```

3. **Team members can now access files**:
   ```bash
   # Bob can encrypt/decrypt using his private key
   sss seal --user bob secrets.txt
   sss open --user bob secrets.txt
   ```

## Commands

### Core Commands

```bash
# Initialise new project
sss init [username]

# Process files with verb-based commands
sss seal <file>                    # Encrypt plaintext markers (outputs to stdout)
sss seal -x <file>                 # Encrypt in-place
sss open <file>                    # Decrypt to plaintext markers (outputs to stdout)
sss open -x <file>                 # Decrypt in-place
sss render <file>                  # Decrypt and strip markers to plain text (outputs to stdout)
sss render -x <file>               # Decrypt to plain text in-place
sss edit <file>                    # Edit with auto-encrypt/decrypt (always in-place)

# All commands support stdin with '-'
echo "⊕{secret}" | sss seal -

# Specify username via --user flag or SSS_USER environment variable
sss seal --user alice config.txt
export SSS_USER=alice
sss seal config.txt
```

### Key Management

```bash
# Generate new keypair
sss keys generate [--force]

# List your private keys
sss keys list

# Show public key
sss keys pubkey                    # Your public key
sss keys pubkey --fingerprint      # SHA256 fingerprint with visual randomart
sss keys pubkey --user <username>  # Another user's public key from project

# Show or set current keypair
sss keys current [key-id]

# Delete a private key
sss keys delete <key-id>
```

### User Management

```bash
# Add user to project
sss users add <username> <public-key-file-or-key>

# Remove user from project
sss users remove <username>

# List project users
sss users list

# Show user information
sss users info <username>
```

### Settings Management

```bash
# Show current settings
sss settings show

# Set default username
sss settings set --username <username>

# Set preferred editor
sss settings set --editor <editor>

# Enable/disable coloured output
sss settings set --coloured true/false

# Reset all settings to defaults
sss settings reset --confirm

# Show configuration file locations
sss settings location
```

### `ssse` - Editor Command

```bash
# Edit with automatic decryption/encryption
ssse filename
```

**Note**: `ssse` uses your system username ($USER/$USERNAME). Create a symlink: `ln -sf sss ssse`

The editor:
1. Decrypts all `⊠{}` patterns to `⊕{}` for editing
2. Launches `$EDITOR` (fallback to `$VISUAL`, then sensible defaults)
3. Re-encrypts all `⊕{}` and `o+{}` patterns to `⊠{}` on save/exit

## Security Properties

### Cryptographic Security

1. **Authenticated Encryption**: XChaCha20-Poly1305 provides both confidentiality and integrity
2. **Large Nonce Space**: 192-bit nonces eliminate collision concerns in practice
3. **Forward Security**: Changing keys invalidates all previous ciphertexts
4. **Unique Ciphertexts**: Identical plaintexts produce different ciphertexts

### Key Management Security

1. **Asymmetric Architecture**: Private keys never shared between users
2. **Key Derivation**: Encryption keys derived from user passphrases using Argon2id
3. **Sealed Repository Keys**: Symmetric keys encrypted for each user individually using crypto_box_seal
4. **Local Keystore**: Private keys stored locally, never transmitted
5. **Memory Protection**: Cryptographic material securely cleared from memory using zeroize

### Implementation Details

1. **Input Validation**: Size limits prevent denial of service attacks
2. **Rate Limiting**: Password attempts limited to prevent brute force attacks
3. **Path Handling**: Symlinks resolved for consistent behaviour
4. **Error Handling**: Sensitive information not leaked in error messages
5. **Secure Temporary Files**: Created with restrictive permissions (0600 on Unix)
6. **Atomic Operations**: Prevent time-of-check to time-of-use vulnerabilities

## Editor Integrations

### 📝 Emacs Package

SSS includes a comprehensive Emacs package providing seamless integration with powerful features:

#### Features
- **🔐 Interactive Operations**: Encrypt/decrypt regions, toggle patterns at point, process entire buffers
- **👥 Multi-User Support**: Project management, user switching, team collaboration
- **🎨 Syntax Highlighting**: Visual distinction of `⊕{}`, `o+{}`, and `⊠{}` patterns
- **⚡ Auto-Processing**: Automatic encrypt/decrypt on file open/save
- **🔥 Doom Integration**: Full Evil operator support, leader keys, text objects
- **🎯 Smart UI**: Transient menus, completion, password caching

#### Quick Setup

**Standard Emacs:**
```elisp
(add-to-list 'load-path "/path/to/sss/plugins/emacs")
(require 'sss)
(require 'sss-mode)
(sss-setup-auto-mode)
```

**Doom Emacs:**
```elisp
;; packages.el
(package! sss :recipe (:local-repo "/path/to/sss/plugins/emacs"))

;; config.el
(use-package! sss
  :commands sss-mode
  :config (require 'sss-doom))
```

#### Key Bindings
- **Standard**: `C-c s e/d/t` (encrypt/decrypt/toggle)
- **Doom**: `SPC e e/d/t` + Evil operators `g e/d/t`
- **Evil Text Objects**: `i s`/`a s` (inner/outer SSS pattern)

See [`plugins/emacs/README.md`](plugins/emacs/README.md) for complete documentation.

### 🔧 Other Editors

SSS works with any editor through the `ssse` command:

```bash
# Edit with automatic encrypt/decrypt
ssse myfile.conf

# Or set your preferred editor
export EDITOR=vim
ssse myfile.conf
```

## Configuration

### Project Configuration (`.sss.toml`)

```toml
# Project metadata
version = "1.0"
created = "2025-01-01T00:00:00Z"

# Users and their sealed repository keys
[alice]
public = "base64_encoded_public_key"
sealed_key = "base64_encoded_sealed_repository_key"
added = "2025-01-01T00:00:00Z"

[bob]
public = "base64_encoded_public_key"
sealed_key = "base64_encoded_sealed_repository_key"
added = "2025-01-01T00:00:00Z"
```

### User Settings

SSS supports layered configuration with the following precedence (highest to lowest):

1. Command-line arguments
2. Environment variables
3. User configuration file (`~/.config/sss/settings.toml`)
4. System defaults

User settings include:
- Default username for operations
- Preferred editor for `ssse` command
- Coloured output preferences

### Environment Variables

- `EDITOR`: Preferred text editor for `ssse`
- `VISUAL`: Alternative text editor
- `SSS_USER`: Default username (overrides config file setting)

## Examples

### Project Setup

```bash
# Create new project
sss init alice
# Enter passphrase when prompted

# Add team member
# (Bob first generates keypair and shares public key)
sss users add bob bob-public-key.txt

# Process files
sss seal --user alice config.txt
sss open --user bob config.txt  # Both can access same files
```

### Key Management

```bash
# View your keys
sss keys list
sss keys pubkey

# View key fingerprint with visual randomart (like SSH)
sss keys pubkey --fingerprint
# Output (with colours when terminal supports it):
# +----[SSS KEY]----+
# |                 |  78:9f:95:91
# |           . .   |  28:7b:49:22
# |o   . + o o o    |  4a:1f:a3:b3
# |.=.+ + = = o o   |  c0:b0:8a:94
# |.oB = o S o *    |
# |+  = +.. o + o . |  f0:39:79:6b
# |o o =oo.  o . . E|  68:5b:e7:e4
# | . + =+  ...     |  c3:b4:fb:f9
# |  .   ++o..o.    |  f3:14:c6:df
# +-----------------+
#
# The randomart uses a heat map colour scheme (blue → green → yellow → red)
# based on visit frequency. The hex bytes use an improved perceptually uniform
# colour mapping where:
# - High nibble (first hex digit) determines the hue (16 distinct colour families)
# - Low nibble (second hex digit) determines brightness (4 levels per family)
# - Identical bytes have IDENTICAL colours, making patterns immediately visible
# - Text colour (black/white) is automatically chosen for WCAG-compliant contrast
#
# A geometric medallion (9x9 grid) appears to the right using cryptographic mixing:
# - Uses avalanche effect: single bit change creates dramatically different pattern
# - 8 different block characters (▀▄█▌▐░▒▓) for geometric variety
# - Colours derived from position-aware hashing for maximum differentiation
# - Provides instant visual verification - identical fingerprints = identical medallions
#
# Colours respect NO_COLOR environment variable and are disabled for non-TTY output.

# View another user's public key
sss keys pubkey --user alice

# Generate new keypair
sss keys generate --force  # Overwrites existing

# Set current keypair
sss keys current my-key-id
```

### Advanced Usage

```bash
# Edit file in-place with encryption
sss edit --user alice secrets.conf

# Render encrypted file to raw plaintext
sss render --user alice encrypted.txt > plaintext.txt

# Use SSS_USER environment variable for convenience
export SSS_USER=alice
sss seal config.txt
sss open secrets.conf
```

## Building

### Requirements

- Rust 1.70+
- libsodium (automatically handled by libsodium-sys)

### Development

```bash
# Clone the repository
git clone https://github.com/dspearson/sss.git
cd sss

# Run unit tests (119 tests total)
cargo test

# Run specific test suites
cargo test --lib                        # Unit tests
cargo test --test command_integration   # Command integration tests
cargo test --test crypto_properties     # Property-based crypto tests
cargo test --test editor_integration    # Editor integration tests

# Run all tests including ignored ones (requires interaction)
cargo test -- --include-ignored

# Check code quality
cargo clippy -- -D warnings

# Build for your platform
cargo build --release

# Cross-compile for other platforms (requires cross)
cargo install cross
cross build --target x86_64-unknown-linux-musl --release
```

### Code Structure

The codebase is organised into well-defined modules:

- `src/main.rs` - CLI interface and command routing
- `src/commands/` - Modular command handlers
  - `init.rs` - Project initialisation
  - `keys.rs` - Key management operations
  - `users.rs` - User management for multi-user projects
  - `process.rs` - File processing (encrypt/decrypt/edit)
  - `settings.rs` - Configuration and user settings management
- `src/crypto.rs` - Core cryptographic operations
- `src/keystore.rs` - Private key storage and management
- `src/config_manager.rs` - Layered configuration management system
- `src/validation.rs` - Input validation and sanitisation
- `src/rate_limiter.rs` - Password attempt rate limiting for security
- `src/processor.rs` - File content processing with optimised regex patterns
- `src/project.rs` - Project configuration handling
- `src/error.rs` - Custom error types and structured error handling
- `src/secure_memory.rs` - Secure memory handling utilities
- `tests/` - Comprehensive test suite with unit and integration tests

## Contributing

Contributions are welcome! Please ensure all tests pass and follow the existing code style.

### Development Guidelines

- Use British English spelling in all documentation and user-facing text
- Follow Rust conventions and run `cargo clippy` before submitting
- Add tests for new functionality
- Update documentation for any API changes

## Licence

This project is licensed under the ISC Licence - see the [LICENCE](LICENCE) file for details.

## Acknowledgements

- Built with [libsodium](https://libsodium.gitbook.io/) for cryptographic operations
- Uses modern Rust cryptography patterns and best practices
