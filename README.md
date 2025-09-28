# SSS - Secret String Substitution

SSS is a command-line tool for transparent encryption and decryption of text within files using XChaCha20Poly1305 with a modern multi-user architecture. It enables seamless protection of sensitive data embedded in configuration files, scripts, and other text documents.

## Features

- **🔒 Secure Encryption**: Uses XChaCha20Poly1305 authenticated encryption with cryptographically secure random nonces
- **👥 Multi-User Support**: Asymmetric encryption for team collaboration with individual private keys
- **🔑 Advanced Key Management**: Integrated keystore with password-protected private keys and user aliases
- **📁 Transparent Operation**: Works with any text file format
- **🛡️ Cross-Platform**: Supports Windows, macOS, and Linux
- **⚡ High Performance**: Optimised with static regex compilation and buffered I/O
- **🛡️ Enhanced Security**: Comprehensive input validation, rate limiting, and path traversal protection
- **⚙️ Flexible Configuration**: Layered configuration system with user settings persistence
- **🧪 Well-Tested**: Comprehensive test suite

## Quick Start

### Installation

#### Build from Source

```bash
git clone https://github.com/dspearson/sss.git
cd sss
cargo build --release
```

### Basic Usage

1. **Initialise a new project**:
   ```bash
   sss init
   # You'll be prompted to enter a username and passphrase for your private key
   ```

2. **Generate a keypair** (if needed):
   ```bash
   sss keys generate
   # Creates a new keypair with passphrase protection
   ```

3. **Encrypt sensitive data in a file**:
   ```bash
   # Mark sensitive data with ⊕{content} or o+{content}
   echo "password=⊕{my-secret-password}" > config.txt

   # Encrypt marked content
   sss --user yourname config.txt > config.encrypted.txt
   ```

4. **Decrypt for viewing**:
   ```bash
   sss --user yourname config.encrypted.txt
   ```

5. **Edit files with automatic encryption/decryption**:
   ```bash
   ssse config.encrypted.txt
   # Uses your system username automatically
   ```

## String Patterns

- **Plaintext markers**:
  - `⊕{content}` - UTF-8 marker (default output)
  - `o+{content}` - ASCII alternative for compatibility
- **Ciphertext marker**: `⊠{content}` - Indicates encrypted content (always UTF-8)

## Multi-User Architecture

### Key Concepts

- **Private Keys**: Individual Ed25519 keypairs stored encrypted in local keystore
- **Repository Keys**: Symmetric keys for file encryption, sealed for each project user
- **Project Configuration**: `.sss.toml` file containing user public keys and sealed repository keys

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
   sss --user bob secrets.txt
   ```

## Commands

### Core Commands

```bash
# Initialise new project
sss init [username]

# Process files (encrypt/decrypt)
sss --user <username> <file>
sss --user <username> --in-place <file>
sss --user <username> --edit <file>
sss --user <username> --render <file>  # Decrypt and strip markers to plain text
```

### Key Management

```bash
# Generate new keypair
sss keys generate [--force]

# List your private keys
sss keys list

# Show public key
sss keys pubkey [--fingerprint]

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

### Alias Management

```bash
# List user aliases
sss aliases list

# Add new alias
sss aliases add <alias> <username>

# Remove alias
sss aliases remove <alias>
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

1. **Authenticated Encryption**: XChaCha20Poly1305 provides both confidentiality and integrity
2. **Large Nonce Space**: 192-bit random nonces eliminate collision concerns in practice
3. **Cryptographically Secure Randomness**: Nonces generated using libsodium's CSPRNG
4. **Forward Security**: Changing keys invalidates all previous ciphertexts
5. **Unique Ciphertexts**: Random nonces ensure identical plaintexts produce different ciphertexts

### Key Management Security

1. **Asymmetric Architecture**: Private keys never shared between users
2. **Password Protection**: Private keys encrypted with user passphrases using Argon2id
3. **Sealed Repository Keys**: Symmetric keys encrypted for each user individually
4. **Local Keystore**: Private keys stored locally, never transmitted
5. **Memory Protection**: Cryptographic material securely cleared from memory

### Additional Security Features

1. **Input Validation**: Comprehensive validation with size limits (prevents DoS)
2. **Rate Limiting**: Password attempt limiting to prevent brute force attacks
3. **Path Traversal Protection**: File paths validated and canonicalised
4. **Error Handling**: Sensitive information not leaked in error messages
5. **Secure Temporary Files**: Created with restrictive permissions (0600 on Unix)
6. **Memory Safety**: Cryptographic material securely cleared from memory using zeroize
7. **Custom Error Types**: Structured error handling with specific error categories

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
sss --user alice config.txt
sss --user bob config.txt  # Both can access same files
```

### Key Management

```bash
# View your keys
sss keys list
sss keys pubkey

# Generate new keypair
sss keys generate --force  # Overwrites existing

# Set current keypair
sss keys current my-key-id
```

### Advanced Usage

```bash
# Edit file in-place with encryption
sss --user alice --in-place secrets.conf

# Render encrypted file to raw plaintext
sss --user alice --render encrypted.txt > plaintext.txt

# Use alias for convenience
sss aliases add prod alice-production
sss --user prod config.txt
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
  - `aliases.rs` - Username alias management
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
