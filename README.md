# sss - Secret String Substitution

sss is a command-line tool for transparent encryption and decryption of text within files using XChaCha20-Poly1305 with a modern multi-user architecture. It enables seamless protection of sensitive data embedded in configuration files, scripts, and other text documents.

## Features

- **Transparent Encryption**: Mark secrets with simple patterns (`⊕{secret}` or `o+{secret}`)
- **Multi-User Architecture**: Asymmetric + symmetric hybrid encryption for team collaboration
- **Git Integration**: Automatic hooks for seal/open/render operations
- **Key Rotation**: Re-encrypt all project files with a new key
- **FUSE Filesystem**: Mount projects with transparent rendering (Linux only, optional)
- **9P Server**: Cross-platform network-transparent file access (optional)
- **Smart Merge**: Preserves encryption markers when editing rendered files
- **Deterministic Encryption**: Clean git diffs with BLAKE2b-derived nonces
- **Comprehensive Security**: XChaCha20-Poly1305, Argon2id, Ed25519, zeroization

## Quick Start

### Installation

#### Build from Source

```bash
git clone <repository-url>
cd sss
cargo build --release
```

#### Optional Features

Build with FUSE support (Linux only):
```bash
# Install libfuse3 development libraries
sudo apt-get install libfuse3-dev fuse3  # Debian/Ubuntu
sudo dnf install fuse3-devel fuse3       # Fedora/RHEL

# Build with FUSE
cargo build --features fuse --release
```

Build with 9P server support (cross-platform):
```bash
cargo build --features ninep --release
```

### Basic Usage

1. **Generate a keypair**:
   ```bash
   sss keys generate
   # Creates a new keypair encrypted with your passphrase
   ```

2. **Initialize a new project**:
   ```bash
   sss init
   ```

3. **Encrypt sensitive data in a file**:
   ```bash
   # Mark sensitive data with ⊕{content} or o+{content}
   echo "password=⊕{my-secret-password}" > config.txt

   # Encrypt marked content
   sss seal config.txt > config.encrypted.txt
   # Or encrypt in-place
   sss seal -x config.txt
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

1. **Project Owner** initializes project:
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
   sss project users add bob bob-pubkey.txt
   ```

3. **Team members can now access files**:
   ```bash
   # Bob can encrypt/decrypt using his private key
   sss seal --user bob secrets.txt
   sss open --user bob secrets.txt
   ```

## Core Commands

### File Operations

```bash
# Process individual files
sss seal <file>                    # Encrypt plaintext markers (outputs to stdout)
sss seal -x <file>                 # Encrypt in-place
sss open <file>                    # Decrypt to plaintext markers (outputs to stdout)
sss open -x <file>                 # Decrypt in-place
sss render <file>                  # Decrypt and strip markers (outputs to stdout)
sss render -x <file>               # Decrypt to plain text in-place
sss edit <file>                    # Edit with auto-encrypt/decrypt (always in-place)

# Process entire project (requires permissions)
sss seal --project                 # Seal all files in project
sss open --project                 # Open all files (requires permission)
sss render --project               # Render all files (requires permission)

# All commands support stdin with '-'
echo "⊕{secret}" | sss seal -
```

### Project Management

```bash
# Initialize project
sss init [username]

# Check project status
sss status                         # Show project root path

# User management
sss project users list             # List project users
sss project users add <username> <pubkey>     # Add user (pubkey can be file or base64)
sss project users remove <username>           # Remove user (triggers key rotation)
sss project users info <username>             # Show user information

# Project settings
sss project show                   # Show current project settings
sss project enable render          # Enable auto-render for this project
sss project enable open            # Enable auto-open for this project
sss project disable render         # Disable auto-render
sss project disable open           # Disable auto-open

# Ignore patterns for project-wide operations
sss project ignore add <pattern>   # Add glob pattern to ignore list
sss project ignore remove <pattern> # Remove pattern
sss project ignore list            # Show ignore patterns
```

### Key Management

```bash
# Generate new keypair
sss keys generate [--force] [--no-password]

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

# Rotate project encryption key
sss keys rotate [--force] [--no-backup] [--dry-run]
```

### Settings Management

```bash
# Show current settings
sss settings show

# Configure defaults
sss settings set --username <username>
sss settings set --editor <editor>
sss settings set --coloured true/false
sss settings set --auto-render-projects true/false
sss settings set --auto-open-projects true/false

# Reset settings
sss settings reset --confirm

# Show configuration file locations
sss settings location
```

### Git Integration

```bash
# Install git hooks to current repository
sss hooks install

# Export hooks to ~/.config/sss/hooks/
sss hooks export

# List available hooks
sss hooks list

# Show hook contents
sss hooks show <hook-name>
```

**Available hooks:**
- `pre-commit`: Seals files with plaintext markers
- `post-merge`: Processes files after git pull/merge
- `post-checkout`: Processes files after checkout/clone

### FUSE Filesystem (Linux Only, Optional)

```bash
# Mount project with transparent rendering
sss mount <source-dir> <mountpoint>
sss mount --in-place               # Overlay mount current directory
sss mount <source-dir> --in-place  # Overlay mount specific directory

# Unmount
fusermount -u <mountpoint>         # Linux
umount <mountpoint>                # macOS
```

### 9P Server (Cross-Platform, Optional)

```bash
# Start 9P server
sss serve9p tcp:0.0.0.0:564                    # TCP server
sss serve9p unix:/tmp/sss-9p.sock              # Unix socket server
sss serve9p tcp:localhost:5640 -d /path -u alice  # Custom options
```

**File access modes:**
- `file` - Rendered view (default)
- `file.open` - Opened view with markers
- `file.sealed` - Raw sealed content

### Editor Command (ssse)

```bash
# Edit with automatic decryption/encryption
ssse filename
```

**Note**: `ssse` uses your system username ($USER/$USERNAME). Create a symlink: `ln -sf sss ssse`

## Configuration

### Project Configuration (.sss.toml)

```toml
# Project metadata
id = "unique-project-id"
version = "1.0"
created = "2025-01-01T00:00:00Z"

# Users and their sealed repository keys
[alice]
public = "base64_encoded_public_key"
sealed_key = "base64_encoded_sealed_repository_key"
added = "2025-01-01T00:00:00Z"
```

### User Settings

Located at `~/.config/sss/settings.toml` (or platform equivalent).

Configuration precedence (highest to lowest):
1. Command-line arguments
2. Environment variables
3. User configuration file
4. System defaults

### Environment Variables

- `EDITOR`: Preferred text editor for `ssse`
- `VISUAL`: Alternative text editor
- `SSS_USER`: Default username (overrides config file setting)

## Examples

### Basic Workflow

```bash
# Create new project
sss init alice

# Mark secrets in a file
echo "api_key=⊕{secret-key-123}" > config.txt

# Seal the file
sss seal -x config.txt
# Now contains: api_key=⊠{base64-encrypted-data}

# Open for editing
sss edit config.txt
# Automatically decrypts, opens editor, re-encrypts on save

# Render to plain text
sss render config.txt
# Output: api_key=secret-key-123
```

### Team Collaboration

```bash
# Alice initializes project
sss init alice

# Bob generates keypair and shares public key
sss keys generate
sss keys pubkey > bob-key.txt
# Send bob-key.txt to Alice

# Alice adds Bob to project
sss project users add bob bob-key.txt

# Both can now work with the same files
sss seal -x --user alice secrets.conf
sss open --user bob secrets.conf
```

### Git Integration

```bash
# Install hooks for automatic encryption
cd /path/to/project
sss hooks install

# Now git operations automatically seal/open files
git add config.txt   # pre-commit hook seals plaintext markers
git pull             # post-merge hook opens/renders files
git checkout branch  # post-checkout hook processes files
```

### Key Rotation

```bash
# Rotate project encryption key (re-encrypts all files)
sss keys rotate

# Dry run to see what would be rotated
sss keys rotate --dry-run

# Rotate without backup
sss keys rotate --no-backup
```

## Security Features

- **Authenticated Encryption**: XChaCha20-Poly1305 with integrity verification
- **Deterministic Nonces**: BLAKE2b-derived for clean git diffs
- **Key Derivation**: Argon2id for password-protected private keys
- **Memory Protection**: Zeroization of sensitive data
- **Rate Limiting**: Password attempt throttling
- **Input Validation**: DoS protection with 100MB per-secret limit
- **No Secret Leakage**: Careful error message handling

## Building

### Requirements

- Rust 1.70+
- libsodium (automatically handled by libsodium-sys)
- libfuse3 (optional, for FUSE feature)
- rust-9p (optional, for 9P feature - see ARCHITECTURE.md for setup)

### Development

```bash
# Clone the repository
git clone <repository-url>
cd sss

# Run tests (302 tests total)
cargo test

# Run specific test suites
cargo test --lib                   # Library tests
cargo test --test verb_commands    # Integration tests

# Check code quality
cargo clippy -- -D warnings

# Build for your platform
cargo build --release

# Build with optional features
cargo build --features fuse --release
cargo build --features ninep --release
```

### Code Structure

The codebase is organized into well-defined modules:

- `src/main.rs` - CLI interface and command routing
- `src/commands/` - Modular command handlers
  - `init.rs` - Project initialization
  - `keys.rs` - Key management and rotation
  - `users.rs` - User management
  - `process.rs` - File processing (seal/open/render/edit)
  - `settings.rs` - User settings management
  - `project.rs` - Project settings and permissions
  - `hooks.rs` - Git hooks management
  - `status.rs` - Project status
  - `mount.rs` - FUSE mount operations (optional)
  - `ninep.rs` - 9P server (optional)
- `src/crypto.rs` - Core cryptographic operations
- `src/keystore.rs` - Private key storage
- `src/processor.rs` - File content processing
- `src/project.rs` - Project configuration handling
- `src/config_manager.rs` - Layered configuration system
- `src/rotation.rs` - Key rotation orchestration
- `src/merge.rs` - Smart reconstruction algorithm
- `src/validation.rs` - Input validation
- `src/error.rs` - Custom error types
- `src/secure_memory.rs` - Secure memory handling

## Documentation

For detailed technical documentation, architecture details, and implementation notes, see [ARCHITECTURE.md](ARCHITECTURE.md).

For security policy and vulnerability disclosure, see [SECURITY.md](SECURITY.md).

For contribution guidelines, see [CONTRIBUTING.md](CONTRIBUTING.md).

For version history, see [CHANGELOG.md](CHANGELOG.md).

## License

This project is licensed under the ISC License - see the [LICENSE](LICENSE) file for details.

## Acknowledgements

- Built with [libsodium](https://libsodium.gitbook.io/) for cryptographic operations
- FUSE support via [fuser](https://github.com/cberner/fuser)
- 9P server via [pfpacket/rust-9p](https://github.com/pfpacket/rust-9p)
