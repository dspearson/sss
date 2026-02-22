# Installation Guide

This guide covers installation methods for sss (Secret String Substitution) across all supported platforms, as well as development environment setup.

## Table of Contents

1. [Pre-built Packages](#pre-built-packages)
2. [Building from Source](#building-from-source)
3. [Platform-Specific Notes](#platform-specific-notes)
4. [Optional Features](#optional-features)
5. [Development Environment Setup](#development-environment-setup)
6. [Verifying Your Installation](#verifying-your-installation)
7. [Uninstallation](#uninstallation)
8. [Troubleshooting](#troubleshooting)

---

## Pre-built Packages

### Debian/Ubuntu (.deb)

```bash
./debian/build-deb.sh
sudo dpkg -i target/debian/sss_*.deb
```

### RHEL/CentOS/Fedora (.rpm)

```bash
./rpm-build/build-rpm.sh
sudo rpm -i target/rpm/sss-*.rpm
```

### Alpine Linux (musl static binary)

```bash
docker build -f Dockerfile.alpine -t sss-alpine .
docker run --rm sss-alpine cat /usr/local/bin/sss > sss
chmod +x sss
sudo mv sss /usr/local/bin/
```

### macOS (Apple Silicon / Intel)

```bash
# Install dependencies
brew install libsodium pkg-config

# Build from source
cargo build --release
sudo cp target/release/sss /usr/local/bin/

# Optional: FUSE support
brew install --cask macfuse
cargo build --features fuse --release
```

### Windows

```bash
# Install dependencies:
# - Rust toolchain: https://rustup.rs/
# - libsodium: via vcpkg or pre-built binaries

cargo build --release

# Optional: WinFSP support
# Install WinFSP from https://winfsp.dev/
cargo build --features winfsp --release
```

---

## Building from Source

### Prerequisites

- **Rust**: 2024 edition (1.85+) -- install via [rustup](https://rustup.rs/)
- **libsodium**: linked automatically by `libsodium-sys` (builds from source if not found)
- **pkg-config** (Linux/macOS): for locating system libsodium
- **C compiler**: for libsodium-sys build (gcc, clang, or MSVC)

### Basic Build

```bash
git clone <repository-url>
cd sss
cargo build --release
```

Binaries are placed in `target/release/`:

| Binary | Description |
|--------|-------------|
| `sss` | Main CLI tool |
| `sss-agent` | Key management daemon (Unix) |
| `sss-askpass-tty` | TTY confirmation helper for agent |
| `sss-askpass-gui` | GUI confirmation helper for agent |

### Install to PATH

```bash
# System-wide
sudo cp target/release/sss /usr/local/bin/
sudo cp target/release/sss-agent /usr/local/bin/

# User-local
mkdir -p ~/.local/bin
cp target/release/sss ~/.local/bin/
cp target/release/sss-agent ~/.local/bin/
# Ensure ~/.local/bin is in your PATH
```

### Editor Symlink

Create an `ssse` symlink for transparent edit-in-place from any editor:

```bash
ln -s /usr/local/bin/sss /usr/local/bin/ssse
```

When invoked as `ssse <file>`, it automatically opens, launches your editor, and re-seals on save.

---

## Platform-Specific Notes

### Linux

libsodium is typically available via your package manager:

```bash
# Debian/Ubuntu
sudo apt-get install libsodium-dev pkg-config

# Fedora/RHEL
sudo dnf install libsodium-devel pkgconf-pkg-config

# Arch Linux
sudo pacman -S libsodium pkg-config
```

For FUSE support:

```bash
# Debian/Ubuntu
sudo apt-get install libfuse3-dev fuse3

# Fedora/RHEL
sudo dnf install fuse3-devel fuse3

# Arch Linux
sudo pacman -S fuse3
```

### macOS

```bash
brew install libsodium pkg-config

# For FUSE support, install macFUSE:
brew install --cask macfuse
```

**Note:** macFUSE requires approval of a system extension. After installation:

1. Open **System Settings**
2. Go to **Privacy & Security**
3. Find the blocked extension and click **Allow**
4. Restart if prompted

### Cross-Compilation (Linux to macOS)

If building macOS binaries from Linux, you will need osxcross or a similar toolchain. The Nix development environment (see below) provides this automatically.

```bash
# With osxcross configured:
cargo build --target aarch64-apple-darwin --release
```

---

## Optional Features

sss has three optional Cargo features:

| Feature | Platform | Description |
|---------|----------|-------------|
| `fuse` | Linux, macOS | FUSE filesystem for transparent rendering |
| `winfsp` | Windows | WinFSP filesystem for transparent rendering |
| `ninep` | All | 9P network file server |

Build with one or more features:

```bash
cargo build --features fuse --release
cargo build --features ninep --release
cargo build --features fuse,ninep --release
cargo build --features winfsp --release
```

### FUSE Dependencies

- **Linux**: `libfuse3-dev` / `fuse3-devel` and `fuse3`
- **macOS**: [macFUSE](https://osxfuse.github.io/) (`brew install --cask macfuse`)

### WinFSP Dependencies

- **Windows**: [WinFSP](https://winfsp.dev/) (download and install the MSI package)

### 9P Dependencies

No additional system dependencies. The 9P server uses a vendored Rust implementation.

---

## Development Environment Setup

### Using Nix (Recommended)

The project includes a `flake.nix` providing a complete development environment:

```bash
# Install Determinate Nix (if not already present)
curl --proto '=https' --tlsv1.2 -sSf -L https://install.determinate.systems/nix | sh

# Enter the development shell
nix develop

# Or with direnv (automatic environment loading)
direnv allow
```

The Nix flake provides:

- Rust toolchain (stable)
- Cross-compilation tools (including osxcross for macOS targets)
- All required libraries (libsodium, libfuse, etc.)
- Build tools (cargo, rustc, pkg-config)
- Development tools (rust-analyzer, clippy, rustfmt)

### Using direnv

With [direnv](https://direnv.net/) installed and configured, the development environment loads automatically when you `cd` into the project directory:

```bash
# Install direnv
brew install direnv   # macOS
sudo apt install direnv  # Debian/Ubuntu

# Add hook to your shell
echo 'eval "$(direnv hook zsh)"' >> ~/.zshrc   # or bash equivalent

# Allow direnv for this project
cd sss
direnv allow
```

### Manual Setup

Without Nix, install the prerequisites manually:

```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Install system dependencies (Debian/Ubuntu)
sudo apt-get install libsodium-dev pkg-config libfuse3-dev fuse3

# Build and test
cargo build
cargo test
cargo clippy -- -D warnings
```

---

## Verifying Your Installation

```bash
# Check version
sss --version

# Generate a test keypair
sss keys generate

# Initialise a test project
mkdir /tmp/sss-test && cd /tmp/sss-test
sss init testuser

# Seal and open a test file
echo "secret=⊕{hello-world}" > test.txt
sss seal -x test.txt
cat test.txt            # Shows ⊠{...} ciphertext
sss open test.txt       # Shows ⊕{hello-world}

# Clean up
cd -
rm -rf /tmp/sss-test
```

---

## Uninstallation

### Remove Binaries

```bash
# If installed to /usr/local/bin
sudo rm -f /usr/local/bin/sss /usr/local/bin/sss-agent
sudo rm -f /usr/local/bin/sss-askpass-tty /usr/local/bin/sss-askpass-gui
sudo rm -f /usr/local/bin/ssse

# If installed to ~/.local/bin
rm -f ~/.local/bin/sss ~/.local/bin/sss-agent
rm -f ~/.local/bin/sss-askpass-tty ~/.local/bin/sss-askpass-gui
rm -f ~/.local/bin/ssse
```

### Remove Configuration

```bash
# User configuration and keys
rm -rf ~/.config/sss/

# On macOS
rm -rf ~/Library/Application\ Support/sss/
```

**Warning:** removing `~/.config/sss/` deletes your private keys. Ensure you have backups or that no projects depend on those keys before proceeding.

### Remove Nix Development Environment

```bash
/nix/nix-installer uninstall
```

---

## Troubleshooting

### libsodium not found

If `cargo build` fails with libsodium errors, ensure the development headers are installed:

```bash
# Debian/Ubuntu
sudo apt-get install libsodium-dev

# Fedora
sudo dnf install libsodium-devel

# macOS
brew install libsodium
```

If libsodium is installed but not found, set `PKG_CONFIG_PATH`:

```bash
export PKG_CONFIG_PATH="/usr/local/lib/pkgconfig:$PKG_CONFIG_PATH"
```

### FUSE mount permission denied

Ensure your user is in the `fuse` group (Linux):

```bash
sudo usermod -a -G fuse $USER
# Log out and back in for the change to take effect
```

### macFUSE system extension blocked

See [Platform-Specific Notes -- macOS](#macos) above for instructions on approving the system extension.

### PATH not configured

If `sss` is not found after installation:

```bash
# For zsh
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.zshrc
source ~/.zshrc

# For bash
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc
```

### Passphrase prompts in CI/CD

Use the `SSS_PASSPHRASE` environment variable and `--non-interactive` flag:

```bash
export SSS_PASSPHRASE="your-passphrase"
sss --non-interactive seal --project
```

Or generate keys without a passphrase for CI environments:

```bash
sss keys generate --no-password
```
