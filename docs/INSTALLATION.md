# Installation Guide

This guide covers installation methods for SSS (Shamir Secret Sharing) and development environment setup on macOS.

## Table of Contents

1. [SSS Installation](#sss-installation)
2. [Development Environment Setup](#development-environment-setup)
3. [Building from Source](#building-from-source)

---

## SSS Installation

### One-Line Install (macOS Apple Silicon)

The easiest way to install SSS on macOS:

```bash
curl -fsSL https://technoanimal.net/sss/install-macos.sh | bash
```

Or download and run:

```bash
chmod +x install-macos.sh
./install-macos.sh
```

### What Gets Installed

The installer will:

1. ✅ Extract all SSS binaries (sss, sss-agent, sss-askpass-tty, sss-askpass-gui)
2. ✅ Install Homebrew (if not present)
3. ✅ Install libsodium dependency
4. ✅ Install macFUSE (with system extension approval prompt)
5. ✅ Copy binaries to `~/.local/bin`
6. ✅ Add `~/.local/bin` to your PATH
7. ✅ Configure shell environment

### Requirements

- **macOS**: 12.0 (Monterey) or later
- **Architecture**: Apple Silicon (ARM64)
- **System Extensions**: Must approve macFUSE extension

### Post-Installation

After installation completes:

```bash
# Reload your shell
source ~/.zshrc  # or ~/.bash_profile for bash

# Verify installation
sss --version

# Quick start
sss init
sss keygen
sss mount --in-place
```

### Manual Installation

If you prefer manual installation:

1. Download the binary from [releases](https://github.com/dspearson/sss/releases)
2. Install dependencies:
   ```bash
   brew install libsodium
   brew install --cask macfuse
   ```
3. Move binary to your PATH:
   ```bash
   sudo mv sss /usr/local/bin/
   chmod +x /usr/local/bin/sss
   ```

---

## Development Environment Setup

For developers who want to build SSS or contribute to the project, we provide an automated development environment installer.

### One-Line Install

```bash
curl -fsSL https://raw.githubusercontent.com/dspearson/sss/main/scripts/devenv-macos-installer.sh | bash
```

Or download and run:

```bash
chmod +x scripts/devenv-macos-installer.sh
./scripts/devenv-macos-installer.sh
```

### What Gets Installed

The development environment installer sets up:

1. **Determinate Nix** (noninteractive)
   - Nix package manager with flakes enabled by default
   - Better than standard Nix for development
   - Drop-in replacement with improved UX

2. **direnv**
   - Automatic environment loading
   - Loads Nix environments when you cd into project directory
   - No need to manually run `nix develop`

3. **Shell Integration**
   - Configures direnv hooks for your shell (zsh/bash)
   - Backs up existing shell config before modification
   - Adds PATH configuration automatically

4. **Optional: nix-direnv**
   - Caches Nix environments for faster loading
   - Significantly speeds up direnv operations
   - Highly recommended for Nix+direnv workflow

### Why Determinate Nix?

Determinate Nix is preferred over standard Nix because:

- ✅ Flakes enabled by default (no manual configuration)
- ✅ Noninteractive installation (great for automation)
- ✅ Better uninstall support
- ✅ More user-friendly error messages
- ✅ Drop-in replacement for standard Nix
- ✅ Works with all existing Nix flakes

### Post-Installation Workflow

After installing the development environment:

```bash
# Reload your shell
source ~/.zshrc  # or ~/.bash_profile for bash

# Verify installation
nix --version
direnv version

# Clone the SSS repository
git clone https://github.com/dspearson/sss.git
cd sss

# Allow direnv (first time only)
direnv allow

# The environment will automatically load!
# All build tools, dependencies, and compilers are now available

# Build the project
cargo build --release

# Run tests
cargo test
```

### Using with Nix Flakes

The SSS project includes a `flake.nix` with development shells:

```bash
# Enter development shell manually (if not using direnv)
nix develop

# Or with direnv, just cd into the directory
cd sss
# direnv automatically loads the environment!
```

### What's in the Development Environment?

The Nix flake provides:

- Rust toolchain (stable/nightly as configured)
- Cross-compilation tools for macOS (osxcross)
- All required libraries (libsodium, libfuse, etc.)
- Build tools (cargo, rustc, pkg-config)
- Development tools (rust-analyzer, clippy, rustfmt)

---

## Building from Source

### Prerequisites

If you installed the development environment (recommended):

```bash
# Just cd into the project directory
cd sss
# All dependencies are automatically available via direnv!
```

Without the development environment:

```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Install dependencies
brew install libsodium pkg-config
brew install --cask macfuse
```

### Build Commands

```bash
# Build for local architecture
cargo build --release

# Cross-compile for macOS Apple Silicon (from Linux)
./build-macos-cross.sh

# Run tests
cargo test

# Generate installer (after building)
./generate-installer.sh
```

### Build Outputs

Built binaries are located in:

```
target/release/sss              # Main binary
target/release/sss-agent         # SSH agent integration
target/release/sss-askpass-tty   # Terminal password prompt
target/release/sss-askpass-gui   # GUI password prompt
```

For cross-compilation:

```
target/aarch64-apple-darwin/release/sss
```

---

## Troubleshooting

### macFUSE System Extension

If you see an error about system extensions:

1. Open **System Settings**
2. Go to **Privacy & Security**
3. Scroll down to find the blocked extension
4. Click **Allow** next to "System software from developer 'Benjamin Fleischer'"
5. Restart your Mac if prompted

### PATH Not Working

If `sss` command is not found after installation:

```bash
# For zsh (default on modern macOS)
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.zshrc
source ~/.zshrc

# For bash
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bash_profile
source ~/.bash_profile
```

### Nix Installation Issues

If Determinate Nix installation fails:

```bash
# Check for existing Nix installation
which nix

# If using standard Nix, uninstall first:
# https://nixos.org/manual/nix/stable/installation/uninstall.html

# Then retry the installer
./scripts/devenv-macos-installer.sh
```

### direnv Not Loading

If direnv doesn't automatically load:

```bash
# Check if hook is configured
cat ~/.zshrc | grep direnv

# If not present, add manually:
echo 'eval "$(direnv hook zsh)"' >> ~/.zshrc
source ~/.zshrc

# Allow direnv in the project directory
cd sss
direnv allow
```

---

## Uninstallation

### Remove SSS

```bash
# Remove binaries
rm -f ~/.local/bin/sss*

# Remove from PATH (edit your shell config manually)
# Remove the line: export PATH="$HOME/.local/bin:$PATH"
```

### Remove Development Environment

```bash
# Uninstall Determinate Nix
/nix/nix-installer uninstall

# Uninstall direnv
brew uninstall direnv

# Remove shell hooks (edit your ~/.zshrc or ~/.bash_profile)
# Remove lines containing: direnv hook
```

---

## Support

- **Issues**: https://github.com/dspearson/sss/issues
- **Documentation**: https://github.com/dspearson/sss
- **Determinate Nix Docs**: https://determinate.systems/nix/
- **direnv Docs**: https://direnv.net/

---

## License

SSS is licensed under the ISC License. See [LICENSE](../LICENSE) for details.
