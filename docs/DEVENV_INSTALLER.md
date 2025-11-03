# Development Environment Installer Guide

This guide covers the universal development environment installer that works across macOS, Linux, and WSL.

## Table of Contents

1. [Quick Start](#quick-start)
2. [Supported Platforms](#supported-platforms)
3. [What Gets Installed](#what-gets-installed)
4. [Platform Detection](#platform-detection)
5. [Installation Process](#installation-process)
6. [Platform-Specific Notes](#platform-specific-notes)
7. [Troubleshooting](#troubleshooting)

---

## Quick Start

### One-Line Install (All Platforms)

```bash
curl -fsSL https://raw.githubusercontent.com/dspearson/sss/main/scripts/devenv-installer.sh | bash
```

Or download and run:

```bash
chmod +x scripts/devenv-installer.sh
./scripts/devenv-installer.sh
```

---

## Supported Platforms

### ✅ Fully Supported

| Platform | Architecture | Package Manager | Shell |
|----------|-------------|----------------|-------|
| **macOS** | ARM64, x86_64 | Homebrew | zsh, bash |
| **WSL2 Ubuntu** | x86_64, ARM64 | apt | bash, zsh |
| **WSL2 Debian** | x86_64, ARM64 | apt | bash, zsh |
| **Ubuntu** | x86_64, ARM64 | apt | bash, zsh |
| **Debian** | x86_64, ARM64 | apt | bash, zsh |
| **Fedora** | x86_64, ARM64 | dnf | bash, zsh |
| **RHEL/CentOS** | x86_64, ARM64 | dnf/yum | bash, zsh |
| **Arch Linux** | x86_64, ARM64 | pacman | bash, zsh, fish |
| **openSUSE** | x86_64, ARM64 | zypper | bash, zsh |

### Package Manager Support

The installer automatically detects and uses:

- **Homebrew** (macOS)
- **apt/apt-get** (Debian, Ubuntu, WSL)
- **dnf** (Fedora, RHEL 8+)
- **yum** (CentOS, RHEL 7)
- **pacman** (Arch Linux, Manjaro)
- **zypper** (openSUSE, SLES)
- **Nix** (fallback for any platform)

---

## What Gets Installed

### 1. Determinate Nix

- **Modern Nix installer** with flakes enabled by default
- Better than standard Nix for development
- Noninteractive installation
- Cross-platform support

### 2. direnv

- Automatic environment loading when entering directories
- No more manual `nix develop` commands
- Per-project environment isolation

### 3. Shell Integration

- Automatic hook configuration for zsh, bash, or fish
- Backup of existing configuration
- PATH setup

### 4. nix-direnv (Optional)

- Caches Nix environments for 10-100x faster loading
- Highly recommended for Nix+direnv workflow

---

## Platform Detection

The installer automatically detects:

### Operating System
```bash
# macOS
uname -s = Darwin
→ Platform: macos

# Native Linux
uname -s = Linux
→ Platform: linux

# WSL (any distro)
uname -s = Linux + microsoft in /proc/version
→ Platform: wsl
```

### Linux Distribution
```bash
# Reads /etc/os-release
ID=ubuntu → Ubuntu
ID=debian → Debian
ID=fedora → Fedora
ID=arch → Arch Linux
# etc.
```

### Package Manager
```bash
# Auto-detects installed package manager
command -v apt-get → apt
command -v dnf → dnf
command -v pacman → pacman
# etc.
```

### Shell
```bash
# Detects current shell
$SHELL = /bin/zsh → zsh + ~/.zshrc
$SHELL = /bin/bash → bash + ~/.bashrc (Linux/WSL) or ~/.bash_profile (macOS)
$SHELL = /bin/fish → fish + ~/.config/fish/config.fish
```

---

## Installation Process

### Step 1: Platform Detection

```
Detected Platform:
  Platform:        wsl
  Distribution:    ubuntu
  Package Manager: apt
  Architecture:    x86_64

Shell Configuration:
  Shell:           bash
  Config File:     /home/user/.bashrc
```

### Step 2: Determinate Nix Installation

```bash
# Noninteractive installation
curl https://install.determinate.systems/nix | sh -s -- install --no-confirm

# Creates:
/nix/                           # Nix store and profiles
/etc/nix/nix.conf               # Configuration with flakes enabled
```

### Step 3: direnv Installation

**macOS:**
```bash
brew install direnv
```

**Ubuntu/Debian/WSL:**
```bash
sudo apt-get update
sudo apt-get install -y direnv
```

**Fedora:**
```bash
sudo dnf install -y direnv
```

**Arch:**
```bash
sudo pacman -Sy --noconfirm direnv
```

**Fallback (any platform):**
```bash
nix-env -iA nixpkgs.direnv
```

### Step 4: Shell Hook Configuration

Adds to your shell config:

**zsh (~/.zshrc):**
```bash
# Added by devenv-installer.sh
eval "$(direnv hook zsh)"
```

**bash (~/.bashrc or ~/.bash_profile):**
```bash
# Added by devenv-installer.sh
eval "$(direnv hook bash)"
```

**fish (~/.config/fish/config.fish):**
```fish
# Added by devenv-installer.sh
direnv hook fish | source
```

### Step 5: nix-direnv (Optional)

If you choose "yes":

```bash
# Install
nix-env -iA nixpkgs.nix-direnv

# Configure in ~/.config/direnv/direnvrc
source $HOME/.nix-profile/share/nix-direnv/direnvrc
```

---

## Platform-Specific Notes

### macOS

**Homebrew Installation:**
- Automatically installs Homebrew if not present
- Uses `/opt/homebrew` on Apple Silicon
- Uses `/usr/local` on Intel

**Shell Default:**
- macOS Catalina+ uses zsh by default
- Configures `~/.zshrc`

**Permissions:**
- No sudo required for user-level installation
- Nix daemon runs as system service

### WSL (Windows Subsystem for Linux)

**Detection:**
- Checks `/proc/version` for "microsoft" or "WSL"
- Checks `$WSL_DISTRO_NAME` environment variable

**Performance:**
- WSL2 recommended (much faster than WSL1)
- Nix store on Linux filesystem performs best
- Avoid storing Nix on Windows drives (/mnt/c)

**Path Integration:**
- Windows PATH is visible in WSL
- Keep Nix environments separate from Windows tools

**System Packages:**
- May require sudo password for apt/dnf installations
- Script prompts for password once, then caches

**Common WSL Distros:**
- Ubuntu 22.04 LTS (most common)
- Ubuntu 20.04 LTS
- Debian 11+
- Fedora Remix
- Arch WSL

### Native Linux

**Package Manager Selection:**
- Script auto-detects available package manager
- Prefers native package manager for direnv
- Falls back to Nix if no package manager found

**Systemd:**
- Nix daemon uses systemd on most distros
- Check status: `systemctl status nix-daemon`

**Multi-User Mode:**
- Nix installs in multi-user mode by default
- Creates `nixbld` group and users
- Requires sudo during installation

---

## Post-Installation Workflow

### 1. Reload Shell

```bash
# Source your config
source ~/.zshrc      # zsh
source ~/.bashrc     # bash (Linux/WSL)
source ~/.bash_profile  # bash (macOS)

# Or just open a new terminal
```

### 2. Verify Installation

```bash
# Check Nix
nix --version
# Output: nix (Nix) 2.18.1

# Check direnv
direnv version
# Output: 2.32.3

# Check flakes support
nix flake --help
# Should show flake commands
```

### 3. Test with a Project

```bash
# Create a test project
mkdir test-project && cd test-project

# Initialize a flake
nix flake init

# Create .envrc
echo "use flake" > .envrc

# Allow direnv (first time only)
direnv allow

# Environment loads automatically!
# direnv: loading ~/test-project/.envrc
# direnv: using flake
# direnv: nix-direnv: using cached dev shell
```

### 4. Real Project Example (SSS)

```bash
# Clone SSS repository
git clone https://github.com/dspearson/sss.git
cd sss

# Allow direnv
direnv allow

# Wait for environment to load (first time is slow)
# Subsequent loads are instant with nix-direnv

# All tools are now available!
which cargo
# /nix/store/.../bin/cargo

# Build the project
cargo build --release

# When you leave the directory, environment unloads
cd ..
# direnv: unloading
```

---

## Advanced Usage

### Custom Nix Flake

Create `flake.nix`:

```nix
{
  description = "My development environment";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs = { self, nixpkgs }: {
    devShells.x86_64-linux.default =
      nixpkgs.legacyPackages.x86_64-linux.mkShell {
        packages = with nixpkgs.legacyPackages.x86_64-linux; [
          rustc
          cargo
          pkg-config
          libsodium
        ];
      };
  };
}
```

Create `.envrc`:

```bash
use flake
```

### Multiple Environments

```bash
# Project A uses Python
cd project-a
# direnv loads Python environment

# Project B uses Rust
cd project-b
# direnv unloads Python, loads Rust

# No environment
cd ~
# direnv cleans up
```

### Shell-Specific Optimizations

**zsh with oh-my-zsh:**
```bash
# .zshrc
plugins=(git direnv)  # Use oh-my-zsh direnv plugin
```

**bash with bash-preexec:**
```bash
# .bashrc
eval "$(direnv hook bash)"
```

---

## Troubleshooting

### Nix Installation Fails

**Error:** "Installation failed"

**Solutions:**
```bash
# Check system requirements
uname -a

# Ensure curl is installed
sudo apt-get install curl  # Ubuntu/Debian
sudo dnf install curl      # Fedora
brew install curl          # macOS

# Check disk space
df -h /nix

# Try manual installation
curl --proto '=https' --tlsv1.2 -sSf -L \
  https://install.determinate.systems/nix | \
  sh -s -- install --no-confirm --explain
```

### direnv Not Loading

**Error:** "direnv: error .envrc is blocked"

**Solution:**
```bash
# Allow the .envrc file
direnv allow

# Or allow all .envrc in this project
direnv allow .
```

**Error:** "direnv hook not working"

**Solution:**
```bash
# Check if hook is in shell config
grep direnv ~/.zshrc  # or ~/.bashrc

# If not present, add manually
echo 'eval "$(direnv hook zsh)"' >> ~/.zshrc

# Reload shell
source ~/.zshrc
```

### WSL-Specific Issues

**Error:** "Nix daemon not running"

**Solution:**
```bash
# Check daemon status
sudo systemctl status nix-daemon

# Start daemon
sudo systemctl start nix-daemon

# Enable at boot
sudo systemctl enable nix-daemon
```

**Error:** "Permission denied" on /nix

**Solution:**
```bash
# Check ownership
ls -la /nix

# Fix permissions (if needed)
sudo chown -R $USER:$USER $HOME/.nix-profile
```

### Package Manager Issues

**Error:** "Unknown package manager"

**Solution:**
```bash
# Install direnv via Nix instead
nix-env -iA nixpkgs.direnv

# Verify
direnv version
```

### Slow Environment Loading

**Without nix-direnv:**
- First load: 5-10 seconds (normal)
- Subsequent loads: 5-10 seconds (slow!)

**With nix-direnv:**
- First load: 5-10 seconds (normal, building cache)
- Subsequent loads: <1 second (cached!)

**Solution:**
```bash
# Install nix-direnv
nix-env -iA nixpkgs.nix-direnv

# Configure in ~/.config/direnv/direnvrc
mkdir -p ~/.config/direnv
echo 'source $HOME/.nix-profile/share/nix-direnv/direnvrc' \
  >> ~/.config/direnv/direnvrc
```

---

## Uninstallation

### Remove Everything

```bash
# Uninstall Determinate Nix
/nix/nix-installer uninstall

# Remove direnv
brew uninstall direnv          # macOS
sudo apt-get remove direnv     # Ubuntu/Debian
sudo dnf remove direnv         # Fedora
sudo pacman -R direnv          # Arch

# Remove shell hooks
# Edit your ~/.zshrc or ~/.bashrc and remove lines:
# eval "$(direnv hook ...)"

# Remove nix-direnv config
rm -rf ~/.config/direnv/

# Restore from backup (if desired)
mv ~/.zshrc.backup-YYYYMMDD-HHMMSS ~/.zshrc
```

---

## Comparison: macOS-Only vs Unified Installer

| Feature | devenv-macos-installer.sh | devenv-installer.sh |
|---------|---------------------------|---------------------|
| **Platforms** | macOS only | macOS, Linux, WSL |
| **Package Managers** | Homebrew | 6+ package managers |
| **Distro Detection** | N/A | Full Linux distro detection |
| **WSL Support** | ❌ No | ✅ Yes |
| **Size** | 291 lines | 520 lines |
| **Maintenance** | macOS-specific | Universal |
| **Recommended** | Legacy | ✅ Use this |

---

## Support

- **Issues**: https://github.com/dspearson/sss/issues
- **Nix Docs**: https://nixos.org/manual/nix/stable/
- **direnv Docs**: https://direnv.net/
- **Determinate Nix**: https://determinate.systems/nix/

---

## License

SSS and its installers are licensed under the ISC License. See [LICENSE](../LICENSE) for details.
