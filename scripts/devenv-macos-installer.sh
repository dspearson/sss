#!/bin/bash
# Development Environment Installer for macOS
# Installs: Determinate Nix (with flakes) + direnv
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}  Development Environment Installer for macOS   ${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "${CYAN}This will install:${NC}"
echo -e "  • Homebrew (if not already installed)"
echo -e "  • Determinate Nix (with flakes enabled)"
echo -e "  • direnv (for automatic environment loading)"
echo -e "  • libsodium (crypto library)"
echo -e "  • Shell hooks for direnv"
echo ""

# Check if running on macOS
if [[ "$(uname -s)" != "Darwin" ]]; then
    echo -e "${RED}Error: This installer is for macOS only.${NC}"
    exit 1
fi

# Detect architecture
ARCH=$(uname -m)
echo -e "${CYAN}Detected architecture:${NC} $ARCH"
echo ""

# Detect shell and config file
SHELL_NAME=$(basename "$SHELL")
if [[ "$SHELL_NAME" == "zsh" ]]; then
    SHELL_CONFIG="$HOME/.zshrc"
    SHELL_TYPE="zsh"
elif [[ "$SHELL_NAME" == "bash" ]]; then
    if [[ -f "$HOME/.bash_profile" ]]; then
        SHELL_CONFIG="$HOME/.bash_profile"
    else
        SHELL_CONFIG="$HOME/.bashrc"
    fi
    SHELL_TYPE="bash"
else
    SHELL_CONFIG="$HOME/.profile"
    SHELL_TYPE="sh"
fi

echo -e "${CYAN}Detected shell:${NC} $SHELL_TYPE"
echo -e "${CYAN}Config file:${NC} $SHELL_CONFIG"
echo ""

# Confirmation prompt
read -p "$(echo -e ${YELLOW}Continue with installation? [y/N]:${NC} )" -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Installation cancelled."
    exit 0
fi
echo ""

# ============================================================================
# Step 1: Install Determinate Nix
# ============================================================================
echo -e "${BLUE}[1/3]${NC} Installing Determinate Nix..."
echo ""

if command -v nix &> /dev/null; then
    echo -e "${GREEN}✓${NC} Nix is already installed"
    nix --version
    echo ""

    # Check if flakes are enabled
    if nix flake --help &> /dev/null 2>&1; then
        echo -e "${GREEN}✓${NC} Flakes are enabled"
    else
        echo -e "${YELLOW}⚠${NC}  Flakes are not enabled in your Nix installation"
        echo ""
        read -p "$(echo -e ${YELLOW}Would you like to reinstall with Determinate Nix? [y/N]:${NC} )" -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            echo "Uninstalling existing Nix installation..."
            if [ -f /nix/receipt.json ]; then
                # Determinate Nix uninstaller
                /nix/nix-installer uninstall
            else
                # Standard Nix uninstaller
                if [ -f /nix/uninstall ]; then
                    /nix/uninstall
                else
                    echo -e "${YELLOW}⚠${NC}  Manual uninstall required. Please follow:"
                    echo "  https://nixos.org/manual/nix/stable/installation/uninstall.html"
                    exit 1
                fi
            fi
            echo "Installing Determinate Nix..."
            curl --proto '=https' --tlsv1.2 -sSf -L https://install.determinate.systems/nix | sh -s -- install --no-confirm
        fi
    fi
else
    echo "Installing Determinate Nix (this may take a few minutes)..."
    echo ""

    # Install Determinate Nix noninteractively
    # The --no-confirm flag makes it noninteractive
    curl --proto '=https' --tlsv1.2 -sSf -L https://install.determinate.systems/nix | sh -s -- install --no-confirm

    if [ $? -eq 0 ]; then
        echo ""
        echo -e "${GREEN}✓${NC} Determinate Nix installed successfully"

        # Source Nix for this session
        if [ -e '/nix/var/nix/profiles/default/etc/profile.d/nix-daemon.sh' ]; then
            . '/nix/var/nix/profiles/default/etc/profile.d/nix-daemon.sh'
        fi
    else
        echo -e "${RED}Error: Failed to install Determinate Nix${NC}"
        exit 1
    fi
fi

echo ""

# ============================================================================
# Step 2: Install Homebrew (if needed) and dependencies
# ============================================================================
echo -e "${BLUE}[2/4]${NC} Installing Homebrew (if needed)..."
echo ""

if command -v brew &> /dev/null; then
    echo -e "${GREEN}✓${NC} Homebrew is already installed"
else
    echo "Installing Homebrew..."
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

    # Add Homebrew to PATH for this session
    if [[ -f "/opt/homebrew/bin/brew" ]]; then
        eval "$(/opt/homebrew/bin/brew shellenv)"
    elif [[ -f "/usr/local/bin/brew" ]]; then
        eval "$(/usr/local/bin/brew shellenv)"
    fi

    if command -v brew &> /dev/null; then
        echo -e "${GREEN}✓${NC} Homebrew installed successfully"
    else
        echo -e "${RED}Error: Failed to install Homebrew${NC}"
        exit 1
    fi
fi

echo ""

# ============================================================================
# Step 3: Install direnv and libsodium
# ============================================================================
echo -e "${BLUE}[3/4]${NC} Installing direnv and libsodium..."
echo ""

if command -v direnv &> /dev/null; then
    echo -e "${GREEN}✓${NC} direnv is already installed"
    direnv version
else
    # Install direnv via Homebrew or Nix
    if command -v brew &> /dev/null; then
        echo "Installing direnv via Homebrew..."
        brew install direnv
    elif command -v nix-env &> /dev/null; then
        echo "Installing direnv via Nix..."
        nix-env -iA nixpkgs.direnv
    else
        echo -e "${YELLOW}⚠${NC}  Cannot install direnv (no package manager found)"
        echo "Please install Homebrew or use Nix to install direnv manually:"
        echo "  nix-env -iA nixpkgs.direnv"
        exit 1
    fi

    if command -v direnv &> /dev/null; then
        echo -e "${GREEN}✓${NC} direnv installed successfully"
    else
        echo -e "${RED}Error: Failed to install direnv${NC}"
        exit 1
    fi
fi

# Install libsodium
if brew list libsodium &> /dev/null; then
    echo -e "${GREEN}✓${NC} libsodium is already installed"
else
    echo "Installing libsodium via Homebrew..."
    brew install libsodium
    if brew list libsodium &> /dev/null; then
        echo -e "${GREEN}✓${NC} libsodium installed successfully"
    else
        echo -e "${RED}Error: Failed to install libsodium${NC}"
        exit 1
    fi
fi

echo ""

# ============================================================================
# Step 4: Configure direnv shell hooks
# ============================================================================
echo -e "${BLUE}[4/4]${NC} Configuring direnv shell hooks..."
echo ""

# Backup shell config
if [ -f "$SHELL_CONFIG" ]; then
    cp "$SHELL_CONFIG" "$SHELL_CONFIG.backup-$(date +%Y%m%d-%H%M%S)"
    echo -e "${GREEN}✓${NC} Backed up $SHELL_CONFIG"
fi

# Check if direnv hook is already configured
if grep -q "direnv hook" "$SHELL_CONFIG" 2>/dev/null; then
    echo -e "${GREEN}✓${NC} direnv hook already configured in $SHELL_CONFIG"
else
    echo "Adding direnv hook to $SHELL_CONFIG..."

    # Add hook based on shell type
    {
        echo ""
        echo "# Added by devenv-macos-installer.sh"
        echo "# direnv - automatic environment loading"
        if [[ "$SHELL_TYPE" == "zsh" ]]; then
            echo 'eval "$(direnv hook zsh)"'
        elif [[ "$SHELL_TYPE" == "bash" ]]; then
            echo 'eval "$(direnv hook bash)"'
        else
            echo 'eval "$(direnv hook $SHELL)"'
        fi
    } >> "$SHELL_CONFIG"

    echo -e "${GREEN}✓${NC} direnv hook added to $SHELL_CONFIG"
fi

echo ""

# ============================================================================
# Optional: Install nix-direnv for better Nix integration
# ============================================================================
echo -e "${CYAN}Optional:${NC} Install nix-direnv for faster Nix shell loading?"
echo "nix-direnv caches Nix environments for much faster direnv loading."
echo ""
read -p "$(echo -e ${YELLOW}Install nix-direnv? [Y/n]:${NC} )" -n 1 -r
echo
if [[ ! $REPLY =~ ^[Nn]$ ]]; then
    if command -v nix-env &> /dev/null; then
        echo "Installing nix-direnv..."
        nix-env -iA nixpkgs.nix-direnv

        # Configure nix-direnv in direnv config
        mkdir -p "$HOME/.config/direnv"

        if ! grep -q "source.*nix-direnv" "$HOME/.config/direnv/direnvrc" 2>/dev/null; then
            {
                echo ""
                echo "# Added by devenv-macos-installer.sh"
                echo "# nix-direnv integration"
                echo 'source $HOME/.nix-profile/share/nix-direnv/direnvrc'
            } >> "$HOME/.config/direnv/direnvrc"
            echo -e "${GREEN}✓${NC} nix-direnv configured"
        else
            echo -e "${GREEN}✓${NC} nix-direnv already configured"
        fi
    else
        echo -e "${YELLOW}⚠${NC}  Nix not available, skipping nix-direnv"
    fi
fi

echo ""

# ============================================================================
# Installation Complete
# ============================================================================
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}✅ Installation complete!${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

echo -e "${CYAN}What was installed:${NC}"
echo -e "  ${GREEN}✓${NC} Homebrew"
echo -e "  ${GREEN}✓${NC} Determinate Nix (with flakes enabled)"
echo -e "  ${GREEN}✓${NC} direnv"
echo -e "  ${GREEN}✓${NC} libsodium"
echo -e "  ${GREEN}✓${NC} Shell hooks configured"
echo ""

echo -e "${BLUE}🔄 Next Steps:${NC}"
echo ""
echo "1. Reload your shell configuration:"
echo -e "   ${CYAN}source $SHELL_CONFIG${NC}"
echo ""
echo "2. Or open a new terminal window"
echo ""
echo "3. Verify installation:"
echo -e "   ${CYAN}nix --version${NC}"
echo -e "   ${CYAN}direnv version${NC}"
echo ""

echo -e "${BLUE}🚀 Quick Start with Nix Flakes:${NC}"
echo ""
echo "Create a flake.nix in your project:"
echo -e "   ${CYAN}nix flake init${NC}"
echo ""
echo "Create a .envrc file for direnv:"
echo -e '   echo "use flake" > .envrc'
echo -e "   ${CYAN}direnv allow${NC}"
echo ""
echo "Now direnv will automatically load your Nix environment when you cd into the directory!"
echo ""

echo -e "${BLUE}📖 Documentation:${NC}"
echo "  Nix Flakes: https://nixos.wiki/wiki/Flakes"
echo "  direnv: https://direnv.net/"
echo "  Determinate Nix: https://determinate.systems/nix/"
echo ""

# Verification
if command -v nix &> /dev/null && command -v direnv &> /dev/null; then
    echo -e "${GREEN}✓${NC} Installation verified successfully!"
    echo ""

    # Show versions
    echo -e "${CYAN}Installed versions:${NC}"
    echo -n "  Nix: "
    nix --version
    echo -n "  direnv: "
    direnv version
    echo ""
fi

echo -e "${YELLOW}💡 Tip:${NC} Use this with the SSS project for automatic environment setup!"
echo ""
