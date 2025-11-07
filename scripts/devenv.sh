#!/bin/bash
# Universal Development Environment Manager
# Supports: macOS, Linux, WSL (Ubuntu/Debian/Fedora/Arch)
# Features: Install/Uninstall Determinate Nix (with flakes) + direnv + shell hooks
set -e

# Parse command line arguments
MODE="install"
for arg in "$@"; do
    case $arg in
        --uninstall)
            MODE="uninstall"
            shift
            ;;
        --help|-h)
            echo "Universal Development Environment Manager"
            echo ""
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  (none)        Install development environment (default)"
            echo "  --uninstall   Uninstall development environment"
            echo "  --help, -h    Show this help message"
            echo ""
            echo "What it manages:"
            echo "  • Determinate Nix (with flakes enabled)"
            echo "  • direnv (for automatic environment loading)"
            echo "  • Shell hooks for direnv"
            echo "  • nix-direnv (optional, for faster loading)"
            exit 0
            ;;
    esac
done

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'

# Global variables
PLATFORM=""
DISTRO=""
PKG_MANAGER=""

# ============================================================================
# Platform Detection Functions
# ============================================================================

detect_platform() {
    local os_type="$(uname -s)"

    case "$os_type" in
        Darwin)
            PLATFORM="macos"
            DISTRO="macos"
            PKG_MANAGER="brew"
            ;;
        Linux)
            PLATFORM="linux"

            # Check if WSL
            if grep -qi microsoft /proc/version 2>/dev/null || \
               grep -qi WSL /proc/version 2>/dev/null || \
               [ -n "$WSL_DISTRO_NAME" ]; then
                PLATFORM="wsl"
            fi

            # Detect distribution
            detect_linux_distro
            ;;
        *)
            echo -e "${RED}Error: Unsupported operating system: $os_type${NC}"
            exit 1
            ;;
    esac
}

detect_linux_distro() {
    # Try os-release first (modern standard)
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        DISTRO="$ID"

        # Detect package manager
        if command -v apt-get &> /dev/null; then
            PKG_MANAGER="apt"
        elif command -v dnf &> /dev/null; then
            PKG_MANAGER="dnf"
        elif command -v yum &> /dev/null; then
            PKG_MANAGER="yum"
        elif command -v pacman &> /dev/null; then
            PKG_MANAGER="pacman"
        elif command -v zypper &> /dev/null; then
            PKG_MANAGER="zypper"
        else
            PKG_MANAGER="unknown"
        fi

    # Fallback detection methods
    elif [ -f /etc/debian_version ]; then
        DISTRO="debian"
        PKG_MANAGER="apt"
    elif [ -f /etc/redhat-release ]; then
        DISTRO="rhel"
        PKG_MANAGER="yum"
    elif [ -f /etc/arch-release ]; then
        DISTRO="arch"
        PKG_MANAGER="pacman"
    else
        DISTRO="unknown"
        PKG_MANAGER="unknown"
    fi
}

# ============================================================================
# Shell Detection
# ============================================================================

detect_shell_config() {
    SHELL_NAME=$(basename "$SHELL")

    if [[ "$SHELL_NAME" == "zsh" ]]; then
        SHELL_CONFIG="$HOME/.zshrc"
        SHELL_TYPE="zsh"
    elif [[ "$SHELL_NAME" == "bash" ]]; then
        # Linux/WSL typically uses .bashrc, macOS uses .bash_profile
        if [[ "$PLATFORM" == "macos" ]] && [[ -f "$HOME/.bash_profile" ]]; then
            SHELL_CONFIG="$HOME/.bash_profile"
        else
            SHELL_CONFIG="$HOME/.bashrc"
        fi
        SHELL_TYPE="bash"
    elif [[ "$SHELL_NAME" == "fish" ]]; then
        SHELL_CONFIG="$HOME/.config/fish/config.fish"
        SHELL_TYPE="fish"
    else
        SHELL_CONFIG="$HOME/.profile"
        SHELL_TYPE="sh"
    fi
}

# ============================================================================
# Installation Functions
# ============================================================================

install_direnv_native() {
    echo "Installing direnv and dependencies via system package manager..."

    case "$PKG_MANAGER" in
        brew)
            if ! command -v brew &> /dev/null; then
                echo "Installing Homebrew..."
                /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

                # Add Homebrew to PATH for this session
                if [[ -f "/opt/homebrew/bin/brew" ]]; then
                    eval "$(/opt/homebrew/bin/brew shellenv)"
                elif [[ -f "/usr/local/bin/brew" ]]; then
                    eval "$(/usr/local/bin/brew shellenv)"
                fi
            fi
            echo "Installing direnv and libsodium..."
            brew install direnv libsodium
            ;;

        apt)
            echo "Using apt package manager..."
            sudo apt-get update -qq
            sudo apt-get install -y direnv libfuse3-dev fuse3
            ;;

        dnf)
            echo "Using dnf package manager..."
            sudo dnf install -y direnv fuse3 fuse3-devel
            ;;

        yum)
            echo "Using yum package manager..."
            sudo yum install -y direnv fuse3 fuse3-devel
            ;;

        pacman)
            echo "Using pacman package manager..."
            sudo pacman -Sy --noconfirm direnv fuse3
            ;;

        zypper)
            echo "Using zypper package manager..."
            sudo zypper install -y direnv fuse3 fuse3-devel
            ;;

        *)
            echo -e "${YELLOW}⚠${NC}  Unknown package manager, will install via Nix later"
            return 1
            ;;
    esac

    return 0
}

show_install_banner() {
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}  Universal Development Environment Installer      ${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo -e "${CYAN}This will install:${NC}"
    echo -e "  • Determinate Nix (with flakes enabled)"
    echo -e "  • direnv (for automatic environment loading)"
    if [[ "$PLATFORM" == "macos" ]]; then
        echo -e "  • libsodium (crypto library)"
    else
        echo -e "  • FUSE3 (filesystem in userspace)"
    fi
    echo -e "  • Shell hooks for direnv"
    echo ""
}

show_platform_info() {
    echo -e "${CYAN}Detected Platform:${NC}"
    echo -e "  Platform:        $PLATFORM"
    echo -e "  Distribution:    $DISTRO"
    echo -e "  Package Manager: $PKG_MANAGER"
    echo -e "  Architecture:    $(uname -m)"
    echo ""

    detect_shell_config
    echo -e "${CYAN}Shell Configuration:${NC}"
    echo -e "  Shell:           $SHELL_TYPE"
    echo -e "  Config File:     $SHELL_CONFIG"
    echo ""
}

check_prerequisites() {
    echo -e "${BLUE}Checking prerequisites...${NC}"
    echo ""

    # Check if running as root (not recommended for Nix)
    if [[ $EUID -eq 0 ]]; then
        echo -e "${YELLOW}⚠${NC}  Running as root is not recommended, but continuing anyway..."
        echo "Nix works best when installed as a regular user"
    fi

    # Check for curl (required for installers)
    if ! command -v curl &> /dev/null; then
        echo -e "${RED}Error: curl is required but not installed${NC}"
        echo "Please install curl first:"
        case "$PKG_MANAGER" in
            apt) echo "  sudo apt-get install curl" ;;
            dnf) echo "  sudo dnf install curl" ;;
            yum) echo "  sudo yum install curl" ;;
            pacman) echo "  sudo pacman -S curl" ;;
            *) echo "  (use your package manager to install curl)" ;;
        esac
        exit 1
    fi

    echo -e "${GREEN}✓${NC} Prerequisites met"
    echo ""
}

install_nix() {
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
            echo -e "${YELLOW}⚠${NC}  Flakes are not enabled, reinstalling with Determinate Nix..."
            echo ""

            echo "Uninstalling existing Nix installation..."
            if [ -f /nix/receipt.json ]; then
                /nix/nix-installer uninstall
            else
                if [ -f /nix/uninstall ]; then
                    /nix/uninstall
                else
                    echo -e "${YELLOW}⚠${NC}  Manual uninstall required"
                    echo "See: https://nixos.org/manual/nix/stable/installation/uninstall.html"
                    exit 1
                fi
            fi

            echo "Installing Determinate Nix..."
            curl --proto '=https' --tlsv1.2 -sSf -L https://install.determinate.systems/nix | \
                sh -s -- install --no-confirm
        fi
    else
        echo "Installing Determinate Nix (this may take a few minutes)..."
        echo ""

        # Install Determinate Nix noninteractively
        curl --proto '=https' --tlsv1.2 -sSf -L https://install.determinate.systems/nix | \
            sh -s -- install --no-confirm

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
}

install_direnv() {
    echo -e "${BLUE}[2/3]${NC} Installing direnv..."
    echo ""

    if command -v direnv &> /dev/null; then
        echo -e "${GREEN}✓${NC} direnv is already installed"
        direnv version
    else
        # Try native package manager first
        if ! install_direnv_native; then
            # Fallback to Nix
            echo "Installing direnv via Nix..."
            if command -v nix-env &> /dev/null; then
                nix-env -iA nixpkgs.direnv
            else
                echo -e "${RED}Error: Cannot install direnv (no package manager or Nix found)${NC}"
                exit 1
            fi
        fi

        if command -v direnv &> /dev/null; then
            echo -e "${GREEN}✓${NC} direnv installed successfully"
        else
            echo -e "${RED}Error: Failed to install direnv${NC}"
            exit 1
        fi
    fi

    echo ""
}

configure_shell_hooks() {
    echo -e "${BLUE}[3/3]${NC} Configuring direnv shell hooks..."
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
            echo "# Added by devenv.sh"
            echo "# direnv - automatic environment loading"
            case "$SHELL_TYPE" in
                zsh)
                    echo 'eval "$(direnv hook zsh)"'
                    ;;
                bash)
                    echo 'eval "$(direnv hook bash)"'
                    ;;
                fish)
                    echo 'direnv hook fish | source'
                    ;;
                *)
                    echo 'eval "$(direnv hook $SHELL)"'
                    ;;
            esac
        } >> "$SHELL_CONFIG"

        echo -e "${GREEN}✓${NC} direnv hook added to $SHELL_CONFIG"
    fi

    echo ""
}

install_nix_direnv() {
    echo -e "${CYAN}Installing nix-direnv for faster Nix shell loading...${NC}"
    echo "nix-direnv caches Nix environments for much faster direnv loading."
    echo ""
        if command -v nix &> /dev/null; then
            echo "Installing nix-direnv..."
            # Use flakes-based installation (works with Determinate Nix)
            nix profile add nixpkgs#nix-direnv

            # Configure nix-direnv
            mkdir -p "$HOME/.config/direnv"

            if ! grep -q "source.*nix-direnv" "$HOME/.config/direnv/direnvrc" 2>/dev/null; then
                {
                    echo ""
                    echo "# Added by devenv.sh"
                    echo "# nix-direnv integration"
                    echo 'NIX_DIRENV_PATHS=('
                    echo '  "$HOME/.nix-profile/share/nix-direnv/direnvrc"'
                    echo '  "$HOME/.local/state/nix/profile/share/nix-direnv/direnvrc"'
                    echo ')'
                    echo 'for path in "${NIX_DIRENV_PATHS[@]}"; do'
                    echo '  if [ -f "$path" ]; then'
                    echo '    source "$path"'
                    echo '    break'
                    echo '  fi'
                    echo 'done'
                } >> "$HOME/.config/direnv/direnvrc"
                echo -e "${GREEN}✓${NC} nix-direnv configured"
            else
                echo -e "${GREEN}✓${NC} nix-direnv already configured"
            fi
        else
            echo -e "${YELLOW}⚠${NC}  Nix not available, skipping nix-direnv"
        fi

    echo ""
}

show_install_completion() {
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${GREEN}✅ Installation complete!${NC}"
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""

    echo -e "${CYAN}What was installed:${NC}"
    echo -e "  ${GREEN}✓${NC} Determinate Nix (with flakes enabled)"
    echo -e "  ${GREEN}✓${NC} direnv"
    if [[ "$PLATFORM" == "macos" ]]; then
        echo -e "  ${GREEN}✓${NC} libsodium"
    else
        echo -e "  ${GREEN}✓${NC} FUSE3"
    fi
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
    echo "Now direnv will automatically load your Nix environment!"
    echo ""

    # Platform-specific notes
    if [[ "$PLATFORM" == "wsl" ]]; then
        echo -e "${MAGENTA}WSL-Specific Notes:${NC}"
        echo "  • Windows binaries won't work in Nix environments"
        echo "  • Use Linux tools installed via Nix or native package manager"
        echo "  • WSL2 recommended for best performance"
        echo ""
    fi

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
        nix --version 2>/dev/null || echo "installed (restart shell to use)"
        echo -n "  direnv: "
        direnv version
        echo ""
    fi

    echo -e "${YELLOW}💡 Tip:${NC} Use this with projects that have flake.nix for automatic environment setup!"
    echo ""
}

# ============================================================================
# Uninstallation Functions
# ============================================================================

show_uninstall_banner() {
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}  Universal Development Environment Uninstaller    ${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo -e "${CYAN}This will uninstall:${NC}"
    echo -e "  • Determinate Nix"
    echo -e "  • direnv shell hooks"
    echo -e "  • nix-direnv configuration"
    echo ""
    echo -e "${YELLOW}Note: direnv package will NOT be removed (use your package manager)${NC}"
    echo ""
}

uninstall_nix() {
    echo -e "${BLUE}[1/3]${NC} Uninstalling Nix..."
    echo ""

    if command -v nix &> /dev/null; then
        # Determinate Nix uninstaller
        if [ -f /nix/receipt.json ]; then
            echo "Uninstalling Determinate Nix..."
            /nix/nix-installer uninstall
            echo -e "${GREEN}✓${NC} Nix uninstalled"
        # Legacy Nix uninstaller
        elif [ -f /nix/uninstall ]; then
            echo "Uninstalling legacy Nix..."
            /nix/uninstall
            echo -e "${GREEN}✓${NC} Nix uninstalled"
        else
            echo -e "${YELLOW}⚠${NC}  Nix found but no uninstaller detected"
            echo "Manual uninstall may be required:"
            echo "  https://nixos.org/manual/nix/stable/installation/uninstall.html"
        fi
    else
        echo -e "${GREEN}✓${NC} Nix not installed (skipping)"
    fi

    echo ""
}

remove_shell_hooks() {
    echo -e "${BLUE}[2/3]${NC} Removing direnv shell hooks..."
    echo ""

    detect_shell_config

    if [ -f "$SHELL_CONFIG" ]; then
        # Backup first
        cp "$SHELL_CONFIG" "$SHELL_CONFIG.backup-uninstall-$(date +%Y%m%d-%H%M%S)"
        echo -e "${GREEN}✓${NC} Backed up $SHELL_CONFIG"

        # Remove direnv hook lines added by devenv.sh or devenv-installer.sh
        if grep -q "devenv.sh\|devenv-installer.sh" "$SHELL_CONFIG" 2>/dev/null; then
            # Remove the comment and hook lines added by installer
            sed -i.tmp '/# Added by devenv.*\.sh/,/direnv hook/d' "$SHELL_CONFIG"
            rm -f "$SHELL_CONFIG.tmp"
            echo -e "${GREEN}✓${NC} Removed direnv hooks from $SHELL_CONFIG"
        else
            echo -e "${GREEN}✓${NC} No direnv hooks found in $SHELL_CONFIG"
        fi
    else
        echo -e "${GREEN}✓${NC} Shell config not found (skipping)"
    fi

    echo ""
}

remove_nix_direnv() {
    echo -e "${BLUE}[3/3]${NC} Removing nix-direnv configuration..."
    echo ""

    if [ -f "$HOME/.config/direnv/direnvrc" ]; then
        # Backup first
        cp "$HOME/.config/direnv/direnvrc" "$HOME/.config/direnv/direnvrc.backup-$(date +%Y%m%d-%H%M%S)"
        echo -e "${GREEN}✓${NC} Backed up direnvrc"

        # Remove nix-direnv configuration added by devenv.sh or devenv-installer.sh
        if grep -q "devenv.*\.sh" "$HOME/.config/direnv/direnvrc" 2>/dev/null; then
            # Remove lines between the marker and 'done'
            sed -i.tmp '/# Added by devenv.*\.sh/,/^done$/d' "$HOME/.config/direnv/direnvrc"
            rm -f "$HOME/.config/direnv/direnvrc.tmp"
            echo -e "${GREEN}✓${NC} Removed nix-direnv configuration"
        else
            echo -e "${GREEN}✓${NC} No nix-direnv configuration found"
        fi
    else
        echo -e "${GREEN}✓${NC} direnvrc not found (skipping)"
    fi

    echo ""
}

show_uninstall_completion() {
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${GREEN}✅ Uninstallation complete!${NC}"
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""

    echo -e "${CYAN}What was removed:${NC}"
    echo -e "  ${GREEN}✓${NC} Nix installation (/nix directory)"
    echo -e "  ${GREEN}✓${NC} direnv shell hooks"
    echo -e "  ${GREEN}✓${NC} nix-direnv configuration"
    echo ""

    echo -e "${BLUE}Optional: Remove direnv package${NC}"
    echo ""
    echo "To completely remove direnv, use your package manager:"

    # Detect package manager
    if command -v brew &> /dev/null; then
        echo -e "  ${CYAN}brew uninstall direnv${NC}"
    elif command -v apt-get &> /dev/null; then
        echo -e "  ${CYAN}sudo apt-get remove direnv${NC}"
    elif command -v dnf &> /dev/null; then
        echo -e "  ${CYAN}sudo dnf remove direnv${NC}"
    elif command -v yum &> /dev/null; then
        echo -e "  ${CYAN}sudo yum remove direnv${NC}"
    elif command -v pacman &> /dev/null; then
        echo -e "  ${CYAN}sudo pacman -R direnv${NC}"
    fi

    echo ""
    echo -e "${BLUE}🔄 Next Steps:${NC}"
    echo ""
    echo "1. Restart your shell or open a new terminal"
    echo ""
    echo "2. Verify removal:"
    echo -e "   ${CYAN}command -v nix${NC} (should show nothing)"
    echo ""

    echo -e "${YELLOW}💡 Backup files created:${NC}"
    echo "  • $SHELL_CONFIG.backup-uninstall-*"
    if [ -f "$HOME/.config/direnv/direnvrc.backup-"* 2>/dev/null ]; then
        echo "  • $HOME/.config/direnv/direnvrc.backup-*"
    fi
    echo ""
}

# ============================================================================
# Main Execution
# ============================================================================

main_install() {
    # Show immediate progress
    echo "Starting Development Environment Installer..."
    echo ""

    # Cache sudo credentials if needed (non-root users on Linux)
    if [[ $EUID -ne 0 ]] && [[ "$(uname -s)" == "Linux" ]]; then
        echo "This installer may need sudo access for package installation."
        echo "Caching sudo credentials..."
        sudo -v
        # Keep sudo alive in background
        ( while true; do sudo -n true; sleep 50; done 2>/dev/null ) &
        SUDO_KEEP_ALIVE_PID=$!
        trap "kill $SUDO_KEEP_ALIVE_PID 2>/dev/null" EXIT
        echo ""
    fi

    # Detect platform
    detect_platform

    # Show banner and info
    show_install_banner
    show_platform_info

    # Check prerequisites
    check_prerequisites

    # Auto-proceed with installation (non-interactive)
    echo -e "${GREEN}Starting installation...${NC}"
    echo ""

    # Install components
    install_nix
    install_direnv
    configure_shell_hooks
    install_nix_direnv

    # Show completion message
    show_install_completion
}

main_uninstall() {
    # Detect platform
    detect_platform

    # Show banner
    show_uninstall_banner

    # Uninstall components
    uninstall_nix
    remove_shell_hooks
    remove_nix_direnv

    # Show completion message
    show_uninstall_completion
}

# Run appropriate mode
if [[ "$MODE" == "uninstall" ]]; then
    main_uninstall
else
    main_install
fi
