#!/bin/bash
# SSS Installer for macOS
# Usage: curl -fsSL https://raw.githubusercontent.com/user/sss/main/install.sh | bash

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}SSS Installer for macOS${NC}"
echo ""

# Detect architecture
ARCH=$(uname -m)
if [[ "$ARCH" == "arm64" ]]; then
    BINARY_URL="https://github.com/yourusername/sss/releases/latest/download/sss-macos-arm64"
    echo "Detected: Apple Silicon (ARM64)"
elif [[ "$ARCH" == "x86_64" ]]; then
    BINARY_URL="https://github.com/yourusername/sss/releases/latest/download/sss-macos-x86_64"
    echo "Detected: Intel (x86_64)"
else
    echo -e "${RED}Error: Unsupported architecture: $ARCH${NC}"
    exit 1
fi

# Installation directory
INSTALL_DIR="$HOME/.local/bin"
BINARY_NAME="sss"
INSTALL_PATH="$INSTALL_DIR/$BINARY_NAME"

echo ""
echo "Installing to: $INSTALL_PATH"
echo ""

# Create directory
mkdir -p "$INSTALL_DIR"

# Download binary
echo -e "${BLUE}[1/5]${NC} Downloading sss binary..."
if ! curl -fsSL "$BINARY_URL" -o "$INSTALL_PATH"; then
    echo -e "${RED}Error: Failed to download binary from $BINARY_URL${NC}"
    echo "Please check if the release exists or download manually from:"
    echo "https://github.com/yourusername/sss/releases"
    exit 1
fi

# Remove quarantine attribute (macOS Gatekeeper)
echo -e "${BLUE}[2/5]${NC} Removing quarantine attribute..."
xattr -d com.apple.quarantine "$INSTALL_PATH" 2>/dev/null || true
xattr -c "$INSTALL_PATH" 2>/dev/null || true

# Make executable
echo -e "${BLUE}[3/5]${NC} Making binary executable..."
chmod +x "$INSTALL_PATH"

# Detect shell and config file
SHELL_NAME=$(basename "$SHELL")
if [[ "$SHELL_NAME" == "zsh" ]]; then
    SHELL_CONFIG="$HOME/.zshrc"
elif [[ "$SHELL_NAME" == "bash" ]]; then
    if [[ -f "$HOME/.bash_profile" ]]; then
        SHELL_CONFIG="$HOME/.bash_profile"
    else
        SHELL_CONFIG="$HOME/.bashrc"
    fi
else
    SHELL_CONFIG="$HOME/.profile"
fi

# Add to PATH if not already there
echo -e "${BLUE}[4/5]${NC} Configuring PATH..."
PATH_EXPORT="export PATH=\"\$HOME/.local/bin:\$PATH\""

if [[ ":$PATH:" != *":$INSTALL_DIR:"* ]]; then
    # Check if already in shell config
    if ! grep -q "\.local/bin" "$SHELL_CONFIG" 2>/dev/null; then
        echo "" >> "$SHELL_CONFIG"
        echo "# Added by SSS installer" >> "$SHELL_CONFIG"
        echo "$PATH_EXPORT" >> "$SHELL_CONFIG"
        echo -e "${GREEN}✓${NC} Added $INSTALL_DIR to PATH in $SHELL_CONFIG"
        PATH_UPDATED=true
    else
        echo -e "${GREEN}✓${NC} PATH already configured in $SHELL_CONFIG"
        PATH_UPDATED=false
    fi
else
    echo -e "${GREEN}✓${NC} $INSTALL_DIR already in PATH"
    PATH_UPDATED=false
fi

# Install dependencies check
echo -e "${BLUE}[5/5]${NC} Checking dependencies..."
MISSING_DEPS=()

if ! command -v brew &> /dev/null; then
    echo -e "${YELLOW}⚠${NC}  Homebrew not found (needed for dependencies)"
    MISSING_DEPS+=("homebrew")
fi

if ! brew list libsodium &> /dev/null 2>&1; then
    echo -e "${YELLOW}⚠${NC}  libsodium not installed"
    MISSING_DEPS+=("libsodium")
fi

if ! [ -e /Library/Filesystems/macfuse.fs ] && ! [ -e /Library/Filesystems/osxfuse.fs ]; then
    echo -e "${YELLOW}⚠${NC}  macFUSE not installed"
    MISSING_DEPS+=("macfuse")
fi

# Installation complete
echo ""
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}✅ Installation complete!${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# Show next steps
if [[ ${#MISSING_DEPS[@]} -gt 0 ]]; then
    echo -e "${YELLOW}📦 Install required dependencies:${NC}"
    echo ""
    if [[ " ${MISSING_DEPS[@]} " =~ " homebrew " ]]; then
        echo "  # Install Homebrew first:"
        echo "  /bin/bash -c \"\$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\""
        echo ""
    fi
    if [[ " ${MISSING_DEPS[@]} " =~ " libsodium " ]]; then
        echo "  brew install libsodium"
    fi
    if [[ " ${MISSING_DEPS[@]} " =~ " macfuse " ]]; then
        echo "  brew install --cask macfuse"
    fi
    echo ""
fi

if [[ "$PATH_UPDATED" == "true" ]]; then
    echo -e "${BLUE}🔄 Reload your shell configuration:${NC}"
    echo ""
    echo "  source $SHELL_CONFIG"
    echo ""
    echo "Or open a new terminal window."
    echo ""
fi

echo -e "${BLUE}🚀 Quick Start:${NC}"
echo ""
echo "  sss --version           # Verify installation"
echo "  sss init                # Initialize a new project"
echo "  sss mount --in-place    # Mount with transparent encryption"
echo ""
echo -e "📖 Documentation: ${BLUE}https://github.com/yourusername/sss${NC}"
echo ""

# Verify binary works (if PATH is set)
if command -v sss &> /dev/null || [[ ":$PATH:" == *":$INSTALL_DIR:"* ]]; then
    echo -e "${GREEN}✓${NC} Installation verified successfully!"
    echo ""
fi
