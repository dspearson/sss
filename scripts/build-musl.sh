#!/bin/bash
# Build script for static musl binaries

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Default target
TARGET="${1:-x86_64-unknown-linux-musl}"
BUILD_TYPE="${2:-release}"

echo -e "${GREEN}Building sss for ${TARGET} (${BUILD_TYPE})...${NC}"

# Check if target is installed
if ! rustup target list --installed | grep -q "${TARGET}"; then
    echo -e "${YELLOW}Target ${TARGET} not installed. Installing...${NC}"
    rustup target add "${TARGET}"
fi

# Check for musl-gcc based on target
case "${TARGET}" in
    x86_64-unknown-linux-musl)
        MUSL_GCC="x86_64-linux-musl-gcc"
        ;;
    aarch64-unknown-linux-musl)
        MUSL_GCC="aarch64-linux-musl-gcc"
        ;;
    armv7-unknown-linux-musleabihf)
        MUSL_GCC="armv7l-linux-musleabihf-gcc"
        ;;
    *)
        echo -e "${RED}Unknown target: ${TARGET}${NC}"
        exit 1
        ;;
esac

# Check if musl-gcc is available
if ! command -v "${MUSL_GCC}" &> /dev/null; then
    echo -e "${RED}Error: ${MUSL_GCC} not found${NC}"
    echo ""
    echo "Please install musl development tools:"
    echo "  Debian/Ubuntu: sudo apt-get install musl-tools"
    echo "  Arch:          sudo pacman -S musl"
    echo "  Fedora:        sudo dnf install musl-gcc musl-libc-static"
    echo "  Alpine:        apk add musl-dev"
    echo ""
    echo "Or use Docker:"
    echo "  docker run --rm -v \"\$PWD\":/volume -w /volume clux/muslrust:stable \\"
    echo "    cargo build --release --target ${TARGET}"
    exit 1
fi

# Build
if [ "${BUILD_TYPE}" = "release" ]; then
    cargo build --target "${TARGET}" --release
    BINARY_PATH="target/${TARGET}/release/sss"
else
    cargo build --target "${TARGET}"
    BINARY_PATH="target/${TARGET}/debug/sss"
fi

# Verify
echo ""
echo -e "${GREEN}Build successful!${NC}"
echo "Binary: ${BINARY_PATH}"
echo ""

# Check if it's static
if ldd "${BINARY_PATH}" 2>&1 | grep -q "not a dynamic executable"; then
    echo -e "${GREEN}✓ Binary is statically linked${NC}"
else
    echo -e "${YELLOW}⚠ Warning: Binary may not be fully static${NC}"
    ldd "${BINARY_PATH}"
fi

# Show size
echo ""
echo "Binary size:"
ls -lh "${BINARY_PATH}"

# Optionally strip
echo ""
read -p "Strip debug symbols to reduce size? [y/N] " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    strip "${BINARY_PATH}"
    echo -e "${GREEN}Stripped binary:${NC}"
    ls -lh "${BINARY_PATH}"
fi

echo ""
echo -e "${GREEN}Done! You can test with:${NC}"
echo "  ${BINARY_PATH} --version"
