#!/bin/bash
# Build static musl binaries using Docker (no local musl-tools needed)

set -e

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

TARGET="${1:-x86_64-unknown-linux-musl}"
BUILD_TYPE="${2:-release}"

echo -e "${GREEN}Building sss for ${TARGET} using Docker...${NC}"

# Check if docker is available
if ! command -v docker &> /dev/null; then
    echo "Error: docker not found. Please install Docker first."
    exit 1
fi

# Build using muslrust container
if [ "${BUILD_TYPE}" = "release" ]; then
    docker run --rm \
        -v "$PWD":/volume \
        -w /volume \
        -u "$(id -u):$(id -g)" \
        clux/muslrust:stable \
        cargo build --release --target "${TARGET}"

    BINARY_PATH="target/${TARGET}/release/sss"
else
    docker run --rm \
        -v "$PWD":/volume \
        -w /volume \
        -u "$(id -u):$(id -g)" \
        clux/muslrust:stable \
        cargo build --target "${TARGET}"

    BINARY_PATH="target/${TARGET}/debug/sss"
fi

echo ""
echo -e "${GREEN}Build successful!${NC}"
echo "Binary: ${BINARY_PATH}"
echo ""

# Verify
if [ -f "${BINARY_PATH}" ]; then
    if ldd "${BINARY_PATH}" 2>&1 | grep -q "not a dynamic executable"; then
        echo -e "${GREEN}✓ Binary is statically linked${NC}"
    else
        echo -e "${YELLOW}⚠ Warning: Binary may not be fully static${NC}"
        ldd "${BINARY_PATH}" || true
    fi

    echo ""
    echo "Binary size:"
    ls -lh "${BINARY_PATH}"

    echo ""
    echo -e "${GREEN}Done! Test with:${NC}"
    echo "  ${BINARY_PATH} --version"
else
    echo "Error: Binary not found at ${BINARY_PATH}"
    exit 1
fi
