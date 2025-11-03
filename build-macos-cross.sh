#!/usr/bin/env bash
# Build sss for macOS Apple Silicon (ARM64) from Linux using osxcross
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OSXCROSS_DIR="$SCRIPT_DIR/cross/osxcross"

echo "==> Cross-compiling sss for macOS Apple Silicon (aarch64-apple-darwin)"

# Check if osxcross is set up
if [ ! -d "$OSXCROSS_DIR/target" ]; then
    echo "Error: osxcross not found at $OSXCROSS_DIR/target"
    echo "Please run the setup in cross/osxcross first"
    exit 1
fi

# Add osxcross to PATH
export PATH="$OSXCROSS_DIR/target/bin:$PATH"

# Verify osxcross toolchain
if ! command -v aarch64-apple-darwin23.5-clang &> /dev/null; then
    echo "Error: osxcross toolchain not found in PATH"
    exit 1
fi

echo "==> osxcross toolchain found"
aarch64-apple-darwin23.5-clang --version | grep "Target:"

# Set up environment for cross-compilation
export CC_aarch64_apple_darwin=aarch64-apple-darwin23.5-clang
export CXX_aarch64_apple_darwin=aarch64-apple-darwin23.5-clang++
export AR_aarch64_apple_darwin=aarch64-apple-darwin23.5-ar

echo "==> Setting up environment for libsodium shared library..."
export SODIUM_LIB_DIR="$SCRIPT_DIR/cross/libsodium-install/lib"
export SODIUM_SHARED=1

# Set up pkg-config for both libsodium and FUSE
export PKG_CONFIG_PATH="$SCRIPT_DIR/cross/libsodium-install/lib/pkgconfig:$SCRIPT_DIR/cross/pkgconfig"
export PKG_CONFIG_ALLOW_CROSS=1
export PKG_CONFIG_ALLOW_CROSS_aarch64_apple_darwin=1
export PKG_CONFIG_SYSROOT_DIR="$SCRIPT_DIR/cross/osxcross/target/SDK/MacOSX14.5.sdk"

# Add SDK library path for macFUSE libfuse3
export RUSTFLAGS="-L $SCRIPT_DIR/cross/osxcross/target/SDK/MacOSX14.5.sdk/usr/local/lib"

echo "==> Building sss for aarch64-apple-darwin with macFUSE support..."
echo "Using pre-built libsodium from cross/libsodium-install/"
echo "Using libfuse3 from macFUSE in SDK"

cargo build --target aarch64-apple-darwin --release --features macfuse

if [ $? -eq 0 ]; then
    echo ""
    echo "==> Build successful!"
    echo "Binary location: target/aarch64-apple-darwin/release/sss"
    echo ""

    # Fix libsodium path to use system library
    echo "==> Updating libsodium path to use system library..."
    "$OSXCROSS_DIR/target/bin/aarch64-apple-darwin23.5-install_name_tool" \
        -change "$SCRIPT_DIR/cross/libsodium-install/lib/libsodium.26.dylib" \
        "/opt/homebrew/opt/libsodium/libsodium.26.dylib" \
        target/aarch64-apple-darwin/release/sss 2>/dev/null || true

    echo ""
    echo "Verify the binary:"
    file target/aarch64-apple-darwin/release/sss
    echo ""
    echo "Library dependencies:"
    "$OSXCROSS_DIR/target/bin/aarch64-apple-darwin23.5-otool" -L target/aarch64-apple-darwin/release/sss | grep libsodium
    echo ""
    echo "Note: On macOS, install required dependencies:"
    echo "  brew install libsodium"
    echo "  brew install --cask macfuse"
else
    echo ""
    echo "==> Build failed"
    echo "See cross/README.md for troubleshooting information"
    exit 1
fi
