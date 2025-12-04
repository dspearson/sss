#!/usr/bin/env bash
# Build sss for macOS Apple Silicon (ARM64) from Linux using osxcross
# For use with fuse-t (no libfuse3 needed!)
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OSXCROSS_DIR="$SCRIPT_DIR/cross/osxcross"

echo "==> Cross-compiling sss for macOS Apple Silicon (aarch64-apple-darwin)"
echo "==> Target FUSE implementation: fuse-t (no libfuse3 linking required)"

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

echo "==> Setting up environment for libsodium..."
export SODIUM_LIB_DIR="$SCRIPT_DIR/cross/libsodium-install/lib"
export SODIUM_SHARED=1

# Set up pkg-config for libsodium
export PKG_CONFIG_PATH="$SCRIPT_DIR/cross/libsodium-install/lib/pkgconfig"
export PKG_CONFIG_ALLOW_CROSS=1
export PKG_CONFIG_ALLOW_CROSS_aarch64_apple_darwin=1

# NOTE: We do NOT set up FUSE library paths because:
# 1. fuse-t does NOT use libfuse3
# 2. The fuser crate handles FUSE integration at runtime
# 3. The binary will work with both fuse-t and macFUSE on the target system

# Basic RUSTFLAGS without FUSE library paths
export RUSTFLAGS="-C target-feature=+crt-static"

echo "==> Building sss for aarch64-apple-darwin..."
echo "    libsodium: cross/libsodium-install/"
echo "    FUSE: Runtime detection via fuser crate (fuse-t or macFUSE)"
echo ""
echo "NOTE: This binary will work with fuse-t (recommended) or macFUSE"
echo "      Install on target macOS: brew install fuse-t"
echo ""

cargo build --release --target aarch64-apple-darwin --features macfuse


"$OSXCROSS_DIR/target/bin/aarch64-apple-darwin23.5-install_name_tool" \
  -change "$SCRIPT_DIR/cross/libsodium-install/lib/libsodium.26.dylib" \
  "/opt/homebrew/opt/libsodium/lib/libsodium.26.dylib" \
  target/aarch64-apple-darwin/release/sss 2>/dev/null || true

echo ""
echo "==> Build successful!"
echo "==> Binary: target/aarch64-apple-darwin/release/sss"
echo ""
echo "To use on macOS:"
echo "  1. Install fuse-t: brew install fuse-t"
echo "  2. Copy binary to macOS system"
echo "  3. Run: ./sss mount --foreground /source /mount"
echo ""
echo "The binary will automatically detect and use fuse-t (or macFUSE if present)"
