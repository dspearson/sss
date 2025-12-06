#!/usr/bin/env bash
# Build sss for macOS Apple Silicon (ARM64) from Linux using osxcross
# Based on build-macos.sh - kept simple, no unnecessary features
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

echo "==> Setting up environment for libsodium..."
export SODIUM_LIB_DIR="$SCRIPT_DIR/cross/libsodium-install/lib"
export SODIUM_SHARED=1

# Set up pkg-config for libsodium
export PKG_CONFIG_PATH="$SCRIPT_DIR/cross/libsodium-install/lib/pkgconfig"
export PKG_CONFIG_ALLOW_CROSS=1
export PKG_CONFIG_ALLOW_CROSS_aarch64_apple_darwin=1

echo "==> Building sss for aarch64-apple-darwin..."
echo "    libsodium: $SODIUM_LIB_DIR"
echo "    FUSE: Using SDK macFUSE libs for build-time linking"
echo "          Runtime detection: fuse-t (preferred) or macFUSE"
echo ""

# Build with --features fuse (NOT macfuse!)
# The 'fuse' feature enables the fuser dependency
#
# At BUILD TIME: We link against macFUSE libraries from osxcross SDK
# At RUNTIME: fuser automatically detects and uses fuse-t (preferred) or macFUSE
#
# This works because:
# 1. fuser v0.14 requires libfuse3 symbols at link time on macOS
# 2. osxcross SDK includes macFUSE libraries with all required symbols
# 3. At runtime, fuser detects which FUSE implementation is available
# 4. fuse-t doesn't use libfuse3 - it's pure userspace NFS-based
# 5. The binary works with both implementations!

echo "==> Setting up FUSE library paths for cross-compilation..."
SDK_FUSE_LIB="$OSXCROSS_DIR/target/SDK/MacOSX14.5.sdk/usr/local/lib"
SDK_LIB="$OSXCROSS_DIR/target/SDK/MacOSX14.5.sdk/usr/lib"

# Add SDK library paths and tell linker to treat pthread as a weak reference
# (pthread is part of libSystem on macOS, not a separate library)
export RUSTFLAGS="-L $SDK_FUSE_LIB -C link-arg=-Wl,-weak-lpthread"

# Set up pkg-config to find both libsodium and fuse3
# This prevents pkg-config from adding wrong system library paths
export PKG_CONFIG_PATH="$SCRIPT_DIR/cross/libsodium-install/lib/pkgconfig" #:$SCRIPT_DIR/cross/fuse-pkgconfig"
export PKG_CONFIG_LIBDIR="$SCRIPT_DIR/cross/libsodium-install/lib/pkgconfig" #:$SCRIPT_DIR/cross/fuse-pkgconfig"

cargo build --release --target aarch64-apple-darwin

# Fix libsodium path to point to Homebrew location on target macOS
echo ""
echo "==> Fixing libsodium library path..."
"$OSXCROSS_DIR/target/bin/aarch64-apple-darwin23.5-install_name_tool" \
  -change "$SCRIPT_DIR/cross/libsodium-install/lib/libsodium.26.dylib" \
  "/opt/homebrew/opt/libsodium/lib/libsodium.26.dylib" \
  target/aarch64-apple-darwin/release/sss 2>/dev/null || true

# Also fix for other binaries if they exist
for bin in sss-agent sss-askpass-tty sss-askpass-gui; do
  if [ -f "target/aarch64-apple-darwin/release/$bin" ]; then
    "$OSXCROSS_DIR/target/bin/aarch64-apple-darwin23.5-install_name_tool" \
      -change "$SCRIPT_DIR/cross/libsodium-install/lib/libsodium.26.dylib" \
      "/opt/homebrew/opt/libsodium/lib/libsodium.26.dylib" \
      "target/aarch64-apple-darwin/release/$bin" 2>/dev/null || true
  fi
done

echo ""
echo "==> Build successful!"
echo "==> Binary: target/aarch64-apple-darwin/release/sss"
echo ""
echo "==> Verifying linked libraries:"
"$OSXCROSS_DIR/target/bin/aarch64-apple-darwin23.5-otool" -L target/aarch64-apple-darwin/release/sss | head -10
echo ""
echo "To use on macOS:"
echo "  1. Install dependencies: brew install fuse-t libsodium"
echo "  2. Copy binary to macOS system"
echo "  3. Run: ./sss mount --foreground /source /mount"
echo ""
echo "Note: Binary works with both fuse-t (recommended) and macFUSE"
echo "      fuser crate handles FUSE integration at runtime"
