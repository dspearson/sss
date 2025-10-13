#!/bin/bash
# Build SSS for macOS (run this on a Mac)

set -e

echo "Building SSS for macOS..."

# Check if we're on macOS
if [[ "$OSTYPE" != "darwin"* ]]; then
    echo "Error: This script must be run on macOS"
    echo "Current OS: $OSTYPE"
    exit 1
fi

# Check if rust is installed
if ! command -v cargo &> /dev/null; then
    echo "Error: Rust not found"
    echo "Install with: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
    exit 1
fi

# Check if libsodium is available
if pkg-config --exists libsodium 2>/dev/null; then
    echo "Using system libsodium (dynamic linking via Homebrew)"
else
    echo "Warning: libsodium not found via pkg-config"
    echo "Building libsodium from source (slower first build)..."
    echo "To speed up future builds: brew install libsodium"
    echo ""
    # Build libsodium from source (bundled with libsodium-sys)
    export SODIUM_BUILD_STATIC=1
    # Note: SODIUM_STATIC is deprecated, don't use it
    # SODIUM_BUILD_STATIC=1 automatically uses static linking
fi

# Detect architecture
ARCH=$(uname -m)
if [ "$ARCH" = "arm64" ]; then
    TARGET="aarch64-apple-darwin"
    echo "Building for Apple Silicon (ARM64)..."
elif [ "$ARCH" = "x86_64" ]; then
    TARGET="x86_64-apple-darwin"
    echo "Building for Intel (x86_64)..."
else
    echo "Unknown architecture: $ARCH"
    exit 1
fi

# Build release binary
echo "Building release binary..."
cargo build --release --target $TARGET

# Create output directory
mkdir -p dist/macos

# Copy binaries
echo "Copying binaries to dist/macos/..."
cp target/$TARGET/release/sss dist/macos/
cp target/$TARGET/release/sss-agent dist/macos/ 2>/dev/null || echo "  Warning: sss-agent not built"
cp target/$TARGET/release/sss-askpass-tty dist/macos/ 2>/dev/null || echo "  Warning: sss-askpass-tty not built"
cp target/$TARGET/release/sss-askpass-gui dist/macos/ 2>/dev/null || echo "  Warning: sss-askpass-gui not built"

echo ""
echo "Build complete! Binaries are in: dist/macos/"
echo ""
ls -lh dist/macos/

echo ""
echo "Verify dependencies with:"
echo "  otool -L dist/macos/sss"
