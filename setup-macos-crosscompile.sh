#!/usr/bin/env bash
# Setup cross-compilation environment for macOS from Linux
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CROSS_DIR="$SCRIPT_DIR/cross"
OSXCROSS_DIR="$CROSS_DIR/osxcross"

echo "==> Setting up macOS cross-compilation environment"
echo ""
# Create cross directory
mkdir -p "$CROSS_DIR"
cd "$CROSS_DIR"

# 1. Setup osxcross
echo ""
echo "==> Setting up osxcross..."
if [ ! -d "osxcross" ]; then
    git clone https://github.com/tpoechtrager/osxcross
else
    echo "osxcross already cloned"
fi

cd osxcross
mkdir -p tarballs

# Check for SDK
echo ""
echo "==> Checking for macOS SDK..."
if ! ls tarballs/MacOSX*.tar.* 1> /dev/null 2>&1; then
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  macOS SDK Required"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    echo "You need to download a macOS SDK tarball."
    echo ""
    echo "Option 1: Download from GitHub (easiest)"
    echo "  wget -P tarballs https://github.com/joseluisq/macosx-sdks/releases/download/14.5/MacOSX14.5.sdk.tar.xz"
    echo ""
    echo "Option 2: Create from Xcode on Mac"
    echo "  On a Mac, run:"
    echo "    cd \$(xcodebuild -version -sdk macosx Path)/.."
    echo "    tar -czf MacOSX14.5.sdk.tar.gz MacOSX14.5.sdk"
    echo "    # Transfer to: $OSXCROSS_DIR/tarballs/"
    echo ""
    echo "After downloading, re-run this script."
    echo ""
    exit 1
fi

# Build osxcross
echo "==> SDK found!"
ls -lh tarballs/MacOSX*.tar.*
echo ""
echo "==> Building osxcross (this may take a while)..."

if [ ! -d "target/bin" ]; then
    # Ensure we're in the osxcross directory
    cd "$OSXCROSS_DIR"
    UNATTENDED=1 ./build.sh
else
    echo "osxcross already built"
fi

echo "==> osxcross build complete!"
echo ""

# 2. Build libsodium for macOS
echo "==> Building libsodium for macOS..."
cd "$CROSS_DIR"

if [ ! -d "libsodium-install" ]; then
    # Download libsodium
    if [ ! -d "libsodium" ]; then
        echo "Downloading libsodium..."
        git clone https://github.com/jedisct1/libsodium.git --depth 1 --branch stable
    fi

    cd libsodium

    # Add osxcross to PATH
    export PATH="$OSXCROSS_DIR/target/bin:$PATH"

    # Configure for macOS cross-compilation
    ./autogen.sh
    ./configure \
        --host=aarch64-apple-darwin23.5 \
        --prefix="$CROSS_DIR/libsodium-install" \
        CC=aarch64-apple-darwin23.5-clang \
        CXX=aarch64-apple-darwin23.5-clang++ \
        AR=aarch64-apple-darwin23.5-ar \
        RANLIB=aarch64-apple-darwin23.5-ranlib

    # Build and install
    make -j$(nproc)
    make install

    echo "==> libsodium build complete!"
else
    echo "libsodium already built"
fi

# 3. Add Rust target
echo ""
echo "==> Adding Rust macOS target..."
rustup target add aarch64-apple-darwin

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Setup Complete!"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Cross-compilation environment is ready."
echo ""
echo "Next steps:"
echo "  1. Build for macOS: ./build-macos-cross.sh"
echo "  2. Binary will be in: target/aarch64-apple-darwin/release/sss"
echo ""
