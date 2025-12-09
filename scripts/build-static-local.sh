#!/usr/bin/env bash
# Build fully static sss binary locally (no libsodium dependency)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT"

# Detect platform
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    PLATFORM="linux"
elif [[ "$OSTYPE" == "darwin"* ]]; then
    PLATFORM="macos"
else
    echo "Unsupported platform: $OSTYPE"
    exit 1
fi

echo "🔧 Building static sss binary for $PLATFORM..."
echo ""

if [[ "$PLATFORM" == "macos" ]]; then
    echo "📦 Step 1: Building static libsodium from source..."

    # Create build directory
    mkdir -p target/libsodium-build
    cd target/libsodium-build

    # Download and extract libsodium if not already present
    if [[ ! -f "libsodium.tar.gz" ]]; then
        echo "Downloading libsodium 1.0.20..."
        curl -L https://download.libsodium.org/libsodium/releases/libsodium-1.0.20.tar.gz -o libsodium.tar.gz
    fi

    if [[ ! -d "libsodium-stable" ]]; then
        echo "Extracting libsodium..."
        tar xzf libsodium.tar.gz
    fi

    # Find the actual directory name (might be libsodium-stable or libsodium-1.0.20)
    LIBSODIUM_DIR=$(find . -maxdepth 1 -type d -name "libsodium-*" | head -n1)

    if [[ -z "$LIBSODIUM_DIR" ]]; then
        echo "❌ Error: Could not find extracted libsodium directory"
        ls -la
        exit 1
    fi

    echo "Found libsodium directory: $LIBSODIUM_DIR"
    cd "$LIBSODIUM_DIR"

    # Build static library
    echo "Configuring libsodium for static linking..."
    ./configure --prefix="$PROJECT_ROOT/target/libsodium-static" \
                --disable-shared \
                --enable-static

    echo "Building libsodium (this may take a minute)..."
    make -j$(sysctl -n hw.ncpu)
    make install

    cd "$PROJECT_ROOT"

    echo "✅ Static libsodium built at: target/libsodium-static"
    echo ""
    echo "🦀 Step 2: Building sss with static libsodium..."

    # Set environment for static linking
    export SODIUM_LIB_DIR="$PROJECT_ROOT/target/libsodium-static/lib"
    export SODIUM_SHARED=0

    # Override cargo linker settings to use system clang
    export CARGO_TARGET_AARCH64_APPLE_DARWIN_LINKER=clang
    export CARGO_TARGET_AARCH64_APPLE_DARWIN_AR=ar

    # Build
    cargo build --release

    echo ""
    echo "🔪 Step 3: Stripping debug symbols..."
    strip target/release/sss
    echo "✅ Binary stripped"

    echo ""
    echo "🔍 Step 4: Verifying static linking..."
    echo "Dynamic dependencies:"
    otool -L target/release/sss
    echo ""

    if otool -L target/release/sss | grep -i libsodium; then
        echo "❌ ERROR: Binary still has dynamic libsodium dependency!"
        exit 1
    else
        echo "✅ SUCCESS: Binary is fully statically linked with libsodium"
    fi

elif [[ "$PLATFORM" == "linux" ]]; then
    echo "📦 Step 1: Checking for musl toolchain..."

    # Check if musl target is installed
    if ! rustup target list --installed | grep -q x86_64-unknown-linux-musl; then
        echo "Installing musl target..."
        rustup target add x86_64-unknown-linux-musl
    fi

    # Check for musl-gcc
    if ! command -v musl-gcc &> /dev/null; then
        echo "❌ musl-gcc not found. Install it with:"
        echo "   Ubuntu/Debian: sudo apt-get install musl-tools"
        echo "   Fedora/RHEL:   sudo dnf install musl-gcc musl-devel"
        echo "   Arch:          sudo pacman -S musl"
        exit 1
    fi

    echo "✅ musl toolchain ready"
    echo ""
    echo "🦀 Step 2: Building static binary with musl..."

    # Build static binary
    export SODIUM_SHARED=0
    RUSTFLAGS='-C target-feature=+crt-static' \
        cargo build --release --target x86_64-unknown-linux-musl

    echo ""
    echo "🔪 Step 3: Stripping debug symbols..."
    strip target/x86_64-unknown-linux-musl/release/sss
    echo "✅ Binary stripped"

    echo ""
    echo "🔍 Step 4: Verifying static linking..."
    echo "Dynamic dependencies:"
    ldd target/x86_64-unknown-linux-musl/release/sss || echo "(statically linked - no dependencies)"

    # Check file type
    file target/x86_64-unknown-linux-musl/release/sss

    if ldd target/x86_64-unknown-linux-musl/release/sss 2>&1 | grep -q "not a dynamic executable"; then
        echo "✅ SUCCESS: Binary is fully statically linked"
    else
        echo "⚠️  WARNING: Binary may have dynamic dependencies"
    fi

    # Copy to standard location
    cp target/x86_64-unknown-linux-musl/release/sss target/release/sss-static
    echo ""
    echo "📦 Static binary copied to: target/release/sss-static"
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "✨ Build complete!"
echo ""
if [[ "$PLATFORM" == "macos" ]]; then
    echo "Binary location: target/release/sss"
    echo "Size: $(du -h target/release/sss | cut -f1)"
else
    echo "Binary location: target/release/sss-static"
    echo "Size: $(du -h target/release/sss-static | cut -f1)"
fi
echo ""
echo "This binary has NO external dependencies and can be"
echo "distributed as a single file."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
