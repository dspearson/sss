#!/usr/bin/env bash
# Build sss with bundled libsodium that loads from executable directory

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT"

echo "Building sss with bundled libsodium..."

# Detect platform
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    PLATFORM="linux"
    LIB_EXT="so"
elif [[ "$OSTYPE" == "darwin"* ]]; then
    PLATFORM="macos"
    LIB_EXT="dylib"
else
    echo "Unsupported platform: $OSTYPE"
    exit 1
fi

# Build with RPATH
if [[ "$PLATFORM" == "linux" ]]; then
    echo "Building for Linux with \$ORIGIN RPATH..."
    RUSTFLAGS='-C link-arg=-Wl,-rpath,$ORIGIN' cargo build --release

    # Find libsodium
    LIBSODIUM=$(ldconfig -p | grep libsodium.so | awk '{print $NF}' | head -n1)
    if [[ -z "$LIBSODIUM" ]]; then
        echo "Error: libsodium not found in system"
        exit 1
    fi

    echo "Copying $LIBSODIUM to target/release/"
    cp "$LIBSODIUM" target/release/

    echo "Verifying RPATH..."
    readelf -d target/release/sss | grep RPATH || echo "Warning: RPATH not set"

elif [[ "$PLATFORM" == "macos" ]]; then
    echo "Building for macOS with @executable_path..."
    cargo build --release

    # Find current libsodium path
    CURRENT_PATH=$(otool -L target/release/sss | grep libsodium | awk '{print $1}')

    if [[ -z "$CURRENT_PATH" ]]; then
        echo "Warning: No dynamic libsodium dependency found (might be statically linked)"
        exit 0
    fi

    # Get libsodium filename
    LIBSODIUM_FILE=$(basename "$CURRENT_PATH")

    echo "Modifying binary to use @executable_path..."
    install_name_tool -change \
        "$CURRENT_PATH" \
        "@executable_path/$LIBSODIUM_FILE" \
        target/release/sss

    echo "Copying libsodium to target/release/"
    cp "$CURRENT_PATH" "target/release/$LIBSODIUM_FILE"

    echo "Verifying changes..."
    otool -L target/release/sss | grep libsodium
fi

echo ""
echo "✅ Build complete!"
echo ""
echo "Distribution files:"
echo "  - target/release/sss"
echo "  - target/release/libsodium.$LIB_EXT"
echo ""
echo "Both files must be distributed together in the same directory."
