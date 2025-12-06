# Building Static Binaries

This guide explains how to build fully static `sss` binaries with no external dependencies.

## macOS - Static Build

### Automated (Recommended)

```bash
./scripts/build-static-local.sh
```

### Manual Process

```bash
# 1. Download and build static libsodium
mkdir -p target/libsodium-build
cd target/libsodium-build

curl -L https://download.libsodium.org/libsodium/releases/libsodium-1.0.20.tar.gz -o libsodium.tar.gz
tar xzf libsodium.tar.gz
cd libsodium-stable

# Build as static library (no .dylib, only .a)
./configure --prefix=$HOME/libsodium-static \
            --disable-shared \
            --enable-static

make -j$(sysctl -n hw.ncpu)
make install

# 2. Build sss with static libsodium
cd /path/to/sss

export SODIUM_LIB_DIR="$HOME/libsodium-static/lib"
export SODIUM_STATIC=1

cargo build --release

# 3. Verify no dynamic libsodium dependency
otool -L target/release/sss | grep -i libsodium
# Should return nothing (no match)

# Check what IS linked
otool -L target/release/sss
# Should only show system libraries:
#   /usr/lib/libSystem.B.dylib
#   /usr/lib/libiconv.2.dylib
#   /usr/lib/libresolv.9.dylib
```

### Result

- **Binary**: `target/release/sss`
- **Size**: ~2-3MB larger than dynamic (includes libsodium code)
- **Dependencies**: None (except system libs)
- **Distribution**: Single file, works on any macOS system

## Linux - Static Build (musl)

### Automated (Recommended)

```bash
./scripts/build-static-local.sh
```

### Manual Process

```bash
# 1. Install musl toolchain
sudo apt-get install musl-tools  # Ubuntu/Debian
# or
sudo dnf install musl-gcc musl-devel  # Fedora/RHEL

# 2. Add musl target to Rust
rustup target add x86_64-unknown-linux-musl

# 3. Build static binary
export SODIUM_STATIC=1
RUSTFLAGS='-C target-feature=+crt-static' \
    cargo build --release --target x86_64-unknown-linux-musl

# 4. Verify fully static
ldd target/x86_64-unknown-linux-musl/release/sss
# Should say: "not a dynamic executable"

file target/x86_64-unknown-linux-musl/release/sss
# Should say: "statically linked"
```

### Result

- **Binary**: `target/x86_64-unknown-linux-musl/release/sss`
- **Dependencies**: ZERO (100% static)
- **Distribution**: Single file, works on any Linux system

## Windows - Static Build

Windows binaries built with `libsodium-sys` are automatically static by default.

```bash
cargo build --release --target x86_64-pc-windows-msvc
```

The `libsodium-sys` crate handles downloading and statically linking libsodium on Windows.

## Cross-Compilation

### Can I cross-compile macOS binaries from Linux?

**No.** Building macOS binaries requires:
- A real Mac or macOS VM
- macOS SDK (legally only available on macOS)
- Apple's toolchain

### Can I cross-compile Linux binaries from macOS?

**Yes**, but it's complex. The script above only supports native builds.

For cross-compilation, use:
```bash
# On macOS, build for Linux
cargo install cross
cross build --release --target x86_64-unknown-linux-musl
```

## Environment Variables

These control static linking:

| Variable | Effect |
|----------|--------|
| `SODIUM_STATIC=1` | Forces libsodium-sys to link statically |
| `SODIUM_LIB_DIR=/path` | Path to libsodium library directory |
| `RUSTFLAGS='-C target-feature=+crt-static'` | Forces static C runtime (musl) |

## Troubleshooting

### macOS: "Binary still has dynamic libsodium dependency"

```bash
# Check what's linked
otool -L target/release/sss

# If you see libsodium.dylib, the static build failed
# Clean and rebuild:
cargo clean
rm -rf target/libsodium-build
./scripts/build-static-local.sh
```

### Linux: "musl-gcc not found"

```bash
# Install musl toolchain
sudo apt-get install musl-tools musl-dev
```

### macOS: "configure: error: C compiler cannot create executables"

```bash
# Install Xcode Command Line Tools
xcode-select --install
```

## Size Comparison

| Build Type | Linux | macOS |
|------------|-------|-------|
| Dynamic (system libsodium) | ~1.5MB | ~1.8MB |
| Static (bundled libsodium) | ~1.8MB | ~2.1MB |
| Difference | +300KB | +300KB |

The small size increase is worth it for zero-dependency distribution.

## CI/CD Integration

The GitHub Actions workflows already build static binaries:

- **Linux**: Uses musl target
- **macOS**: Builds libsodium from source
- **Windows**: Handled automatically by libsodium-sys

See `.github/workflows/release.yml` for the full process.
