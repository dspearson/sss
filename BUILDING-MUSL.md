# Building sss with musl for Static Binaries

This document explains how to build sss as a statically-linked binary using musl libc.

## Why musl?

musl provides fully static binaries that are portable across Linux distributions without requiring specific system libraries. This is ideal for:

- Distribution as a single standalone binary
- Running in minimal containers (Alpine, scratch, etc.)
- Deployment to systems with different glibc versions

## Prerequisites

### 1. Install Rust musl target

```bash
rustup target add x86_64-unknown-linux-musl
```

For other architectures:
```bash
rustup target add aarch64-unknown-linux-musl    # ARM64
rustup target add armv7-unknown-linux-musleabihf # ARMv7
```

### 2. Install musl cross-compilation tools

#### Debian/Ubuntu
```bash
sudo apt-get install musl-tools
```

#### Arch Linux
```bash
sudo pacman -S musl
```

#### Fedora/RHEL
```bash
sudo dnf install musl-gcc musl-libc-static
```

#### Alpine Linux
```bash
apk add musl-dev
```

#### Manual Installation
If your distribution doesn't provide musl tools, you can use [musl-cross-make](https://github.com/richfelker/musl-cross-make) to build cross-compilers.

## Building

Once prerequisites are installed:

### Debug build
```bash
cargo build --target x86_64-unknown-linux-musl
```

### Release build
```bash
cargo build --target x86_64-unknown-linux-musl --release
```

The binary will be in:
- Debug: `target/x86_64-unknown-linux-musl/debug/sss`
- Release: `target/x86_64-unknown-linux-musl/release/sss`

### Other architectures

```bash
# ARM64
cargo build --target aarch64-unknown-linux-musl --release

# ARMv7
cargo build --target armv7-unknown-linux-musleabihf --release
```

## Verifying Static Linking

Check that the binary is statically linked:

```bash
ldd target/x86_64-unknown-linux-musl/release/sss
```

You should see: `not a dynamic executable`

Check the binary size and dependencies:
```bash
file target/x86_64-unknown-linux-musl/release/sss
size target/x86_64-unknown-linux-musl/release/sss
```

## Configuration

The project is already configured for musl builds via:

- `.cargo/config.toml`: Sets up linkers and flags for static linking
- `Cargo.toml`: Dependencies configured to work with musl

The key configuration in `.cargo/config.toml`:

```toml
[target.x86_64-unknown-linux-musl]
linker = "x86_64-linux-musl-gcc"
rustflags = ["-C", "target-feature=+crt-static"]
```

## Troubleshooting

### "C compiler cannot create executables"

This means musl-gcc is not installed or not in PATH. Install musl-tools as described above.

### "failed to find tool x86_64-linux-musl-gcc"

The musl cross-compiler for your target architecture is missing. Ensure you've installed the correct musl-tools package.

### Large binary size

Release builds with musl are typically 2-3MB. You can reduce this with:

```bash
cargo build --target x86_64-unknown-linux-musl --release
strip target/x86_64-unknown-linux-musl/release/sss
```

Or enable LTO in Cargo.toml:
```toml
[profile.release]
lto = true
codegen-units = 1
```

## Using Docker (alternative approach)

If you can't install musl tools locally, use Docker with a musl builder:

```bash
docker run --rm -v "$PWD":/volume -w /volume \
  clux/muslrust:stable \
  cargo build --release --target x86_64-unknown-linux-musl
```

## Dependencies

The project uses libsodium for cryptography. libsodium-sys will automatically:
1. Build libsodium from source (vendored build)
2. Link it statically when building for musl targets
3. Use the configured musl cross-compiler

No additional libsodium installation is needed.
