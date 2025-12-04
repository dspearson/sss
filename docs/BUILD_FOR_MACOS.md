# Building sss for macOS

## Quick Answer

**Use the new build script:**
```bash
./build-macos-cross-fuse-t.sh
```

This builds for fuse-t (no libfuse3 needed!).

## Understanding the Build

### What You DON'T Need

❌ libfuse3 libraries
❌ macFUSE headers at build time
❌ FUSE kernel extensions

### What You DO Need

✅ libsodium (for encryption)
✅ osxcross toolchain
✅ Rust toolchain with macOS target

The `fuser` crate in `Cargo.toml` handles all FUSE integration and works with both fuse-t and macFUSE at **runtime**, not build time.

## Two Build Scripts

### build-macos-cross-fuse-t.sh (NEW - Recommended)
```bash
# For fuse-t (modern, no kernel extension)
./build-macos-cross-fuse-t.sh
```

**What it does:**
- ✅ Links only libsodium
- ✅ Lets fuser crate handle FUSE
- ✅ Binary works with fuse-t or macFUSE
- ✅ No unnecessary library linking

### build-macos-cross.sh (OLD - Problematic)
```bash
# Tries to link libfuse3 (not needed!)
./build-macos-cross.sh
```

**Problems:**
- ❌ Tries to link libfuse3 (fuse-t doesn't provide it)
- ❌ Adds unnecessary library paths
- ❌ May fail if libfuse3 not in SDK

## Native macOS Build

If building directly on macOS (not cross-compiling):

```bash
# 1. Install fuse-t
brew install fuse-t

# 2. Install libsodium
brew install libsodium

# 3. Build normally
cargo build --release

# That's it! No special flags needed.
```

## Cross-Compilation from Linux

### Prerequisites

1. **osxcross toolchain** (you have this)
   ```bash
   ls cross/osxcross/target/bin/
   # Should see: aarch64-apple-darwin23.5-clang, etc.
   ```

2. **libsodium for macOS** (you have this)
   ```bash
   ls cross/libsodium-install/lib/
   # Should see: libsodium.dylib, pkgconfig/, etc.
   ```

3. **Rust macOS target**
   ```bash
   rustup target add aarch64-apple-darwin
   ```

### Build Process

```bash
# Use the new fuse-t-compatible script
./build-macos-cross-fuse-t.sh
```

This will:
1. Set up osxcross environment
2. Configure libsodium paths
3. Build with cargo (fuser handles FUSE)
4. Create binary at `target/aarch64-apple-darwin/release/sss`

### What Gets Linked

Check what libraries are in the binary:
```bash
# After build
arm64-apple-darwin23.5-otool -L target/aarch64-apple-darwin/release/sss
```

You should see:
```
libsodium.23.dylib               ✅ (encryption)
/usr/lib/libSystem.B.dylib       ✅ (system)
/usr/lib/libresolv.9.dylib       ✅ (DNS)
```

You should NOT see:
```
libfuse3.dylib                   ❌ (not needed!)
```

## How fuser Works

The `fuser` crate is pure Rust and abstracts FUSE operations:

```toml
# Cargo.toml
[dependencies]
fuser = "0.15"  # Pure Rust, no native libraries
```

At **runtime** on macOS:
1. fuser detects available FUSE implementation
2. If fuse-t installed → uses NFS-based transport
3. If macFUSE installed → uses kernel extension
4. No libfuse3 linking needed at build time!

## Deploying to macOS

### 1. Copy binary to macOS
```bash
scp target/aarch64-apple-darwin/release/sss user@mac:~/
```

### 2. Install fuse-t on macOS
```bash
# On the macOS system
brew install fuse-t
```

### 3. Test
```bash
# On the macOS system
./sss mount --foreground /source /mount
```

You should see debug output showing fuse-t being used.

## Troubleshooting

### Error: "library not found for -lfuse3"
**Cause:** Build script trying to link libfuse3
**Fix:** Use `build-macos-cross-fuse-t.sh` instead

### Error: "Could not find libfuse3"
**Cause:** Build script looking for libfuse3
**Fix:** Don't look for it! Use new build script

### Runtime Error: "/dev/fuse: No such file"
**Cause:** No FUSE implementation on macOS
**Fix:** On macOS: `brew install fuse-t`

### Build succeeds but hangs when mounting
**Cause:** Different issue (FUSE protocol issue)
**Fix:** See `docs/FUSE_T_DEBUGGING.md` for detailed debugging

## Comparison

| Aspect | Old Script | New Script |
|--------|-----------|------------|
| libfuse3 linking | ❌ Yes (wrong) | ✅ No (correct) |
| Works with fuse-t | ❌ May fail | ✅ Yes |
| Works with macFUSE | ✅ Yes | ✅ Yes |
| Binary size | Larger | Smaller |
| Build complexity | High | Low |
| Runtime detection | ✅ Yes | ✅ Yes |

## Migration

If you've been using the old build script:

```bash
# 1. Use new script
./build-macos-cross-fuse-t.sh

# 2. Compare binaries
ls -lh target/aarch64-apple-darwin/release/sss

# 3. Test on macOS with fuse-t
# (should work the same or better)
```

## Advanced: Manual Build

If you want to build manually:

```bash
# Set up environment
export PATH="cross/osxcross/target/bin:$PATH"
export CC_aarch64_apple_darwin=aarch64-apple-darwin23.5-clang
export SODIUM_LIB_DIR="$(pwd)/cross/libsodium-install/lib"
export SODIUM_SHARED=1

# Build (no FUSE library paths needed!)
cargo build --release --target aarch64-apple-darwin
```

That's it! The `fuser` crate handles everything else.

## Summary

**Key Points:**
1. ✅ Use `build-macos-cross-fuse-t.sh`
2. ✅ Don't try to link libfuse3
3. ✅ fuser crate handles FUSE at runtime
4. ✅ Binary works with both fuse-t and macFUSE
5. ✅ Install fuse-t on target macOS system

The old approach of trying to link libfuse3 is:
- Unnecessary (fuser is pure Rust)
- Wrong for fuse-t (doesn't use libfuse3)
- Overcomplicated (extra library paths)

The new approach is simpler and correct! 🎉
