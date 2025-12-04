# fuse-t vs macFUSE: What You Need to Know

## The Fundamental Difference

**fuse-t does NOT use libfuse3 at all.**

### fuse-t (Recommended)
- **Pure userspace** FUSE implementation
- **No kernel extension** required
- **No libfuse3** - has its own FUSE protocol implementation
- Uses macOS's native NFS client (`mount_nfs`) as transport
- Installed via: `brew install fuse-t`

### macFUSE (Traditional)
- Requires **kernel extension** (kext)
- Uses **libfuse** library (fuse2 or fuse3)
- More traditional FUSE approach (like Linux)
- Requires system reboot after installation
- Installed via: `brew install macfuse`

## Why fuse-t is Better for Modern macOS

1. **No kernel extension** - Works on systems with strict kernel security
2. **No reboot required** - Install and go
3. **Safer** - Runs entirely in userspace
4. **Modern** - Designed for current macOS security model

## How This Affects Your Build

### ❌ WRONG Approach (Your build script is doing this)
```bash
# This is looking for libfuse3 which fuse-t doesn't provide!
Using libfuse3 from macFUSE in SDK
```

Your `build-macos-cross.sh` is trying to link against libfuse3, but **fuse-t doesn't provide or need libfuse3**.

### ✅ CORRECT Approach

The code uses the **`fuser` crate** which handles all platform differences:

```rust
// In Cargo.toml
[dependencies]
fuser = "0.15"  # Abstracts over FUSE implementations
```

The `fuser` crate:
- On Linux: Uses libfuse3 via FFI
- On macOS with fuse-t: Uses native macOS APIs
- On macOS with macFUSE: Uses libfuse via FFI
- You don't need to link libfuse3 manually!

## Fixing Your Build

### Option 1: Let Cargo Handle It (Recommended)

Just build normally - `fuser` will detect and use what's available:

```bash
# Install fuse-t
brew install fuse-t

# Build - fuser handles everything
cargo build --release --target aarch64-apple-darwin
```

### Option 2: Update Your Cross-Compile Script

If you must cross-compile, **don't try to link libfuse3**:

```bash
#!/bin/bash
# build-macos-cross.sh - CORRECTED VERSION

export MACOSX_DEPLOYMENT_TARGET=11.0
export CC=arm64-apple-darwin23.5-clang
export CXX=arm64-apple-darwin23.5-clang++
export AR=arm64-apple-darwin23.5-ar

# Only need libsodium, NOT libfuse3
export SODIUM_LIB_DIR=/path/to/libsodium

# fuser crate will handle FUSE integration
cargo build --release --target aarch64-apple-darwin
```

## What the fuser Crate Does

The `fuser` crate provides a unified API that works across platforms:

```rust
// Your code (platform-agnostic)
impl Filesystem for SssFS {
    fn init(&mut self, req: &Request, config: &mut KernelConfig) { ... }
    fn getattr(&mut self, req: &Request, ino: u64, reply: ReplyAttr) { ... }
    // etc.
}

// fuser handles the platform differences internally:
// - On Linux: calls libfuse3 functions
// - On macOS with fuse-t: uses native macOS NFS-based transport
// - On macOS with macFUSE: calls libfuse functions
```

## Which FUSE Implementation Will Be Used?

When you run your code on macOS, the `fuser` crate will automatically detect and use:

1. **fuse-t** if installed (preferred)
2. **macFUSE** if fuse-t is not available
3. Error if neither is installed

You can check what's available:

```bash
# Check for fuse-t
brew list fuse-t

# Check for macFUSE
brew list macfuse

# See what /dev/fuse* devices exist
ls -l /dev/fuse* 2>/dev/null
```

## Testing on macOS

### With fuse-t (Recommended)
```bash
# Install
brew install fuse-t

# Build (no special flags needed)
cargo build --release

# Run
./target/release/sss mount --foreground /src /mnt
```

### With macFUSE (If you prefer)
```bash
# Install
brew install macfuse

# Build (same)
cargo build --release

# Run (same)
./target/release/sss mount --foreground /src /mnt
```

## Common Build Errors

### Error: "ld: library not found for -lfuse3"
**Cause:** Build script trying to link libfuse3 manually
**Fix:** Remove manual linking, let `fuser` crate handle it

### Error: "Could not find libfuse3"
**Cause:** Build script looking for libfuse3
**Fix:** Don't look for it! fuse-t doesn't use libfuse3

### Error: "/dev/fuse: No such file or directory"
**Cause:** No FUSE implementation installed
**Fix:** `brew install fuse-t`

## Updated Build Instructions

### For Native macOS Build

```bash
# 1. Install fuse-t
brew install fuse-t

# 2. Build (Cargo handles everything)
cargo build --release

# That's it! No libfuse3 needed.
```

### For Cross-Compilation from Linux

```bash
# 1. Setup osxcross (you have this)
# 2. Build libsodium for macOS (you have this)
# 3. Build without trying to link libfuse3

export CC=arm64-apple-darwin23.5-clang
export SODIUM_LIB_DIR=/path/to/your/cross/libsodium-install

# Don't set FUSE library paths - fuser will handle it at runtime
cargo build --release --target aarch64-apple-darwin
```

The resulting binary will:
- **Not contain** libfuse3 code (it's not needed)
- **Dynamically use** whatever FUSE implementation is on the macOS system (fuse-t or macFUSE)
- **Work with both** fuse-t and macFUSE

## Checking Your Binary

```bash
# See what libraries it links
otool -L target/aarch64-apple-darwin/release/sss

# Should NOT see libfuse3
# Should only see system libs and libsodium
```

## Runtime: How It Actually Works

When you run `sss mount` on macOS:

1. **fuser crate detects environment**
   ```
   Found: /usr/local/bin/mount_nfs (fuse-t present)
   Using: fuse-t transport
   ```

2. **Communication happens via NFS**
   ```
   fuse-t creates NFS server
   macOS mounts it via mount_nfs
   Your code handles FUSE operations via fuser API
   ```

3. **No libfuse3 involved**
   ```
   Everything is pure Rust (fuser) + macOS APIs
   ```

## Summary

| Component | fuse-t | macFUSE | Your Code |
|-----------|--------|---------|-----------|
| Kernel Extension | ❌ No | ✅ Yes | N/A |
| libfuse3 | ❌ No | ✅ Yes | ❌ No |
| fuser crate | ✅ Yes | ✅ Yes | ✅ Yes |
| Transport | NFS | kernel | Doesn't care |
| Link at build | ❌ No | ❌ No | ❌ No |
| Runtime detection | ✅ Auto | ✅ Auto | ✅ Auto |

## Key Takeaway

**Stop trying to link libfuse3 in your build script!**

The `fuser` crate is a pure Rust library that:
- Abstracts over platform differences
- Detects the FUSE implementation at runtime
- Doesn't require you to link against libfuse3

Your build script should only:
1. ✅ Link libsodium (for encryption)
2. ❌ NOT try to link libfuse3
3. ✅ Let cargo/fuser handle FUSE

Then on the macOS system where you run it:
- Install `fuse-t` via brew
- Run your binary
- `fuser` automatically uses fuse-t's transport

No libfuse3 needed anywhere in the process!
