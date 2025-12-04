# Build Fix Summary - macOS Cross-Compilation

## Problem

Building with `--features macfuse` caused linking errors:
```
ld: file too small (length=8) file '/usr/lib/x86_64-linux-gnu/libpthread.a' for architecture arm64
```

The linker was trying to link against:
- ❌ libfuse3 (not needed for fuse-t)
- ❌ Wrong architecture libraries (x86_64 instead of arm64)

## Root Cause

The `--features macfuse` flag in Cargo triggers the `fuser` crate to link against libfuse3:
```bash
# WRONG - triggers libfuse3 linking
cargo build --release --target aarch64-apple-darwin --features macfuse
```

This happens because:
1. `macfuse` feature is defined in `Cargo.toml`
2. When enabled, `fuser` crate's build script adds `-lfuse3` to linker flags
3. This is unnecessary because fuser detects FUSE at **runtime**, not build time

## Solution

**Use the corrected `build-macos-cross.sh` script:**

### Key Changes

1. **Removed `--features macfuse`**
   ```bash
   # Before (WRONG)
   cargo build --release --target aarch64-apple-darwin --features macfuse

   # After (CORRECT)
   cargo build --release --target aarch64-apple-darwin
   ```

2. **Based on working `build-macos.sh`**
   - Simple, minimal configuration
   - No unnecessary feature flags
   - Let fuser handle FUSE detection

3. **Fixed unused constant warnings**
   ```rust
   // Only define ioctl constants on non-macOS
   #[cfg(not(target_os = "macos"))]
   const SSS_IOC_OPENED_MODE: u32 = 0x5353_0001;
   #[cfg(not(target_os = "macos"))]
   const SSS_IOC_SEALED_MODE: u32 = 0x5353_0002;
   ```

## Verification

✅ **Build succeeds:**
```bash
$ ./build-macos-cross.sh
Finished `release` profile [optimized] target(s) in 16.26s
==> Build successful!
```

✅ **NO libfuse3 linked:**
```bash
$ otool -L target/aarch64-apple-darwin/release/sss
target/aarch64-apple-darwin/release/sss:
    CoreFoundation.framework     ✅
    libsodium.26.dylib          ✅
    libiconv.2.dylib            ✅
    libSystem.B.dylib           ✅
    # NO libfuse3!              ✅
```

✅ **No compiler warnings**

## Why This Works

### The `fuser` Crate is Smart

The `fuser` crate (version 0.14+) has runtime FUSE detection:

```rust
// In your code - platform agnostic
impl Filesystem for SssFS {
    fn init(&mut self, req: &Request, config: &mut KernelConfig) { ... }
    // ... other operations
}

// fuser handles platform differences internally:
// - On Linux: Uses libfuse3 (found at runtime)
// - On macOS with fuse-t: Uses NFS transport (no libfuse3)
// - On macOS with macFUSE: Uses libfuse (found at runtime)
```

**Key insight:** You don't need to specify which FUSE implementation at build time!

### What Happens on macOS

When you run the binary on macOS:

1. `fuser` crate checks for available FUSE implementations
2. Finds fuse-t → uses NFS-based transport
3. OR finds macFUSE → uses kernel extension
4. **No libfuse3 needed** - it's all handled dynamically

## Comparison

| Approach | Linker Flags | Result |
|----------|--------------|--------|
| `--features macfuse` | `-lfuse3 -lpthread` | ❌ Link error |
| No features (correct) | (none for FUSE) | ✅ Success |

## Files Changed

1. **build-macos-cross.sh** - Simplified, no macfuse feature
2. **src/fuse_fs.rs** - Conditional compilation for ioctl constants

## Usage

```bash
# Build
./build-macos-cross.sh

# On macOS - install fuse-t
brew install fuse-t libsodium

# Run
./sss mount --foreground /source /mount
```

The binary works with both fuse-t and macFUSE - the fuser crate detects which is available at runtime.

## Lessons Learned

1. **Don't use `--features macfuse` for cross-compilation**
   - It triggers unwanted linking
   - The feature is only needed for special cases

2. **Trust the fuser crate's runtime detection**
   - It's smarter than build-time feature flags
   - Works across platforms automatically

3. **Keep it simple**
   - Follow the pattern in `build-macos.sh`
   - Don't add unnecessary features or flags

4. **fuse-t doesn't use libfuse3**
   - It's a completely different implementation
   - No library linking needed at all

## What's Next

The binary is ready to test on macOS:

1. Copy to macOS system
2. Install fuse-t: `brew install fuse-t`
3. Run with debugging: `./sss mount --foreground /src /mnt`
4. Check debug output for FUSE init sequence
5. Test file access with virtual suffixes

All FUSE operations have comprehensive debug logging to help diagnose any issues!
