# macOS Quick Start with fuse-t

## Installation

1. Install fuse-t:
```bash
brew install fuse-t
```

2. Build sss:
```bash
cargo build --release
```

## Mounting

### Basic Mount
```bash
# Mount in foreground for testing
./target/release/sss mount --foreground /path/to/source /path/to/mount

# Mount in background (daemonize)
./target/release/sss mount /path/to/source /path/to/mount

# In-place mount (mount over source directory)
./target/release/sss mount --in-place /path/to/source
```

### Unmounting
```bash
# Unmount the filesystem
umount /path/to/mount

# Force unmount if stuck
sudo umount -f /path/to/mount

# Or kill the FUSE process
pkill -f "sss mount"
```

## Using Virtual Suffixes (No ioctl needed!)

### Rendered Mode (Default)
**What:** Decrypted content, ⊠{} markers removed
**Use:** Normal file access

```bash
# Read decrypted content
cat /mount/config.yaml

# Edit with auto re-encryption
vim /mount/config.yaml

# Copy decrypted version
cp /mount/config.yaml /tmp/decrypted.yaml
```

### Opened Mode (For Editing Secrets)
**What:** ⊠{} converted to ⊕{}, secrets visible for editing
**Use:** When you need to add/remove/modify secret markers

```bash
# View with ⊕{} markers
cat /mount/config.yaml.sss-opened

# Edit secret structure
vim /mount/config.yaml.sss-opened

# Example content:
#   database:
#     password: ⊕{my-secret-password}
#     host: localhost
```

### Sealed Mode (Raw/Debug)
**What:** Raw file with ⊠{} markers, no decryption
**Use:** Debug, inspect encrypted content

```bash
# View raw sealed content
cat /mount/config.yaml.sss-sealed

# Inspect with hex dump
xxd /mount/config.yaml.sss-sealed

# Example content:
#   database:
#     password: ⊠{encrypted-blob-here}
#     host: localhost
```

## Practical Examples

### Example 1: Normal Editing
```bash
# Mount filesystem
./target/release/sss mount --foreground ~/myproject /tmp/mount &

# Edit file normally (secrets auto-decrypted)
vim /tmp/mount/config.yaml

# Changes are auto-encrypted when saved
# Secrets with ⊠{} markers remain encrypted
```

### Example 2: Adding New Secrets
```bash
# Edit with .sss-opened suffix to see ⊕{} markers
vim /tmp/mount/config.yaml.sss-opened

# Before:
#   api_key: ⊕{old-key-here}
#
# After editing:
#   api_key: ⊕{new-key-here}
#   db_password: ⊕{my-db-pass}  # New secret added

# Save - both secrets encrypted with ⊠{} markers
```

### Example 3: Debugging Encryption
```bash
# Compare three views of same file:

# 1. Rendered (decrypted)
cat /tmp/mount/config.yaml
# Output: api_key: my-secret-value

# 2. Opened (editable)
cat /tmp/mount/config.yaml.sss-opened
# Output: api_key: ⊕{my-secret-value}

# 3. Sealed (raw)
cat /tmp/mount/config.yaml.sss-sealed
# Output: api_key: ⊠{encrypted-base64-blob}
```

## Debugging Hangs

If the mount hangs, you'll see exactly where in the debug output:

```bash
./target/release/sss mount --foreground /src /mnt 2>&1 | tee debug.log
```

Look for:
```
[DEBUG] About to call fuser::mount2()           ← Mount starting
[DEBUG] Mountpoint: "/mnt"
[DEBUG] Options: ...
========== FUSE INIT CALLED ==========          ← FUSE initialized
→ getattr(ino=1)                                ← First operation
← getattr(ino=1) = OK [127.42µs]                ← Completed
```

If output stops, that's your hang point!

### Common Hang Points

**Hangs before "FUSE INIT":**
- fuse-t not installed or not running
- Permission issues with /dev/fuse*
- Kernel extension problem

**Fix:**
```bash
brew reinstall fuse-t
sudo pkill -9 fuse-t  # Then remount
```

**Hangs during INIT:**
- Source directory not accessible
- File descriptor issues

**Fix:**
```bash
# Check source directory permissions
ls -ld /path/to/source

# Try with different source
mkdir /tmp/test
echo "test: ⊠{secret}" > /tmp/test/file.txt
./target/release/sss mount --foreground /tmp/test /tmp/mount
```

**Hangs on first operation:**
- Lock contention in inode management
- Blocking I/O

**Fix:**
Check debug output for timing:
```bash
grep "←" debug.log | grep -o "\[.*\]" | sort -nr
```
Slow operations (>100ms) indicate the problem area.

## Performance Tips

### Use Direct I/O for Large Files
The `.overlay` directory provides raw passthrough:
```bash
# Slow: Goes through SSS processing
cp /mount/large-video.mp4 /dest/

# Fast: Raw passthrough, no processing
cp /mount/.overlay/large-video.mp4 /dest/
```

### Check Cache Behavior
```bash
# Monitor cache entries in debug output
grep "cache" debug.log

# Or check filesystem statistics
mount | grep fuse
```

## Integration with Tools

### With ssse Command
The `ssse` command automatically uses the right suffix:

```bash
# Uses .sss-opened suffix internally
ssse edit config.yaml

# Uses normal (rendered) access
ssse view config.yaml
```

### With Git
```bash
# Git operations see decrypted content
cd /mount
git add config.yaml      # Encrypted version committed
git diff                 # Shows decrypted diff
```

### With Your Editor
```bash
# VS Code
code /mount/config.yaml.sss-opened

# Vim
vim /mount/config.yaml.sss-opened

# Emacs
emacs /mount/config.yaml.sss-opened
```

## Troubleshooting

### Problem: "ioctl: Inappropriate ioctl for device"
**Cause:** Some tool is trying to use ioctl (not supported on fuse-t)
**Solution:** Use virtual suffixes instead, they provide all the same functionality

### Problem: File not found with .sss-opened suffix
**Cause:** Base file doesn't exist
**Solution:**
```bash
# Check base file exists
ls -l /mount/file.txt          # Should exist
ls -l /mount/file.txt.sss-opened  # Virtual, won't show in ls but can access
cat /mount/file.txt.sss-opened    # Should work
```

### Problem: Mount succeeds but ls hangs
**Cause:** readdir operation hanging
**Solution:** Check debug output for last operation:
```bash
./target/release/sss mount --foreground /src /mnt 2>&1 | grep "readdir"
```

### Problem: Writes don't persist
**Cause:** File not properly released/flushed
**Solution:** Ensure proper file close, check debug for release:
```bash
grep "release\|flush" debug.log
```

## Next Steps

1. **Read full documentation:**
   - `docs/MACOS_FUSE_T_NOTES.md` - Detailed implementation notes
   - `docs/FUSE_T_DEBUGGING.md` - Advanced debugging guide

2. **Test your workflow:**
   ```bash
   # Create test directory
   mkdir -p /tmp/sss-test
   cd /tmp/sss-test

   # Initialize project
   ../../target/release/sss init

   # Create test file with secret
   echo "password: ⊕{my-secret}" > config.yaml
   ../../target/release/sss seal config.yaml

   # Mount and test
   ../../target/release/sss mount --foreground . /tmp/mount &
   cat /tmp/mount/config.yaml          # Rendered
   cat /tmp/mount/config.yaml.sss-opened  # Opened
   cat /tmp/mount/config.yaml.sss-sealed  # Sealed
   ```

3. **Report issues:**
   If you encounter hangs, save debug output and report with:
   - Last debug message before hang
   - System info: `sw_vers && brew list fuse-t`
   - Mount command used

## Summary

- ✅ **Virtual suffixes work perfectly** on macOS with fuse-t
- ✅ **No ioctl needed** - all functionality available through suffixes
- ✅ **Three access modes:** rendered, opened, sealed
- ✅ **Comprehensive debugging** - see exactly where hangs occur
- ✅ **Full compatibility** - works just like Linux FUSE

The lack of ioctl support is not a limitation - virtual suffixes provide a better, more portable solution!
