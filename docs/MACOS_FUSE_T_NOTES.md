# macOS fuse-t Implementation Notes

## Overview

The FUSE filesystem implementation on macOS uses fuse-t instead of the traditional OSXFUSE/macFUSE. While fuse-t provides excellent compatibility, there are some differences in supported operations.

## ioctl Not Supported

**Issue:** fuse-t does not support the `ioctl()` FUSE operation.

**Impact:** Custom ioctl commands cannot be used to signal special file access modes.

**Solution:** Use virtual file suffixes instead, which are fully supported and provide the same functionality.

## File Access Modes

There are three ways to access files through the FUSE filesystem:

### 1. Rendered Mode (Default)
**Access:** Open the file normally
```bash
cat file.txt
vim file.txt
```
**Behavior:**
- ⊠{} markers are decrypted and removed
- Content is shown as plain text
- Writes are automatically re-sealed with ⊠{} markers

### 2. Opened Mode (For Editing)
**Access:** Append `.sss-opened` suffix to filename
```bash
cat file.txt.sss-opened
vim file.txt.sss-opened
```
**Behavior:**
- ⊠{} markers converted to ⊕{} markers for editing
- Secrets shown in cleartext between ⊕{} markers
- Writes with ⊕{} markers are sealed to ⊠{} markers

**Use case:** When you need to edit the structure (add/remove secrets)

### 3. Sealed Mode (Raw Access)
**Access:** Append `.sss-sealed` suffix to filename
```bash
cat file.txt.sss-sealed
xxd file.txt.sss-sealed
```
**Behavior:**
- Raw file content with ⊠{} markers
- No decryption performed
- See exactly what's stored on disk

**Use case:** Debugging, inspecting encrypted markers, low-level operations

## Virtual Suffix Implementation

The virtual suffix mechanism is implemented in the FUSE filesystem:

```rust
// In VirtualFileSystem::parse_virtual_file_mode()
pub fn parse_virtual_file_mode(name: &OsStr) -> (String, FileMode) {
    let name_str = name.to_string_lossy();

    if let Some(base) = name_str.strip_suffix(".sss-opened") {
        (base.to_string(), FileMode::Opened)
    } else if let Some(base) = name_str.strip_suffix(".sss-sealed") {
        (base.to_string(), FileMode::Sealed)
    } else {
        (name_str.to_string(), FileMode::Rendered)
    }
}
```

### How It Works

1. **Lookup:** When you access `file.txt.sss-opened`, the filesystem:
   - Strips the `.sss-opened` suffix
   - Looks up the real file `file.txt`
   - Returns attributes with the opened mode flag set

2. **Open:** When opening the file:
   - The mode is determined from the suffix
   - Content is processed according to the mode
   - File handle is tagged with the mode

3. **Read:** When reading:
   - Content is transformed based on the mode
   - Rendered: ⊠{} → plaintext
   - Opened: ⊠{} → ⊕{}
   - Sealed: raw content

4. **Write:** When writing:
   - Content is processed in reverse
   - Rendered: plaintext → ⊠{}
   - Opened: ⊕{} → ⊠{}
   - Sealed: raw write

## Alternative: Flag-Based Signaling (Advanced)

For programmatic access, the filesystem also supports flag-based mode signaling:

### Opened Mode
Use nonsense flag combination `O_DIRECTORY | O_CREAT` when opening:
```c
int fd = openat(dirfd, "file.txt", O_RDONLY | O_DIRECTORY | O_CREAT);
```
This is semantically invalid (can't create when opening as directory), so it's used as a signal.

### Sealed Mode
Use nonsense flag combination `O_RDONLY | O_TRUNC`:
```c
int fd = openat(dirfd, "file.txt", O_RDONLY | O_TRUNC);
```
This is semantically invalid (can't truncate when read-only), so it's used as a signal.

**Note:** This mechanism is primarily for internal use and testing. End users should use the virtual suffix approach.

## Comparison: Linux vs macOS

| Feature | Linux (FUSE) | macOS (fuse-t) |
|---------|-------------|----------------|
| ioctl support | ✅ Yes | ❌ No |
| Virtual suffixes | ✅ Yes | ✅ Yes |
| Flag signaling | ✅ Yes | ✅ Yes |
| O_PATH support | ✅ Yes | ❌ No (use O_RDONLY) |
| fdatasync | ✅ Yes | ❌ No (use fsync) |

## Best Practices for macOS

1. **Use virtual suffixes** for all mode selection:
   ```bash
   # Good - works everywhere
   ssse edit file.txt.sss-opened

   # Avoid - ioctl not available on macOS
   # (some hypothetical ioctl-based tool)
   ```

2. **Check for fuse-t presence** before mounting:
   ```bash
   if ! brew list fuse-t &>/dev/null; then
       echo "Please install fuse-t: brew install fuse-t"
       exit 1
   fi
   ```

3. **Use foreground mode** for debugging:
   ```bash
   sss mount --foreground /source /mount
   ```

4. **Monitor debug output** to see mode detection:
   ```
   [FUSE DEBUG] → lookup(parent=1, name="file.txt.sss-opened")
   [FUSE DEBUG]   lookup: .sss-opened suffix detected, mode=Opened
   [FUSE DEBUG] ← lookup(...) = OK
   ```

## User-Visible Commands

### ssse edit (Uses Opened Mode)
```bash
ssse edit file.txt
```
Internally opens `file.txt.sss-opened` in the mounted filesystem.

### ssse view (Uses Rendered Mode)
```bash
ssse view file.txt
```
Opens the file normally with full decryption.

### Direct Access
```bash
# Rendered mode (default)
cat /mount/file.txt

# Opened mode (for editing)
cat /mount/file.txt.sss-opened

# Sealed mode (raw)
cat /mount/file.txt.sss-sealed
```

## Troubleshooting

### "ioctl: Inappropriate ioctl for device"
This is expected on macOS. Use virtual suffixes instead:
```bash
# Instead of ioctl-based tools
cat file.txt.sss-opened  # Use suffix approach
```

### Virtual Suffixes Not Working
Check that the file exists without the suffix:
```bash
ls -la /mount/file.txt         # Should exist
ls -la /mount/file.txt.sss-opened  # Virtual, won't show in ls
cat /mount/file.txt.sss-opened     # But can be read
```

### Mode Not Detected
Enable debug logging to see mode detection:
```bash
# Look for "parse_virtual_file_mode" in debug output
./sss mount --foreground /src /mnt 2>&1 | grep -i mode
```

## Implementation Details

The virtual suffix mechanism is preferred over ioctl because:

1. **Cross-platform:** Works on Linux, macOS, Windows (WinFsp)
2. **User-friendly:** Clear intent from filename
3. **Tool-friendly:** Works with standard Unix tools
4. **Discoverable:** Users can see and understand the suffixes
5. **Compatible:** No special syscalls needed

The ioctl mechanism was originally added for programmatic control but proved unnecessary since virtual suffixes handle all use cases effectively.

## Future Enhancements

Possible improvements for macOS support:

1. **Extended attributes** - Use xattrs to signal modes
   - `getxattr("user.sss.mode") = "opened"`
   - Would require changes to FUSE handlers

2. **Special directory** - Mode selection via path
   - `/mount/.sss/opened/file.txt`
   - `/mount/.sss/sealed/file.txt`
   - More discoverable than suffixes

3. **Control file** - JSON/YAML configuration
   - `/mount/.sss-control` with mode mappings
   - More flexible but less immediate

However, the current virtual suffix approach works well and requires no additional fuse-t features.

## Conclusion

The lack of ioctl support in fuse-t is not a limitation in practice. The virtual suffix mechanism provides all necessary functionality in a more portable and user-friendly way. Users on macOS should use `.sss-opened` and `.sss-sealed` suffixes to access different file modes.
