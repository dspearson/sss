# Fuse-t Debugging Guide for macOS

## Overview

This document describes the comprehensive debugging instrumentation added to the FUSE subsystem to diagnose hanging and mounting issues with fuse-t on macOS.

## Debug Logging

All FUSE operations now include detailed debug logging with:
- Thread ID and Process ID for tracking concurrent operations
- Timing information (in microseconds/milliseconds)
- Entry and exit points for all operations
- Parameters and return values

### Debug Log Format

```
[FUSE DEBUG ThreadId(N) PID:XXXXX] message
```

### Key Debug Points

1. **Mount Initialization** (`src/commands/mount.rs`)
   - Process PID
   - Mountpoint path
   - Mount options
   - Entry/exit of `fuser::mount2()` call

2. **FUSE Init Callback** (`src/fuse_fs.rs::init()`)
   - Filesystem initialization
   - Source path and file descriptors
   - Pinned path configuration
   - UID/GID information

3. **FUSE Operations** (all instrumented)
   - `getattr` - File attribute queries
   - `lookup` - Directory entry lookups
   - `readdir` - Directory content enumeration
   - `open` - File open operations
   - `read` - File read operations
   - `write` - File write operations
   - `release` - File close/cleanup
   - `flush` - Pre-close data flush
   - `fsync` - File synchronization
   - `access` - Permission checks

## Common Hang Points with fuse-t

### 1. Mount Handshake Hang

**Symptoms:**
- `fuser::mount2()` called but never returns
- No FUSE init callback logged

**Debug output to look for:**
```
[DEBUG] About to call fuser::mount2()
[DEBUG] Mountpoint: ...
[DEBUG] Options: ...
```

**Possible causes:**
- fuse-t daemon not running
- Kernel extension issues
- Permission problems with /dev/fuseN devices

**Solutions:**
```bash
# Check if fuse-t is installed
brew list fuse-t

# Restart fuse-t services
sudo pkill -9 fuse-t
# Remount will auto-start it

# Check for kernel extension loading issues
kextstat | grep fuse
```

### 2. Init Callback Hang

**Symptoms:**
- FUSE init called but never completes
- Hangs during initialization

**Debug output to look for:**
```
========== FUSE INIT CALLED ==========
FUSE filesystem initialization starting
Source path: ...
```

**Possible causes:**
- Blocking I/O during init
- File descriptor issues
- Permission problems accessing source directory

### 3. First Operation Hang

**Symptoms:**
- Init completes successfully
- First getattr/lookup hangs

**Debug output to look for:**
```
→ getattr(ino=1)
```
(But no corresponding `←` completion log)

**Possible causes:**
- Deadlock in inode management
- File descriptor access issues
- Permissions on source directory

## Debugging Workflow

### Step 1: Run with Foreground Mode

Always test with `--foreground` flag first:

```bash
cargo build --release
./target/release/sss mount --foreground /path/to/source /path/to/mount
```

This ensures:
- All debug output goes to stderr
- No daemonization interferes with debugging
- Easy Ctrl+C termination

### Step 2: Analyze Debug Output

Look for the progression:

1. **Mount initialization**
   ```
   [DEBUG] About to call fuser::mount2()
   ```

2. **FUSE init callback**
   ```
   ========== FUSE INIT CALLED ==========
   ```

3. **First operations** (macOS typically does these immediately)
   ```
   → getattr(ino=1)
   ← getattr(ino=1) = OK
   → readdir(ino=1, offset=0)
   ```

### Step 3: Identify Hang Point

If output stops at any point, that's where the hang occurs:

- **Before mount2 returns**: Kernel/daemon communication issue
- **During init**: Filesystem initialization issue
- **During first operation**: Operation handler deadlock/blocking

### Step 4: Check Timing

Look at timing information in brackets:

```
← getattr(ino=1) = OK [127.42µs]
```

Slow operations (>100ms) may indicate:
- I/O blocking
- Lock contention
- Heavy computation

## fuse-t Specific Considerations

### 1. File Descriptor Flags

macOS doesn't support `O_PATH`, so we use `O_RDONLY | O_DIRECTORY`:

```rust
#[cfg(target_os = "macos")]
let flags = libc::O_RDONLY | libc::O_DIRECTORY;
```

### 2. Sync Operations

macOS doesn't have `fdatasync()`:

```rust
#[cfg(target_os = "macos")]
let result = unsafe { libc::fsync(fd) };
```

### 3. Kernel Differences

fuse-t implements FUSE protocol differently than Linux FUSE:
- May send different operation sequences
- Different caching behavior
- Different attribute/permission handling

## Advanced Debugging

### Enable Even More Verbose Logging

Modify `fuse_debug!` macro to include more context:

```rust
macro_rules! fuse_debug {
    ($($arg:tt)*) => {
        {
            let thread_id = std::thread::current().id();
            let pid = std::process::id();
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_micros();
            eprintln!("[{} FUSE DEBUG {:?} PID:{}] {}",
                timestamp, thread_id, pid, format!($($arg)*));
        }
    };
}
```

### Capture Debug Output

```bash
./target/release/sss mount --foreground /source /mount 2> fuse_debug.log
```

Then analyze:

```bash
# Show operation sequence
grep "→\|←" fuse_debug.log

# Find operations that didn't complete
grep "→" fuse_debug.log | while read line; do
    op=$(echo "$line" | grep -o "→ [a-z]*")
    if ! grep -q "← ${op#→ }" fuse_debug.log; then
        echo "Incomplete: $line"
    fi
done

# Show slowest operations
grep "←" fuse_debug.log | grep -o "\[.*\]" | sort -nr
```

### Use dtrace/Instruments

On macOS, you can also use system tracing:

```bash
# Trace syscalls
sudo dtruss -f ./target/release/sss mount --foreground /source /mount 2>&1 | tee dtrace.log

# Use Instruments.app
# File > Record Trace > System Trace
# Then run mount command
```

## Known Issues with fuse-t

1. **Mount hangs on first access**
   - Usually due to permission issues
   - Check source directory is readable

2. **Slow initial operations**
   - fuse-t may do more aggressive attribute caching
   - First operations populate kernel caches

3. **Unexpected unmounts**
   - Check system logs: `log show --predicate 'process == "fuse-t"' --last 1h`

## Troubleshooting Checklist

- [ ] fuse-t installed via brew
- [ ] Source directory exists and is readable
- [ ] Mount point exists and is empty
- [ ] No other FUSE filesystems mounted at same point
- [ ] Running with `--foreground` for debugging
- [ ] Debug output shows mount2 call
- [ ] Debug output shows init callback
- [ ] No errors in system log

## Getting Help

When reporting issues, include:

1. Full debug output: `2> debug.log`
2. System info: `sw_vers && brew list fuse-t`
3. Mount command used
4. Point where it hangs (last debug message)
5. Relevant system logs

## Example Debug Session

```bash
# Terminal 1: Run with debugging
cargo build --release
./target/release/sss mount --foreground ~/test /tmp/mount 2>&1 | tee fuse_debug.txt

# Terminal 2: Monitor in real-time
tail -f fuse_debug.txt

# Terminal 3: Test operations (after mount succeeds)
ls /tmp/mount
cat /tmp/mount/file.txt

# When done, Ctrl+C in Terminal 1
# Then analyze fuse_debug.txt for timing and hang points
```

## Performance Analysis

Use the timing information to identify bottlenecks:

```bash
# Extract all operation timings
grep "←.*\[" fuse_debug.log | \
    awk -F'[][µms]' '{print $(NF-1) " " $0}' | \
    sort -n | \
    tail -20
```

This shows the 20 slowest operations, helping identify performance issues.

## Conclusion

With this comprehensive debugging instrumentation, you can precisely identify where fuse-t is hanging or having issues. The key is to:

1. Run in foreground mode
2. Watch for the progression of debug messages
3. Note where output stops
4. Check timing for performance issues
5. Use the debug output to narrow down the root cause

The instrumentation covers all critical paths from mount initialization through every FUSE operation, giving complete visibility into the filesystem behavior.
