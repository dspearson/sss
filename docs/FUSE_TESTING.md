# FUSE Integration Testing

## Overview

The FUSE integration tests (`tests/fuse_integration.rs`) provide comprehensive end-to-end testing of the marker inference system in a real FUSE filesystem context.

## Test Coverage

### ✅ Tests Implemented (11 tests)

| Test | Description | What It Verifies |
|------|-------------|------------------|
| `test_fuse_mount_and_basic_read` | Basic mount and file reading | FUSE mount works, files are rendered correctly |
| `test_fuse_marker_inference_simple_edit` | Edit a marked value | Markers are preserved on simple edits |
| `test_fuse_marker_inference_content_propagation` | Add duplicate content | Propagation marks all instances |
| `test_fuse_marker_inference_adjacent_modification` | Insert text next to marker | Adjacent modification expands marker |
| `test_fuse_user_inserted_marker` | User adds new marker | User markers are validated and converted |
| `test_fuse_multiline_marker_edit` | Edit multiline marked content | Multiline markers preserved correctly |
| `test_fuse_complete_rewrite` | Completely rewrite a file | Markers expand to cover new content |
| `test_fuse_delimiter_handling` | Edit quoted values | Delimiters stay with markers |
| `test_fuse_unicode_handling` | Edit unicode content | UTF-8 safe marker handling |
| `test_fuse_multiple_markers_in_file` | Edit file with multiple secrets | All markers preserved independently |

## Requirements

### System Requirements

**Linux:**
- FUSE kernel module loaded (`lsmod | grep fuse`)
- `fusermount` utility installed
- User has FUSE permissions

**macOS:**
- macFUSE installed (https://osxfuse.github.io/)
- System extension loaded

**Both:**
- `ed` text editor (for noninteractive editing)
- Rust with `--features fuse` (or `macfuse` on macOS)

### Install Requirements

**Debian/Ubuntu:**
```bash
sudo apt-get install fuse ed
sudo modprobe fuse
sudo usermod -a -G fuse $USER  # Add user to fuse group
```

**macOS:**
```bash
brew install --cask macfuse
brew install ed  # Usually already installed
```

**RHEL/CentOS:**
```bash
sudo yum install fuse ed
sudo modprobe fuse
```

## Running the Tests

### Quick Start

Use the provided test runner script:
```bash
./scripts/run-fuse-tests.sh
```

This will:
1. Check FUSE availability
2. Verify `ed` is installed
3. Build the project with FUSE support
4. Run all FUSE integration tests
5. Report results and cleanup

### Run Specific Test

```bash
./scripts/run-fuse-tests.sh test_fuse_marker_inference_simple_edit
```

### Manual Execution

**Linux:**
```bash
cargo test --features fuse --test fuse_integration -- --ignored --nocapture
```

**macOS:**
```bash
cargo test --features macfuse --test fuse_integration -- --ignored --nocapture
```

**Note**: Tests are marked with `#[ignore]` because they require FUSE to be available and working. The `--ignored` flag is required to run them.

## Test Architecture

### TestProject Helper

The `TestProject` struct manages the complete lifecycle:

```rust
struct TestProject {
    source_dir: TempDir,    // Encrypted backing store
    mount_dir: TempDir,     // FUSE mount point
    mount_process: Option<Child>,  // Mount process
}
```

#### Lifecycle

```
1. TestProject::new()
   ├─> Create temporary directories
   ├─> Initialize SSS project
   └─> Return project instance

2. project.mount()
   ├─> Spawn FUSE mount process
   ├─> Wait for mount to be ready
   └─> Verify directory is accessible

3. Test operations
   ├─> project.write_source_file() - Write encrypted files
   ├─> project.read_mount_file() - Read rendered content
   ├─> project.edit_file_with_ed() - Noninteractive edits
   └─> project.read_source_file() - Verify encryption

4. project.unmount() [automatic via Drop]
   ├─> Call fusermount -u / umount
   ├─> Kill mount process
   └─> Cleanup temporary directories
```

### Noninteractive Editing with `ed`

The tests use `ed` (the standard Unix line editor) for noninteractive file editing:

```rust
project.edit_file_with_ed(
    "config.txt",
    "s/old/new/\n"  // Substitute command
)?;
```

**Why `ed`?**
- Available on all Unix systems
- Fully scriptable
- No terminal required
- Deterministic behavior

**Common ed commands used:**
- `s/old/new/` - Substitute (search and replace)
- `a` - Append text
- `d` - Delete line
- `$` - Last line
- `w` - Write file
- `q` - Quit

## Test Workflow Example

### Test: Simple Marker Edit

```rust
#[test]
fn test_fuse_marker_inference_simple_edit() {
    // 1. Setup
    let mut project = TestProject::new()?;

    // 2. Create file with marker in source
    project.write_source_file(
        "config.txt",
        "api_key: o+{abc-123-def}"
    )?;

    // 3. Mount FUSE
    project.mount()?;

    // 4. Edit file through FUSE (noninteractive)
    //    User sees: "api_key: abc-123-def"
    //    User changes to: "api_key: xyz-456-uvw"
    project.edit_file_with_ed(
        "config.txt",
        "s/abc-123-def/xyz-456-uvw/\n"
    )?;

    // 5. Wait for write to complete
    thread::sleep(Duration::from_millis(200));

    // 6. Unmount
    project.unmount()?;

    // 7. Verify marker was preserved in source
    let source = project.read_source_file("config.txt")?;
    assert!(source.contains("⊕{xyz-456-uvw}"));
}
```

### What Happens Behind the Scenes

```
Source File (Encrypted):
  api_key: o+{abc-123-def}

FUSE Mount (Rendered):
  api_key: abc-123-def

User Edit via ed:
  s/abc-123-def/xyz-456-uvw/

FUSE Write Handler:
  1. Receives: "api_key: xyz-456-uvw"
  2. Calls: marker_inference::infer_markers()
  3. Input source: "api_key: o+{abc-123-def}"
  4. Input edited: "api_key: xyz-456-uvw"
  5. Output: "api_key: ⊕{xyz-456-uvw}"
  6. Encrypts and writes to backing store

Result in Source:
  api_key: ⊕{xyz-456-uvw}
```

## Debugging Failed Tests

### Check FUSE Availability

```bash
# Linux
lsmod | grep fuse
fusermount --version

# macOS
ls -la /Library/Filesystems/macfuse.fs
```

### Check for Lingering Mounts

```bash
# Linux
mount | grep fuse
fusermount -u /path/to/mount

# macOS
mount | grep macfuse
umount /path/to/mount
```

### Run with Verbose Output

```bash
RUST_LOG=debug cargo test --features fuse \
  --test fuse_integration \
  test_name -- --ignored --nocapture
```

### Common Issues

**1. "FUSE not available"**
- Linux: `sudo modprobe fuse`
- macOS: Install macFUSE and reboot

**2. "Permission denied" on mount**
- Linux: Add user to `fuse` group
- macOS: Check System Preferences > Security > Allow macFUSE

**3. "ed: command not found"**
- Install: `sudo apt-get install ed` or `brew install ed`

**4. "Mount failed to become ready"**
- Check FUSE daemon is running
- Verify mount point exists and is empty
- Check system logs: `dmesg | grep fuse` (Linux)

**5. Tests hang**
- Lingering FUSE mount: unmount manually
- Kill orphaned processes: `pkill -9 sss`

## Performance Characteristics

### Test Execution Time

| Test | Typical Duration |
|------|------------------|
| Mount + basic read | ~500ms |
| Simple edit | ~800ms |
| Content propagation | ~900ms |
| Multiple markers | ~1000ms |
| Complete suite | ~10s |

**Note**: Most time is spent waiting for FUSE mount/unmount, not the marker inference itself.

### Optimization Opportunities

The tests use conservative timeouts for reliability:
- Mount wait: 2 seconds (20 retries × 100ms)
- Write wait: 200ms after edit

These could be reduced for faster test runs on reliable systems.

## Continuous Integration

### GitHub Actions Example

```yaml
name: FUSE Tests

on: [push, pull_request]

jobs:
  fuse-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Install FUSE
        run: |
          sudo apt-get update
          sudo apt-get install -y fuse ed
          sudo modprobe fuse

      - name: Setup Rust
        uses: actions-rs/toolchain@v1
        with:
          toolchain: stable

      - name: Run FUSE tests
        run: ./scripts/run-fuse-tests.sh
```

**Note**: FUSE tests may not work in all CI environments due to kernel module requirements. Consider using Docker with `--privileged` flag or skip in CI and run locally.

## Test Maintenance

### Adding New Tests

1. Follow the existing pattern in `tests/fuse_integration.rs`
2. Use `TestProject` helper for setup/teardown
3. Mark test with `#[ignore]`
4. Add to this documentation

### Best Practices

- **Always use `#[ignore]`**: These tests require system resources
- **Use timeouts**: FUSE operations are async
- **Clean up properly**: Implement in `Drop` trait
- **Verify both sides**: Check source (encrypted) and mount (rendered)
- **Test edge cases**: Unicode, multiline, empty files, etc.

## Related Documentation

- **Marker Inference**: `src/marker_inference/README.md`
- **Design Spec**: `docs/marker-design.md`
- **Implementation**: `docs/MARKER_INFERENCE_IMPLEMENTATION.md`
- **FUSE Code**: `src/fuse_fs.rs`

## Future Enhancements

Potential improvements to test coverage:

- [ ] Concurrent edits (multiple files)
- [ ] Large file performance tests (>1MB)
- [ ] Stress tests (many edits in succession)
- [ ] Binary file handling
- [ ] Symlink handling
- [ ] Permission changes
- [ ] File deletion and recreation
- [ ] Directory operations
- [ ] Cross-platform compatibility matrix

## Summary

The FUSE integration tests provide **comprehensive end-to-end verification** that the marker inference system works correctly in real-world scenarios. They test the complete stack:

1. ✅ FUSE filesystem mounting
2. ✅ File rendering (marker removal)
3. ✅ Noninteractive editing (via `ed`)
4. ✅ Marker inference on write
5. ✅ Content encryption
6. ✅ Proper cleanup

Run these tests before any release to ensure the marker preservation system works correctly in production.
