# Quality Assurance Audit - Code Duplication Analysis

**Date:** 2025-12-11
**Branch:** qa
**Focus:** Identifying duplicate functionality and refactoring opportunities

## Executive Summary

This audit identified **7 major areas of code duplication** and inconsistency across the codebase, with the most critical being duplicate secret interpolation logic between FUSE filesystem and the core processor.

---

## 1. 🔴 CRITICAL: Secret Interpolation Duplication

**Problem:** Secret interpolation is implemented twice with different approaches.

### Current Implementation:

#### A. Core Processor (`processor/core.rs:219-240`)
```rust
fn interpolate_secrets(&self, content: &str, file_path: &Path) -> Result<String> {
    // Uses SecretsCache with find_secrets_file()
    // Works with normal filesystem paths
    // Used by: sss render, 9P filesystem
}
```

#### B. FUSE Filesystem (`fuse_fs.rs:792-841`)
```rust
fn interpolate_secrets_via_fd(&self, content: &str, rel_path: &Path) -> Result<String> {
    // Duplicates the regex logic
    // Uses fd-based operations to avoid deadlock
    // Duplicates secrets file finding logic
    // Used by: FUSE mount only
}
```

### Issues:
1. **Same regex pattern duplicated** - `r"(?:⊲|<)\{([^}]+)\}"` appears in both places
2. **Different error handling** - processor warns, FUSE silently keeps marker
3. **Maintenance burden** - changes must be synced between both implementations
4. **Testing complexity** - same logic tested in two places

### Impact:
- **Risk:** HIGH - Changes to interpolation logic must be duplicated
- **Maintainability:** LOW - Easy to miss updating one location
- **Code size:** ~50 lines of duplicate logic

---

## 2. 🔴 CRITICAL: Secrets File Finding Duplication

**Problem:** Finding secrets files is implemented twice with slight variations.

### Current Implementation:

#### A. SecretsCache (`secrets.rs:145-195`)
```rust
pub fn find_secrets_file<P: AsRef<Path>>(
    &self,
    file_path: P,
    project_root: &Path,
) -> Result<PathBuf> {
    // Strategy 1: Check $filename.secrets
    // Strategy 2: Search upward for 'secrets' file
    // Uses normal filesystem operations (.exists())
}
```

#### B. FUSE Filesystem (`fuse_fs.rs:841-877`)
```rust
fn find_secrets_file_via_fd(&self, file_rel_path: &Path) -> Result<PathBuf> {
    // Strategy 1: Check $filename.secrets
    // Strategy 2: Search upward for 'secrets' file
    // Uses fd-based operations (file_exists_via_fd)
}
```

### Issues:
1. **Same search logic duplicated** - both check filename.secrets then search upward
2. **Different underlying operations** - one uses .exists(), one uses faccessat()
3. **Inconsistent error messages** - slightly different wording

### Impact:
- **Risk:** HIGH - Algorithm changes need duplication
- **Bug potential:** MEDIUM - Fixed empty parent path bug in FUSE, not in SecretsCache
- **Code size:** ~35 lines of duplicate logic

---

## 3. 🟡 MEDIUM: Render Call Path Inconsistency

**Problem:** Different code paths are used for the same operation.

### Analysis:

#### sss render (command-line):
```
handle_render()
  └─> processor.decrypt_to_raw_with_path(&content, &file_path)
      ├─> interpolate_secrets(content, file_path)  // Uses SecretsCache
      └─> decrypt_to_raw(content)                  // Removes markers
```

#### FUSE mount:
```
read_and_render()
  └─> read_and_process(path, |fs, content, rel_path| {
      ├─> interpolate_secrets_via_fd(content, rel_path)  // DUPLICATE logic
      └─> processor.decrypt_to_raw(content_with_secrets)
  })
```

#### 9P mount:
```
read_and_render()
  └─> processor.decrypt_to_raw_with_path(&content, path)  // ✅ Shared code
```

### Issues:
1. **FUSE bypasses shared code** - reimplements interpolation instead of using processor
2. **9P uses shared code correctly** - calls decrypt_to_raw_with_path()
3. **Inconsistent behavior** - FUSE and command-line might diverge

### Why FUSE Can't Use Processor Directly:
- **FUSE deadlock issue** - calling .exists() goes back through FUSE mount
- **Needs fd-based operations** - must use source_fd with faccessat(), openat()
- **Valid technical reason** - but implementation should still be shared

### Impact:
- **Risk:** MEDIUM - Behavioral divergence between FUSE and command-line
- **Complexity:** HIGH - FUSE implementation harder to understand
- **Testing:** Need to verify FUSE and CLI produce identical output

---

## 4. 🟡 MEDIUM: Marker Detection Duplication

**Problem:** Marker checking logic exists in multiple forms.

### Current Implementation:

#### A. String-based checking (`filesystem_common.rs:47-55`)
```rust
pub fn has_any_markers(content: &str) -> bool {
    content.contains("⊠{")
        || content.contains("⊕{")
        || content.contains("[*{")
        || content.contains("o+{")
        || content.contains("⊲{")
        || content.contains("<{")
}
```

#### B. Byte-based checking (`fuse_fs.rs:806-808`)
```rust
let has_markers = bytes.windows(2).any(|w| {
    matches!(w, b"\xe2\x8a" | b"[*" | b"o+" | b"<{")
});
```

### Issues:
1. **Different marker sets** - byte version missing some markers
2. **Different approaches** - string vs bytes
3. **No single source of truth** - markers defined in multiple places

### Impact:
- **Risk:** MEDIUM - Byte version might miss markers
- **Accuracy:** Missing `⊕{}` check in byte version
- **Maintainability:** Adding new marker types requires multiple updates

---

## 5. 🟡 MEDIUM: Configuration Loading Patterns

**Problem:** Various patterns for loading `.sss.toml` across commands.

### Patterns Found:

#### Pattern 1: Direct file access (DEPRECATED)
```rust
// src/commands/users.rs (NOW FIXED)
ProjectConfig::load_from_file(CONFIG_FILE_NAME)  // Only checks current dir
```

#### Pattern 2: Search upward (CORRECT)
```rust
// Most commands now use this
let config_path = get_project_config_path()?;
ProjectConfig::load_from_file(&config_path)
```

#### Pattern 3: From specific directory
```rust
// src/commands/mount.rs
let config_path = get_project_config_path_from(source_path)?;
```

### Issues:
1. **Inconsistent usage** - some commands were using wrong pattern (now fixed)
2. **Error messages vary** - different wording for same error
3. **No central helper** - pattern repeated across files

### Impact:
- **Risk:** LOW (after recent fix to users.rs)
- **UX:** Better now - all commands search upward consistently
- **Future:** Should create helper function for common pattern

---

## 6. 🟢 LOW: File Reading Duplication

**Problem:** Multiple filesystem implementations duplicate file reading logic.

### Analysis:

#### FUSE (`fuse_fs.rs:731-788`)
- `read_file_via_fd()` - uses openat() with source_fd
- Platform-specific code for macOS vs Linux
- Handles read loops for large files

#### 9P (`ninep_fs.rs`)
- Uses standard `fs::read()` - simpler approach
- No fd-based operations needed (no in-place mounting)

#### Windows FUSE (`winfsp_fs.rs`)
- Likely has its own implementation

### Issues:
1. **Platform-specific code scattered** - not centralized
2. **Different error handling** - varies by implementation
3. **Testing complexity** - each needs separate tests

### Impact:
- **Risk:** LOW - Platform differences are necessary
- **Justification:** Each filesystem has different requirements
- **Recommendation:** Document why differences exist

---

## 7. 🟢 LOW: Regex Pattern Duplication

**Problem:** Secret interpolation regex defined in two places.

### Current Implementation:

#### A. Core Processor (`processor/core.rs:28`)
```rust
static SECRETS_INTERPOLATION_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?:⊲|<)\{([^}]+)\}").unwrap());
```

#### B. FUSE (`fuse_fs.rs:796-797`)
```rust
static SECRETS_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?:⊲|<)\{([^}]+)\}").unwrap());
```

### Impact:
- **Risk:** LOW - Regex is simple and stable
- **Maintenance:** Adding new marker syntax requires two updates
- **Solution:** Define in `constants.rs` or `filesystem_common.rs`

---

## Recommendations

### Priority 1: CRITICAL (Do First)

#### 1.1 Refactor Secret Interpolation
**Create unified interface that works for both normal and fd-based operations**

```rust
// New trait in secrets.rs
pub trait FileSystemOps {
    fn file_exists(&self, path: &Path) -> bool;
    fn read_file(&self, path: &Path) -> Result<Vec<u8>>;
}

// Normal filesystem implementation
struct StdFileSystemOps;
impl FileSystemOps for StdFileSystemOps {
    fn file_exists(&self, path: &Path) -> bool { path.exists() }
    fn read_file(&self, path: &Path) -> Result<Vec<u8>> { fs::read(path) }
}

// FD-based implementation
struct FdFileSystemOps { source_fd: i32 }
impl FileSystemOps for FdFileSystemOps {
    fn file_exists(&self, path: &Path) -> bool { /* faccessat */ }
    fn read_file(&self, path: &Path) -> Result<Vec<u8>> { /* openat */ }
}

// Unified interpolation
pub fn interpolate_secrets<F: FileSystemOps>(
    content: &str,
    file_path: &Path,
    fs_ops: &F,
) -> Result<String> {
    // Single implementation used by both processor and FUSE
}
```

**Benefits:**
- Single source of truth for interpolation logic
- Same behavior guaranteed for CLI and FUSE
- Easier to test and maintain
- FD-based operations only when needed

**Estimated effort:** 4-6 hours
**Risk:** Medium (requires careful testing)

---

#### 1.2 Unify Secrets File Finding

**Similar approach - create trait for file operations**

```rust
pub fn find_secrets_file<F: FileSystemOps>(
    file_path: &Path,
    project_root: &Path,
    fs_ops: &F,
) -> Result<PathBuf> {
    // Single implementation
    // Strategy 1: filename.secrets
    // Strategy 2: search upward
}
```

**Benefits:**
- Single search algorithm
- Bug fixes apply everywhere
- Consistent error messages

**Estimated effort:** 2-3 hours
**Risk:** Low

---

### Priority 2: MEDIUM (Do Next)

#### 2.1 Unify Marker Detection

**Create comprehensive marker detection in filesystem_common.rs**

```rust
// Add to filesystem_common.rs
pub const MARKER_PATTERNS: &[&str] = &["⊠{", "⊕{", "[*{", "o+{", "⊲{", "<{"];

pub fn has_any_markers(content: &str) -> bool {
    MARKER_PATTERNS.iter().any(|m| content.contains(m))
}

pub fn has_any_markers_bytes(bytes: &[u8]) -> bool {
    // Comprehensive byte-level check for ALL markers
    const MARKER_BYTES: &[&[u8]] = &[
        b"\xe2\x8a\xa0{",  // ⊠{
        b"\xe2\x8a\x95{",  // ⊕{
        b"\xe2\x8a\xb2{",  // ⊲{
        b"[*{",
        b"o+{",
        b"<{",
    ];
    MARKER_BYTES.iter().any(|marker| {
        bytes.windows(marker.len()).any(|w| w == *marker)
    })
}
```

**Benefits:**
- All markers checked consistently
- Byte and string versions stay in sync
- Single place to add new markers

**Estimated effort:** 2 hours
**Risk:** Low

---

#### 2.2 Create Configuration Loading Helper

**Add to config.rs**

```rust
pub fn load_project_config() -> Result<(PathBuf, ProjectConfig)> {
    let config_path = get_project_config_path()?;
    let config = ProjectConfig::load_from_file(&config_path)
        .map_err(|_| anyhow!(
            "No SSS project found. Run 'sss init' first.\n\
             Looking for .sss.toml in {} or parent directories.",
            std::env::current_dir()?.display()
        ))?;
    Ok((config_path, config))
}
```

**Benefits:**
- Consistent error messages
- Less code duplication
- Easier to add features (like config validation)

**Estimated effort:** 1 hour
**Risk:** Very low

---

### Priority 3: LOW (Nice to Have)

#### 3.1 Centralize Regex Patterns

**Move to constants.rs or filesystem_common.rs**

```rust
// In constants.rs or filesystem_common.rs
pub const SECRETS_INTERPOLATION_PATTERN: &str = r"(?:⊲|<)\{([^}]+)\}";
```

**Benefits:**
- Single definition
- Import where needed
- Clear ownership

**Estimated effort:** 30 minutes
**Risk:** Very low

---

#### 3.2 Document Platform Differences

**Add documentation explaining why FUSE needs special handling**

```rust
//! # Platform-Specific File Operations
//!
//! ## FUSE In-Place Mounting
//!
//! When FUSE is mounted over the source directory (in-place mount),
//! normal filesystem operations like `path.exists()` and `fs::read()`
//! will route back through the FUSE mount, causing deadlock.
//!
//! **Solution:** Use fd-based operations with `source_fd`:
//! - `faccessat()` instead of `.exists()`
//! - `openat()` instead of `File::open()`
//! - `fstatat()` instead of `.metadata()`
//!
//! The `source_fd` was opened before mounting, so it still points to
//! the real filesystem underneath the mount point.
```

**Benefits:**
- Future developers understand the rationale
- Prevents "fixing" intentional differences
- Helps with maintenance

**Estimated effort:** 1 hour
**Risk:** None

---

## Testing Recommendations

### 1. Verify Render Equivalence

**Create integration test comparing outputs:**

```rust
#[test]
fn test_render_equivalence_cli_vs_fuse() {
    // Given: A file with secrets interpolation
    // When: Rendered via CLI vs accessed via FUSE
    // Then: Output should be identical
}
```

### 2. Test All Marker Types

**Ensure byte-level detection catches everything:**

```rust
#[test]
fn test_marker_detection_completeness() {
    for marker in MARKER_PATTERNS {
        let content = format!("test {}secret}}", marker);
        assert!(has_any_markers(&content));
        assert!(has_any_markers_bytes(content.as_bytes()));
    }
}
```

### 3. Test Configuration Search

**Verify all commands search upward:**

```rust
#[test]
fn test_all_commands_search_upward() {
    // Create .sss.toml in parent directory
    // Run commands from subdirectory
    // Verify they all find the config
}
```

---

## Metrics

### Current State:
- **Total duplicate lines:** ~150
- **Duplicate functions:** 4 major (interpolate_secrets × 2, find_secrets_file × 2)
- **Maintenance burden:** HIGH
- **Risk of divergence:** HIGH

### After Refactoring:
- **Duplicate lines:** ~20 (platform-specific wrappers only)
- **Shared implementations:** 4
- **Maintenance burden:** LOW
- **Risk of divergence:** LOW

---

## Conclusion

The most critical issue is **duplicate secret interpolation logic** between the core processor and FUSE filesystem. This creates risk of behavioral divergence and doubles the maintenance burden.

**Recommended approach:**
1. Create FileSystemOps trait abstraction (**Priority 1**)
2. Unify interpolation and secrets finding (**Priority 1**)
3. Fix marker detection inconsistencies (**Priority 2**)
4. Add helper functions for common patterns (**Priority 2**)

**Total estimated effort:** 10-15 hours
**Expected benefit:**
- Eliminated behavioral divergence
- Reduced code by ~130 lines
- Easier to maintain and test
- Single source of truth for critical logic

---

**Audit completed by:** Claude Code
**Review date:** 2025-12-11
