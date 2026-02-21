# Codebase Concerns

**Analysis Date:** 2026-02-21

## Tech Debt

**Unextracted secrets handler module:**
- Issue: Secrets interpolation logic remains monolithic in `processor/core.rs` instead of being separated into dedicated `secrets_handler.rs` module
- Files: `src/processor/mod.rs`, `src/processor/core.rs`
- Impact: Code reusability is reduced; module organization is incomplete per design intent; maintenance difficulty increases
- Fix approach: Extract secrets lookup, caching, and interpolation into `src/processor/secrets_handler.rs` and re-export from `mod.rs`

**Legacy private key format in projects:**
- Issue: Project configuration files may contain private keys in legacy format; system warns users but doesn't enforce migration
- Files: `src/project.rs` (lines 486)
- Impact: Mixed old/new formats reduce security clarity; migration is optional, creating long-term compatibility burden
- Fix approach: Implement automatic migration on project load or deprecate legacy format entirely with explicit migration command

**Incomplete agent key listing:**
- Issue: `list keys` command is stubbed but not implemented in sss-agent binary
- Files: `src/bin/sss-agent.rs` (line 242)
- Impact: Agent key management is incomplete; users cannot enumerate available keys through agent interface
- Fix approach: Implement list functionality to query available keys from agent policy file

**Persistent backup directories:**
- Issue: 22 backup directories (`.sss_backup_*`) are present in repository root, created by backup operations
- Files: `.sss_backup_20251211_*`, `.sss_backup_20260213_*`, `.sss_backup_20260215_*` (22 total)
- Impact: Repository bloat; version control pollution; unclear which backups are stale/needed
- Fix approach: Establish backup retention policy; move backups to `.backups/` directory; add to `.gitignore`

## Security Considerations

**Unencrypted private key storage without password protection:**
- Risk: When storing keypairs without password protection, private keys are only base64-encoded, accessible to anyone with filesystem access
- Files: `src/keystore.rs` (lines 122-141), `src/commands/keys.rs` (line 426)
- Current mitigation: Clear warnings printed to stderr; secure directory permissions (0o700); optional system keyring integration
- Recommendations:
  1. Make password protection mandatory for new keys (option to skip only for system keyring)
  2. Detect unencrypted keys on load and warn/prompt for password protection
  3. Document keyring setup more prominently in CLI help

**System keyring fallback silent degradation:**
- Risk: When `SSS_USE_KEYRING=true` but system keyring unavailable, system silently falls back to unencrypted file storage
- Files: `src/keystore.rs` (lines 74-78)
- Current mitigation: Warning message printed, but proceeds without error
- Recommendations:
  1. Make this an error condition (fail if keyring explicitly requested but unavailable)
  2. Or require explicit acknowledgment flag when falling back is acceptable
  3. Document the fallback behavior in configuration

**Weak password warnings insufficient:**
- Risk: Weak password detection only warns in `secure_memory.rs`, may not catch all password paths
- Files: `src/secure_memory.rs` (line 323)
- Current mitigation: Warning printed to stderr
- Recommendations:
  1. Enforce minimum password strength at derivation time
  2. Add configurable password policy (length, complexity requirements)
  3. Use ZXCVBN or similar library for password strength estimation

**Insecure temporary file fallback on Linux:**
- Risk: When `/dev/shm` unavailable on Linux, falls back to `/tmp` which is world-readable
- Files: `src/commands/process.rs` (lines 664-674)
- Current mitigation: Warning message `[WARN] /dev/shm not available, using /tmp (insecure!)`
- Recommendations:
  1. Use secure temporary directory creation (tempfile crate with secure permissions)
  2. Check `/tmp` permissions and warn if world-writable
  3. Consider failing if secure tmp unavailable on production systems

**Cryptographic operations panic on libsodium initialization failure:**
- Risk: `panic!()` in crypto module initialization prevents graceful error handling
- Files: `src/crypto.rs` (line 27)
- Current mitigation: None - process will crash
- Recommendations:
  1. Return `Result` from initialization instead of panicking
  2. Implement lazy initialization with error propagation
  3. Test failure scenarios (libsodium unavailable, corrupted)

**Multiple unwrap() calls in test code may mask issues:**
- Risk: 69+ unwrap() calls throughout codebase, mostly in tests and example code; panic on unexpected state
- Files: Scattered across `src/lib.rs`, `src/audit_log.rs`, `src/agent_policy.rs`, `src/crypto.rs` (test sections)
- Current mitigation: Limited to test/example contexts in most cases
- Recommendations:
  1. Replace test unwraps with `?` operator and propagate errors
  2. Use Result types in test assertions rather than unwrap
  3. Audit non-test unwraps for production code paths

**Lock poisoning from mutex unwraps:**
- Risk: 11 instances of `.lock().unwrap()` will panic if mutex is poisoned (another thread panicked while holding it)
- Files: `src/audit_log.rs` (5 instances), others scattered
- Current mitigation: None - poisoned locks cause process crash
- Recommendations:
  1. Use parking_lot::Mutex instead of std::Mutex (never poisons)
  2. Or handle poisoned state: `.lock().unwrap_or_else(|poisoned| poisoned.into_inner())`
  3. Review all lock usage for poison recovery

## Performance Bottlenecks

**FUSE filesystem caching strategy incomplete:**
- Problem: 58 unwrap_or() calls in `fuse_fs.rs` for missing cache entries; no cache invalidation strategy
- Files: `src/fuse_fs.rs` (entire file, 3629 lines)
- Cause: Cache key scheme doesn't account for file modifications; render_cache, path_to_ino mappings may become stale after external edits
- Improvement path:
  1. Implement file modification time tracking in inode entries
  2. Invalidate cache on stat changes (mtime, size)
  3. Add cache eviction policy (LRU or time-based)
  4. Profile cache hit rates under concurrent workloads

**Large monolithic processor core module:**
- Problem: `processor/core.rs` is 1274 lines, handling encryption, decryption, marker parsing, error handling, secrets interpolation
- Files: `src/processor/core.rs`
- Cause: Incomplete module extraction; secrets_handler design acknowledged but not implemented
- Improvement path:
  1. Extract marker parsing (350 lines) → completed in `processor/marker_parser.rs`
  2. Extract secrets interpolation (200 lines) → `processor/secrets_handler.rs` (TODO)
  3. Extract error handling (100 lines) → `processor/errors.rs`
  4. Keep core processing logic compact (<500 lines)

**String cloning and allocations in hot paths:**
- Problem: Multiple `clone()` and `to_string()` calls in encryption/decryption loops
- Files: `src/processor/core.rs` (lines 576-593 example), `src/secrets.rs` (interpolation paths)
- Cause: Immutable string building; content preparation before processing
- Improvement path:
  1. Use `String::with_capacity()` and `push_str()` for result building (already done in some paths)
  2. Profile marker processing on large files (>10MB)
  3. Consider reference-based content processing for read-only operations

**Regex lazy_static allocations at runtime:**
- Problem: Regex patterns for secrets interpolation and marker detection compiled via `Lazy::new()` at first use
- Files: `src/secrets.rs` (lines 37-53), multiple regex definitions
- Cause: Necessary for complex patterns but deferred initialization may cause first-use latency spikes
- Improvement path:
  1. Pre-compile regex patterns at startup
  2. Test initialization timing under load
  3. Consider alternative marker parsing (custom parser instead of regex)

**FUSE mount directory walk with ignore patterns:**
- Problem: Full directory traversal with globset matching on every readdir call
- Files: `src/fuse_fs.rs` (directory listing operations)
- Cause: Ignore patterns applied per-file instead of at directory level
- Improvement path:
  1. Cache ignore pattern matching results per directory
  2. Use globset's optimization features for batch matching
  3. Profile deep directory structures (1000+ files)

## Fragile Areas

**FUSE fd-based filesystem operations with path relativization:**
- Files: `src/fuse_fs.rs` (lines 215-240)
- Why fragile:
  - Critical assumption: all paths must be relative to source_fd to prevent deadlocks
  - If absolute paths accidentally passed, operations silently route through FUSE (deadlock)
  - `unwrap_or()` fallback may mask path correctness issues
  - No type-level enforcement of relativized paths
- Safe modification:
  1. Create newtype wrapper `RelativePath(PathBuf)` to enforce at type level
  2. Add assertions/debug checks for path format validity
  3. Add integration tests for path handling edge cases
- Test coverage: Limited to basic path operations; needs end-to-end FUSE mount testing

**Nested project processor management without ownership model:**
- Files: `src/fuse_fs.rs` (lines 203-204)
- Why fragile:
  - `nested_processors: HashMap<PathBuf, Processor>` stores Processor per nested project
  - Key scheme (relative path) must match exactly for correct processor selection
  - No validation that nested project actually exists or has matching keys
  - If key loading fails for nested project, no_key_roots accumulates but processors may not match
- Safe modification:
  1. Validate all nested paths at mount time, not lazily
  2. Return explicit error if any nested project cannot be initialized
  3. Cache initialization results with clear failure states
- Test coverage: No specific tests for nested project handling; only unit tests in isolation

**Marker size validation bypass:**
- Files: `src/processor/core.rs` (lines 537-541, 648-649)
- Why fragile:
  - Size check returns early but keeps original marker if too large
  - No error propagated; silent truncation/rejection of large secrets
  - Encrypted marker size (`⊠{...}`) larger than plaintext; recursive encryption risk
- Safe modification:
  1. Return `Result` for size validation; propagate errors upward
  2. Document maximum supported secret size in config/constants
  3. Add tests for boundary conditions (exactly at limit, slightly over)
- Test coverage: No tests for size boundary conditions

**LibSodium FFI unsafe blocks without comprehensive testing:**
- Files: `src/crypto.rs` (lines 85-90 and multiple other unsafe blocks)
- Why fragile:
  - Multiple unsafe blocks for FFI calls to libsodium
  - Pointer arithmetic in randombytes_buf call
  - No memory safety tests; relies entirely on libsodium correctness
  - Version pinning: `libsodium-sys = 0.2` (old); libsodium 1.0.12+ required at runtime
- Safe modification:
  1. Upgrade to latest libsodium-sys
  2. Add integration tests with valgrind/miri for memory safety
  3. Use safer wrapper crates where possible (sodiumoxide alternative)
  4. Document exact libsodium version requirements
- Test coverage: Basic crypto roundtrip tests only; no memory safety checks

**Keyring integration with fallback masking real issues:**
- Files: `src/keystore.rs` (lines 73-81), `src/keyring_support.rs`
- Why fragile:
  - Silently falling back from keyring to file storage masks real configuration issues
  - Error context lost; user won't know why keyring wasn't used
  - If keyring became available later, user won't automatically switch
  - No audit trail of storage location decisions
- Safe modification:
  1. Log all keyring availability checks with reasons for fallback
  2. Add `sss keys inspect` command to show where each key is stored
  3. Implement background check for keyring availability (warn if it became available)
  4. Add migration command: `sss keys migrate-to-keyring`
- Test coverage: No tests for keyring fallback scenarios

## Scaling Limits

**FUSE inode table memory usage unbounded:**
- Current capacity: Single u64 counter; HashMap grows without eviction
- Files: `src/fuse_fs.rs` (lines 189-192)
- Limit: Memory exhaustion on very large directories (>1M files) or long-running mounts
- Scaling path:
  1. Implement inode cache eviction (LRU or time-based)
  2. Add configurable max inode count
  3. Profile memory usage with large directory trees
  4. Consider two-tier inode scheme (memory + persistent)

**File handle table with no cleanup for abandoned handles:**
- Current capacity: Unbounded HashMap of FileHandle structs; no timeout/cleanup
- Files: `src/fuse_fs.rs` (lines 196-197)
- Limit: Handles accumulate if editors crash without closing; unbounded memory growth
- Scaling path:
  1. Implement handle expiration (e.g., 5-minute timeout on unused handles)
  2. Add background cleanup task
  3. Track handle lifecycle with metrics
  4. Warn if handle count exceeds threshold

**Render cache memory usage on large files:**
- Current capacity: Entire file contents cached per inode; no size limit
- Files: `src/fuse_fs.rs` (lines 200)
- Limit: Files >100MB can consume significant RAM; concurrent access amplifies
- Scaling path:
  1. Implement cache size limit (e.g., 1GB total)
  2. Add cache statistics endpoint for monitoring
  3. Profile real-world usage patterns
  4. Consider streaming reads for large files

**Nested project discovery not lazy:**
- Current capacity: All nested projects discovered at mount time
- Files: `src/fuse_fs.rs` (entire initialization)
- Limit: Deep nested structures with many projects cause slow mount times
- Scaling path:
  1. Implement lazy nested project discovery (on-demand)
  2. Cache project detection results
  3. Profile discovery time for 100+ nested projects
  4. Add mount-time timeout for discovery

## Dependencies at Risk

**Old libsodium-sys version:**
- Risk: `libsodium-sys = 0.2` is outdated; newer versions may have important security patches
- Impact: May miss critical libsodium security fixes; compatibility with newer libsodium versions uncertain
- Migration plan: Upgrade to latest libsodium-sys while ensuring ABI compatibility

**Fuser FUSE library compatibility:**
- Risk: `fuser = 0.14` may not support latest FUSE kernel features or macFUSE versions
- Impact: Platform-specific issues on macOS; potential deadlock fixes missed
- Migration plan: Profile latest fuser versions; test on macOS with latest macFUSE

**Tokio full features for optional ninep:**
- Risk: `tokio = { version = "1", features = ["full"] }` pulls entire runtime even when feature not used
- Impact: Unnecessary dependency bloat for binary users not using 9P server
- Migration plan: Use feature flags to conditionally include tokio; only enable needed features

**Regex crate without SIMD acceleration:**
- Risk: Current regex dependency doesn't enable `regex-syntax` SIMD optimizations
- Impact: Pattern matching slower than optimal on large files
- Migration plan: Test regex performance; consider aho-corasick for marker scanning

## Missing Critical Features

**No integrated backup/recovery system:**
- Problem: Users must manually manage backup locations; no built-in backup strategy
- Blocks: Disaster recovery workflows; accidental key loss recovery
- Recommendations:
  1. Implement `sss backup` command for safe key/config backup
  2. Implement `sss restore` with integrity verification
  3. Document backup location best practices

**Incomplete secrets handling in agent:**
- Problem: Agent can authenticate but secrets interpolation not fully integrated
- Blocks: Remote agent workflows requiring secrets
- Recommendations:
  1. Implement secrets lookup in agent context
  2. Add secure secret transmission over agent protocol
  3. Document agent secret handling limitations

**No key rotation audit trail:**
- Problem: Rotation metadata stored but no detailed audit log of what was rotated
- Blocks: Compliance audits; forensic analysis
- Recommendations:
  1. Log each key rotation with before/after fingerprints
  2. Implement `sss audit key-history` command
  3. Add rotation reason tracking (currently optional)

## Test Coverage Gaps

**FUSE overlay mounting scenario:**
- What's not tested: In-place FUSE mounting with concurrent operations on both rendered and sealed files
- Files: `src/fuse_fs.rs`, `src/commands/mount.rs`
- Risk: Deadlock or inconsistency between paths; race conditions between FUSE and direct filesystem access
- Priority: High (core feature)

**Nested project key inheritance:**
- What's not tested: Nested projects with different keys; key resolution precedence; no_key_roots behavior
- Files: `src/fuse_fs.rs` (nested_processors, no_key_roots)
- Risk: Incorrect processor selected; secrets encrypted with wrong key
- Priority: High (data integrity)

**Large file encryption/decryption:**
- What's not tested: Files >100MB; memory usage under concurrent processing
- Files: `src/processor/core.rs`, `src/crypto.rs`
- Risk: OOM kills; performance degradation on real-world data
- Priority: Medium (scale requirement)

**KeyRing integration on different systems:**
- What's not tested: Linux (various distros with/without Secret Service), macOS Keychain, Windows Credential Manager fallback
- Files: `src/keyring_support.rs`, `src/keystore.rs`
- Risk: Silent fallback to unencrypted storage without user awareness
- Priority: Medium (security)

**Secrets file encryption/decryption roundtrip:**
- What's not tested: Encrypted .secrets files; nesting of secrets within encrypted content
- Files: `src/processor/core.rs` (process_secrets_file_content)
- Risk: Secrets exposure; incorrect decryption key usage
- Priority: High (security-critical)

**Marker parser edge cases:**
- What's not tested: Deeply nested braces (10+ levels); mixed marker types; UTF-8 edge cases in markers
- Files: `src/processor/marker_parser.rs`
- Risk: Parser bugs on unusual but valid input; potential DoS
- Priority: Medium (robustness)

**Error recovery in FUSE operations:**
- What's not tested: Partial write failures; interrupted file operations; corrupted cache recovery
- Files: `src/fuse_fs.rs` (write operations)
- Risk: File corruption; incomplete edits persisting
- Priority: High (data integrity)

---

*Concerns audit: 2026-02-21*
