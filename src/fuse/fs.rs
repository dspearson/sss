//! # SAFETY invariant (module-level)
//!
//! This module contains multiple `unsafe { libc::* }` blocks for FFI calls
//! (openat, faccessat, fstatat, open, close, read, write, opendir, fdopendir,
//! closedir, getuid, getgid). All are necessary for FUSE filesystem
//! implementation using fd-relative syscalls. See STRUCT-04 audit.
//!
//! All `unsafe { libc::* }` blocks in this module share the same SAFETY
//! invariant: the libc syscall is called with arguments validated by the
//! surrounding Rust code (file descriptors are non-negative i32 from
//! `open()`; buffer pointers are valid `&mut [u8]` of declared length;
//! flags are constructed from libc constants; return values are checked
//! for `-1` errno per the libc API contract for each syscall).
//!
//! This module is feature-gated behind `feature = "fuse"` and is NOT in
//! the default/hybrid clippy gate (`.github/workflows/ci-matrix.yml` does
//! not enable `feature = "fuse"`). REM-48 / MEM-15-001 (2026-06-10)
//! replaced the former `#![allow(clippy::undocumented_unsafe_blocks)]`
//! with `#![deny(clippy::undocumented_unsafe_blocks)]` — every executable
//! `unsafe { }` block now carries an inline `// SAFETY:` comment. The
//! universal libc invariant above is reused / condensed in each per-block
//! comment. A fuse-scoped CI grep-gate (`scripts/check-fuse-unsafe-safety.sh`)
//! enforces SAFETY comments on future additions.

// Why: REM-48 / MEM-15-001 (2026-06-10) reverses the 2026-05-18 Option-B blanket allow.
// Per-block SAFETY comments are now required; the ~70 existing per-block comments are
// preserved. The module rustdoc above (:1-23) documents the universal libc invariant
// reused in the per-block comments. A fuse-scoped CI grep-gate (scripts/check-fuse-unsafe-safety.sh)
// enforces SAFETY on any future unsafe blocks added under src/fuse/. fuse-gated, not in
// the default/hybrid clippy gate.
#![deny(clippy::undocumented_unsafe_blocks)]

use anyhow::{anyhow, Result};
use fuser::{
    FileAttr, FileType, Filesystem, ReplyAttr, ReplyData, ReplyDirectory, ReplyEntry, Request,
    ReplyWrite, ReplyOpen,
};
use globset::GlobSet;
use parking_lot::RwLock;
use std::collections::{HashMap, HashSet};
use std::ffi::{CString, OsStr};
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::FromRawFd;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;
#[cfg(feature = "vault")]
use zeroize::Zeroize;

/// Process-global monotonic counter for temp-file nonce generation (WR-01 / CON-07-001).
///
/// Combined with the process id and timestamp, this provides at least 64 bits of
/// uniqueness per temp path, eliminating the ~30-bit collision window from `subsec_nanos()`.
static TEMP_NONCE_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Decrypted plaintext content buffer — volatile-zeroed on drop via [`Zeroizing`].
///
/// Used for `render_cache` entries and `FileHandle::cached_content` so that
/// decrypted secret-file bytes are overwritten in memory when evicted or when
/// the handle drops (REM-15 / CON-05-001).
type PlaintextBuf = Zeroizing<Vec<u8>>;

/// RAII guard that unlinks a plaintext temp file on drop.
///
/// Prevents orphaned plaintext temps on panic, error return, or signal that
/// unwinds the stack.  Arm the guard immediately after the temp path is known;
/// disarm it (`guard.active = false`) only after a successful `renameat`.
///
/// # Lifetime invariant
///
/// This struct must only be constructed inside `write_via_fd_atomic`, which
/// borrows `&self` (i.e. `&SssFS`).  That borrow prevents `SssFS` — and
/// therefore `source_fd` — from being dropped while the guard is live.  The
/// guard therefore always drops before `source_fd` is closed, keeping the fd
/// valid for the `unlinkat` call in `Drop`.
struct TempFileGuard {
    /// Parent directory fd (copy of `SssFS::source_fd`; see lifetime invariant above).
    dir_fd: libc::c_int,
    /// Relative path `CString` passed to `unlinkat`.
    path_cstr: std::ffi::CString,
    /// When `true` the guard is *armed*: `Drop` will call `unlinkat`.
    /// Set to `false` after a successful `renameat` to *disarm* the guard.
    active: bool,
}

impl Drop for TempFileGuard {
    fn drop(&mut self) {
        if self.active {
            // SAFETY: `dir_fd` is a valid open directory fd (see lifetime invariant on the
            // struct).  `path_cstr` is NUL-terminated.  `unlinkat` is best-effort cleanup;
            // ignoring the return value is intentional — if the file was already renamed or
            // removed the unlink simply fails, which is correct.
            unsafe {
                libc::unlinkat(self.dir_fd, self.path_cstr.as_ptr(), 0);
            }
        }
    }
}

use crate::filesystem_common::{has_encrypted_markers, has_any_markers, has_any_markers_bytes};
use crate::project::ProjectConfig;
use crate::secrets::{FileSystemOps, SecretsCache, interpolate_secrets};
use crate::Processor;

/// Debug logging macro for FUSE operations. Enabled by setting SSS_FUSE_DEBUG=1.
/// Includes thread ID and PID for diagnosing deadlocks and concurrency issues.
macro_rules! fuse_debug {
    ($($arg:tt)*) => {
        if FUSE_DEBUG.load(std::sync::atomic::Ordering::Relaxed) {
            let thread_id = std::thread::current().id();
            let pid = std::process::id();
            eprintln!("[FUSE DEBUG {:?} PID:{}] {}", thread_id, pid, format!($($arg)*));
        }
    };
}

/// Global flag checked by fuse_debug! — set once from SSS_FUSE_DEBUG env var.
static FUSE_DEBUG: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Initialise the debug flag from the environment. Call once at startup.
fn init_fuse_debug() {
    if std::env::var("SSS_FUSE_DEBUG").map_or(false, |v| v == "1" || v.eq_ignore_ascii_case("true")) {
        FUSE_DEBUG.store(true, std::sync::atomic::Ordering::Relaxed);
    }
}

/// Predicate: do RAW backing-store bytes contain at least one Vault reference
/// (`⊳{…}` or its ASCII alias `>{…}`)?
///
/// This is the unit-testable core of [`SssFS::file_has_vault_refs`]: it runs the
/// non-feature-gated [`VAULT_INTERPOLATION_REGEX`](crate::vault::resolver::VAULT_INTERPOLATION_REGEX)
/// over the bytes EXACTLY as they sit on the backing store — never over decrypted
/// or rendered output (49-RESEARCH.md anti-pattern: scanning plaintext would both
/// miss the marker after a render and risk touching resolved secret values).
///
/// `from_utf8_lossy` is deliberate: a binary backing file must NOT allocate-fail;
/// it simply yields no match (the `⊳`/`>` markers are ASCII-anchored, so lossy
/// replacement of non-UTF-8 bytes elsewhere cannot manufacture a false positive).
///
/// Defined unconditionally (the regex is always compiled per VREF-01) so the
/// detection logic is unit-testable on every build without a live mount.
// Why: kept NON-gated by design (VREF-01: the regex is always available; the
// predicate must be unit-testable on every build). Its production callers
// (`file_has_vault_refs`, `apply_vault_pass`) are `#[cfg(feature = "vault")]`,
// so on a `fuse`-without-`vault` build nothing calls it — dead_code there is
// expected and intentional, not a missing wiring.
#[allow(dead_code)]
fn bytes_have_vault_refs(bytes: &[u8]) -> bool {
    let as_str = String::from_utf8_lossy(bytes);
    crate::vault::resolver::VAULT_INTERPOLATION_REGEX.is_match(as_str.as_ref())
}

/// Should `open()` BYPASS the open-time precache for this file?
///
/// Pure decision predicate (unit-testable without a live mount). The open-time
/// precache (`precache_for_open`) is skipped for:
/// - passthrough files (raw access, never rendered); and
/// - vault-backed files — so each `read()` re-drives `read_and_render` → a fresh
///   `VaultRequestCache` → a fresh Vault fetch. Caching a vault-backed file would
///   serve stale plaintext on the second read and violate SC3 (research risk 2).
const fn should_skip_precache(is_passthrough: bool, vault_backed: bool) -> bool {
    is_passthrough || vault_backed
}

/// Should `open()` set `FOPEN_DIRECT_IO` (bypass the kernel page cache) for this
/// inode?
///
/// Pure decision predicate (unit-testable without a live mount). `direct_io` is set
/// per-inode (NOT mount-level — R2) for:
/// - passthrough writable files (mmap writes must route through our handlers); and
/// - vault-backed files (resolved secrets must not linger in the page cache after
///   close — VMNT-04).
const fn should_set_direct_io(is_passthrough: bool, writable: bool, vault_backed: bool) -> bool {
    (is_passthrough && writable) || vault_backed
}

/// Pure freshness decision behind `mount_token_needs_refresh` / the WR-03
/// single-flight re-check: does the mount token need a (re-)auth?
///
/// `true` when the token is ABSENT, OR when the lease reports a REAL near-expiry
/// TTL (`0 < ttl_secs <= near_expiry_secs`). A `0` / `None` TTL is "unknown but
/// usable" — we do NOT auth on every read just because Vault returned no TTL; an
/// on-demand renewal still fires once a genuine near-expiry TTL is observed.
///
/// Pure (unit-testable without a live mount); the method peeks the token/lease
/// guards and forwards the booleans/TTL here.
#[cfg(feature = "vault")]
const fn mount_token_refresh_decision(
    token_present: bool,
    lease_ttl_secs: Option<u64>,
    near_expiry_secs: u64,
) -> bool {
    if !token_present {
        return true;
    }
    match lease_ttl_secs {
        Some(ttl) => ttl > 0 && ttl <= near_expiry_secs,
        None => false,
    }
}

/// Should the synthetic `.sss` control directory be injected at ROOT?
///
/// Pure decision predicate (unit-testable without a live mount). The synthetic
/// `.sss`/`vault-status` surface is best-effort and MUST yield to real user data:
/// inject it ONLY when there is no real `.sss` entry in the backing root (WR-02).
/// When a real `.sss` exists it wins — served normally in both `lookup` and
/// `readdir` — and the synthetic vault-status surface is simply unavailable.
#[cfg(feature = "vault")]
const fn should_inject_synthetic_sss(real_sss_present: bool) -> bool {
    !real_sss_present
}

/// Should `compute_size_override` RENDER-AND-CACHE this file's resolved content
/// into `render_cache` to report an accurate (post-render) size?
///
/// Pure decision predicate (unit-testable without a live mount). `getattr`/`lookup`
/// eagerly render marked files so the reported size matches the rendered byte length.
/// For a VAULT-BACKED file this is unsafe: caching the resolved plaintext retains
/// resolved Vault secrets in userspace memory for the unbounded `getattr`→`release`
/// window (WR-01 / SC3 / VMNT-03: "never retain resolved secrets"). Such files are
/// `FOPEN_DIRECT_IO`, so the kernel re-reads via `read()` → `read_and_render` and does
/// NOT trust a stale size — reporting the on-disk byte count is an acceptable
/// approximation. So: cache only when the file has NO vault refs.
const fn should_cache_rendered_size(has_vault_refs: bool) -> bool {
    !has_vault_refs
}

const TTL: Duration = Duration::from_secs(1);
const TTL_ZERO: Duration = Duration::from_secs(0);  // No caching for passthrough files
const ROOT_INO: u64 = 1;

// Synthetic inodes for virtual files
const SYNTHETIC_OVERLAY_DIR_INO: u64 = u64::MAX - 1;  // Passthrough directory with raw filesystem access
/// Synthetic directory: `<mnt>/.sss/` — virtual control directory (vault-gated).
#[cfg(feature = "vault")]
const SYNTHETIC_SSS_DIR_INO: u64 = u64::MAX - 2;
/// Synthetic file: `<mnt>/.sss/vault-status` — value-free key:value vault status report (vault-gated).
#[cfg(feature = "vault")]
const SYNTHETIC_VAULT_STATUS_INO: u64 = u64::MAX - 3;

// Custom ioctl command for ssse edit to request opened mode (with ⊕{} markers)
// Only used on Linux - macOS/fuse-t doesn't support ioctl
#[cfg(not(target_os = "macos"))]
const SSS_IOC_OPENED_MODE: u32 = 0x5353_0001; // 'SS' magic + command 1
#[cfg(not(target_os = "macos"))]
const SSS_IOC_SEALED_MODE: u32 = 0x5353_0002; // 'SS' magic + command 2 - request sealed content (requires O_NONBLOCK)

/// Inode information
#[derive(Clone)]
struct InodeEntry {
    _ino: u64,
    path: PathBuf,
    parent: u64,
}

/// File access mode for virtual paths
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FileMode {
    /// Normal access: fully rendered (no markers)
    Rendered,
    /// .sss-opened: opened with ⊕{} markers for editing
    Opened,
    /// .sss-sealed: raw sealed content with ⊠{} markers from backing store
    Sealed,
}

/// File handle for tracking open files
struct FileHandle {
    ino: u64,
    path: PathBuf,
    /// Cached content (rendered or original) — volatile-zeroed on drop (REM-15)
    cached_content: Option<PlaintextBuf>,
    /// Whether the file is open for writing
    writable: bool,
    /// Dirty flag for writes
    dirty: bool,
    /// Opened mode: return content with ⊕{} markers (for ssse edit)
    opened_mode: bool,
    /// Sealed mode: return raw sealed content with ⊠{} markers (signaled by O_NONBLOCK)
    sealed_mode: bool,
    /// Origin mode: file is under .overlay/ - raw passthrough with no processing
    origin_mode: bool,
    /// File descriptor for passthrough files (kept open for lifetime of handle)
    passthrough_fd: Option<i32>,
    /// Original sealed content from backing store (captured at open time for writable files)
    /// Used for smart reconstruction when editor truncates file before writing
    original_sealed: Option<String>,
}

/// File operations strategy - defines how files are displayed and filtered
trait FileOperations: Send + Sync {
    /// Should this file be hidden from directory listings?
    fn should_hide(&self, name: &str) -> bool;
}

/// SSS operations - renders ⊠{} to plaintext on read, seals to ⊠{} on write
struct SssOperations {}

impl FileOperations for SssOperations {
    fn should_hide(&self, name: &str) -> bool {
        matches!(
            name,
            ".git" | ".gitignore" | ".gitattributes" | ".gitmodules"
        )
    }
}

/// Passthrough operations - raw read/write with no SSS processing
struct PassthroughOperations {}

impl FileOperations for PassthroughOperations {
    fn should_hide(&self, _name: &str) -> bool {
        false  // Show everything including .git
    }
}

/// Pinned path - maps a virtual prefix to source path with specific operations
struct PinnedPath {
    /// Virtual mount point (e.g., "/", "/.overlay")
    virtual_prefix: PathBuf,

    /// Corresponding source path (e.g., "/", "/")
    source_path: PathBuf,

    /// Operations for files under this path
    operations: std::sync::Arc<dyn FileOperations>,
}

/// FUSE filesystem for transparent encryption/decryption of sss-managed files.
///
/// `SssFS` provides a FUSE-based virtual filesystem that transparently renders
/// encrypted content on read and seals (encrypts) content on write. It supports:
///
/// - **Transparent rendering**: Files with `⊠{...}` markers are automatically decrypted
/// - **Virtual files**: `.sss-opened` suffix provides content with `⊕{...}` markers for editing
/// - **Sealed mode**: Two-factor protocol (O_NONBLOCK + fsetxattr) for raw sealed access
/// - **Overlay mounting**: Can mount over source directory while preserving file access
/// - **Smart reconstruction**: Preserves encryption structure when writing edited files
///
/// # Architecture
///
/// - Uses file descriptors for all operations to support overlay mounting
/// - Maintains bidirectional inode mapping for stable file identity
/// - Caches rendered content per inode for performance
/// - Hides git-related files (`.git/`, `.gitignore`, etc.) from FUSE view
///
/// # Thread Safety
///
/// All internal state (inode tables, file handles, caches) uses `RwLock` for
/// thread-safe concurrent access required by FUSE.
///
/// # Lock Order
///
/// To prevent deadlocks, `RwLock` fields in this struct MUST be acquired in the
/// following total order whenever more than one lock is needed in the same call frame:
///
/// 1. `inode_table` / `path_to_ino` / `next_ino`  (inode metadata tier)
/// 2. `file_handles` / `next_fh`                   (open handle tier)
/// 3. `render_cache`                               (content cache tier)
/// 4. `secrets_cache`                              (secrets interpolation tier)
///
/// **Vault tier (Phase 49, pitfall 5):** the mount-level Vault token/lease live
/// in `vault_state` behind their OWN independent `parking_lot::Mutex`es — they are
/// NOT part of the `RwLock` total order above. The invariant is that a `vault_state`
/// token/lease `Mutex` is NEVER held across a `secrets_cache` acquisition (and vice
/// versa): the token guard is taken, copied/checked, and dropped before any
/// `interpolate_secrets` call that acquires `secrets_cache`. The per-read
/// `VaultRequestCache` is a stack local that holds no `SssFS` lock at all.
///
/// **Rules:**
/// - Never acquire a lower-numbered tier lock while holding a higher-numbered tier lock.
/// - Never hold two locks from the same tier simultaneously.
/// - Temporary guards such as `self.render_cache.write().remove(...)` drop at the
///   statement boundary (end of the `;`) and do **not** count as "held" across any
///   subsequent lock acquire on the same or any other tier.
///
/// **Verified acquisition paths (static analysis 2026-06-09, CON-19):**
/// - `compute_size_override`: `file_handles.read()` → explicit `drop()` →
///   `render_cache.read()` / `render_cache.write()` — strictly sequential, never nested.
/// - `release`: `file_handles.write()` → handle removed → `render_cache.write()` as a
///   temporary guard that drops at the `;` — sequential, not nested.
/// - `setattr`: `render_cache.write().remove(...)` (temporary, drops at `;`) → then
///   `file_handles.write()` — the apparent reversal is sequential because the
///   `render_cache` guard drops before `file_handles` is acquired.
/// - `read` / `write` / `ioctl` callbacks: `file_handles` only; `render_cache` not touched.
///
/// **Conclusion:** No two of these locks are ever held simultaneously in any code path.
/// No inversion exists; no deadlock cycle is possible under the current acquisition pattern.
///
/// **LOOM NOTE:** `parking_lot::RwLock` is not loom-instrumented (`parking_lot` 0.12 has no
/// `cfg(loom)` feature and does not delegate to `std::sync`). This static analysis is the
/// documented verification for CON-19. Re-evaluate if the lock set grows or if
/// `parking_lot` is replaced with a loom-compatible primitive.
/// Mount-level Vault state carried by [`SssFS`] (Phase 49, VMNT-01/05).
///
/// Holds everything the read path (49-02) and the `vault-status` control file
/// (49-03) need to drive Vault resolution WITHOUT retaining any resolved
/// plaintext: the signed [`VaultConfig`](crate::project::VaultConfig) behind an
/// `Arc` (so the borrow-checked `VaultResolver<'a>` lifetime never has to be
/// `'static`; research risk 1 / pitfall 3), the `SecretsCache` + the two paths
/// `VaultResolver::new` needs, the long-lived bootstrap token + lease (each under
/// its own independent `Mutex` per pitfall 5), and the three mount-flag booleans.
///
/// The token is the ONLY secret-bearing field; it is held in
/// [`Zeroizing`] and wiped both on `Mutex`-guard drop and again by the explicit
/// [`Drop`] impl at unmount (Open Question 3). No resolved reference value is ever
/// stored here — that would violate SC3 (every read re-fetches).
// Why: 49-01 lands the struct + carrier fields (keep_unresolved/lazy/no_vault/
// auth_method/binding_count) WITH the SssFS field that owns them — the post-merge
// orphan-commit gate forbids splitting a def from its owner. The read path (49-02)
// and vault-status file (49-03) are the consumers, so these fields are
// write-in-this-wave / read-in-the-next; dead_code is expected until 49-02 lands.
#[cfg(feature = "vault")]
#[allow(dead_code)]
pub(crate) struct VaultMountState {
    /// Signed `[vault]` config, `Arc`-shared so a `VaultResolver` can be
    /// reconstructed per-need without leaking a `'static` lifetime into Phase-47
    /// code (research risk 1).
    config: std::sync::Arc<crate::project::VaultConfig>,
    /// Secrets cache used to resolve the bootstrap credential / pinned CA.
    secrets_cache: crate::secrets::SecretsCache,
    /// `file_path` anchor passed to `VaultResolver::new` (`project_root/.sss.toml`).
    secrets_anchor: std::path::PathBuf,
    /// Project root passed to `VaultResolver::new`.
    project_root: std::path::PathBuf,
    /// Long-lived mount bootstrap token (`None` until eager auth / first lazy
    /// read). Independent tier (pitfall 5); zeroised on drop.
    token: parking_lot::Mutex<Option<zeroize::Zeroizing<String>>>,
    /// Lease (TTL + renewability) for `token`; value-free. Independent tier.
    lease: parking_lot::Mutex<Option<crate::vault::auth::AuthLease>>,
    /// WR-03 single-flight auth gate. FUSE callbacks are dispatched concurrently
    /// by the kernel, so `ensure_mount_token`'s check-then-auth-then-store was a
    /// race: two threads could both observe "needs auth", both `bootstrap_auth`,
    /// and mint two tokens — exhausting a single-use `AppRole` secret-id on first
    /// `--vault-lazy` read. This dedicated lock serialises the WHOLE freshness
    /// check + network auth + store so exactly ONE login happens per refresh; a
    /// thread that waited on it re-checks freshness and reuses the just-minted
    /// token. Held ONLY across auth — never the token/lease value guards (those
    /// are acquired/released for the freshness peek and again for the store, so
    /// the value `Mutex` never spans the network call; pitfall 5 preserved). This
    /// makes `--vault-lazy` safe with single-use `AppRole` secret-ids.
    auth_lock: parking_lot::Mutex<()>,
    /// `--keep-unresolved`: on a per-ref miss serve the `⊳{}` marker verbatim.
    keep_unresolved: bool,
    /// `--vault-lazy`: defer bootstrap auth to first read.
    lazy: bool,
    /// `--no-vault` / no `[vault]` table: Vault is a complete no-op for this mount.
    no_vault: bool,
    /// Auth method label for the `vault-status` file (`"approle"` / `"token"` /
    /// `"none"`); value-free.
    auth_method: String,
    /// Configured binding count for the `vault-status` file; value-free.
    binding_count: usize,
}

#[cfg(feature = "vault")]
// Why: `lazy` / `with_token` are consumed by the Task-3 bootstrap block in this
// same plan; `reconstruct_resolver` + `auth_method_label` are consumed by the
// read path (49-02) and vault-status file (49-03). They are landed here with the
// struct they belong to (orphan-commit gate); dead_code is expected pre-49-02.
#[allow(dead_code)]
impl VaultMountState {
    /// Vault-disabled state: used for `--no-vault` AND for repos with no `[vault]`
    /// table. No token, no auth, markers left literal.
    pub(crate) fn disabled() -> Self {
        Self {
            config: std::sync::Arc::new(crate::project::VaultConfig::default()),
            secrets_cache: crate::secrets::SecretsCache::new(),
            secrets_anchor: std::path::PathBuf::new(),
            project_root: std::path::PathBuf::new(),
            token: parking_lot::Mutex::new(None),
            lease: parking_lot::Mutex::new(None),
            auth_lock: parking_lot::Mutex::new(()),
            keep_unresolved: false,
            lazy: false,
            no_vault: true,
            auth_method: "none".to_string(),
            binding_count: 0,
        }
    }

    /// Lazy state: sig-verified at mount, but bootstrap auth deferred to first
    /// read (`--vault-lazy`). No token is held yet.
    pub(crate) fn lazy(
        config: std::sync::Arc<crate::project::VaultConfig>,
        secrets_cache: crate::secrets::SecretsCache,
        secrets_anchor: std::path::PathBuf,
        project_root: std::path::PathBuf,
        keep_unresolved: bool,
    ) -> Self {
        let auth_method = Self::auth_method_label(&config);
        let binding_count = config.bindings.len();
        Self {
            config,
            secrets_cache,
            secrets_anchor,
            project_root,
            token: parking_lot::Mutex::new(None),
            lease: parking_lot::Mutex::new(None),
            auth_lock: parking_lot::Mutex::new(()),
            keep_unresolved,
            lazy: true,
            no_vault: false,
            auth_method,
            binding_count,
        }
    }

    /// Eager state: sig-verified AND bootstrap-authenticated at mount. The
    /// long-lived `token` + `lease` were drained out of the boot
    /// `VaultRequestCache` by the caller and are stored here for reuse across
    /// reads.
    pub(crate) fn with_token(
        config: std::sync::Arc<crate::project::VaultConfig>,
        secrets_cache: crate::secrets::SecretsCache,
        secrets_anchor: std::path::PathBuf,
        project_root: std::path::PathBuf,
        token: Option<zeroize::Zeroizing<String>>,
        lease: Option<crate::vault::auth::AuthLease>,
        keep_unresolved: bool,
    ) -> Self {
        let auth_method = Self::auth_method_label(&config);
        let binding_count = config.bindings.len();
        Self {
            config,
            secrets_cache,
            secrets_anchor,
            project_root,
            token: parking_lot::Mutex::new(token),
            lease: parking_lot::Mutex::new(lease),
            auth_lock: parking_lot::Mutex::new(()),
            keep_unresolved,
            lazy: false,
            no_vault: false,
            auth_method,
            binding_count,
        }
    }

    /// Value-free auth-method label for `vault-status` (`config.auth.method`,
    /// defaulting to `"none"`).
    fn auth_method_label(config: &crate::project::VaultConfig) -> String {
        config
            .auth
            .as_ref()
            .and_then(|a| a.method.clone())
            .unwrap_or_else(|| "none".to_string())
    }

    /// Reconstruct a request-scoped [`VaultResolver`] borrowing the `Arc`-held
    /// config. This is the per-need reconstruction that sidesteps the `'static`
    /// lifetime tangle (research risk 1): `VaultResolver::new` only builds a
    /// `VaultClient`, so it is cheap to call per read.
    ///
    /// # Errors
    ///
    /// Propagates [`VaultResolveError`](crate::vault::resolver::VaultResolveError)
    /// from `VaultResolver::new` (exit-4 conditions: absent address, CA secret
    /// resolution failure, client construction failure).
    pub(crate) fn reconstruct_resolver(
        &self,
    ) -> Result<crate::vault::resolver::VaultResolver<'_>, crate::vault::resolver::VaultResolveError>
    {
        crate::vault::resolver::VaultResolver::new(
            self.config.as_ref(),
            self.secrets_cache.clone(),
            &self.secrets_anchor,
            &self.project_root,
        )
    }
}

#[cfg(feature = "vault")]
impl Drop for VaultMountState {
    fn drop(&mut self) {
        // The Zeroizing<String> token already wipes on its own drop; this explicit
        // Drop documents intent (Open Question 3) and guarantees the mount-level
        // token buffer is cleared the instant the filesystem object is torn down
        // at unmount, rather than relying solely on field-drop ordering. The
        // zeroize crate implements `Zeroize for Option<Z>`, so this wipes the inner
        // Zeroizing<String> buffer and leaves the Option in None.
        self.token.lock().zeroize();
        *self.lease.lock() = None;
    }
}

/// Free-function core of the `vault-status` content generator — unit-testable without
/// a full [`SssFS`] instance (the method is a thin delegator to here).
///
/// NEVER prints a secret value: `token_present` is a boolean, `token_ttl_secs` is a
/// bare integer, `auth_method` and `binding_count` come from the value-free fields
/// set during mount-time config parsing. (VMNT-03/04 Information-Disclosure mitigation.)
#[cfg(feature = "vault")]
fn vault_status_content_from_state(vs: &VaultMountState) -> String {
    let token_present = vs.token.lock().is_some();
    let ttl = vs.lease.lock()
        .as_ref()
        .map_or_else(|| "unknown".to_string(), |l| l.ttl_secs.to_string());
    format!(
        "auth_method: {auth}\n\
         token_present: {present}\n\
         token_ttl_secs: {ttl}\n\
         binding_count: {bindings}\n\
         lockfile_drift: unknown (run `sss vault verify` for an authoritative check)\n\
         no_vault: {no_vault}\n\
         vault_lazy: {lazy}\n\
         keep_unresolved: {keep}\n",
        auth     = vs.auth_method,
        present  = token_present,
        ttl      = ttl,
        bindings = vs.binding_count,
        no_vault = vs.no_vault,
        lazy     = vs.lazy,
        keep     = vs.keep_unresolved,
    )
}

pub struct SssFS {
    /// Path to the real directory being mirrored
    source_path: PathBuf,
    /// File descriptor to source directory (kept open to access files even if mounted over)
    source_fd: std::os::unix::io::RawFd,
    /// File descriptor to mount point directory (held open before mount for /proc access)
    /// Allows accessing the underlying directory via /proc/self/fd/<mount_fd> even after FUSE mount
    mount_fd: Option<std::os::unix::io::RawFd>,
    /// Processor for encryption/decryption operations
    processor: Processor,
    /// Secrets cache for finding and loading .secrets files
    secrets_cache: RwLock<SecretsCache>,
    /// Inode table: maps inode number to path information
    inode_table: RwLock<HashMap<u64, InodeEntry>>,
    /// Reverse lookup: path to inode number
    path_to_ino: RwLock<HashMap<PathBuf, u64>>,
    /// Next available inode number (atomic counter)
    next_ino: RwLock<u64>,
    /// Open file handles with cached content and mode flags
    file_handles: RwLock<HashMap<u64, FileHandle>>,
    /// Next available file handle ID (atomic counter)
    next_fh: RwLock<u64>,
    /// Cache of rendered file contents (inode → decrypted bytes), volatile-zeroed on eviction (REM-15)
    render_cache: RwLock<HashMap<u64, PlaintextBuf>>,
    /// Pinned virtual paths with their operations
    pinned_paths: Vec<PinnedPath>,
    /// Processors for nested projects (rel_path from source → Processor)
    nested_processors: HashMap<PathBuf, Processor>,
    /// Relative paths of nested projects where we have no matching keys
    no_key_roots: HashSet<PathBuf>,
    /// Ignore patterns from root project config (positive matches → skip processing)
    ignore_patterns: Option<GlobSet>,
    /// Negation patterns from root project config (overrides ignore)
    negation_patterns: Option<GlobSet>,
    /// Per-nested-project ignore patterns (rel_path → (positive, negation))
    nested_ignore: HashMap<PathBuf, (GlobSet, GlobSet)>,
    /// Mount-level Vault state (token/lease/flags/config); see [`VaultMountState`].
    /// Its token/lease `Mutex`es are an independent lock tier (pitfall 5) — see the
    /// `SssFS` lock-order doc. Built fully-formed by `handle_mount` and moved in.
    // Why: stored in 49-01 (this wave) but first READ by the read_and_render vault
    // pass in 49-02. The field must land with the struct now (orphan-commit gate);
    // dead_code is expected until 49-02 wires the reader.
    #[cfg(feature = "vault")]
    #[allow(dead_code)]
    vault_state: VaultMountState,
}

/// FD-based filesystem operations for FUSE in-place mounts
///
/// When FUSE is mounted over the source directory, normal filesystem operations
/// like .exists() and fs::read() will route back through the FUSE mount, causing
/// deadlock. This implementation uses fd-based operations (openat, faccessat) with
/// source_fd to access the real filesystem underneath the mount.
///
/// IMPORTANT: All paths MUST be relative to source_fd. Absolute paths are
/// automatically relativised by stripping `source_path` to prevent deadlocks
/// when faccessat/openat would otherwise resolve through the FUSE mount.
struct FdFileSystemOps {
    source_fd: std::os::unix::io::RawFd,
    source_path: PathBuf,
}

impl FdFileSystemOps {
    /// Convert a path to be relative to source_fd.
    /// Absolute paths starting with source_path are stripped; other absolute
    /// paths are returned as-is (openat will resolve them through VFS).
    fn relativise<'a>(&self, path: &'a Path) -> &'a Path {
        if path.is_absolute() {
            path.strip_prefix(&self.source_path).unwrap_or(path)
        } else {
            path
        }
    }
}

impl FileSystemOps for FdFileSystemOps {
    fn file_exists(&self, path: &Path) -> bool {
        let rel = self.relativise(path);
        let path_bytes = rel.as_os_str().as_bytes();
        let path_cstr = match std::ffi::CString::new(path_bytes) {
            Ok(p) => p,
            Err(_) => return false,
        };

        // SAFETY: `self.source_fd` is a valid open directory fd obtained in `new()`.
        // `path_cstr` is a valid NUL-terminated C string derived from a Rust Path.
        // `faccessat` does not retain the pointer after returning.
        let result = unsafe {
            libc::faccessat(
                self.source_fd,
                path_cstr.as_ptr(),
                libc::F_OK,
                0,
            )
        };

        result == 0
    }

    fn read_file(&self, path: &Path) -> Result<Vec<u8>> {
        let rel = self.relativise(path);
        let path_bytes = rel.as_os_str().as_bytes();
        let path_cstr = std::ffi::CString::new(path_bytes)?;

        // SAFETY: `self.source_fd` is a valid open directory fd. `path_cstr` is a valid
        // NUL-terminated path. `openat` returns a new fd or -1 on error.
        // O_CLOEXEC: prevents this fd from being inherited by child processes (REM-17 / CR-01).
        let fd = unsafe {
            libc::openat(self.source_fd, path_cstr.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC)
        };

        if fd < 0 {
            return Err(anyhow!("Failed to open file {:?}", path));
        }

        // Read file contents
        // SAFETY: `fd` is a valid file descriptor returned by `openat` above (fd >= 0).
        // `File::from_raw_fd` takes ownership; `mem::forget` prevents double-close since
        // we close `fd` manually below after reading.
        let mut file = unsafe { fs::File::from_raw_fd(fd) };
        let mut contents = Vec::new();
        std::io::Read::read_to_end(&mut file, &mut contents)?;
        std::mem::forget(file); // Don't close fd automatically

        // Close fd manually
        // SAFETY: `fd` was opened above, `mem::forget` on `file` means it was not closed.
        unsafe { libc::close(fd); }

        Ok(contents)
    }
}

impl SssFS {
    /// Creates a new FUSE filesystem for transparent sss encryption/decryption.
    ///
    /// # Arguments
    ///
    /// * `source_path` - Path to the directory containing files to be transparently processed
    /// * `processor` - Configured [`Processor`] instance for encryption/decryption operations
    /// * `mount_path` - Optional path to the mount point directory. If provided, a file descriptor
    ///   will be held open to this directory, allowing access via /proc/self/fd/<fd>
    ///   even after the FUSE filesystem is mounted over it.
    ///
    /// # Returns
    ///
    /// Returns `Ok(SssFS)` if successful, or an error if:
    /// - The source path doesn't exist
    /// - The source path is not a directory
    /// - The source directory cannot be opened (permission denied, etc.)
    /// - The mount path (if provided) cannot be opened
    ///
    /// # Examples
    ///
    /// On `--features vault` builds the constructor takes an additional trailing
    /// `vault_state: VaultMountState` argument (an internal, `pub(crate)` type),
    /// so this example is `ignore`d rather than compiled — it documents the
    /// non-vault shape only.
    ///
    /// ```ignore
    /// # use sss::fuse::fs::SssFS;
    /// # use sss::{Processor, RepositoryKey};
    /// # use std::path::PathBuf;
    /// # fn example() -> anyhow::Result<()> {
    /// let source = PathBuf::from("/path/to/project");
    /// let mount = PathBuf::from("/mnt/project");
    /// let key = RepositoryKey::new();
    /// let processor = Processor::new(key)?;
    /// // Hold fd to mount point for /proc access
    /// let fs = SssFS::new(source, processor, Some(mount), None)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(source_path: PathBuf, processor: Processor, mount_path: Option<PathBuf>,
               config: Option<&ProjectConfig>,
               #[cfg(feature = "vault")] vault_state: VaultMountState) -> Result<Self> {
        init_fuse_debug();
        fuse_debug!("SssFS::new source={:?} mount={:?}", source_path, mount_path);

        if !source_path.exists() {
            return Err(anyhow!("Source path does not exist: {:?}", source_path));
        }

        if !source_path.is_dir() {
            return Err(anyhow!("Source path is not a directory: {:?}", source_path));
        }

        // Open a file descriptor to the source directory before mounting
        // This allows us to access files even if we mount over the source location
        let source_path_str = source_path
            .to_str()
            .ok_or_else(|| anyhow!("Source path is not valid UTF-8: {:?}", source_path))?;
        // SAFETY: `source_path` was verified to exist and be a directory above.
        // `source_path_str` is a valid UTF-8 string (checked above); `CString::new` produces
        // a NUL-terminated C string. The returned fd is checked for -1 immediately.
        let source_fd = unsafe {
            let path_cstr = std::ffi::CString::new(source_path_str)?;
            libc::open(path_cstr.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC)
        };

        if source_fd < 0 {
            return Err(anyhow!(
                "Failed to open source directory: {}",
                std::io::Error::last_os_error()
            ));
        }

        // Open a file descriptor to the mount point directory if provided
        // This allows accessing the underlying directory via /proc/self/fd/<mount_fd>
        // even after the FUSE filesystem is mounted over it
        //
        // We use O_PATH which is perfect for this purpose:
        // - Obtains a fd that can be used with /proc/PID/fd/N access
        // - Allows full read/write operations through the /proc path
        // - The actual permissions are determined by the directory's mode and user's access
        let mount_fd = if let Some(ref mount_path) = mount_path {
            let mount_path_str = mount_path
                .to_str()
                .ok_or_else(|| anyhow!("Mount path is not valid UTF-8: {:?}", mount_path))?;
            // SAFETY: `mount_path` exists (checked by caller). `mount_path_str` is valid UTF-8
            // (checked above); `CString::new` produces a NUL-terminated C string. The fd is
            // checked for -1 immediately after the block. Flags are libc constants.
            let fd = unsafe {
                let path_cstr = std::ffi::CString::new(mount_path_str)?;
                // O_PATH | O_DIRECTORY: path-based fd for directory access via /proc
                // macOS doesn't have O_PATH, use O_RDONLY | O_DIRECTORY instead
                // O_CLOEXEC: prevent inheritance across exec (REM-17 / CON-14)
                #[cfg(target_os = "linux")]
                let flags = libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC;
                #[cfg(target_os = "macos")]
                let flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC;
                libc::open(path_cstr.as_ptr(), flags)
            };

            if fd < 0 {
                // Clean up source_fd before returning error
                // SAFETY: `source_fd` is valid (checked above, fd >= 0); closing it here
                // because we are about to return an error without storing it in `self`.
                unsafe { libc::close(source_fd); }
                return Err(anyhow!(
                    "Failed to open mount point directory: {}",
                    std::io::Error::last_os_error()
                ));
            }

            Some(fd)
        } else {
            None
        };

        let mut inode_table = HashMap::new();
        let mut path_to_ino = HashMap::new();

        // Initialize root inode
        let root_entry = InodeEntry {
            _ino: ROOT_INO,
            path: PathBuf::from("/"),
            parent: ROOT_INO,
        };
        inode_table.insert(ROOT_INO, root_entry.clone());
        path_to_ino.insert(PathBuf::from("/"), ROOT_INO);

        // Initialize pinned paths - order matters! More specific prefixes first
        let pinned_paths = vec![
            // .overlay/ - passthrough to root with no SSS processing
            PinnedPath {
                virtual_prefix: PathBuf::from("/.overlay"),
                source_path: PathBuf::from("/"),
                operations: std::sync::Arc::new(PassthroughOperations {}),
            },
            // Root - normal SSS operations (render/seal)
            PinnedPath {
                virtual_prefix: PathBuf::from("/"),
                source_path: PathBuf::from("/"),
                operations: std::sync::Arc::new(SssOperations {}),
            },
        ];

        // Create secrets cache from processor configuration
        let secrets_cache = processor.get_secrets_cache().clone();

        // Parse root project ignore patterns from config
        let (ignore_patterns, negation_patterns) = if let Some(cfg) = config {
            let (pos, neg) = cfg.parse_ignore_patterns()?;
            (
                if pos.is_empty() { None } else { Some(pos) },
                if neg.is_empty() { None } else { Some(neg) },
            )
        } else {
            (None, None)
        };

        // Scan for nested projects (subdirectories with their own .sss.toml)
        let mut nested_processors = HashMap::new();
        let mut no_key_roots = HashSet::new();
        let mut nested_ignore = HashMap::new();

        for entry in walkdir::WalkDir::new(&source_path)
            .follow_links(false)
            .into_iter()
            .filter_entry(|e| {
                let name = e.file_name().to_string_lossy();
                if name.starts_with('.') { return false; }
                if e.file_type().is_dir() {
                    let skip = ["target", "node_modules", "dist", "build"];
                    return !skip.contains(&name.as_ref());
                }
                true
            })
        {
            let entry = match entry {
                Ok(e) => e,
                Err(_) => continue,
            };
            if !entry.file_type().is_dir() { continue; }
            if entry.path() == source_path { continue; }

            let config_path = entry.path().join(".sss.toml");
            if !config_path.exists() { continue; }

            let rel_path = entry.path().strip_prefix(&source_path)
                .unwrap_or(entry.path())
                .to_path_buf();

            match crate::commands::utils::try_create_processor_for_config(&config_path) {
                Ok(Some((cfg, proc))) => {
                    // Parse ignore patterns for this nested project
                    if let Ok((pos, neg)) = cfg.parse_ignore_patterns() {
                        if !pos.is_empty() {
                            nested_ignore.insert(rel_path.clone(), (pos, neg));
                        }
                    }
                    nested_processors.insert(rel_path, proc);
                }
                Ok(None) => {
                    eprintln!("Note: FUSE - no keys for nested project at {}", rel_path.display());
                    no_key_roots.insert(rel_path);
                }
                Err(e) => {
                    eprintln!("Warning: FUSE - cannot load nested project at {}: {}", rel_path.display(), e);
                    no_key_roots.insert(rel_path);
                }
            }
        }

        Ok(Self {
            source_path,
            source_fd,
            mount_fd,
            processor,
            secrets_cache: RwLock::new(secrets_cache),
            inode_table: RwLock::new(inode_table),
            path_to_ino: RwLock::new(path_to_ino),
            next_ino: RwLock::new(ROOT_INO + 1),
            file_handles: RwLock::new(HashMap::new()),
            next_fh: RwLock::new(1),
            render_cache: RwLock::new(HashMap::new()),
            pinned_paths,
            nested_processors,
            no_key_roots,
            ignore_patterns,
            negation_patterns,
            nested_ignore,
            #[cfg(feature = "vault")]
            vault_state,
        })
    }

    /// Get the mount point file descriptor (if available)
    ///
    /// Returns the raw file descriptor to the mount point directory.
    /// This can be used to access the underlying directory via /proc/self/fd/<fd>
    /// even after the FUSE filesystem is mounted over it.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use sss::fuse::fs::SssFS;
    /// # use sss::{Processor, RepositoryKey};
    /// # use std::path::PathBuf;
    /// # fn example() -> anyhow::Result<()> {
    /// # let source = PathBuf::from("/path/to/project");
    /// # let mount = PathBuf::from("/mnt/project");
    /// # let key = RepositoryKey::new();
    /// # let processor = Processor::new(key)?;
    /// let fs = SssFS::new(source, processor, Some(mount), None)?;
    /// if let Some(fd) = fs.get_mount_fd() {
    ///     println!("Access underlying directory: /proc/self/fd/{}", fd);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn get_mount_fd(&self) -> Option<std::os::unix::io::RawFd> {
        self.mount_fd
    }

    /// Find the pinned path that matches the given virtual path (longest prefix match)
    fn find_pinned_path(&self, virtual_path: &Path) -> &PinnedPath {
        // Longest prefix match - more specific paths come first in the vec
        for pinned in &self.pinned_paths {
            if virtual_path.starts_with(&pinned.virtual_prefix) {
                return pinned;
            }
        }

        // INVARIANT: SssFS::new always installs a root "/" entry in pinned_paths,
        // so a caller-supplied virtual_path always matches at least the root prefix.
        // Reaching this panic means the constructor invariant has been violated —
        // a fatal program bug, not recoverable state. HARDEN-01 / 08-01.
        panic!("No pinned path found for: {:?}", virtual_path);
    }

    /// Translate virtual path to source path and get operations
    /// Returns: (source_rel_path, pinned_path)
    fn translate_virtual_to_source(&self, virtual_path: &Path) -> (PathBuf, &PinnedPath) {
        let pinned = self.find_pinned_path(virtual_path);

        // Strip the virtual prefix and apply to source path
        let rel_to_virtual = virtual_path
            .strip_prefix(&pinned.virtual_prefix)
            .unwrap_or(Path::new(""));

        let source_path = if rel_to_virtual.as_os_str().is_empty() {
            pinned.source_path.clone()
        } else if pinned.source_path == Path::new("/") {
            PathBuf::from(rel_to_virtual)
        } else {
            pinned.source_path.join(rel_to_virtual)
        };

        // Convert to relative path for fd operations
        let source_rel = if source_path == Path::new("/") {
            PathBuf::from(".")
        } else {
            source_path.strip_prefix("/").unwrap_or(&source_path).to_path_buf()
        };

        (source_rel, pinned)
    }

    /// Get or create an inode for a path
    fn get_or_create_inode(&self, virtual_path: &Path, parent_ino: u64) -> u64 {
        // Check if we already have this path
        let path_map = self.path_to_ino.read();
        if let Some(&ino) = path_map.get(virtual_path) {
            return ino;
        }
        drop(path_map);

        // Create new inode
        let mut next_ino = self.next_ino.write();
        let ino = *next_ino;
        *next_ino += 1;
        drop(next_ino);

        let entry = InodeEntry {
            _ino: ino,
            path: virtual_path.to_path_buf(),
            parent: parent_ino,
        };

        self.inode_table.write().insert(ino, entry);
        self.path_to_ino.write().insert(virtual_path.to_path_buf(), ino);

        ino
    }

    /// Get inode entry
    fn get_inode(&self, ino: u64) -> Option<InodeEntry> {
        self.inode_table.read().get(&ino).cloned()
    }

    /// Convert filesystem metadata to FUSE FileAttr
    fn metadata_to_attr(&self, ino: u64, metadata: &fs::Metadata, size_override: Option<u64>, force_writable: bool) -> FileAttr {
        self.metadata_to_attr_with_secrets(ino, metadata, size_override, force_writable, false)
    }

    /// Convert filesystem metadata to FUSE FileAttr — always mirrors original metadata.
    /// Only `size` may differ (via size_override) because rendered content length differs from on-disk.
    fn metadata_to_attr_with_secrets(&self, ino: u64, metadata: &fs::Metadata, size_override: Option<u64>, _force_writable: bool, _has_secrets: bool) -> FileAttr {
        let kind = if metadata.is_dir() {
            FileType::Directory
        } else if metadata.is_symlink() {
            FileType::Symlink
        } else {
            FileType::RegularFile
        };

        // Use override size for rendered content
        let size = size_override.unwrap_or(metadata.len());

        FileAttr {
            ino,
            size,
            blocks: Self::get_blocks(metadata),
            atime: metadata.accessed().unwrap_or(UNIX_EPOCH),
            mtime: metadata.modified().unwrap_or(UNIX_EPOCH),
            ctime: Self::get_ctime(metadata),
            crtime: metadata.created().unwrap_or(UNIX_EPOCH),
            kind,
            perm: Self::get_permissions(metadata),
            nlink: Self::get_nlink(metadata) as u32,
            uid: Self::get_uid(metadata),
            gid: Self::get_gid(metadata),
            rdev: Self::get_rdev(metadata),
            blksize: Self::get_blksize(metadata),
            flags: 0,
        }
    }

    #[cfg(unix)]
    fn get_permissions(metadata: &fs::Metadata) -> u16 {
        use std::os::unix::fs::PermissionsExt;
        (metadata.permissions().mode() & 0o777) as u16
    }

    #[cfg(not(unix))]
    fn get_permissions(_metadata: &fs::Metadata) -> u16 {
        0o644
    }

    #[cfg(unix)]
    fn get_uid(metadata: &fs::Metadata) -> u32 {
        use std::os::unix::fs::MetadataExt;
        metadata.uid()
    }

    #[cfg(not(unix))]
    fn get_uid(_metadata: &fs::Metadata) -> u32 {
        0
    }

    #[cfg(unix)]
    fn get_gid(metadata: &fs::Metadata) -> u32 {
        use std::os::unix::fs::MetadataExt;
        metadata.gid()
    }

    #[cfg(not(unix))]
    fn get_gid(_metadata: &fs::Metadata) -> u32 {
        0
    }

    #[cfg(unix)]
    fn get_nlink(metadata: &fs::Metadata) -> u64 {
        use std::os::unix::fs::MetadataExt;
        metadata.nlink()
    }

    #[cfg(not(unix))]
    fn get_nlink(_metadata: &fs::Metadata) -> u64 {
        1
    }

    #[cfg(unix)]
    fn get_ctime(metadata: &fs::Metadata) -> std::time::SystemTime {
        use std::os::unix::fs::MetadataExt;
        let secs = metadata.ctime();
        let nsecs = metadata.ctime_nsec() as u32;
        if secs >= 0 {
            UNIX_EPOCH + Duration::new(secs as u64, nsecs)
        } else {
            UNIX_EPOCH
        }
    }

    #[cfg(not(unix))]
    fn get_ctime(metadata: &fs::Metadata) -> std::time::SystemTime {
        metadata.created().unwrap_or(UNIX_EPOCH)
    }

    #[cfg(unix)]
    fn get_blocks(metadata: &fs::Metadata) -> u64 {
        use std::os::unix::fs::MetadataExt;
        metadata.blocks()
    }

    #[cfg(not(unix))]
    fn get_blocks(metadata: &fs::Metadata) -> u64 {
        metadata.len().div_ceil(512)
    }

    #[cfg(unix)]
    fn get_blksize(metadata: &fs::Metadata) -> u32 {
        use std::os::unix::fs::MetadataExt;
        metadata.blksize() as u32
    }

    #[cfg(not(unix))]
    fn get_blksize(_metadata: &fs::Metadata) -> u32 {
        512
    }

    #[cfg(unix)]
    fn get_rdev(metadata: &fs::Metadata) -> u32 {
        use std::os::unix::fs::MetadataExt;
        metadata.rdev() as u32
    }

    #[cfg(not(unix))]
    fn get_rdev(_metadata: &fs::Metadata) -> u32 {
        0
    }

    /// Get the processor for a given relative path by walking up to find
    /// the nearest nested project, or falling back to the root processor.
    /// Returns `None` if the path falls inside a no-key root (passthrough).
    fn get_processor_for_path(&self, rel_path: &Path) -> Option<&Processor> {
        let mut current = Some(rel_path);
        while let Some(p) = current {
            if self.no_key_roots.contains(p) {
                return None;
            }
            if let Some(proc) = self.nested_processors.get(p) {
                return Some(proc);
            }
            current = p.parent();
        }
        Some(&self.processor)
    }

    /// Check if a file should skip SSS processing due to ignore patterns.
    /// Ignored files are still visible but returned as raw bytes (no decrypt/render).
    fn should_skip_processing(&self, rel_path: &Path) -> bool {
        // Walk up from rel_path to find the nearest nested project with ignore patterns
        let mut current = Some(rel_path);
        while let Some(p) = current {
            if let Some((positive, negative)) = self.nested_ignore.get(p) {
                // Found nested project — check path relative to this project root
                let sub_path = rel_path.strip_prefix(p).unwrap_or(rel_path);
                return Self::matches_ignore_patterns(sub_path, positive, negative);
            }
            current = p.parent();
        }

        // No nested project found, use root patterns
        if let Some(ref positive) = self.ignore_patterns {
            let negative = self.negation_patterns.as_ref();
            let empty = GlobSet::empty();
            let neg = negative.unwrap_or(&empty);
            Self::matches_ignore_patterns(rel_path, positive, neg)
        } else {
            false
        }
    }

    /// Check if a path matches positive ignore patterns without being overridden by negation.
    fn matches_ignore_patterns(path: &Path, positive: &GlobSet, negative: &GlobSet) -> bool {
        if positive.is_empty() {
            return false;
        }

        // Check both full path and filename (so *.log matches subdir/debug.log)
        let matches_ignore = positive.is_match(path)
            || path.file_name()
                .and_then(|n| n.to_str())
                .map(|name| positive.is_match(name))
                .unwrap_or(false);

        if !matches_ignore {
            return false;
        }

        // Check negation override
        if !negative.is_empty() {
            let matches_negation = negative.is_match(path)
                || path.file_name()
                    .and_then(|n| n.to_str())
                    .map(|name| negative.is_match(name))
                    .unwrap_or(false);

            if matches_negation {
                return false; // Negation overrides ignore
            }
        }

        true
    }

    /// Check if a file/directory should be hidden from FUSE view
    fn should_hide(name: &str) -> bool {
        matches!(
            name,
            ".git" | ".gitignore" | ".gitattributes" | ".gitmodules"
        )
    }

    /// Read and render a file (decrypt and remove all markers)
    /// Get metadata using source_fd (works even if mounted over source)
    fn metadata_via_fd(&self, rel_path: &Path) -> Result<fs::Metadata> {

        // On macOS with in-place mounts, path-based operations deadlock
        // because they route through the FUSE mount. Use FD-based operations
        // through source_fd which was opened before mounting.
        #[cfg(target_os = "macos")]
        {
            use std::os::unix::ffi::OsStrExt;

            if rel_path == Path::new(".") {
                // For root directory, use fstat directly on source_fd
                // SAFETY: `self.source_fd` is a valid open fd held for the lifetime of SssFS.
                // `mem::forget` prevents File from closing the fd — it is managed by SssFS::drop.
                let file = unsafe { std::fs::File::from_raw_fd(self.source_fd) };
                let metadata = file.metadata()?;
                std::mem::forget(file); // Don't close source_fd
                return Ok(metadata);
            }

            // For other paths, use fstatat relative to source_fd
            // This should work because source_fd was opened before mounting
            let path_bytes = rel_path.as_os_str().as_bytes();
            let path_cstr = std::ffi::CString::new(path_bytes)?;

            // SAFETY: `self.source_fd` is valid. `path_cstr` is NUL-terminated.
            // `stat` is zeroed stack memory of the correct size for `libc::stat`.
            // `fstatat` writes into `stat` and returns 0 on success, -1 on error.
            let mut stat: libc::stat = unsafe { std::mem::zeroed() };
            // SAFETY: `self.source_fd` is a valid directory fd. `path_cstr` is NUL-terminated.
            // `stat` is validly zeroed memory of `libc::stat` size; `fstatat` writes into it.
            // `AT_SYMLINK_NOFOLLOW` is a valid libc flag. Return value checked for -1 below.
            let result = unsafe {
                libc::fstatat(self.source_fd, path_cstr.as_ptr(), &mut stat, libc::AT_SYMLINK_NOFOLLOW)
            };

            if result < 0 {
                let err = std::io::Error::last_os_error();
                return Err(anyhow!("Failed to stat file: {}", err));
            }


            // Determine file type
            let is_dir = (stat.st_mode & libc::S_IFMT) == libc::S_IFDIR;
            let is_symlink = (stat.st_mode & libc::S_IFMT) == libc::S_IFLNK;

            // Open with appropriate flags based on file type
            // For symlinks: use O_SYMLINK if available (macOS) to open symlink itself
            // For directories: use O_RDONLY | O_DIRECTORY | O_NOFOLLOW
            // For regular files: use O_RDONLY | O_NOFOLLOW
            #[cfg(target_os = "macos")]
            let flags = if is_symlink {
                libc::O_RDONLY | libc::O_SYMLINK | libc::O_NOFOLLOW
            } else if is_dir {
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW
            } else {
                libc::O_RDONLY | libc::O_NOFOLLOW
            };

            // SAFETY: `self.source_fd` is valid. `path_cstr` is NUL-terminated.
            // `flags` are platform-appropriate open flags computed above.
            // O_CLOEXEC: prevents fd from being inherited by child processes (REM-17 / CR-01).
            let fd = unsafe {
                libc::openat(self.source_fd, path_cstr.as_ptr(), flags | libc::O_CLOEXEC)
            };

            if fd < 0 {
                let err = std::io::Error::last_os_error();

                // If this is a symlink and openat failed, try with O_SYMLINK | O_NOFOLLOW
                #[cfg(target_os = "macos")]
                if is_symlink && err.raw_os_error() == Some(libc::ELOOP) {
                    // SAFETY: retry with O_SYMLINK flag; same preconditions as above.
                    // O_CLOEXEC: included for consistency with primary open above.
                    let retry_fd = unsafe {
                        libc::openat(self.source_fd, path_cstr.as_ptr(),
                                   libc::O_RDONLY | libc::O_SYMLINK | libc::O_NOFOLLOW | libc::O_CLOEXEC)
                    };
                    if retry_fd >= 0 {
                        // SAFETY: `retry_fd` is valid (>= 0). File takes ownership and
                        // will close it when dropped.
                        let file = unsafe { std::fs::File::from_raw_fd(retry_fd) };
                        let metadata = file.metadata()?;
                        return Ok(metadata);
                    }
                }

                return Err(anyhow!("Failed to open file for metadata: {}", err));
            }

            // SAFETY: `fd` is valid (>= 0). File takes ownership and closes it when dropped.
            let file = unsafe { std::fs::File::from_raw_fd(fd) };
            let metadata = file.metadata()?;
            return Ok(metadata);
        }

        #[cfg(not(target_os = "macos"))]
        {
            use std::os::unix::ffi::OsStrExt;

            let path_bytes = rel_path.as_os_str().as_bytes();
            let path_cstr = std::ffi::CString::new(path_bytes)?;

            // SAFETY: `stat` is zeroed stack memory of the correct size. `self.source_fd`
            // is valid. `path_cstr` is NUL-terminated. Result checked immediately.
            let mut stat: libc::stat = unsafe { std::mem::zeroed() };

            // SAFETY: `self.source_fd` is a valid directory fd. `path_cstr` is NUL-terminated.
            // `stat` is validly zeroed memory of `libc::stat` size; `fstatat` writes into it.
            // `AT_SYMLINK_NOFOLLOW` is a valid libc flag. Return value checked for -1 below.
            let result = unsafe {
                libc::fstatat(self.source_fd, path_cstr.as_ptr(), &mut stat, libc::AT_SYMLINK_NOFOLLOW)
            };

            if result < 0 {
                let err = std::io::Error::last_os_error();
                return Err(anyhow!("Failed to stat file: {}", err));
            }

            // Determine file type from the stat result
            let is_dir = (stat.st_mode & libc::S_IFMT) == libc::S_IFDIR;
            let is_symlink = (stat.st_mode & libc::S_IFMT) == libc::S_IFLNK;

            // Open with appropriate flags based on file type
            // For symlinks: use O_PATH | O_NOFOLLOW to open the symlink itself
            //               without following it (avoids ELOOP for circular/broken symlinks)
            // For directories: use O_RDONLY | O_DIRECTORY | O_NOFOLLOW
            // For regular files: use O_RDONLY | O_NOFOLLOW
            let flags = if is_symlink {
                libc::O_PATH | libc::O_NOFOLLOW
            } else if is_dir {
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW
            } else {
                libc::O_RDONLY | libc::O_NOFOLLOW
            };

            // SAFETY: `self.source_fd` is valid. `path_cstr` is NUL-terminated.
            // `flags` are computed above based on file type from `fstatat` result.
            // O_CLOEXEC: prevents fd from being inherited by child processes (REM-17 / CR-01).
            let fd = unsafe {
                libc::openat(self.source_fd, path_cstr.as_ptr(), flags | libc::O_CLOEXEC)
            };

            if fd < 0 {
                let err = std::io::Error::last_os_error();

                // If this is a symlink and openat failed with ELOOP, try O_PATH | O_NOFOLLOW
                // as a fallback (in case the first attempt didn't use those flags)
                if is_symlink && err.raw_os_error() == Some(libc::ELOOP) {
                    // SAFETY: retry with O_PATH|O_NOFOLLOW; same source_fd/path preconditions.
                    // O_CLOEXEC: included for consistency with primary open above.
                    let retry_fd = unsafe {
                        libc::openat(self.source_fd, path_cstr.as_ptr(), libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC)
                    };
                    if retry_fd >= 0 {
                        // SAFETY: `retry_fd` is valid (>= 0). File takes ownership and closes on drop.
                        let file = unsafe { std::fs::File::from_raw_fd(retry_fd) };
                        let metadata = file.metadata()?;
                        return Ok(metadata);
                    }
                }

                return Err(anyhow!("Failed to open file for metadata: {}", err));
            }

            // SAFETY: `fd` is valid (>= 0). File takes ownership and closes it when dropped.
            let file = unsafe { std::fs::File::from_raw_fd(fd) };
            let metadata = file.metadata()?;
            Ok(metadata)
        }
    }

    /// Check if a file exists using source_fd (works even if mounted over source)
    // Why: file existence probe via source_fd that survives mount-over-source; kept as an internal API for future passthrough invariant checks; deleting it would force a re-implementation when the next FUSE invariant test lands; fuse-gated helper appears dead when feature = "fuse" is off.
    #[allow(dead_code)]
    fn file_exists_via_fd(&self, rel_path: &Path) -> bool {
        let path_bytes = rel_path.as_os_str().as_bytes();
        let path_cstr = match std::ffi::CString::new(path_bytes) {
            Ok(p) => p,
            Err(_) => return false,
        };

        // Use faccessat to check if file exists without deadlocking
        // SAFETY: `self.source_fd` is a valid directory fd. `path_cstr` is NUL-terminated.
        // `faccessat` does not retain the pointer after returning.
        let result = unsafe {
            libc::faccessat(
                self.source_fd,
                path_cstr.as_ptr(),
                libc::F_OK,  // Check for existence
                0,
            )
        };

        result == 0
    }

    /// Read file using source_fd (works even if mounted over source)
    fn read_file_via_fd(&self, rel_path: &Path) -> Result<Vec<u8>> {
        fuse_debug!("      read_file_via_fd: rel_path={:?} source_fd={}", rel_path, self.source_fd);
        // On macOS, openat can deadlock from FUSE handlers
        // Use full path instead
        #[cfg(target_os = "macos")]
        {
            let full_path = self.source_path.join(rel_path);
            fuse_debug!("      read_file_via_fd: macOS fs::read {:?}", full_path);
            let buffer = fs::read(&full_path)?;
            fuse_debug!("      read_file_via_fd: done, {}bytes", buffer.len());
            return Ok(buffer);
        }

        #[cfg(not(target_os = "macos"))]
        {
            use std::os::unix::ffi::OsStrExt;

            let path_bytes = rel_path.as_os_str().as_bytes();
            let path_cstr = std::ffi::CString::new(path_bytes)?;

            // Open file relative to source_fd
            fuse_debug!("      read_file_via_fd: calling openat(fd={}, {:?}, O_RDONLY)", self.source_fd, rel_path);
            // SAFETY: `self.source_fd` is a valid directory fd. `path_cstr` is NUL-terminated.
            // The returned fd is checked for errors before use.
            // O_CLOEXEC: prevents this fd from being inherited by child processes (REM-17 / CR-01).
            let fd = unsafe {
                libc::openat(self.source_fd, path_cstr.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC)
            };
            fuse_debug!("      read_file_via_fd: openat returned fd={}", fd);

            if fd < 0 {
                let err = std::io::Error::last_os_error();
                return Err(anyhow!("Failed to open file: {}", err));
            }

            // Read file contents
            fuse_debug!("      read_file_via_fd: reading contents");
            let mut buffer = Vec::new();
            // SAFETY: `fd` is valid (>= 0). File takes ownership and closes it when dropped
            // (via BufReader, which consumes File).
            let file = unsafe { std::fs::File::from_raw_fd(fd) };
            use std::io::Read;
            std::io::BufReader::new(file).read_to_end(&mut buffer)?;
            fuse_debug!("      read_file_via_fd: done, {}bytes", buffer.len());

            Ok(buffer)
        }
    }

    /// Does this backing file contain at least one Vault reference (`⊳{}` / `>{}`)?
    ///
    /// Reads the RAW backing-store bytes via [`Self::read_file_via_fd`] and runs the
    /// [`bytes_have_vault_refs`] predicate over them. Used at `open()` time to decide
    /// whether a file is "vault-backed" — which drives both the `FOPEN_DIRECT_IO`
    /// flag (VMNT-04) and the open-time precache bypass (VMNT-03 / SC3). A backing
    /// read error (missing / unreadable file) returns `false` (the file is treated as
    /// non-vault — a subsequent `read()` would surface its own error).
    ///
    /// This is a cold read at open time and is intentionally NOT cached: the file is
    /// small and correctness (always re-detecting) is preferred over a micro-cache
    /// that could itself retain bytes. Only the method is feature-gated; the regex
    /// and the [`bytes_have_vault_refs`] predicate are non-gated (VREF-01).
    #[cfg(feature = "vault")]
    fn file_has_vault_refs(&self, file_path: &Path) -> bool {
        let rel_path = file_path.strip_prefix(&self.source_path).unwrap_or(file_path);
        match self.read_file_via_fd(rel_path) {
            Ok(bytes) => bytes_have_vault_refs(&bytes),
            Err(_) => false,
        }
    }

    /// WR-02: is there a REAL `.sss` entry in the backing-store root?
    ///
    /// The synthetic `<mnt>/.sss/` control directory (`vault-status`) is a
    /// best-effort surface that MUST yield to real user data: if a project already
    /// has a root-level `.sss` of its own, that real entry wins and the synthetic
    /// node is suppressed in both `lookup` and `readdir` (the real dir is served
    /// normally; `vault-status` is simply unavailable, which is acceptable). Without
    /// this precedence the listing would carry a duplicate `.sss` and the synthetic
    /// inode would permanently shadow the real directory.
    ///
    /// Stats the root-relative `.sss` via the source fd (same path the real lookup
    /// uses). Any stat error (absent / unreadable) means "no real `.sss`" → the
    /// synthetic surface is safe to expose.
    #[cfg(feature = "vault")]
    fn real_sss_dir_present(&self) -> bool {
        self.metadata_via_fd(Path::new(".sss")).is_ok()
    }

    /// Generic file reading with optional processing
    /// Reduces duplication across read_and_render, read_and_open, and read_sealed
    fn read_and_process<F>(&self, path: &Path, process_fn: F) -> Result<Vec<u8>>
    where
        F: FnOnce(&Self, String, &Path) -> Result<String>,
    {
        // Get relative path from source root
        let rel_path = path.strip_prefix(&self.source_path)
            .unwrap_or(path);

        fuse_debug!("    read_and_process: rel_path={:?}", rel_path);

        // Read file via fd
        fuse_debug!("    read_and_process: calling read_file_via_fd");
        let bytes = self.read_file_via_fd(rel_path)?;
        fuse_debug!("    read_and_process: read {}bytes", bytes.len());

        // Skip processing for files matching ignore patterns — return raw bytes
        if self.should_skip_processing(rel_path) {
            fuse_debug!("    read_and_process: skipped (ignore pattern)");
            return Ok(bytes);
        }

        // Quick byte-level scan for marker opening sequences (avoids String conversion
        // for the vast majority of files that have no markers at all)
        use crate::filesystem_common::has_any_markers_bytes;
        // CR-01: vault refs (⊳{}/>{}) are NOT standard SSS markers, so
        // has_any_markers_bytes is blind to a vault-ONLY file. Without the
        // bytes_have_vault_refs check, such a file early-returns raw here and the
        // vault pass in read_and_render never runs (markers served verbatim).
        if !has_any_markers_bytes(&bytes) && !bytes_have_vault_refs(&bytes) {
            fuse_debug!("    read_and_process: no markers, returning raw");
            return Ok(bytes);
        }

        // File has marker-like bytes — convert to string for deeper validation
        let content = match String::from_utf8(bytes.clone()) {
            Ok(c) => c,
            Err(_) => {
                // Has marker-like bytes but not valid UTF-8, return raw bytes
                return Ok(bytes);
            }
        };

        // Verify file actually has balanced markers (prefix + { + content + })
        // Files that merely mention marker characters (e.g. in grep patterns or
        // documentation) are returned as-is to avoid false-positive processing
        use crate::filesystem_common::has_balanced_markers;
        // CR-01: same vault-blindness as the byte gate above — a balanced ⊳{…} is
        // not a "balanced marker" to has_balanced_markers, so keep the vault file
        // flowing to the render closure (which owns the ⊳{} resolution).
        if !has_balanced_markers(&content) && !bytes_have_vault_refs(content.as_bytes()) {
            fuse_debug!("    read_and_process: no balanced markers, returning raw");
            return Ok(bytes);
        }

        fuse_debug!("    read_and_process: has balanced markers, processing");

        // Apply processing function with relative path for proper secrets resolution
        let processed = process_fn(self, content, rel_path)?;
        fuse_debug!("    read_and_process: done");
        Ok(processed.into_bytes())
    }

    fn read_and_render(&self, path: &Path) -> Result<Vec<u8>> {
        self.read_and_process(path, |fs, content, rel_path| {
            // Check for a nested-project processor (None → no keys, passthrough)
            let proc = match fs.get_processor_for_path(rel_path) {
                Some(p) => p,
                None => return Ok(content), // no keys — return as-is
            };

            // Process if file has any markers (sealed or opened) OR vault refs
            // (⊳{}). CR-01: a vault-only file has no standard markers, so without
            // the bytes_have_vault_refs arm it would skip the interpolate→vault→
            // decrypt block and be returned verbatim with markers unresolved.
            if has_any_markers(&content) || bytes_have_vault_refs(content.as_bytes()) {
                // First, interpolate secrets (⊲{}) using the unified function with
                // fd-based operations (avoids deadlock). The `secrets_cache` write
                // guard is scoped to JUST this call so it is released BEFORE the
                // vault block acquires the independent vault token tier (pitfall 5:
                // the vault token Mutex is NEVER held across `secrets_cache`).
                let content_with_secrets = {
                    let fd_ops = FdFileSystemOps {
                        source_fd: fs.source_fd,
                        source_path: fs.source_path.clone(),
                    };
                    let mut secrets_cache = fs.secrets_cache.write();
                    // keep_unresolved=true: FUSE mount read must never raise exit-3;
                    // a missing ⊲{} on a mount read preserves the marker verbatim
                    // (mount-time miss semantics are Phase 49's concern via EIO).
                    interpolate_secrets(
                        &content,
                        rel_path,
                        &fs.source_path,
                        &mut *secrets_cache,
                        &fd_ops,
                        true,
                    )?
                };

                // R2 SEAM (VMNT-02/06): the Vault (⊳{}) interpolation pass sits
                // BETWEEN the ⊲{} secrets pass above and `decrypt_to_raw` below.
                // ADDITIVE — the secrets pass is unchanged. The per-read
                // VaultRequestCache is constructed AND dropped inside this block,
                // so no resolved plaintext is ever retained across reads (SC3).
                #[cfg(feature = "vault")]
                let content_with_secrets =
                    fs.apply_vault_pass(content_with_secrets)?;

                // Then decrypt and remove all markers using the correct processor
                proc.decrypt_to_raw(&content_with_secrets)
            } else {
                // Return as-is for non-marked files
                Ok(content)
            }
        })
    }

    /// Re-authenticate the long-lived mount token when its lease TTL drops to or
    /// below this many seconds (on-demand renewal; no background thread).
    #[cfg(feature = "vault")]
    const VAULT_TOKEN_NEAR_EXPIRY_SECS: u64 = 60;

    /// Apply the Vault (`⊳{}`) interpolation pass to already-secrets-interpolated
    /// content — the R2 seam between `interpolate_secrets` and `decrypt_to_raw`
    /// (VMNT-02/06). Returns the content with every resolvable `⊳{}` substituted.
    ///
    /// Failure routing (fail-closed):
    /// - A per-reference miss returns `Err` (the `read()` callback maps it to EIO)
    ///   UNLESS `--keep-unresolved`, in which case the `⊳{}` marker is left verbatim.
    /// - A whole-operation failure (Vault unreachable / auth failure) returns `Err`
    ///   UNCONDITIONALLY — `--keep-unresolved` never masks it (T-48-12 parity).
    /// - Never returns truncated/partial content.
    ///
    /// The fresh [`VaultRequestCache`](crate::vault::resolver::VaultRequestCache) is
    /// created and dropped within this call → token + any resolved values are
    /// zeroised the instant the read frame ends (SC3 / VAUTH-03). NEVER stores a
    /// resolved value in any `SssFS` field. NEVER writes `.sss.vault.lock` (VMNT-03).
    /// NEVER calls `reply.error` (the read callback owns the Err→EIO mapping).
    #[cfg(feature = "vault")]
    fn apply_vault_pass(&self, content_with_secrets: String) -> Result<String> {
        use crate::vault::resolver::{interpolate_vault_refs_resolved, VaultRequestCache};

        // (1) Cheap gate: skip ALL resolver/network work under --no-vault or when
        // the content carries no ⊳{} markers (reuses the raw-bytes predicate).
        if self.vault_state.no_vault
            || !bytes_have_vault_refs(content_with_secrets.as_bytes())
        {
            return Ok(content_with_secrets);
        }

        // (2) Token freshness + reuse (independent vault tier; guard never spans the
        // resolver call). Re-auth on demand when the long-lived token is absent
        // (lazy first read) or near-expiry — no background refresh thread.
        let token = self.ensure_mount_token()?;

        // (3) Fresh per-read cache seeded with the (reused or just-minted) token.
        // The resolver is reconstructed per read — cheap (just builds a client) and
        // sidesteps the 'static lifetime tangle (research risk 1).
        let mut cache = VaultRequestCache::new();
        cache.seed_token(token);
        let resolver = self
            .vault_state
            .reconstruct_resolver()
            .map_err(|e| anyhow!("vault resolver construction failed: {e}"))?;

        let result =
            interpolate_vault_refs_resolved(&content_with_secrets, &resolver, &mut cache);

        match result {
            Ok(outcome) => {
                if !outcome.unresolved.is_empty() && !self.vault_state.keep_unresolved {
                    // Per-ref miss and NOT --keep-unresolved → EIO. Count only —
                    // never log the reference values (value-free boundary).
                    Err(anyhow!(
                        "unresolved vault references: {} ref(s)",
                        outcome.unresolved.len()
                    ))
                } else {
                    // All resolved, OR --keep-unresolved (markers preserved verbatim
                    // by the resolver). `cache` drops here → values zeroised.
                    Ok(outcome.content)
                }
            }
            Err(e) if e.is_whole_operation() => {
                // Whole-op failure → EIO ALWAYS; keep_unresolved does NOT apply.
                Err(anyhow!("vault whole-operation failure"))
            }
            Err(_) => {
                // Any other resolver error is treated as EIO (fail-closed).
                Err(anyhow!("vault error"))
            }
        }
        // `cache` (and the seeded token clone) drop here → zeroised (SC3).
    }

    /// Does the long-lived mount token need a (re-)auth right now?
    ///
    /// `true` when the token is absent (lazy first read / never authed) OR its lease
    /// reports a real near-expiry TTL (`0 < ttl_secs <= VAULT_TOKEN_NEAR_EXPIRY_SECS`).
    /// A `0` / absent TTL is "unknown but usable" — we do NOT hammer Vault every read;
    /// on-demand renewal still kicks in once a real near-expiry TTL is observed.
    ///
    /// Acquires (and releases) only the token + lease value guards — held briefly for
    /// this peek and NEVER across a network call (pitfall 5).
    #[cfg(feature = "vault")]
    fn mount_token_needs_refresh(&self) -> bool {
        let token_present = self.vault_state.token.lock().is_some();
        let lease_ttl_secs = self.vault_state.lease.lock().as_ref().map(|l| l.ttl_secs);
        // both guards released above; the decision itself is pure (unit-tested).
        mount_token_refresh_decision(
            token_present,
            lease_ttl_secs,
            Self::VAULT_TOKEN_NEAR_EXPIRY_SECS,
        )
    }

    /// Obtain a live mount-level Vault token, re-authenticating on demand.
    ///
    /// Returns a CLONE of the long-lived token (the per-read cache owns the copy;
    /// `Zeroizing<String>` cloning is fine — both copies wipe on drop). The vault
    /// token `Mutex` guard is dropped before returning so it never spans a resolver
    /// call (pitfall 5). Re-auth happens when the token is absent (lazy first read)
    /// or its lease TTL is at/below [`Self::VAULT_TOKEN_NEAR_EXPIRY_SECS`]. A lazy
    /// first-read auth failure surfaces as `Err` → EIO for THAT read only (the mount
    /// stays up — VMNT-02 lazy contract).
    ///
    /// # Concurrency (WR-03 single-flight)
    ///
    /// FUSE callbacks run concurrently, so a naive check-then-auth let two threads
    /// both decide "needs auth" and mint two tokens — wasting a login and, with a
    /// SINGLE-USE `AppRole` secret-id, exhausting the credential on first
    /// `--vault-lazy` read. The whole freshness-check + network auth + store now runs
    /// under [`VaultMountState::auth_lock`] so exactly ONE login happens per refresh.
    /// A thread that waited on `auth_lock` RE-CHECKS freshness inside the lock and
    /// reuses the just-minted token instead of auth'ing again. The token/lease value
    /// guards are still only ever held for the brief freshness peek and the store —
    /// never across the network auth (pitfall 5 preserved). This makes `--vault-lazy`
    /// safe with single-use `AppRole` secret-ids.
    #[cfg(feature = "vault")]
    fn ensure_mount_token(&self) -> Result<zeroize::Zeroizing<String>> {
        use crate::vault::resolver::VaultRequestCache;

        // Fast path: if the token is already fresh, return its clone without taking
        // the single-flight gate. Fresh concurrent reads must NOT serialise on auth.
        // (If the token vanished between the freshness peek and the clone — e.g. a
        // concurrent Drop / refresh — this guard is false and we fall through to the
        // gated slow path to (re-)mint it.)
        if !self.mount_token_needs_refresh()
            && let Some(tok) = self.vault_state.token.lock().as_ref().cloned()
        {
            return Ok(tok);
        }

        // Slow path: serialise the freshness re-check + network auth + store under
        // the dedicated single-flight gate so exactly ONE login happens per refresh.
        let _auth_guard = self.vault_state.auth_lock.lock();

        // RE-CHECK under the gate: a thread that queued behind another thread's auth
        // must reuse the token that thread just stored, NOT auth again. Only auth if
        // it is still absent / near-expiry.
        if self.mount_token_needs_refresh() {
            // Reconstruct + bootstrap into a temporary cache, then drain the fresh
            // token + lease into the long-lived mount state. The network auth runs
            // while holding ONLY `auth_lock` — the token/lease value guards are not
            // held here (they are taken briefly below for the store).
            let resolver = self
                .vault_state
                .reconstruct_resolver()
                .map_err(|e| anyhow!("vault auth failed — resolver construction: {e}"))?;
            let mut boot = VaultRequestCache::new();
            resolver
                .bootstrap_auth(&mut boot)
                .map_err(|e| anyhow!("vault auth failed: {e}"))?;
            let fresh = boot.take_token();
            let lease = boot.take_lease();
            *self.vault_state.token.lock() = fresh;
            *self.vault_state.lease.lock() = lease;
        }

        // Clone the now-present token out, dropping the value guard before returning
        // (the `auth_lock` guard drops at end of scope, after this clone).
        let token_guard = self.vault_state.token.lock();
        token_guard
            .as_ref()
            .cloned()
            .ok_or_else(|| anyhow!("vault token unavailable after authentication"))
    }

    /// Generate the value-free key:value content for `<mnt>/.sss/vault-status`.
    ///
    /// All fields are non-sensitive (no token text, no resolved secret values):
    /// - `auth_method`     — method name from the `[vault]` config (`"approle"` / `"token"` / `"none"`).
    /// - `token_present`   — `true`/`false` (Mutex read; NEVER the token text).
    /// - `token_ttl_secs`  — lease TTL or `"unknown"` (lease Mutex; NEVER the token).
    /// - `binding_count`   — number of configured `[vault]` bindings.
    /// - `lockfile_drift`  — always a static pointer to `sss vault verify` (cheap; VMNT-03).
    /// - `no_vault`        — reflects `--no-vault` / no `[vault]` table.
    /// - `vault_lazy`      — reflects `--vault-lazy`.
    /// - `keep_unresolved` — reflects `--keep-unresolved`.
    ///
    /// This method performs NO network call, NO file I/O, and NEVER accesses resolved
    /// secret values — all fields come from already-stored scalar state on
    /// [`VaultMountState`]. Generating the block on every `getattr`/`read` is
    /// intentional: the size and content must stay in sync (Pitfall 6 guard).
    ///
    /// # Security
    ///
    /// Reviewed against the Information-Disclosure mitigation in 49-RESEARCH.md:
    /// `token_present` is a boolean derived from `Option::is_some()` — the token
    /// string itself is never accessed here. `token_ttl_secs` is a bare integer from
    /// [`AuthLease::ttl_secs`] — not the token or any secret value.
    #[cfg(feature = "vault")]
    fn vault_status_content(&self) -> String {
        vault_status_content_from_state(&self.vault_state)
    }

    /// Read and open a file (decrypt ⊠{} → ⊕{} but keep markers for ssse edit)
    fn read_and_open(&self, path: &Path) -> Result<Vec<u8>> {
        self.read_and_process(path, |fs, content, rel_path| {
            // Check for a nested-project processor (None → no keys, passthrough)
            let proc = match fs.get_processor_for_path(rel_path) {
                Some(p) => p,
                None => return Ok(content), // no keys — return as-is
            };

            // Only process if file has encrypted markers
            if has_encrypted_markers(&content) {
                // Decrypt to opened form (⊠{} → ⊕{})
                proc.decrypt_content(&content)
            } else {
                // Return as-is for non-encrypted files
                Ok(content)
            }
        })
    }

    /// Read sealed file (raw content with ⊠{} markers from backing store)
    /// This is used by .sss-sealed virtual paths for sss edit
    fn read_sealed(&self, path: &Path) -> Result<Vec<u8>> {
        // Get relative path from source root
        let rel_path = path.strip_prefix(&self.source_path)
            .unwrap_or(path);

        // Read raw file via fd - no processing!
        let bytes = self.read_file_via_fd(rel_path)?;
        Ok(bytes)
    }

    /// Write rendered content back (with smart reconstruction and sealing)
    /// Check if a file should be processed by sss encryption
    /// Files like swap files, temp files, etc. should be written through directly
    fn should_process_with_sss(path: &Path) -> bool {
        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            // Skip vim swap files and temporary files
            if name.starts_with('.') && (name.ends_with(".swp") || name.ends_with(".swo") ||
                                         name.ends_with(".swn") || name.ends_with(".tmp")) {
                return false;
            }
            // Skip other temporary file patterns
            if name.ends_with('~') || name.starts_with("#") || name.ends_with("#") {
                return false;
            }
        }
        true
    }

    /// Write raw content directly to backing store (no sss processing)
    fn write_raw_to_backing(&self, path: &Path, content: &[u8]) -> Result<()> {
        let rel_path = path.strip_prefix(&self.source_path).unwrap_or(path);
        let path_cstr = CString::new(rel_path.as_os_str().as_bytes())?;

        // Write directly via fd
        // SAFETY: `self.source_fd` is a valid directory fd. `path_cstr` is NUL-terminated.
        // Mode 0o600 restricts access to the file owner. Error checked immediately.
        // O_CLOEXEC: prevents this fd from being inherited by child processes (REM-17 / CR-01).
        let fd = unsafe {
            libc::openat(
                self.source_fd,
                path_cstr.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC | libc::O_CLOEXEC,
                0o600,
            )
        };

        if fd < 0 {
            return Err(anyhow!("Failed to open file for writing"));
        }

        // SAFETY: `fd` is valid (>= 0). `content.as_ptr()` points to `content.len()` valid bytes.
        // `libc::write` does not retain the pointer. `close` is called after write completes.
        let write_result = unsafe {
            let bytes_written = libc::write(
                fd,
                content.as_ptr() as *const _,
                content.len(),
            );
            libc::close(fd);
            bytes_written
        };

        if write_result < 0 || write_result != content.len() as isize {
            return Err(anyhow!("Failed to write content"));
        }

        Ok(())
    }

    /// Creates a temporary file path for atomic write operations.
    ///
    /// The name includes a 64-bit nonce derived from a process-global counter,
    /// the process id, and the current timestamp so that concurrent or rapidly
    /// repeated writes use distinct paths (WR-01 fix / REM-16 / CON-07-001).
    /// Using `subsec_nanos()` alone gave only ~30 bits of uniqueness, causing
    /// `O_EXCL` collisions under concurrent writes or a tight write loop.
    fn create_temp_file_path(&self, rel_path: &Path) -> Result<(PathBuf, CString)> {
        // 64-bit nonce: monotonic counter XOR'd with pid-mixing constant XOR timestamp.
        // The counter alone guarantees per-process uniqueness; XOR with pid and nanos
        // provides inter-process and cross-restart distinctness.
        let seq = TEMP_NONCE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let nonce = seq
            ^ (std::process::id() as u64).wrapping_mul(0x9e3779b97f4a7c15)
            ^ SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0);
        let temp_name = format!(
            ".{}.{:016x}.tmp",
            rel_path.file_name().and_then(|n| n.to_str()).unwrap_or("unnamed"),
            nonce,
        );
        let temp_rel_path = rel_path.parent()
            .unwrap_or_else(|| Path::new("."))
            .join(&temp_name);
        let temp_path_cstr = CString::new(temp_rel_path.as_os_str().as_bytes())?;
        Ok((temp_rel_path, temp_path_cstr))
    }

    /// Atomically writes content via file descriptor using temp file + rename pattern.
    ///
    /// The temp file is opened with `O_CREAT|O_EXCL|O_NOFOLLOW` (REM-16 / CON-07-001): a
    /// pre-existing symlink at the temp path causes an error instead of being followed, and a
    /// stale collision fails loudly rather than truncating an existing file.  A [`TempFileGuard`]
    /// is armed immediately after the path is known so that an error return or panic between the
    /// `openat` and the `renameat` never leaves a plaintext `.tmp` behind (REM-18 / CON-13-001).
    fn write_via_fd_atomic(&self, rel_path: &Path, content: &str) -> Result<()> {
        let path_cstr = CString::new(rel_path.as_os_str().as_bytes())?;
        let (_temp_path, temp_path_cstr) = self.create_temp_file_path(rel_path)?;

        // Arm the RAII guard immediately after the temp path is chosen so that any
        // error return or panic between here and the successful renameat triggers unlink.
        // The guard is disarmed (guard.active = false) only after renameat succeeds.
        // Lifetime safety: this guard lives inside write_via_fd_atomic which borrows
        // &self, so it drops before SssFS (and before source_fd closes). See the
        // TempFileGuard struct doc for the full lifetime invariant.
        let mut guard = TempFileGuard {
            dir_fd: self.source_fd,
            path_cstr: temp_path_cstr.clone(),
            active: true,
        };

        // Open the temp file with O_EXCL|O_NOFOLLOW (REM-16 / CON-07-001).
        // O_EXCL: fails if the path already exists — no overwriting a pre-placed file/symlink.
        // O_NOFOLLOW: fails if the path is a symlink — prevents a race where an attacker
        //   replaces the just-verified path with a symlink before the open.
        // O_TRUNC is intentionally absent: it is semantically contradictory under O_EXCL
        //   (the open fails if the file exists, so truncation can never apply).
        // O_CLOEXEC: prevents this plaintext-holding fd from being inherited by child
        //   processes during the atomic-write window (REM-17 / CR-01).
        // SAFETY: `self.source_fd` is a valid directory fd. `temp_path_cstr` is NUL-terminated.
        // Mode 0o600 restricts access to the file owner. Error checked immediately.
        let temp_fd = unsafe {
            libc::openat(
                self.source_fd,
                temp_path_cstr.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };

        if temp_fd < 0 {
            return Err(anyhow!("Failed to create temp file"));
            // guard drops here: active=true → unlink attempted (file may not exist yet,
            // that is fine — unlinkat on a non-existent path returns ENOENT, which is ignored).
        }

        // SAFETY: `temp_fd` is valid (>= 0). `content.as_ptr()` points to `content.len()` valid
        // UTF-8 bytes. `libc::write` does not retain the pointer. `close` follows immediately.
        let write_result = unsafe {
            let bytes_written = libc::write(
                temp_fd,
                content.as_ptr() as *const _,
                content.len(),
            );
            libc::close(temp_fd);
            bytes_written
        };

        if write_result < 0 || write_result != content.len() as isize {
            return Err(anyhow!("Failed to write content"));
            // guard drops here: active=true → unlinks the partially-written temp.
        }

        // Atomically rename temp to target.
        // SAFETY: both `temp_path_cstr` and `path_cstr` are NUL-terminated. `self.source_fd`
        // is the same directory fd for both paths (relative rename within one directory).
        let result = unsafe {
            libc::renameat(
                self.source_fd,
                temp_path_cstr.as_ptr(),
                self.source_fd,
                path_cstr.as_ptr(),
            )
        };

        if result < 0 {
            return Err(anyhow!("Failed to rename temp file"));
            // guard drops here: active=true → unlinks the temp that could not be renamed.
        }

        // Rename succeeded: disarm the guard so Drop does NOT unlink the now-final file.
        guard.active = false;

        Ok(())
    }

    /// Write opened content (with ⊕{} markers) directly to backing store
    /// This is used for opened_mode writes where content already has markers
    fn write_sealed_to_backing(&self, path: &Path, opened_content: &[u8]) -> Result<()> {
        // REM-15 / CR-04: borrow the already-Zeroizing caller buffer as &str instead of
        // allocating a fresh bare String via `String::from_utf8(opened_content.to_vec())`.
        // Using std::str::from_utf8 avoids the heap copy and the unzeroed intermediate.
        let opened_str = std::str::from_utf8(opened_content)
            .map_err(|_| anyhow!("Content is not valid UTF-8"))?;

        // Select the correct processor for this path
        let rel_path = path.strip_prefix(&self.source_path).unwrap_or(path);
        let proc = self.get_processor_for_path(rel_path).unwrap_or(&self.processor);

        // Seal the opened content (⊕{} → ⊠{})
        let sealed_content = proc.encrypt_content(opened_str)?;

        // Write to backing store via file descriptor
        self.write_via_fd_atomic(rel_path, &sealed_content)
    }

    /// Gets current sealed content from parameter or backing store
    fn get_current_sealed_content(&self, path: &Path, original_sealed: Option<&String>) -> Result<Option<String>> {
        if let Some(original) = original_sealed {
            return Ok(Some(original.clone()));
        }

        // Read current sealed version FROM BACKING STORE (not through FUSE!)
        let rel_path = path.strip_prefix(&self.source_path).unwrap_or(path);
        match self.read_file_via_fd(rel_path) {
            Ok(content) => {
                let sealed = String::from_utf8(content)
                    .map_err(|_| anyhow!("Backing file is not valid UTF-8"))?;
                Ok(Some(sealed))
            }
            Err(_) => Ok(None), // File doesn't exist or can't be read
        }
    }

    /// Performs smart reconstruction using marker inference
    fn perform_smart_reconstruction(&self, path: &Path, sealed_current: &str, rendered_str: &str) -> Result<String> {
        // Select the correct processor for this path
        let rel_path = path.strip_prefix(&self.source_path).unwrap_or(path);
        let proc = self.get_processor_for_path(rel_path).unwrap_or(&self.processor);

        // Open (decrypt/open) current version to get content with markers
        let opened_current = proc.decrypt_content(sealed_current)?;

        // Use intelligent marker inference to reconstruct markers
        let inference_result = crate::marker_inference::infer_markers(&opened_current, rendered_str)
            .map_err(|e| anyhow!("Marker inference failed: {}", e))?;

        // Log any warnings from marker inference
        if !inference_result.warnings.is_empty() {
            eprintln!("Marker inference warnings for {:?}:", path);
            for warning in &inference_result.warnings {
                eprintln!("  - {}", warning);
            }
        }

        Ok(inference_result.output)
    }

    fn write_and_seal(&self, path: &Path, rendered_content: &[u8], original_sealed: Option<&String>) -> Result<()> {
        // Check if this file is in a no-key zone — write raw
        let rel_path = path.strip_prefix(&self.source_path).unwrap_or(path);
        if self.get_processor_for_path(rel_path).is_none() {
            return self.write_raw_to_backing(path, rendered_content);
        }

        // Skip processing for files matching ignore patterns — write raw
        if self.should_skip_processing(rel_path) {
            return self.write_raw_to_backing(path, rendered_content);
        }

        // REM-15 / CR-04: borrow the already-Zeroizing caller buffer as &str instead of
        // allocating a fresh bare String via `String::from_utf8(rendered_content.to_vec())`.
        // Using std::str::from_utf8 avoids the heap copy and the unzeroed intermediate.
        let rendered_str = std::str::from_utf8(rendered_content)
            .map_err(|_| anyhow!("Content is not valid UTF-8"))?;

        // Get current sealed version
        let sealed_current = match self.get_current_sealed_content(path, original_sealed)? {
            Some(content) => content,
            None => return self.write_raw_to_backing(path, rendered_content), // New file, write as-is
        };

        // Check if new content has plaintext markers
        let new_has_plaintext_markers = rendered_str.contains("⊕{") || rendered_str.contains("o+{");

        // Simple case: no markers in either version
        if !has_any_markers(&sealed_current) && !new_has_plaintext_markers {
            return self.write_raw_to_backing(path, rendered_content);
        }

        // Normalize case: no current markers but new has plaintext markers
        if !has_any_markers(&sealed_current) && new_has_plaintext_markers {
            let normalized = rendered_str.replace("o+{", "⊕{");
            return self.write_raw_to_backing(path, normalized.as_bytes());
        }

        // Smart reconstruction: use marker inference to preserve marker placement
        let reconstructed = self.perform_smart_reconstruction(path, &sealed_current, rendered_str)?;
        self.write_raw_to_backing(path, reconstructed.as_bytes())
    }


    /// Internal lookup implementation that returns Result
    fn lookup_impl(&mut self, parent: u64, name: &OsStr) -> Result<(u64, FileAttr)> {
        // Handle .overlay synthetic directory
        let parent_entry = if parent == SYNTHETIC_OVERLAY_DIR_INO {
            InodeEntry {
                _ino: SYNTHETIC_OVERLAY_DIR_INO,
                path: PathBuf::from("/.overlay"),
                parent: ROOT_INO,
            }
        } else {
            self.get_inode(parent)
                .ok_or_else(|| anyhow!("Parent inode not found"))?
        };

        // Construct virtual path for the file
        let virtual_path = parent_entry.path.join(name);

        // Use translate_virtual_to_source to properly handle .overlay/ paths
        let (source_rel_path, pinned) = self.translate_virtual_to_source(&virtual_path);

        // Hide git-related files from FUSE view (but not in .overlay passthrough)
        if pinned.virtual_prefix != Path::new("/.overlay")
            && let Some(name_str) = name.to_str()
                && Self::should_hide(name_str) {
                    return Err(anyhow!("File hidden"));
                }

        let rel_path = if source_rel_path.as_os_str().is_empty() {
            Path::new(".")
        } else {
            &source_rel_path
        };

        let metadata = self.metadata_via_fd(rel_path)?;

        // Get or create inode
        let ino = self.get_or_create_inode(&virtual_path, parent);
        let is_passthrough = pinned.virtual_prefix == Path::new("/.overlay");
        let size_override = if is_passthrough {
            None
        } else {
            self.compute_size_override(ino, &metadata)
        };
        let attr = self.metadata_to_attr(ino, &metadata, size_override, false);

        Ok((ino, attr))
    }

    /// Parse virtual file name and determine file mode
    /// Returns (actual_name, file_mode)
    fn parse_virtual_file_mode(name: &OsStr) -> (&OsStr, FileMode) {
        if let Some(name_str) = name.to_str() {
            if let Some(actual) = name_str.strip_suffix(".sss-sealed") {
                (std::ffi::OsStr::new(actual), FileMode::Sealed)
            } else if let Some(actual) = name_str.strip_suffix(".sss-opened") {
                (std::ffi::OsStr::new(actual), FileMode::Opened)
            } else {
                (name, FileMode::Rendered)
            }
        } else {
            (name, FileMode::Rendered)
        }
    }

    /// Strip virtual suffix (.sss-opened) from path if present
    fn strip_virtual_suffix(path: &Path, is_opened_mode: bool) -> PathBuf {
        if is_opened_mode {
            let path_str = path.to_string_lossy();
            if let Some(stripped) = path_str.strip_suffix(".sss-opened") {
                PathBuf::from(stripped)
            } else {
                path.to_path_buf()
            }
        } else {
            path.to_path_buf()
        }
    }

    /// Pre-cache file content based on mode flags.
    ///
    /// Returns a [`PlaintextBuf`] (`Zeroizing<Vec<u8>>`) so the decrypted bytes are
    /// volatile-zeroed when the handle drops (REM-15).
    fn precache_for_open(&self, file_path: &Path, is_sealed_mode: bool, is_opened_mode: bool, writable: bool) -> Option<PlaintextBuf> {
        fuse_debug!("  precache: path={:?} sealed={} opened={} writable={}", file_path, is_sealed_mode, is_opened_mode, writable);
        let result = if is_sealed_mode {
            // Sealed mode: pre-cache raw sealed content with ⊠{} markers
            fuse_debug!("  precache: reading sealed");
            self.read_sealed(file_path).ok().map(Zeroizing::new)
        } else if is_opened_mode {
            // Opened mode: pre-cache with ⊕{} markers
            fuse_debug!("  precache: reading opened");
            self.read_and_open(file_path).ok().map(Zeroizing::new)
        } else {
            // Normal mode (read-only or writable): pre-render so that
            // getattr reports the correct rendered size rather than the
            // on-disk size (which includes encrypted markers and differs).
            // For writable files the cached content is updated in-place by
            // write() and flushed/sealed in release(), so precaching is safe.
            fuse_debug!("  precache: reading rendered (writable={})", writable);
            self.read_and_render(file_path).ok().map(Zeroizing::new)
        };
        fuse_debug!("  precache: done, got={}bytes", result.as_ref().map_or(0, |c| c.len()));
        result
    }

    /// Get content for file handle based on its mode.
    ///
    /// Returns a [`PlaintextBuf`] (`Zeroizing<Vec<u8>>`) so the decrypted bytes are
    /// volatile-zeroed when the caller drops the buffer (REM-15).
    fn get_handle_content(&self, handle: &FileHandle) -> Result<PlaintextBuf> {
        if handle.opened_mode {
            // Opened mode: return content with ⊕{} markers
            self.read_and_open(&handle.path).map(Zeroizing::new)
        } else if let Some(ref cached) = handle.cached_content {
            // Use cached content — clone propagates the Zeroizing wrapper (REM-15)
            Ok(cached.clone())
        } else {
            // Render normally
            self.read_and_render(&handle.path).map(Zeroizing::new)
        }
    }

    /// Open directory via file descriptor (safe wrapper around openat/fdopendir)
    fn open_dir_fd(&self, rel_path: &Path) -> Result<*mut libc::DIR> {
        use std::os::unix::ffi::OsStrExt;

        // macOS has issues with fdopendir() in FUSE contexts - it can hang
        // Use direct opendir() with absolute path instead
        #[cfg(target_os = "macos")]
        {
            let full_path = self.source_path.join(rel_path);
            let path_cstr = std::ffi::CString::new(full_path.as_os_str().as_bytes())
                .map_err(|_| anyhow!("Invalid path for CString"))?;

            // SAFETY: `path_cstr` is a valid NUL-terminated absolute path.
            // `opendir` returns a DIR* or NULL on error; checked immediately.
            let dir_ptr = unsafe { libc::opendir(path_cstr.as_ptr()) };
            if dir_ptr.is_null() {
                return Err(anyhow!("opendir failed: {}", std::io::Error::last_os_error()));
            }

            return Ok(dir_ptr);
        }

        // Linux: use openat + fdopendir for proper FD-relative operations
        #[cfg(target_os = "linux")]
        {
            let path_bytes = rel_path.as_os_str().as_bytes();
            let path_cstr = std::ffi::CString::new(path_bytes)
                .map_err(|_| anyhow!("Invalid path for CString"))?;

            // SAFETY: `self.source_fd` is valid. `path_cstr` is NUL-terminated.
            // O_RDONLY|O_DIRECTORY ensures we only open a directory. Error checked immediately.
            // O_CLOEXEC: prevents this dir fd from being inherited by child processes (REM-17 / CR-01).
            let dir_fd = unsafe {
                libc::openat(self.source_fd, path_cstr.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC)
            };

            if dir_fd < 0 {
                return Err(anyhow!("openat failed: {}", std::io::Error::last_os_error()));
            }

            // SAFETY: `dir_fd` is a valid directory fd (>= 0). `fdopendir` takes ownership;
            // if it fails (returns NULL) we close `dir_fd` manually to avoid a leak.
            let dir_ptr = unsafe { libc::fdopendir(dir_fd) };
            if dir_ptr.is_null() {
                // SAFETY: `dir_fd` is still valid; fdopendir failed so we own it.
                unsafe { libc::close(dir_fd); }
                return Err(anyhow!("fdopendir failed"));
            }

            Ok(dir_ptr)
        }
    }

    /// Read all entries from an open directory using pinned path operations
    fn read_dir_entries_with_operations(&mut self, dir_ptr: *mut libc::DIR, parent_ino: u64, parent_path: &Path, operations: &dyn FileOperations)
        -> Vec<(u64, FileType, String)> {
        let mut items = Vec::new();
        let mut _count = 0;

        // SAFETY: `dir_ptr` is a valid non-null DIR* obtained from `open_dir_fd`.
        // `readdir` returns a pointer to a static dirent buffer owned by the DIR stream;
        // the pointer is valid until the next `readdir`/`closedir` call. We copy all
        // needed fields (d_name, d_type) before the next iteration. `__errno_location`
        // and `__error` return a valid per-thread errno pointer; dereferencing to reset
        // it is safe in a single-threaded FUSE callback context.
        unsafe {
            loop {
                // Reset errno before readdir
                #[cfg(target_os = "linux")]
                { *libc::__errno_location() = 0; }
                #[cfg(target_os = "macos")]
                { *libc::__error() = 0; }

                let entry_ptr = libc::readdir(dir_ptr);

                if entry_ptr.is_null() {
                    break;
                }

                let dirent = &*entry_ptr;
                let name = std::ffi::CStr::from_ptr(dirent.d_name.as_ptr())
                    .to_string_lossy()
                    .to_string();


                // Skip . and ..
                if name == "." || name == ".." {
                    continue;
                }

                // Use operations from pinned path for hiding logic
                if operations.should_hide(&name) {
                    continue;
                }

                let virtual_path = parent_path.join(&name);
                let child_ino = self.get_or_create_inode(&virtual_path, parent_ino);

                let file_type = if dirent.d_type == libc::DT_DIR {
                    FileType::Directory
                } else {
                    FileType::RegularFile
                };

                items.push((child_ino, file_type, name));
                _count += 1;
            }
        }

        items
    }

    /// Compute size override for cached/rendered content
    /// Checks file handles first, then falls back to render cache
    fn compute_size_override(&self, ino: u64, metadata: &fs::Metadata) -> Option<u64> {
        if !metadata.is_file() {
            return None;
        }

        // Check file handles for cached content
        let handles = self.file_handles.read();
        let handle_size = handles.values()
            .find(|h| h.ino == ino && h.cached_content.is_some())
            .and_then(|h| h.cached_content.as_ref())
            .map(|content| content.len() as u64);

        if handle_size.is_some() {
            return handle_size;
        }
        drop(handles);

        // Check render cache
        {
            let cache = self.render_cache.read();
            if let Some(content) = cache.get(&ino) {
                return Some(content.len() as u64);
            }
        }

        // Nothing cached yet — eagerly render files with markers so that
        // getattr/lookup report the correct (rendered) size instead of the
        // on-disk size.  Without this, editors like vim see the larger
        // on-disk size, read fewer rendered bytes, and display trailing NULs.
        let entry = self.get_inode(ino)?;
        let (source_rel_path, pinned) = self.translate_virtual_to_source(&entry.path);
        if pinned.virtual_prefix == Path::new("/.overlay") {
            return None; // passthrough — on-disk size is correct
        }

        // Quick byte-level scan: only render if markers are present
        let bytes = self.read_file_via_fd(&source_rel_path).ok()?;
        if !has_any_markers_bytes(&bytes) {
            return None; // no markers — on-disk size matches rendered size
        }

        // WR-01 (SC3 / VMNT-03 "never retain resolved secrets"): if this file is
        // vault-backed, do NOT render-and-cache here. Rendering would resolve the
        // ⊳{} refs and stash the resolved plaintext in `render_cache` for the
        // unbounded getattr→release window — inconsistent with the read path's
        // precache bypass. Reuse the raw bytes already read above (no second fd
        // read) and report the on-disk size as the approximation; the kernel
        // re-reads via read() → read_and_render and, because vault files are
        // FOPEN_DIRECT_IO, will not trust this size. Non-gated: on non-vault builds
        // bytes_have_vault_refs is always false, so this is a no-op there.
        if !should_cache_rendered_size(bytes_have_vault_refs(&bytes)) {
            return None;
        }

        // File has markers — render and cache to get the true size
        let file_path = self.source_path.join(&source_rel_path);
        match self.read_and_render(&file_path) {
            Ok(content) => {
                let size = content.len() as u64;
                // Wrap in PlaintextBuf so the cached bytes are volatile-zeroed on eviction (REM-15)
                self.render_cache.write().insert(ino, Zeroizing::new(content));
                Some(size)
            }
            Err(_) => None,
        }
    }

    /// Resolve entry path to relative path suitable for fd operations
    /// Handles prefix stripping and empty path conversion to "."
    fn resolve_rel_path(&self, entry_path: &Path) -> std::borrow::Cow<'static, Path> {
        // Use translate_virtual_to_source to properly handle .overlay/ paths
        let (source_rel_path, _pinned) = self.translate_virtual_to_source(entry_path);

        
        if source_rel_path.as_os_str().is_empty() {
            std::borrow::Cow::Borrowed(Path::new("."))
        } else {
            std::borrow::Cow::Owned(source_rel_path)
        }
    }

    /// Map an inode to the backing source file path that xattr queries should target.
    /// Strips virtual suffixes (.sss-opened/.sss-sealed) so xattrs are read from the
    /// real underlying file, and handles the synthetic .overlay root specially.
    fn resolve_source_for_xattr(&self, ino: u64) -> Option<PathBuf> {
        if ino == SYNTHETIC_OVERLAY_DIR_INO {
            return Some(PathBuf::from("."));
        }
        let entry = self.get_inode(ino)?;
        let virtual_path = entry.path.clone();

        let stripped = if let Some(name) = virtual_path.file_name() {
            let (actual, _mode) = Self::parse_virtual_file_mode(name);
            if actual != name {
                let parent = virtual_path.parent().unwrap_or(Path::new(""));
                parent.join(actual)
            } else {
                virtual_path
            }
        } else {
            virtual_path
        };

        let (rel, _pinned) = self.translate_virtual_to_source(&stripped);
        Some(rel)
    }

    /// Open an fd for xattr operations against a source-relative path. Returns a raw
    /// fd that the caller MUST close (-1 on error, errno set via last_os_error).
    /// Uses O_PATH|O_NOFOLLOW on Linux so we can inspect symlinks and special files
    /// without opening them for I/O; fgetxattr on O_PATH fds has been supported since
    /// Linux 4.17 (RHEL 8 kernel is 4.18+).
    #[cfg(target_os = "linux")]
    fn open_fd_for_xattr(&self, rel_path: &Path) -> i32 {
        use std::os::unix::ffi::OsStrExt;
        let path_bytes = rel_path.as_os_str().as_bytes();
        let path_cstr = match std::ffi::CString::new(path_bytes) {
            Ok(c) => c,
            Err(_) => return -1,
        };
        // SAFETY: `self.source_fd` is a valid dir fd held for the lifetime of SssFS.
        // `path_cstr` is NUL-terminated. O_PATH|O_NOFOLLOW opens the dirent itself
        // without following the final symlink and without acquiring a read reference.
        unsafe {
            libc::openat(
                self.source_fd,
                path_cstr.as_ptr(),
                libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        }
    }

    /// Implementation of getxattr passthrough.
    #[cfg(target_os = "linux")]
    fn xattr_get_impl(&self, rel_path: &Path, name: &OsStr, size: u32, reply: fuser::ReplyXattr) {
        use std::os::unix::ffi::OsStrExt;

        let fd = self.open_fd_for_xattr(rel_path);
        if fd < 0 {
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(libc::EIO);
            reply.error(errno);
            return;
        }

        let name_cstr = match std::ffi::CString::new(name.as_bytes()) {
            Ok(c) => c,
            Err(_) => {
                // SAFETY: `fd` was just opened via openat() above and is >=0.
                unsafe { libc::close(fd); }
                reply.error(libc::EINVAL);
                return;
            }
        };

        // When size=0 the kernel just wants the size of the value; otherwise we
        // must fill the provided buffer or return ERANGE.
        let (ret, buf): (libc::ssize_t, Vec<u8>) = if size == 0 {
            // SAFETY: `fd` is a valid O_PATH fd. `name_cstr` is NUL-terminated.
            // Passing NULL buffer with size=0 is well-defined — returns value size.
            let r = unsafe {
                libc::fgetxattr(fd, name_cstr.as_ptr(), std::ptr::null_mut(), 0)
            };
            (r, Vec::new())
        } else {
            let mut buf = vec![0u8; size as usize];
            // SAFETY: `fd` is valid, `name_cstr` NUL-terminated, `buf` is a heap slice
            // of exactly `size` bytes. fgetxattr writes at most `size` bytes.
            let r = unsafe {
                libc::fgetxattr(
                    fd,
                    name_cstr.as_ptr(),
                    buf.as_mut_ptr() as *mut libc::c_void,
                    size as usize,
                )
            };
            (r, buf)
        };
        let errno = if ret < 0 {
            std::io::Error::last_os_error().raw_os_error().unwrap_or(libc::ENOTSUP)
        } else { 0 };
        // SAFETY: close the fd opened above regardless of success.
        unsafe { libc::close(fd); }

        if ret < 0 {
            reply.error(errno);
        } else if size == 0 {
            reply.size(ret as u32);
        } else {
            reply.data(&buf[..ret as usize]);
        }
    }

    /// Implementation of listxattr passthrough.
    #[cfg(target_os = "linux")]
    fn xattr_list_impl(&self, rel_path: &Path, size: u32, reply: fuser::ReplyXattr) {
        let fd = self.open_fd_for_xattr(rel_path);
        if fd < 0 {
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(libc::EIO);
            reply.error(errno);
            return;
        }

        let (ret, buf): (libc::ssize_t, Vec<u8>) = if size == 0 {
            // SAFETY: fd valid, NULL buffer with size 0 is documented behaviour.
            let r = unsafe {
                libc::flistxattr(fd, std::ptr::null_mut(), 0)
            };
            (r, Vec::new())
        } else {
            let mut buf = vec![0u8; size as usize];
            // SAFETY: fd valid; buf is a heap slice of exactly `size` bytes.
            let r = unsafe {
                libc::flistxattr(fd, buf.as_mut_ptr() as *mut libc::c_char, size as usize)
            };
            (r, buf)
        };
        let errno = if ret < 0 {
            std::io::Error::last_os_error().raw_os_error().unwrap_or(libc::ENOTSUP)
        } else { 0 };
        // SAFETY: close the fd opened above.
        unsafe { libc::close(fd); }

        if ret < 0 {
            reply.error(errno);
        } else if size == 0 {
            reply.size(ret as u32);
        } else {
            reply.data(&buf[..ret as usize]);
        }
    }

    /// Non-Linux fallback — we don't have fd-relative xattr on macOS (macFUSE adds a
    /// position argument and HFS/APFS xattrs aren't used by SELinux tooling anyway).
    #[cfg(not(target_os = "linux"))]
    fn xattr_get_impl(&self, _rel_path: &Path, _name: &OsStr, _size: u32, reply: fuser::ReplyXattr) {
        reply.error(libc::ENOTSUP);
    }

    #[cfg(not(target_os = "linux"))]
    fn xattr_list_impl(&self, _rel_path: &Path, _size: u32, reply: fuser::ReplyXattr) {
        reply.error(libc::ENOTSUP);
    }
}

impl Filesystem for SssFS {
    /// Initialize filesystem - called when FUSE connection is established
    fn init(
        &mut self,
        _req: &Request<'_>,
        _config: &mut fuser::KernelConfig,
    ) -> Result<(), libc::c_int> {
        fuse_debug!("========== FUSE INIT ==========");
        fuse_debug!("source={:?} pinned_paths={}", self.source_path, self.pinned_paths.len());

        for (_idx, _pinned) in self.pinned_paths.iter().enumerate() {
        }

        fuse_debug!("INIT complete");
        Ok(())
    }

    /// Destroy filesystem - called when FUSE connection is terminated
    fn destroy(&mut self) {
        fuse_debug!("========== FUSE DESTROY ==========");
    }

    /// Get file attributes by inode
    #[allow(clippy::too_many_lines)] // vault synthetic-inode branches added in 49-03
    fn getattr(&mut self, _req: &Request<'_>, ino: u64, fh: Option<u64>, reply: ReplyAttr) {
        let _ = fh; // SssFS tracks handles internally; fh from kernel not needed
        let _start = Instant::now();
        fuse_debug!("getattr ino={}", ino);

        // Synthetic `.sss/` control directory and `vault-status` file (vault-gated).
        // Full special-cases: NEVER routed through `metadata_via_fd` (Pitfall 6).
        #[cfg(feature = "vault")]
        {
            if ino == SYNTHETIC_SSS_DIR_INO {
                let now = std::time::SystemTime::now();
                let attr = FileAttr {
                    ino: SYNTHETIC_SSS_DIR_INO,
                    size: 0,
                    blocks: 0,
                    atime: now,
                    mtime: now,
                    ctime: now,
                    crtime: now,
                    kind: FileType::Directory,
                    perm: 0o555,
                    nlink: 2,
                    uid: 0,
                    gid: 0,
                    rdev: 0,
                    blksize: 512,
                    flags: 0,
                };
                reply.attr(&TTL_ZERO, &attr);
                return;
            }
            if ino == SYNTHETIC_VAULT_STATUS_INO {
                // Size computed from the current state each call (Pitfall 6: must match read).
                let content = self.vault_status_content();
                let now = std::time::SystemTime::now();
                let attr = FileAttr {
                    ino: SYNTHETIC_VAULT_STATUS_INO,
                    size: content.len() as u64,
                    blocks: 0,
                    atime: now,
                    mtime: now,
                    ctime: now,
                    crtime: now,
                    kind: FileType::RegularFile,
                    perm: 0o444,
                    nlink: 1,
                    uid: 0,
                    gid: 0,
                    rdev: 0,
                    blksize: 512,
                    flags: 0,
                };
                reply.attr(&TTL_ZERO, &attr);
                return;
            }
        }

        // Handle synthetic .overlay directory
        if ino == SYNTHETIC_OVERLAY_DIR_INO {
            // Get attributes from the actual source directory — mirror all metadata
            match self.metadata_via_fd(Path::new(".")) {
                Ok(metadata) => {
                    let attr = FileAttr {
                        ino: SYNTHETIC_OVERLAY_DIR_INO,
                        size: metadata.len(),
                        blocks: Self::get_blocks(&metadata),
                        atime: metadata.accessed().unwrap_or(UNIX_EPOCH),
                        mtime: metadata.modified().unwrap_or(UNIX_EPOCH),
                        ctime: Self::get_ctime(&metadata),
                        crtime: metadata.created().unwrap_or(UNIX_EPOCH),
                        kind: FileType::Directory,
                        perm: Self::get_permissions(&metadata),
                        nlink: Self::get_nlink(&metadata) as u32,
                        uid: Self::get_uid(&metadata),
                        gid: Self::get_gid(&metadata),
                        rdev: Self::get_rdev(&metadata),
                        blksize: Self::get_blksize(&metadata),
                        flags: 0,
                    };
                    reply.attr(&TTL, &attr);
                }
                Err(_e) => {
                    reply.error(libc::EIO);
                }
            }
            return;
        }

        let entry = match self.get_inode(ino) {
            Some(e) => {
                e
            }
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        // Translate virtual path to source path using pinned paths
        let (source_rel_path, pinned) = self.translate_virtual_to_source(&entry.path);

        match self.metadata_via_fd(&source_rel_path) {
            Ok(metadata) => {
                let is_passthrough = pinned.virtual_prefix == Path::new("/.overlay");

                let _is_opened_mode = entry.path.to_str()
                    .map(|s| s.ends_with(".sss-opened"))
                    .unwrap_or(false);

                // Compute size override for rendered/opened modes (passthrough = no override)
                let size_override = if is_passthrough {
                    None
                } else {
                    self.compute_size_override(ino, &metadata)
                };

                // Build FileAttr — mirror all original metadata
                let kind = if metadata.is_dir() {
                    FileType::Directory
                } else if metadata.is_symlink() {
                    FileType::Symlink
                } else {
                    FileType::RegularFile
                };

                let size = size_override.unwrap_or(metadata.len());

                let attr = FileAttr {
                    ino,
                    size,
                    blocks: Self::get_blocks(&metadata),
                    atime: metadata.accessed().unwrap_or(UNIX_EPOCH),
                    mtime: metadata.modified().unwrap_or(UNIX_EPOCH),
                    ctime: Self::get_ctime(&metadata),
                    crtime: metadata.created().unwrap_or(UNIX_EPOCH),
                    kind,
                    perm: Self::get_permissions(&metadata),
                    nlink: Self::get_nlink(&metadata) as u32,
                    uid: Self::get_uid(&metadata),
                    gid: Self::get_gid(&metadata),
                    rdev: Self::get_rdev(&metadata),
                    blksize: Self::get_blksize(&metadata),
                    flags: 0,
                };

                reply.attr(&TTL, &attr);
            }
            Err(_e) => {
                reply.error(libc::ENOENT);
            }
        }
    }

    /// Lookup entry in directory
    #[allow(clippy::too_many_lines)] // vault synthetic-inode branches added in 49-03
    fn lookup(&mut self, _req: &Request, parent: u64, name: &OsStr, reply: ReplyEntry) {
        let _start = Instant::now();
        fuse_debug!("lookup parent={} name={:?}", parent, name);

        // Special case: looking up ".overlay" from root
        if parent == ROOT_INO && name == ".overlay" {
            match self.metadata_via_fd(Path::new(".")) {
                Ok(metadata) => {
                    let attr = FileAttr {
                        ino: SYNTHETIC_OVERLAY_DIR_INO,
                        size: metadata.len(),
                        blocks: Self::get_blocks(&metadata),
                        atime: metadata.accessed().unwrap_or(UNIX_EPOCH),
                        mtime: metadata.modified().unwrap_or(UNIX_EPOCH),
                        ctime: Self::get_ctime(&metadata),
                        crtime: metadata.created().unwrap_or(UNIX_EPOCH),
                        kind: FileType::Directory,
                        perm: Self::get_permissions(&metadata),
                        nlink: Self::get_nlink(&metadata) as u32,
                        uid: Self::get_uid(&metadata),
                        gid: Self::get_gid(&metadata),
                        rdev: Self::get_rdev(&metadata),
                        blksize: Self::get_blksize(&metadata),
                        flags: 0,
                    };
                    reply.entry(&TTL, &attr, 0);
                }
                Err(_) => {
                    reply.error(libc::EIO);
                }
            }
            return;
        }

        // Synthetic `.sss/` control directory + `vault-status` file lookups (vault-gated).
        // Full special-cases: NEVER routed through `metadata_via_fd` (Pitfall 6).
        #[cfg(feature = "vault")]
        {
            // WR-02: the synthetic `.sss` is a best-effort control surface that
            // YIELDS to real user data. Only resolve it synthetically when there is
            // NO real `.sss` in the backing root; otherwise fall through to the
            // normal lookup path below, which serves the real directory via
            // metadata_via_fd. Real data wins (vault-status is then unavailable).
            if parent == ROOT_INO
                && name == ".sss"
                && should_inject_synthetic_sss(self.real_sss_dir_present())
            {
                let now = std::time::SystemTime::now();
                let attr = FileAttr {
                    ino: SYNTHETIC_SSS_DIR_INO,
                    size: 0,
                    blocks: 0,
                    atime: now,
                    mtime: now,
                    ctime: now,
                    crtime: now,
                    kind: FileType::Directory,
                    perm: 0o555,
                    nlink: 2,
                    uid: 0,
                    gid: 0,
                    rdev: 0,
                    blksize: 512,
                    flags: 0,
                };
                reply.entry(&TTL_ZERO, &attr, 0);
                return;
            }
            if parent == SYNTHETIC_SSS_DIR_INO && name == "vault-status" {
                let content = self.vault_status_content();
                let now = std::time::SystemTime::now();
                let attr = FileAttr {
                    ino: SYNTHETIC_VAULT_STATUS_INO,
                    size: content.len() as u64,
                    blocks: 0,
                    atime: now,
                    mtime: now,
                    ctime: now,
                    crtime: now,
                    kind: FileType::RegularFile,
                    perm: 0o444,
                    nlink: 1,
                    uid: 0,
                    gid: 0,
                    rdev: 0,
                    blksize: 512,
                    flags: 0,
                };
                reply.entry(&TTL_ZERO, &attr, 0);
                return;
            }
        }

        // Handle lookups within .overlay/ - parent is synthetic, build path manually
        let parent_entry = if parent == SYNTHETIC_OVERLAY_DIR_INO {
            // Parent is .overlay synthetic directory
            InodeEntry {
                _ino: SYNTHETIC_OVERLAY_DIR_INO,
                path: PathBuf::from("/.overlay"),
                parent: ROOT_INO,
            }
        } else {
            // Get parent entry from inode table
            match self.get_inode(parent) {
                Some(e) => e,
                None => {
                    reply.error(libc::ENOENT);
                    return;
                }
            }
        };


        // Parse virtual file mode (.sss-sealed, .sss-opened, or normal)
        let (actual_name, file_mode) = Self::parse_virtual_file_mode(name);
        let is_opened_mode = matches!(file_mode, FileMode::Opened);

        // Build virtual path
        let virtual_path = if is_opened_mode {
            parent_entry.path.join(name) // Keep .sss-opened suffix
        } else {
            parent_entry.path.join(actual_name)
        };


        // Translate to source path using pinned paths
        let (source_rel_path, pinned) = self.translate_virtual_to_source(&virtual_path);


        // Check if should hide (only for normal SSS paths, not passthrough)
        if pinned.virtual_prefix != Path::new("/.overlay")
            && let Some(name_str) = actual_name.to_str()
                && pinned.operations.should_hide(name_str) {
                    reply.error(libc::ENOENT);
                    return;
                }

        // Get metadata
        match self.metadata_via_fd(&source_rel_path) {
            Ok(metadata) => {
                let ino = self.get_or_create_inode(&virtual_path, parent);

                let is_passthrough = pinned.virtual_prefix == Path::new("/.overlay");

                let size_override = if is_passthrough || matches!(file_mode, FileMode::Sealed) {
                    None
                } else {
                    self.compute_size_override(ino, &metadata)
                };

                // Build FileAttr — mirror all original metadata
                let kind = if metadata.is_dir() {
                    FileType::Directory
                } else if metadata.is_symlink() {
                    FileType::Symlink
                } else {
                    FileType::RegularFile
                };

                let size = size_override.unwrap_or(metadata.len());

                let attr = FileAttr {
                    ino,
                    size,
                    blocks: Self::get_blocks(&metadata),
                    atime: metadata.accessed().unwrap_or(UNIX_EPOCH),
                    mtime: metadata.modified().unwrap_or(UNIX_EPOCH),
                    ctime: Self::get_ctime(&metadata),
                    crtime: metadata.created().unwrap_or(UNIX_EPOCH),
                    kind,
                    perm: Self::get_permissions(&metadata),
                    nlink: Self::get_nlink(&metadata) as u32,
                    uid: Self::get_uid(&metadata),
                    gid: Self::get_gid(&metadata),
                    rdev: Self::get_rdev(&metadata),
                    blksize: Self::get_blksize(&metadata),
                    flags: 0,
                };

                // Use zero TTL for passthrough files to disable kernel caching
                // This prevents stale negative lookups after rename operations
                let ttl = if is_passthrough { &TTL_ZERO } else { &TTL };
                reply.entry(ttl, &attr, 0);
            }
            Err(_e) => {
                reply.error(libc::ENOENT);
            }
        }
    }

    /// Read directory contents
    fn readdir(
        &mut self,
        _req: &Request,
        ino: u64,
        _fh: u64,
        offset: i64,
        mut reply: ReplyDirectory,
    ) {
        let _start = Instant::now();
        fuse_debug!("readdir ino={} offset={}", ino, offset);

        // Synthetic `.sss/` control directory readdir — fully virtual, no backing fd.
        // NEVER routed through `open_dir_fd` / `metadata_via_fd` (Pitfall 6).
        #[cfg(feature = "vault")]
        if ino == SYNTHETIC_SSS_DIR_INO {
            let items = [
                (SYNTHETIC_SSS_DIR_INO, FileType::Directory, "."),
                (ROOT_INO, FileType::Directory, ".."),
                (SYNTHETIC_VAULT_STATUS_INO, FileType::RegularFile, "vault-status"),
            ];
            let offset_usize = usize::try_from(offset).unwrap_or(0);
            for (i, &(entry_ino, kind, name)) in items.iter().enumerate().skip(offset_usize) {
                #[allow(clippy::cast_possible_wrap)]
                if reply.add(entry_ino, (i + 1) as i64, kind, name) {
                    break;
                }
            }
            reply.ok();
            return;
        }

        // Handle .overlay/ - parent is synthetic, build entry manually
        let entry = if ino == SYNTHETIC_OVERLAY_DIR_INO {
            InodeEntry {
                _ino: SYNTHETIC_OVERLAY_DIR_INO,
                path: PathBuf::from("/.overlay"),
                parent: ROOT_INO,
            }
        } else {
            // Get directory entry from inode table
            match self.get_inode(ino) {
                Some(e) => {
                    e
                },
                None => {
                    reply.error(libc::ENOENT);
                    return;
                }
            }
        };

        // Translate virtual path to source path using pinned paths
        let (source_rel_path, pinned) = self.translate_virtual_to_source(&entry.path);
        // Clone the operations Arc to avoid holding a borrow on self
        let operations = pinned.operations.clone();

        // Open directory via FD
        let dir_ptr = match self.open_dir_fd(&source_rel_path) {
            Ok(p) => {
                p
            },
            Err(_e) => {
                reply.error(libc::EIO);
                return;
            }
        };

        // Build entry list: . and .. first
        let mut items = vec![
            (ino, FileType::Directory, ".".to_string()),
            (entry.parent, FileType::Directory, "..".to_string()),
        ];

        // Read directory entries - use pinned path operations for filtering
        let entries = self.read_dir_entries_with_operations(dir_ptr, ino, &entry.path, &*operations);
        items.extend(entries);

        // If this is the root directory, add synthetic .overlay directory and (vault-gated) .sss/
        if ino == ROOT_INO {
            items.push((SYNTHETIC_OVERLAY_DIR_INO, FileType::Directory, ".overlay".to_string()));
            // WR-02: the synthetic `.sss` control directory YIELDS to real user
            // data. Emit it ONLY when no real `.sss` is already in the listing
            // (collected above by read_dir_entries_with_operations) — never a
            // duplicate. If a real `.sss` exists it wins, served normally, and the
            // synthetic vault-status surface is simply unavailable. We test the
            // collected `items` directly (rather than re-stat) so the listing can
            // never carry two `.sss` entries regardless of backing-store state.
            #[cfg(feature = "vault")]
            {
                let real_sss_listed = items.iter().any(|(_, _, name)| name == ".sss");
                if should_inject_synthetic_sss(real_sss_listed) {
                    items.push((SYNTHETIC_SSS_DIR_INO, FileType::Directory, ".sss".to_string()));
                }
            }
        }

        // Close directory
        // SAFETY: `dir_ptr` is a valid non-null DIR* from `open_dir_fd`; closedir is the
        // matching cleanup call. Not called again after this point.
        unsafe { libc::closedir(dir_ptr); }

        // Send entries to FUSE
        let _entry_count = items.len();
        for (i, item) in items.iter().enumerate().skip(offset as usize) {
            if reply.add(item.0, (i + 1) as i64, item.1, &item.2) {
                break;
            }
        }

        reply.ok();
    }

    /// Open a file
    fn open(&mut self, _req: &Request, ino: u64, flags: i32, reply: ReplyOpen) {
        let _start = Instant::now();
        fuse_debug!("open ino={} flags={:#x}", ino, flags);

        // Block opens on synthetic directories (EISDIR) and grant read-only open on the
        // synthetic `vault-status` file (no backing fd needed; read() handles it inline).
        if ino == SYNTHETIC_OVERLAY_DIR_INO {
            reply.error(libc::EISDIR);
            return;
        }
        #[cfg(feature = "vault")]
        {
            if ino == SYNTHETIC_SSS_DIR_INO {
                reply.error(libc::EISDIR);
                return;
            }
            if ino == SYNTHETIC_VAULT_STATUS_INO {
                let _ = flags; // read-only file; write flags rejected silently via FOPEN_DIRECT_IO
                // Allocate a dummy file handle so read() receives a valid fh.
                let fh = {
                    let mut next_fh = self.next_fh.write();
                    let fh = *next_fh;
                    *next_fh += 1;
                    fh
                };
                reply.opened(fh, fuser::consts::FOPEN_DIRECT_IO);
                return;
            }
        }

        let entry = match self.get_inode(ino) {
            Some(e) => e,
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        fuse_debug!("  open: path={:?}", entry.path);

        // Translate virtual path to source path using pinned paths
        let (source_rel_path, pinned) = self.translate_virtual_to_source(&entry.path);
        let is_passthrough = pinned.virtual_prefix == Path::new("/.overlay");

        fuse_debug!("  open: source_rel={:?} passthrough={}", source_rel_path, is_passthrough);

        // Determine file modes (not applicable for passthrough files)
        // Opened mode: detected by nonsense flag combination O_DIRECTORY|O_CREAT
        // (semantically invalid: can't create when opening as directory, so never used by real programs)
        let is_opened_mode = !is_passthrough &&
            (flags & libc::O_DIRECTORY) != 0 &&
            (flags & libc::O_CREAT) != 0;
        // Sealed mode: detected by nonsense flag combination O_RDONLY|O_TRUNC
        // (semantically invalid: can't truncate read-only file, so never used by real programs)
        let is_sealed_mode = !is_passthrough &&
            (flags & libc::O_ACCMODE) == libc::O_RDONLY &&
            (flags & libc::O_TRUNC) != 0;
        let writable = (flags & libc::O_RDWR) != 0 || (flags & libc::O_WRONLY) != 0;

        // Get full file path for handle
        let file_path = if is_passthrough {
            // Passthrough: use source path directly
            self.source_path.join(&source_rel_path)
        } else {
            // SSS mode: use translated source path and strip virtual suffix if opened mode
            let translated_path = self.source_path.join(&source_rel_path);
            Self::strip_virtual_suffix(&translated_path, is_opened_mode)
        };

        // Vault-backed detection (open-time RAW-bytes marker scan). Drives BOTH the
        // precache bypass (so each read() re-fetches — SC3 / research risk 2) and the
        // FOPEN_DIRECT_IO flag (so resolved secrets are not kept in the page cache —
        // VMNT-04). Passthrough files are raw and never vault-resolved. Defined
        // feature-uniform so the downstream precache/flags logic needs no cfg.
        #[cfg(feature = "vault")]
        let vault_backed = !is_passthrough && self.file_has_vault_refs(&file_path);
        #[cfg(not(feature = "vault"))]
        let vault_backed = false;

        fuse_debug!("  open: file_path={:?} writable={} sealed={} opened={}", file_path, writable, is_sealed_mode, is_opened_mode);

        // Generate file handle
        let fh = {
            let mut next_fh = self.next_fh.write();
            let fh = *next_fh;
            *next_fh += 1;
            fh
        };

        fuse_debug!("  open: fh={}, starting precache", fh);

        // Pre-cache content based on mode (skip for passthrough - raw access).
        // Vault-backed files are NEVER precached so each read() drives a fresh
        // read_and_render → fresh VaultRequestCache → fresh Vault fetch; caching
        // would serve stale plaintext on the 2nd read and violate SC3 (research
        // risk 2). With cached_content=None the read() handle path falls through to
        // get_handle_content/read_and_render on every read.
        let cached_content = if should_skip_precache(is_passthrough, vault_backed) {
            None
        } else {
            self.precache_for_open(&file_path, is_sealed_mode, is_opened_mode, writable)
        };

        fuse_debug!("  open: precache done, cached={}bytes", cached_content.as_ref().map_or(0, |c| c.len()));

        // Capture original sealed content from backing store if file is writable
        // This is needed for smart reconstruction when editor truncates file before writing
        // Skip for passthrough files (raw, no markers)
        let original_sealed = if !is_passthrough && writable && !is_sealed_mode && !is_opened_mode {
            let rel_path = file_path.strip_prefix(&self.source_path).unwrap_or(&file_path);
            self.read_file_via_fd(rel_path)
                .ok()
                .and_then(|bytes| String::from_utf8(bytes).ok())
                .filter(|s| has_any_markers(s))
        } else {
            None
        };

        // Open file descriptor for passthrough files to avoid reopening on every operation
        let passthrough_fd = if is_passthrough && writable {
            // Build open flags for passthrough file
            let mut open_flags = if writable {
                if (flags & libc::O_RDWR) != 0 {
                    libc::O_RDWR
                } else {
                    libc::O_WRONLY
                }
            } else {
                libc::O_RDONLY
            };

            // Preserve important flags
            if (flags & libc::O_TRUNC) != 0 {
                open_flags |= libc::O_TRUNC;
            }
            if (flags & libc::O_CREAT) != 0 {
                open_flags |= libc::O_CREAT;
            }
            if (flags & libc::O_EXCL) != 0 {
                open_flags |= libc::O_EXCL;
            }
            // O_CLOEXEC: always set regardless of caller flags — no child process should
            // inherit passthrough fds to the backing secret store (REM-17 / CR-01).
            open_flags |= libc::O_CLOEXEC;

            // Open file via source_fd (with mode 0666 if creating)
            let path_cstr = match std::ffi::CString::new(source_rel_path.as_os_str().as_bytes()) {
                Ok(p) => p,
                Err(_) => {
                    reply.error(libc::EINVAL);
                    return;
                }
            };

            // SAFETY: `self.source_fd` is a valid directory fd. `path_cstr` is NUL-terminated.
            // `open_flags` are caller-supplied FUSE open flags with O_CLOEXEC ORed in.
            // Mode 0o666 applies only with O_CREAT; the actual mode is masked by umask.
            // Error checked immediately.
            let fd = unsafe {
                if (open_flags & libc::O_CREAT) != 0 {
                    libc::openat(self.source_fd, path_cstr.as_ptr(), open_flags, 0o666)
                } else {
                    libc::openat(self.source_fd, path_cstr.as_ptr(), open_flags)
                }
            };

            if fd < 0 {
                let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(libc::EIO);
                reply.error(errno);
                return;
            }

            Some(fd)
        } else {
            None
        };

        // Store file handle
        let mut handle = FileHandle {
            ino,
            path: file_path.clone(),
            cached_content,
            writable,
            dirty: false,
            opened_mode: is_opened_mode,
            sealed_mode: is_sealed_mode,
            origin_mode: is_passthrough,  // Keep field name for now
            passthrough_fd,
            original_sealed,
        };

        // Handle O_TRUNC flag for writable non-passthrough files (but not sealed mode)
        // When a file is opened with O_TRUNC, it should be truncated to zero length immediately
        let should_truncate = !is_passthrough &&
                              writable &&
                              (flags & libc::O_TRUNC) != 0 &&
                              !is_sealed_mode;

        if should_truncate {
            // Truncate the file on disk immediately
            if std::fs::OpenOptions::new()
                .write(true)
                .truncate(true)
                .open(&file_path)
                .is_err()
            {
                reply.error(libc::EIO);
                return;
            }

            // Set cached content to empty since file is now truncated (PlaintextBuf — REM-15)
            handle.cached_content = Some(Zeroizing::new(Vec::new()));
            handle.dirty = false;  // File is already truncated on disk
        }

        self.file_handles.write().insert(fh, handle);

        // FOPEN_DIRECT_IO bypasses the kernel page cache for this inode. Two cases:
        //   (a) passthrough writable files — so mmap writes route through our
        //       handlers instead of the page cache (existing behaviour);
        //   (b) vault-backed files — so resolved secrets are NOT retained in the
        //       page cache after close, and every read() hits read_and_render for a
        //       fresh Vault fetch (VMNT-04 / R2, per-inode — NOT mount-level).
        let flags = if should_set_direct_io(is_passthrough, writable, vault_backed) {
            const FOPEN_DIRECT_IO: u32 = 1 << 0;  // From linux/fuse.h / fuser fuse_abi.rs:148
            FOPEN_DIRECT_IO
        } else {
            0
        };

        reply.opened(fh, flags);
    }

    /// Read file data
    fn read(
        &mut self,
        _req: &Request,
        ino: u64,
        fh: u64,
        offset: i64,
        size: u32,
        _flags: i32,
        _lock: Option<u64>,
        reply: ReplyData,
    ) {
        let _start = Instant::now();
        fuse_debug!("read ino={} fh={} offset={} size={}", ino, fh, offset, size);

        // Synthetic `vault-status` file: generate content in-memory, no backing fd.
        // NEVER routed through the handle/fd path (Pitfall 6; no network call).
        #[cfg(feature = "vault")]
        if ino == SYNTHETIC_VAULT_STATUS_INO {
            let content = self.vault_status_content();
            let bytes = content.as_bytes();
            let offset_usize = usize::try_from(offset).unwrap_or(0);
            let end = std::cmp::min(offset_usize + size as usize, bytes.len());
            if offset_usize < bytes.len() {
                reply.data(&bytes[offset_usize..end]);
            } else {
                reply.data(&[]);
            }
            return;
        }

        // Get content from handle or fall back to direct read
        let handles = self.file_handles.read();
        let content = match handles.get(&fh) {
            Some(handle) => {
                // Origin mode: raw passthrough, read directly from file
                if handle.origin_mode {
                    let path = handle.path.clone();
                    drop(handles);
                    let rel_path = path.strip_prefix(&self.source_path).unwrap_or(&path);
                    match self.read_file_via_fd(rel_path) {
                        // Wrap in PlaintextBuf so the match arms share the same type with
                        // get_handle_content (which now returns Zeroizing<Vec<u8>>) (REM-15)
                        Ok(c) => Zeroizing::new(c),
                        Err(_) => {
                            reply.error(libc::EIO);
                            return;
                        }
                    }
                } else if handle.sealed_mode && handle.cached_content.is_none() {
                    // Sealed mode pending: wait for setxattr confirmation
                    reply.error(libc::EAGAIN);
                    return;
                } else {
                    // Get content based on handle mode
                    match self.get_handle_content(handle) {
                        Ok(c) => c,
                        Err(_e) => {
                            reply.error(libc::EIO);
                            return;
                        }
                    }
                }
            }
            None => {
                drop(handles);

                let entry = match self.get_inode(ino) {
                    Some(e) => e,
                    None => {
                        reply.error(libc::ENOENT);
                        return;
                    }
                };

                // Use translate_virtual_to_source to properly handle .overlay/ paths
                let (source_rel_path, _pinned) = self.translate_virtual_to_source(&entry.path);
                let file_path = self.source_path.join(&source_rel_path);
                match self.read_and_render(&file_path) {
                    // Wrap in PlaintextBuf to match the type produced by all other arms (REM-15)
                    Ok(c) => Zeroizing::new(c),
                    Err(_e) => {
                        reply.error(libc::EIO);
                        return;
                    }
                }
            }
        };

        // Return requested slice
        let offset_usize = offset as usize;
        let end = std::cmp::min(offset_usize + size as usize, content.len());

        if offset_usize < content.len() {
            let _bytes_read = end - offset_usize;
            reply.data(&content[offset_usize..end]);
        } else {
            reply.data(&[]);
        }
    }

    /// Write file data
    fn write(
        &mut self,
        _req: &Request,
        ino: u64,
        fh: u64,
        offset: i64,
        data: &[u8],
        _write_flags: u32,
        _flags: i32,
        _lock: Option<u64>,
        reply: ReplyWrite,
    ) {
        let _start = Instant::now();
        fuse_debug!("write ino={} fh={} offset={} size={}", ino, fh, offset, data.len());
        // Block writes to .git blocking directory only
        if ino == SYNTHETIC_OVERLAY_DIR_INO {
            reply.error(libc::EPERM);
            return;
        }

        let mut handles = self.file_handles.write();
        let handle = match handles.get_mut(&fh) {
            Some(h) => h,
            None => {
                reply.error(libc::EBADF);
                return;
            }
        };

        if !handle.writable {
            reply.error(libc::EBADF);
            return;
        }

        // Block writes to .git/* at project root (unless in origin_mode passthrough via .overlay/)
        if !handle.origin_mode
            && let Ok(rel_path) = handle.path.strip_prefix(&self.source_path) {
                let path_str = rel_path.to_string_lossy();
                if path_str.starts_with(".git/") || path_str == ".git" {
                    reply.error(libc::EPERM);
                    return;
                }
            }

        // For passthrough files (origin_mode), write directly to disk without caching
        // Use the stored fd to avoid reopening on every write (which fixes race conditions)
        if handle.origin_mode {
            let fd = match handle.passthrough_fd {
                Some(fd) => fd,
                None => {
                    reply.error(libc::EIO);
                    return;
                }
            };

            // Use pwrite() for atomic seek+write operation
            // Note: pwrite() may do partial writes, but FUSE handles retries,
            // so we just report how many bytes were actually written
            // SAFETY: `fd` is a valid open file descriptor from `passthrough_fd` (opened in
            // `open`). `data.as_ptr()` points to `data.len()` valid bytes. `pwrite` does
            // not retain the pointer. `offset` is the FUSE-supplied byte offset.
            let bytes_written = unsafe {
                libc::pwrite(
                    fd,
                    data.as_ptr() as *const libc::c_void,
                    data.len(),
                    offset,
                )
            };

            if bytes_written < 0 {
                let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(libc::EIO);
                reply.error(errno);
                return;
            }

            if bytes_written == 0 && !data.is_empty() {
                reply.error(libc::EIO);
                return;
            }

            reply.written(bytes_written as u32);
            return;
        }

        // Non-passthrough files: use caching (for SSS processing)

        // Initialize or extend cached content (PlaintextBuf — volatile-zeroed on drop, REM-15)
        let mut content = handle.cached_content.take().unwrap_or_else(|| Zeroizing::new(Vec::new()));

        // Ensure content is large enough
        let end_offset = offset as usize + data.len();
        if content.len() < end_offset {
            content.resize(end_offset, 0);
        }

        // Write data at offset
        content[offset as usize..end_offset].copy_from_slice(data);

        handle.cached_content = Some(content);
        handle.dirty = true;

        reply.written(data.len() as u32);
    }

    /// Release (close) file
    fn release(
        &mut self,
        _req: &Request,
        _ino: u64,
        fh: u64,
        _flags: i32,
        _lock_owner: Option<u64>,
        _flush: bool,
        reply: fuser::ReplyEmpty,
    ) {
        let _start = Instant::now();
        fuse_debug!("release fh={} flush={}", fh, _flush);
        let mut handles = self.file_handles.write();
        if let Some(handle) = handles.remove(&fh) {
            // Close passthrough fd if present
            if let Some(fd) = handle.passthrough_fd {
                // SAFETY: `fd` is a valid open file descriptor stored in `FileHandle`.
                // We have exclusive access here (handle removed from the map).
                // Not closed anywhere else after removal.
                unsafe {
                    libc::close(fd);
                }
            }

            // If file was written to, seal and write back
            if handle.dirty && handle.writable
                && let Some(content) = handle.cached_content {
                    // Check if this is an origin file (raw passthrough)
                    let write_result = if handle.origin_mode {
                        // Origin mode: write raw without any SSS processing
                        self.write_raw_to_backing(&handle.path, &content)
                    } else {
                        // Normal SSS processing
                        let content_str = String::from_utf8_lossy(&content);

                        // Check if content already has encrypted markers (⊠{})
                        let is_already_sealed = has_encrypted_markers(&content_str);

                        // Check if this file should be processed by sss or written raw
                        if !Self::should_process_with_sss(&handle.path) {
                            // Swap files and temp files: write raw (no sss processing)
                            self.write_raw_to_backing(&handle.path, &content)
                        } else if handle.sealed_mode {
                            // Sealed mode: content is already sealed (⊠{}), write raw to backing store
                            self.write_raw_to_backing(&handle.path, &content)
                        } else if is_already_sealed {
                            // Content already has ⊠{} markers - write directly (no processing)
                            self.write_raw_to_backing(&handle.path, &content)
                        } else if handle.opened_mode {
                            // Opened mode: content has ⊕{} markers, seal directly
                            self.write_sealed_to_backing(&handle.path, &content)
                        } else {
                            // Normal mode: content is rendered, do smart reconstruction
                            // Pass original_sealed if we have it (prevents marker loss when editor truncates)
                            self.write_and_seal(&handle.path, &content, handle.original_sealed.as_ref())
                        }
                    };

                    if let Err(e) = write_result {
                        eprintln!("Error writing file on close: {}", e);
                        reply.error(libc::EIO);
                        return;
                    }

                    // Invalidate render cache
                    self.render_cache.write().remove(&handle.ino);
                }
        }
        reply.ok();
    }

    /// Handle ioctl commands
    ///
    /// Note: ioctl is not supported on macOS with fuse-t. Use virtual file suffixes instead:
    /// - file.txt.sss-opened → opened mode (⊕{} markers)
    /// - file.txt.sss-sealed → sealed mode (⊠{} markers)
    fn ioctl(
        &mut self,
        _req: &Request,
        _ino: u64,
        fh: u64,
        _flags: u32,
        cmd: u32,
        _in_data: &[u8],
        _out_size: u32,
        reply: fuser::ReplyIoctl,
    ) {

        // fuse-t on macOS doesn't support ioctl operations
        // Users should use virtual file suffixes instead:
        //   file.txt.sss-opened for opened mode
        //   file.txt.sss-sealed for sealed mode
        #[cfg(target_os = "macos")]
        {
            reply.error(libc::ENOTTY);
        }

        #[cfg(not(target_os = "macos"))]
        {
            if cmd == SSS_IOC_OPENED_MODE {
                // Enable opened mode for this file handle
                let mut handles = self.file_handles.write();
                if let Some(handle) = handles.get_mut(&fh) {
                    handle.opened_mode = true;
                    // Clear cached content - need to re-read with markers
                    handle.cached_content = None;
                    reply.ioctl(0, &[]);
                } else {
                    reply.error(libc::EBADF);
                }
            } else if cmd == SSS_IOC_SEALED_MODE {
                // Enable sealed mode - requires O_NONBLOCK was used
                let mut handles = self.file_handles.write();
                if let Some(handle) = handles.get_mut(&fh) {
                    if !handle.sealed_mode {
                        reply.error(libc::EINVAL);
                        return;
                    }

                    // O_NONBLOCK was used, now cache sealed content (PlaintextBuf — REM-15)
                    match self.read_sealed(&handle.path) {
                        Ok(content) => {
                            handle.cached_content = Some(Zeroizing::new(content));
                            reply.ioctl(0, &[]);
                        }
                        Err(_e) => {
                            reply.error(libc::EIO);
                        }
                    }
                } else {
                    reply.error(libc::EBADF);
                }
            } else {
                reply.error(libc::ENOTTY);
            }
        }
    }

    /// Set file attributes (permissions, timestamps, etc.)
    fn setattr(
        &mut self,
        _req: &Request,
        ino: u64,
        mode: Option<u32>,
        _uid: Option<u32>,
        _gid: Option<u32>,
        size: Option<u64>,
        _atime: Option<fuser::TimeOrNow>,
        _mtime: Option<fuser::TimeOrNow>,
        _ctime: Option<std::time::SystemTime>,
        _fh: Option<u64>,
        _crtime: Option<std::time::SystemTime>,
        _chgtime: Option<std::time::SystemTime>,
        _bkuptime: Option<std::time::SystemTime>,
        _flags: Option<u32>,
        reply: ReplyAttr,
    ) {
        fuse_debug!("setattr ino={} mode={:?} size={:?}", ino, mode, size);
        // Handle .overlay synthetic directory - return current attributes
        if ino == SYNTHETIC_OVERLAY_DIR_INO {
            match self.metadata_via_fd(Path::new(".")) {
                Ok(metadata) => {
                    let attr = FileAttr {
                        ino: SYNTHETIC_OVERLAY_DIR_INO,
                        size: metadata.len(),
                        blocks: Self::get_blocks(&metadata),
                        atime: metadata.accessed().unwrap_or(UNIX_EPOCH),
                        mtime: metadata.modified().unwrap_or(UNIX_EPOCH),
                        ctime: Self::get_ctime(&metadata),
                        crtime: metadata.created().unwrap_or(UNIX_EPOCH),
                        kind: FileType::Directory,
                        perm: Self::get_permissions(&metadata),
                        nlink: Self::get_nlink(&metadata) as u32,
                        uid: Self::get_uid(&metadata),
                        gid: Self::get_gid(&metadata),
                        rdev: Self::get_rdev(&metadata),
                        blksize: Self::get_blksize(&metadata),
                        flags: 0,
                    };
                    reply.attr(&TTL, &attr);
                }
                Err(_) => {
                    reply.error(libc::EIO);
                }
            }
            return;
        }

        let entry = match self.get_inode(ino) {
            Some(e) => e,
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        let rel_path = self.resolve_rel_path(&entry.path);

        // Handle truncate (size change)
        if let Some(new_size) = size {
            let path_cstr = match CString::new(rel_path.as_os_str().as_bytes()) {
                Ok(p) => p,
                Err(_) => {
                    reply.error(libc::EINVAL);
                    return;
                }
            };

            // Open file and truncate via fd
            // SAFETY: `self.source_fd` is a valid directory fd. `path_cstr` is NUL-terminated.
            // Error checked immediately; `fd` is closed after use.
            // O_CLOEXEC: prevents this fd from being inherited by child processes (REM-17 / CR-01).
            let fd = unsafe {
                libc::openat(
                    self.source_fd,
                    path_cstr.as_ptr(),
                    libc::O_WRONLY | libc::O_CLOEXEC,
                )
            };

            if fd < 0 {
                reply.error(libc::EIO);
                return;
            }

            // SAFETY: `fd` is valid (>= 0). `ftruncate` adjusts the file size.
            // `close` is called unconditionally after (regardless of ftruncate result).
            let result = unsafe { libc::ftruncate(fd, new_size as i64) };
            // SAFETY: `fd` is valid and not closed yet.
            unsafe { libc::close(fd) };

            if result != 0 {
                reply.error(libc::EIO);
                return;
            }

            // Clear render cache for this file
            self.render_cache.write().remove(&ino);

            // IMPORTANT: Clear cached_content in any open file handles for this inode
            // to prevent stale data from being written back on close
            let mut handles = self.file_handles.write();
            for handle in handles.values_mut() {
                if handle.ino == ino {
                    if new_size == 0 {
                        // Truncate to zero - clear all cached content
                        handle.cached_content = None;
                    } else if let Some(ref mut content) = handle.cached_content {
                        // Truncate to specific size
                        content.truncate(new_size as usize);
                    }
                }
            }
        }

        // Handle mode change
        if let Some(new_mode) = mode {
            let path_cstr = match CString::new(rel_path.as_os_str().as_bytes()) {
                Ok(p) => p,
                Err(_) => {
                    reply.error(libc::EINVAL);
                    return;
                }
            };

            // SAFETY: `self.source_fd` is a valid directory fd. `path_cstr` is NUL-terminated.
            // `new_mode` is a valid mode_t from the FUSE request. Error checked immediately.
            let result = unsafe {
                libc::fchmodat(
                    self.source_fd,
                    path_cstr.as_ptr(),
                    new_mode as libc::mode_t,
                    0,
                )
            };

            if result != 0 {
                reply.error(libc::EIO);
                return;
            }
        }

        // Return updated attributes
        match self.metadata_via_fd(&rel_path) {
            Ok(metadata) => {
                let is_opened_mode = entry.path.to_str()
                    .map(|s| s.ends_with(".sss-opened"))
                    .unwrap_or(false);

                let size_override = self.compute_size_override(ino, &metadata);
                let attr = self.metadata_to_attr(ino, &metadata, size_override, is_opened_mode);
                reply.attr(&TTL, &attr);
            }
            Err(_) => reply.error(libc::EIO),
        }
    }

    /// Sync file content (flush writes)
    fn fsync(
        &mut self,
        _req: &Request,
        _ino: u64,
        fh: u64,
        datasync: bool,
        reply: fuser::ReplyEmpty,
    ) {
        let _start = Instant::now();
        fuse_debug!("fsync fh={} datasync={}", fh, datasync);

        // For passthrough files with an fd, sync to flush mmap writes
        let handles = self.file_handles.read();
        if let Some(handle) = handles.get(&fh)
            && let Some(fd) = handle.passthrough_fd {
                let result = if datasync {
                    // macOS doesn't have fdatasync, use fsync or F_FULLFSYNC
                    #[cfg(target_os = "linux")]
                    // SAFETY: `fd` is a valid open file descriptor stored in `passthrough_fd`.
                    // `fdatasync` is always safe to call on a valid fd; return value checked below.
                    unsafe { libc::fdatasync(fd) }
                    #[cfg(target_os = "macos")]
                    // SAFETY: `fd` is a valid open file descriptor stored in `passthrough_fd`.
                    // `fsync` is always safe to call on a valid fd; return value checked below.
                    unsafe { libc::fsync(fd) }
                } else {
                    // SAFETY: `fd` is a valid open file descriptor stored in `passthrough_fd`.
                    // `fsync` is always safe to call on a valid fd; return value checked below.
                    unsafe { libc::fsync(fd) }
                };

                if result < 0 {
                    let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(libc::EIO);
                    reply.error(errno);
                    return;
                }
            }

        reply.ok();
    }

    /// Check file access permissions
    fn access(&mut self, _req: &Request, ino: u64, mask: i32, reply: fuser::ReplyEmpty) {
        let _start = Instant::now();
        fuse_debug!("access ino={} mask={:#x}", ino, mask);

        // Handle synthetic directories
        if ino == SYNTHETIC_OVERLAY_DIR_INO {
            reply.ok();
            return;
        }

        // On macOS, faccessat() can deadlock when called from within FUSE handlers
        // because it may try to access through the FUSE mount itself.
        // Since actual permission checks happen at open/read/write time anyway,
        // we can safely return OK here.
        #[cfg(target_os = "macos")]
        {
            reply.ok();
            return;
        }

        #[cfg(not(target_os = "macos"))]
        {
            let entry = match self.get_inode(ino) {
                Some(e) => {
                    e
                }
                None => {
                    reply.error(libc::ENOENT);
                    return;
                }
            };

            // Translate virtual path to source path
            let (source_rel_path, _pinned) = self.translate_virtual_to_source(&entry.path);

            // Use faccessat to check actual permissions
            let path_cstr = match CString::new(source_rel_path.as_os_str().as_bytes()) {
                Ok(p) => p,
                Err(_) => {
                    reply.error(libc::EINVAL);
                    return;
                }
            };

            // faccessat checks access permissions relative to source_fd
            // SAFETY: `self.source_fd` is a valid directory fd. `path_cstr` is NUL-terminated.
            // `mask` is a valid access mode from the FUSE request. Flags=0 uses normal behavior.
            let result = unsafe {
                libc::faccessat(
                    self.source_fd,
                    path_cstr.as_ptr(),
                    mask,
                    0, // flags
                )
            };

            if result == 0 {
                reply.ok();
            } else {
                // SAFETY: `__errno_location`/`__error` return the per-thread errno pointer.
                // Dereferencing to read errno immediately after the failed syscall is safe.
                let errno = unsafe {
                    #[cfg(target_os = "linux")]
                    { *libc::__errno_location() }
                    #[cfg(target_os = "macos")]
                    { *libc::__error() }
                };
                reply.error(errno);
            }
        }
    }

    /// Flush data before close
    fn flush(
        &mut self,
        _req: &Request,
        // Used only by the vault-gated `vault-status` no-op-flush branch below (F-1);
        // otherwise unused, so suppress the unused-variable lint on non-vault builds.
        #[cfg_attr(not(feature = "vault"), allow(unused_variables))] ino: u64,
        fh: u64,
        _lock_owner: u64,
        reply: fuser::ReplyEmpty,
    ) {
        let _start = Instant::now();
        fuse_debug!("flush fh={}", fh);

        // For passthrough files, sync to flush any mmap'd writes
        let handles = self.file_handles.read();
        if let Some(handle) = handles.get(&fh) {
            if let Some(fd) = handle.passthrough_fd {
                // Use fdatasync for better performance (only data, not metadata)
                // macOS doesn't have fdatasync, use fsync instead
                #[cfg(target_os = "linux")]
                // SAFETY: `fd` is a valid open file descriptor stored in `passthrough_fd`.
                // `fdatasync` is always safe to call on a valid fd; return value checked below.
                let result = unsafe { libc::fdatasync(fd) };
                #[cfg(target_os = "macos")]
                // SAFETY: `fd` is a valid open file descriptor stored in `passthrough_fd`.
                // `fsync` is always safe to call on a valid fd; return value checked below.
                let result = unsafe { libc::fsync(fd) };

                if result < 0 {
                    let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(libc::EIO);
                    reply.error(errno);
                    return;
                }
            }
            reply.ok();
        } else {
            // The synthetic `vault-status` control file is granted a dummy fh with no
            // `file_handles` entry (see `open()`); a flush on it has nothing to sync.
            // Returning EBADF here surfaced as `cat: …/.sss/vault-status: Bad file
            // descriptor` *after* the correct value-free content (UAT F-1). A flush on a
            // backing-less handle is a no-op success.
            #[cfg(feature = "vault")]
            if ino == SYNTHETIC_VAULT_STATUS_INO {
                reply.ok();
                return;
            }
            reply.error(libc::EBADF);
        }
    }

    /// Create and open a file
    fn create(
        &mut self,
        _req: &Request,
        parent: u64,
        name: &OsStr,
        _mode: u32,
        _umask: u32,
        flags: i32,
        reply: fuser::ReplyCreate,
    ) {
        fuse_debug!("create parent={} name={:?} flags={:#x}", parent, name, flags);

        // Handle .overlay synthetic directory
        let parent_entry = if parent == SYNTHETIC_OVERLAY_DIR_INO {
            InodeEntry {
                _ino: SYNTHETIC_OVERLAY_DIR_INO,
                path: PathBuf::from("/.overlay"),
                parent: ROOT_INO,
            }
        } else {
            match self.get_inode(parent) {
                Some(e) => e,
                None => {
                    reply.error(libc::ENOENT);
                    return;
                }
            }
        };

        // Build virtual path for new file
        let virtual_path = parent_entry.path.join(name);

        // Translate to source path using pinned paths
        let (source_rel_path, pinned) = self.translate_virtual_to_source(&virtual_path);
        let is_passthrough = pinned.virtual_prefix == Path::new("/.overlay");

        // Get full file path for attr response
        let file_path = self.source_path.join(&source_rel_path);

        // Create the file in the backing store
        let path_cstr = match CString::new(source_rel_path.as_os_str().as_bytes()) {
            Ok(p) => p,
            Err(_) => {
                reply.error(libc::EINVAL);
                return;
            }
        };

        // Check if file already exists
        // SAFETY: `self.source_fd` is valid. `path_cstr` is NUL-terminated. `stat_buf` is
        // zeroed stack memory. Result is only used as a boolean (== 0 means exists).
        let exists = unsafe {
            let mut stat_buf: libc::stat = std::mem::zeroed();
            libc::fstatat(
                self.source_fd,
                path_cstr.as_ptr(),
                &mut stat_buf,
                libc::AT_SYMLINK_NOFOLLOW,
            ) == 0
        };

        // Determine open flags
        // If file exists and O_EXCL is NOT in flags, open it without O_EXCL
        // If file exists and O_EXCL IS in flags, let the open fail with EEXIST
        // If file doesn't exist, create it with O_EXCL to ensure atomic creation
        // O_CLOEXEC is ORed in unconditionally — no child process should inherit a
        // newly-created backing-store fd (REM-17 / CR-01).
        let open_flags = if exists && (flags & libc::O_EXCL) == 0 {
            // File exists, caller didn't request exclusive - open existing file
            libc::O_CREAT | (flags & !libc::O_EXCL) | libc::O_CLOEXEC
        } else {
            // Either file doesn't exist, or caller wants exclusive creation
            libc::O_CREAT | libc::O_EXCL | flags | libc::O_CLOEXEC
        };

        // SAFETY: `self.source_fd` is valid. `path_cstr` is NUL-terminated. `open_flags`
        // are FUSE-supplied flags with O_CLOEXEC ORed in. Mode 0o600 restricts to file
        // owner; masked by umask.
        let fd = unsafe {
            libc::openat(
                self.source_fd,
                path_cstr.as_ptr(),
                open_flags,
                0o600,
            )
        };

        if fd < 0 {
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(libc::EIO);
            reply.error(errno);
            return;
        }

        // For passthrough writable files, keep fd open; otherwise close it
        let writable = (flags & libc::O_WRONLY) != 0 || (flags & libc::O_RDWR) != 0;
        let passthrough_fd = if is_passthrough && writable {
            Some(fd)
        } else {
            // SAFETY: `fd` is valid (>= 0); not stored anywhere; closing here to avoid leak.
            unsafe { libc::close(fd) };
            None
        };

        // Now do a regular lookup and open
        match self.lookup_impl(parent, name) {
            Ok((ino, attr)) => {
                // Create file handle
                let mut next_fh = self.next_fh.write();
                let fh = *next_fh;
                *next_fh += 1;
                drop(next_fh);

                let handle = FileHandle {
                    ino,
                    path: file_path,
                    cached_content: None,
                    writable,
                    dirty: false,
                    opened_mode: false,
                    sealed_mode: false,
                    origin_mode: is_passthrough,
                    passthrough_fd,
                    original_sealed: None,
                };

                self.file_handles.write().insert(fh, handle);

                // For passthrough writable files, use FOPEN_DIRECT_IO to bypass page cache
                let open_flags = if is_passthrough && writable {
                    const FOPEN_DIRECT_IO: u32 = 1 << 0;  // From linux/fuse.h
                    FOPEN_DIRECT_IO
                } else {
                    0
                };

                reply.created(&TTL, &attr, 0, fh, open_flags);
            }
            Err(_) => reply.error(libc::EIO),
        }
    }

    /// Create a directory
    fn mkdir(
        &mut self,
        _req: &Request,
        parent: u64,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        reply: fuser::ReplyEntry,
    ) {
        fuse_debug!("mkdir parent={} name={:?} mode={:#o}", parent, name, mode);
        // Handle .overlay synthetic directory
        let parent_entry = if parent == SYNTHETIC_OVERLAY_DIR_INO {
            InodeEntry {
                _ino: SYNTHETIC_OVERLAY_DIR_INO,
                path: PathBuf::from("/.overlay"),
                parent: ROOT_INO,
            }
        } else {
            match self.get_inode(parent) {
                Some(e) => e,
                None => {
                    reply.error(libc::ENOENT);
                    return;
                }
            }
        };

        // Build virtual path and translate using pinned paths
        let virtual_path = parent_entry.path.join(name);
        let (source_rel_path, _) = self.translate_virtual_to_source(&virtual_path);

        // Create the directory using mkdirat
        use std::os::unix::ffi::OsStrExt;
        let path_cstr = match std::ffi::CString::new(source_rel_path.as_os_str().as_bytes()) {
            Ok(p) => p,
            Err(_) => {
                reply.error(libc::EINVAL);
                return;
            }
        };

        // SAFETY: `self.source_fd` is valid. `path_cstr` is NUL-terminated. `mode` is from
        // FUSE request; cast to `mode_t` is valid (both are unsigned integers). Error checked.
        let result = unsafe {
            libc::mkdirat(self.source_fd, path_cstr.as_ptr(), mode as libc::mode_t)
        };

        if result != 0 {
            reply.error(libc::EIO);
            return;
        }

        // Lookup the newly created directory to get its attributes
        match self.lookup_impl(parent, name) {
            Ok((_ino, attr)) => reply.entry(&TTL, &attr, 0),
            Err(_) => reply.error(libc::EIO),
        }
    }

    /// Remove a file
    fn unlink(&mut self, _req: &Request, parent: u64, name: &OsStr, reply: fuser::ReplyEmpty) {
        fuse_debug!("unlink parent={} name={:?}", parent, name);
        // Handle .overlay synthetic directory
        let parent_entry = if parent == SYNTHETIC_OVERLAY_DIR_INO {
            InodeEntry {
                _ino: SYNTHETIC_OVERLAY_DIR_INO,
                path: PathBuf::from("/.overlay"),
                parent: ROOT_INO,
            }
        } else {
            match self.get_inode(parent) {
                Some(e) => e,
                None => {
                    reply.error(libc::ENOENT);
                    return;
                }
            }
        };

        // Build virtual path and translate using pinned paths
        let virtual_path = parent_entry.path.join(name);
        let (source_rel_path, _pinned) = self.translate_virtual_to_source(&virtual_path);

        let path_cstr = match CString::new(source_rel_path.as_os_str().as_bytes()) {
            Ok(p) => p,
            Err(_) => {
                reply.error(libc::EINVAL);
                return;
            }
        };

        // SAFETY: `self.source_fd` is a valid directory fd. `path_cstr` is NUL-terminated.
        // flags=0 means unlink the file (not the directory). Error checked immediately.
        let result = unsafe { libc::unlinkat(self.source_fd, path_cstr.as_ptr(), 0) };

        if result == 0 {
            // Remove from inode cache (inode table uses virtual paths)
            let mut inodes = self.inode_table.write();
            inodes.retain(|_, entry| entry.path != virtual_path);
            drop(inodes);

            // Also remove from path-to-inode map to keep caches synchronized
            let mut path_map = self.path_to_ino.write();
            path_map.remove(&virtual_path);

            reply.ok();
        } else {
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(libc::EIO);
            reply.error(errno);
        }
    }

    /// Remove a directory
    fn rmdir(&mut self, _req: &Request, parent: u64, name: &OsStr, reply: fuser::ReplyEmpty) {
        fuse_debug!("rmdir parent={} name={:?}", parent, name);
        // Handle .overlay synthetic directory
        let parent_entry = if parent == SYNTHETIC_OVERLAY_DIR_INO {
            InodeEntry {
                _ino: SYNTHETIC_OVERLAY_DIR_INO,
                path: PathBuf::from("/.overlay"),
                parent: ROOT_INO,
            }
        } else {
            match self.get_inode(parent) {
                Some(e) => e,
                None => {
                    reply.error(libc::ENOENT);
                    return;
                }
            }
        };

        // Build virtual path and translate using pinned paths
        let virtual_path = parent_entry.path.join(name);
        let (source_rel_path, _) = self.translate_virtual_to_source(&virtual_path);

        let path_cstr = match CString::new(source_rel_path.as_os_str().as_bytes()) {
            Ok(p) => p,
            Err(_) => {
                reply.error(libc::EINVAL);
                return;
            }
        };

        // Use AT_REMOVEDIR flag for rmdir
        // SAFETY: `self.source_fd` is a valid directory fd. `path_cstr` is NUL-terminated.
        // `AT_REMOVEDIR` tells `unlinkat` to remove the directory (equivalent to rmdir).
        let result = unsafe {
            libc::unlinkat(self.source_fd, path_cstr.as_ptr(), libc::AT_REMOVEDIR)
        };

        if result == 0 {
            // Remove from inode cache
            let mut inodes = self.inode_table.write();
            inodes.retain(|_, entry| entry.path != virtual_path);
            drop(inodes);

            // Also remove from path-to-inode map to keep caches synchronized
            let mut path_map = self.path_to_ino.write();
            path_map.remove(&virtual_path);

            reply.ok();
        } else {
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(libc::EIO);
            reply.error(errno);
        }
    }

    /// Create a hard link to a file
    fn link(
        &mut self,
        _req: &Request,
        ino: u64,
        newparent: u64,
        newname: &OsStr,
        reply: ReplyEntry,
    ) {

        // Get the existing file's path
        let existing_entry = match self.get_inode(ino) {
            Some(e) => e,
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        // Get the new parent directory's path
        let new_parent_entry = if newparent == SYNTHETIC_OVERLAY_DIR_INO {
            InodeEntry {
                _ino: SYNTHETIC_OVERLAY_DIR_INO,
                path: PathBuf::from("/.overlay"),
                parent: ROOT_INO,
            }
        } else {
            match self.get_inode(newparent) {
                Some(e) => e,
                None => {
                    reply.error(libc::ENOENT);
                    return;
                }
            }
        };


        // Build paths and translate to source
        let (old_rel, old_pinned) = self.translate_virtual_to_source(&existing_entry.path);

        let new_virtual_path = new_parent_entry.path.join(newname);
        let (new_rel, new_pinned) = self.translate_virtual_to_source(&new_virtual_path);

        // Only allow hard links for passthrough files in .overlay
        let is_passthrough = old_pinned.virtual_prefix == Path::new("/.overlay")
            && new_pinned.virtual_prefix == Path::new("/.overlay");

        if !is_passthrough {
            reply.error(libc::EPERM);
            return;
        }


        // Convert paths to CStrings
        let old_cstr = match CString::new(old_rel.as_os_str().as_bytes()) {
            Ok(p) => p,
            Err(_) => {
                reply.error(libc::EINVAL);
                return;
            }
        };

        let new_cstr = match CString::new(new_rel.as_os_str().as_bytes()) {
            Ok(p) => p,
            Err(_) => {
                reply.error(libc::EINVAL);
                return;
            }
        };

        // Create hard link using linkat()
        // SAFETY: `self.source_fd` is a valid directory fd for both old and new paths.
        // Both `old_cstr` and `new_cstr` are NUL-terminated. flags=0 means no special behavior.
        let result = unsafe {
            libc::linkat(
                self.source_fd,
                old_cstr.as_ptr(),
                self.source_fd,
                new_cstr.as_ptr(),
                0,
            )
        };

        if result == 0 {

            // Invalidate cache for new path
            let mut path_map = self.path_to_ino.write();
            path_map.remove(&new_virtual_path);
            drop(path_map);

            // Look up the newly created link and return its attributes
            match self.lookup_impl(newparent, newname) {
                Ok((_, attr)) => {
                    let ttl = &TTL_ZERO;  // Use zero TTL for passthrough files
                    reply.entry(ttl, &attr, 0);
                }
                Err(_) => {
                    reply.error(libc::EIO);
                }
            }
        } else {
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(libc::EIO);
            reply.error(errno);
        }
    }

    /// Rename a file
    fn rename(
        &mut self,
        _req: &Request,
        parent: u64,
        name: &OsStr,
        newparent: u64,
        newname: &OsStr,
        _flags: u32,
        reply: fuser::ReplyEmpty,
    ) {
        fuse_debug!("rename parent={} name={:?} newparent={} newname={:?}", parent, name, newparent, newname);
        // Handle .overlay synthetic directory for old parent
        let old_parent_entry = if parent == SYNTHETIC_OVERLAY_DIR_INO {
            InodeEntry {
                _ino: SYNTHETIC_OVERLAY_DIR_INO,
                path: PathBuf::from("/.overlay"),
                parent: ROOT_INO,
            }
        } else {
            match self.get_inode(parent) {
                Some(e) => e,
                None => {
                    reply.error(libc::ENOENT);
                    return;
                }
            }
        };

        // Handle .overlay synthetic directory for new parent
        let new_parent_entry = if newparent == SYNTHETIC_OVERLAY_DIR_INO {
            InodeEntry {
                _ino: SYNTHETIC_OVERLAY_DIR_INO,
                path: PathBuf::from("/.overlay"),
                parent: ROOT_INO,
            }
        } else {
            match self.get_inode(newparent) {
                Some(e) => e,
                None => {
                    reply.error(libc::ENOENT);
                    return;
                }
            }
        };

        // Build virtual paths and translate using pinned paths
        let old_virtual_path = old_parent_entry.path.join(name);
        let (old_rel, _) = self.translate_virtual_to_source(&old_virtual_path);

        let new_virtual_path = new_parent_entry.path.join(newname);
        let (new_rel, _) = self.translate_virtual_to_source(&new_virtual_path);

        let old_cstr = match CString::new(old_rel.as_os_str().as_bytes()) {
            Ok(p) => p,
            Err(_) => {
                reply.error(libc::EINVAL);
                return;
            }
        };

        let new_cstr = match CString::new(new_rel.as_os_str().as_bytes()) {
            Ok(p) => p,
            Err(_) => {
                reply.error(libc::EINVAL);
                return;
            }
        };


        // SAFETY: `self.source_fd` is a valid directory fd for both paths.
        // Both `old_cstr` and `new_cstr` are NUL-terminated. `renameat` is atomic on POSIX.
        let result = unsafe {
            libc::renameat(
                self.source_fd,
                old_cstr.as_ptr(),
                self.source_fd,
                new_cstr.as_ptr(),
            )
        };

        if result == 0 {

            // Update inode cache - remove both old and new paths to force fresh lookups
            // This prevents stale cache entries from causing ENOENT errors
            let mut inodes = self.inode_table.write();
            inodes.retain(|_, entry| entry.path != old_virtual_path && entry.path != new_virtual_path);
            drop(inodes);

            // Also remove from path-to-inode map to keep caches synchronized
            let mut path_map = self.path_to_ino.write();
            path_map.remove(&old_virtual_path);
            path_map.remove(&new_virtual_path);


            reply.ok();
        } else {
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(libc::EIO);
            reply.error(errno);
        }
    }

    /// Set extended attribute - used for sealed mode confirmation
    /// Protocol: O_NONBLOCK on open, then fsetxattr("user.sss.sealed", "1") to confirm
    fn setxattr(
        &mut self,
        _req: &Request,
        _ino: u64,
        name: &OsStr,
        value: &[u8],
        _flags: i32,
        _position: u32,
        reply: fuser::ReplyEmpty,
    ) {

        // Check if this is our sealed mode confirmation signal
        if name == "user.sss.sealed" && value == b"1" {

            // We need to find the file handle, but setxattr doesn't give us fh!
            // We'll need to match by inode and sealed_mode flag
            let mut handles = self.file_handles.write();

            // Find a handle with sealed_mode=true (there should only be one per file)
            let mut found = false;
            for (_fh, handle) in handles.iter_mut() {
                if handle.sealed_mode && handle.cached_content.is_none() {

                    // Both signals present! Cache sealed content (PlaintextBuf — REM-15)
                    match self.read_sealed(&handle.path) {
                        Ok(content) => {
                            handle.cached_content = Some(Zeroizing::new(content));
                            found = true;
                            break;
                        }
                        Err(_e) => {
                            reply.error(libc::EIO);
                            return;
                        }
                    }
                }
            }

            if found {
                reply.ok();
            } else {
                reply.error(libc::EINVAL);
            }
        } else {
            // Not our signal - reject
            reply.error(libc::ENOTSUP);
        }
    }

    /// Get extended attribute — passes through to the backing source file so that
    /// security.selinux and other xattrs observed through the mount match the raw
    /// files (important for tools like stat -Z, ls -Z, restorecon and SELinux-aware
    /// processes such as `openstack undercloud install`).
    fn getxattr(
        &mut self,
        _req: &Request,
        ino: u64,
        name: &OsStr,
        size: u32,
        reply: fuser::ReplyXattr,
    ) {
        let rel_path = match self.resolve_source_for_xattr(ino) {
            Some(p) => p,
            None => { reply.error(libc::ENOENT); return; }
        };
        self.xattr_get_impl(&rel_path, name, size, reply);
    }

    /// List extended attribute names — passthrough, same rationale as getxattr.
    fn listxattr(
        &mut self,
        _req: &Request,
        ino: u64,
        size: u32,
        reply: fuser::ReplyXattr,
    ) {
        let rel_path = match self.resolve_source_for_xattr(ino) {
            Some(p) => p,
            None => { reply.error(libc::ENOENT); return; }
        };
        self.xattr_list_impl(&rel_path, size, reply);
    }

    /// Create a symlink
    fn symlink(
        &mut self,
        _req: &Request,
        parent: u64,
        name: &OsStr,
        link: &std::path::Path,
        reply: fuser::ReplyEntry,
    ) {
        // Handle .overlay synthetic directory
        let parent_entry = if parent == SYNTHETIC_OVERLAY_DIR_INO {
            InodeEntry {
                _ino: SYNTHETIC_OVERLAY_DIR_INO,
                path: PathBuf::from("/.overlay"),
                parent: ROOT_INO,
            }
        } else {
            match self.get_inode(parent) {
                Some(e) => e,
                None => {
                    reply.error(libc::ENOENT);
                    return;
                }
            }
        };

        // Build virtual path and translate using pinned paths
        let virtual_path = parent_entry.path.join(name);
        let (rel_path, _) = self.translate_virtual_to_source(&virtual_path);

        // Create the symlink using symlinkat
        use std::os::unix::ffi::OsStrExt;
        let link_cstr = match std::ffi::CString::new(link.as_os_str().as_bytes()) {
            Ok(p) => p,
            Err(_) => {
                reply.error(libc::EINVAL);
                return;
            }
        };

        let name_cstr = match std::ffi::CString::new(rel_path.as_os_str().as_bytes()) {
            Ok(p) => p,
            Err(_) => {
                reply.error(libc::EINVAL);
                return;
            }
        };

        // SAFETY: `link_cstr` (the symlink target) and `name_cstr` (the symlink name) are both
        // NUL-terminated. `self.source_fd` is a valid directory fd. Error checked immediately.
        let result = unsafe {
            libc::symlinkat(
                link_cstr.as_ptr(),
                self.source_fd,
                name_cstr.as_ptr(),
            )
        };

        if result != 0 {
            reply.error(libc::EIO);
            return;
        }

        // Lookup the newly created symlink
        match self.lookup_impl(parent, name) {
            Ok((_ino, attr)) => reply.entry(&TTL, &attr, 0),
            Err(_) => reply.error(libc::EIO),
        }
    }

    /// Read symlink target
    fn readlink(&mut self, _req: &Request, ino: u64, reply: fuser::ReplyData) {
        // Block operations on .git synthetic directories
        if ino == SYNTHETIC_OVERLAY_DIR_INO {
            reply.error(libc::EINVAL);
            return;
        }

        let entry = match self.get_inode(ino) {
            Some(e) => e,
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        // Translate virtual path to source path using pinned paths
        let (rel_path, _) = self.translate_virtual_to_source(&entry.path);

        // Read symlink target using readlinkat
        use std::os::unix::ffi::OsStrExt;
        let path_cstr = match std::ffi::CString::new(rel_path.as_os_str().as_bytes()) {
            Ok(p) => p,
            Err(_) => {
                reply.error(libc::EINVAL);
                return;
            }
        };

        let mut buf = vec![0u8; libc::PATH_MAX as usize];
        // SAFETY: `self.source_fd` is a valid directory fd. `path_cstr` is NUL-terminated.
        // `buf` is a heap-allocated slice of `PATH_MAX` bytes — sufficient for any symlink target.
        // `readlinkat` writes at most `buf.len()` bytes; we truncate to `len` afterwards.
        let len = unsafe {
            libc::readlinkat(
                self.source_fd,
                path_cstr.as_ptr(),
                buf.as_mut_ptr() as *mut libc::c_char,
                buf.len(),
            )
        };

        if len < 0 {
            reply.error(libc::EIO);
        } else {
            buf.truncate(len as usize);
            reply.data(&buf);
        }
    }

    /// Get filesystem statistics
    fn statfs(&mut self, _req: &Request, _ino: u64, reply: fuser::ReplyStatfs) {

        // Get statfs from the underlying filesystem
        // SAFETY: `stat` is zeroed stack memory of the correct size for `libc::statfs`.
        // `self.source_fd` is a valid file descriptor (the source directory fd).
        // `fstatfs` writes filesystem statistics into `stat`; result checked before use.
        let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
        // SAFETY: `self.source_fd` is a valid open file descriptor (source directory fd).
        // `stat` is validly zeroed memory of `libc::statfs` size; `fstatfs` writes into it.
        // Return value is checked for 0 (success) immediately below.
        let result = unsafe {
            libc::fstatfs(self.source_fd, &mut stat)
        };

        if result == 0 {
            // Return the underlying filesystem's stats
            // This ensures all directories appear to be on the same filesystem
            #[cfg(target_os = "linux")]
            reply.statfs(
                stat.f_blocks,           // Total blocks
                stat.f_bfree,            // Free blocks
                stat.f_bavail,           // Available blocks
                stat.f_files,            // Total inodes
                stat.f_ffree,            // Free inodes
                stat.f_bsize as u32,     // Block size
                stat.f_namelen as u32,   // Max filename length
                stat.f_frsize as u32,    // Fragment size
            );
            #[cfg(target_os = "macos")]
            reply.statfs(
                stat.f_blocks,           // Total blocks
                stat.f_bfree,            // Free blocks
                stat.f_bavail,           // Available blocks
                stat.f_files,            // Total inodes
                stat.f_ffree,            // Free inodes
                stat.f_bsize as u32,     // Block size
                255,                     // Max filename length (macOS typical)
                stat.f_bsize as u32,     // Fragment size (use bsize)
            );
        } else {
            reply.error(libc::EIO);
        }
    }
}

impl Drop for SssFS {
    fn drop(&mut self) {
        // Close the source directory file descriptor
        // SAFETY: `self.source_fd` is a valid open fd opened in `new()`. Drop is called
        // exactly once, so there is no double-close. No other code closes `source_fd`.
        unsafe {
            libc::close(self.source_fd);
        }
        // Close the mount point directory file descriptor if present
        if let Some(mount_fd) = self.mount_fd {
            // SAFETY: `mount_fd` is a valid open fd opened in `new()`. Drop is called
            // exactly once. The Option ensures we only close it if it was opened.
            unsafe {
                libc::close(mount_fd);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_has_encrypted_markers_true() {
        assert!(has_encrypted_markers("password: ⊠{abc123}"));
        assert!(has_encrypted_markers("⊠{secret}"));
        assert!(has_encrypted_markers("prefix ⊠{data} suffix"));
    }

    #[test]
    fn test_has_encrypted_markers_false() {
        assert!(!has_encrypted_markers("password: plaintext"));
        assert!(!has_encrypted_markers("⊕{plaintext_marker}"));
        assert!(!has_encrypted_markers(""));
        assert!(!has_encrypted_markers("no markers here"));
    }

    #[test]
    fn test_should_hide_git_files() {
        assert!(SssFS::should_hide(".git"));
        assert!(SssFS::should_hide(".gitignore"));
        assert!(SssFS::should_hide(".gitattributes"));
        assert!(SssFS::should_hide(".gitmodules"));
    }

    #[test]
    fn test_should_hide_regular_files() {
        assert!(!SssFS::should_hide("README.md"));
        assert!(!SssFS::should_hide("config.yml"));
        assert!(!SssFS::should_hide(".hidden"));
        assert!(!SssFS::should_hide("gitignore")); // No leading dot
    }

    #[test]
    fn test_should_process_with_sss_regular_files() {
        assert!(SssFS::should_process_with_sss(Path::new("config.yml")));
        assert!(SssFS::should_process_with_sss(Path::new("README.md")));
        assert!(SssFS::should_process_with_sss(Path::new("src/main.rs")));
    }

    #[test]
    fn test_should_process_with_sss_vim_swap_files() {
        assert!(!SssFS::should_process_with_sss(Path::new(".config.yml.swp")));
        assert!(!SssFS::should_process_with_sss(Path::new(".file.swo")));
        assert!(!SssFS::should_process_with_sss(Path::new(".test.swn")));
        assert!(!SssFS::should_process_with_sss(Path::new(".temp.tmp")));
    }

    #[test]
    fn test_should_process_with_sss_temp_files() {
        assert!(!SssFS::should_process_with_sss(Path::new("file~")));
        assert!(!SssFS::should_process_with_sss(Path::new("#file#")));
        assert!(!SssFS::should_process_with_sss(Path::new("#backup")));
    }

    #[test]
    fn test_parse_virtual_file_mode_sealed() {
        let (name, mode) = SssFS::parse_virtual_file_mode(OsStr::new("config.yml.sss-sealed"));
        assert_eq!(name, OsStr::new("config.yml"));
        assert_eq!(mode, FileMode::Sealed);
    }

    #[test]
    fn test_parse_virtual_file_mode_opened() {
        let (name, mode) = SssFS::parse_virtual_file_mode(OsStr::new("config.yml.sss-opened"));
        assert_eq!(name, OsStr::new("config.yml"));
        assert_eq!(mode, FileMode::Opened);
    }

    #[test]
    fn test_parse_virtual_file_mode_rendered() {
        let (name, mode) = SssFS::parse_virtual_file_mode(OsStr::new("config.yml"));
        assert_eq!(name, OsStr::new("config.yml"));
        assert_eq!(mode, FileMode::Rendered);
    }

    #[test]
    fn test_parse_virtual_file_mode_double_suffix() {
        // Should only strip one suffix
        let (name, mode) = SssFS::parse_virtual_file_mode(OsStr::new("file.sss-opened.sss-sealed"));
        assert_eq!(name, OsStr::new("file.sss-opened"));
        assert_eq!(mode, FileMode::Sealed);
    }

    #[test]
    fn test_strip_virtual_suffix_with_opened() {
        let path = PathBuf::from("/path/to/file.txt.sss-opened");
        let result = SssFS::strip_virtual_suffix(&path, true);
        assert_eq!(result, PathBuf::from("/path/to/file.txt"));
    }

    #[test]
    fn test_strip_virtual_suffix_without_opened_mode() {
        let path = PathBuf::from("/path/to/file.txt.sss-opened");
        let result = SssFS::strip_virtual_suffix(&path, false);
        assert_eq!(result, path); // Unchanged when not in opened mode
    }

    #[test]
    fn test_strip_virtual_suffix_no_suffix() {
        let path = PathBuf::from("/path/to/file.txt");
        let result = SssFS::strip_virtual_suffix(&path, true);
        assert_eq!(result, path); // Unchanged when no suffix
    }

    // --- VMNT-04 / VMNT-03: vault-backed file detection (raw-bytes predicate) ---
    // These exercise `bytes_have_vault_refs`, the unit-testable core that
    // `SssFS::file_has_vault_refs` calls (the method itself needs a live source_fd,
    // so the regex-on-raw-bytes logic is tested via the free predicate per the
    // 49-02 plan). The predicate MUST scan raw backing bytes, never rendered output.

    #[test]
    fn file_has_vault_refs_true_on_marker() {
        // A backing file whose RAW bytes contain a Unicode `⊳{}` vault reference
        // is detected as vault-backed.
        let raw = b"api_key: \xe2\x8a\xb3{secret/prod#api_key}\n"; // ⊳ = U+22B3 = e2 8a b3
        assert!(
            bytes_have_vault_refs(raw),
            "raw bytes containing ⊳{{secret/prod#api_key}} must be detected as vault-backed"
        );
    }

    #[test]
    fn file_has_vault_refs_false_on_plain() {
        // Plain content with no vault marker returns false — even when it mentions
        // the literal word "vault" or carries a ⊲{} secrets-file marker (⊲ = U+22B2,
        // a DIFFERENT marker that the vault regex must not match).
        let plain = b"database:\n  host: vault.example.com  # not a reference\n";
        assert!(
            !bytes_have_vault_refs(plain),
            "the literal word 'vault' must NOT be detected as a vault reference"
        );
        let secrets_marker = b"token: \xe2\x8a\xb2{api_key}\n"; // ⊲{api_key} secrets-file ref
        assert!(
            !bytes_have_vault_refs(secrets_marker),
            "a ⊲{{}} secrets-file marker must NOT match the ⊳{{}} vault regex"
        );
        // Binary bytes (invalid UTF-8) must not panic and must not match.
        let binary = b"\xff\xfe\x00\x01\x02\xc0\xc1";
        assert!(
            !bytes_have_vault_refs(binary),
            "binary (non-UTF-8) bytes must yield no match without allocate-failing"
        );
    }

    #[test]
    fn file_has_vault_refs_ascii_alias() {
        // The ASCII alias `>{…}` is matched by the same regex (both forms supported).
        let raw = b"endpoint: >{secret#f}\n";
        assert!(
            bytes_have_vault_refs(raw),
            "the ASCII alias >{{secret#f}} must be detected as a vault reference"
        );
    }

    #[test]
    fn vault_only_content_invisible_to_standard_markers_cr01() {
        // CR-01 regression: a file containing ONLY ⊳{}/>{} vault refs has NO
        // standard SSS markers, so has_any_markers_bytes / has_balanced_markers are
        // BLIND to it. The read_and_process / read_and_render gates therefore MUST
        // ALSO consult bytes_have_vault_refs — otherwise the file early-returns raw
        // and the vault pass never runs, serving ⊳{} verbatim to the FUSE client.
        let vault_only = "key=⊳{secret/data/app#password}".as_bytes();
        assert!(
            !crate::filesystem_common::has_any_markers_bytes(vault_only),
            "vault-only content has NO standard SSS markers — exactly why the read \
             gate must not rely on has_any_markers_bytes alone (CR-01)"
        );
        assert!(
            !crate::filesystem_common::has_balanced_markers(
                std::str::from_utf8(vault_only).unwrap()
            ),
            "vault-only content is not a balanced standard marker either (CR-01)"
        );
        assert!(
            bytes_have_vault_refs(vault_only),
            "but bytes_have_vault_refs DOES detect it — the gate's vault arm catches \
             what the standard marker scanners miss"
        );
        // ASCII alias must be caught by the same gate arm.
        assert!(bytes_have_vault_refs(b"key=>{secret/data/app#password}"));
    }

    // --- VMNT-03 / SC3: open-time precache-bypass DECISION (research risk 2) ---
    // The subtle correctness point: a vault-backed file must NOT be precached, so
    // every read() re-drives read_and_render → a fresh Vault fetch (otherwise the
    // 2nd read serves stale plaintext, INVISIBLE on a first `cat`). These tests pin
    // the pure decision used by open(); the live read-through proof is the 49 live tier.

    #[test]
    fn precache_bypassed_for_vault_backed_file() {
        // A non-passthrough vault-backed file must bypass the precache.
        assert!(
            should_skip_precache(false, true),
            "vault-backed files MUST skip the open-time precache (SC3)"
        );
    }

    #[test]
    fn precache_used_for_plain_sss_file() {
        // A normal (non-passthrough, non-vault) SSS file is precached as before —
        // the bypass must NOT regress page-cache behaviour for ordinary files.
        assert!(
            !should_skip_precache(false, false),
            "plain SSS files must still be precached (no behaviour change)"
        );
        // Passthrough files are always raw (skip precache) regardless of vault flag.
        assert!(should_skip_precache(true, false), "passthrough files skip precache");
    }

    #[test]
    fn direct_io_set_for_vault_backed_file() {
        // Vault-backed files get FOPEN_DIRECT_IO even when read-only (the page-cache
        // bypass is about not RETAINING resolved secrets, independent of writability).
        assert!(
            should_set_direct_io(false, false, true),
            "vault-backed read-only files MUST get FOPEN_DIRECT_IO (VMNT-04)"
        );
        assert!(
            should_set_direct_io(false, true, true),
            "vault-backed writable files MUST get FOPEN_DIRECT_IO"
        );
    }

    #[test]
    fn direct_io_preserves_passthrough_writable_and_spares_plain() {
        // Existing behaviour preserved: passthrough writable → direct_io.
        assert!(
            should_set_direct_io(true, true, false),
            "passthrough writable files keep FOPEN_DIRECT_IO (pre-existing)"
        );
        // A plain non-vault, non-passthrough file (even writable) must NOT get
        // direct_io — only vault/passthrough-writable inodes bypass the page cache.
        assert!(
            !should_set_direct_io(false, true, false),
            "plain writable SSS files must NOT get FOPEN_DIRECT_IO"
        );
        assert!(
            !should_set_direct_io(false, false, false),
            "plain read-only SSS files must NOT get FOPEN_DIRECT_IO"
        );
        // Passthrough read-only does not need direct_io (matches pre-existing arm).
        assert!(
            !should_set_direct_io(true, false, false),
            "passthrough read-only files do not get FOPEN_DIRECT_IO"
        );
    }

    // --- WR-01 / SC3 / VMNT-03: getattr/lookup must NOT cache resolved vault
    // secrets. `compute_size_override` eagerly renders+caches marked files to
    // report an accurate size, but for a vault-backed file that retains resolved
    // plaintext in `render_cache` for the unbounded getattr→release window. These
    // tests pin the pure decision used to skip that caching; the cache-bypass is
    // proven end-to-end by the 49 live tier.

    #[test]
    fn rendered_size_not_cached_for_vault_backed_file() {
        // A file whose raw bytes carry vault refs must NOT be render-and-cached by
        // compute_size_override — caching the resolved plaintext would retain the
        // resolved secret past the read frame (WR-01).
        assert!(
            !should_cache_rendered_size(true),
            "vault-bearing content MUST NOT be cached in render_cache (WR-01 / SC3)"
        );
    }

    #[test]
    fn rendered_size_cached_for_plain_marked_file() {
        // A plain (non-vault) marked file is still render-and-cached so getattr
        // reports the correct rendered size — the bypass must NOT regress the
        // accurate-size behaviour for ordinary SSS files.
        assert!(
            should_cache_rendered_size(false),
            "non-vault marked files keep their accurate-size render cache (no regression)"
        );
    }

    #[test]
    fn rendered_size_decision_tracks_raw_byte_predicate() {
        // The decision is wired to the SAME raw-bytes predicate the read/open paths
        // use, so a vault-bearing buffer is consistently treated as "do not cache"
        // and a plain buffer as "cache". This guards against the two predicates
        // drifting apart (the cache-bypass must mirror bytes_have_vault_refs).
        let vault_bearing = "key=⊳{secret/data/app#password}".as_bytes();
        assert!(
            !should_cache_rendered_size(bytes_have_vault_refs(vault_bearing)),
            "a ⊳{{}} buffer must resolve to do-not-cache via the shared predicate"
        );
        // ASCII alias must reach the same do-not-cache decision.
        assert!(!should_cache_rendered_size(bytes_have_vault_refs(
            b"key=>{secret/data/app#password}"
        )));
        let plain = b"database:\n  host: example.com\n";
        assert!(
            should_cache_rendered_size(bytes_have_vault_refs(plain)),
            "a plain buffer must resolve to cache via the shared predicate"
        );
    }

    // --- WR-02: a real `.sss` directory in the backing store must win over the
    // synthetic control surface (no duplicate, no shadowing). These pin the pure
    // injection decision used by both lookup and readdir; the live two-entry /
    // shadow proof is the 49 live tier.

    #[cfg(feature = "vault")]
    #[test]
    fn synthetic_sss_suppressed_when_real_present() {
        // A real `.sss` in the backing root → do NOT inject the synthetic node, so
        // the real directory is served normally and never duplicated/shadowed.
        assert!(
            !should_inject_synthetic_sss(true),
            "a real .sss must win — the synthetic control dir is suppressed (WR-02)"
        );
    }

    #[cfg(feature = "vault")]
    #[test]
    fn synthetic_sss_injected_when_absent() {
        // No real `.sss` → the synthetic control surface (vault-status) is exposed.
        assert!(
            should_inject_synthetic_sss(false),
            "with no real .sss, the synthetic control dir is injected as before"
        );
    }

    #[cfg(feature = "vault")]
    #[test]
    fn synthetic_sss_readdir_dedupe_matches_predicate() {
        // The readdir guard tests the collected listing directly: if `.sss` is
        // already present the predicate must say "do not inject" (no duplicate),
        // and if absent it must say "inject". This mirrors the inline
        // items.iter().any(name == ".sss") check.
        let with_sss: Vec<(u64, FileType, String)> = vec![
            (10, FileType::Directory, ".".to_string()),
            (1, FileType::Directory, "..".to_string()),
            (42, FileType::Directory, ".sss".to_string()),
        ];
        let real_present = with_sss.iter().any(|(_, _, name)| name == ".sss");
        assert!(
            !should_inject_synthetic_sss(real_present),
            "a listing already containing .sss must not get a duplicate synthetic entry"
        );

        let without_sss: Vec<(u64, FileType, String)> = vec![
            (10, FileType::Directory, ".".to_string()),
            (1, FileType::Directory, "..".to_string()),
            (43, FileType::RegularFile, "config.yaml".to_string()),
        ];
        let real_absent = without_sss.iter().any(|(_, _, name)| name == ".sss");
        assert!(
            should_inject_synthetic_sss(real_absent),
            "a listing with no .sss must get the synthetic control directory"
        );
    }

    // --- WR-03: single-flight auth freshness decision. The concurrency itself
    // (one login per refresh under auth_lock) needs a live Vault to prove, but the
    // freshness predicate that the in-lock RE-CHECK consults is pure and pinned
    // here — it is what makes a queued thread REUSE the just-minted token instead
    // of auth'ing again. The live double-auth-prevention proof is the 49 live tier.

    #[cfg(feature = "vault")]
    #[test]
    fn mount_token_refresh_when_absent() {
        // No token (lazy first read / never authed) → must auth, regardless of any
        // (irrelevant) lease TTL value.
        let near = SssFS::VAULT_TOKEN_NEAR_EXPIRY_SECS;
        assert!(
            mount_token_refresh_decision(false, None, near),
            "an absent token must trigger auth (lazy first read)"
        );
        assert!(
            mount_token_refresh_decision(false, Some(3600), near),
            "an absent token must trigger auth even if a stale lease TTL lingers"
        );
    }

    #[cfg(feature = "vault")]
    #[test]
    fn mount_token_reused_when_fresh() {
        // Present token with a healthy TTL (or unknown TTL) → do NOT auth. This is
        // the branch a thread takes after waiting on auth_lock: it REUSES the
        // just-minted token rather than minting a second one (WR-03).
        let near = SssFS::VAULT_TOKEN_NEAR_EXPIRY_SECS;
        assert!(
            !mount_token_refresh_decision(true, Some(near + 1), near),
            "a present token comfortably above near-expiry must be reused, not re-authed"
        );
        assert!(
            !mount_token_refresh_decision(true, Some(3600), near),
            "a present token with a long TTL must be reused"
        );
        // Unknown/zero TTL is 'usable' — must NOT hammer Vault on every read.
        assert!(
            !mount_token_refresh_decision(true, None, near),
            "a present token with unknown TTL must be reused (no per-read auth storm)"
        );
        assert!(
            !mount_token_refresh_decision(true, Some(0), near),
            "a present token with a 0 TTL is treated as unknown-but-usable, not re-authed"
        );
    }

    #[cfg(feature = "vault")]
    #[test]
    fn mount_token_refresh_at_near_expiry_boundary() {
        // On-demand renewal fires when a REAL TTL is at/below the near-expiry
        // threshold (inclusive boundary), and not one second above it.
        let near = SssFS::VAULT_TOKEN_NEAR_EXPIRY_SECS;
        assert!(
            mount_token_refresh_decision(true, Some(near), near),
            "TTL exactly at the near-expiry threshold must re-auth (inclusive)"
        );
        assert!(
            mount_token_refresh_decision(true, Some(1), near),
            "a TTL of 1s (about to expire) must re-auth"
        );
        assert!(
            !mount_token_refresh_decision(true, Some(near + 1), near),
            "a TTL one second above the threshold must NOT re-auth"
        );
    }

    // Note: Testing methods that require SssFS instance or file I/O:
    // - new() requires a real directory and Processor
    // - metadata_via_fd(), read_file_via_fd() require valid file descriptors
    // - read_and_render(), read_and_open(), read_sealed() require Processor and files
    // - write_*() methods require file I/O
    // - FUSE operations (lookup, getattr, read, write) require FUSE context
    // These are better tested through integration tests with actual filesystems

    // --- CORR-07: FUSE data integrity tests ---
    // Tests for the pure logic layer (mode parsing, file filtering) that guards
    // the read/write transformation pipeline.  Full mount tests live in
    // tests/fuse_integration.rs.

    #[test]
    fn test_transform_fuse_file_mode_all_variants() {
        // CORR-07: parse_virtual_file_mode must correctly classify every recognised
        // virtual suffix so that the correct transformation (render/open/sealed) is
        // applied on read.

        // Rendered — no suffix
        let (name, mode) = SssFS::parse_virtual_file_mode(OsStr::new("secrets.yaml"));
        assert_eq!(name, OsStr::new("secrets.yaml"));
        assert_eq!(mode, FileMode::Rendered, ".yaml with no suffix must be Rendered");

        // Opened — .sss-opened suffix
        let (name, mode) = SssFS::parse_virtual_file_mode(OsStr::new("secrets.yaml.sss-opened"));
        assert_eq!(name, OsStr::new("secrets.yaml"));
        assert_eq!(mode, FileMode::Opened, ".sss-opened suffix must give Opened mode");

        // Sealed — .sss-sealed suffix
        let (name, mode) = SssFS::parse_virtual_file_mode(OsStr::new("secrets.yaml.sss-sealed"));
        assert_eq!(name, OsStr::new("secrets.yaml"));
        assert_eq!(mode, FileMode::Sealed, ".sss-sealed suffix must give Sealed mode");
    }

    #[test]
    fn test_transform_fuse_mode_sealed_takes_priority_over_opened() {
        // CORR-07: when both virtual suffixes are stacked, only the outermost one is
        // stripped — preventing accidental mode mis-classification.
        let (name, mode) = SssFS::parse_virtual_file_mode(OsStr::new("file.sss-opened.sss-sealed"));
        // Outermost suffix is .sss-sealed → Sealed mode; inner suffix remains in basename
        assert_eq!(name, OsStr::new("file.sss-opened"));
        assert_eq!(mode, FileMode::Sealed);
    }

    #[test]
    fn test_transform_fuse_strip_suffix_opened_mode() {
        // CORR-07: strip_virtual_suffix must remove .sss-opened when in opened mode,
        // ensuring writes go to the correct backing-store path (not a .sss-opened file).
        let path = PathBuf::from("/mnt/project/config.toml.sss-opened");
        let stripped = SssFS::strip_virtual_suffix(&path, true);
        assert_eq!(stripped, PathBuf::from("/mnt/project/config.toml"),
            "Opened-mode suffix must be stripped for backing-store writes");
    }

    #[test]
    fn test_transform_fuse_strip_suffix_not_in_opened_mode() {
        // CORR-07: strip_virtual_suffix must be a no-op when not in opened mode —
        // preventing accidental path mutation for normal (Rendered) reads.
        let path = PathBuf::from("/mnt/project/config.toml.sss-opened");
        let stripped = SssFS::strip_virtual_suffix(&path, false);
        assert_eq!(stripped, path, "Path must not be modified when opened_mode=false");
    }

    #[test]
    fn test_transform_fuse_should_process_excludes_editor_artifacts() {
        // CORR-07: editor temporary files must never be passed through the
        // encryption/decryption pipeline — doing so would corrupt them or leak
        // secrets into editor state.
        for artifact in &[
            ".config.yml.swp",   // vim swap
            ".file.swo",         // vim swap (alternate)
            ".notes.swn",        // vim swap (third)
            ".tmp_file.tmp",     // generic temp
            "backup~",           // emacs/vim backup
            "#autosave#",        // emacs auto-save
        ] {
            assert!(
                !SssFS::should_process_with_sss(Path::new(artifact)),
                "Editor artifact {artifact:?} must be excluded from SSS processing"
            );
        }
    }

    #[test]
    fn test_transform_fuse_should_process_includes_regular_files() {
        // CORR-07: regular project files must pass through the encryption pipeline.
        for regular in &[
            "config.toml",
            "secrets.yaml",
            ".env",
            "src/main.rs",
            "README.md",
        ] {
            assert!(
                SssFS::should_process_with_sss(Path::new(regular)),
                "Regular file {regular:?} must be included in SSS processing"
            );
        }
    }

    // REM-18 / CON-13-001: TempFileGuard RAII drop-unlink tests.
    // Gated behind cfg(feature = "fuse") because TempFileGuard only exists in this module
    // (which is itself cfg-gated on the fuse feature).  No /dev/fuse required — these tests
    // operate on an ordinary tempdir obtained from the `tempfile` crate.

    #[test]
    #[cfg(feature = "fuse")]
    fn test_temp_file_guard_armed_drop_unlinks_file() {
        // Verify: an armed TempFileGuard unlinks its temp file when dropped.
        // This validates the REM-18 FUSE leg — Drop::drop calls unlinkat when active=true.
        use std::ffi::CString;

        let dir = tempfile::tempdir().expect("create tempdir");
        let dir_path = dir.path();

        // Obtain a directory fd for the tempdir.
        let dir_path_cstr = CString::new(dir_path.as_os_str().as_bytes())
            .expect("tempdir path is NUL-free");
        // SAFETY: dir_path is a valid UTF-8 path from tempfile::tempdir(); `dir_path_cstr`
        // is NUL-terminated. O_RDONLY|O_DIRECTORY|O_CLOEXEC is the standard safe open for
        // a directory fd. The result is checked via assert immediately after.
        let dir_fd = unsafe {
            libc::open(
                dir_path_cstr.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        assert!(dir_fd >= 0, "Failed to open tempdir as fd");

        // Create the temp file that the guard will track.
        let file_name = ".test.secret.abc12345.tmp";
        let temp_path = dir_path.join(file_name);
        std::fs::write(&temp_path, b"plaintext secret").expect("write temp file");
        assert!(temp_path.exists(), "temp file must exist before guard drop");

        let file_name_cstr = CString::new(file_name).expect("file_name is NUL-free");

        // Arm the guard and drop it WITHOUT disarming.
        // Drop::drop should call unlinkat(dir_fd, file_name_cstr, 0).
        let guard = TempFileGuard {
            dir_fd,
            path_cstr: file_name_cstr,
            active: true,
        };
        drop(guard);

        assert!(
            !temp_path.exists(),
            "TempFileGuard Drop must unlink the armed temp file"
        );

        // SAFETY: dir_fd is valid (>= 0, opened above). Closing an fd once is sound.
        unsafe { libc::close(dir_fd) };
    }

    #[test]
    #[cfg(feature = "fuse")]
    fn test_temp_file_guard_disarmed_drop_preserves_file() {
        // Verify: a disarmed TempFileGuard (active=false) does NOT unlink its file.
        // This validates the disarm path: guard.active=false after successful renameat.
        use std::ffi::CString;

        let dir = tempfile::tempdir().expect("create tempdir");
        let dir_path = dir.path();

        let dir_path_cstr = CString::new(dir_path.as_os_str().as_bytes())
            .expect("tempdir path is NUL-free");
        // SAFETY: dir_path is a valid UTF-8 path from tempfile::tempdir(); `dir_path_cstr`
        // is NUL-terminated. O_RDONLY|O_DIRECTORY|O_CLOEXEC is the standard safe open for
        // a directory fd. The result is checked via assert immediately after.
        let dir_fd = unsafe {
            libc::open(
                dir_path_cstr.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        assert!(dir_fd >= 0, "Failed to open tempdir as fd");

        let file_name = ".test.disarmed.def67890.tmp";
        let temp_path = dir_path.join(file_name);
        std::fs::write(&temp_path, b"plaintext secret").expect("write temp file");
        assert!(temp_path.exists(), "temp file must exist before guard drop");

        let file_name_cstr = CString::new(file_name).expect("file_name is NUL-free");

        // Construct guard as armed, then disarm before drop — simulating a successful rename.
        let mut guard = TempFileGuard {
            dir_fd,
            path_cstr: file_name_cstr,
            active: true,
        };
        guard.active = false; // disarm
        drop(guard);

        assert!(
            temp_path.exists(),
            "Disarmed TempFileGuard must NOT unlink its file"
        );

        std::fs::remove_file(&temp_path).ok(); // clean up
        // SAFETY: dir_fd valid, closing once.
        unsafe { libc::close(dir_fd) };
    }

    /// Verify that `vault_status_content_from_state` is value-free: it contains the
    /// required informational keys and NEVER leaks a secret token string.
    ///
    /// This test constructs a [`VaultMountState`] with a seeded fake token and asserts:
    /// 1. The output contains all required key names.
    /// 2. The output does NOT contain the fake token text (Information-Disclosure gate).
    #[test]
    #[cfg(feature = "vault")]
    fn vault_status_is_value_free() {
        use zeroize::Zeroizing;

        // Build a VaultMountState with a known fake token and a fake lease TTL.
        let fake_token = "FAKE-SECRET-TOKEN-should-never-appear-in-output";
        let fake_token_z = Zeroizing::new(fake_token.to_string());
        let fake_lease = crate::vault::auth::AuthLease {
            ttl_secs: 3600,
            renewable: true,
            expire_time: None,
        };
        let state = VaultMountState::with_token(
            std::sync::Arc::new(crate::project::VaultConfig::default()),
            crate::secrets::SecretsCache::new(),
            std::path::PathBuf::new(),
            std::path::PathBuf::new(),
            Some(fake_token_z),
            Some(fake_lease),
            /*keep_unresolved=*/ true,
        );

        let content = vault_status_content_from_state(&state);

        // Required informational keys must be present.
        assert!(content.contains("auth_method:"),     "missing auth_method field");
        assert!(content.contains("token_present:"),   "missing token_present field");
        assert!(content.contains("token_ttl_secs:"),  "missing token_ttl_secs field");
        assert!(content.contains("binding_count:"),   "missing binding_count field");
        assert!(content.contains("lockfile_drift:"),  "missing lockfile_drift field");
        assert!(content.contains("no_vault:"),        "missing no_vault field");
        assert!(content.contains("vault_lazy:"),      "missing vault_lazy field");
        assert!(content.contains("keep_unresolved:"), "missing keep_unresolved field");

        // Token TTL present as a readable value (not "unknown" — we seeded 3600).
        assert!(content.contains("token_ttl_secs: 3600"), "expected TTL 3600 in output");

        // token_present reflects a live token (we seeded one).
        assert!(content.contains("token_present: true"), "expected token_present: true");

        // CRITICAL: the fake token text must NEVER appear in the output.
        assert!(
            !content.contains(fake_token),
            "INFORMATION DISCLOSURE: vault-status output contains the token text: {content:?}"
        );
    }
}
