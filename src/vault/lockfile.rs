//! Vault lockfile: `VaultLockFile` / `VaultLockEntry` structs, keyed blake2b
//! digest primitive, and project-wide `⊳{}` reference-discovery walk.
//!
//! **Feature gating:** this module is NOT feature-gated.  The struct, serde,
//! digest primitive, and discovery walk are all compilable and testable on the
//! default (no `--features vault`) build so that `vault list` works without
//! network access and so unit tests for the digest cover both build arms.
//!
//! Network-touching code (resolve + recompute for `vault lock`/`update`/`verify`)
//! lives in `src/commands/vault.rs` and is gated with `#[cfg(feature = "vault")]`.

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

use crate::crypto::classic::ensure_sodium_init;
use crate::crypto::RepositoryKey;
use crate::vault::VAULT_INTERPOLATION_REGEX;

// ─── Personal-string constants ────────────────────────────────────────────────

/// Human-readable personal tag written to the lockfile header.
///
/// # Why this string is 17 bytes but `BLAKE2B_PERSONALBYTES` is 16
///
/// `"sss-vault-lock-v1"` is 17 bytes.  The libsodium constant
/// `crypto_generichash_blake2b_PERSONALBYTES` is 16.  When the personal
/// string is copied into the 16-byte zero-padded buffer used by the FFI call,
/// the trailing `"1"` is truncated.  **The effective personal parameter is
/// therefore the 16-byte string `b"sss-vault-lock-v"`.**
///
/// **THESE 16 BYTES ARE FROZEN FOREVER.**  Changing them — even by one bit —
/// invalidates every existing `.sss.vault.lock` file because all stored
/// digests were computed with the old personal.  The constant below is the
/// canonical source of truth; never recompute it inline.
pub const LOCKFILE_PERSONAL: &[u8] = b"sss-vault-lock-v1";

/// Number of bytes produced by `compute_lockfile_digest`.  Must be in the
/// range `[16, 64]` accepted by blake2b.
pub const LOCKFILE_DIGEST_LEN: usize = 32;

/// The *effective* 16-byte personal parameter actually passed to libsodium.
/// (Matches the first 16 bytes of `LOCKFILE_PERSONAL` after truncation.)
/// Documented separately so the frozen value is immediately visible.
///
/// # Why
/// See `LOCKFILE_PERSONAL`; the separation here makes it easy to grep for
/// `LOCKFILE_EFFECTIVE_PERSONAL` and understand exactly what bytes are in use.
pub const LOCKFILE_EFFECTIVE_PERSONAL: &[u8; 16] = b"sss-vault-lock-v";

// Avoid re-importing the private const from classic.rs by using the libsodium
// constant directly.  Value is 16 on all supported platforms.
const LOCKFILE_PERSONALBYTES: usize =
    libsodium_sys::crypto_generichash_blake2b_PERSONALBYTES as usize;

// ─── Digest primitive ─────────────────────────────────────────────────────────

/// Compute a 32-byte keyed `BLAKE2b` digest of `value` bound to `key`.
///
/// The personal string (`b"sss-vault-lock-v"`, 16 effective bytes) domain-
/// separates this digest from other `BLAKE2b` uses in the codebase (nonce
/// derivation uses `b"sss_autononce_v1"`).
///
/// # Security
/// The key is the repository `RepositoryKey` (32 bytes of random data, never
/// committed).  Without the key the digest is not an offline guess-and-confirm
/// oracle for low-entropy secrets — this is the T-48-01 mitigation (R1 /
/// VLOCK-03).  **Never call the FFI variant without passing `key.0` as the
/// key parameter.**
///
/// # Errors
/// Returns `Err` if libsodium initialisation fails or if the FFI call returns
/// a non-zero status code.
pub fn compute_lockfile_digest(
    key: &RepositoryKey,
    value: &[u8],
) -> Result<[u8; LOCKFILE_DIGEST_LEN]> {
    ensure_sodium_init();

    // Obtain the raw key bytes via the pub(crate) accessor.
    // `RepositoryKey.0` is a private tuple field; `to_bytes()` is the
    // crate-internal accessor that exposes the underlying `[u8; 32]`.
    let key_bytes = key.to_bytes();

    // Build a zero-padded 16-byte personal buffer.
    // LOCKFILE_PERSONAL is 17 bytes; only the first 16 fit.  See the module-
    // level doc on LOCKFILE_PERSONAL for why this truncation is intentional
    // and frozen.
    let mut personal_padded = [0u8; LOCKFILE_PERSONALBYTES];
    let copy_len = LOCKFILE_PERSONAL.len().min(LOCKFILE_PERSONALBYTES);
    personal_padded[..copy_len].copy_from_slice(&LOCKFILE_PERSONAL[..copy_len]);
    // personal_padded is now b"sss-vault-lock-v" (16 bytes; trailing "1" truncated).
    debug_assert_eq!(&personal_padded, LOCKFILE_EFFECTIVE_PERSONAL.as_slice());

    let mut out = [0u8; LOCKFILE_DIGEST_LEN];

    #[cfg(not(miri))]
    {
        // SAFETY: `ensure_sodium_init()` guarantees libsodium is initialised.
        // - `out` is a stack buffer of exactly `LOCKFILE_DIGEST_LEN` (32) bytes,
        //   within blake2b's valid output range [16, 64].
        // - `value` is a valid slice; `value.as_ptr()` / `value.len()` are a
        //   consistent (ptr, len) pair.
        // - `key_bytes.len()` is `SYMMETRIC_KEY_SIZE` (32 bytes), within blake2b's
        //   valid key range [1, 64].
        // - `std::ptr::null()` is accepted by libsodium for the salt parameter
        //   when no salt is required.
        // - `personal_padded` is exactly `LOCKFILE_PERSONALBYTES` (16) bytes.
        // Returns 0 on success; non-zero on invalid parameters.
        let ret = unsafe {
            libsodium_sys::crypto_generichash_blake2b_salt_personal(
                out.as_mut_ptr(),
                LOCKFILE_DIGEST_LEN,
                value.as_ptr(),
                value.len() as u64,
                key_bytes.as_ptr(),
                key_bytes.len(),
                std::ptr::null(),
                personal_padded.as_ptr(),
            )
        };
        if ret != 0 {
            return Err(anyhow!("BLAKE2b lockfile digest failed"));
        }
    }
    #[cfg(miri)]
    {
        // Miri cannot execute FFI; return a zero buffer so surrounding logic
        // (buffer layout, Result<_> chain) can be exercised.
        let _ = (value, key_bytes, personal_padded);
    }

    Ok(out)
}

/// Encode a digest byte slice as a lowercase hex string.
///
/// Returns a 64-character string for a 32-byte input (2 × `LOCKFILE_DIGEST_LEN`).
#[must_use]
pub fn digest_to_hex(digest: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(digest.len() * 2);
    for b in digest {
        // `write!` on a `String` is infallible; the `let _ =` suppresses
        // the unused-result lint without `unwrap`.
        let _ = write!(s, "{b:02x}");
    }
    s
}

// ─── Lockfile structs ─────────────────────────────────────────────────────────

/// The contents of a `.sss.vault.lock` file.
///
/// Serialises to TOML via `toml_helpers::serialize_toml` (which calls
/// `toml::to_string_pretty`).  The `entries` field is a `BTreeMap` so keys
/// are sorted lexicographically, producing deterministic TOML output across
/// runs — this is essential for clean `git diff` output.
///
/// The `personal` field is a human-readable marker that records which personal
/// string was used when the lockfile was created.  **It is NOT the literal FFI
/// input** — the effective 16-byte input is `b"sss-vault-lock-v"` (the first
/// 16 bytes of `LOCKFILE_PERSONAL` after truncation).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VaultLockFile {
    /// Lockfile schema version (always `1` for Phase 48).
    pub version: u32,
    /// Human-readable personal-string marker.  Documents which domain-
    /// separation tag was used; the actual effective FFI parameter is the
    /// first 16 bytes (`b"sss-vault-lock-v"`).
    pub personal: String,
    /// Locked references, keyed by canonical reference string.  `BTreeMap`
    /// ensures lexicographic order for deterministic serialisation.
    pub entries: BTreeMap<String, VaultLockEntry>,
}

/// A single locked vault reference.
///
/// Records `{binding, path, field, version, digest}` per VLOCK-02.
/// **No plaintext secret value is ever stored here** — only the keyed digest.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VaultLockEntry {
    /// Vault binding name from `.sss.toml`.
    pub binding: String,
    /// KV path (e.g., `"secret/data/myapp"`).
    pub path: String,
    /// Field name within the KV document.
    pub field: String,
    /// Concrete KV v2 version that was resolved.  `0` means no versioning
    /// (latest, unpinned).
    pub version: u64,
    /// Pin ORIGIN: whether the SOURCE `⊳{}` reference carried an explicit `@N`.
    ///
    /// This is distinct from the concrete resolved [`version`](Self::version):
    /// - `pinned == true`  ⇒ the source ref was written `⊳{…@N}`; `version` is
    ///   that literal pin and is an immutable integrity target.  `vault verify`
    ///   re-resolves that exact `@N` — a *newer* KV version existing is NOT
    ///   drift (VLOCK-01).
    /// - `pinned == false` ⇒ the source ref tracks latest (`⊳{…}` with no `@N`)
    ///   and `version` is merely the lock-time resolved KV version.  `vault
    ///   verify` re-resolves LATEST and compares digests, so a secret rotation
    ///   is meaningful drift (VLOCK-05).
    ///
    /// `#[serde(default)]` so any `.sss.vault.lock` TOML written before this
    /// field existed still deserialises (forward/back-compat); a missing key
    /// reads as `false`.
    #[serde(default)]
    pub pinned: bool,
    /// Lowercase hex digest (64 chars for a 32-byte output).
    pub digest: String,
}

impl VaultLockFile {
    /// Construct an empty lockfile with schema version `1` and the full
    /// (17-byte) personal tag as the documentary `personal` field.
    ///
    /// The `personal` field is human-readable; the effective 16-byte FFI
    /// parameter is documented in `LOCKFILE_PERSONAL`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            version: 1,
            personal: String::from_utf8_lossy(LOCKFILE_PERSONAL).into_owned(),
            entries: BTreeMap::new(),
        }
    }

    /// Canonical `BTreeMap` key for an entry.
    ///
    /// Keys on pin ORIGIN ([`pinned`](VaultLockEntry::pinned)), NOT on
    /// `version`: `"binding:path#field@N"` for a `@N`-pinned entry, or
    /// `"binding:path#field"` for a latest-tracking (unpinned) entry — even
    /// when an unpinned ref resolved to a concrete `version > 0`.
    ///
    /// Keying on `version > 0` would collide an unpinned ref that resolved to
    /// version N with a `@N`-pinned ref to the same path/field, silently
    /// overwriting one in the `BTreeMap` and downgrading the pinned integrity
    /// check to latest-tracking (WR-01).  This MUST mirror the `inner_ref`
    /// reconstruction in `vault_verify`, which also branches on `pinned`.
    #[must_use]
    pub fn canonical_key(entry: &VaultLockEntry) -> String {
        if entry.pinned {
            format!(
                "{}:{}#{}@{}",
                entry.binding, entry.path, entry.field, entry.version
            )
        } else {
            format!("{}:{}#{}", entry.binding, entry.path, entry.field)
        }
    }

    /// Read a lockfile from `path`.
    ///
    /// # Errors
    /// Returns `Err` if the file cannot be read or if the TOML is malformed.
    pub fn read(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| anyhow!("failed to read lockfile {}: {e}", path.display()))?;
        toml::from_str(&content)
            .map_err(|e| anyhow!("failed to parse lockfile {}: {e}", path.display()))
    }

    /// Serialise and write the lockfile atomically to `target`.
    ///
    /// Uses `crate::config::write_atomic_bytes` (temp-in-parent → rename) so
    /// a failure leaves `target` untouched.
    ///
    /// # Errors
    /// Returns `Err` if serialisation fails or if the atomic write fails.
    pub fn write_atomic(&self, target: &Path) -> Result<()> {
        let toml_str = crate::toml_helpers::serialize_toml(self, "vault lockfile")?;
        crate::config::write_atomic_bytes(toml_str.as_bytes(), target)
    }
}

impl Default for VaultLockFile {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Reference discovery ──────────────────────────────────────────────────────

/// A single `⊳{}` vault reference found by `discover_vault_references`.
#[derive(Debug, Clone)]
pub struct VaultRefDiscovery {
    /// Path of the file that contains the reference.
    pub file: PathBuf,
    /// Raw matched string (e.g., `"⊳{kv:secret/app#password}"`).
    pub raw_ref: String,
}

/// Walk `project_root`, find every `⊳{}` vault reference in text files, and
/// return them sorted by `raw_ref` for deterministic `vault list` output.
///
/// # Skip list
/// The following directories are pruned (mirroring
/// `process_project_recursively` in `src/commands/process.rs`):
/// - `target` (Cargo build artefacts)
/// - `.git`
/// - `node_modules`
/// - `dist`
/// - `build`
///
/// # Binary file guard
/// Before running the regex, the first 8 KiB of each file is checked for NUL
/// bytes.  Files containing NUL are treated as binary and skipped.  This
/// prevents false positives (and potential panic paths) when the walk
/// encounters `.so` files, Git pack files, or other binary artefacts (T-48-04).
///
/// # Errors
/// Returns `Err` only for `WalkDir` errors that cannot be recovered by
/// `continue`.  Read errors on individual files are silently skipped.
pub fn discover_vault_references(project_root: &Path) -> Result<Vec<VaultRefDiscovery>> {
    // Why: mirrors the skip-dir list from process_project_recursively
    // (src/commands/process.rs:597).  Keep in sync if that list changes.
    const SKIP_DIRS: &[&str] = &["target", "node_modules", ".git", "dist", "build"];

    let mut refs: Vec<VaultRefDiscovery> = Vec::new();

    for entry in WalkDir::new(project_root)
        .follow_links(false)
        .into_iter()
        .filter_entry(|e| {
            if e.file_type().is_dir() {
                let name = e.file_name().to_string_lossy();
                !SKIP_DIRS.contains(&name.as_ref())
            } else {
                true
            }
        })
    {
        let Ok(entry) = entry else { continue };
        if !entry.file_type().is_file() {
            continue;
        }

        let Ok(raw) = std::fs::read(entry.path()) else { continue };

        // Binary-file guard: skip files whose first 8 KiB contains a NUL byte.
        if raw[..raw.len().min(8192)].contains(&0u8) {
            continue;
        }

        let content = String::from_utf8_lossy(&raw);
        for m in VAULT_INTERPOLATION_REGEX.find_iter(&content) {
            refs.push(VaultRefDiscovery {
                file: entry.path().to_owned(),
                raw_ref: m.as_str().to_owned(),
            });
        }
    }

    // Sort by raw_ref for deterministic vault list / vault lock output.
    refs.sort_by(|a, b| a.raw_ref.cmp(&b.raw_ref));
    Ok(refs)
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::RepositoryKey;

    // ── Helper: two distinct RepositoryKeys ──────────────────────────────────

    fn key1() -> RepositoryKey {
        // Safety: from_bytes validates length; 32 bytes of 0x01 is a valid key.
        RepositoryKey::from_bytes(&[1u8; 32]).expect("key1")
    }

    fn key2() -> RepositoryKey {
        RepositoryKey::from_bytes(&[2u8; 32]).expect("key2")
    }

    // ── compute_lockfile_digest ───────────────────────────────────────────────

    #[test]
    fn deterministic_digest() {
        let k = key1();
        let d1 = compute_lockfile_digest(&k, b"hunter2").expect("digest 1");
        let d2 = compute_lockfile_digest(&k, b"hunter2").expect("digest 2");
        assert_eq!(d1, d2, "same key + value must yield identical digest");
    }

    #[test]
    fn different_keys_different_digest() {
        // VLOCK-03: proves the oracle-closure property.
        // Two repositories with different RepositoryKeys must produce
        // different digests for the same secret value.  If this test fails
        // the digest is effectively unkeyed.
        let d1 = compute_lockfile_digest(&key1(), b"hunter2").expect("digest k1");
        let d2 = compute_lockfile_digest(&key2(), b"hunter2").expect("digest k2");
        assert_ne!(
            d1, d2,
            "different repo keys MUST produce different digests for the same value (VLOCK-03)"
        );
    }

    #[test]
    fn digest_to_hex_format() {
        // 32-byte input → 64-character lowercase hex string.
        let digest = [0xde, 0xad, 0xbe, 0xef];
        let hex = digest_to_hex(&digest);
        assert_eq!(hex.len(), 8, "2 hex chars per byte");
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()));
        assert_eq!(hex, "deadbeef");

        // Full 32-byte digest.
        let full = compute_lockfile_digest(&key1(), b"x").expect("digest");
        let h = digest_to_hex(&full);
        assert_eq!(h.len(), 64);
        assert!(h.chars().all(|c| "0123456789abcdef".contains(c)));
    }

    // ── write_atomic_bytes (via config) ──────────────────────────────────────

    #[test]
    fn write_atomic_bytes_roundtrip() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let target = dir.path().join("out.bin");
        crate::config::write_atomic_bytes(b"hello world", &target).expect("write");
        let got = std::fs::read(&target).expect("read");
        assert_eq!(got, b"hello world");
    }

    #[test]
    fn write_atomic_bytes_no_parent_errors() {
        // A path whose parent() returns None must return Err.
        // Path::new("") has no parent component on all platforms.
        let result = crate::config::write_atomic_bytes(b"x", Path::new(""));
        assert!(result.is_err(), "no-parent path must return Err");
    }

    // ── VaultLockFile / VaultLockEntry ───────────────────────────────────────

    fn sample_lockfile() -> VaultLockFile {
        let mut lf = VaultLockFile::new();
        let e1 = VaultLockEntry {
            binding: "kv".into(),
            path: "secret/app".into(),
            field: "password".into(),
            version: 0,
            pinned: false,
            digest: "aabbcc".into(),
        };
        let e2 = VaultLockEntry {
            binding: "kv".into(),
            path: "secret/db".into(),
            field: "url".into(),
            version: 2,
            pinned: true,
            digest: "ddeeff".into(),
        };
        let key1 = VaultLockFile::canonical_key(&e1);
        let key2 = VaultLockFile::canonical_key(&e2);
        lf.entries.insert(key1, e1);
        lf.entries.insert(key2, e2);
        lf
    }

    #[test]
    fn serde_roundtrip() {
        // RESEARCH open question #2: confirm BTreeMap round-trips correctly
        // under toml 0.8.
        let lf = sample_lockfile();
        let toml_str = crate::toml_helpers::serialize_toml(&lf, "test").expect("serialize");
        let back: VaultLockFile = toml::from_str(&toml_str).expect("deserialize");
        assert_eq!(lf, back, "VaultLockFile must round-trip through TOML");
    }

    #[test]
    fn deterministic() {
        // Serialising the same lockfile twice must produce byte-identical TOML.
        let lf = sample_lockfile();
        let s1 = crate::toml_helpers::serialize_toml(&lf, "test").expect("s1");
        let s2 = crate::toml_helpers::serialize_toml(&lf, "test").expect("s2");
        assert_eq!(s1, s2, "TOML serialisation must be deterministic");
    }

    #[test]
    fn no_plaintext() {
        // VLOCK-02: the serialised lockfile must not contain any plaintext
        // secret value.
        let known_plaintext = "super_secret_value";
        let mut lf = VaultLockFile::new();
        let d = compute_lockfile_digest(&key1(), known_plaintext.as_bytes())
            .expect("digest");
        let entry = VaultLockEntry {
            binding: "kv".into(),
            path: "secret/app".into(),
            field: "pass".into(),
            version: 0,
            pinned: false,
            digest: digest_to_hex(&d),
        };
        let k = VaultLockFile::canonical_key(&entry);
        lf.entries.insert(k, entry);
        let toml_str = crate::toml_helpers::serialize_toml(&lf, "test").expect("serialize");
        assert!(
            !toml_str.contains(known_plaintext),
            "lockfile TOML must not contain the plaintext value (VLOCK-02)"
        );
    }

    #[test]
    fn canonical_key() {
        let e_unversioned = VaultLockEntry {
            binding: "kv".into(),
            path: "secret/app".into(),
            field: "pass".into(),
            version: 0,
            pinned: false,
            digest: String::new(),
        };
        let e_versioned = VaultLockEntry {
            version: 3,
            pinned: true,
            ..e_unversioned.clone()
        };
        assert_eq!(
            VaultLockFile::canonical_key(&e_unversioned),
            "kv:secret/app#pass"
        );
        assert_eq!(
            VaultLockFile::canonical_key(&e_versioned),
            "kv:secret/app#pass@3"
        );
    }

    #[test]
    fn unpinned_resolved_version_does_not_collide_with_pinned() {
        // WR-01 regression: an UNPINNED ref `⊳{kv:secret/app#pass}` that Vault
        // resolves to version 5 records `version = 5, pinned = false`.  Its
        // canonical key must be `kv:secret/app#pass` (NO `@5`) so it does NOT
        // collide with a `@5`-PINNED ref to the same path/field.  Keying on
        // `version > 0` (the pre-fix behaviour) produced the same `…@5` key for
        // both, silently overwriting one in the BTreeMap and downgrading the
        // pinned integrity check to latest-tracking with no diagnostic.
        let unpinned_resolved_v5 = VaultLockEntry {
            binding: "kv".into(),
            path: "secret/app".into(),
            field: "pass".into(),
            version: 5,
            pinned: false,
            digest: String::new(),
        };
        let pinned_v5 = VaultLockEntry {
            pinned: true,
            ..unpinned_resolved_v5.clone()
        };
        assert_eq!(
            VaultLockFile::canonical_key(&unpinned_resolved_v5),
            "kv:secret/app#pass",
            "unpinned entry keys on pin-origin (no @N) even when version > 0"
        );
        assert_eq!(
            VaultLockFile::canonical_key(&pinned_v5),
            "kv:secret/app#pass@5"
        );
        assert_ne!(
            VaultLockFile::canonical_key(&unpinned_resolved_v5),
            VaultLockFile::canonical_key(&pinned_v5),
            "unpinned-resolved-to-N and @N-pinned must NOT collide (WR-01)"
        );
        // Both must coexist as distinct entries in one lockfile.
        let mut lf = VaultLockFile::new();
        lf.entries.insert(
            VaultLockFile::canonical_key(&unpinned_resolved_v5),
            unpinned_resolved_v5,
        );
        lf.entries
            .insert(VaultLockFile::canonical_key(&pinned_v5), pinned_v5);
        assert_eq!(
            lf.entries.len(),
            2,
            "both entries must survive — no BTreeMap collision (WR-01)"
        );
    }

    #[test]
    fn pinned_serde_default_back_compat() {
        // Forward/back-compat: a `.sss.vault.lock` written before the `pinned`
        // field existed has an [entries.*] table with NO `pinned` key.  The
        // `#[serde(default)]` annotation must let it deserialise, defaulting
        // `pinned` to `false`.  (A pre-field lockfile is, by definition, the
        // old "version-only" shape where drift was structurally undetectable,
        // so `false` — "treat as unpinned / track latest" — is the correct,
        // drift-meaningful default.)
        let toml_no_pinned = r#"
version = 1
personal = "sss-vault-lock-v1"

[entries."kv:secret/app#pass"]
binding = "kv"
path = "secret/app"
field = "pass"
version = 0
digest = "aabbcc"
"#;
        let lf: VaultLockFile =
            toml::from_str(toml_no_pinned).expect("pinned-less lockfile must deserialise");
        let entry = lf
            .entries
            .get("kv:secret/app#pass")
            .expect("entry present");
        assert!(
            !entry.pinned,
            "a `pinned`-less TOML entry must default to pinned == false (#[serde(default)])"
        );
        // Sanity: the rest of the entry still parsed correctly.
        assert_eq!(entry.version, 0);
        assert_eq!(entry.binding, "kv");
        assert_eq!(entry.digest, "aabbcc");
    }

    // ── discover_vault_references ─────────────────────────────────────────────

    #[test]
    fn discover() {
        // VCLI-03 + T-48-04: discovery finds ⊳{} refs sorted, skips binaries.
        let dir = tempfile::tempdir().expect("tmpdir");
        let root = dir.path();

        // File 1: one ⊳{} reference
        std::fs::write(
            root.join("config.yaml"),
            "password: ⊳{kv:secret/app#password}\n",
        )
        .expect("write file1");

        // File 2: one pinned reference
        std::fs::write(
            root.join("db.conf"),
            "url = >{ kv:secret/db#url@2 }\n",
        )
        .expect("write file2");

        // Binary file: starts with NUL — must be skipped.
        let mut binary = vec![0u8, 1, 2, 3];
        binary.extend_from_slice(b"\xe2\x8a\xb3{kv:should/not#appear}");
        std::fs::write(root.join("binary.bin"), &binary).expect("write binary");

        let refs = discover_vault_references(root).expect("discover");

        // Only the two text-file refs should appear.
        assert_eq!(refs.len(), 2, "expected 2 refs, got: {refs:?}");

        // Results must be sorted by raw_ref.
        let raw: Vec<&str> = refs.iter().map(|r| r.raw_ref.as_str()).collect();
        let mut expected = raw.clone();
        expected.sort_unstable();
        assert_eq!(raw, expected, "refs must be sorted");

        // The binary file ref must not appear.
        assert!(
            refs.iter().all(|r| !r.raw_ref.contains("should/not")),
            "binary file must be skipped"
        );
    }
}
