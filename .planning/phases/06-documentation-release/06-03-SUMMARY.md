---
phase: 06
plan: 03
subsystem: benchmarks
tags: [benchmarks, crypto, hybrid, release-smoke-test]
requirements: [DOCS-03, TEST-05]

dependency_graph:
  requires: [06-01, 06-02]
  provides: [hybrid-crypto-benchmarks, release-build-verification]
  affects: [benches/project_ops.rs]

tech_stack:
  added: [criterion 0.5 benchmark groups, base64 decode for raw byte measurement]
  patterns: [cfg-gated benchmark functions, criterion_group dual-variant pattern]

key_files:
  created: []
  modified:
    - benches/project_ops.rs

decisions:
  - "PublicKey import kept unconditional with #[allow(unused_imports)] so the hybrid build does not need a separate re-import of variants already used in cfg-gated blocks"
  - "criterion_group! split into two cfg-gated variants (hybrid / not(hybrid)) to avoid referencing undefined functions on non-hybrid builds"
  - "rpm-build/build-rpm.sh does not pass --features hybrid: this is correct for the default classic+fuse package; noted in summary for release engineer"

metrics:
  duration: ~6 min
  completed: "2026-04-26"
  tasks_completed: 2
  files_modified: 1
---

# Phase 06 Plan 03: Hybrid+Classic Benchmarks and Release Smoke Test Summary

Hybrid-vs-classic keygen/wrap/unwrap benchmarks added to `benches/project_ops.rs` with cfg-gating, plus a size-delta reporter that base64-decodes sealed keys to report accurate raw byte counts; release build smoke test passed on x86_64 Linux in 51.85 s.

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 1 | Add hybrid and classic-comparison benchmarks | 7d4ca71 | benches/project_ops.rs |
| 2 | Release-build smoke test + rpm-build features check | (this summary commit) | — |

## What Was Built

### Task 1: Benchmark additions to `benches/project_ops.rs`

New benchmark functions added after the existing `bench_open_1000_files`:

**Classic benchmarks (always compiled — comparison baseline):**
- `bench_classic_keygen` — `crypto_keygen` group, 20 samples
- `bench_classic_wrap_unwrap` — `crypto_wrap` group, 50 samples, wrap + unwrap functions

**Hybrid benchmarks (gated: `#[cfg(feature = "hybrid")]`):**
- `bench_hybrid_keygen` — `crypto_keygen` group, 10 samples (slower; fewer samples)
- `bench_hybrid_wrap_unwrap` — `crypto_wrap` group, 20 samples, wrap + unwrap functions

**Size delta reporter (always compiled):**
- `bench_sealed_key_size_delta` — `sealed_key_size` group; prints classic raw/base64 sizes unconditionally; under `#[cfg(feature = "hybrid")]` prints hybrid sizes and the per-user `.sss.toml` entry size delta (+bytes raw, +chars base64); uses `BASE64_STANDARD.decode(&sealed_b64).len()` to get accurate raw byte counts (not string length).

**Macro changes:**
- `criterion_group!(hybrid_benches, ...)` added in two cfg-gated variants (with and without hybrid functions)
- `criterion_main!(benches, hybrid_benches)` replaces `criterion_main!(benches)`

### Key type-safety notes applied

- `ClassicKeyPair.public_key` is a field (`PublicKey::Classic(...)` already wrapped) — used as `kp.public_key.clone()`
- `HybridKeyPair::public_key()` is a method returning `HybridPublicKey` — wrapped as `PublicKey::Hybrid(kp.public_key())`
- `seal_repo_key` returns `Result<String>` (base64); raw byte count obtained via `BASE64_STANDARD.decode(&sealed_b64).unwrap().len()`

## Smoke Test Result

```
Host: x86_64 Linux
Rust toolchain: rustc 1.93.1 (01f6ddf75 2026-02-11)
Command: cargo build --features hybrid --release
Exit code: 0
Result: PASSED
Duration: ~51.85 s

Last lines of output:
   Compiling sss v1.3.1 (/zpool/.../sss)
    Finished `release` profile [optimized] target(s) in 51.85s
```

## rpm-build --features status

`rpm-build/sss.spec` passes `--features fuse` on line 46 (for the FUSE mount subcommand). Neither `sss.spec` nor `build-rpm.sh` passes `--features hybrid`.

This is correct for the default classic build. `build-rpm.sh` has no `--features hybrid` line — expected. A hybrid RPM variant would require either a separate spec file or the release engineer to add `--features hybrid,fuse` to the `cargo build` invocation in `sss.spec`. No change made to either file.

## Verification

```
grep -c 'cfg(feature = "hybrid")' benches/project_ops.rs   # 5  (>= 3 required)
grep -c "bench_hybrid" benches/project_ops.rs               # 4  (>= 2 required)
grep "size_delta\|sealed_key_size" benches/project_ops.rs   # 5 lines (>= 2 required)
grep -c "BASE64_STANDARD\.decode" benches/project_ops.rs    # 2  (>= 1 required)
grep "criterion_main" benches/project_ops.rs                # contains hybrid_benches
cargo check --bench project_ops                             # Finished (0 warnings)
cargo check --features hybrid --bench project_ops           # Finished (0 warnings)
cargo build --features hybrid --release                     # EXIT 0 (PASSED)
```

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Warning] Suppressed unused `PublicKey` import on non-hybrid builds**
- **Found during:** Task 1 verification (`cargo check --bench project_ops`)
- **Issue:** `PublicKey` is only referenced inside `#[cfg(feature = "hybrid")]` blocks; without the feature, the compiler warns unused import
- **Fix:** Added `#[allow(unused_imports)]` on the unconditional import line; this keeps the import unconditional (as required by the plan) while silencing the warning on classic-only builds
- **Files modified:** `benches/project_ops.rs`
- **Commit:** 7d4ca71

## Self-Check: PASSED

- `benches/project_ops.rs` exists and contains all required functions
- Commit `7d4ca71` verified in git log
- `cargo check --bench project_ops` — clean (no errors, no warnings)
- `cargo check --features hybrid --bench project_ops` — clean (no errors, no warnings)
- `cargo build --features hybrid --release` — exit 0

## Known Stubs

None. All benchmark functions exercise live production API paths.

## Threat Flags

None. The benchmarks import only public API symbols; no new network endpoints, auth paths, file access patterns, or schema changes introduced.
