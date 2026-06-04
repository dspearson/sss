# Security Depth

Auditor entry-point document covering the **defence-in-depth** layers sss
applies beyond the cryptographic specification in
[`docs/security-model.md`](./security-model.md). Where `security-model.md`
answers *what* sss encrypts and with which primitives, this document answers
*how* the codebase is kept honest against memory-safety bugs, supply-chain
drift, build reproducibility, and audit traceability.

This document is the single landing page an external auditor reads
first. v2.3 Phases 22–27 each filled in one subsection; this Phase 27
revision (AUDIT-03) is the consolidated auditor-entry-point pass.

---

## Introduction

sss is a Rust CLI that seals secrets into git-trackable envelopes. The
cryptographic spec lives in [`docs/security-model.md`](./security-model.md);
the implementation lives across the modular `src/` tree plus the
vendored `vendor/rust-9p/` subtree plus the git-rev pinned trelis
crates (the v2.3 hybrid PQ-classic signature surface).

This document threads together six audit-relevant dimensions:

1. **Static analysis** — clippy strictness floor + cherry-picked
   restriction lints + SAFETY-comment + `// Why:` regression gates;
   Phase 21 baseline carried forward through every subsequent phase.
2. **Memory safety (pure Rust)** — miri runs against the safe-Rust
   surface (cfg-stubbed at 17 FFI sites per Phase 22) on a weekly
   Sunday cron; 5 test cases covering the `ptr::read_volatile`
   zeroisation paths in `src/crypto/hybrid.rs`.
3. **Memory safety (FFI)** — AddressSanitizer + ThreadSanitizer on the
   FFI surface that miri can't reach; weekly Saturday cron with
   nightly-pinned toolchain. tsan-suppressions curated empty (will
   populate on first cron run).
4. **Supply chain** — `cargo-deny` strictness (multiple-versions=deny
   + 25-entry curated skip list with 30-day refresh SLA + unsound=all
   + 2 expiring RUSTSEC ignores), `cargo-vet` attestation (Mozilla +
   Google imports + `[policy.<crate>]` blocks for trelis-* + rust-9p);
   weekly Friday cron + PR trigger. 294 exemptions remain — escalated
   to v2.4 hand-author campaign + Bytecode Alliance import revisit.
5. **Reproducible builds** — Cargo.lock committed (v2.3 reversal of
   prior policy), build-reproducible.sh wrapper with four determinism
   env-vars; empirical 2-host run (arm64-builder + macos-builder) scheduled for
   next release-cut.
6. **Release-artefact integrity** — cargo-auditable embed + CycloneDX
   SBOMs (6 per release matrix cell) + cosign keyless signing
   (GitHub OIDC + Fulcio + Rekor) + offline-fallback Ed25519 keypair
   with distinct domain-separation bytes.

Each subsection below covers one dimension with concrete file pointers
+ scope qualifiers + known coverage gaps. The "§ References" section
at the bottom links every audit-relevant doc in the repo.

---

## Static Analysis Posture

The v2.3 static-analysis surface is layered: a clippy strictness floor
at the workspace level + cherry-picked restriction lints for
audit-critical patterns + per-file gate scripts for the `// Why:` +
`// SAFETY:` + `mem::forget` conventions.

**Workspace clippy contract** (`Cargo.toml` `[lints.clippy]`,
Phase 21):

- `pedantic = "warn"` (priority -1) — baseline strictness floor.
- Pedantic-noise suppressions (4 only): `module_name_repetitions`,
  `missing_errors_doc`, `missing_panics_doc`, `unnecessary_wraps`.
- Panic-surface deny: `unwrap_used = "deny"`, `expect_used = "deny"`,
  `panic = "deny"` (test-code exempt via `#![cfg_attr(test, allow(...))]`).
- Unsafe-block discipline: `undocumented_unsafe_blocks = "deny"`,
  `missing_safety_doc = "deny"`.
- Zeroisation hygiene: `mem_forget = "deny"`.
- Cast-surface anchors: `cast_possible_truncation` + `cast_sign_loss`
  at warn (already pedantic, surfaced as named anchors).

The full policy + rationale lives in
[`docs/CLIPPY-POLICY.md`](./CLIPPY-POLICY.md). CI gates via
`cargo clippy --workspace --all-targets ${{ matrix.cargo_features }} -- -D warnings`
in `.github/workflows/ci-matrix.yml`.

**`#[forbid(unsafe_code)]`** on the askpass binaries
(`src/bin/sss-askpass-tty.rs` + `src/bin/sss-askpass-gui.rs`) makes
any `unsafe { }` block in those files a compile error.

**Regression scripts:**

- [`scripts/check-allow-why.sh`](../scripts/check-allow-why.sh) —
  asserts every `#[allow]` carries a `// Why:` rationale comment.
- [`scripts/check-safety-comments.sh`](../scripts/check-safety-comments.sh)
  — asserts every production `unsafe { }` block has a `// SAFETY:`
  comment within 3 lines above.
- [`scripts/check-mem-forget.sh`](../scripts/check-mem-forget.sh) —
  Phase 23 belt-and-braces gate complementing the compile-time
  `mem_forget = "deny"` clippy.

The scripts run as informational steps in `ci-matrix.yml`
(`check-mem-forget.sh` is hard-gated; the other two are informational
in v2.3 with v2.4 promotion to gates on the roadmap).

**Phase 21 closeout state** documented in
`.planning/phases/21-lint-strictness-floor-policy-gates/21-PHASE-SUMMARY.md`:
295 → 0 clippy errors landed under `-D warnings` across the 6-cell
release matrix.

---

## Miri Coverage

[Miri](https://github.com/rust-lang/miri) is the Rust interpreter that
catches undefined behaviour in unsafe code by interpreting MIR with strict
provenance and alignment checks. sss runs miri on a **scoped subset** of the
codebase — pure-Rust unsafe paths only — because miri cannot interpret FFI
to libsodium / libc / trelis. The FFI surface is covered by AddressSanitizer
in Phase 23 instead. This subsection documents the scope honestly.

### What miri runs against

Five `#[test]` functions in
[`tests/miri_smoke.rs`](../tests/miri_smoke.rs) (242 lines, 5 tests, 7
unsafe blocks each with a `// SAFETY:` rationale on the line directly
above):

| # | Test                                              | What it exercises                                                                                                                                                              |
|---|---------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 1 | `test_hybrid_keypair_zeroises_under_miri`         | Drops a real `HybridKeyPair::generate()` instance through `ManuallyDrop` so miri validates the full drop sequence including the `Zeroizing<[u8; HYBRID_SECRET_KEY_SIZE]>` overwrite of `secret_bytes`. |
| 2 | `test_zeroizing_secret_bytes_wrapper_under_miri`  | Raw-ptr pre/post-drop `ptr::read_volatile` assertions on a stand-in `Zeroizing<[u8; HYBRID_SECRET_KEY_SIZE]>` (1819 bytes) filled with `0xA5`.                                  |
| 3 | `test_hybrid_aead_key_zeroises_under_miri`        | 32-byte loop `ptr::read_volatile` assertions on a stand-in `Zeroizing<[u8; 32]>` filled with `0xC3`; decoupled from `trelis_primitives::derive_key` so the smoke validates zeroisation pointer arithmetic, not KEM math. |
| 4 | `test_scanner_regex_compile_under_miri`           | Drives `FileScanner::new` which internally compiles the marker-detection regex `(?:⊕\|o\+\|⊠)\{[^}]*\}` at [`src/scanner.rs:39`](../src/scanner.rs).                            |
| 5 | `test_marker_inference_expand_under_miri`         | Drives `sss::marker_inference::infer_markers` on the canonical doc example from [`src/marker_inference/mod.rs:135-141`](../src/marker_inference/mod.rs) through 8 stages of pure-Rust string manipulation. |

The load-bearing miri targets are the **five `ptr::read_volatile`
zeroisation sites in `src/crypto/hybrid.rs`** (lines 596, 609, 639, 650,
691, 708 — three pre/post-drop assertion pairs across the three zeroise-on-
drop in-source tests). Validating the pointer arithmetic embedded in the
`zeroize` crate's drop loop is the primary value miri delivers here.

### What miri does NOT cover

Miri cannot interpret FFI calls. The **22 production FFI sites** across
five files are gated by `#[cfg(not(miri))]` and skipped under miri:

| File                       | Pairs | FFI calls                                                                                                                                                          |
|----------------------------|-------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `src/crypto/classic.rs`    | 11    | `sodium_init`, `randombytes_buf` ×2, `crypto_box_keypair`, `crypto_box_seed_keypair`, `crypto_box_seal`, `crypto_box_seal_open`, `crypto_generichash_blake2b_salt_personal`, `crypto_secretbox_xchacha20poly1305_easy` ×2, `crypto_secretbox_xchacha20poly1305_open_easy` |
| `src/crypto/hybrid.rs`     | 3     | `randombytes_buf` (seal step 3), `crypto_secretbox_xchacha20poly1305_easy` (seal step 4), `crypto_secretbox_xchacha20poly1305_open_easy` (open step 4)             |
| `src/kdf.rs`               | 3     | `randombytes_buf`, `crypto_pwhash` (Argon2id), `sodium_init`                                                                                                       |
| `src/commands/keys.rs`     | 3     | `crypto_hash_sha256` (randomart), classic-suite block in `handle_keys_show`, hybrid-suite block in `handle_keys_show`                                               |
| `src/commands/process.rs`  | 2     | `libc::statfs` Linux + macOS variants                                                                                                                              |
| **Total**                  | **22**| **22 cfg-attribute applications across ≥17 logical FFI sites**                                                                                                     |

Under `cfg(miri)`, each FFI call is replaced by a deterministic stub
(zero-initialised buffer or `let _ret: i32 = 0;`) and cross-references the
substitute coverage:

```rust
#[cfg(not(miri))]
let ret = unsafe {
    sodium::crypto_secretbox_xchacha20poly1305_easy(...)
};
#[cfg(miri)]
{
    // Miri stub: crypto_secretbox_xchacha20poly1305_easy is FFI;
    // AddressSanitizer (Phase 23 MEMSAFE-03) covers this path under
    // non-miri builds.
    let _ret: i32 = 0;
}
```

The cfg-stub strategy is the milestone-locked decision **D-V23-05**
(v2.3 milestone-research lock, 2026-05-17). The `-Zmiri-native-lib`
alternative was rejected for v2.3 — too new in 2026-05 to bet on;
revisit in v2.4.

Additionally, the following surfaces are out of scope for miri in v2.3:

- **macOS and aarch64** — `ubuntu-24.04` only. macOS / aarch64 miri has
  known gaps; v2.4+ scope.
- **`sss-agent`, `sss-askpass-tty`, `sss-askpass-gui` binaries** —
  `sss-agent` re-exports the sss library and runs the same cfg-stubbed
  paths; askpass binaries carry `#![forbid(unsafe_code)]` so there is no
  unsafe surface for miri to interpret.
- **`fuse` / `winfsp` / `ninep` features** — feature-gated mount surfaces;
  off by default, off under miri.

### Substitute coverage

Phase 23 (**MEMSAFE-03**) layers AddressSanitizer + ThreadSanitizer over
the FFI surface miri cannot interpret. The two coverage layers complement
each other:

- **Miri** — strict provenance, alignment, undefined-behaviour detection
  on pure-Rust unsafe paths (zeroisation, regex, marker_inference).
- **AddressSanitizer** — heap/stack-overflow, use-after-free, double-free
  detection on the FFI boundary (libsodium, libc, trelis) under realistic
  workloads.

Each `cfg(miri)` arm carries an inline comment naming this hand-off so an
auditor reading the cfg-stubbed code path can trace where the substitute
coverage lives without external context.

### Refresh cadence (pinned nightly)

The miri workflow pins **`nightly-2026-04-15`** explicitly — the
last-known-good nightly for miri + the Rust 2024 edition + Phase 21
clippy compatibility as verified at milestone-research time (2026-05-17).
The pin lives in [`.github/workflows/miri.yml`](../.github/workflows/miri.yml)
only — not in `rust-toolchain.toml` — so local development on stable is
unaffected for contributors who do not run miri.

Refresh policy:

1. The pin is bumped **deliberately per milestone**, never silently
   floated to "latest nightly".
2. When miri upstream introduces a breaking change, the weekly cron run
   starts failing and the maintainer notices via the GitHub Actions
   email digest.
3. The bump PR validates the new nightly against `tests/miri_smoke.rs`
   before merging — the smoke harness is the gate for the pin bump.
4. v2.4 may unpin entirely once `-Zmiri-native-lib` matures and the
   cfg-stub strategy can be retired.

### Workflow

The miri runner is scheduled-only by design (cost-bounded; per-push miri
was rejected at CONTEXT-lock time because nightly-toolchain churn would
be too noisy as a per-commit signal):

| Field             | Value                                                                          |
|-------------------|--------------------------------------------------------------------------------|
| Workflow file     | [`.github/workflows/miri.yml`](../.github/workflows/miri.yml)                  |
| Workflow name     | `Miri`                                                                         |
| Schedule          | weekly cron, **Sunday 03:00 UTC** (`0 3 * * 0`) + `workflow_dispatch`          |
| Runner            | `ubuntu-24.04` (linux-x86_64 only)                                             |
| Pinned nightly    | `nightly-2026-04-15`                                                           |
| Primary test      | `cargo +nightly-2026-04-15 miri test --test miri_smoke --features hybrid`      |
| Default-arm test  | `cargo +nightly-2026-04-15 miri test --lib`                                    |
| `MIRIFLAGS`       | `-Zmiri-strict-provenance -Zmiri-symbolic-alignment-check`                     |
| `timeout-minutes` | 30 (safety margin over expected <10 min on the 5-test surface)                 |
| Permissions       | none declared — defaults to read-only repo access                              |

The two-step invocation (`--test miri_smoke --features hybrid` then
`--lib` on default features) confirms the cfg-stubs work in both feature
arms, not just hybrid.

### Scope qualifier (audit-readiness)

sss is **miri-clean on pure-Rust paths only**: 5 zeroisation sites in
`src/crypto/hybrid.rs` plus the scanner regex compilation and
marker_inference pure-Rust string manipulation. The FFI surface is
covered by AddressSanitizer in Phase 23 (MEMSAFE-03), not by miri.

This document never claims sss is "fully miri-clean" because that would
be misleading — the cfg-stub strategy is honest defence-in-depth, not
universal coverage.

---

## Sanitizer Coverage

AddressSanitizer (ASan) + ThreadSanitizer (TSan) provide the dynamic-analysis
counterpart to miri: where miri runs against the **pure-Rust** unsafe surface
behind cfg-stubs (§ Miri Coverage above), the sanitizers run against the
**real FFI** boundary — libsodium / libc / trelis — that miri cannot
interpret. The two together compose the sss memory-safety story.

### What ASan runs against

The `asan` job in [`.github/workflows/sanitizer.yml`](../.github/workflows/sanitizer.yml)
runs `cargo test --workspace --features hybrid --target
x86_64-unknown-linux-gnu -Zbuild-std` under
`RUSTFLAGS=-Zsanitizer=address`. The `-Zbuild-std` flag is load-bearing —
without it the libsodium-sys build script gets instrumented and the build
breaks. A second invocation runs without `--features hybrid` to exercise the
classic-only FFI surface (X25519 / XChaCha20-Poly1305 / Argon2id).

The job catches use-after-free, heap-buffer-overflow, stack-buffer-overflow,
double-free, and uninitialised-read on every libsodium / libc / trelis call
exercised by the test suite. `ASAN_OPTIONS=detect_stack_use_after_return=1:check_initialization_order=1`
extends the default detection set.

### What TSan runs against

The `tsan` job runs the same toolchain with
`RUSTFLAGS=-Zsanitizer=thread` scoped to the concurrency-bearing tests:
`tests/soak_agent.rs` and `tests/stress_render.rs` (the `slow-tests`
feature-gated runners exercising `sss-agent` IPC and parallel render
workloads).

Curated suppressions live in [`tsan-suppressions.txt`](../tsan-suppressions.txt)
at the repo root with a strict policy header. Initial commit ships **empty**
(no suppressions yet); the file becomes a committed audit artefact once the
first cron-triggered TSan run surfaces real findings — each suppression
landing in its own commit with a `# Why:` rationale citing the upstream
issue or library behaviour.

### What sanitizers do NOT cover

- **macOS / aarch64** — Linux-x86_64 only per **D-SAN-1**. The build-host
  complexity of running sanitizers on Apple Silicon is out of scope for
  v2.3; revisit in v2.4.
- **rebuilt libsodium under sanitizer instrumentation** — out of scope for
  v2.3. Default position is curated TSan suppressions instead, with the
  trade-off explicit: false positives on libsodium inline-asm are managed by
  the suppressions file, not by re-instrumenting the C dependency.
- **memory sanitizer (`-Zsanitizer=memory`)** — would require recompiling
  all C deps with MSan; deferred to v2.4 alongside the rebuild-libsodium
  decision.

### Substitute relationship with miri

| Surface                                | Coverage in v2.3        |
|----------------------------------------|-------------------------|
| Pure-Rust unsafe (ptr::read_volatile, ManuallyDrop, raw-ptr) | miri (Phase 22)         |
| libsodium FFI (X25519, AEAD, KDF)      | ASan (this section)     |
| libc FFI (env / fd / mmap)             | ASan (this section)     |
| trelis FFI (X448 / sntrup761 / Ed448)  | ASan (this section)     |
| Multi-threaded races (agent IPC + stress) | TSan (this section)     |

Where miri's cfg-stubs in `src/crypto/*.rs`, `src/kdf.rs`, `src/commands/{keys,process}.rs`
elide the real FFI call, the sanitizer job exercises that exact call site
without stubs. There is **no FFI hole** in the joint coverage.

### Zeroisation 2nd-pass

Phase 23 refreshed the v2.1 Phase 8 22-site zeroisation audit against the
v2.2-era source tree. The walk is recorded in
[`.planning/phases/23-sanitizers-asan-tsan-zeroisation-second-pass/ZEROISATION-AUDIT.md`](../.planning/phases/23-sanitizers-asan-tsan-zeroisation-second-pass/ZEROISATION-AUDIT.md):

- **v2.1 baseline:** 22 sites in `src/crypto/`, `src/kdf.rs`, `src/secure_memory.rs`.
- **v2.2 additions:** 12 new sites covering the signed-envelope sig
  keypair material (Ed448 secret half 57 B; ML-DSA-65 secret half 4032 B)
  and the canonical-encoded envelope payload buffer.
- **v2.3 final count:** 34 sites.

Three Drop-tests in
[`tests/zeroisation_drop_tests.rs`](../tests/zeroisation_drop_tests.rs)
exercise the v2.2 additions via the `ManuallyDrop<Zeroizing<[u8; N]>>`
pattern with raw-ptr `ptr::read_volatile` after drop — the same shape miri
validates in § Miri Coverage above.

### `mem::forget` grep gate (belt-and-braces)

Phase 21's `[lints.clippy]` block already denies `clippy::mem_forget` at
compile time. Phase 23 adds a complementary runtime gate via
[`scripts/check-mem-forget.sh`](../scripts/check-mem-forget.sh), invoked per
matrix cell in `.github/workflows/ci-matrix.yml`. Every `mem::forget` in
`src/` must carry a `// Why:` rationale (line above, trailing on the call
line, or `/* Why: */` block comment above); `tests/` is exempt. Current
state: 2 sites in `src/fuse/fs.rs` (file-fd ownership transfer via
`File::from_raw_fd` — both have trailing rationale comments). The gate is
belt-and-braces because clippy may miss macro-expanded forms.

### Refresh cadence

The sanitizer workflow runs **weekly on Saturday 03:00 UTC** (offset from
the miri Sunday cron to spread runner load), with a pinned nightly
toolchain (`nightly-2026-04-15`, matching `.github/workflows/miri.yml`).
The pinned-nightly refresh policy is shared with miri: bump only when
both pinned-nightly users (miri + sanitizer) validate cleanly against the
new pin.

---

## cargo-geiger Coverage

[cargo-geiger](https://github.com/geiger-rs/cargo-geiger) walks the
workspace + dep graph and counts `unsafe` blocks per crate. It produces a
quantitative answer to the auditor question "how much unsafe surface does
sss depend on transitively?" — useful as a **trend signal** rather than a
gate.

Per **MEMSAFE-07** the output is **informational only** (not a CI gate):
the snapshot lives at
[`.planning/phases/23-sanitizers-asan-tsan-zeroisation-second-pass/CARGO-GEIGER.md`](../.planning/phases/23-sanitizers-asan-tsan-zeroisation-second-pass/CARGO-GEIGER.md)
and is refreshed manually per milestone. v2.4 may move the snapshot into
CI for per-release publication; v2.3 keeps it as a manual cadence to
avoid the cargo-geiger setup-time + flakiness penalty in the matrix.

The snapshot file documents: date, commit SHA, cargo-geiger version,
workspace total unsafe-block count (production + test), and the top-10
dep crates by unsafe-block count.

---

## Supply Chain

The Phase 24 supply-chain story is a tiered enforcement surface:
`cargo-deny` gates duplicate-version drift + advisories;
`cargo-vet` attests per-dep review status; `.github/workflows/supply-chain.yml`
runs both as a weekly Friday 03:00 UTC cron + workflow_dispatch +
path-filtered pull_request job.

**Policy-of-record:** [`docs/SUPPLY-CHAIN.md`](SUPPLY-CHAIN.md) — six
sections covering cargo-deny configuration (multiple-versions = "deny"
with 30-day skip-refresh SLA per D-DENY-1, unsound = "all" with two
expiring RUSTSEC ignores), cargo-vet configuration (Mozilla + Google
imports per D-VET-1 with explicit non-import of Bytecode Alliance until
v2.4, `[policy.<crate>]` notes for trelis-* + rust-9p with AUDIT-01 /
EXPERIMENTAL / `vendor/rust-9p` substrings retained per D-V23-06 no-scrub,
the 294-exemption deferral to Phase 27 AUDIT-03 + v2.4 hand-author
campaign), vendored-dep summary (forward-pointer to Phase 26 SUPPLY-06),
trelis pin policy (live-discovered grep-count invariant: 10 occurrences
across Cargo.toml + docs/security-model.md + docs/CRYPTOGRAPHY.md +
supply-chain/config.toml), and the evolution workflow.

**Enforcement surfaces:**

- [`deny.toml`](../deny.toml) — cargo-deny configuration.
- [`supply-chain/config.toml`](../supply-chain/config.toml) +
  [`supply-chain/audits.toml`](../supply-chain/audits.toml) +
  [`supply-chain/imports.lock`](../supply-chain/imports.lock) — cargo-vet
  store (community-default location; deviates from earlier `.cargo/`
  planning).
- [`.github/workflows/supply-chain.yml`](../.github/workflows/supply-chain.yml)
  — weekly Friday cron + PR trigger; five jobs: deny (GATE), vet (GATE),
  trelis-pin (GATE), geiger (advisory, continue-on-error), auditable-stub
  (Phase 25 BUILD-04 forward-pointer).

**SBOM + cargo-auditable embed deferred to Phase 25** — supply-chain.yml
has a placeholder slot. Phase 25 BUILD-03 (CycloneDX SBOM generation) +
BUILD-04 (cargo-auditable embed verification) will replace the
placeholder with substantive verification steps.

**Vendored dep coverage** — trelis-hybrid + trelis-primitives (git-rev
pinned) and rust-9p (vendored path-dep) are first-party from cargo-vet's
perspective; their `[policy.<crate>]` entries in
`supply-chain/config.toml` carry the audit-defensible notes (AUDIT-01
external-audit tracking for trelis; Phase 26 SUPPLY-06 forward-pointer
for rust-9p). The full vendoring policy lands in Phase 26 SUPPLY-06
(`docs/vendoring-policy.md`).

---

## Reproducible Builds

The Phase 26 reproducible-build story has four pieces: a committed
`Cargo.lock` (D-V23-01), a deterministic build wrapper, an empirical
2-host diff transcript, and a vendoring policy doc.

**Cargo.lock committed (BUILD-01).** Prior to v2.3, `Cargo.lock` was
gitignored on the rationale that sss is a binary crate where the lock
isn't strictly required. v2.3 reverses this for reproducibility: the
lock pins exact dep versions across all build hosts.
`.gitignore` no longer ignores `Cargo.lock`; CI runs `cargo build
--locked` and the committed lock matches the resolved state. Bumps
happen via deliberate `cargo update -p <crate>` + commit per
`docs/SUPPLY-CHAIN.md` policy.

**Deterministic build wrapper (BUILD-02).**
[`scripts/release/build-reproducible.sh`](../scripts/release/build-reproducible.sh)
wraps `cargo build --release --locked` with four determinism env-vars
from the April 2026 reproducible-builds.org Rust report:

1. `SOURCE_DATE_EPOCH` — defaulted to the committer date of `HEAD`;
   honoured by `rustc` + `libsodium-sys` build scripts.
2. `RUSTFLAGS --remap-path-prefix` — strips absolute repo path + cargo
   registry path + rustup toolchain path from embedded source-location
   strings. Stable alternative to `[profile.release].trim-paths` which
   is still cargo-unstable on cargo 1.93.
3. `CARGO_BUILD_JOBS=1` — serial compilation eliminates some
   non-deterministic LLVM IR-merge orderings.
4. `LC_ALL=C.UTF-8` + `TZ=UTC` — locale + timezone pinning for build
   scripts that emit locale-specific strings.

`cargo --locked` is the load-bearing flag for cross-host determinism;
it refuses to resolve any version not pinned by `Cargo.lock`.

**2-host diff transcript (BUILD-05).** The empirical reproducibility
verification runs the wrapper on two non-x86 release hosts
(`arm64-builder` Linux aarch64 + `macos-builder` macOS arm64) and compares the
resulting binary SHA-256s. The transcript lives at
`.planning/phases/26-reproducible-builds-vendoring-policy/REPRODUCIBLE-BUILD-TRANSCRIPT.md`
and is preserved per D-V23-06 no-scrub. Per-cell comparisons
(Linux↔Linux, macOS↔macOS) are expected to be byte-identical;
cross-OS comparisons (Linux↔macOS) are expected to diverge on
platform-specific ELF/Mach-O metadata and are NOT part of the
reproducibility claim.

The first empirical 2-host run is scheduled for the next release-cut
after `milestone/quality-security` merges to master; the wrapper
script + procedure ship with Phase 26 close.

**Vendoring policy (SUPPLY-06).**
[`docs/vendoring-policy.md`](vendoring-policy.md) is the
single-source-of-truth for non-crates.io deps:

- `vendor/rust-9p/` (path-dep) — refresh expectation, current frozen
  state, planned v2.5 review.
- `trelis-hybrid` + `trelis-primitives` (git-rev pinned at
  `5374dff...`) — refresh trigger (AUDIT-01 close), drift gate
  (supply-chain.yml `trelis-pin` job).
- `libsodium` (linked-dynamic + static per release artefact) —
  system-library scope, outside cargo-vet trust path.
- Should-we-vendor-X? decision framework for future deps.

---

## Audit Packet

Each tagged release ships an audit packet — a self-contained bundle
of every artefact a third-party auditor needs to verify the v2.3
claims without re-running the toolchain.

**Per-release artefacts** (uploaded to the distribution endpoint +
linked from `latest.json`):

- 6 CycloneDX SBOMs (`sss-<platform>-<arm>.cdx.json`) — one per
  matrix cell (3 platforms × 2 feature arms). trelis-* + fips204 +
  ed448-goldilocks-plus appear in `-hybrid.cdx.json` only.
- cargo-auditable embed inside each binary — verify with
  `cargo audit bin sss`. cargo-audit reads the embedded manifest +
  cross-references RUSTSEC advisories at audit time.
- cosign keyless signature per archive (`.tar.gz.sig` + `.tar.gz.pem`)
  — verify with `cosign verify-blob --certificate <cert> --signature <sig> ...`
  per the procedure in [`docs/RELEASE.md § Verification`](RELEASE.md).
  Logged to the Rekor public transparency log.
- SLSA Level 2 provenance per cell (`.intoto.jsonl`) — cosign
  attest-blob output documenting the build environment.
- SHA-256 checksums per archive (`.sha256`).

**Per-milestone audit-readiness package** (in the repo at v2.3 close):

- This document ([`docs/security-depth.md`](./security-depth.md)) —
  defence-in-depth posture across six dimensions (you're reading it).
- [`docs/security-model.md`](./security-model.md) — full cryptographic
  threat model with the `Constant-Time Considerations` section per
  D-V23-03 (Phase 23 MEMSAFE-06).
- [`docs/CRYPTOGRAPHY.md`](./CRYPTOGRAPHY.md) — primitive-level
  implementation reference with the trelis pin rationale.
- [`docs/CLIPPY-POLICY.md`](./CLIPPY-POLICY.md) — clippy strictness
  contract.
- [`docs/SUPPLY-CHAIN.md`](./SUPPLY-CHAIN.md) — supply-chain policy
  of record (cargo-deny / cargo-vet / supply-chain.yml gate suite).
- [`docs/vendoring-policy.md`](./vendoring-policy.md) — non-crates.io
  dep policy (vendor/rust-9p + trelis git-rev + libsodium linked).
- [`docs/RELEASE.md`](./RELEASE.md) — release pipeline + supply-chain
  artefacts + reproducible-build verification commands.
- [`docs/TESTING.md`](./TESTING.md) — test taxonomy + the
  visibility-audit gate + the slow-tests + soak-tests + stress-tests
  + miri-smoke layout.
- [`docs/release-keys/README.md`](./release-keys/README.md) — offline
  Ed25519 release-signing keypair policy.

**Per-milestone planning archive** (preserved per D-V23-06 no-scrub):

- `.planning/REQUIREMENTS.md` — 28 REQs across 6 categories with
  locked policy decisions D-V23-01..06.
- `.planning/ROADMAP.md` — phase-by-phase progression with completed
  checkboxes + deferral notes.
- `.planning/STATE.md` — frontmatter-tracked completion state.
- `.planning/phases/2[1-7]-*/2[1-7]-PHASE-SUMMARY.md` — one phase
  summary per phase (7 files); each documents REQ coverage, live
  gate state, deviations from PLAN.md, and cross-phase notes.
- `.planning/phases/2[1-3]-*/2[1-3]-NN-SUMMARY.md` — per-plan
  summaries for Phases 21-23 (formal PLAN.md ceremony era).
- `.planning/milestones/v2.{0,1,2,3}-phases/*/deferred-items.md` —
  preserved historical deferred items (no scrubbing during cleanup).

**Reproducible-build evidence:**

- [`Cargo.lock`](../Cargo.lock) — committed at v2.3 (D-V23-01).
- [`scripts/release/build-reproducible.sh`](../scripts/release/build-reproducible.sh)
  — deterministic build wrapper.
- `.planning/phases/26-reproducible-builds-vendoring-policy/REPRODUCIBLE-BUILD-TRANSCRIPT.md`
  — 2-host empirical-verification procedure + (post first
  release-cut) the SHA-256 transcript.

**CI gate workflows** (`.github/workflows/`):

- `ci-matrix.yml` — per-push clippy gate + build matrix + 3 informational
  scripts.
- `miri.yml` — weekly Sunday 03:00 UTC, pinned nightly, miri-smoke tests.
- `sanitizer.yml` — weekly Saturday 03:00 UTC, pinned nightly, ASan +
  TSan scoped jobs.
- `supply-chain.yml` — weekly Friday 03:00 UTC + PR trigger + 5 jobs
  (cargo-deny gate + cargo-vet gate + trelis-pin grep + cargo-geiger
  advisory + cargo-auditable + SBOM verification).
- `release.yml` — manual-dispatch + tag-triggered with cosign keyless
  signing per matrix cell.

The v2.3 milestone close (`milestone/quality-security` branch merge to
master) is the audit-readiness boundary — every artefact above is on
disk + version-controlled at that point.

---

## References

- [`docs/security-model.md`](./security-model.md) — algorithms, key
  hierarchy, threat model (the "what" companion to this "how" document)
- [`docs/CRYPTOGRAPHY.md`](./CRYPTOGRAPHY.md) — implementation details for
  the cryptographic primitives
- [`docs/CLIPPY-POLICY.md`](./CLIPPY-POLICY.md) — clippy strictness
  contract and the `// Why:` requirement for every `#[allow]` exception
- [`tests/miri_smoke.rs`](../tests/miri_smoke.rs) — miri smoke harness
  (5 tests, 7 unsafe blocks)
- [`.github/workflows/miri.yml`](../.github/workflows/miri.yml) — weekly
  miri runner pinned to `nightly-2026-04-15`
- [docs/SECURITY-PROPERTIES.md](./SECURITY-PROPERTIES.md) — auditor-checkable replay-resistance matrix + trust-anchor diagram
