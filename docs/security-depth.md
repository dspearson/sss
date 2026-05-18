# Security Depth

Auditor entry-point document covering the **defence-in-depth** layers sss
applies beyond the cryptographic specification in
[`docs/security-model.md`](./security-model.md). Where `security-model.md`
answers *what* sss encrypts and with which primitives, this document answers
*how* the codebase is kept honest against memory-safety bugs, supply-chain
drift, build reproducibility, and audit traceability.

This document is finalised in **Phase 27 AUDIT-03** as the single landing
page an external auditor reads first. v2.3 Phases 22–27 each fill in one
subsection. Sections marked *(placeholder — Phase N)* below are stubs to be
expanded in the named phase.

---

## Introduction

*(placeholder — Phase 27 AUDIT-03)*

The auditor-facing narrative tying together static analysis, dynamic analysis,
sanitizer coverage, supply-chain hygiene, reproducible builds, and the
release-artefact audit packet. Will reference each subsection below as a
chapter heading in the final audit hand-off.

---

## Static Analysis Posture

*(placeholder — extends Phase 21 STATIC-* coverage)*

Phase 21 landed the workspace clippy strictness floor (pedantic group + a
short cherry-pick of restriction lints; see
[`docs/CLIPPY-POLICY.md`](./CLIPPY-POLICY.md) for the policy of record). Phase
27 will summarise the static-analysis posture across the matrix and link the
clippy gate, the panic-surface deny, and the SAFETY-comment regression
scripts (`scripts/check-safety-comments.sh`, `scripts/check-allow-why.sh`).

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
([`CONTEXT.md`](.planning/phases/22-miri-on-safe-wrappers/22-CONTEXT.md)).
The `-Zmiri-native-lib` alternative was rejected for v2.3 — too new in
2026-05 to bet on; revisit in v2.4.

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

*(placeholder — Phase 23 MEMSAFE-03/04)*

Phase 23 will land an AddressSanitizer (and optionally ThreadSanitizer)
GitHub Actions workflow mirroring the shape of `.github/workflows/miri.yml`.
The sanitizer runner exercises the FFI boundary (libsodium + libc + trelis)
under realistic workloads — the surface miri cannot interpret. This
subsection will document the same shape as § Miri Coverage above: what
ASan runs against, what it does not, the refresh cadence, and the cross-
reference back to miri for the pure-Rust paths.

---

## Supply Chain

*(placeholder — Phase 24 SUPPLY-01/02/03)*

Phase 24 will land `cargo-deny` tightening, `cargo-vet` adoption, and the
SBOM (CycloneDX) generation pipeline. This subsection will document the
audit trail from `Cargo.lock` → `cargo vet certify` → SBOM → release
artefact, with explicit handling of the vendored `trelis` git pin and the
`vendor/rust-9p` tree.

---

## Reproducible Builds

*(placeholder — Phase 26 REPRO-01/02)*

Phase 26 will land reproducible-build guarantees for the release artefacts
(rpm, deb, apk, macOS pkg). This subsection will document the build
environment pinning, the `SOURCE_DATE_EPOCH` discipline, and the
byte-comparison process for verifying that two independent builders
produce byte-identical artefacts.

---

## Audit Packet

*(placeholder — Phase 27 AUDIT-03)*

Phase 27 will assemble the audit packet that ships alongside each tagged
release: SBOM, signed release artefacts, threat model, security model,
this document (`security-depth.md`), the SAFETY/Why-comment regression
reports, and the cargo-vet imports. This subsection will be the index
page an external auditor reads first when commissioned to review sss.

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
