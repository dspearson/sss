# Roadmap: sss v2.0 Post-Quantum Crypto Upgrade Path

## Overview

Ship an opt-in hybrid post-quantum crypto suite (trelis: X448 + sntrup761 → BLAKE3 → 32-byte shared secret) alongside the existing libsodium classic suite. The repo key `K` and deterministic nonce derivation stay unchanged across suites — only the per-user wraps in `.sss.toml` differ — so in-file ciphertexts are byte-identical regardless of which suite sealed `K`. Selection is a single knob: the existing `.sss.toml` `version` field (`"1.0"` = classic, `"2.0"` = hybrid). The per-user keystore grows to hold both classic and hybrid keypairs side-by-side. `sss migrate` flips a repo forward without re-encrypting any file content. trelis is treated as experimental throughout — vendored at a pinned commit, gated on opt-in, and surfaced to users as unaudited in security documentation. Classic remains the recommended default until a trelis audit lands (deferred to v2.1).

## Phases

**Phase Numbering:**
- Integer phases (1, 2, 3): Planned milestone work
- Decimal phases (2.1, 2.2): Urgent insertions (marked with INSERTED)

- [x] **Phase 1: Suite Abstraction** - Introduce the `CryptoSuite` trait, route `.sss.toml` version dispatch through it, keep classic behaviour byte-identical — **Complete 2026-04-24**
- [x] **Phase 2: Hybrid Crypto Suite** - Vendor trelis, implement `HybridCryptoSuite` for repo-key wrap, lock in the byte-identical-ciphertexts invariant — **Complete 2026-04-26**
- [ ] **Phase 3: Keystore Dual-Suite Support** - Extend on-disk keystore to carry classic + hybrid keypairs under one user identity; grow `sss keygen`
- [ ] **Phase 4: Migration Command** - `sss migrate` re-wraps `K` per user to hybrid, bumps version, never touches file content
- [ ] **Phase 5: End-to-End Validation** - Property test and full-repo tests that lock in the cross-suite invariants and v1/v2 interop
- [ ] **Phase 6: Documentation & Release** - Security/crypto docs, README/man pages, benchmarks, CHANGELOG, release-matrix cross-check

## Phase Details

### Phase 1: Suite Abstraction
**Goal**: A `CryptoSuite` trait exists and routes all repo-key wrap/unwrap through it; `.sss.toml` `version` dispatches to the right suite; the classic suite slots in behind the trait with zero behavioural change.
**Depends on**: Nothing (first phase)
**Requirements**: SUITE-01, SUITE-02, SUITE-03, SUITE-04
**Success Criteria** (what must be TRUE):
  1. A v1-format `.sss.toml` opens with the v2 binary and every existing crypto-related test passes unchanged (no regression — classic suite is routed through the trait).
  2. `sss init --crypto classic` (default) and `sss init --crypto hybrid` both parse; hybrid is gated off until Phase 2 wires the real implementation but the dispatch path exists.
  3. Opening a `.sss.toml` with `version = "2.0"` using a v1 binary emits a single-line actionable error (e.g. "this project requires sss v2.0 or newer") — not a TOML parse error, not a panic, not silent corruption.
  4. All repo-key seal/open call sites in `src/` go through the `CryptoSuite` trait — no direct `seal_repository_key` calls leak outside `crypto/classic.rs`.
**Plans**: 4 plans
  - [x] 01-01-PLAN.md — Wave 1: introduce `CryptoSuite` trait, `Suite` dispatch enum, and `ClassicSuite` impl under `src/crypto/` (SUITE-01 scaffolding) — **Complete 2026-04-23**
  - [x] 01-02-PLAN.md — Wave 1: wire `.sss.toml` `version` dispatch and the v1-binary-opening-v2 single-line actionable error (SUITE-02, SUITE-04) — **Complete 2026-04-23**
  - [x] 01-03-PLAN.md — Wave 1: add `sss init --crypto <classic|hybrid>` flag (classic default) and thread it into the generated `.sss.toml` `version` field (SUITE-03) — **Complete 2026-04-23**
  - [x] 01-04-PLAN.md — Wave 2: migrate every in-src seal/open call site to `ClassicSuite` trait dispatch; mark free functions `#[deprecated]` (SUITE-01 completion) — **Complete 2026-04-24**

### Phase 2: Hybrid Crypto Suite
**Goal**: trelis is vendored at a reviewed pinned commit; `HybridCryptoSuite` implements the same `CryptoSuite` trait as classic; given the same `K`, in-file AEAD ciphertexts are byte-identical to classic (invariant locked in by test).
**Depends on**: Phase 1
**Requirements**: PQCRYPTO-01, PQCRYPTO-02, PQCRYPTO-03, PQCRYPTO-04
**Success Criteria** (what must be TRUE):
  1. `trelis-hybrid` and `trelis-primitives` are in `Cargo.toml` as git deps pinned to specific commits, gated behind a `hybrid` feature flag; the default build still links only libsodium.
  2. A `HybridCryptoSuite` round-trips a repo key: wrap with a hybrid pubkey → unwrap with the matching hybrid secret key → same 32 bytes out.
  3. For a fixed `K`, path, timestamp and plaintext, `encrypt(...)` produces byte-identical output whether `K` was wrapped classically or hybridly — the AEAD layer never observes which wrap was used.
  4. Hybrid keypairs and intermediate shared secrets implement `ZeroizeOnDrop`; no plaintext `K` material lingers in hybrid-specific types after drop (verified by a zeroise test on a known-poison buffer pattern).
**Plans**: 4 plans
  - [x] 02-01-PLAN.md — Wave 1: vendor `trelis-hybrid`, `trelis-primitives`, `blake3` in `Cargo.toml` as git deps pinned by SHA, add `hybrid` feature flag, default build stays libsodium-only (PQCRYPTO-01)
  - [x] 02-02-PLAN.md — Wave 1: widen `PublicKey`/`KeyPair` to suite-aware enums, introduce `ClassicKeyPair`, stub `HybridPublicKey`/`HybridKeyPair` in `src/crypto/hybrid.rs`, wire variant-mismatch errors in `ClassicSuite`, add `PublicKey::decode_base64_for_suite` (PQCRYPTO-02 scaffolding)
  - [x] 02-03-PLAN.md — Wave 2: implement `HybridCryptoSuite` (trelis encapsulate → blake3 KDF → libsodium XChaCha20-Poly1305 AEAD) and `suite_for(Suite) -> Box<dyn CryptoSuite>` dispatcher; upgrade hybrid keypair/public-key to sized byte arrays with `ZeroizeOnDrop` (PQCRYPTO-02 completion, PQCRYPTO-04 surface)
  - [x] 02-04-PLAN.md — Wave 3: byte-identical-ciphertext test (fixed `K` + fixed path/timestamp/plaintext across both suites) and poison-pattern zeroise tests for `HybridKeyPair` secret material and `blake3`-derived AEAD key (PQCRYPTO-03, PQCRYPTO-04 completion)

### Phase 3: Keystore Dual-Suite Support
**Goal**: The per-user keystore on disk holds classic (X25519) and hybrid (X448 + sntrup761) keypairs side-by-side under one user identity; `sss keygen` can generate either or both; upgrading an existing keystore never destroys the user's classic keypair.
**Depends on**: Phase 2
**Requirements**: KEYSTORE-01, KEYSTORE-02, KEYSTORE-03, KEYSTORE-04
**Success Criteria** (what must be TRUE):
  1. An existing v1 keystore file loads under the v2 binary with the classic keypair intact and no hybrid section; `sss keys show` prints the same classic public key byte-for-byte as before.
  2. `sss keygen --suite hybrid` on an existing keystore adds a hybrid keypair without touching the classic one; re-loading yields both.
  3. `sss keygen --suite both` on a fresh keystore produces both keypairs atomically; passphrase-wrap uses the same Argon2id (libsodium `crypto_pwhash`) path for every private key in the file — classic and hybrid share one KDF.
  4. A user who only holds a classic keypair gets a clear error when the repo is `version = "2.0"` and they have no hybrid public key on file — not silent failure, not auto-generation.
**Plans**: 2 plans
  - [ ] 03-01-PLAN.md — Wave 1: extend StoredKeyPair with optional hybrid fields + Keystore::store_dual_keypair / load_hybrid_keypair / get_current_stored_raw (KEYSTORE-01, KEYSTORE-03, KEYSTORE-04)
  - [ ] 03-02-PLAN.md — Wave 2: sss keys generate --suite CLI flag + handle_keys_generate_command dispatch + sss keys show subcommand (KEYSTORE-02, KEYSTORE-03)

### Phase 4: Migration Command
**Goal**: `sss migrate` re-wraps the existing repo key `K` for every user under the hybrid suite, bumps `.sss.toml` from `"1.0"` to `"2.0"`, and never rewrites any file content on disk.
**Depends on**: Phase 3
**Requirements**: MIGRATE-01, MIGRATE-02, MIGRATE-03, MIGRATE-04
**Success Criteria** (what must be TRUE):
  1. Running `sss migrate` on a multi-user v1 repo produces a v2 repo where every user's `sealed_key` entry is a hybrid wrap of the same `K`; the `version` field in `.sss.toml` is `"2.0"`.
  2. After migration, SHA-256 of every sealed file in the repo is byte-identical to its pre-migration hash — migration touches only `.sss.toml`.
  3. If any user listed in `.sss.toml` does not yet have a recorded hybrid public key, `sss migrate` exits non-zero with a message listing the affected users and pointing to `sss keygen --suite hybrid` as the remediation; no partial write happens.
  4. `sss migrate --dry-run` prints the full plan (which users get re-wrapped, the version bump) and exits without touching disk; running it produces no modifications detectable by `git status`.
**Plans**: TBD

### Phase 5: End-to-End Validation
**Goal**: The invariants this milestone depends on are locked in by property and end-to-end tests — random-input property check on the shared-AEAD invariant, cross-version read tests, and a full multi-user migration test.
**Depends on**: Phase 4
**Requirements**: TEST-01, TEST-02, TEST-03, TEST-04
**Success Criteria** (what must be TRUE):
  1. A property test runs ≥1000 randomised cases: for random `K`, path, timestamp and plaintext, classic-wrap and hybrid-wrap of `K` both produce byte-identical in-file AEAD ciphertexts; failure prints the minimised counter-example.
  2. End-to-end test: v2 binary opens a v1-format `.sss.toml` repo, renders all sealed files, and round-trips seal/render — no migration required.
  3. End-to-end test: v1 binary pointed at a v2-format `.sss.toml` repo exits with the documented error message (asserted literally), non-zero, no panic, no corrupting writes.
  4. End-to-end test: `sss migrate` on a representative multi-user repo (≥3 users) produces a v2 repo where each user can independently render the content with byte-identical plaintext to the pre-migration state.
**Plans**: TBD

### Phase 6: Documentation & Release
**Goal**: The security tradeoffs, migration flow and default selection are documented; benchmarks quantify hybrid cost vs classic; the release matrix still builds cleanly.
**Depends on**: Phase 5
**Requirements**: DOCS-01, DOCS-02, DOCS-03, TEST-05
**Success Criteria** (what must be TRUE):
  1. `docs/SECURITY.md` and `docs/CRYPTOGRAPHY.md` describe the hybrid suite wire format, the shared-`K`/shared-nonce invariant, the threat-model delta, and carry an unmissable "trelis is unaudited and experimental" disclaimer; the hybrid suite is documented as opt-in, classic as the recommended default until audit.
  2. README and the `sss` man page explain the classic/hybrid choice, show the `sss init --crypto`, `sss keygen --suite`, and `sss migrate` commands with worked examples; the CHANGELOG carries a v2.0 entry covering the above.
  3. Benchmarks compare hybrid keygen, hybrid wrap, hybrid unwrap vs their classic counterparts and report the per-user `.sss.toml` size delta in bytes; results land in `benches/` or a documented section.
  4. `rpm-build/build-rpm.sh`, macOS and musl build scripts still produce artefacts with the `hybrid` feature enabled on every host in the existing release matrix (Linux x86_64, Linux aarch64 on `keflavik`, macOS arm64 on `mac`, musl static).
**Plans**: TBD

## Progress

**Execution Order:**
Phases execute in numeric order: 1 → 2 → 3 → 4 → 5 → 6

| Phase | Plans Complete | Status | Completed |
|-------|----------------|--------|-----------|
| 1. Suite Abstraction | 4/4 | Complete | 2026-04-24 |
| 2. Hybrid Crypto Suite | 4/4 | Complete | 2026-04-26 |
| 3. Keystore Dual-Suite Support | 0/2 | In progress | - |
| 4. Migration Command | 0/TBD | Not started | - |
| 5. End-to-End Validation | 0/TBD | Not started | - |
| 6. Documentation & Release | 0/TBD | Not started | - |
