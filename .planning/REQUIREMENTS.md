# Requirements: sss v2.0 Post-Quantum Crypto Upgrade Path

**Defined:** 2026-04-23
**Core Value:** Strong authenticated encryption for secrets in git, with deterministic ciphertexts that produce clean diffs.

## v2.0 Milestone Requirements

Requirements for the PQ upgrade path. Each maps to exactly one roadmap phase.

### Suite Abstraction

Refactor the crypto boundary so the classic libsodium suite and the new hybrid suite can coexist behind one trait.

- [ ] **SUITE-01**: Introduce a `CryptoSuite` trait covering per-user wrap/unwrap of the repo key; classic implementation slots in unchanged  _(scaffolding landed in Plan 01-01; completion gated on Plan 01-04 call-site migration)_
- [x] **SUITE-02**: `.sss.toml` `version` field dispatches to the correct `CryptoSuite` (`"1.0"` → classic, `"2.0"` → hybrid); no new fields added  _(Plan 01-02, 2026-04-23)_
- [x] **SUITE-03**: Binary accepts a `--crypto <classic|hybrid>` opt-in flag for `sss init`; default remains `classic` (v1.0) until trelis is further vetted  _(Plan 01-03, 2026-04-23)_
- [x] **SUITE-04**: v1 binary emits a clear, actionable error when opening a v2 `.sss.toml` (not silent corruption or generic parse failure)  _(Plan 01-02, 2026-04-23)_

### PQ Crypto Integration

Wire trelis into sss as the second `CryptoSuite` implementation.

- [ ] **PQCRYPTO-01**: Add `trelis-hybrid` and `trelis-primitives` as workspace dependencies (pinned to a reviewed git commit; trelis is experimental)
- [x] **PQCRYPTO-02**: Implement `HybridCryptoSuite` using trelis `HybridKemKeypair` for key-wrap of the existing repo key `K`
- [ ] **PQCRYPTO-03**: Confirm in tests that, given the same `K`, the in-file AEAD ciphertexts produced by both suites are byte-identical — nonce derivation and `K` are shared across suites
- [ ] **PQCRYPTO-04**: Zeroise-on-drop for all hybrid secret material; no plaintext K material leaks in hybrid wrap/unwrap

### Keystore Extension

Per-user keystore gains side-by-side storage for both suites' keypairs.

- [x] **KEYSTORE-01**: Keystore on-disk format extended to hold both classic (X25519) and hybrid (X448 + sntrup761) keypairs under one user identity  _(Plan 03-01, 2026-04-26)_
- [x] **KEYSTORE-02**: `sss keygen` grows `--suite <classic|hybrid|both>` (default `both` once users have opted into v2; stays `classic` when they haven't)  _(Plan 03-02, 2026-04-26)_
- [x] **KEYSTORE-03**: Upgrading an existing keystore preserves the user's classic keypair verbatim; hybrid is added when requested, not silently generated  _(Plan 03-01, 2026-04-26)_
- [x] **KEYSTORE-04**: Argon2id passphrase wrapping still covers every private key in the keystore — both suites share the same KDF path (libsodium `crypto_pwhash`)  _(Plan 03-01, 2026-04-26)_

### Migration Command

`sss migrate` flips a repo from classic to hybrid without re-encrypting content.

- [ ] **MIGRATE-01**: `sss migrate` re-wraps `K` for every known user under the hybrid suite and rewrites `.sss.toml` user entries
- [ ] **MIGRATE-02**: Migration never re-encrypts file content — the in-file ciphertexts must be byte-identical before and after `sss migrate`
- [ ] **MIGRATE-03**: Migration errors clearly when any user in `.sss.toml` does not yet have a hybrid public key recorded; offers the user list and remediation
- [ ] **MIGRATE-04**: `sss migrate --dry-run` shows the full plan (per-user wrap changes, version bump) without touching disk

### Documentation & Release

Surface the security tradeoffs to users and keep release artefacts consistent.

- [ ] **DOCS-01**: `docs/SECURITY.md` and `docs/CRYPTOGRAPHY.md` updated with the hybrid suite spec, threat-model deltas, and an explicit "trelis is unaudited / experimental" disclaimer
- [ ] **DOCS-02**: README and man pages describe the classic/hybrid choice, migration flow, and default selection
- [ ] **DOCS-03**: CHANGELOG entry for v2.0; release-build scripts cross-check the PQ feature compiles cleanly on the existing release matrix (Linux, macOS, musl)

### Validation

Test suite locks in the invariants this milestone depends on.

- [ ] **TEST-01**: Property test — for a random `K`, path, timestamp and plaintext, classic-wrap and hybrid-wrap of `K` both produce identical in-file AEAD ciphertexts
- [ ] **TEST-02**: End-to-end — v2 binary transparently reads a v1.0 repo without migration
- [ ] **TEST-03**: End-to-end — v1 binary produces the documented error (not a panic, not a data-destroying parse) when pointed at a v2.0 repo
- [ ] **TEST-04**: End-to-end — `sss migrate` on a representative multi-user v1 repo yields a v2 repo that every user can open, with byte-identical file content
- [ ] **TEST-05**: Benchmarks — hybrid keygen, hybrid wrap, hybrid unwrap vs classic; `.sss.toml` size delta reported per user entry

## Future Requirements

Deferred to a later milestone.

### Post-Quantum Signatures

- **PQSIG-01**: Add hybrid signature verification (Ed448 + ML-DSA-65) for keystore entries — currently deferred because sss doesn't sign data at rest today
- **PQSIG-02**: Signed `.sss.toml` envelope with hybrid signatures from the repo owner

### Audit & Default Switch

- **AUDIT-01**: Commission / track a third-party audit of trelis or its dependencies
- **AUDIT-02**: Flip the default for newly-created repos to `version = "2.0"` once trelis is audited

## Out of Scope

Explicitly excluded from v2.0 to keep the milestone focused.

| Feature | Reason |
|---------|--------|
| Post-quantum KDF replacement | Argon2id remains the standard for passphrase KDF; trelis does not offer one and PQ-KDF is not a practical threat |
| Re-encrypting in-file ciphertexts during migration | Breaks the clean-diff property and is wholly unnecessary — `K` is unchanged |
| Dropping libsodium | BLAKE2b-personal deterministic nonces and Argon2id are still libsodium-only in this codebase |
| Crypto agility for AEAD | Both suites use XChaCha20-Poly1305; nothing to switch |
| Adding a 1-byte suite-tag to in-file envelopes | Unneeded — `K` and nonce derivation are shared, so ciphertexts don't care which wrap produced `K` |
| New `crypto_version` field in `.sss.toml` | The existing `version` field (`src/project.rs:30`) already fulfils this purpose |

## Traceability

Filled by `gsd-roadmapper` on 2026-04-23.

| Requirement | Phase | Status |
|-------------|-------|--------|
| SUITE-01 | Phase 1 | Scaffolding complete (Plan 01-01); closure in 01-04 |
| SUITE-02 | Phase 1 | Complete (Plan 01-02, 2026-04-23) |
| SUITE-03 | Phase 1 | Complete (Plan 01-03, 2026-04-23) |
| SUITE-04 | Phase 1 | Complete (Plan 01-02, 2026-04-23) |
| PQCRYPTO-01 | Phase 2 | Pending |
| PQCRYPTO-02 | Phase 2 | Complete |
| PQCRYPTO-03 | Phase 2 | Pending |
| PQCRYPTO-04 | Phase 2 | Pending |
| KEYSTORE-01 | Phase 3 | Complete (Plan 03-01, 2026-04-26) |
| KEYSTORE-02 | Phase 3 | Complete (Plan 03-02, 2026-04-26) |
| KEYSTORE-03 | Phase 3 | Complete (Plan 03-01, 2026-04-26) |
| KEYSTORE-04 | Phase 3 | Complete (Plan 03-01, 2026-04-26) |
| MIGRATE-01 | Phase 4 | Pending |
| MIGRATE-02 | Phase 4 | Pending |
| MIGRATE-03 | Phase 4 | Pending |
| MIGRATE-04 | Phase 4 | Pending |
| TEST-01 | Phase 5 | Pending |
| TEST-02 | Phase 5 | Pending |
| TEST-03 | Phase 5 | Pending |
| TEST-04 | Phase 5 | Pending |
| DOCS-01 | Phase 6 | Pending |
| DOCS-02 | Phase 6 | Pending |
| DOCS-03 | Phase 6 | Pending |
| TEST-05 | Phase 6 | Pending |

**Coverage:**
- v2.0 requirements: 24 total
- Mapped to phases: 24
- Unmapped: 0 ✓

---
*Requirements defined: 2026-04-23*
*Last updated: 2026-04-26 after Plan 03-02 landed — KEYSTORE-02 complete (gsd-executor)*
