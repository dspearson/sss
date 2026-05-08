# SSS Test Coverage

Single source of truth for measuring `cargo tarpaulin` coverage on this repo. The top section is the copy-paste invocation; the per-target tables below record the per-public-method baseline for the hybrid suite (TEST-07) and the per-file workspace baseline.

## Quick Reference

Coverage is measured natively on `arm64-builder` (Linux aarch64, the canonical release-target build host per `docs/RELEASE.md`). One invocation, two outputs: an HTML report for browse and a per-file percentage table snapshot below.

```bash
# 1. Sync source (.git included; one tarpaulin test asserts the working dir is a git repo).
rsync -aqz --delete \
    --exclude='.cargo' --exclude='target' --exclude='.planning' \
    --exclude='*.log' --exclude='release-*' --exclude='vendor/rust-9p/target' \
    /path/to/sss/ arm64-builder:/home/dsp/sss-build/

# 2. Run tarpaulin (Instrumented engine; ptrace is unsupported on aarch64 Linux).
ssh arm64-builder 'cd /home/dsp/sss-build && cargo tarpaulin --features hybrid \
    --out Html --out Json \
    --output-dir target/tarpaulin \
    --timeout 900 \
    --exclude-files "vendor/*" --exclude-files "benches/*"'
```

Tooling pin: `cargo-tarpaulin` 0.35.4 (the `llvm-profparser` profile-merge bug present in 0.30.0 is fixed upstream as of 0.34.x).

Output:
- HTML report: `target/tarpaulin/tarpaulin-report.html`
- JSON report: `target/tarpaulin/tarpaulin-report.json`
- Stdout per-file table: see "Per-file Baseline" below.

## Hybrid Suite Baseline (HybridCryptoSuite + HybridKeyPair + HybridPublicKey)

Source file: `src/crypto/hybrid.rs` (97.25% line coverage, 106/109). Direct unit tests live in `tests/hybrid_coverage.rs`; round-trip property tests live in `tests/cross_suite_property_test.rs`.

| Method | Line | Covered by | Status |
|--------|------|------------|--------|
| `HybridPublicKey::from_bytes` | 49 | `hybrid_public_key_from_bytes_*` (correct length, too short, too long, empty) | covered |
| `HybridPublicKey::from_bytes_unchecked` | 71 | `hybrid_public_key_from_bytes_unchecked_preserves_bytes` | covered |
| `HybridPublicKey::as_bytes` | 79 | `hybrid_public_key_as_bytes_roundtrip_with_from_bytes` | covered |
| `HybridKeyPair::generate` | 96 | `hybrid_key_pair_generate_does_not_panic` | covered |
| `HybridKeyPair::public_key` | 116 | `hybrid_key_pair_public_key_extracts_consistently` | covered |
| `HybridCryptoSuite::seal_repo_key` | 134 | `hybrid_crypto_suite_seal_open_roundtrip_recovers_repo_key` + `hybrid_crypto_suite_seal_rejects_classic_public_key_returns_err` | covered |
| `HybridCryptoSuite::open_repo_key` | 215 | round-trip + `*_rejects_classic_keypair_returns_err` + `*_rejects_wrong_length_sealed_key_returns_err` + `*_detects_aead_tamper_returns_err` | covered |

## Per-file Baseline

Captured on `arm64-builder` (Linux aarch64) at 2026-05-08 with `cargo tarpaulin --workspace --features hybrid --all-targets --skip-clean`. Refresh by re-running the Quick Reference invocation; commit the new numbers in a follow-up.

**Workspace overall: 75.48% (5333/7065 lines covered)**

Top files (by descending percentage):

| File | Lines covered | Total lines | Percentage |
|------|---------------|-------------|------------|
| `src/crypto/suite.rs`              | 7    | 7    | 100.00% |
| `src/commands/status.rs`           | 6    | 6    | 100.00% |
| `src/validation.rs`                | 63   | 63   | 100.00% |
| `src/marker_inference/validator.rs`| 61   | 61   | 100.00% |
| `src/marker_inference/parser.rs`   | 52   | 52   | 100.00% |
| `src/marker_inference/diff.rs`     | 40   | 40   | 100.00% |
| `src/marker_inference/mapper.rs`   | 31   | 31   | 100.00% |
| `src/marker_inference/mod.rs`      | 14   | 14   | 100.00% |
| `src/toml_helpers.rs`              | 5    | 5    | 100.00% |
| `src/marker_inference/delimiter.rs`| 82   | 83   | 98.80%  |
| `src/crypto/hybrid.rs`             | 106  | 109  | 97.25%  |
| `src/marker_inference/propagator.rs`| 27  | 28   | 96.43%  |
| `src/kdf.rs`                       | 66   | 69   | 95.65%  |
| `src/processor/marker_parser.rs`   | 44   | 46   | 95.65%  |
| `src/marker_inference/marker_syntax.rs`| 80| 84   | 95.24%  |
| `src/marker_inference/expander.rs` | 295  | 311  | 94.86%  |
| `src/secrets.rs`                   | 152  | 168  | 90.48%  |
| `src/project.rs`                   | 180  | 199  | 90.45%  |
| `src/processor/core.rs`            | 367  | 406  | 90.39%  |
| `src/crypto/classic.rs`            | 252  | 280  | 90.00%  |
| `src/merge.rs`                     | 130  | 145  | 89.66%  |
| `src/scanner.rs`                   | 129  | 144  | 89.58%  |
| `src/main.rs`                      | 446  | 507  | 87.97%  |
| `src/commands/migrate.rs`          | 87   | 104  | 83.65%  |
| `src/keystore.rs`                  | 375  | 456  | 82.24%  |
| `src/commands/hooks.rs`            | 173  | 234  | 73.93%  |
| `src/commands/keys.rs`             | 369  | 504  | 73.21%  |
| `src/commands/users.rs`            | 114  | 160  | 71.25%  |
| `src/commands/process.rs`          | 238  | 360  | 66.11%  |

Files below 50% (intentional gaps — UI, daemon, FUSE/9p):

| File | Lines covered | Total lines | Percentage | Why low |
|------|---------------|-------------|------------|---------|
| `src/filesystem_common.rs` | 14  | 42  | 33.33% | FUSE/9p shared paths; cross-platform stubs |
| `src/agent/client.rs`      | 14  | 54  | 25.93% | sss-agent IPC; covered by panic-surface + manual e2e |
| `src/askpass.rs`           | 12  | 79  | 15.19% | TTY/GUI prompts; manually exercised |
| `src/bin/sss-askpass-gui.rs`| 6  | 47  | 12.77% | GTK GUI binary; not unit-tested |
| `src/bin/sss-askpass-tty.rs`| 8  | 78  | 10.26% | TTY prompt binary; manually tested |
| `src/commands/agent.rs`    | 6   | 133 | 4.51%  | Agent CLI dispatcher; covered by manual e2e |
| `src/bin/sss-agent.rs`     | 0   | 152 | 0.00%  | Daemon binary; integration-tested manually |
| `src/fuse/fs.rs`           | 0   | 26  | 0.00%  | FUSE filesystem ops; feature-gated, manual mount tests |
| `src/ninep_fs.rs`          | 0   | 2   | 0.00%  | 9p filesystem entry; feature-gated |
| `src/constants.rs`         | 0   | 2   | 0.00%  | Constants only; no executable lines |

## See Also

- `docs/RELEASE.md` — canonical Linux aarch64 host pin (`arm64-builder`); cross-platform release matrix.
- `tests/hybrid_coverage.rs` — direct unit tests for every public hybrid method (TEST-07).
- `tests/cross_suite_property_test.rs` — cross-suite property tests; AEAD byte-identity invariant (TEST-01).
- `tests/keystore_integration_tests.rs` — keystore round-trip tests (TEST-08 extension target).
- `.planning/REQUIREMENTS.md` — TEST-07 acceptance criterion.

## Out of Scope

Explicitly excluded from this baseline document:

| Item | Reason |
|------|--------|
| CI matrix integration | Deferred to a later milestone; v2.1 is internal hardening only. |
| Per-test timing breakdown | Not in v2.1 scope; tarpaulin time-and-coverage decoupling is a future tooling task. |
| macOS arm64 / Linux x86_64 / Alpine musl tarpaulin | Linux aarch64 (`arm64-builder`) is the canonical baseline per Phase 13 D-01; cross-platform tarpaulin is future work. |
| `cargo llvm-cov` baseline | D-02 (CONTEXT.md): tarpaulin matches the acceptance-criterion verbatim; llvm-cov adds tooling without a milestone-level win. |
| Branch / region coverage | Line coverage only; branch coverage requires `--branch` and is unstable on aarch64 in 0.35.4. |
