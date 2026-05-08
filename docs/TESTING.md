# Testing

This project ships with four distinct test tiers. Each has its own command,
runtime budget, and platform support story. Run all four during a release
gate; default `cargo test` is sufficient for day-to-day work.

## Default

```sh
cargo test --workspace --features hybrid
```

Runs the standard unit + integration test suite under the `hybrid` feature.
This is the suite enforced by every commit. Expected runtime: under 2 minutes
on Linux aarch64 (arm64-builder baseline). Includes:

- All `#[cfg(test)] mod tests` blocks across `src/`.
- All non-slow integration tests under `tests/` (e.g., `tests/migrate_e2e.rs`).

Excludes (gated out): the `slow-tests` suite (soak / stress) and the entire
`fuzz/` workspace.

## Coverage

```sh
cargo tarpaulin --workspace --features hybrid --out Html --exclude-files 'fuzz/**'
```

Produces a per-line coverage report. The canonical coverage workflow,
including the v2.2 retention gates and the out-of-scope file matrix, is
documented in [docs/test-coverage.md](test-coverage.md). Default tarpaulin
runs DO NOT exercise `slow-tests` or `fuzz/` (the gating ensures this is
trivially true). Expected runtime: 5–10 minutes.

## Slow-tests

```sh
cargo test --workspace --features hybrid,slow-tests -- --nocapture
```

Runs the long-lived integration tests gated behind the `slow-tests` Cargo
feature. Two tests live in this tier:

- `tests/soak_agent.rs` — spawns `sss-agent --foreground`, drives 10 000
  seal/unseal cycles, asserts RSS growth ≤ 10 MB across a ≥10-minute run.
- `tests/stress_render.rs` — fires 1 000 concurrent `sss render`
  invocations against a shared 1 000-secret fixture; asserts all exits
  are 0.

Belt-and-braces gating: each test has a source-level
`#![cfg(feature = "slow-tests")]` AND a `Cargo.toml` `[[test]]
required-features = ["hybrid", "slow-tests"]`. Default `cargo test` does
not compile these files at all.

Expected runtime: ~12–18 minutes total (the soak's 10-minute floor
dominates; stress fan-out is 30s–5min depending on host). Linux only —
the soak test reads `/proc/<pid>/status`. The slow-tests gate makes this
non-portable assumption acceptable.

For fast development iteration on the soak test, override the duration
floor:

```sh
SSS_SOAK_DURATION_SEC=60 cargo test --features hybrid,slow-tests --test soak_agent -- --nocapture
```

The 10-minute floor is enforced only when the env var is unset. Production
gate runs the floor.

## Fuzz

```sh
cd fuzz && cargo +nightly fuzz run <harness> -- -max_total_time=300
```

Runs one libFuzzer harness for 5 minutes. Three harnesses live in
`fuzz/fuzz_targets/`:

- `config_parser` — fuzzes `toml::from_str::<ProjectConfig>` against
  arbitrary bytes.
- `marker_scanner` — fuzzes `marker_inference::infer_markers(s, s)` (the
  public wrapper; the internal `parse_markers` is private).
- `keystore_deser` — fuzzes both `toml::from_str` and `serde_json::from_str`
  against `StoredKeyPair`.

Acceptance gate: each harness runs for 5 minutes (`-max_total_time=300`)
on a clean tree (corpus seeded, `fuzz/artifacts/` empty), with no crash
output. To run all three sequentially:

```sh
cd fuzz
for h in config_parser marker_scanner keystore_deser; do
  cargo +nightly fuzz run "$h" -- -max_total_time=300
done
```

Prerequisites: nightly Rust toolchain, `cargo-fuzz` installed
(`cargo +nightly install cargo-fuzz`), Linux x86_64 or aarch64. macOS and
Windows fuzz support is out of scope; libFuzzer is a Linux-first tool. The
`fuzz/` crate is a separate workspace and is invisible to
`cargo test --workspace`.

Corpus seeds are committed under `fuzz/corpus/<harness>/`; libFuzzer
generates new inputs from these starters. Crash bodies (if any) land
under `fuzz/artifacts/` (gitignored — environment-specific).

CI integration of the fuzz suite is out of scope for v2.2; it is a Phase 20
deliverable per `.planning/ROADMAP.md` §Phase 20.

---

For the coverage gate matrix, retention thresholds, and out-of-scope
file list, see [test-coverage.md](test-coverage.md).
