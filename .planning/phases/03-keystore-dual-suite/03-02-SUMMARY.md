---
phase: "03-keystore-dual-suite"
plan: "02"
subsystem: "cli"
tags: ["cli", "keygen", "keys-show", "dual-suite", "hybrid", "KEYSTORE-02", "KEYSTORE-03"]
dependency_graph:
  requires:
    - "03-01: StoredKeyPair hybrid fields + store_dual_keypair + get_current_stored_raw"
  provides:
    - "--suite <classic|hybrid|both> arg on keys generate and deprecated keygen"
    - "keys show subcommand displaying labelled Classic/Hybrid randomart blocks"
    - "sss init --crypto hybrid hint: run sss keygen --suite both"
  affects:
    - "src/main.rs"
    - "src/commands/keys.rs"
    - "src/commands/init.rs"
    - "tests/keys_suite_flag.rs"
tech_stack:
  added: []
  patterns:
    - "#[cfg(feature = \"hybrid\")] match arms for suite dispatch"
    - "#[cfg(not(feature = \"hybrid\"))] feature-absent guard before hybrid code paths"
    - "saturating_sub for usize header padding in randomart (overflow-safe)"
    - "cfg-split get_current_stored_raw (hybrid) vs list_key_ids (non-hybrid) in keys show"
key_files:
  created:
    - "tests/keys_suite_flag.rs"
  modified:
    - "src/main.rs"
    - "src/commands/keys.rs"
    - "src/commands/init.rs"
decisions:
  - "--suite is required(true) with value_parser([classic,hybrid,both]) — no default (CONTEXT.md decision)"
  - "handle_keys_show uses get_current_stored_raw on hybrid builds; list_key_ids fallback on non-hybrid to avoid feature-gated method call"
  - "generate_randomart header padding uses saturating_sub to handle key_type labels wider than RANDOMART_WIDTH"
  - "Feature-absent guard fires before the no-classic-key check to give a clear --features message even if a classic key is present"
metrics:
  duration: "~25 minutes"
  completed_date: "2026-04-26"
  tasks_completed: 3
  files_modified: 4
requirements_completed:
  - KEYSTORE-02
  - KEYSTORE-03
---

# Phase 03 Plan 02: keygen --suite CLI flag and sss keys show Summary

`--suite <classic|hybrid|both>` wired to `keys generate` and deprecated `keygen`; `sss keys show` added displaying labelled SHA256-fingerprint randomart blocks per suite; `sss init --crypto hybrid` now prints a keygen hint.

## Accomplishments

- Added `--suite <classic|hybrid|both>` (`required(true)`, `value_parser` restricted) to both `keys generate` and deprecated `keygen` subcommand definitions in `src/main.rs`. Clap rejects unknown values at parse time before the handler runs.

- Added `Command::new("show")` to the `keys` group in `src/main.rs`.

- Extended `handle_keys_generate_command` in `src/commands/keys.rs` with three dispatch arms:
  - `classic`: existing path — `KeyPair::generate()` + `store_keypair`.
  - `hybrid` (`#[cfg(feature = "hybrid")]`): checks for existing classic key (T-03-08); errors with exact CONTEXT.md message if absent; generates `HybridKeyPair`, calls `store_dual_keypair(None, Some(&hybrid), pw)`, prints "classic keypair kept; hybrid keypair added".
  - `both` (`#[cfg(feature = "hybrid")]`): generates classic + hybrid atomically, calls `store_dual_keypair(Some(&classic), Some(&hybrid), pw)`, prints both public keys.
  - Feature-absent guard at the top of the dispatch fires immediately for `hybrid`/`both` on non-hybrid builds with message "hybrid suite requires a --features hybrid build".

- Added `handle_keys_show` in `src/commands/keys.rs`:
  - On hybrid builds: calls `get_current_stored_raw()` to read public fields without decryption; shows Classic block always; shows Hybrid block iff `stored.hybrid_public_key.is_some()`.
  - On non-hybrid builds: reads public key string via `list_key_ids` + `get_current_key_id` (always-available, no decryption).
  - Both paths hash the public key base64 bytes with SHA256 and pass to `generate_randomart`.

- Wired `"show"` arm in `handle_keys` dispatch; updated the `None =>` error message to include `show` in the subcommand list.

- Added post-init hint in `src/commands/init.rs`: prints `"Run \`sss keygen --suite both\` to generate your keypairs."` only when `crypto == Suite::Hybrid`.

- Added integration test file `tests/keys_suite_flag.rs` with two named tests:
  - `test_keys_generate_suite_arg`: verifies clap rejects unknown `--suite` value and accepts `--suite classic` end-to-end.
  - `test_suite_hybrid_no_feature_errors` (`#[cfg(not(feature = "hybrid"))]`): verifies the exact feature-absent error message.

## Task Commits

| Task | Type | Commit | Description |
|------|------|--------|-------------|
| 1 | feat | `7efe9c5` | Add --suite arg to keygen/keys generate and keys show subcommand |
| 2 | feat | `6101472` | Extend handle_keys_generate_command for --suite; add handle_keys_show |
| 3 | feat | `4785320` | Print keygen hint after sss init --crypto hybrid |
| Dev | fix | `c3d6aa3` | saturating_sub overflow fix in generate_randomart header |

## Files Modified

| File | Changes |
|------|---------|
| `src/main.rs` | +20 lines: --suite arg (×2) + show subcommand definition |
| `src/commands/keys.rs` | +247 lines / -28: suite dispatch, handle_keys_show, overflow fix |
| `src/commands/init.rs` | +4 lines: hybrid hint after init_project_config |
| `tests/keys_suite_flag.rs` | +92 lines: new integration test file |

## Test Results

| Command | Result |
|---------|--------|
| `cargo build -p sss` | No errors |
| `cargo build --features hybrid -p sss` | No errors |
| `cargo test --lib` | 370/370 pass |
| `cargo test --lib --features hybrid` | 391/391 pass |
| `cargo test --test keys_suite_flag` | 2/2 pass |
| `cargo test --test keys_suite_flag --features hybrid` | 1/1 pass (hybrid-only test skipped) |
| `cargo test --test keystore_integration_tests --features hybrid` | 18/18 pass |

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Overflow panic in `generate_randomart` header padding**
- **Found during:** Task 2 smoke test (`sss keys show` after `keys generate --suite classic`)
- **Issue:** `generate_randomart` computed `right_padding = RANDOMART_WIDTH - padding - header.len()` with standard subtraction. The new label `"SSS KEY (Classic)"` produces a 19-char header `[SSS KEY (Classic)]`, which is wider than `RANDOMART_WIDTH` (17). `padding` was 0 (from `saturating_sub`) but `header.len()` (19) exceeded `RANDOMART_WIDTH` (17), causing a `usize` underflow panic.
- **Fix:** Changed the `right_padding` line to use `saturating_sub` for both operands: `RANDOMART_WIDTH.saturating_sub(padding).saturating_sub(header.len())`. The border now prints with zero dashes on both sides when the label fills or exceeds the art width — visually correct, no panic.
- **Files modified:** `src/commands/keys.rs` (line 915)
- **Commit:** `c3d6aa3`

## Known Stubs

None — all dispatch arms are fully implemented. `handle_keys_show` reads real public key data from disk; no placeholder values flow to output.

## Threat Flags

None — no new network endpoints, auth paths, or file access patterns introduced. `handle_keys_show` reads only public fields from the TOML identity file (T-03-09 accepted in plan threat model).

## Self-Check

| Item | Status |
|------|--------|
| `src/main.rs` has `--suite` arg | FOUND |
| `src/commands/keys.rs` has `handle_keys_show` | FOUND |
| `src/commands/init.rs` has keygen hint | FOUND |
| `tests/keys_suite_flag.rs` exists | FOUND |
| Commit `7efe9c5` (Task 1) | FOUND |
| Commit `6101472` (Task 2) | FOUND |
| Commit `4785320` (Task 3) | FOUND |
| Commit `c3d6aa3` (overflow fix) | FOUND |
| 370 lib tests pass without hybrid | PASSED |
| 391 lib tests pass with hybrid | PASSED |
| 18 keystore integration tests pass with hybrid | PASSED |

## Self-Check: PASSED
