---
phase: 06-documentation-release
plan: 02
subsystem: docs
tags: [documentation, hybrid, post-quantum, man-page, changelog, readme]
dependency_graph:
  requires: []
  provides: [DOCS-02, DOCS-03]
  affects: [README.md, man/sss.1, CHANGELOG.md]
tech_stack:
  added: []
  patterns: [Keep-a-Changelog, roff/troff man page format]
key_files:
  modified:
    - README.md
    - man/sss.1
    - CHANGELOG.md
decisions:
  - "hybrid section placed after Multi-User Collaboration and before Secrets Files in README"
  - "man page HYBRID SUITE section inserted as .SH (top-level) before .SH SECURITY"
  - "Migration commands documented in a new .SS Migration (v2.0) subsection between Key Management and User Settings"
  - "trelis described as experimental and formally unaudited in both README and man page"
  - "CHANGELOG [2.0.0] entry includes Security subsection per threat model T-06-02-01"
metrics:
  duration: "~8 minutes"
  completed: "2026-04-26"
  tasks_completed: 2
  tasks_total: 2
  files_changed: 3
  insertions: 203
  deletions: 4
---

# Phase 06 Plan 02: Documentation — Hybrid Suite Summary

User-facing documentation extended to cover the v2.0 hybrid post-quantum suite across README.md, man/sss.1, and CHANGELOG.md.

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 1 | Add hybrid suite section to README.md and update Security table | 269c8cd | README.md |
| 2 | Extend man/sss.1 with v2.0 commands and hybrid suite section; add v2.0.0 entry to CHANGELOG.md | 269c8cd | man/sss.1, CHANGELOG.md |

(Both tasks committed atomically per plan instruction.)

## What Was Done

### README.md

- Added **Post-quantum hybrid suite** bullet to the Features list (after Key derivation)
- Added **`## Hybrid / Post-Quantum Suite (v2.0)`** section after Multi-User Collaboration, before Secrets Files, containing:
  - Experimental/unaudited trelis warning blockquote
  - Classic vs hybrid version dispatch table (`"1.0"` / `"2.0"`)
  - "Creating a new hybrid project" subsection with `sss keys generate --suite both` and `sss init --crypto hybrid`
  - "Migrating an existing project to hybrid" 5-step walkthrough including `sss keys pubkey --suite hybrid`
  - "Building with hybrid support" subsection (`cargo build --features hybrid --release`)
- Updated **Security cryptographic primitives table** — new row: Key exchange (hybrid, opt-in) / X448 + sntrup761 KEM (trelis, experimental)
- Added **v2.0 note** blockquote below the Security table pointing to docs/security-model.md and docs/CRYPTOGRAPHY.md
- Updated **Command Reference / Key Management** to show `--suite classic/hybrid/both` variants; added `sss init --crypto hybrid` variant
- Added **`### Migration`** subsection in Command Reference with `sss migrate`, `sss migrate --dry-run`, `sss users add-hybrid-key`
- Updated **Documentation table** row for docs/security-model.md to mention v2.0 hybrid suite

### man/sss.1

- Updated `.SS Key Management` — `sss keys generate` entry now documents `--suite classic|hybrid|both` with descriptions of each
- Added `.SS Migration (v2.0)` subsection (between Key Management and User Settings) documenting:
  - `sss migrate [--dry-run]` — full description including non-zero exit on missing hybrid keys
  - `sss migrate --dry-run` — no-disk-write behaviour, `git-status(1)` shows no changes
  - `sss users add-hybrid-key <username> <pubkey>` — 1214-byte raw public key prerequisite
- Added `.SH HYBRID SUITE` top-level section (before .SH SECURITY) with:
  - trelis experimental/unaudited warning
  - version field dispatch table (`"1.0"` classic, `"2.0"` hybrid)
  - byte-identical ciphertext statement
- Added `.SS Hybrid Suite Migration` example in the EXAMPLES section showing the full 5-command migration flow

### CHANGELOG.md

- Inserted `## [2.0.0] - 2026-04-26` entry immediately before `## [1.2.0] - 2025-03-15`
- Entry covers Added (hybrid suite, keystore dual-suite, sss migrate, sss users add-hybrid-key, suite-aware types), Security (trelis EXPERIMENTAL/unaudited caveat, ZeroizeOnDrop, v1 error on v2 toml), and Changed (.sss.toml version dispatch, sealed_key size increase)

## Deviations from Plan

None — plan executed exactly as written.

## Threat Model Compliance

| Threat ID | Mitigation | Status |
|-----------|-----------|--------|
| T-06-02-01 | CHANGELOG Security section carries "EXPERIMENTAL — trelis is unaudited" | Mitigated |
| T-06-02-02 | man/sss.1 documents all new commands accurately | Mitigated |

## Verification Results

All plan acceptance criteria pass:

| Criterion | Required | Actual |
|-----------|----------|--------|
| `grep -c "sss migrate" README.md` | ≥ 3 | 5 |
| `grep -i "unaudited\|experimental" README.md` | ≥ 2 | 8 |
| `grep "sss keys generate --suite" README.md` | ≥ 2 | 4 |
| `grep "sss users add-hybrid-key" README.md` | ≥ 1 | 2 |
| `grep -i "Hybrid.*Post-Quantum\|Post-Quantum Suite" README.md` | ≥ 1 | 5 |
| `grep "version.*1\.0.*classic\|version.*2\.0.*hybrid" README.md` | ≥ 1 | 4 |
| `grep "sss keys pubkey --suite hybrid" README.md` | ≥ 1 | 1 |
| `grep "\[2\.0\.0\]" CHANGELOG.md` | = 1 | 1 |
| ORDER OK (`awk` order check) | ORDER OK | ORDER OK |
| `grep -c "sss migrate" CHANGELOG.md` | ≥ 2 | 2 |
| `grep "trelis.*unaudited\|EXPERIMENTAL.*trelis" CHANGELOG.md` | ≥ 1 | 1 |
| `grep -c "sss migrate" man/sss.1` | ≥ 2 | 8 |
| `grep -c "add-hybrid-key" man/sss.1` | ≥ 1 | 3 |
| `grep -c "HYBRID SUITE" man/sss.1` | ≥ 1 | 3 |
| `grep -i "unaudited\|experimental" man/sss.1` | ≥ 1 | 1 |
| `grep "byte-identical" man/sss.1` | ≥ 1 | 1 |
| `man --warnings -E UTF-8 -l man/sss.1 > /dev/null` | troff: OK | troff: OK |

## Self-Check: PASSED

- README.md exists and contains "Hybrid / Post-Quantum Suite"
- man/sss.1 exists and contains ".SH HYBRID SUITE"
- CHANGELOG.md exists and contains "[2.0.0]"
- Commit 269c8cd exists in git log
