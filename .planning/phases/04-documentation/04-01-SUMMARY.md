---
phase: 04-documentation
plan: 01
subsystem: documentation
tags: [markdown, sss, usage-guide, configuration, cli]

# Dependency graph
requires:
  - phase: 01-cli-foundation
    provides: CLI subcommands and flag names verified against src/main.rs
  - phase: 04-documentation
    provides: 04-RESEARCH.md with verified source-first accuracy findings
provides:
  - docs/usage-guide.md — complete workflow guide from setup through team collaboration
  - docs/configuration.md — full reference for .sss.toml, settings.toml, env vars
affects: [04-02-marker-format, 04-03-architecture, README-overhaul]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Documentation written from source code (src/main.rs, src/project.rs, src/config_manager.rs), not from README"
    - "British English throughout all documentation"
    - "All CLI examples verified against clap subcommand definitions in src/main.rs"

key-files:
  created:
    - docs/usage-guide.md
    - docs/configuration.md
  modified: []

key-decisions:
  - "docs/usage-guide.md uses sss keys generate (not sss keygen) — confirmed from handle_keygen_deprecated in main.rs"
  - "docs/configuration.md serde field names taken from struct definitions — no serde rename attributes found, field names match"
  - "Cross-links between usage-guide.md and configuration.md use relative paths within docs/"
  - "sss project users add/remove documented (not sss users add/remove) — project subcommand is correct per main.rs"

patterns-established:
  - "Source-First: Every CLI example verified against src/main.rs before inclusion"
  - "British English: initialise, colour, behaviour, serialise throughout"
  - "Cross-linking: each doc links to related docs for complete coverage without duplication"

requirements-completed: [DOC-02, DOC-06]

# Metrics
duration: 5min
completed: 2026-02-21
---

# Phase 4 Plan 01: Documentation (Usage Guide + Configuration Reference) Summary

**Usage guide covering key generation through team collaboration, and configuration reference for .sss.toml, settings.toml, env vars, and CLI options — written from source code with all CLI examples verified against src/main.rs**

## Performance

- **Duration:** 5 min
- **Started:** 2026-02-21T16:46:43Z
- **Completed:** 2026-02-21T16:51:39Z
- **Tasks:** 2
- **Files modified:** 2

## Accomplishments
- Complete usage guide (docs/usage-guide.md) covering all 12 sections: overview, initial setup, marking secrets, seal, open, edit, render, key management, team collaboration, git integration, secrets files, stdin support
- Complete configuration reference (docs/configuration.md) with annotated .sss.toml and settings.toml examples, platform-specific paths, full env vars table, global CLI options, ignore patterns, and secrets file configuration
- All CLI examples verified against src/main.rs clap definitions — zero deprecated/incorrect subcommands
- British English verified: initialise, colour, behaviour, serialise appear throughout both files

## Task Commits

Each task was committed atomically:

1. **Task 1: Write docs/usage-guide.md (DOC-02)** - `8d5e1cd` (docs)
2. **Task 2: Write docs/configuration.md (DOC-06)** - `a0a4109` (docs)

**Plan metadata:** (this commit)

## Files Created/Modified
- `docs/usage-guide.md` — complete workflow guide: setup, seal/open/edit/render, key management, team collaboration, git hooks, secrets files, stdin
- `docs/configuration.md` — configuration reference: .sss.toml schema, settings.toml schema, platform paths, env vars, CLI global options, ignore patterns, secrets file config

## Decisions Made
- `sss project users add/remove` (not `sss users add/remove`) — the `project` subcommand is the correct path per main.rs; `users` also exists as a top-level but `project users` is the recommended path used in documentation
- Field names in settings.toml match Rust struct field names exactly (default_username, coloured_output, etc.) — no serde rename attributes found in config_manager.rs
- Cross-links between the two docs use relative paths (no absolute URLs) so they work in any documentation viewer

## Deviations from Plan

None - plan executed exactly as written. Both documents follow the specified section structure. All accuracy rules from the research file were applied.

## Issues Encountered
None.

## User Setup Required
None - no external service configuration required.

## Next Phase Readiness
- DOC-02 and DOC-06 complete. Remaining documentation phase plans can reference these files.
- usage-guide.md and configuration.md are stable foundations for DOC-01 (README overhaul) which can link to them.

---
*Phase: 04-documentation*
*Completed: 2026-02-21*
