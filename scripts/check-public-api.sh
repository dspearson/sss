#!/usr/bin/env bash
# Why: API-01 + ASVS V1 (Architecture) — committed PUBLIC.md snapshot of the sss
# default-feature public API surface. Catches unintended public-API changes (added,
# removed, or renamed pub items) that would silently break downstream users or
# auditor expectations. Mirrors the check-mem-forget.sh + check-no-scrub.sh pattern.
#
# Scope: default features only (classic crypto arm, no --features hybrid).
#        pub mod envelope_sig and hybrid crypto items are intentionally absent from
#        PUBLIC.md — gated on --features hybrid (Phase 19 / PQSIG-04 addition).
#
# To re-baseline PUBLIC.md after an intentional API change:
#   bash scripts/check-public-api.sh --update
#
# Requires: cargo-public-api installed to .gsd-tools/bin/ or /tmp/cargo-tools/bin/
#   Install: cargo install --root .gsd-tools --locked cargo-public-api
# Nightly:  uses RUSTUP_TOOLCHAIN=nightly-2026-04-15 (project pin for miri/sanitizer;
#           satisfies cargo-public-api 0.52.x requirement of >= nightly-2025-08-02)
#
# Exit codes:
#   0 = pass (live cargo-public-api output matches PUBLIC.md)
#   1 = drift (live output differs from PUBLIC.md — API changed without re-baselining)
#   2 = setup-error (binary not found) or invalid arguments

set -euo pipefail

UPDATE=0

usage() {
    cat <<'USAGE'
Usage: check-public-api.sh [--update] [--help]

Runs cargo-public-api with default features (no --features hybrid), diffs
the live output against the committed PUBLIC.md snapshot. Exits non-zero on
drift so the deviation is caught before merge rather than silently shipped.

Options:
  --update   Regenerate PUBLIC.md from the live cargo-public-api output.
             Use after an intentional API change to re-baseline the snapshot.
  --help     Print this message.

Exit codes: 0=match, 1=drift, 2=setup-error/invalid-args.

Re-baseline one-liner:
  bash scripts/check-public-api.sh --update
USAGE
}

while [ $# -gt 0 ]; do
    case "$1" in
        --update)
            UPDATE=1
            shift
            ;;
        --help|-h)
            usage
            exit 0
            ;;
        *)
            echo "ERROR: unknown argument: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

# Locate the cargo-public-api binary.
# Primary: .gsd-tools/bin/ (gitignored, persistent across sessions — Phase 10 / DEPS-01 convention).
# Fallback: /tmp/cargo-tools/bin/ (ephemeral, reboot-cleared; Phase 30 install root).
TOOL_BIN=""
for candidate in \
    "$REPO_ROOT/.gsd-tools/bin/cargo-public-api" \
    "/tmp/cargo-tools/bin/cargo-public-api" ; do
    if [ -x "$candidate" ]; then
        TOOL_BIN="$candidate"
        break
    fi
done

if [ -z "$TOOL_BIN" ]; then
    echo "ERROR: cargo-public-api not found in .gsd-tools/bin/ or /tmp/cargo-tools/bin/" >&2
    echo "Install: cargo install --root \"\$REPO_ROOT/.gsd-tools\" --locked cargo-public-api" >&2
    echo "Then re-run this script." >&2
    exit 2
fi

SNAPSHOT="$REPO_ROOT/PUBLIC.md"

# Capture the live public-API output with the pinned nightly toolchain.
# --color never: suppress ANSI codes (else every diff shows spurious drift).
# -s / --simplified: omit blanket/auto-derived impls (reduces noise).
# --manifest-path: cwd-independent invocation.
LIVE=$(RUSTUP_TOOLCHAIN=nightly-2026-04-15 \
    "$TOOL_BIN" \
    --manifest-path "$REPO_ROOT/Cargo.toml" \
    --color never \
    -s \
    2>/dev/null)

if [ "$UPDATE" = "1" ]; then
    # Preserve the header comment block (lines up to and including the closing -->),
    # then append the fresh live output.
    HEADER=$(awk '/^-->/{print; exit} {print}' "$SNAPSHOT")
    {
        printf '%s\n' "$HEADER"
        echo ""
        printf '%s\n' "$LIVE"
    } > "$SNAPSHOT"
    echo "PUBLIC.md updated with live cargo-public-api output."
    exit 0
fi

# Check mode: diff live output against the committed snapshot body.
# We compare only the API lines (strip the header comment block from the snapshot).
SNAPSHOT_BODY=$(awk '/^-->/{found=1; next} found && NF{print}' "$SNAPSHOT")

if ! diff <(printf '%s\n' "$LIVE") <(printf '%s\n' "$SNAPSHOT_BODY") >/dev/null 2>&1; then
    echo "FAIL: public API has drifted from PUBLIC.md." >&2
    echo "" >&2
    diff <(printf '%s\n' "$LIVE") <(printf '%s\n' "$SNAPSHOT_BODY") || true
    echo "" >&2
    echo "If this is an intentional API change, re-baseline with:" >&2
    echo "  bash scripts/check-public-api.sh --update" >&2
    exit 1
fi

echo "OK: public API matches PUBLIC.md."
exit 0
