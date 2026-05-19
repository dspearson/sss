#!/usr/bin/env bash
# Phase 27 / AUDIT-04 — no-scrub rule assertion script.
#
# Per locked decision D-V23-06 (REQUIREMENTS.md):
#   "Preserve .planning/milestones/v2.2-phases/*/deferred-items.md and
#    retain EXPERIMENTAL trelis disclaimer until AUDIT-01 closes."
#
# This script asserts both invariants. It's wired into ci-matrix.yml as
# an informational step in v2.3 (hard-gate promoted in v2.4 if any
# regression appears).
#
# Exit codes:
#   0  — all assertions hold
#   1  — at least one assertion failed; output identifies which

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

FAIL=0

# ─── Assertion 1: EXPERIMENTAL trelis disclaimer in CRYPTOGRAPHY.md ───
if ! grep -q 'WARNING: trelis is Unaudited and Experimental' docs/CRYPTOGRAPHY.md; then
    echo "no-scrub FAIL: docs/CRYPTOGRAPHY.md missing 'WARNING: trelis is Unaudited and Experimental' header"
    FAIL=1
fi

# ─── Assertion 2: EXPERIMENTAL trelis disclaimer in security-model.md ───
if ! grep -q 'EXPERIMENTAL' docs/security-model.md; then
    echo "no-scrub FAIL: docs/security-model.md missing EXPERIMENTAL substring"
    FAIL=1
fi

# ─── Assertion 3: v2.2 milestone deferred-items.md files preserved ───
V22_DEFERRED_COUNT=$(find .planning/milestones/v2.2-phases -name 'deferred-items.md' 2>/dev/null | wc -l)
if [ "$V22_DEFERRED_COUNT" -lt 5 ]; then
    echo "no-scrub FAIL: v2.2 deferred-items.md count is $V22_DEFERRED_COUNT (expected >= 5)"
    FAIL=1
fi

# ─── Assertion 4: v2.1 + v2.2 milestone archive artefacts preserved ───
for f in \
    .planning/milestones/v2.1-MILESTONE-AUDIT.md \
    .planning/milestones/v2.1-REQUIREMENTS.md \
    .planning/milestones/v2.1-ROADMAP.md \
    .planning/milestones/v2.2-REQUIREMENTS.md \
    .planning/milestones/v2.2-ROADMAP.md ; do
    if [ ! -f "$f" ]; then
        echo "no-scrub FAIL: $f missing"
        FAIL=1
    fi
done

# ─── Assertion 5: v2.3 milestone in-flight archive shape ───
for f in \
    .planning/REQUIREMENTS.md \
    .planning/ROADMAP.md \
    .planning/STATE.md ; do
    if [ ! -f "$f" ]; then
        echo "no-scrub FAIL: $f missing"
        FAIL=1
    fi
done

# ─── Reporting ───
if [ "$FAIL" = "0" ]; then
    echo "no-scrub OK: all 5 invariant categories pass"
    exit 0
else
    echo
    echo "no-scrub assertion(s) failed. See D-V23-06 (REQUIREMENTS.md) for the rule."
    echo "Re-running cleanup or archive operations that scrubbed audit history"
    echo "is the most common cause. Restore from git history if needed."
    exit 1
fi
