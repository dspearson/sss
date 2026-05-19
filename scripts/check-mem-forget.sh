#!/usr/bin/env bash
# Why: MEMSAFE-05 + ASVS V8 audit-readiness regression gate. Catches the
# zeroisation-defeat anti-pattern where `std::mem::forget(...)` on a
# Zeroizing<T> (or any secret-bearing wrapper) bypasses the Drop impl that
# would otherwise zero the buffer. Complements `clippy::mem_forget = "deny"`
# from Phase 21 [lints.clippy] at compile time — this grep gate is
# belt-and-braces for macro-expanded mem::forget calls clippy may miss, and
# for ensuring every legitimate mem::forget in src/ carries an inline
# rationale.
#
# Phase 23 plan: 23-04 (Sanitizers + Zeroisation Second-Pass).
# Scope: per memory feedback_no_find_root we never walk the filesystem
# root — searches are scoped to src/ (default) and tests/ (with
# --include-tests). Optional --root <dir> supports fixture-based testing.
#
# Policy:
# - mem::forget in src/ requires a `// Why:` line IMMEDIATELY above OR a
#   trailing `// ...` comment on the same line (matching the fuse/fs.rs
#   precedent where File::from_raw_fd ownership transfer requires the call).
# - mem::forget in tests/ is allowed without rationale (test scaffolding may
#   use it legitimately).
# - mem::forget behind #[allow(clippy::mem_forget)] with a `// Why:` line
#   above the attribute is also accepted (explicit clippy-suppression form).
#
# Exit codes:
#   0 = pass (every mem::forget in src/ has rationale, or tests/ is exempt)
#   1 = fail (one or more mem::forget sites missing rationale)
#   2 = invalid arguments

set -u

INCLUDE_TESTS=0
ROOT=""

usage() {
    cat <<'USAGE'
Usage: check-mem-forget.sh [--include-tests] [--root <dir>] [--help]

Walks every Rust source file under src/ (and tests/ with --include-tests)
looking for `mem::forget(` / `std::mem::forget(` calls. For each call site,
either:
  - the line IMMEDIATELY ABOVE must begin with "// Why:" (leading whitespace OK), OR
  - the call line itself must carry a trailing `// ...` comment of >=10 chars
    (the rationale on the same line).

Options:
  --include-tests   Also scan tests/*.rs in addition to src/.
  --root <dir>      Scan <dir> instead of src/. Used for fixture testing.
  --help            Print this message.

Exit codes: 0=pass, 1=missing-Why, 2=invalid-args.
USAGE
}

# Argument parsing
while [ $# -gt 0 ]; do
    case "$1" in
        --include-tests)
            INCLUDE_TESTS=1
            shift
            ;;
        --root)
            if [ $# -lt 2 ]; then
                echo "ERROR: --root requires a directory argument" >&2
                exit 2
            fi
            ROOT="$2"
            shift 2
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

# Build the file list. Per feedback_no_find_root: never walk filesystem
# root. Scope is strictly the project's src/ (or --root) and optionally tests/.
SEARCH_DIRS=()
if [ -n "$ROOT" ]; then
    if [ ! -d "$ROOT" ]; then
        echo "ERROR: --root path is not a directory: $ROOT" >&2
        exit 2
    fi
    SEARCH_DIRS+=("$ROOT")
else
    if [ ! -d src ]; then
        echo "ERROR: src/ not found in CWD ($(pwd)) — run from project root or pass --root" >&2
        exit 2
    fi
    SEARCH_DIRS+=("src")
    if [ "$INCLUDE_TESTS" = "1" ] && [ -d tests ]; then
        SEARCH_DIRS+=("tests")
    fi
fi

# Find every mem::forget(...) call site. Pattern: `mem::forget(` or
# `std::mem::forget(` or `core::mem::forget(`, anywhere on the line.
PASSED=0
FAILED=0
declare -a FAIL_MSGS=()

for dir in "${SEARCH_DIRS[@]}"; do
    while IFS= read -r -d '' f; do
        # tests/ files are exempt from the rationale requirement
        case "$f" in
            tests/*|*/tests/*)
                continue
                ;;
        esac

        # Iterate over each mem::forget occurrence in this file
        while IFS=: read -r lineno _; do
            # Read the call line itself + the line above
            call_line=$(sed -n "${lineno}p" "$f")
            prev_lineno=$((lineno - 1))
            if [ "$prev_lineno" -gt 0 ]; then
                prev_line=$(sed -n "${prev_lineno}p" "$f")
            else
                prev_line=""
            fi

            # Check 1: previous line starts with "// Why:" (leading ws OK)
            if echo "$prev_line" | grep -qE '^\s*//\s*Why:'; then
                PASSED=$((PASSED + 1))
                continue
            fi

            # Check 2: previous line is a /* Why: ... */ block comment
            if echo "$prev_line" | grep -qE '/\*\s*Why:'; then
                PASSED=$((PASSED + 1))
                continue
            fi

            # Check 3: same-line trailing comment of >=10 chars
            trailing=$(echo "$call_line" | sed -nE 's|.*mem::forget\([^)]*\)\s*;\s*//\s*(.*)|\1|p')
            if [ -n "$trailing" ] && [ "${#trailing}" -ge 10 ]; then
                PASSED=$((PASSED + 1))
                continue
            fi

            # No rationale found — fail
            FAILED=$((FAILED + 1))
            FAIL_MSGS+=("FAIL: $f:$lineno: mem::forget() without // Why: rationale on line above or trailing comment")
        done < <(grep -n -E '\bmem::forget\s*\(' "$f" 2>/dev/null || true)
    done < <(find "$dir" -name '*.rs' -type f -print0 2>/dev/null)
done

# Summary
echo
echo "Passed: $PASSED"
echo "Failed: $FAILED"

if [ "$FAILED" -gt 0 ]; then
    echo
    printf '%s\n' "${FAIL_MSGS[@]}"
    exit 1
fi
exit 0
