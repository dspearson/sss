#!/usr/bin/env bash
# Why: QUAL-02 + ASVS V14 audit-readiness regression gate. Enforces the v2.1
# Plan 11-04 "// Why:" rationale convention universally across src/ (and
# optionally tests/) so every surviving #[allow(...)] / #![allow(...)] is
# justified inline by an immediately-adjacent rationale. CI invokes this
# script as a complement to clippy's pedantic-group enforcement; an allow
# without a // Why: above is a regression.
#
# Phase 21 plan: 21-04 (Lint Strictness Floor + Policy Gates).
# Scope: per memory feedback_no_find_root we never walk the filesystem
# root — searches are scoped to src/ (default) and tests/ (with
# --include-tests). Optional --root <dir> supports fixture-based testing.
#
# Exit codes:
#   0 = pass (every #[allow] has a // Why: line above)
#   1 = fail (one or more allow sites missing rationale)
#   2 = invalid arguments

set -u

INCLUDE_TESTS=0
ROOT=""

usage() {
    cat <<'USAGE'
Usage: check-allow-why.sh [--include-tests] [--root <dir>] [--help]

Walks every Rust source file under src/ (and tests/ with --include-tests)
looking for #[allow(...)] / #![allow(...)] attributes. For each attribute
the line IMMEDIATELY ABOVE must begin with "// Why:" (leading whitespace
allowed). Block-comment rationale (/* Why: ... */ above) is also accepted.

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
    if [ $INCLUDE_TESTS -eq 1 ]; then
        if [ -d tests ]; then
            SEARCH_DIRS+=("tests")
        fi
    fi
fi

# Collect every .rs file under the scoped roots.
FILES=()
for dir in "${SEARCH_DIRS[@]}"; do
    while IFS= read -r -d '' f; do
        FILES+=("$f")
    done < <(find "$dir" -type f -name '*.rs' -print0)
done

if [ ${#FILES[@]} -eq 0 ]; then
    echo "WARNING: no .rs files found under: ${SEARCH_DIRS[*]}"
    echo "Passed: 0"
    echo "Failed: 0"
    exit 0
fi

# Indented-tolerant pattern per plan-checker warning #11. The leading \s*
# catches method-scoped indented allows like `    #[allow(clippy::unused_self)]`
# that a strict `^#\[allow` anchor would silently skip.
ALLOW_PATTERN='^[[:space:]]*#\[allow\(|^[[:space:]]*#!\[allow\('

PASSED=0
FAILED=0
FAIL_LINES=()

# check_block_comment_above
#   Returns 0 (true) iff lines ending at $end_line in $file form a /* Why: ... */
#   block-comment that closes at $end_line. Lookback up to 10 lines.
check_block_comment_above() {
    local file="$1"
    local end_line="$2"

    # The line immediately above the allow must end with */ for this to be a
    # block-comment closer.
    if ! sed -n "${end_line}p" "$file" | grep -qE '\*/[[:space:]]*$'; then
        return 1
    fi

    # Walk upward looking for the matching /* opener (within 10 lines).
    local start=$end_line
    local low=$((end_line - 10))
    if [ $low -lt 1 ]; then
        low=1
    fi
    local cur
    for ((cur = end_line; cur >= low; cur--)); do
        if sed -n "${cur}p" "$file" | grep -qE '/\*'; then
            start=$cur
            break
        fi
    done

    if [ "$start" -eq "$end_line" ] && ! sed -n "${start}p" "$file" | grep -qE '/\*'; then
        return 1
    fi

    # The block must contain "Why:" anywhere between start and end_line.
    if sed -n "${start},${end_line}p" "$file" | grep -q 'Why:'; then
        return 0
    fi
    return 1
}

for f in "${FILES[@]}"; do
    # Locate every allow attribute line in this file.
    # grep -nE prints "lineno:content" — we only need the line numbers.
    while IFS= read -r match; do
        [ -z "$match" ] && continue
        lineno=${match%%:*}
        # Skip lineno = 1 — there cannot be a line above to carry the rationale.
        # Such a top-of-file allow is reported as failing (it cannot satisfy
        # the convention by definition; the file should carry a //! rustdoc
        # block first or be normalised to put the // Why: above).
        if [ "$lineno" -eq 1 ]; then
            FAILED=$((FAILED + 1))
            FAIL_LINES+=("FAIL: ${f}:${lineno}: #[allow] is on line 1 — no // Why: line above possible")
            continue
        fi

        prev=$((lineno - 1))
        prev_content=$(sed -n "${prev}p" "$f")

        # Strict check: previous line starts (after optional whitespace) with "// Why:".
        if echo "$prev_content" | grep -qE '^[[:space:]]*//[[:space:]]*Why:'; then
            PASSED=$((PASSED + 1))
            continue
        fi

        # Fallback: block-comment rationale (/* Why: ... */) closing on prev line.
        if check_block_comment_above "$f" "$prev"; then
            PASSED=$((PASSED + 1))
            continue
        fi

        FAILED=$((FAILED + 1))
        FAIL_LINES+=("FAIL: ${f}:${lineno}: #[allow] has no // Why: comment on line above")
    done < <(grep -nE "$ALLOW_PATTERN" "$f" 2>/dev/null || true)
done

# Report
for line in "${FAIL_LINES[@]}"; do
    echo "$line"
done

echo ""
echo "Passed: $PASSED"
echo "Failed: $FAILED"

if [ $FAILED -gt 0 ]; then
    exit 1
fi
exit 0
