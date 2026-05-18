#!/usr/bin/env bash
# Why: QUAL-05 + ASVS V6 audit-readiness — enforce that every production
# `unsafe { }` block in the workspace carries a `// SAFETY:` comment within
# 3 lines above. Belt-and-braces gate complementing the clippy
# `undocumented_unsafe_blocks = "deny"` lint enabled by Plan 21-01; catches
# drift between commits during Phase 21 itself while the lint floor is
# being landed.
#
# Hard rules:
#   - Never `find /` (per memory feedback_no_find_root).
#   - No internal-mirror / vendor-private strings in any commit reaching origin.
#   - POSIX-compatible bash; avoid GNU-specific find flags.
#
# Exit codes:
#   0 = pass (every in-scope unsafe block has SAFETY OR is exempted)
#   1 = SAFETY missing on at least one unsafe block in scope
#   2 = invalid arguments

set -u

INCLUDE_TESTS=0
ROOT=""

usage() {
    cat <<'EOF'
Usage: check-safety-comments.sh [--include-tests] [--root <PATH>] [--help]

Scans `.rs` files in scope for `unsafe { }` block opens and verifies that
each carries a `// SAFETY:` comment within 3 lines above.

Options:
  --include-tests   Also scan `tests/` and `#[cfg(test)] mod tests` blocks.
                    Without this flag, test code is excluded from the scan.
  --root <PATH>     Override the default scan root (defaults to `src/`).
                    Path must be inside the workspace OR under `/tmp/`
                    (the latter enables fixture testing).
  --help            Show this help text.

Exit codes: 0 = pass, 1 = SAFETY missing, 2 = invalid args.
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --include-tests)
            INCLUDE_TESTS=1
            shift
            ;;
        --root)
            if [ $# -lt 2 ]; then
                echo "ERROR: --root requires a PATH argument" >&2
                usage >&2
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

# Default scan root.
if [ -z "$ROOT" ]; then
    ROOT="src/"
fi

# --root safety guard: accept only paths inside the workspace OR under /tmp/.
# This prevents accidental scans of unrelated filesystem locations.
case "$ROOT" in
    /tmp/*|tmp/*)
        ;; # fixture testing — accepted
    /*)
        # Absolute path outside /tmp — reject defensively.
        echo "ERROR: --root must be a workspace-relative path or under /tmp/; got '$ROOT'" >&2
        exit 2
        ;;
    *)
        ;; # relative path — accepted (assumed workspace-relative)
esac

if [ ! -d "$ROOT" ]; then
    echo "ERROR: scan root does not exist: $ROOT" >&2
    exit 2
fi

# Build the file list. Use `find` scoped to ROOT — never `find /`.
# Excludes the `tests/` subdirectory unless --include-tests is passed.
RS_FILES=$(find "$ROOT" -type f -name '*.rs' 2>/dev/null | sort)

if [ "$INCLUDE_TESTS" -eq 1 ] && [ "$ROOT" = "src/" ] && [ -d "tests" ]; then
    TESTS_FILES=$(find tests -type f -name '*.rs' 2>/dev/null | sort)
    RS_FILES="$RS_FILES
$TESTS_FILES"
fi

PASSED=0
FAILED=0
EXEMPTED=0

# Iterate over each `.rs` file in scope.
while IFS= read -r file; do
    [ -z "$file" ] && continue
    [ -f "$file" ] || continue

    # Locate `unsafe { ... ` block-open lines. Patterns accepted:
    #   - `    unsafe {`             (block-start on its own line, with leading indent)
    #   - `let x = unsafe {`         (rhs of let-binding)
    #   - `INIT.call_once(|| unsafe {` (inline in closure)
    # Patterns NOT accepted (the missing_safety_doc lint covers these):
    #   - `unsafe fn`
    #   - `unsafe trait`
    #   - `unsafe impl`
    #
    # Approach: grep for `unsafe\s*\{` then post-filter out fn/trait/impl declarations.
    UNSAFE_LINES=$(grep -nE 'unsafe[[:space:]]*\{' "$file" 2>/dev/null \
        | grep -vE 'unsafe[[:space:]]+(fn|trait|impl)\b' \
        || true)

    [ -z "$UNSAFE_LINES" ] && continue

    # If --include-tests was NOT passed, prepare a per-file exclusion of
    # `#[cfg(test)] mod tests { ... }` body line ranges by locating the
    # opening brace line for the test module.
    EXCLUDE_TEST_START=""
    if [ "$INCLUDE_TESTS" -eq 0 ]; then
        # Find the first `#[cfg(test)] mod tests {` (or `#[cfg(test)] mod <name> {`).
        # If present, the unsafe blocks below it are test-only and excluded.
        EXCLUDE_TEST_START=$(grep -nE '^#\[cfg\(test\)\]' "$file" 2>/dev/null | head -1 | cut -d: -f1 || true)
    fi

    while IFS=: read -r lineno _; do
        [ -z "$lineno" ] && continue

        # Skip test-module blocks when --include-tests is not set.
        if [ -n "$EXCLUDE_TEST_START" ] && [ "$lineno" -ge "$EXCLUDE_TEST_START" ]; then
            continue
        fi

        # Look at the 3 lines immediately above the unsafe-block-open line.
        START=$((lineno - 3))
        END=$((lineno - 1))
        [ "$START" -lt 1 ] && START=1

        # Extract the 3-line window.
        WINDOW=$(sed -n "${START},${END}p" "$file" 2>/dev/null)

        # Match SAFETY in any of: `// SAFETY:`, `/// SAFETY:`, `//SAFETY:`,
        # with leading whitespace allowed.
        if echo "$WINDOW" | grep -qE '^[[:space:]]*(///?[[:space:]]*)SAFETY:'; then
            PASSED=$((PASSED + 1))
            continue
        fi

        # Check for `#[allow(clippy::undocumented_unsafe_blocks)]` exemption
        # within the 10 lines above (covers fn-level + block-level attrs).
        EXEMPT_START=$((lineno - 10))
        [ "$EXEMPT_START" -lt 1 ] && EXEMPT_START=1
        EXEMPT_END=$((lineno - 1))
        EXEMPT_WINDOW=$(sed -n "${EXEMPT_START},${EXEMPT_END}p" "$file" 2>/dev/null)
        if echo "$EXEMPT_WINDOW" | grep -qE 'allow\(clippy::undocumented_unsafe_blocks\)'; then
            echo "INFO: $file:$lineno: unsafe block exempt via #[allow]"
            EXEMPTED=$((EXEMPTED + 1))
            continue
        fi

        echo "FAIL: $file:$lineno: unsafe block has no SAFETY comment within 3 lines above"
        FAILED=$((FAILED + 1))
    done <<EOF
$UNSAFE_LINES
EOF
done <<EOF
$RS_FILES
EOF

echo ""
echo "Passed: $PASSED"
echo "Failed: $FAILED"
echo "Exempted: $EXEMPTED"

if [ "$FAILED" -gt 0 ]; then
    exit 1
fi
exit 0
