#!/usr/bin/env bash
# Why: REM-48 / MEM-15-001 — fuse-scoped SAFETY-comment regression gate.
# Complements the module-level `#![deny(clippy::undocumented_unsafe_blocks)]`
# in src/fuse/fs.rs with a feature-independent text scan: this script runs on
# every CI matrix cell WITHOUT requiring `--features fuse` compilation, blocking
# any future PR that adds an undocumented `unsafe { }` block under src/fuse/.
#
# Why a NEW script (not check-safety-comments.sh):
# The existing `scripts/check-safety-comments.sh` currently exits NONZERO on
# 23 workspace blocks — two false-positive classes that `cargo clippy` accepts:
#   1. It greps `unsafe {` inside `//!` rustdoc PROSE (e.g. fs.rs module doc).
#   2. It does not tolerate an intervening `#[cfg(...)]` / `#[allow(...)]`
#      attribute line between a `// SAFETY:` comment and the `unsafe {`, so it
#      wrongly flags documented blocks in keys.rs/kdf.rs/classic.rs/hybrid.rs/
#      store.rs. Wiring it to CI for the fuse surface would break CI on
#      non-fuse, out-of-scope blocks.
# This script is scoped to src/fuse/*.rs only and avoids both false-positive
# classes. See 45-02-SUMMARY.md for the full deviation note.
#
# Adjacency window (upward scan algorithm):
# For each `unsafe {` block-open, the script walks upward past any contiguous
# block of comment lines (// ... continuation lines) and Rust attribute lines
# (#[...]), stopping only when it hits a blank line OR a non-comment/non-attribute
# code line. A `// SAFETY:` (or `/// SAFETY:`) anywhere in that contiguous
# preceding block satisfies the requirement. This correctly handles:
#   - Multi-line SAFETY comment blocks of arbitrary length (e.g. the 6-line
#     readdir SAFETY note in fs.rs).
#   - A `#[cfg(...)]` attribute between the SAFETY comment and `unsafe {`
#     (used at the fdatasync/fsync inline blocks).
# A code line (or blank line) terminates the search — if code intervenes
# between a SAFETY comment and the `unsafe {`, a SAFETY comment must be added
# immediately above the `unsafe {`.
#
# Scope: src/fuse/*.rs ONLY (not the full workspace).
# Per memory feedback_no_find_root we never walk filesystem root.
#
# Exit codes:
#   0 = pass (every executable unsafe { block in src/fuse/ has a SAFETY comment)
#   1 = fail (one or more blocks missing SAFETY comment)

# `set -u` only — `set -e` is DELIBERATELY omitted (do not "fix" by adding it).
# This gate's control flow relies on `grep -q` returning exit 1 as a normal
# "pattern not found" signal (e.g. a line is not an attribute, not a SAFETY
# comment). Under `set -e` those expected non-matches would abort the script
# mid-scan and silently break the gate. `set -u` is kept to catch genuine
# unset-variable typos.
set -u

# Configurable: top-level scan directory relative to CWD (project root).
FUSE_DIR="src/fuse"

if [ ! -d "$FUSE_DIR" ]; then
    echo "ERROR: $FUSE_DIR not found in CWD ($(pwd)) — run from project root" >&2
    exit 1
fi

PASSED=0
FAILED=0
declare -a FAIL_MSGS=()

# Process each .rs file in src/fuse/
for f in "$FUSE_DIR"/*.rs; do
    [ -f "$f" ] || continue

    # Read the file into an array of lines (0-indexed, line N = index N-1).
    mapfile -t LINES < "$f"
    total="${#LINES[@]}"

    # Block-comment state tracker (CR-02): true while the scanner is inside an
    # open `/* … */` block. Lines inside a block comment are prose and are never
    # treated as `unsafe {` blocks — this lets us distinguish block-comment
    # continuation lines (which legitimately start with `*`) from a Rust
    # deref-assign statement (`*ptr = unsafe { … };`) that ALSO starts with `*`
    # but is real code and MUST be scanned for a SAFETY comment. The previous
    # blanket "skip any line starting with *" filter created a latent
    # false-negative: a single-line `*p = unsafe {…};` would slip the gate.
    in_block_comment=0

    for ((i = 0; i < total; i++)); do
        line="${LINES[$i]}"

        # Strip leading whitespace then inspect the first chars.
        stripped="${line#"${line%%[! ]*}"}"   # leading-whitespace trim (handles empty line)

        # If we are inside an open block comment, this whole line is prose:
        # skip it, but first update state if it closes the comment (`*/`).
        if [ "$in_block_comment" -eq 1 ]; then
            case "$line" in
                *"*/"*) in_block_comment=0 ;;
            esac
            continue
        fi

        # Skip whole-line single-line comment / rustdoc lines FIRST — these may
        # contain `unsafe {` in prose (e.g. fs.rs module-level //! rustdoc lines
        # 3 and 8) and may also contain a literal `/*` in prose (e.g. the
        # `.git/*` glob in a `// Block writes …` comment) that must NOT be
        # mistaken for a block-comment opener. Doing this before the `/*`
        # detection below prevents that false block-comment entry.
        case "$stripped" in
            "//"*) continue ;;
        esac

        # Block-comment opener detection operates on the portion of the line
        # BEFORE any trailing `//` line comment, so a `/*` that appears inside a
        # trailing `// … /* …` comment is not treated as a real block-comment
        # opener. (No such case exists in src/fuse/ today, but this keeps the
        # heuristic honest.)
        code_part="${line%%//*}"
        case "$code_part" in
            *"/*"*)
                case "$code_part" in
                    *"/*"*"*/"*) : ;;          # opened and closed on one line — stays outside
                    *) in_block_comment=1 ;;    # opened, not closed — enter block-comment state
                esac
                continue
                ;;
        esac

        # Check for `unsafe {` (excluding `unsafe fn`, `unsafe trait`, `unsafe impl`).
        # We require `unsafe` followed by optional spaces and `{`.
        if echo "$line" | grep -qE 'unsafe[[:space:]]*\{'; then
            # Exclude declarations: unsafe fn ..., unsafe trait ..., unsafe impl ...
            if echo "$line" | grep -qE 'unsafe[[:space:]]+(fn|trait|impl)[[:space:]]'; then
                continue
            fi

            lineno=$((i + 1))   # 1-based for human-readable output

            # Walk upward through the contiguous preceding comment/attribute block.
            # Stop if we hit:
            #   - A blank line (empty or whitespace-only), OR
            #   - A non-comment, non-attribute code line.
            # Attribute lines (#[...]) and comment continuation lines are transparent.
            # If any line in the block contains "SAFETY:", the block is documented.
            found_safety=0
            j=$((i - 1))

            while [ "$j" -ge 0 ]; do
                above="${LINES[$j]}"
                above_stripped="${above#"${above%%[! ]*}"}"

                # Blank line — stop searching.
                if [ -z "$above_stripped" ]; then
                    break
                fi

                # Rust attribute line (#[...]) — transparent, keep searching.
                if echo "$above_stripped" | grep -qE '^#\['; then
                    j=$((j - 1))
                    continue
                fi

                # Comment / rustdoc line — check for SAFETY:, then keep searching.
                case "$above_stripped" in
                    "//"*)
                        if echo "$above_stripped" | grep -qE '^//+[[:space:]]*SAFETY:'; then
                            found_safety=1
                            break
                        fi
                        # Continuation comment line — keep searching upward.
                        j=$((j - 1))
                        continue
                        ;;
                    "/*"*|"*/"*|"* "*|"*"$'\t'*)
                        # Genuine block-comment opener/continuation (`/* …`, `*/`,
                        # or `* `/`*<tab>` prose). A bare leading `*` that is a Rust
                        # deref-assign (`*p = unsafe {…};`) is intentionally NOT
                        # matched here — it falls through to the code-line `break`
                        # below so a deref-assign above an `unsafe {` terminates the
                        # upward scan instead of being transparently skipped.
                        if echo "$above_stripped" | grep -qE 'SAFETY:'; then
                            found_safety=1
                            break
                        fi
                        j=$((j - 1))
                        continue
                        ;;
                esac

                # Non-blank, non-comment, non-attribute code line — stop searching.
                break
            done

            if [ "$found_safety" -eq 1 ]; then
                PASSED=$((PASSED + 1))
            else
                FAILED=$((FAILED + 1))
                FAIL_MSGS+=("FAIL: $f:$lineno: unsafe { block missing // SAFETY: comment in contiguous block above")
            fi
        fi
    done
done

echo
echo "fuse unsafe SAFETY-comment gate: Passed=$PASSED Failed=$FAILED"

if [ "$FAILED" -gt 0 ]; then
    echo
    printf '%s\n' "${FAIL_MSGS[@]}"
    exit 1
fi
exit 0
