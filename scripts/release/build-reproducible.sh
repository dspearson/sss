#!/usr/bin/env bash
# Phase 26 / BUILD-02 — reproducible-build wrapper.
#
# Produces a deterministic sss release binary that should be SHA-256
# identical when built from the same git commit + Cargo.lock on two
# different hosts within the same target cell.
#
# The April 2026 reproducible-builds.org "Rust" report identifies four
# determinism sources that must be controlled:
#   1. Embedded build timestamps    → SOURCE_DATE_EPOCH (cargo + libsodium honour it)
#   2. Embedded source paths        → --remap-path-prefix (RUSTFLAGS)
#   3. Toolchain version drift      → cargo --locked (against committed Cargo.lock)
#   4. Parallel-compilation         → CARGO_BUILD_JOBS=1 deterministic order
#                                     (the default is non-determinism for some IR-merge passes)
#
# This script controls all four. The output binary path is printed at
# exit so the caller can sha256sum + diff against a sibling-host build.
#
# Usage:
#   scripts/release/build-reproducible.sh [--features <args>] [--target <triple>]
#
# Example:
#   scripts/release/build-reproducible.sh --features hybrid,fuse
#   scripts/release/build-reproducible.sh --target aarch64-unknown-linux-gnu --features hybrid
#
# Verification (2-host diff per BUILD-05 acceptance criterion):
#   # On arm64-builder (Linux aarch64):
#   scripts/release/build-reproducible.sh --features hybrid
#   sha256sum target/release/sss
#   # On mac (macOS arm64):
#   scripts/release/build-reproducible.sh --features hybrid
#   sha256sum target/release/sss
#   # The two checksums MUST be identical (or any divergence MUST be
#   # documented as accepted-with-rationale in
#   # .planning/phases/26-*/REPRODUCIBLE-BUILD-TRANSCRIPT.md).

set -euo pipefail

# Resolve repo root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$REPO_ROOT"

# ─── Pre-flight: Cargo.lock must exist (BUILD-01 / D-V23-01 compliance) ───
if [ ! -f "Cargo.lock" ]; then
    echo "Error: Cargo.lock not found at repo root."
    echo "Phase 26 BUILD-01 requires Cargo.lock to be committed (D-V23-01)."
    echo "Run cargo build once to generate it, then commit."
    exit 1
fi

# ─── Determinism env-var #1: SOURCE_DATE_EPOCH ───
# If unset, default to the committer date of HEAD (deterministic per commit).
# Both cargo (rustc -Cembed-bitcode) and libsodium-sys's build.rs honour this.
if [ -z "${SOURCE_DATE_EPOCH:-}" ]; then
    SOURCE_DATE_EPOCH=$(git log -1 --format=%ct 2>/dev/null || date +%s)
fi
export SOURCE_DATE_EPOCH
echo "==> SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH"

# ─── Determinism env-var #2: --remap-path-prefix ───
# Strip the absolute repo path AND the cargo registry path from embedded
# source-location strings. Two remap-prefixes appended via RUSTFLAGS;
# the order matters (longest-match first so .cargo/registry is found
# before the broader $HOME).
HOME_PREFIX="${HOME:-}"
REPO_REMAP="--remap-path-prefix=${REPO_ROOT}=sss-src"
CARGO_REMAP=""
if [ -n "$HOME_PREFIX" ] && [ -d "$HOME_PREFIX/.cargo/registry" ]; then
    CARGO_REMAP="--remap-path-prefix=$HOME_PREFIX/.cargo/registry=cargo-registry"
fi
RUSTC_BOOTSTRAP_REMAP=""
if [ -n "$HOME_PREFIX" ] && [ -d "$HOME_PREFIX/.rustup/toolchains" ]; then
    RUSTC_BOOTSTRAP_REMAP="--remap-path-prefix=$HOME_PREFIX/.rustup/toolchains=rust-toolchain"
fi

EXISTING_RUSTFLAGS="${RUSTFLAGS:-}"
RUSTFLAGS="$REPO_REMAP $CARGO_REMAP $RUSTC_BOOTSTRAP_REMAP $EXISTING_RUSTFLAGS"
# Strip leading/trailing whitespace
RUSTFLAGS="$(echo "$RUSTFLAGS" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')"
export RUSTFLAGS
echo "==> RUSTFLAGS=$RUSTFLAGS"

# ─── Determinism env-var #3: deterministic job count ───
# Cargo's default is parallel (rayon). Some LLVM IR-merge passes have
# non-deterministic output ordering when parallel; serial compilation
# is byte-identical at the cost of wall-clock time. For release builds
# this trade-off is correct.
export CARGO_BUILD_JOBS=1
echo "==> CARGO_BUILD_JOBS=1 (serial for determinism)"

# ─── Determinism env-var #4: locale + timezone ───
# Some build scripts emit locale-specific strings (e.g. month names);
# pinning C.UTF-8 + UTC eliminates that drift.
export LC_ALL=C.UTF-8
export TZ=UTC

# ─── Build ───
# Always --locked so cargo refuses to resolve any version not pinned by
# Cargo.lock. This is the load-bearing flag for cross-host determinism.
echo "==> cargo build --release --locked $*"
cargo build --release --locked "$@"

# ─── Locate the output binary + report ───
TARGET_ARG=""
prev=""
for arg in "$@"; do
    if [ "$prev" = "--target" ]; then
        TARGET_ARG="$arg"
    fi
    prev="$arg"
done
unset prev

if [ -n "$TARGET_ARG" ]; then
    OUTPUT="target/$TARGET_ARG/release/sss"
else
    OUTPUT="target/release/sss"
fi

if [ ! -f "$OUTPUT" ]; then
    echo "Error: expected binary $OUTPUT not found post-build"
    exit 1
fi

echo
echo "==> Build successful. Output binary:"
echo "    $OUTPUT"
echo
echo "==> SHA-256:"
if command -v sha256sum &> /dev/null; then
    sha256sum "$OUTPUT"
elif command -v shasum &> /dev/null; then
    shasum -a 256 "$OUTPUT"
else
    echo "    (no sha256sum or shasum available)"
fi
echo
echo "==> For BUILD-05 2-host diff verification: run this same script"
echo "    with the same flags on the sibling host (arm64-builder / macos-builder), then"
echo "    compare the two SHA-256 values. Identical = reproducible; divergent"
echo "    = document the divergence in"
echo "    .planning/phases/26-reproducible-builds-vendoring-policy/REPRODUCIBLE-BUILD-TRANSCRIPT.md"
