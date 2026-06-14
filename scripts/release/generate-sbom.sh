#!/usr/bin/env bash
# Phase 25 / BUILD-03 — CycloneDX SBOM generation across the 6-cell release matrix.
#
# Produces one .cdx.json SBOM file per (platform × feature-arm) combination,
# so the dep tree per release artefact is explicit and tooling-ingestible
# (e.g. dependency-track, grype, syft can read CycloneDX 1.4+).
#
# Matrix (per .planning/REQUIREMENTS.md BUILD-03 + Phase 47 VNET-05):
#   platforms:    linux-x86_64, linux-aarch64, macos-arm64
#   feature arms: default (classic crypto only), hybrid (classic + PQ X448 + ML-DSA-65),
#                 vault (Vault secret resolver — ureq+rustls+ring, no tokio)
#   = 9 SBOM files in dist/sbom/
#
# Naming:  sss-<platform>-<arm>.cdx.json
#   sss-linux-x86_64-default.cdx.json
#   sss-linux-x86_64-hybrid.cdx.json
#   sss-linux-x86_64-vault.cdx.json
#   sss-linux-aarch64-default.cdx.json
#   sss-linux-aarch64-hybrid.cdx.json
#   sss-linux-aarch64-vault.cdx.json
#   sss-macos-arm64-default.cdx.json
#   sss-macos-arm64-hybrid.cdx.json
#   sss-macos-arm64-vault.cdx.json
#
# Notes:
#   - cargo-cyclonedx 0.5.9+ is the toolchain pin per REQUIREMENTS.md BUILD-03.
#   - cargo-cyclonedx walks `cargo metadata --target=<TARGET>` so the SBOM
#     reflects the actual dep set for that target+features combination. trelis
#     ONLY appears in the `--features hybrid` SBOMs (hybrid feature is the
#     only path that pulls trelis-* in); this satisfies the BUILD-03
#     acceptance criterion "explicit on trelis inclusion under hybrid".
#   - The 6 .cdx.json files are uploaded alongside binary release artefacts
#     to the distribution endpoint; `latest.json` schema extension
#     (Phase 25 BUILD-03 second clause) advertises each SBOM path.
#   - cargo-cyclonedx is invoked locally on the milestone build host; release
#     CI (.github/workflows/release.yml) integrates this script per-cell.
#
# Usage:  bash scripts/release/generate-sbom.sh
#   Requires: cargo-cyclonedx in PATH (cargo install --locked cargo-cyclonedx)
#   Outputs:  dist/sbom/sss-*.cdx.json (6 files)

set -euo pipefail

# Resolve repo root from script location
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$REPO_ROOT"

# Tool preflight: cargo-cyclonedx >= 0.5.9 required per REQUIREMENTS.md BUILD-03.
if ! command -v cargo-cyclonedx &> /dev/null; then
    echo "Error: cargo-cyclonedx not found in PATH. Install with:"
    echo "  cargo install --locked cargo-cyclonedx"
    exit 1
fi

CYCLONEDX_VERSION=$(cargo cyclonedx --version 2>&1 | awk '{print $2}')
echo "==> cargo-cyclonedx version: $CYCLONEDX_VERSION"

OUTPUT_DIR="dist/sbom"
mkdir -p "$OUTPUT_DIR"

# Matrix definition. Each (platform, target, features) tuple produces one SBOM.
#
# Phase 47 / VNET-05 / T-47-SC4: vault arm added so the vault dep surface
# (ureq 3.3.0, rustls 0.23.40, ring 0.17.14, rustls-webpki 0.103.13, and 8
# transitive crates) is enumerated in release artefacts. vault is a blocking
# HTTP client for HashiCorp Vault; it does NOT pull tokio. The 3 vault SBOMs
# are: linux-x86_64-vault, linux-aarch64-vault, macos-arm64-vault.
declare -a CELLS=(
    "linux-x86_64:x86_64-unknown-linux-gnu:default:"
    "linux-x86_64:x86_64-unknown-linux-gnu:hybrid:hybrid"
    "linux-x86_64:x86_64-unknown-linux-gnu:vault:vault"
    "linux-aarch64:aarch64-unknown-linux-gnu:default:"
    "linux-aarch64:aarch64-unknown-linux-gnu:hybrid:hybrid"
    "linux-aarch64:aarch64-unknown-linux-gnu:vault:vault"
    "macos-arm64:aarch64-apple-darwin:default:"
    "macos-arm64:aarch64-apple-darwin:hybrid:hybrid"
    "macos-arm64:aarch64-apple-darwin:vault:vault"
)

echo "==> Generating $((${#CELLS[@]})) CycloneDX SBOM files in $OUTPUT_DIR/"
echo

for cell in "${CELLS[@]}"; do
    IFS=':' read -r PLATFORM TARGET ARM FEATURES <<< "$cell"
    OUTPUT_FILE="$OUTPUT_DIR/sss-${PLATFORM}-${ARM}.cdx.json"
    echo "  ----------------------------------------"
    echo "  Cell: $PLATFORM / $ARM (target=$TARGET)"
    echo "  Output: $OUTPUT_FILE"

    # cargo-cyclonedx writes to default location (<crate>/<crate>.cdx.json);
    # we move it to the predictable matrix-cell name afterwards.
    FEATURE_FLAG=""
    if [ -n "$FEATURES" ]; then
        FEATURE_FLAG="--features $FEATURES"
    else
        FEATURE_FLAG="--no-default-features"
    fi

    # --describe crate gives one SBOM per crate (we want one per workspace).
    # --target restricts cargo metadata to the specified target's dep resolution.
    cargo cyclonedx \
        --format json \
        --describe crate \
        --target "$TARGET" \
        $FEATURE_FLAG \
        -q

    # Move the produced sss.cdx.json (or workspace.cdx.json) to the matrix-cell name.
    if [ -f "sss.cdx.json" ]; then
        mv "sss.cdx.json" "$OUTPUT_FILE"
    elif [ -f "${PLATFORM}-${ARM}.cdx.json" ]; then
        mv "${PLATFORM}-${ARM}.cdx.json" "$OUTPUT_FILE"
    else
        # Fallback: search for the most recent .cdx.json file
        FOUND=$(find . -maxdepth 2 -name '*.cdx.json' -newer "$OUTPUT_DIR" 2>/dev/null | head -1)
        if [ -n "$FOUND" ] && [ -f "$FOUND" ]; then
            mv "$FOUND" "$OUTPUT_FILE"
        else
            echo "  ERROR: cargo-cyclonedx did not produce expected output"
            exit 1
        fi
    fi

    # Quick sanity-check: ensure the SBOM is non-empty + valid JSON
    if ! [ -s "$OUTPUT_FILE" ]; then
        echo "  ERROR: $OUTPUT_FILE is empty"
        exit 1
    fi
    if ! jq -e . "$OUTPUT_FILE" > /dev/null 2>&1; then
        echo "  ERROR: $OUTPUT_FILE is not valid JSON"
        exit 1
    fi

    COMPONENT_COUNT=$(jq '.components | length' "$OUTPUT_FILE" 2>/dev/null || echo "0")
    echo "  Components: $COMPONENT_COUNT"
done

echo
echo "==> Generation complete: $((${#CELLS[@]})) SBOM files in $OUTPUT_DIR/"
ls -la "$OUTPUT_DIR/"

# Optional: emit a manifest listing the produced files for latest.json schema
# extension (Phase 25 BUILD-03 second clause). Format mirrors how the existing
# latest.json advertises binary download URLs.
MANIFEST="$OUTPUT_DIR/manifest.json"
{
    echo '{'
    echo '  "schema_version": "v2.3-sbom-1",'
    echo '  "generated_at": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'",'
    echo '  "cyclonedx_version": "'$CYCLONEDX_VERSION'",'
    echo '  "sboms": ['
    FIRST=1
    for cell in "${CELLS[@]}"; do
        IFS=':' read -r PLATFORM TARGET ARM FEATURES <<< "$cell"
        OUTPUT_FILE="sss-${PLATFORM}-${ARM}.cdx.json"
        if [ "$FIRST" = "1" ]; then FIRST=0; else echo ','; fi
        printf '    { "platform": "%s", "feature_arm": "%s", "target": "%s", "path": "%s" }' \
            "$PLATFORM" "$ARM" "$TARGET" "$OUTPUT_FILE"
    done
    echo
    echo '  ]'
    echo '}'
} > "$MANIFEST"
echo "==> Manifest: $MANIFEST"
