#!/usr/bin/env bash
# Phase 25 / SIGN-01 — release-artefact signing keypair generation.
#
# Per locked decision D-V23-04 (REQUIREMENTS.md):
#   "Distinct keypair + distinct domain-separation bytes
#    (b\"sss-release-artifact-sig-v1\"); sigstore/cosign keyless preferred
#    while AUDIT-01 open."
#
# The release-signing keypair is a separate concern from the envelope-sig
# Ed448 + ML-DSA-65 material used inside sealed envelopes (Phase 21 baseline).
# Key reuse across security domains is an auditor red flag (PITFALLS.md
# Pitfall 14) and is explicitly avoided by this script.
#
# Primary signing flow (v2.3): sigstore/cosign keyless via GitHub Actions
# OIDC (Phase 25 SIGN-02, .github/workflows/release.yml). No long-lived
# signing key in the public release path; ephemeral Fulcio cert + Rekor
# transparency log per release.
#
# Fallback signing flow (this script): offline Ed25519 keypair for
# environments where sigstore is unavailable OR for cross-verification
# of the cosign signature. The keypair is generated ONCE per major
# version (v2.3 -> v3.0 etc.) and the public key is committed to the
# repo under /docs/release-keys/; the private key is stored offline
# in the release operator's HSM or password-protected vault.
#
# Domain separation: the bytes b"sss-release-artifact-sig-v1" appear in
# the signature pre-image (or the "context" field of the chosen signature
# scheme) — distinct from the envelope-sig pre-image
# b"sss-envelope-sig-v1" (Phase 19 lock) so a release-signing key cannot
# be cross-used to forge envelope signatures and vice versa.
#
# Usage:
#   bash scripts/release/generate-release-key.sh /path/to/output/dir
#
# Produces:
#   <output>/sss-release-sig-v1.key    (Ed25519 private, 0600, KEEP OFFLINE)
#   <output>/sss-release-sig-v1.pub    (Ed25519 public, 0644, commit to docs/release-keys/)
#   <output>/sss-release-sig-v1.notes  (generation metadata + domain sep tag)
#
# Verification:
#   The public key file embeds the comment line
#   "# domain-separation: sss-release-artifact-sig-v1"
#   so an auditor reading docs/release-keys/sss-release-sig-v1.pub
#   sees the distinct domain tag without external context.

set -euo pipefail

DOMAIN_SEP="sss-release-artifact-sig-v1"
KEY_NAME="sss-release-sig-v1"

if [ $# -lt 1 ]; then
    echo "Usage: $0 <output-dir>"
    echo
    echo "Output directory MUST be on encrypted offline storage (HSM, hardware"
    echo "token, or password-protected USB). DO NOT generate keys into the repo"
    echo "working tree — only the .pub file gets committed (to docs/release-keys/)."
    exit 1
fi

OUT_DIR="$1"

if [ ! -d "$OUT_DIR" ]; then
    echo "Error: output directory $OUT_DIR does not exist"
    exit 1
fi

PRIV="$OUT_DIR/$KEY_NAME.key"
PUB="$OUT_DIR/$KEY_NAME.pub"
NOTES="$OUT_DIR/$KEY_NAME.notes"

if [ -f "$PRIV" ] || [ -f "$PUB" ]; then
    echo "Error: keypair files already exist in $OUT_DIR/"
    echo "  $PRIV"
    echo "  $PUB"
    echo
    echo "Refusing to overwrite. Move existing keys to an archive location"
    echo "before generating a new pair."
    exit 1
fi

# Use openssl for Ed25519 generation; ubiquitous and audit-defensible.
if ! command -v openssl &> /dev/null; then
    echo "Error: openssl not found in PATH"
    exit 1
fi

OPENSSL_VERSION=$(openssl version 2>&1)
echo "==> Using $OPENSSL_VERSION"
echo "==> Domain separation tag: $DOMAIN_SEP"
echo

# Generate Ed25519 keypair. PKCS#8 PEM format for the private key
# (interoperable with sodium, libsodium, signify, age, etc.).
#
# REM-44: close the create→chmod permission window by setting umask 0077
# before openssl genpkey so the private key is born mode 0600 (no other
# user can read it even in the brief moment before chmod 0600 runs).
# The prior umask is captured and restored before the public-key write so
# that the public key is created at the normal umask (explicit chmod 0644
# below provides the required final permission regardless).
OLD_UMASK=$(umask)
umask 0077                                   # private key born 0600
openssl genpkey -algorithm ED25519 -out "$PRIV"
chmod 0600 "$PRIV"                           # defence-in-depth (keep)
umask "$OLD_UMASK"                           # restore before pubkey write

# Extract the public key
openssl pkey -in "$PRIV" -pubout -out "$PUB.tmp"
chmod 0644 "$PUB.tmp"

# Prefix the public key with the domain-separation comment so an auditor
# reading the .pub file sees the explicit cross-domain protection.
{
    echo "# sss release-artefact signing public key"
    echo "# generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "# openssl version: $OPENSSL_VERSION"
    echo "# domain-separation: $DOMAIN_SEP"
    echo "# usage: see docs/RELEASE.md § Release Signing"
    echo "# verification: openssl pkeyutl -verify -pubin -inkey THIS_FILE -sigfile X.sig -in X"
    echo "#"
    cat "$PUB.tmp"
} > "$PUB"
rm -f "$PUB.tmp"

# Generation metadata file for the audit trail
{
    echo "Release-Signing Keypair Generation Metadata"
    echo "==========================================="
    echo
    echo "Key name:           $KEY_NAME"
    echo "Domain separation:  $DOMAIN_SEP"
    echo "Algorithm:          Ed25519 (PKCS#8 PEM)"
    echo "Generated:          $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "Generated by:       ${USER:-unknown}@$(hostname -f 2>/dev/null || hostname)"
    echo "OpenSSL version:    $OPENSSL_VERSION"
    echo
    echo "Storage policy:"
    echo "  - Private key:    THIS DIRECTORY must be on encrypted offline"
    echo "                    storage. Never copy $KEY_NAME.key to a network"
    echo "                    location, a cloud sync directory, or any host"
    echo "                    that is not air-gapped from the public internet."
    echo
    echo "  - Public key:     Commit $KEY_NAME.pub to docs/release-keys/ in"
    echo "                    the sss git repo. The committed file embeds the"
    echo "                    domain-separation tag in the comment header so"
    echo "                    auditors reading the file know which security"
    echo "                    domain it belongs to."
    echo
    echo "  - Notes file:     This $KEY_NAME.notes file stays alongside the"
    echo "                    private key. It is the audit trail for who"
    echo "                    generated the key, when, and on what host."
    echo
    echo "Domain separation guarantee:"
    echo "  This keypair signs release artefacts only. The envelope-sig"
    echo "  keypair (Ed448 + ML-DSA-65, Phase 19 baseline) signs sealed"
    echo "  envelope payloads. The two security domains are kept separate"
    echo "  by the distinct domain-separation tags AND by using a different"
    echo "  signature algorithm (Ed25519 here vs Ed448+ML-DSA-65 for envelopes)."
    echo "  Reuse of either key in the other domain MUST be flagged as a"
    echo "  Pitfall 14 (key-reuse-across-security-domains) finding."
    echo
    echo "Verification:"
    echo "  Verify a signature with:"
    echo "    openssl pkeyutl -verify -pubin -inkey docs/release-keys/$KEY_NAME.pub \\"
    echo "                    -sigfile <artefact>.sig -in <artefact>"
    echo
    echo "Cosign keyless coexistence:"
    echo "  v2.3 SIGN-02 uses sigstore/cosign keyless via GitHub Actions OIDC"
    echo "  as the PRIMARY signing flow. This Ed25519 keypair is the OFFLINE"
    echo "  FALLBACK for environments where sigstore is unavailable OR for"
    echo "  cross-verification of cosign signatures. Both signatures may"
    echo "  appear on a release artefact; verification of EITHER is sufficient."
} > "$NOTES"
chmod 0644 "$NOTES"

echo "==> Generated:"
echo "    Private key:    $PRIV  (mode 0600)"
echo "    Public key:     $PUB  (mode 0644)"
echo "    Notes:          $NOTES"
echo
echo "==> Next steps:"
echo "    1. Move $PRIV to encrypted offline storage (HSM or air-gapped USB)"
echo "    2. Copy $PUB to docs/release-keys/ in the sss repo and commit"
echo "    3. Record the public-key fingerprint in docs/RELEASE.md:"
echo "       openssl pkey -pubin -in $PUB -text -noout | head -3"
echo "    4. Keep $NOTES alongside the private key as the audit trail"
echo
echo "==> Public-key fingerprint:"
openssl pkey -pubin -in "$PUB" -outform DER 2>/dev/null \
    | openssl dgst -sha256 -hex \
    | awk '{print "    SHA-256:", $2}'
