#!/usr/bin/env bash
# Rsync project to Mac, build statically, and rsync binary back
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MAC_HOST="mac"
MAC_DIR="sss"

echo "==> Syncing project to Mac..."
rsync -avz --delete \
  --exclude 'target/' \
  --exclude '.git/' \
  --exclude '*.o' \
  --exclude '*.dylib' \
  --exclude '*.so' \
  "$SCRIPT_DIR/" "$MAC_HOST:$MAC_DIR/"

echo ""
echo "==> Building on Mac..."
ssh "$MAC_HOST" "cd $MAC_DIR && cargo clean && ./build-macos-static.sh"

echo ""
echo "==> Syncing binary back..."
mkdir -p "$SCRIPT_DIR/target/aarch64-apple-darwin/release"
rsync -avz "$MAC_HOST:$MAC_DIR/target/aarch64-apple-darwin/release/sss" \
  "$SCRIPT_DIR/target/aarch64-apple-darwin/release/"

echo ""
echo "==> Build complete!"
echo "==> Binary: target/aarch64-apple-darwin/release/sss"
file "$SCRIPT_DIR/target/aarch64-apple-darwin/release/sss"
ls -lh "$SCRIPT_DIR/target/aarch64-apple-darwin/release/sss"
