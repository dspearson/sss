#!/usr/bin/env bash
# Rsync project to ARM64 Linux machine, build statically, and rsync binary back
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REMOTE_HOST="keflavik"
REMOTE_DIR="sss"

echo "==> Syncing project to $REMOTE_HOST..."
rsync -avz --delete \
  --exclude 'target/' \
  --exclude '.git/' \
  --exclude '*.o' \
  --exclude 'cross/' \
  "$SCRIPT_DIR/" "$REMOTE_HOST:$REMOTE_DIR/"

echo ""
echo "==> Building on $REMOTE_HOST (ARM64 Linux)..."
ssh "$REMOTE_HOST" "cd $REMOTE_DIR && bash -l -c '
set -e

# Install Rust if not present
if ! command -v cargo &> /dev/null; then
    echo \"==> Installing Rust...\"
    curl --proto \"=https\" --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source \$HOME/.cargo/env
fi

# Install libsodium if not present
if ! pkg-config --exists libsodium; then
    echo \"==> Installing libsodium...\"
    sudo apt-get update
    sudo apt-get install -y libsodium-dev pkg-config
fi

# Build release binary
echo \"==> Building release binary for ARM64 Linux...\"
source \$HOME/.cargo/env
cargo build --release

echo \"\"
echo \"==> Build successful!\"
echo \"==> Binary: target/release/sss\"
file target/release/sss
'"

echo ""
echo "==> Syncing binary back..."
mkdir -p "$SCRIPT_DIR/target/aarch64-unknown-linux-gnu/release"
rsync -avz "$REMOTE_HOST:$REMOTE_DIR/target/release/sss" \
  "$SCRIPT_DIR/target/aarch64-unknown-linux-gnu/release/"

echo ""
echo "==> Build complete!"
echo "==> Binary: target/aarch64-unknown-linux-gnu/release/sss"
file "$SCRIPT_DIR/target/aarch64-unknown-linux-gnu/release/sss"
