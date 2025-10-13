#!/bin/bash
# Build SSS for RHEL 8 using podman/docker

set -e

echo "Building SSS for RHEL 8..."

# Detect container runtime
if command -v podman &> /dev/null; then
    CONTAINER_CMD="podman"
elif command -v docker &> /dev/null; then
    CONTAINER_CMD="docker"
else
    echo "Error: Neither podman nor docker found"
    exit 1
fi

echo "Using: $CONTAINER_CMD"

# Build the container image
echo "Building container image..."
$CONTAINER_CMD build -f Dockerfile.rhel8 -t sss-rhel8-builder .

# Extract the binaries
echo "Extracting binaries..."
CONTAINER_ID=$($CONTAINER_CMD create sss-rhel8-builder)

# Create output directory
mkdir -p dist/rhel8

# Copy binaries
$CONTAINER_CMD cp $CONTAINER_ID:/build/target/release/sss dist/rhel8/
$CONTAINER_CMD cp $CONTAINER_ID:/build/target/release/sss-agent dist/rhel8/ 2>/dev/null || true
$CONTAINER_CMD cp $CONTAINER_ID:/build/target/release/sss-askpass-tty dist/rhel8/ 2>/dev/null || true
$CONTAINER_CMD cp $CONTAINER_ID:/build/target/release/sss-askpass-gui dist/rhel8/ 2>/dev/null || true

# Cleanup
$CONTAINER_CMD rm $CONTAINER_ID

echo ""
echo "Build complete! Binaries are in: dist/rhel8/"
echo ""
ls -lh dist/rhel8/

echo ""
echo "Verify compatibility:"
echo "  file dist/rhel8/sss"
echo "  ldd dist/rhel8/sss"
