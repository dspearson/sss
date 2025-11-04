#!/usr/bin/env bash
# Run FUSE integration tests
#
# Usage: ./scripts/run-fuse-tests.sh [test_name]
#
# Requirements:
# - FUSE kernel module loaded
# - User has permission to use FUSE
# - 'ed' text editor installed

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if FUSE is available
check_fuse() {
    echo "Checking FUSE availability..."

    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        # Linux: Check for fusermount
        if ! command -v fusermount &> /dev/null; then
            echo -e "${RED}ERROR: fusermount not found${NC}"
            echo "Install FUSE: sudo apt-get install fuse (Debian/Ubuntu) or sudo yum install fuse (RHEL/CentOS)"
            exit 1
        fi

        # Check if FUSE module is loaded
        if ! lsmod | grep -q fuse; then
            echo -e "${YELLOW}WARNING: FUSE module not loaded${NC}"
            echo "Try: sudo modprobe fuse"
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS: Check for macFUSE
        if [[ ! -d "/Library/Filesystems/macfuse.fs" ]]; then
            echo -e "${RED}ERROR: macFUSE not installed${NC}"
            echo "Install macFUSE: brew install --cask macfuse"
            echo "Or download from: https://osxfuse.github.io/"
            exit 1
        fi
    else
        echo -e "${YELLOW}WARNING: Unknown OS type: $OSTYPE${NC}"
    fi

    echo -e "${GREEN}✓ FUSE is available${NC}"
}

# Check if ed is installed
check_ed() {
    echo "Checking for ed text editor..."
    if ! command -v ed &> /dev/null; then
        echo -e "${RED}ERROR: ed text editor not found${NC}"
        echo "Install ed: sudo apt-get install ed (Debian/Ubuntu)"
        exit 1
    fi
    echo -e "${GREEN}✓ ed is available${NC}"
}

# Build the project
build_project() {
    echo "Building SSS with FUSE support..."

    if [[ "$OSTYPE" == "darwin"* ]]; then
        cargo build --features macfuse --tests
    else
        cargo build --features fuse --tests
    fi

    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✓ Build successful${NC}"
    else
        echo -e "${RED}ERROR: Build failed${NC}"
        exit 1
    fi
}

# Run the tests
run_tests() {
    local test_name="${1:-}"

    echo "Running FUSE integration tests..."
    echo "NOTE: These tests will:"
    echo "  - Create temporary directories"
    echo "  - Mount FUSE filesystems"
    echo "  - Edit files programmatically"
    echo "  - Unmount and cleanup"
    echo ""

    if [[ "$OSTYPE" == "darwin"* ]]; then
        feature_flag="macfuse"
    else
        feature_flag="fuse"
    fi

    if [ -n "$test_name" ]; then
        echo "Running specific test: $test_name"
        cargo test --features "$feature_flag" --test fuse_integration "$test_name" -- --ignored --nocapture
    else
        echo "Running all FUSE integration tests"
        cargo test --features "$feature_flag" --test fuse_integration -- --ignored --nocapture
    fi

    local exit_code=$?

    echo ""
    if [ $exit_code -eq 0 ]; then
        echo -e "${GREEN}✓ All tests passed${NC}"
    else
        echo -e "${RED}✗ Some tests failed${NC}"

        # Cleanup any lingering mounts
        echo "Checking for lingering FUSE mounts..."
        if [[ "$OSTYPE" == "linux-gnu"* ]]; then
            mount | grep "type fuse" || true
        elif [[ "$OSTYPE" == "darwin"* ]]; then
            mount | grep "macfuse" || true
        fi
    fi

    return $exit_code
}

# Main
main() {
    echo "========================================"
    echo "  SSS FUSE Integration Test Runner"
    echo "========================================"
    echo ""

    check_fuse
    check_ed
    build_project
    echo ""
    run_tests "$@"
}

main "$@"
