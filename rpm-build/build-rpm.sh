#!/usr/bin/env bash
# Build RPM packages for RHEL 8, RHEL 9, and RHEL 10
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
VERSION="1.3.0"
NAME="sss"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $*"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $*"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*"
}

usage() {
    cat <<EOF
Usage: $0 [OPTIONS] TARGET

Build RPM packages for SSS

TARGETS:
    rhel8       Build for RHEL 8
    rhel9       Build for RHEL 9
    rhel10      Build for RHEL 10
    fedora42    Build for Fedora 42
    all         Build for RHEL 8, 9, 10, and Fedora 42

OPTIONS:
    -h, --help          Show this help message
    -c, --clean         Clean build artifacts before building
    -n, --no-container  Build locally (requires proper environment)

EXAMPLES:
    $0 rhel8                    # Build for RHEL 8 using podman/docker
    $0 fedora42                 # Build for Fedora 42 using podman/docker
    $0 --clean all              # Clean and build for all versions
    $0 --no-container rhel9     # Build for RHEL 9 locally

REQUIREMENTS:
    - Podman or Docker (unless using --no-container)
    - For local builds: rpmbuild, rust >= 1.70, libsodium-devel

EOF
    exit 0
}

check_container_runtime() {
    # Prefer podman, fall back to docker
    if command -v podman &> /dev/null; then
        CONTAINER_CMD="podman"
    elif command -v docker &> /dev/null; then
        CONTAINER_CMD="docker"
    else
        log_error "Neither podman nor docker is installed or in PATH"
        log_error "Install podman (preferred) or docker, or use --no-container to build locally"
        exit 1
    fi
    log_info "Using container runtime: $CONTAINER_CMD"
}

clean_artifacts() {
    log_info "Cleaning build artifacts..."
    rm -rf "$PROJECT_ROOT/target/release"
    rm -rf "$PROJECT_ROOT/rpm-build/rpmbuild"
    rm -f "$PROJECT_ROOT/rpm-build/"*.rpm
    log_info "Clean complete"
}

create_tarball() {
    log_info "Creating source tarball..."

    local temp_dir=$(mktemp -d)
    local source_dir="$temp_dir/$NAME-$VERSION"

    # Copy source files
    mkdir -p "$source_dir"
    cp -r "$PROJECT_ROOT/src" "$source_dir/"
    cp -r "$PROJECT_ROOT/benches" "$source_dir/"
    cp -r "$PROJECT_ROOT/githooks" "$source_dir/"
    cp -r "$PROJECT_ROOT/vendor" "$source_dir/"
    cp "$PROJECT_ROOT/Cargo.toml" "$source_dir/"
    cp "$PROJECT_ROOT/Cargo.lock" "$source_dir/"
    cp "$PROJECT_ROOT/LICENCE" "$source_dir/"
    cp "$PROJECT_ROOT/README.md" "$source_dir/"

    # Create tarball
    tar -czf "$PROJECT_ROOT/rpm-build/$NAME-$VERSION.tar.gz" -C "$temp_dir" "$NAME-$VERSION"

    # Cleanup
    rm -rf "$temp_dir"

    log_info "Tarball created: $NAME-$VERSION.tar.gz"
}

build_local() {
    local target="$1"

    log_info "Building RPM for $target locally..."

    # Check for rpmbuild
    if ! command -v rpmbuild &> /dev/null; then
        log_error "rpmbuild not found. Install rpm-build package."
        exit 1
    fi

    # Setup rpmbuild directory structure
    local rpmbuild_dir="$PROJECT_ROOT/rpm-build/rpmbuild"
    mkdir -p "$rpmbuild_dir"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}

    # Create tarball if it doesn't exist
    if [ ! -f "$PROJECT_ROOT/rpm-build/$NAME-$VERSION.tar.gz" ]; then
        create_tarball
    fi

    # Copy source tarball and spec file
    cp "$PROJECT_ROOT/rpm-build/$NAME-$VERSION.tar.gz" "$rpmbuild_dir/SOURCES/"
    cp "$PROJECT_ROOT/rpm-build/sss.spec" "$rpmbuild_dir/SPECS/"

    # Build RPM
    rpmbuild -ba \
        --define "_topdir $rpmbuild_dir" \
        --define "dist .el${target#rhel}" \
        "$rpmbuild_dir/SPECS/sss.spec"

    # Copy built RPMs to rpm-build directory
    find "$rpmbuild_dir/RPMS" -name "*.rpm" -exec cp {} "$PROJECT_ROOT/rpm-build/" \;
    find "$rpmbuild_dir/SRPMS" -name "*.rpm" -exec cp {} "$PROJECT_ROOT/rpm-build/" \;

    log_info "RPM build complete for $target"
    log_info "RPMs available in: $PROJECT_ROOT/rpm-build/"
}

build_container() {
    local target="$1"
    local dist_tag=""

    log_info "Building RPM for $target using $CONTAINER_CMD..."

    # Determine base image and dist tag
    local base_image
    case "$target" in
        rhel8)
            base_image="rockylinux:8"
            dist_tag=".el8"
            ;;
        rhel9)
            base_image="rockylinux:9"
            dist_tag=".el9"
            ;;
        rhel10)
            base_image="rockylinux:10"
            dist_tag=".el10"
            ;;
        fedora42)
            base_image="fedora:42"
            dist_tag=".fc42"
            ;;
        *)
            log_error "Unknown target: $target"
            exit 1
            ;;
    esac

    # Create tarball if it doesn't exist
    if [ ! -f "$PROJECT_ROOT/rpm-build/$NAME-$VERSION.tar.gz" ]; then
        create_tarball
    fi

    # Determine if we need epel-release (RHEL/Rocky only, not Fedora)
    local install_epel=""
    if [[ "$target" =~ ^rhel ]]; then
        install_epel="RUN dnf install -y epel-release"
    fi

    # Create Dockerfile
    cat > "$PROJECT_ROOT/rpm-build/Dockerfile.$target" <<DOCKERFILE
FROM $base_image

# Install build dependencies
$install_epel
RUN dnf install -y \\
        rpm-build \\
        rpmdevtools \\
        gcc \\
        libsodium-devel \\
        fuse3 \\
        fuse3-devel \\
        make \\
        wget && \\
    dnf clean all

# Install Rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
ENV PATH="/root/.cargo/bin:\${PATH}"

# Setup build environment
RUN rpmdev-setuptree

WORKDIR /build

# Copy source files
COPY $NAME-$VERSION.tar.gz /root/rpmbuild/SOURCES/
COPY sss.spec /root/rpmbuild/SPECS/

# Build RPM
RUN rpmbuild -ba \\
    --define "dist $dist_tag" \\
    /root/rpmbuild/SPECS/sss.spec

# Copy built RPMs to output
RUN mkdir -p /output && \\
    cp /root/rpmbuild/RPMS/*/*.rpm /output/ && \\
    cp /root/rpmbuild/SRPMS/*.rpm /output/

CMD ["/bin/bash"]
DOCKERFILE

    # Build container image and extract RPMs
    log_info "Building container image..."
    $CONTAINER_CMD build \
        --no-cache \
        -f "$PROJECT_ROOT/rpm-build/Dockerfile.$target" \
        -t "sss-rpm-builder:$target" \
        "$PROJECT_ROOT/rpm-build/"

    log_info "Extracting RPMs..."
    local container_id=$($CONTAINER_CMD create "sss-rpm-builder:$target")
    $CONTAINER_CMD cp "$container_id:/output/." "$PROJECT_ROOT/rpm-build/"
    $CONTAINER_CMD rm "$container_id"

    log_info "RPM build complete for $target"
    log_info "RPMs available in: $PROJECT_ROOT/rpm-build/"
}

# Parse command line arguments
CLEAN=false
USE_CONTAINER=true
TARGET=""

while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            usage
            ;;
        -c|--clean)
            CLEAN=true
            shift
            ;;
        -n|--no-container|--no-docker)
            USE_CONTAINER=false
            shift
            ;;
        rhel8|rhel9|rhel10|fedora42|all)
            TARGET="$1"
            shift
            ;;
        *)
            log_error "Unknown option: $1"
            usage
            ;;
    esac
done

# Validate target
if [ -z "$TARGET" ]; then
    log_error "No target specified"
    usage
fi

# Main execution
main() {
    cd "$PROJECT_ROOT"

    # Clean if requested
    if [ "$CLEAN" = true ]; then
        clean_artifacts
    fi

    # Check for container runtime if needed
    if [ "$USE_CONTAINER" = true ]; then
        check_container_runtime
    fi

    # Build based on target
    case "$TARGET" in
        rhel8|rhel9|rhel10|fedora42)
            if [ "$USE_CONTAINER" = true ]; then
                build_container "$TARGET"
            else
                build_local "$TARGET"
            fi
            ;;
        all)
            for target in rhel8 rhel9 rhel10 fedora42; do
                if [ "$USE_CONTAINER" = true ]; then
                    build_container "$target"
                else
                    build_local "$target"
                fi
            done
            ;;
    esac

    # List generated RPMs
    log_info ""
    log_info "Generated RPM packages:"
    find "$PROJECT_ROOT/rpm-build" -maxdepth 1 -name "*.rpm" -type f -exec basename {} \;
}

main
