# RPM Packaging for SSS

This directory contains RPM packaging files for building SSS packages for RHEL 8, RHEL 9, and RHEL 10.

## Quick Start

### Build for RHEL 9 (using Docker)
```bash
./rpm-build/build-rpm.sh rhel9
```

### Build for RHEL 8 (using Docker)
```bash
./rpm-build/build-rpm.sh rhel8
```

### Build for RHEL 10 (using Docker)
```bash
./rpm-build/build-rpm.sh rhel10
```

### Build for all versions
```bash
./rpm-build/build-rpm.sh all
```

## Prerequisites

### Using Docker (Recommended)

- Docker installed and running
- User has permission to run Docker commands

The script will automatically use Rocky Linux container images as build environments.

### Building Locally (Without Docker)

For local builds on RHEL/Rocky/AlmaLinux:

```bash
# RHEL 8 / Rocky 8 / AlmaLinux 8
sudo dnf install -y epel-release
sudo dnf install -y rpm-build rpmdevtools gcc libsodium-devel fuse3 fuse3-devel

# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Build
./rpm-build/build-rpm.sh --no-container rhel8
```

```bash
# RHEL 9 / Rocky 9 / AlmaLinux 9
sudo dnf install -y epel-release
sudo dnf install -y rpm-build rpmdevtools gcc libsodium-devel fuse3 fuse3-devel

# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Build
./rpm-build/build-rpm.sh --no-container rhel9
```

```bash
# RHEL 10 / Rocky 10 / AlmaLinux 10
sudo dnf install -y epel-release
sudo dnf install -y rpm-build rpmdevtools gcc libsodium-devel fuse3 fuse3-devel

# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Build
./rpm-build/build-rpm.sh --no-container rhel10
```

## Build Script Options

```
Usage: ./rpm-build/build-rpm.sh [OPTIONS] TARGET

TARGETS:
    rhel8       Build for RHEL 8
    rhel9       Build for RHEL 9
    rhel10      Build for RHEL 10
    all         Build for RHEL 8, 9, and 10

OPTIONS:
    -h, --help          Show help message
    -c, --clean         Clean build artifacts before building
    -n, --no-container  Build locally (requires proper RHEL environment)
```

## Examples

### Clean build for all versions
```bash
./rpm-build/build-rpm.sh --clean all
```

### Local build for RHEL 9 (no Docker)
```bash
./rpm-build/build-rpm.sh --no-container rhel9
```

### Build only for RHEL 10
```bash
./rpm-build/build-rpm.sh rhel10
```

## Output

Built RPM packages will be placed in the `rpm-build/` directory:

- `sss-1.0.0-1.el8.x86_64.rpm` - Binary package for RHEL 8
- `sss-1.0.0-1.el8.src.rpm` - Source package for RHEL 8
- `sss-1.0.0-1.el9.x86_64.rpm` - Binary package for RHEL 9
- `sss-1.0.0-1.el9.src.rpm` - Source package for RHEL 9
- `sss-1.0.0-1.el10.x86_64.rpm` - Binary package for RHEL 10
- `sss-1.0.0-1.el10.src.rpm` - Source package for RHEL 10

## Installation

### On RHEL 8 / Rocky 8 / AlmaLinux 8
```bash
# Install EPEL (for libsodium)
sudo dnf install -y epel-release

# Install the RPM
sudo dnf install -y ./rpm-build/sss-1.0.0-1.el8.x86_64.rpm
```

### On RHEL 9 / Rocky 9 / AlmaLinux 9
```bash
# Install EPEL (for libsodium)
sudo dnf install -y epel-release

# Install the RPM
sudo dnf install -y ./rpm-build/sss-1.0.0-1.el9.x86_64.rpm
```

### On RHEL 10 / Rocky 10 / AlmaLinux 10
```bash
# Install EPEL (for libsodium)
sudo dnf install -y epel-release

# Install the RPM
sudo dnf install -y ./rpm-build/sss-1.0.0-1.el10.x86_64.rpm
```

## Package Contents

The RPM package includes:

- `/usr/bin/sss` - Main SSS command
- `/usr/bin/ssse` - Editor mode (symlink to sss)
- `/usr/bin/sss-agent` - SSH agent-style key agent
- `/usr/bin/sss-askpass-tty` - TTY password prompt
- `/usr/bin/sss-askpass-gui` - GUI password prompt
- Documentation files (README.md, LICENSE)
- Man pages (if available)

## Spec File

The RPM spec file is located at `sss.spec` in the project root. You can customize:

- Version and release numbers
- Dependencies
- Build options
- File locations
- Changelog entries

## Troubleshooting

### libsodium not found

If you get errors about missing libsodium, ensure EPEL is enabled:

```bash
sudo dnf install -y epel-release
sudo dnf install -y libsodium-devel  # For building
sudo dnf install -y libsodium        # For runtime
```

### FUSE3 not found

SSS requires FUSE3 (not FUSE2) for filesystem mounting. On RHEL 8 systems:

```bash
sudo dnf install -y fuse3 fuse3-libs  # For runtime
sudo dnf install -y fuse3-devel       # For building
```

Note: RHEL 9+ includes FUSE3 by default.

### Docker permission denied

If you get permission errors with Docker:

```bash
# Add your user to the podman/docker group (if using rootless containers)
# For docker:
sudo usermod -aG docker $USER
# For podman: no group needed, rootless by default

# Log out and log back in for changes to take effect
```

### Rust version too old

The spec file requires Rust 1.70 or newer. If your system Rust is too old:

```bash
# Install rustup (recommended)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
rustup update stable
```

## Creating a YUM/DNF Repository

To host your RPMs in a local repository:

```bash
# Create repository directory
mkdir -p ~/sss-repo

# Copy RPMs
cp rpm-build/*.rpm ~/sss-repo/

# Create repository metadata
createrepo ~/sss-repo

# Serve via HTTP (optional)
cd ~/sss-repo
python3 -m http.server 8000
```

Then on client machines:

```bash
# Create repo file
sudo tee /etc/yum.repos.d/sss.repo <<EOF
[sss]
name=SSS Repository
baseurl=http://your-server:8000
enabled=1
gpgcheck=0
EOF

# Install
sudo dnf install sss
```

## Version Updates

When updating the version:

1. Update `Cargo.toml` version field
2. Update `sss.spec` Version field
3. Add changelog entry in `sss.spec`
4. Update VERSION in `build-rpm.sh` if not parsing from Cargo.toml
5. Rebuild RPMs

## CI/CD Integration

You can integrate RPM building into your CI/CD pipeline:

```yaml
# Example GitHub Actions workflow
jobs:
  build-rpms:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Build RPMs
        run: |
          ./rpm-build/build-rpm.sh all
      - name: Upload artifacts
        uses: actions/upload-artifact@v3
        with:
          name: rpm-packages
          path: rpm-build/*.rpm
```

## License

The packaging scripts are distributed under the same license as SSS.
