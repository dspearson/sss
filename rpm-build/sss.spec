Name:           sss
Version:        1.1.9
Release:        1%{?dist}
Summary:        Secret String Substitution - Transparent file encryption tool

License:        ISC
URL:            https://github.com/dspearson/sss
Source0:        %{name}-%{version}.tar.gz

# Disable debug package generation (Rust binaries are stripped in release mode)
%global debug_package %{nil}

BuildRequires:  libsodium-devel >= 1.0.14
BuildRequires:  gcc
BuildRequires:  fuse3-devel
BuildRequires:  fuse3
# Note: rust and cargo installed via rustup in container builds

Requires:       libsodium >= 1.0.14
Requires:       fuse3

%description
SSS (Secret String Substitution) is a command-line tool for transparent
encryption and decryption of text within files using XChaCha20-Poly1305
with a modern multi-user architecture. It enables seamless protection
of sensitive data embedded in configuration files, scripts, and other
text documents.

Features:
- Verb-based commands: seal, open, render, edit
- Deterministic encryption for clean git diffs
- Multi-user support with asymmetric encryption
- Password-protected private keys with Argon2id
- Git hooks management (pre-commit, post-merge, post-checkout)
- Project-wide operations with permission system
- Key rotation with automatic re-encryption
- Stdin/stdout support for pipeline integration
- Environment variable configuration (SSS_USER)
- Cross-platform: Linux, macOS, Windows

%prep
%setup -q

%build
# Build in release mode with FUSE support only (excludes 9P)
cargo build --release --features fuse

%install
# Create necessary directories
install -d %{buildroot}%{_bindir}
install -d %{buildroot}%{_mandir}/man1
install -d %{buildroot}%{_datadir}/%{name}

# Install binaries
install -m 755 target/release/sss %{buildroot}%{_bindir}/sss
install -m 755 target/release/sss-agent %{buildroot}%{_bindir}/sss-agent
install -m 755 target/release/sss-askpass-tty %{buildroot}%{_bindir}/sss-askpass-tty
install -m 755 target/release/sss-askpass-gui %{buildroot}%{_bindir}/sss-askpass-gui

# Create symlink for editor mode
ln -s sss %{buildroot}%{_bindir}/ssse

# Install man pages if they exist
if [ -d "man" ]; then
    install -m 644 man/sss.1 %{buildroot}%{_mandir}/man1/
fi

%files
%license LICENCE
%doc README.md
%{_bindir}/sss
%{_bindir}/ssse
%{_bindir}/sss-agent
%{_bindir}/sss-askpass-tty
%{_bindir}/sss-askpass-gui

%changelog
* Thu Oct 16 2025 Dominic Pearson <dsp@technoanimal.net> - 1.1.0-1
- Added deterministic encryption using BLAKE2b-derived nonces for clean git diffs
- Added git hooks management (sss hooks install/export/list/show)
- Added project-wide operations (--project flag for seal/open/render)
- Added project permissions system (enable-render/enable-open per project)
- Added global auto-render-projects and auto-open-projects settings
- Updated key rotation to change project timestamp for new nonces
- Improved git hooks with smart render > open > skip priority
- Added sss status command to check project status

* Mon Oct 13 2025 Dominic Pearson <dsp@technoanimal.net> - 1.0.0-1
- Initial RPM release
