# SSS Release Process

Single source of truth for cutting an sss release. The top section is a copy-paste crib for the common case; the per-host sections below cover troubleshooting and divergent steps.

## Quick Reference

Tag → build per-host → upload → update pointers. The version string `<VER>` (e.g. `2.0.1`) is set by the tag.

```bash
# 0. Pre-flight: working tree is clean, version in Cargo.toml is the tag's <VER>, CHANGELOG entry is in place.
git status                                # must be clean
grep '^version =' Cargo.toml              # must match <VER>

# 1. Tag.
git tag -s "v<VER>" -m "sss <VER>"
git push origin "v<VER>"

# 2. Build per host (run in parallel where possible).
#    Linux x86_64 (local or any glibc/musl Linux x86_64 host):
docker build -f Dockerfile.alpine -t sss-musl-x86_64 .
docker create --name sss-musl-tmp sss-musl-x86_64
docker cp sss-musl-tmp:/usr/local/bin/sss   ./sss-<VER>-linux-x86_64-musl
docker rm sss-musl-tmp

#    Linux aarch64 (build natively on `arm64-builder`, no QEMU):
rsync -a --exclude=target --exclude=.cargo ./ arm64-builder:/tmp/sss-build/
ssh arm64-builder 'cd /tmp/sss-build && cargo build --release --features fuse'
scp arm64-builder:/tmp/sss-build/target/release/sss ./sss-<VER>-linux-aarch64

#    macOS arm64 (build natively on `macos-builder`, no QEMU):
rsync -a --exclude=target --exclude=.cargo ./ macos-builder:/tmp/sss-build/
ssh macos-builder 'cd /tmp/sss-build && cargo build --release --features fuse'
scp macos-builder:/tmp/sss-build/target/release/sss ./sss-<VER>-macos-aarch64

#    RPM packages (RHEL 8/9/10 + Fedora 42, Linux x86_64 host with Docker):
./rpm-build/build-rpm.sh all
# → produces rpm-build/sss-<VER>-1.{el8,el9,el10,fc42}.x86_64.rpm + .src.rpm
# NOTE: build-rpm.sh auto-generates rpm-build/Dockerfile.<distro> at runtime via heredoc;
#       you do not maintain those Dockerfiles by hand and they are gitignored (Dockerfile.* in rpm-build/.gitignore).

# 3. Stage release/.
mkdir -p "release-<VER>"
cp sss-<VER>-linux-x86_64-musl sss-<VER>-linux-aarch64 sss-<VER>-macos-aarch64 "release-<VER>/"
cp rpm-build/sss-<VER>-1.{el8,el9,el10,fc42}.x86_64.rpm "release-<VER>/"

# 4. Generate latest.json manifest.
cat > "release-<VER>/latest.json" <<EOF
{
  "version": "<VER>",
  "released": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "artifacts": {
    "linux-x86_64-musl":     "sss-<VER>-linux-x86_64-musl",
    "linux-aarch64":         "sss-<VER>-linux-aarch64",
    "macos-aarch64":         "sss-<VER>-macos-aarch64",
    "rhel8-x86_64":          "sss-<VER>-1.el8.x86_64.rpm",
    "rhel9-x86_64":          "sss-<VER>-1.el9.x86_64.rpm",
    "rhel10-x86_64":         "sss-<VER>-1.el10.x86_64.rpm",
    "fedora42-x86_64":       "sss-<VER>-1.fc42.x86_64.rpm"
  }
}
EOF

# 5. Upload to the distribution host.
rsync -av "release-<VER>/" "releasehost:/var/www/html/sss/v<VER>/"
ssh releasehost "cd /var/www/html/sss && ln -sfn v<VER> latest && cp v<VER>/latest.json latest.json"

# 6. Verify.
curl -s https://technoanimal.net/sss/latest.json | jq .version    # must echo <VER>
curl -sI https://technoanimal.net/sss/latest/sss-<VER>-linux-aarch64 | head -1
```

## Supported Targets

| Target | Build host | Build entry point |
|--------|-----------|-------------------|
| Linux x86_64 (musl, portable) | local x86_64 host with Docker | `Dockerfile.alpine` |
| Linux aarch64 | `ssh arm64-builder` (native, no QEMU) | `cargo build --release --features fuse` |
| macOS arm64 | `ssh macos-builder` (native, no QEMU) | `cargo build --release --features fuse` |
| RHEL 8 / Rocky 8 / AlmaLinux 8 (.rpm) | local x86_64 host with Docker | `./rpm-build/build-rpm.sh rhel8` |
| RHEL 9 / Rocky 9 / AlmaLinux 9 (.rpm) | local x86_64 host with Docker | `./rpm-build/build-rpm.sh rhel9` |
| RHEL 10 / Rocky 10 / AlmaLinux 10 (.rpm) | local x86_64 host with Docker | `./rpm-build/build-rpm.sh rhel10` |
| Fedora 42 (.rpm) | local x86_64 host with Docker | `./rpm-build/build-rpm.sh fedora42` |

Cross-arch builds happen on native hosts (`ssh macos-builder`, `ssh arm64-builder`); QEMU emulation is not used.

## Per-Host Detail

### Linux x86_64 (Alpine musl portable binary)

The musl binary is the universal Linux artefact: it runs on any glibc Linux as well as Alpine. Built inside `Dockerfile.alpine`.

```bash
docker build -f Dockerfile.alpine -t sss-musl-x86_64 .
docker create --name sss-musl-tmp sss-musl-x86_64
docker cp sss-musl-tmp:/usr/local/bin/sss ./sss-<VER>-linux-x86_64-musl
docker rm sss-musl-tmp
```

Verification:

```bash
file sss-<VER>-linux-x86_64-musl       # statically linked
./sss-<VER>-linux-x86_64-musl --version
```

Troubleshooting:

- **`fuse3-static` package not in upstream Alpine repos** — uncommon, but if `apk add fuse3-static` fails inside the build container, ensure the Alpine version in `Dockerfile.alpine` (currently `FROM rust:alpine` and `FROM alpine:latest`) is fresh; `docker pull alpine:latest` and rebuild.
- **Build cache is huge** — the `target/` directory inside the container is 4–8 GB of cached crates; `docker system prune -f` between releases keeps disk pressure manageable.
- **Hybrid feature build error** — the Dockerfile builds with `--features fuse,hybrid`; if the trelis vendored crate fails to compile (rare), rebuild without `--no-cache` to avoid a stale layer; if persistent, see `docs/security-model.md` § Trelis Attack Surface for the pinned-commit reference.

Alternative entry points for ad-hoc local musl builds (not the release path; documented for completeness):

- `scripts/build-musl.sh` — local rustup + system `musl-gcc`. Supports `x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl`, `armv7-unknown-linux-musleabihf`. Use this if you have musl-tools installed locally and want a quick sanity build.
- `scripts/build-musl-docker.sh` — same as above but uses the `clux/muslrust:stable` Docker image, no host musl-tools needed. Useful from macOS or Windows hosts.
- `scripts/build-with-bundled-libsodium.sh` — builds with dynamic libsodium and rewrites the binary's RPATH so libsodium ships next to the binary. Distinct from musl static; produces a "fat tarball" distribution model. Not used for the canonical release path.

### Linux aarch64 (`ssh arm64-builder`, native build)

Native aarch64 build host — no QEMU, no cross-compilation.

```bash
rsync -a --exclude=target --exclude=.cargo ./ arm64-builder:/tmp/sss-build/
ssh arm64-builder 'cd /tmp/sss-build && cargo build --release --features fuse'
scp arm64-builder:/tmp/sss-build/target/release/sss ./sss-<VER>-linux-aarch64
```

Verification:

```bash
file sss-<VER>-linux-aarch64        # ELF 64-bit LSB pie executable, ARM aarch64
ssh arm64-builder 'cd /tmp/sss-build && ./target/release/sss --version'
```

Troubleshooting:

- **`.cargo/` rsync inflation** — the `--exclude=.cargo` flag is required; without it, ~5 GB of registry cache copies. If you forget it, the rsync will run for minutes.
- **`cargo build` fails with libsodium-related linker errors** — `arm64-builder` needs `libsodium-dev` (or distro-equivalent) installed. Run `ssh arm64-builder 'sudo apt-get install -y libsodium-dev pkg-config fuse3 libfuse3-dev'` once and re-run.
- **FUSE feature build fails** — `fuse3-dev` package missing on the host. Same `apt-get` line as above.

### macOS arm64 (`ssh macos-builder`, native build)

Native macOS arm64 build host — no QEMU, no Rosetta, no cross-compilation.

```bash
rsync -a --exclude=target --exclude=.cargo ./ macos-builder:/tmp/sss-build/
ssh macos-builder 'cd /tmp/sss-build && cargo build --release --features fuse'
scp macos-builder:/tmp/sss-build/target/release/sss ./sss-<VER>-macos-aarch64
```

Verification:

```bash
file sss-<VER>-macos-aarch64        # Mach-O 64-bit executable arm64
ssh macos-builder 'cd /tmp/sss-build && ./target/release/sss --version'
```

Troubleshooting:

- **`libsodium not found`** — install with `brew install libsodium` on the build host.
- **FUSE feature build fails on macOS** — macOS does not ship FUSE in the OS. The `--features fuse` build links against `macFUSE` (or omits the `fuse` feature on macOS). For the release artefact, the convention is to build without FUSE on macOS unless macFUSE is installed; if you want a FUSE-capable macOS build, install macFUSE from <https://osxfuse.github.io/> first.
- **Fully-static binary on macOS** — for distribution that does not depend on a Homebrew libsodium, use `scripts/build-static-local.sh` on the macOS host: it compiles libsodium 1.0.20 from source under `target/libsodium-build/` and links statically. The release path uses dynamic libsodium because the macOS users we ship to all have Homebrew.
- **`.cargo/` rsync inflation** — same as arm64-builder; `--exclude=.cargo` is required.

### RPM packages (Linux x86_64 host with Docker required)

The canonical RPM-build entry point is `rpm-build/build-rpm.sh`. It builds inside per-distro Docker images.

**Important:** the per-distro Dockerfiles `rpm-build/Dockerfile.{rhel8,rhel9,rhel10,fedora42}` are NOT tracked source — `build-rpm.sh` auto-generates them at runtime via a heredoc (lines 188-228 of the script). They are gitignored (`Dockerfile.*` in `rpm-build/.gitignore`). Do not look for them in `git ls-files`; do not try to maintain them by hand. They appear on disk after a build run and disappear from the index by design. If you need to inspect the generated content, run `bash rpm-build/build-rpm.sh -n rhel8 || true` (the heredoc fires before the `docker build`) and then read `rpm-build/Dockerfile.rhel8` from the working tree.

```bash
./rpm-build/build-rpm.sh all
```

Output: `rpm-build/sss-<VER>-1.{el8,el9,el10,fc42}.x86_64.rpm` plus matching `.src.rpm` files.

See `rpm-build/README.md` for per-distro detail, local (no-container) build options, and yum/dnf repository hosting tips.

Troubleshooting:

- **Docker permission denied** — see `rpm-build/README.md` § Troubleshooting.
- **`libsodium-devel` missing on RHEL 8** — EPEL is required; the build images already enable it. Local builds (`--no-container`) need `sudo dnf install -y epel-release` first.
- **Old RPMs in `rpm-build/` directory** — they are gitignored (`*.rpm`, `*.tar.gz`); clean with `rm -f rpm-build/*.rpm rpm-build/*.tar.gz` before a fresh build if you want a clean output directory. Same applies to the runtime-generated `rpm-build/Dockerfile.<distro>` files (gitignored via `Dockerfile.*`).

## Distribution

Release artefacts live at `releasehost:/var/www/html/sss/` (private host, fronted by <https://technoanimal.net/sss>).

Layout:

```
/var/www/html/sss/
  ├── v2.0.0/
  │   ├── sss-2.0.0-linux-x86_64-musl
  │   ├── sss-2.0.0-linux-aarch64
  │   ├── sss-2.0.0-macos-aarch64
  │   ├── sss-2.0.0-1.el8.x86_64.rpm
  │   ├── sss-2.0.0-1.el9.x86_64.rpm
  │   ├── sss-2.0.0-1.el10.x86_64.rpm
  │   ├── sss-2.0.0-1.fc42.x86_64.rpm
  │   └── latest.json
  ├── v2.0.1/
  │   └── ...
  ├── latest -> v2.0.1                          # symlink, repointed each release
  └── latest.json                                # copy of v2.0.1/latest.json
```

Public download URL pattern: `https://technoanimal.net/sss/latest/<artefact>` or `https://technoanimal.net/sss/v<VER>/<artefact>`.

Update sequence (already in the Quick Reference; repeated here for the per-host context):

```bash
rsync -av "release-<VER>/" "releasehost:/var/www/html/sss/v<VER>/"
ssh releasehost "cd /var/www/html/sss && ln -sfn v<VER> latest && cp v<VER>/latest.json latest.json"
```

Verification:

```bash
curl -s https://technoanimal.net/sss/latest.json | jq -r .version
curl -sI https://technoanimal.net/sss/latest/sss-<VER>-linux-aarch64
```

The `latest.json` manifest is the source of truth for "what is current" — auto-updaters and CI consumers should read it rather than parsing directory listings.

## Vendored Dependencies

The `rs9p` dependency (`Cargo.toml` § `[dependencies]`) is vendored at
`vendor/rust-9p/` rather than consumed from crates.io. The upstream
`rust-9p` crate has no published release suitable for the project's
`ninep` feature, and a path-dep against a committed tree is the
simplest reproducible build for fresh clones. The tree is committed
directly (not gitignored) so `cargo build --features ninep` succeeds
on a fresh `git clone` without manual vendor setup.

Refresh procedure: drop new sources into `vendor/rust-9p/`, run
`cargo build --features ninep` to confirm the tree compiles, and
commit the change as a single atomic commit. There is no upstream
pin to bump — the project owns the vendored copy.

## Reproducible Build (Phase 26)

Phase 26 ships reproducible-build guarantees: the same git commit +
`Cargo.lock` should produce byte-identical binaries when built on
different hosts within the same target cell.

**Wrapper script:**
[`scripts/release/build-reproducible.sh`](../scripts/release/build-reproducible.sh).
Wraps `cargo build --release --locked` with four determinism env-vars
(SOURCE_DATE_EPOCH, RUSTFLAGS `--remap-path-prefix`, CARGO_BUILD_JOBS=1,
LC_ALL=C.UTF-8 + TZ=UTC).

**Cargo.lock policy:** committed to git as of v2.3 (D-V23-01). Bumps
happen via deliberate `cargo update -p <crate>` + commit. CI uses
`cargo build --locked` so any drift between the committed lock and a
resolved state fails the build.

**Verification (2-host diff per BUILD-05):**

```bash
# On arm64-builder (Linux aarch64):
ssh arm64-builder 'cd sss && git fetch && git checkout <COMMIT> && \
  bash scripts/release/build-reproducible.sh --features hybrid && \
  sha256sum target/release/sss'

# On mac (macOS arm64):
ssh macos-builder 'cd sss && git fetch && git checkout <COMMIT> && \
  bash scripts/release/build-reproducible.sh --features hybrid && \
  sha256sum target/release/sss'

# Compare locally — identical SHA-256 within the same target cell
# (Linux↔Linux, macOS↔macOS) is the acceptance criterion.
```

Per-cell results are appended to
`.planning/phases/26-reproducible-builds-vendoring-policy/REPRODUCIBLE-BUILD-TRANSCRIPT.md`
each release cycle. Cross-OS (Linux↔macOS) divergences are expected
on platform-specific ELF/Mach-O metadata and are NOT part of the
reproducibility claim.

See also [`docs/vendoring-policy.md`](vendoring-policy.md) for the
non-crates.io dep policy (vendored rust-9p, git-rev pinned trelis-*,
linked-dynamic libsodium).

## Supply-Chain Artefacts (Phase 25)

Each release ships with three supply-chain artefacts alongside the binary:

1. **CycloneDX SBOM** (`sss-<cell>.cdx.json`) — produced by
   `cargo-cyclonedx 0.5.9+` via `scripts/release/generate-sbom.sh`. Six
   files in `dist/sbom/`: three platforms (linux-x86_64, linux-aarch64,
   macos-arm64) × two feature arms (default, hybrid). `trelis-*`, `fips204`,
   `ed448-goldilocks-plus`, `pqcrypto-*` appear in the `hybrid` SBOMs only
   (default SBOMs are the classic crypto surface).
2. **cargo-auditable embed** — `cargo auditable build` injects the dep
   manifest into the binary itself. Verify with
   `cargo audit bin target/release/sss` (requires `cargo-audit` installed).
   Release entry points using auditable: `Dockerfile.alpine`,
   `build-on-arm64-linux.sh`, `rpm-build/build-rpm.sh`,
   `rpm-build/sss.spec`. Local-only entry points
   (`debian/`, `build-macos-*.sh`, `rpm-build/Dockerfile.*`) follow the
   same pattern on the release operator's host.
3. **cosign keyless signature** (`<artefact>.sig` + `<artefact>.pem`) —
   produced by sigstore/cosign v3.0.3+ via
   `.github/workflows/release.yml` SIGN-02 step. Uses GitHub Actions
   OIDC for ephemeral Fulcio certs; signatures logged to the Rekor
   public transparency log.
4. **SLSA-style provenance** (`<artefact>.intoto.jsonl`) — cosign
   `attest-blob` step in the same workflow; embeds build provenance
   for SLSA Level 2 attestation.

### Release-Signing Keypair (SIGN-01 / D-V23-04)

The release-signing keypair is a separate concern from the envelope-sig
material used inside sealed envelopes. Per D-V23-04 the two security
domains are kept separate by:

- Distinct algorithm (Ed25519 for release-signing vs Ed448 + ML-DSA-65
  for envelope-sig).
- Distinct domain-separation bytes: release-signing uses
  `b"sss-release-artifact-sig-v1"`; envelope-sig uses
  `b"sss-envelope-sig-v1"` (Phase 19 lock).
- Different storage policy: release-signing private key lives offline
  (HSM or air-gapped USB) and is regenerated per major version;
  envelope-sig keys live in the per-user keystore.

Generate the offline fallback keypair with:

```bash
bash scripts/release/generate-release-key.sh /path/to/offline-storage
```

The script produces three files: `sss-release-sig-v1.{key,pub,notes}`.
The public key gets committed to `docs/release-keys/`. The private key
NEVER leaves the offline storage. See the script header for the full
storage policy.

The cosign keyless flow (SIGN-02) is the PRIMARY signing path; the
offline Ed25519 keypair is the FALLBACK for environments where
sigstore is unavailable OR for cross-verification of cosign
signatures.

### Verification

Verify the cosign signature:

```bash
cosign verify-blob \
    --certificate sss-<cell>.tar.gz.pem \
    --signature sss-<cell>.tar.gz.sig \
    --certificate-identity-regexp 'https://github\.com/[^/]+/sss' \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    sss-<cell>.tar.gz
```

Verify the offline Ed25519 signature (if present):

```bash
openssl pkeyutl -verify \
    -pubin -inkey docs/release-keys/sss-release-sig-v1.pub \
    -sigfile sss-<cell>.tar.gz.offline.sig \
    -in sss-<cell>.tar.gz
```

Verify the embedded dep manifest:

```bash
cargo install --locked cargo-audit
cargo audit bin sss
```

Verify the SBOM is well-formed CycloneDX:

```bash
jq '.bomFormat, .specVersion' sss-<cell>.cdx.json
# Expected: "CycloneDX" and "1.4" (or newer)
```

## Post-Release Checklist

- [ ] `git tag -s v<VER>` signed with the release GPG key
- [ ] `git push origin v<VER>` (tag visible on the public remote)
- [ ] Release artefacts uploaded under `v<VER>/` on the distribution host
- [ ] `latest` symlink and `latest.json` updated
- [ ] `curl -s https://technoanimal.net/sss/latest.json | jq -r .version` returns `<VER>`
- [ ] CHANGELOG entry merged to master, version bumped on master for the next development cycle if appropriate
- [ ] **Phase 25:** 6 CycloneDX SBOMs in `dist/sbom/` produced via `scripts/release/generate-sbom.sh`
- [ ] **Phase 25:** Each shipped binary has cargo-auditable embed (`cargo audit bin sss` exits clean)
- [ ] **Phase 25:** Each release archive has a `.sig` + `.pem` + `.intoto.jsonl` from cosign (visible on the GitHub Release page)

## See Also

- `rpm-build/README.md` — per-distro RPM build detail, local (no-container) builds, yum repository hosting.
- `docs/security-model.md` — threat model, hybrid trust boundaries, trelis attack surface, FFI audit.
- `docs/CRYPTOGRAPHY.md` — cryptographic primitives reference; cross-referenced from the security model.

## Out of Scope

- **CI workflow alignment** (`.github/workflows/*.yml`) — the workflows reference scripts and Dockerfiles by path; aligning them with the post-Phase-12 build surface is a follow-up task.
- **Debian `.deb` packaging** — `debian/build-deb.sh` and `debian/Dockerfile.trixie` exist as a private build channel (`debian/` is gitignored at root) and are not part of the public release matrix.
- **Cross-compilation matrix** — native-host builds are the v2.x model; QEMU-based cross-arch is not used.
