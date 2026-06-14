use anyhow::{anyhow, Result};
use clap::ArgMatches;
use std::path::{Path, PathBuf};

use crate::Processor;
use crate::project::ProjectConfig;

#[cfg(any(target_os = "linux", target_os = "macos"))]
use crate::fuse::fs::SssFS;

/// Load project config and create processor for a source directory.
///
/// Changes to source_path temporarily to locate .sss.toml, then restores the
/// original directory. Returns the resolved `config_path` alongside the config +
/// processor so the mount-time vault bootstrap (Phase 49) can re-run the envelope
/// signature verification against the exact loaded file (pitfall 7 ordering).
fn load_processor_for_source(
    source_path: &Path,
) -> Result<(ProjectConfig, Processor, PathBuf)> {
    let original_dir = std::env::current_dir()?;
    std::env::set_current_dir(source_path)?;
    let config_path = crate::config::get_project_config_path()?;
    std::env::set_current_dir(original_dir)?;

    let (config, repository_key, project_root) =
        crate::config::load_project_config_with_repository_key(&config_path)?;

    let secrets_filename = config.get_secrets_filename().to_string();
    let processor = crate::Processor::new_with_context_and_secrets_filename(
        repository_key,
        project_root,
        config.created.clone(),
        secrets_filename,
    )?;

    Ok((config, processor, config_path))
}

/// Build the mount-level `VaultMountState` with the fail-closed sig-verify→auth
/// ordering (VMNT-01, pitfall 7).
///
/// The strict order is: a repo with no `[vault]` table (or `--no-vault`) yields a
/// disabled state (no sig-verify, no auth, `⊳{}` markers stay literal). Otherwise
/// the envelope signature is verified FIRST (on the already-loaded config + the
/// exact `config_path`); only after that passes do we derive the resolver paths
/// and — unless `--vault-lazy` — construct a `VaultResolver` and perform the eager
/// bootstrap login, draining the token+lease out of the boot cache into the
/// long-lived state.
///
/// # Errors
///
/// Returns an error (so the caller exits non-zero and mounts nothing) when the
/// envelope signature verification fails, or when eager bootstrap auth fails.
#[cfg(feature = "vault")]
fn build_vault_mount_state(
    config: &ProjectConfig,
    config_path: &Path,
    source_path: &Path,
    processor: &Processor,
    no_vault: bool,
    vault_lazy: bool,
    keep_unresolved: bool,
) -> Result<crate::fuse::fs::VaultMountState> {
    use crate::fuse::fs::VaultMountState;

    // (1) No [vault] table → Vault is a complete no-op for this mount.
    let Some(vault_cfg) = config.vault.as_ref() else {
        return Ok(VaultMountState::disabled());
    };

    // (2) Explicit opt-out → skip BOTH sig-verify and auth; markers stay literal.
    if no_vault {
        return Ok(VaultMountState::disabled());
    }

    // (3) FAIL-CLOSED ORDERING (pitfall 7): verify the envelope signature BEFORE
    // constructing a resolver or transmitting any credential. A tampered [vault]
    // address must never receive AppRole creds. On a v3 repo the loader already
    // verified this at load time; re-running it here makes the mount-time ordering
    // explicit and self-documenting, and fails the mount closed on any mismatch.
    #[cfg(feature = "hybrid")]
    crate::envelope_sig::verify_envelope_signature(config, config_path).map_err(|e| {
        anyhow!("vault config signature verification failed — mount aborted: {e}")
    })?;
    // On non-hybrid builds the v3 signature cannot be proven; the loader already
    // rejected a v3/[vault] repo before reaching here, so this is unreachable in
    // practice — but bail closed rather than mount an unverifiable [vault] config.
    // (Swallow the otherwise-hybrid-only params so this arm is warning-free.)
    #[cfg(not(feature = "hybrid"))]
    {
        let _ = (config_path, source_path, processor, vault_cfg, vault_lazy, keep_unresolved);
        return Err(anyhow!(
            "vault config signature verification requires the `hybrid` build feature — mount aborted"
        ));
    }

    // Sig-verify passed. Derive the resolver paths exactly as the CLI does
    // (vault.rs): source_path IS the project root (it holds .sss.toml), and the
    // secrets anchor is <root>/.sss.toml so the upward .secrets search starts there.
    #[cfg(feature = "hybrid")]
    {
        use crate::vault::resolver::{VaultRequestCache, VaultResolver};

        let project_root = source_path.to_path_buf();
        let secrets_anchor = config_path.to_path_buf();
        let secrets_cache = processor.get_secrets_cache().clone();
        let config_arc = std::sync::Arc::new(vault_cfg.clone());

        // --vault-lazy: sig-verified, but defer the eager login to first read.
        if vault_lazy {
            return Ok(VaultMountState::lazy(
                config_arc,
                secrets_cache,
                secrets_anchor,
                project_root,
                keep_unresolved,
            ));
        }

        // Default eager path: construct the resolver and authenticate now. The
        // resolver borrows the Arc-held config for the duration of this block only.
        let resolver = VaultResolver::new(
            config_arc.as_ref(),
            secrets_cache.clone(),
            &secrets_anchor,
            &project_root,
        )
        .map_err(|e| anyhow!("vault bootstrap failed — mount aborted: {e}"))?;

        let mut boot_cache = VaultRequestCache::new();
        resolver
            .bootstrap_auth(&mut boot_cache)
            .map_err(|e| anyhow!("vault auth failed — mount aborted: {e}"))?;

        // Drain the token+lease out of the boot cache into the long-lived state;
        // the boot cache's Drop zeroises any remainder.
        let token = boot_cache.take_token();
        let lease = boot_cache.take_lease();

        Ok(VaultMountState::with_token(
            config_arc,
            secrets_cache,
            secrets_anchor,
            project_root,
            token,
            lease,
            keep_unresolved,
        ))
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub fn handle_mount(_main_matches: &ArgMatches, sub_matches: &ArgMatches) -> Result<()> {
    let in_place = sub_matches.get_flag("in-place");
    let foreground = sub_matches.get_flag("foreground");
    let read_only = sub_matches.get_flag("read-only");
    let allow_other = sub_matches.get_flag("allow-other");
    let no_allow_root = sub_matches.get_flag("no-allow-root");
    // Phase 49 vault mount flags (VMNT-05). Extracted on all builds (the clap args
    // exist regardless of the `vault` feature); only consumed on `#[cfg(vault)]`.
    #[cfg(feature = "vault")]
    let no_vault = sub_matches.get_flag("no-vault");
    #[cfg(feature = "vault")]
    let vault_lazy = sub_matches.get_flag("vault-lazy");
    #[cfg(feature = "vault")]
    let keep_unresolved = sub_matches.get_flag("keep-unresolved");

    // Determine source and mountpoint
    let (source, mountpoint) = if in_place {
        // In-place: mount over source directory
        let src = sub_matches
            .get_one::<String>("source")
            .map(|s| s.as_str())
            .unwrap_or(".");
        (src, src)
    } else {
        // Normal: source and mountpoint are separate
        // INVARIANT: clap declares both `source` and `mountpoint` as
        // required_unless_present="in-place"; this branch only fires when
        // `--in-place` is NOT set, so both args are present. HARDEN-01 / 08-01.
        let src = sub_matches.get_one::<String>("source").unwrap().as_str();
        let mp = sub_matches.get_one::<String>("mountpoint").unwrap().as_str();
        (src, mp)
    };

    let source_path = std::fs::canonicalize(PathBuf::from(source))?;
    let mountpoint_path = PathBuf::from(mountpoint);

    // Validate paths
    if !source_path.exists() {
        return Err(anyhow!("Source path does not exist: {}", source));
    }

    if !source_path.is_dir() {
        return Err(anyhow!("Source path must be a directory: {}", source));
    }

    // Note: Mounting over the source directory is now supported!
    // The FUSE filesystem keeps a file descriptor to the source open before mounting,
    // which allows it to access the original files even after mounting over them.
    // This enables hiding .git and other files while showing only rendered content.

    // Create mountpoint if it doesn't exist
    if !mountpoint_path.exists() {
        std::fs::create_dir_all(&mountpoint_path)?;
    }

    if !mountpoint_path.is_dir() {
        return Err(anyhow!("Mountpoint must be a directory: {}", mountpoint));
    }

    // Load project config and create processor
    let (config, processor, config_path) = load_processor_for_source(&source_path)?;
    // `config_path` feeds the vault sig-verify below; on non-vault fuse builds the
    // vault block is cfg'd out, so the binding would otherwise be unused.
    #[cfg(not(feature = "vault"))]
    let _ = &config_path;

    // Canonicalize mountpoint for fd holding
    let mountpoint_canonical = std::fs::canonicalize(&mountpoint_path)?;

    // Phase 49 (49-01 Task 3) — mount-time fail-closed Vault bootstrap (VMNT-01).
    //
    // ORDERING INVARIANT (pitfall 7): the envelope signature is verified BEFORE
    // any VaultResolver is constructed or any network credential is transmitted.
    // A tampered `[vault]` address therefore can never receive AppRole creds.
    // Either failure (sig-verify or auth) returns Err here, so the command exits
    // non-zero and NOTHING is mounted (the FUSE session below never starts).
    //
    // `--no-vault` / no `[vault]` table → disabled() (no sig-verify, no auth).
    // `--vault-lazy` → sig-verify only; eager auth deferred to first read (49-02),
    //   which also sidesteps the pre-fork token-in-parent concern (pitfall 4).
    #[cfg(feature = "vault")]
    let vault_state = build_vault_mount_state(
        &config,
        &config_path,
        &source_path,
        &processor,
        no_vault,
        vault_lazy,
        keep_unresolved,
    )?;

    // Create FUSE filesystem with mount point fd (pass config for ignore patterns)
    let fs = SssFS::new(
        source_path.clone(),
        processor,
        Some(mountpoint_canonical),
        Some(&config),
        #[cfg(feature = "vault")]
        vault_state,
    )?;

    if in_place {
        eprintln!("Mounting in-place (overlay): {}", source_path.display());
        eprintln!("Files will be rendered transparently, .git and work files hidden");
    } else {
        eprintln!("Mounting {} at {}", source, mountpoint);
        eprintln!("Source: {}", source_path.display());
        eprintln!("Mountpoint: {}", mountpoint_path.display());
    }

    // Print mount fd information for /proc access
    if let Some(mount_fd) = fs.get_mount_fd() {
        eprintln!();
        eprintln!("Mount point file descriptor: {}", mount_fd);
        eprintln!("Access underlying directory: /proc/$$/fd/{}", mount_fd);
        eprintln!("  (where $$ is the FUSE server process PID)");
    }

    if foreground {
        eprintln!("Running in foreground mode. Press Ctrl+C to unmount.");
    }

    // Mount options.
    // Note: TTL=0 is set in reply.entry() for passthrough files to disable positive caching.
    let mut options = vec![
        fuser::MountOption::FSName("sss".to_string()),
        // `DefaultPermissions` tells the kernel to run its own DAC uid/gid/mode check against
        // the inode attributes returned by `getattr` before dispatching a request to the FUSE
        // filesystem. Without it the kernel skips its check and delegates entirely to the FUSE
        // `access` callback. On Linux the `access` callback correctly calls `faccessat` against
        // the backing directory; on macOS the callback returns OK unconditionally, so
        // `DefaultPermissions` is the primary enforcement layer there (see the "Access Control"
        // section in docs/security-model.md for the full rationale — CON-16 / REM-19).
        fuser::MountOption::DefaultPermissions,
    ];

    // `AllowRoot` is the default so that commands run via `sudo` (euid=0) can access files on
    // a mount established by a non-root user. Without it, FUSE's security policy hides the
    // mount from every uid other than the mount owner. Root already holds `CAP_DAC_READ_SEARCH`
    // on Linux and can bypass FUSE permission checks regardless; `AllowRoot` is primarily
    // needed on macOS where that capability does not exist. It is kept on by default to
    // preserve common workflows such as `sudo openstack undercloud install` inside the mount.
    // Pass `--no-allow-root` to opt out. `--allow-other` takes precedence and grants access to
    // all users. Both options require `user_allow_other` in /etc/fuse.conf when mounting as a
    // non-root user. See docs/security-model.md "Access Control" for the full rationale.
    // Note: `AllowRoot` and `DefaultPermissions` coexist without conflict — fuser serialises
    // `AllowRoot` as the `allow_other` kernel flag with an internal root-only filter;
    // `DefaultPermissions` is a separate kernel flag (fuser 0.16 mount_options.rs:110).
    if allow_other {
        options.push(fuser::MountOption::AllowOther);
    } else if !no_allow_root {
        options.push(fuser::MountOption::AllowRoot);
    }

    if read_only {
        options.push(fuser::MountOption::RO);
    }

    if !foreground {
        // Daemonize: fork and detach from terminal
        eprintln!("Daemonizing and mounting in background...");

        // `fork()` is a standard POSIX syscall. After fork, only the child process
        // continues execution in this process image; the parent exits via `process::exit`.
        // All file descriptors are valid at fork time. `setsid()` is called in the child
        // to detach from the controlling terminal — standard daemonization pattern.
        // SAFETY: invariants noted above.
        unsafe {
            let pid = libc::fork();

            if pid < 0 {
                return Err(anyhow!("Failed to fork: {}", std::io::Error::last_os_error()));
            }

            if pid > 0 {
                // Parent process: print success message and exit
                eprintln!("Background process started with PID {}", pid);
                if in_place {
                    eprintln!("Mounted in-place (overlay): {}", source);
                } else {
                    eprintln!("Mounted {} at {}", source, mountpoint);
                }
                // Print /proc access information with actual PID
                if let Some(mount_fd) = fs.get_mount_fd() {
                    eprintln!();
                    eprintln!("Access underlying directory:");
                    eprintln!("  /proc/{}/fd/{}", pid, mount_fd);
                    eprintln!("Or from any process:");
                    eprintln!("  ls -la /proc/{}/fd/{}", pid, mount_fd);
                }
                // Flush stderr before exit to ensure all output is visible
                use std::io::Write;
                let _ = std::io::stderr().flush();
                std::process::exit(0);
            }

            // Child process: become session leader
            if libc::setsid() < 0 {
                return Err(anyhow!("Failed to create new session: {}", std::io::Error::last_os_error()));
            }

            // Redirect stdin, stdout, stderr to /dev/null
            let devnull = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open("/dev/null")?;

            use std::os::unix::io::AsRawFd;
            let devnull_fd = devnull.as_raw_fd();

            libc::dup2(devnull_fd, 0); // stdin
            libc::dup2(devnull_fd, 1); // stdout
            libc::dup2(devnull_fd, 2); // stderr

            // Close the devnull fd if it's not one of the standard fds
            if devnull_fd > 2 {
                libc::close(devnull_fd);
            }
        }
    }

    // Mount the filesystem (either in foreground or as daemon)
    match fuser::mount2(fs, &mountpoint_path, &options) {
        Ok(()) => {
            if foreground {
                eprintln!("Filesystem unmounted successfully");
            }
            Ok(())
        }
        Err(e) => {
            let msg = e.to_string();
            // fusermount rejects allow_root/allow_other for non-root users unless
            // `user_allow_other` is set in /etc/fuse.conf. Provide an actionable
            // hint pointing to the fix (or the --no-allow-root escape hatch).
            if (allow_other || !no_allow_root)
                && (msg.contains("user_allow_other") || msg.contains("allow_other"))
            {
                Err(anyhow!(
                    "Failed to mount filesystem: {}\n\n\
                    Tip: AllowRoot/AllowOther require `user_allow_other` in /etc/fuse.conf when mounting as a non-root user. \
                    Fix with:\n    \
                    echo 'user_allow_other' | sudo tee -a /etc/fuse.conf\n\
                    Or pass --no-allow-root to mount without granting root access (sudo inside the mount will then be blocked).",
                    e
                ))
            } else {
                Err(anyhow!("Failed to mount filesystem: {}", e))
            }
        }
    }
}

#[cfg(target_os = "windows")]
pub fn handle_mount(_main_matches: &ArgMatches, sub_matches: &ArgMatches) -> Result<()> {
    use crate::winfsp_fs::SssWinFsp;

    let source = sub_matches
        .get_one::<String>("source")
        .map(|s| s.as_str())
        .unwrap_or(".");
    let mountpoint = sub_matches
        .get_one::<String>("mountpoint")
        .ok_or_else(|| anyhow!("Mountpoint is required on Windows"))?
        .as_str();

    let source_path = std::fs::canonicalize(PathBuf::from(source))?;

    // Validate paths
    if !source_path.exists() {
        return Err(anyhow!("Source path does not exist: {}", source));
    }

    if !source_path.is_dir() {
        return Err(anyhow!("Source path must be a directory: {}", source));
    }

    // Load project config and create processor
    // (config_path unused on Windows: WinFSP vault integration is VMNT-F02, deferred)
    let (_config, processor, _config_path) = load_processor_for_source(&source_path)?;

    // Create WinFsp filesystem
    let fs = SssWinFsp::new(source_path.clone(), processor)?;

    eprintln!("Mounting {} at {}", source, mountpoint);
    eprintln!("Source: {}", source_path.display());
    eprintln!("Mountpoint: {}", mountpoint);

    // Mount the filesystem
    fs.mount(mountpoint)?;

    eprintln!("Filesystem mounted successfully");
    eprintln!("Press Ctrl+C to unmount");

    // Keep running until interrupted
    std::thread::park();

    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub fn handle_mount(_main_matches: &ArgMatches, _sub_matches: &ArgMatches) -> Result<()> {
    Err(anyhow!(
        "Filesystem mounting is only supported on Linux/macOS (FUSE/macFUSE) and Windows (WinFsp). \
        Please use 'sss open' or 'sss render' commands instead."
    ))
}

#[cfg(test)]
mod tests {
    #[test]
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    fn test_mount_requires_unix_platform() {
        // FUSE mounting is supported on Linux and macOS
        // On other platforms, commands should return appropriate errors
    }

    #[test]
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn test_mount_requires_fuse_feature() {
        // FUSE mounting requires the 'fuse' feature to be enabled
        // Without it, the mount/unmount commands are not available
        // This is a compile-time check, enforced by cfg(feature = "fuse")
    }

    // Note: Mount commands involve:
    // - FUSE filesystem operations (requires fuse feature)
    // - Source/mountpoint validation
    // - Reading .sss.toml for project config
    // - Creating FuseFS instance with processor
    // - Managing mount state and file descriptors
    // Integration tests verify the full mounting workflow with actual filesystems
}
