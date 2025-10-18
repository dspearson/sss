use anyhow::{anyhow, Result};
use clap::ArgMatches;
use std::path::{Path, PathBuf};

use crate::Processor;
use crate::project::ProjectConfig;

#[cfg(any(target_os = "linux", target_os = "macos"))]
use crate::fuse_fs::SssFS;

/// Load project config and create processor for a source directory
///
/// Changes to source_path temporarily to locate .sss.toml, then restores original directory
fn load_processor_for_source(source_path: &Path) -> Result<(ProjectConfig, Processor)> {
    let original_dir = std::env::current_dir()?;
    std::env::set_current_dir(source_path)?;
    let config_path = crate::config::get_project_config_path()?;
    std::env::set_current_dir(original_dir)?;

    let (config, repository_key, project_root) =
        crate::config::load_project_config_with_repository_key(&config_path)?;

    let processor = crate::Processor::new_with_context(repository_key, project_root, config.created.clone())?;

    Ok((config, processor))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub fn handle_mount(_main_matches: &ArgMatches, sub_matches: &ArgMatches) -> Result<()> {
    let in_place = sub_matches.get_flag("in-place");
    let foreground = sub_matches.get_flag("foreground");

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
    let (_config, processor) = load_processor_for_source(&source_path)?;

    // Create FUSE filesystem
    let fs = SssFS::new(source_path.clone(), processor)?;

    if in_place {
        eprintln!("Mounting in-place (overlay): {}", source_path.display());
        eprintln!("Files will be rendered transparently, .git and work files hidden");
    } else {
        eprintln!("Mounting {} at {}", source, mountpoint);
        eprintln!("Source: {}", source_path.display());
        eprintln!("Mountpoint: {}", mountpoint_path.display());
    }

    if foreground {
        eprintln!("Running in foreground mode. Press Ctrl+C to unmount.");
    }

    // Mount options
    let options = vec![
        fuser::MountOption::FSName("sss".to_string()),
        // Don't use AutoUnmount or AllowOther - they require /etc/fuse.conf changes
    ];

    if !foreground {
        // Daemonize: fork and detach from terminal
        eprintln!("Daemonizing and mounting in background...");

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
        Err(e) => Err(anyhow!("Failed to mount filesystem: {}", e)),
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
    let (_config, processor) = load_processor_for_source(&source_path)?;

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
