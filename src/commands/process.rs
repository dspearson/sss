use anyhow::{anyhow, Result};
use clap::ArgMatches;
use std::fs;
use std::io::{self, Read, Write};
use std::path::Path;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

#[cfg(target_os = "linux")]
use std::ffi::CString;
#[cfg(target_os = "linux")]
use std::os::unix::ffi::OsStrExt;

use crate::{
    commands::utils, config::load_project_config_with_repository_key, editor::launch_editor,
    validation::validate_file_path, Processor,
};

/// Check if a file is on a FUSE filesystem
#[cfg(target_os = "linux")]
fn is_fuse_mount(file_path: &Path) -> Result<bool> {
    use std::mem;

    const FUSE_SUPER_MAGIC: i64 = 0x65735546;

    let path_cstr = CString::new(file_path.as_os_str().as_bytes())?;

    unsafe {
        let mut stat: libc::statfs = mem::zeroed();
        let result = libc::statfs(path_cstr.as_ptr(), &mut stat);

        if result != 0 {
            return Err(anyhow!("Failed to stat filesystem"));
        }

        Ok(stat.f_type == FUSE_SUPER_MAGIC)
    }
}

#[cfg(not(target_os = "linux"))]
fn is_fuse_mount(_file_path: &Path) -> Result<bool> {
    Ok(false)
}


fn handle_stdin_process(matches: &ArgMatches) -> Result<()> {
    let render = matches.get_flag("render");

    // in-place and edit don't make sense for stdin
    if matches.get_flag("in-place") {
        return Err(anyhow!("Cannot use --in-place with stdin"));
    }
    if matches.get_flag("edit") {
        return Err(anyhow!("Cannot use --edit with stdin"));
    }

    let (_config, processor, _project_root) = utils::create_processor_from_project_config()?;

    // Read from stdin
    let mut input = String::new();
    io::stdin().read_to_string(&mut input)?;

    // Process content
    let output = if render {
        processor.decrypt_to_raw(&input)?
    } else {
        processor.process_content(&input)?
    };

    // Write to stdout
    print!("{}", output);
    io::stdout().flush()?;

    Ok(())
}

pub fn handle_process(matches: &ArgMatches) -> Result<()> {
    if let Some(file_path_str) = matches.get_one::<String>("file") {
        // Handle stdin if file is "-"
        if file_path_str == "-" {
            return handle_stdin_process(matches);
        }

        let file_path = validate_file_path(file_path_str)?;
        let in_place = matches.get_flag("in-place");
        let render = matches.get_flag("render");
        let edit = matches.get_flag("edit");

        let (_config, processor, _project_root) = utils::create_processor_from_project_config()?;

        if render {
            // Processor already created above

            if !file_path.exists() {
                return Err(anyhow!("File does not exist: {:?}", file_path));
            }

            // Read and process the file content to raw text
            let content = fs::read_to_string(&file_path)?;
            let raw_content = processor.decrypt_to_raw_with_path(&content, &file_path)?;

            if in_place {
                // In-place render: replace file with rendered content
                fs::write(&file_path, raw_content)?;
                eprintln!("File rendered in-place: {:?}", file_path);
            } else {
                // Output to stdout
                print!("{}", raw_content);
            }
            return Ok(());
        }

        // Processor already created above, continue with edit or regular processing

        if edit {
            // Edit mode: decrypt -> edit -> encrypt
            if !file_path.exists() {
                return Err(anyhow!("File does not exist: {:?}", file_path));
            }

            // Read and prepare content for editing
            let content = fs::read_to_string(&file_path)?;
            let edit_content = processor.prepare_for_editing(&content)?;

            // Write to temporary file
            let temp_path = format!("{}.tmp", file_path.to_string_lossy());
            fs::write(&temp_path, edit_content)?;

            #[cfg(unix)]
            {
                let mut perms = fs::metadata(&temp_path)?.permissions();
                perms.set_mode(0o600);
                fs::set_permissions(&temp_path, perms)?;
            }

            // Launch editor
            launch_editor(Path::new(&temp_path))?;

            // Read back and finalize
            let edited_content = fs::read_to_string(&temp_path)?;
            let final_content = processor.finalise_after_editing(&edited_content)?;

            // Check if content actually changed
            if final_content == content {
                fs::remove_file(temp_path)?;
                println!("No changes made");
                return Ok(());
            }

            // Write final content
            fs::write(&file_path, final_content)?;
            fs::remove_file(temp_path)?;

            println!("File edited and encrypted: {:?}", file_path);
        } else {
            // Regular processing mode
            if !file_path.exists() {
                return Err(anyhow!("File does not exist: {:?}", file_path));
            }

            let content = fs::read_to_string(&file_path)?;
            let processed_content = processor.process_content(&content)?;

            if in_place {
                fs::write(&file_path, processed_content)?;
                println!("File processed in-place: {:?}", file_path);
            } else {
                // Output to stdout
                print!("{}", processed_content);
                io::stdout().flush()?;
            }
        }

        Ok(())
    } else {
        Err(anyhow!("No file specified for processing"))
    }
}

/// Process a file or stdin with a specific operation
fn process_file_or_stdin(sub_matches: &ArgMatches, operation: &str) -> Result<()> {
    let file_path_str = sub_matches.get_one::<String>("file").unwrap();
    let in_place = sub_matches.get_flag("in-place");

    // Load project config and repository key
    let (_config, processor, _project_root) = utils::create_processor_from_project_config()?;

    // Handle stdin
    if file_path_str == "-" {
        if in_place {
            return Err(anyhow!("Cannot use --in-place with stdin"));
        }

        let mut input = String::new();
        io::stdin().read_to_string(&mut input)?;

        let output = match operation {
            "seal" => processor.encrypt_content(&input)?,
            "open" => processor.decrypt_content(&input)?,
            "render" => processor.decrypt_to_raw(&input)?,
            _ => unreachable!(),
        };

        print!("{}", output);
        io::stdout().flush()?;
        return Ok(());
    }

    // Handle file
    let file_path = validate_file_path(file_path_str)?;

    if !file_path.exists() {
        return Err(anyhow!("File does not exist: {:?}", file_path));
    }

    let content = fs::read_to_string(&file_path)?;
    let output = match operation {
        "seal" => processor.encrypt_content(&content)?,
        "open" => processor.decrypt_content(&content)?,
        "render" => processor.decrypt_to_raw_with_path(&content, &file_path)?,
        _ => unreachable!(),
    };

    if in_place {
        fs::write(&file_path, &output)?;
        eprintln!("File processed in-place: {:?}", file_path);
    } else {
        print!("{}", output);
        io::stdout().flush()?;
    }

    Ok(())
}

/// Handle 'seal' command - encrypt plaintext markers
pub fn handle_seal(_main_matches: &ArgMatches, sub_matches: &ArgMatches) -> Result<()> {
    process_file_or_stdin(sub_matches, "seal")
}

/// Handle 'open' command - decrypt ciphertext to plaintext markers
pub fn handle_open(_main_matches: &ArgMatches, sub_matches: &ArgMatches) -> Result<()> {
    process_file_or_stdin(sub_matches, "open")
}

/// Handle 'render' command - decrypt to raw text (remove all markers)
pub fn handle_render(_main_matches: &ArgMatches, sub_matches: &ArgMatches) -> Result<()> {
    process_file_or_stdin(sub_matches, "render")
}

/// Handle 'edit' command - edit file with automatic encrypt/decrypt
/// Edit file on FUSE mount using sealed mode protocol
#[cfg(target_os = "linux")]
fn handle_edit_fuse(file_path: &Path, processor: &Processor) -> Result<()> {
    use std::os::unix::io::AsRawFd;
    use std::os::unix::fs::OpenOptionsExt;
    use std::ffi::CString;
    use std::io::{Write, Seek, SeekFrom};

    // Open file with O_NONBLOCK + O_RDWR for sealed mode protocol
    let mut fuse_file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(file_path)?;

    let fuse_fd = fuse_file.as_raw_fd();

    // Signal to FUSE that we want sealed content
    let xattr_name = CString::new("user.sss.sealed").unwrap();
    let xattr_value = b"1";

    let setxattr_result = unsafe {
        libc::fsetxattr(
            fuse_fd,
            xattr_name.as_ptr(),
            xattr_value.as_ptr() as *const libc::c_void,
            xattr_value.len(),
            0,
        )
    };

    if setxattr_result != 0 {
        let err = std::io::Error::last_os_error();
        return Err(anyhow!("Failed to confirm sealed mode with fsetxattr: {}", err));
    }

    // Read sealed content (with retry for EAGAIN)
    let sealed_content = read_sealed_content_with_retry(&mut fuse_file)?;

    // Decrypt sealed content
    let edit_content = processor.decrypt_content(&sealed_content)?;

    // Create secure temp file in /dev/shm (or /tmp as fallback)
    let temp_path = create_secure_temp_path(file_path)?;

    // Write decrypted content to temp file
    write_temp_file_secure(&temp_path, &edit_content)?;

    // Launch editor
    launch_editor(Path::new(&temp_path))?;

    // Read edited content
    let edited_content = std::fs::read_to_string(&temp_path)?;

    // Securely remove temp file
    std::fs::remove_file(&temp_path)?;

    // Encrypt edited content
    let final_sealed_content = processor.encrypt_content(&edited_content)?;

    // Check if content actually changed
    if final_sealed_content == sealed_content {
        eprintln!("No changes made");
        return Ok(());
    }

    // Write sealed content back to FUSE file descriptor
    fuse_file.seek(SeekFrom::Start(0))?;
    fuse_file.set_len(0)?;
    fuse_file.write_all(final_sealed_content.as_bytes())?;
    fuse_file.flush()?;

    eprintln!("File edited and encrypted via FUSE: {:?}", file_path);
    Ok(())
}

/// Read sealed content from FUSE with EAGAIN retry logic
#[cfg(target_os = "linux")]
fn read_sealed_content_with_retry(fuse_file: &mut std::fs::File) -> Result<String> {
    use std::io::{Read, Seek, SeekFrom};

    let mut sealed_content = String::new();
    let mut retries = 0;
    const MAX_RETRIES: u32 = 10;

    loop {
        sealed_content.clear();
        match fuse_file.read_to_string(&mut sealed_content) {
            Ok(_) => return Ok(sealed_content),
            Err(e) if e.raw_os_error() == Some(libc::EAGAIN) && retries < MAX_RETRIES => {
                std::thread::sleep(std::time::Duration::from_millis(10));
                retries += 1;
                fuse_file.seek(SeekFrom::Start(0))?;
            }
            Err(e) => return Err(anyhow!("Failed to read sealed content: {}", e)),
        }
    }
}

/// Create secure temp file path in /dev/shm or /tmp
#[cfg(target_os = "linux")]
fn create_secure_temp_path(file_path: &Path) -> Result<String> {
    let file_name = file_path.file_name().unwrap_or_default().to_string_lossy();
    let pid = std::process::id();

    if Path::new("/dev/shm").exists() {
        Ok(format!("/dev/shm/.sss-edit-{}-{}", file_name, pid))
    } else {
        eprintln!("[WARN] /dev/shm not available, using /tmp (insecure!)");
        Ok(format!("/tmp/.sss-edit-{}-{}", file_name, pid))
    }
}

/// Write content to temp file with secure permissions
#[cfg(unix)]
fn write_temp_file_secure(temp_path: &str, content: &str) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    use std::io::Write;

    let mut temp_file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(temp_path)?;
    temp_file.write_all(content.as_bytes())?;
    Ok(())
}

/// Edit regular file (not on FUSE mount)
fn handle_edit_regular(file_path: &Path, processor: &Processor) -> Result<()> {
    let content = fs::read_to_string(file_path)?;
    let edit_content = processor.prepare_for_editing(&content)?;

    // Create secure temp file
    let temp_file_name = format!(
        "sss-edit-{}-{}.tmp",
        file_path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("file"),
        std::process::id()
    );
    let temp_path = std::env::temp_dir().join(temp_file_name);

    // Write with restrictive permissions
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        use std::io::Write;
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&temp_path)?
            .write_all(edit_content.as_bytes())?;
    }

    #[cfg(not(unix))]
    {
        fs::write(&temp_path, edit_content)?;
    }

    // Launch editor
    launch_editor(&temp_path)?;

    // Read edited content and finalize
    let edited_content = fs::read_to_string(&temp_path)?;
    let final_content = processor.finalise_after_editing(&edited_content)?;

    // Write back to original file
    fs::write(file_path, final_content)?;

    // Securely remove temp file
    fs::remove_file(&temp_path)?;

    eprintln!("File edited and encrypted: {:?}", file_path);
    Ok(())
}

/// Main edit handler - dispatches to FUSE or regular file handler
pub fn handle_edit(_main_matches: &ArgMatches, sub_matches: &ArgMatches) -> Result<()> {
    let file_path_str = sub_matches.get_one::<String>("file").unwrap();

    if file_path_str == "-" {
        return Err(anyhow!("Cannot use edit mode with stdin"));
    }

    let file_path = validate_file_path(file_path_str)?;

    if !file_path.exists() {
        return Err(anyhow!("File does not exist: {:?}", file_path));
    }

    // Find project config and load repository key
    let file_dir = file_path.parent().ok_or_else(|| anyhow!("File has no parent directory"))?;
    let config_path = crate::config::get_project_config_path_from(file_dir)?;
    let (config, repository_key, project_root) = load_project_config_with_repository_key(config_path)?;
    let processor = Processor::new_with_context(repository_key, project_root, config.created.clone())?;

    // Dispatch to appropriate handler based on mount type
    if is_fuse_mount(&file_path).unwrap_or(false) {
        #[cfg(target_os = "linux")]
        {
            handle_edit_fuse(&file_path, &processor)
        }

        #[cfg(not(target_os = "linux"))]
        {
            Err(anyhow!("FUSE editing is only available on Linux"))
        }
    } else {
        handle_edit_regular(&file_path, &processor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    #[cfg(target_os = "linux")]
    fn test_is_fuse_mount_non_fuse_path() {
        // Test with a regular non-FUSE path
        let path = PathBuf::from("/tmp");
        let result = is_fuse_mount(&path);

        // Should succeed and return false for non-FUSE mounts
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[test]
    #[cfg(not(target_os = "linux"))]
    fn test_is_fuse_mount_non_linux() {
        // On non-Linux, always returns false
        let path = PathBuf::from("/tmp/test");
        let result = is_fuse_mount(&path);

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), false);
    }

    #[test]
    fn test_create_secure_temp_path() {
        // Test that secure temp path generation works
        let file_path = PathBuf::from("/tmp/test_file.txt");
        let result = create_secure_temp_path(&file_path);

        assert!(result.is_ok());
        let temp_path = result.unwrap();

        // Should use /dev/shm if available, otherwise /tmp
        assert!(temp_path.starts_with("/dev/shm/.sss-edit-") || temp_path.starts_with("/tmp/.sss-edit-"));
        assert!(temp_path.contains("test_file.txt"));
        // Should include process ID
        assert!(temp_path.contains(&std::process::id().to_string()));
    }

    // Note: Most of process.rs involves complex file processing:
    // - Reading/writing encrypted files
    // - FUSE mount detection and special handling
    // - Smart merge algorithm for git integration
    // - Editor integration
    // - Project-wide file scanning
    // These are tested through:
    // - processor module (encryption/decryption logic)
    // - merge module (smart reconstruction)
    // - scanner module (file discovery)
    // - Integration tests (full command workflows)
}
