use anyhow::{anyhow, Result};
use clap::ArgMatches;
use std::fs;
use std::io::{self, Read, Write};
use std::path::Path;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

#[cfg(target_os = "linux")]
use std::ffi::CString;

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

use crate::{
    commands::utils, config::load_project_config_with_repository_key,
    constants::{ERR_STDIN_EDIT, ERR_STDIN_IN_PLACE},
    editor::launch_editor, validation::validate_file_path, Processor,
};

/// Check if a file is on a FUSE filesystem (Linux)
#[cfg(target_os = "linux")]
fn is_fuse_mount(file_path: &Path) -> Result<bool> {
    use std::mem;
    use std::os::unix::ffi::OsStrExt;

    const FUSE_SUPER_MAGIC: i64 = 0x65735546;

    let path_cstr = CString::new(file_path.as_os_str().as_bytes())?;

    unsafe {
        let mut stat: libc::statfs = mem::zeroed();
        let result = libc::statfs(path_cstr.as_ptr(), &mut stat);

        if result != 0 {
            return Err(anyhow!("Failed to stat filesystem"));
        }

        Ok(stat.f_type as i64 == FUSE_SUPER_MAGIC)
    }
}

/// Check if a file is on a FUSE filesystem (macOS)
#[cfg(target_os = "macos")]
fn is_fuse_mount(file_path: &Path) -> Result<bool> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    use std::mem;

    let path_cstr = CString::new(file_path.as_os_str().as_bytes())?;

    unsafe {
        let mut stat: libc::statfs = mem::zeroed();
        let result = libc::statfs(path_cstr.as_ptr(), &mut stat);

        if result != 0 {
            return Err(anyhow!("Failed to stat filesystem"));
        }

        // On macOS, check if the filesystem type name contains "fuse" or "osxfuse" or "macfuse"
        let fs_typename = std::ffi::CStr::from_ptr(stat.f_fstypename.as_ptr())
            .to_string_lossy()
            .to_lowercase();

        Ok(fs_typename.contains("fuse") || fs_typename.contains("osxfuse") || fs_typename.contains("macfuse"))
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn is_fuse_mount(_file_path: &Path) -> Result<bool> {
    Ok(false)
}


fn handle_stdin_process(matches: &ArgMatches) -> Result<()> {
    let render = matches.get_flag("render");

    // in-place and edit don't make sense for stdin
    if matches.get_flag("in-place") {
        return Err(anyhow!(ERR_STDIN_IN_PLACE));
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
            return Err(anyhow!(ERR_STDIN_IN_PLACE));
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
        "seal" => processor.seal_content_with_path(&content, &file_path)?,
        "open" => processor.open_content_with_path(&content, &file_path)?,
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
    // Check if --project flag is set
    if sub_matches.get_flag("project") {
        return process_project_recursively("seal");
    }

    process_file_or_stdin(sub_matches, "seal")
}

/// Handle 'open' command - decrypt ciphertext to plaintext markers
pub fn handle_open(_main_matches: &ArgMatches, sub_matches: &ArgMatches) -> Result<()> {
    // Check if --project flag is set
    if sub_matches.get_flag("project") {
        return process_project_recursively("open");
    }

    process_file_or_stdin(sub_matches, "open")
}

/// Handle 'render' command - decrypt to raw text (remove all markers)
pub fn handle_render(_main_matches: &ArgMatches, sub_matches: &ArgMatches) -> Result<()> {
    // Check if --project flag is set
    if sub_matches.get_flag("project") {
        return process_project_recursively("render");
    }

    process_file_or_stdin(sub_matches, "render")
}

/// Build a GlobSet from ignore patterns in the project config
/// Returns None if no patterns are configured or if building fails
fn build_ignore_globset(config: &crate::project::ProjectConfig) -> Option<globset::GlobSet> {
    use globset::{Glob, GlobSetBuilder};

    let patterns = config.get_ignore_pattern_strings();
    if patterns.is_empty() {
        return None;
    }

    let mut builder = GlobSetBuilder::new();
    for pattern in patterns {
        match Glob::new(&pattern) {
            Ok(glob) => {
                builder.add(glob);
            }
            Err(e) => {
                eprintln!("Warning: Invalid ignore pattern '{}': {}", pattern, e);
            }
        }
    }

    match builder.build() {
        Ok(globset) => Some(globset),
        Err(e) => {
            eprintln!("Warning: Failed to build ignore pattern matcher: {}", e);
            None
        }
    }
}

/// Walk up from `path` to find the nearest project root in `projects` or `passthrough`.
///
/// Returns `Some((root, processor, ignore_globset))` if we find a matching project,
/// or `None` if the file falls inside a passthrough (no-keys) root or has no project.
fn find_project_for_path<'a>(
    path: &Path,
    projects: &'a HashMap<PathBuf, (Processor, Option<globset::GlobSet>)>,
    passthrough: &HashSet<PathBuf>,
) -> Option<(&'a PathBuf, &'a Processor, &'a Option<globset::GlobSet>)> {
    let mut current = path.parent();
    while let Some(dir) = current {
        if passthrough.contains(dir) {
            return None;
        }
        if let Some((proc, gs)) = projects.get(dir) {
            return Some((
                // SAFETY: the key exists, we can get a reference to it from the map
                projects.keys().find(|k| *k == dir).unwrap(),
                proc,
                gs,
            ));
        }
        current = dir.parent();
    }
    None
}

/// Recursively process all files in the project with the given operation.
/// Detects nested project boundaries and uses each project's own key.
/// Projects where the current user has no keys are silently skipped.
/// IMPORTANT: Does not follow symlinks outside the project boundary.
fn process_project_recursively(operation: &str) -> Result<()> {
    use std::fs;
    use walkdir::WalkDir;

    // Find the project root (where .sss.toml is)
    let project_root = crate::config::find_project_root()?;

    // Check permissions for project-wide operations (unless bypassed by environment variable)
    let bypass_open = std::env::var("SSS_PROJECT_OPEN").is_ok_and(|v| v == "true" || v == "1");
    let bypass_render = std::env::var("SSS_PROJECT_RENDER").is_ok_and(|v| v == "true" || v == "1");

    if !bypass_open && !bypass_render {
        // Load config manager to check permissions
        let config_manager = crate::config_manager::ConfigManager::new()?;

        match operation {
            "open" => {
                if !config_manager.is_project_open_enabled(&project_root)? {
                    return Err(anyhow!(
                        "Automatic project-wide opening is disabled.\n\
                        To enable, run: sss project enable open\n\
                        Or use: SSS_PROJECT_OPEN=true sss open --project"
                    ));
                }
            }
            "render" => {
                if !config_manager.is_project_render_enabled(&project_root)? {
                    return Err(anyhow!(
                        "Automatic project-wide rendering is disabled.\n\
                        To enable, run: sss project enable render\n\
                        Or use: SSS_PROJECT_RENDER=true sss render --project"
                    ));
                }
            }
            _ => {} // seal and other operations don't require permission
        }
    }

    // Canonicalize the project root to get absolute path for boundary checking
    let canonical_project_root = fs::canonicalize(&project_root)
        .map_err(|e| anyhow!("Failed to canonicalize project root: {}", e))?;

    // Load root project config and processor
    let (config, processor, _) = utils::create_processor_from_project_config()?;

    // Build per-project maps: project_root → (Processor, ignore_globset)
    let mut projects: HashMap<PathBuf, (Processor, Option<globset::GlobSet>)> = HashMap::new();
    let mut passthrough_roots: HashSet<PathBuf> = HashSet::new();

    // Seed with root project
    let root_ignore = build_ignore_globset(&config);
    projects.insert(project_root.clone(), (processor, root_ignore));

    let mut processed_count = 0;
    let mut error_count = 0;

    let operation_verb = match operation {
        "seal" => "Sealed",
        "open" => "Opened",
        "render" => "Rendered",
        _ => "Processed",
    };

    // Walk the project directory
    for entry in WalkDir::new(&project_root)
        .follow_links(false)  // Don't follow symlinks at all during traversal
        .into_iter()
        .filter_entry(|e| {
            // Skip hidden directories and files (except .sss.toml)
            let name = e.file_name().to_string_lossy();
            if name.starts_with('.') && name != ".sss.toml" {
                return false;
            }

            // Skip common non-text directories
            if e.file_type().is_dir() {
                let skip_dirs = ["target", "node_modules", ".git", "dist", "build"];
                return !skip_dirs.contains(&name.as_ref());
            }

            true
        })
    {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                eprintln!("Warning: Error accessing entry: {}", e);
                error_count += 1;
                continue;
            }
        };

        let path = entry.path();

        // When we encounter a directory (not root) with .sss.toml, register it
        if entry.file_type().is_dir() && path != project_root {
            let nested_config_path = path.join(".sss.toml");
            if nested_config_path.exists() {
                match utils::try_create_processor_for_config(&nested_config_path) {
                    Ok(Some((nested_config, nested_processor))) => {
                        let nested_ignore = build_ignore_globset(&nested_config);
                        projects.insert(path.to_path_buf(), (nested_processor, nested_ignore));
                    }
                    Ok(None) => {
                        eprintln!(
                            "Note: Skipping nested project at {} (no matching keys)",
                            path.display()
                        );
                        passthrough_roots.insert(path.to_path_buf());
                    }
                    Err(e) => {
                        eprintln!(
                            "Warning: Cannot load nested project at {}: {}",
                            path.display(), e
                        );
                        passthrough_roots.insert(path.to_path_buf());
                    }
                }
            }
            continue;
        }

        // Only process files
        if !entry.file_type().is_file() {
            continue;
        }

        // Find the nearest project for this file
        let (proj_root, proj_processor, proj_ignore) =
            match find_project_for_path(path, &projects, &passthrough_roots) {
                Some(found) => found,
                None => continue, // in a passthrough zone — skip silently
            };

        // Check per-project ignore patterns
        if let Some(globset) = proj_ignore {
            if let Ok(rel_path) = path.strip_prefix(proj_root) {
                if globset.is_match(rel_path) {
                    continue;
                }
            }
        }

        // Additional safety: Check if the entry is a symlink and resolve it
        // to ensure it stays within project boundaries
        if entry.path_is_symlink() {
            match fs::canonicalize(path) {
                Ok(target) => {
                    // Check if symlink target is outside project root
                    if !target.starts_with(&canonical_project_root) {
                        continue;
                    }
                }
                Err(_) => {
                    // Cannot resolve symlink, skip it
                    continue;
                }
            }
        }

        // Skip binary files
        if is_binary_file(path)? {
            continue;
        }

        // Skip files that don't have any markers
        let content = match fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => {
                // Likely binary or unreadable
                continue;
            }
        };

        // Check if file has any SSS markers
        if !has_sss_markers(&content) {
            continue;
        }

        // Process the file in-place with the correct project's processor
        match process_file_in_place(path, proj_processor, operation) {
            Ok(changed) => {
                if changed {
                    println!("{}: {}", operation_verb, path.display());
                    processed_count += 1;
                }
            }
            Err(e) => {
                eprintln!("Error processing {}: {}", path.display(), e);
                error_count += 1;
            }
        }
    }

    if processed_count > 0 {
        println!("\n{} {} file(s)", operation_verb, processed_count);
    }

    if error_count > 0 {
        return Err(anyhow!("Failed to {} {} file(s)", operation, error_count));
    }

    Ok(())
}

/// Check if a file has any SSS markers
fn has_sss_markers(content: &str) -> bool {
    content.contains("⊠{") || content.contains("⊕{") ||
    content.contains("o+{") || content.contains("⊲{") ||
    content.contains("<{")
}

/// Process a single file in-place with the given operation, returns true if file was modified
fn process_file_in_place(path: &Path, processor: &crate::processor::core::Processor, operation: &str) -> Result<bool> {
    use std::fs;

    let original_content = fs::read_to_string(path)?;

    let processed_content = match operation {
        "seal" => processor.seal_content_with_path(&original_content, path)?,
        "open" => processor.open_content_with_path(&original_content, path)?,
        "render" => processor.decrypt_to_raw_with_path(&original_content, path)?,
        _ => return Err(anyhow!("Unknown operation: {}", operation)),
    };

    // Check if content actually changed
    if processed_content == original_content {
        return Ok(false);
    }

    // Write the processed content back
    fs::write(path, processed_content)?;

    Ok(true)
}

/// Check if a file appears to be binary
fn is_binary_file(path: &Path) -> Result<bool> {
    use std::fs::File;
    use std::io::Read;

    let mut file = File::open(path)?;
    let mut buffer = [0u8; 8192];
    let bytes_read = file.read(&mut buffer)?;

    // Check for null bytes in first 8KB (common binary indicator)
    Ok(buffer[..bytes_read].contains(&0))
}

/// Handle 'edit' command - edit file with automatic encrypt/decrypt
/// Edit file on FUSE mount using opened mode protocol
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn handle_edit_fuse(file_path: &Path, processor: &Processor) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    use std::io::{Read, Write, Seek, SeekFrom};

    // Open file with O_DIRECTORY | O_CREAT for opened mode (semantically invalid combination)
    // This signals FUSE to return content with ⊕{} markers for editing
    let mut fuse_file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_CREAT)
        .open(file_path)?;

    // Read opened content (with ⊕{} markers for editing)
    let mut sealed_content = String::new();
    fuse_file.read_to_string(&mut sealed_content)?;

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

    eprintln!("File edited and encrypted: {:?}", file_path);
    Ok(())
}

/// Create secure temp file path in /dev/shm (Linux) or /tmp (macOS)
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

/// Create secure temp file path in /tmp (macOS)
#[cfg(target_os = "macos")]
fn create_secure_temp_path(file_path: &Path) -> Result<String> {
    let file_name = file_path.file_name().unwrap_or_default().to_string_lossy();
    let pid = std::process::id();
    // On macOS, /tmp is more secure than on Linux (cleared on reboot, per-user isolation)
    Ok(format!("/tmp/.sss-edit-{}-{}", file_name, pid))
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
        write_temp_file_secure(temp_path.to_str().unwrap(), &edit_content)?;
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

    // Securely remove temp file
    fs::remove_file(&temp_path)?;

    // Check if content actually changed
    if final_content == content {
        eprintln!("No changes made");
        return Ok(());
    }

    // Write back to original file
    fs::write(file_path, final_content)?;

    eprintln!("File edited and encrypted: {:?}", file_path);
    Ok(())
}

/// Main edit handler - dispatches to FUSE or regular file handler
pub fn handle_edit(_main_matches: &ArgMatches, sub_matches: &ArgMatches) -> Result<()> {
    let file_path_str = sub_matches.get_one::<String>("file").unwrap();

    if file_path_str == "-" {
        return Err(anyhow!(ERR_STDIN_EDIT));
    }

    let file_path = validate_file_path(file_path_str)?;

    if !file_path.exists() {
        return Err(anyhow!("File does not exist: {:?}", file_path));
    }

    // Find project config and load repository key
    let file_dir = file_path.parent().ok_or_else(|| anyhow!("File has no parent directory"))?;
    let config_path = crate::config::get_project_config_path_from(file_dir)?;
    let (config, repository_key, project_root) = load_project_config_with_repository_key(config_path)?;
    let secrets_filename = config.get_secrets_filename().to_string();
    let processor = Processor::new_with_context_and_secrets_filename(
        repository_key,
        project_root,
        config.created.clone(),
        secrets_filename,
    )?;

    // Dispatch to appropriate handler based on mount type
    if is_fuse_mount(&file_path).unwrap_or(false) {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            handle_edit_fuse(&file_path, &processor)
        }

        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            Err(anyhow!("FUSE editing is only available on Linux and macOS"))
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
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn test_is_fuse_mount_non_fuse_path() {
        // Test with a regular non-FUSE path
        let path = PathBuf::from("/tmp");
        let result = is_fuse_mount(&path);

        // Should succeed and return false for non-FUSE mounts
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[test]
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    fn test_is_fuse_mount_non_unix() {
        // On non-Linux/macOS, always returns false
        let path = PathBuf::from("/tmp/test");
        let result = is_fuse_mount(&path);

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), false);
    }

    #[test]
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn test_create_secure_temp_path() {
        // Test that secure temp path generation works
        let file_path = PathBuf::from("/tmp/test_file.txt");
        let result = create_secure_temp_path(&file_path);

        assert!(result.is_ok());
        let temp_path = result.unwrap();

        // Linux: should use /dev/shm if available, otherwise /tmp
        // macOS: always uses /tmp
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
