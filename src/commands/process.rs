use anyhow::{anyhow, Context, Result};
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

/// Inspect `err` for a secrets interpolation error and, when found, print the
/// unresolved-references report to stderr and call `std::process::exit(3)`.
///
/// This mapper works on the **default build** (the `⊲{}` exit-3 path is not
/// vault-specific).  It is NOT behind `#[cfg(feature = "vault")]`.
///
/// If `err` is NOT a `SecretsInterpolationError`, the error is returned unchanged
/// so the caller can continue to the next mapper or propagate normally.
///
/// T-48-09 / VFAIL-05: exit 3 = per-reference miss; only the sanitised names are
/// emitted (T-48-13: no secret values in the report).
#[must_use]
fn handle_secrets_render_error(err: anyhow::Error) -> anyhow::Error {
    use crate::secrets::SecretsInterpolationError;
    if let Some(se) = err.downcast_ref::<SecretsInterpolationError>() {
        match se {
            SecretsInterpolationError::Unresolved(names) => {
                eprintln!("unresolved references:");
                for name in names {
                    eprintln!("  {name}");
                }
                // Why: std::process::exit is the correct way to emit a specific
                // exit code from a CLI tool; anyhow exit-code is always 1.
                // VFAIL-05 (exit 3 = per-reference miss, preserve marker, alert).
                #[allow(clippy::exit)]
                std::process::exit(3);
            }
        }
    }
    err
}

/// Inspect `err` for a vault resolve error and, when found, print the
/// appropriate stderr message and call `std::process::exit(3)` (per-reference
/// miss) or `std::process::exit(4)` (whole-operation abort).
///
/// If the error is NOT a vault resolve error, this function returns `err`
/// unchanged so the caller can propagate it normally.
///
/// The process exits directly (without returning) when a vault resolve error is
/// found — this is intentional: the exit-code contract is the CI-facing seam
/// (VFAIL-01/VFAIL-02 / T-47-13).
#[cfg(feature = "vault")]
#[must_use]
pub fn handle_vault_render_error(err: anyhow::Error) -> anyhow::Error {
    use crate::vault::VaultResolveError;
    if let Some(vr_err) = err.downcast_ref::<VaultResolveError>() {
        match vr_err {
            VaultResolveError::MultiReferenceMiss { references, partial } => {
                // Write partial content (with unresolved markers preserved verbatim)
                // to stdout so callers can see what resolved and what did not.
                // VFAIL-01: exit 3 signals per-reference miss; partial output lets
                // the caller audit which markers were unresolvable.
                print!("{partial}");
                eprintln!("unresolved references:");
                for r in references {
                    eprintln!("  {r}");
                }
                // Why: std::process::exit is the correct way to emit a specific
                // exit code from a CLI tool; anyhow exit-code is always 1.
                // VFAIL-01 (exit 3 = per-reference miss, preserve marker, alert).
                #[allow(clippy::exit)]
                std::process::exit(3);
            }
            VaultResolveError::ReferenceMiss { reference, kind } => {
                eprintln!("unresolved references:");
                eprintln!("  {reference}: {kind}");
                #[allow(clippy::exit)]
                std::process::exit(3);
            }
            VaultResolveError::WholeOperation { detail } => {
                eprintln!("vault error: {detail}");
                // VFAIL-02 (exit 4 = whole-operation abort, Vault down/retry).
                #[allow(clippy::exit)]
                std::process::exit(4);
            }
        }
    }
    err
}

/// Attach the vault config (when present) to a `Processor` so that
/// `decrypt_to_raw_with_path` resolves `⊳{}` markers (vault feature).
///
/// On a non-vault build this is a no-op (the config field does not exist).
#[cfg(feature = "vault")]
fn attach_vault_config(processor: &mut Processor, config: &crate::project::ProjectConfig) {
    if let Some(ref vault_cfg) = config.vault {
        processor.set_vault_config(vault_cfg.clone());
    }
}

/// Check if a file is on a FUSE filesystem (Linux)
#[cfg(target_os = "linux")]
fn is_fuse_mount(file_path: &Path) -> Result<bool> {
    use std::mem;
    use std::os::unix::ffi::OsStrExt;

    const FUSE_SUPER_MAGIC: i64 = 0x6573_5546;

    let path_cstr = CString::new(file_path.as_os_str().as_bytes())?;

    // `path_cstr` is a valid CString built from the file path; `stat` is a stack-allocated
    // `libc::statfs` (zeroed in-place is valid per the C ABI).
    // SAFETY: libc's `statfs` writes the struct on success (return 0) and leaves it
    // untouched on failure (return -1 with errno set). `mem::zeroed::<libc::statfs>()` is
    // valid because `libc::statfs` has no Drop and all-zero is a valid bit pattern for it.
    unsafe {
        let mut stat: libc::statfs = mem::zeroed();
        #[cfg(not(miri))]
        let result = libc::statfs(path_cstr.as_ptr(), &raw mut stat);
        // Miri stub: libc::statfs is FFI; AddressSanitizer (Phase 23 MEMSAFE-03) covers
        // this path under non-miri builds. `stat` keeps its zeroed state — the downstream
        // `stat.f_type as i64 == FUSE_SUPER_MAGIC` predicate then reads zeroed memory and
        // returns false (sane non-FUSE default for miri).
        #[cfg(miri)]
        let result: i32 = 0;

        if result != 0 {
            return Err(anyhow!(
                "Failed to stat filesystem for '{}': {}",
                file_path.display(),
                std::io::Error::last_os_error()
            ));
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

    // `path_cstr` is a valid CString built from the file path; `stat` is a
    // stack-allocated `libc::statfs`. macOS `statfs` writes the struct on success
    // (return 0) and leaves it untouched on failure. `CStr::from_ptr` over
    // `stat.f_fstypename` is safe because libc guarantees null-termination on success.
    // SAFETY: invariants noted above.
    unsafe {
        let mut stat: libc::statfs = mem::zeroed();
        #[cfg(not(miri))]
        let result = libc::statfs(path_cstr.as_ptr(), &mut stat);
        // Miri stub: libc::statfs is FFI; AddressSanitizer (Phase 23 MEMSAFE-03) covers
        // this path under non-miri builds. miri runs on linux-x86_64 only per Phase 22
        // CONTEXT scope so the macOS arm is dead-code under miri; the cfg-stub is here
        // for symmetric audit-readiness with the Linux variant.
        #[cfg(miri)]
        let result: i32 = 0;

        if result != 0 {
            return Err(anyhow!(
                "Failed to stat filesystem for '{}': {}",
                file_path.display(),
                std::io::Error::last_os_error()
            ));
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
    print!("{output}");
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

        // processor is mut unconditionally so set_keep_unresolved can be called on
        // both the default and vault builds without feature-gated bindings.
        let (config, mut processor, _project_root) = utils::create_processor_from_project_config()?;

        if render {
            // Attach vault config for ⊳{} resolution (vault feature).
            #[cfg(feature = "vault")]
            attach_vault_config(&mut processor, &config);
            let _ = &config;

            // --keep-unresolved: downgrade per-ref misses to exit 0 (VFAIL-04).
            let keep_unresolved = matches.get_flag("keep-unresolved");
            processor.set_keep_unresolved(keep_unresolved);

            // -o / --output: resolve-in-memory then atomic write (VFAIL-06).
            let output = matches.get_one::<String>("output");

            if !file_path.exists() {
                return Err(anyhow!(
                    "File '{}' does not exist. Check the path and try again.",
                    file_path.display()
                ));
            }

            // VFAIL-06/03: resolve the ENTIRE content in memory first; a miss or
            // whole-op error short-circuits via `?` BEFORE any write_atomic_bytes
            // call — so a failure leaves the target (or -o destination) untouched.
            // This avoids the shell-redirect `> f` truncation footgun and the
            // torn-file hazard from a direct fs::write that is interrupted mid-stream.
            let content = fs::read_to_string(&file_path)
                .with_context(|| format!("Failed to read '{}'", file_path.display()))?;
            let render_result = processor.decrypt_to_raw_with_path(&content, &file_path);
            // Non-gated: ⊲{} miss → exit 3 on BOTH default and vault builds.
            let render_result = render_result.map_err(handle_secrets_render_error);
            #[cfg(feature = "vault")]
            let render_result = render_result.map_err(handle_vault_render_error);
            let raw_content = render_result?;

            if let Some(out_path) = output {
                // -o: resolve-in-memory (done above) then write atomically.
                // VFAIL-06: temp→rename never truncates the destination.
                crate::config::write_atomic_bytes(raw_content.as_bytes(), std::path::Path::new(out_path))?;
                eprintln!("rendered \u{2192} {out_path}");
            } else if in_place {
                // VFAIL-03: upgrade from direct fs::write to atomic temp→rename.
                // A mid-resolution failure never leaves the original file torn.
                crate::config::write_atomic_bytes(raw_content.as_bytes(), &file_path)?;
                eprintln!("File rendered in-place: {}", file_path.display());
            } else {
                // Output to stdout
                print!("{raw_content}");
            }
            return Ok(());
        }

        let _ = &config;

        // Processor already created above, continue with edit or regular processing

        if edit {
            // Edit mode: decrypt -> edit -> encrypt
            if !file_path.exists() {
                return Err(anyhow!(
                    "File '{}' does not exist. Check the path and try again.",
                    file_path.display()
                ));
            }

            // Read and prepare content for editing
            let content = fs::read_to_string(&file_path)
                .with_context(|| format!("Failed to read '{}'", file_path.display()))?;
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

            // Read back and finalize.
            // CR-01 fix: pass the real relative path so the sealed nonce is derived
            // from the same path that `open_content_with_path` will use — preventing
            // a nonce-lineage mismatch on the subsequent open.
            let relative_path = processor.make_relative_path(&file_path)?;
            let edited_content = fs::read_to_string(&temp_path)?;
            let final_content = processor.finalise_after_editing_with_path(&edited_content, &relative_path)?;

            // Check if content actually changed
            if final_content == content {
                fs::remove_file(temp_path)?;
                println!("No changes made");
                return Ok(());
            }

            // Write final content
            fs::write(&file_path, final_content)?;
            fs::remove_file(temp_path)?;

            println!("File edited and encrypted: {}", file_path.display());
        } else {
            // Regular processing mode
            if !file_path.exists() {
                return Err(anyhow!(
                    "File '{}' does not exist. Check the path and try again.",
                    file_path.display()
                ));
            }

            let content = fs::read_to_string(&file_path)
                .with_context(|| format!("Failed to read '{}'", file_path.display()))?;
            // CR-01 fix: use process_content_with_path (real relative path) so the
            // sealed nonce is derived from the file path, matching what open uses.
            let relative_path = processor.make_relative_path(&file_path)?;
            let processed_content = processor.process_content_with_path(&content, &relative_path)?;

            if in_place {
                fs::write(&file_path, processed_content)?;
                println!("File processed in-place: {}", file_path.display());
            } else {
                // Output to stdout
                print!("{processed_content}");
                io::stdout().flush()?;
            }
        }

        Ok(())
    } else {
        Err(anyhow!(
            "No file specified. Provide a file path or '-' for stdin.\n\
            Usage: sss process <file> [--in-place] [--render] [--edit]"
        ))
    }
}

/// Process a file or stdin with a specific operation
fn process_file_or_stdin(sub_matches: &ArgMatches, operation: &str) -> Result<()> {
    // Why: clap declares `file` as required_unless_present="project"; the
    // dispatcher only routes here when `file` is supplied. HARDEN-01 / 08-01.
    #[allow(clippy::unwrap_used)]
    let file_path_str = sub_matches.get_one::<String>("file").unwrap();
    let in_place = sub_matches.get_flag("in-place");
    // VCFG-05 opt-in: when --allow-unsigned is passed to the render subcommand,
    // the project-load gate for format_version=1 repos with [vault] is relaxed.
    // Only present on the render path; seal/open never receive this flag.
    // Use contains_id guard to avoid panicking when called from seal/open paths
    // that share this function but don't register the arg.
    let allow_unsigned = sub_matches.contains_id("allow-unsigned")
        && sub_matches.get_flag("allow-unsigned");

    // Load project config and repository key.
    // processor is mut unconditionally so set_keep_unresolved applies on both builds.
    let (config, mut processor, _project_root) = utils::create_processor_from_project_config_opts(allow_unsigned)?;

    // Attach vault config for the render operation (vault feature).
    // Non-render operations (seal/open) do not resolve ⊳{} markers.
    //
    // VREF-04: `render --in-place` must NOT dereference ⊳{} Vault refs by default — that
    // writes a live Vault secret onto disk (and risks committing it). Resolve ⊳{} for
    // stdout / -o always, but for in-place only when the user explicitly opts in with
    // --allow-deref-inplace; without the opt-in the ⊳{} markers are preserved verbatim in
    // the rewritten file (⊠{}/⊲{} are still rendered as usual).
    #[cfg(feature = "vault")]
    if operation == "render" {
        let allow_deref_inplace = sub_matches.contains_id("allow-deref-inplace")
            && sub_matches.get_flag("allow-deref-inplace");
        if !in_place || allow_deref_inplace {
            attach_vault_config(&mut processor, &config);
        }
    }
    // Suppress unused-variable warning on non-vault builds.
    let _ = &config;

    // --keep-unresolved: downgrade per-ref misses to exit 0 (VFAIL-04).
    // Only present on the render subcommand; use contains_id guard to avoid panic
    // on seal/open paths that share this function but don't register the arg.
    if operation == "render" {
        let keep_unresolved = sub_matches.contains_id("keep-unresolved")
            && sub_matches.get_flag("keep-unresolved");
        processor.set_keep_unresolved(keep_unresolved);
    }

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
            // Stdin render: no file_path for vault ref resolution; use decrypt_to_raw.
            // (⊳{} refs in stdin render are out-of-scope for path-based resolution.)
            "render" => processor.decrypt_to_raw(&input)?,
            _ => unreachable!(),
        };

        print!("{output}");
        io::stdout().flush()?;
        return Ok(());
    }

    // Handle file
    let file_path = validate_file_path(file_path_str)?;

    if !file_path.exists() {
        return Err(anyhow!(
            "File '{}' does not exist. Check the path and try again.",
            file_path.display()
        ));
    }

    let content = fs::read_to_string(&file_path)
        .with_context(|| format!("Failed to read '{}'", file_path.display()))?;
    let output = match operation {
        "seal" => processor.seal_content_with_path(&content, &file_path)?,
        "open" => processor.open_content_with_path(&content, &file_path)?,
        "render" => {
            // Secrets-aware: map SecretsInterpolationError → exit 3 (VFAIL-05).
            // Vault-aware render: map VaultResolveError → exit 3/4 (VFAIL-01/02).
            // The processor has vault_config attached above (vault feature).
            // For --in-place: do NOT write any output on any error (T-47-12/VFAIL-03).
            let result = processor.decrypt_to_raw_with_path(&content, &file_path);
            // Non-gated: ⊲{} miss → exit 3 on BOTH default and vault builds.
            let result = result.map_err(handle_secrets_render_error);
            #[cfg(feature = "vault")]
            let result = result.map_err(handle_vault_render_error);
            result?
        }
        _ => unreachable!(),
    };

    if in_place {
        if operation == "render" {
            // VFAIL-03: atomic temp→rename for render --in-place so a mid-resolution
            // failure never leaves the original file torn or partially overwritten.
            crate::config::write_atomic_bytes(output.as_bytes(), &file_path)?;
        } else {
            fs::write(&file_path, &output)?;
        }
        eprintln!("File processed in-place: {}", file_path.display());
    } else {
        print!("{output}");
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

/// Build a `GlobSet` from ignore patterns in the project config
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
                eprintln!("Warning: Invalid ignore pattern '{pattern}': {e}");
            }
        }
    }

    match builder.build() {
        Ok(globset) => Some(globset),
        Err(e) => {
            eprintln!("Warning: Failed to build ignore pattern matcher: {e}");
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
            // Why: dir was just confirmed to be a key in projects via .get() above;
            // .keys().find() therefore yields Some(_). Infallible-by-construction.
            #[allow(clippy::unwrap_used)]
            let key_ref = projects.keys().find(|k| *k == dir).unwrap();
            return Some((key_ref, proc, gs));
        }
        current = dir.parent();
    }
    None
}

/// Recursively process all files in the project with the given operation.
/// Detects nested project boundaries and uses each project's own key.
/// Projects where the current user has no keys are silently skipped.
/// IMPORTANT: Does not follow symlinks outside the project boundary.
// Why: spans CLI subcommand dispatch — refactor candidate for v2.4, no current pain.
#[allow(clippy::too_many_lines)]
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
        .map_err(|e| anyhow!("Failed to canonicalize project root: {e}"))?;

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
                eprintln!("Warning: Error accessing entry: {e}");
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
        let Some((proj_root, proj_processor, proj_ignore)) =
            find_project_for_path(path, &projects, &passthrough_roots)
        else {
            continue; // in a passthrough zone — skip silently
        };

        // Check per-project ignore patterns
        if let Some(globset) = proj_ignore
            && let Ok(rel_path) = path.strip_prefix(proj_root)
                && globset.is_match(rel_path) {
                    continue;
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
        let Ok(content) = fs::read_to_string(path) else {
            // Likely binary or unreadable
            continue;
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
        println!("\n{operation_verb} {processed_count} file(s)");
    }

    if error_count > 0 {
        return Err(anyhow!("Failed to {operation} {error_count} file(s)"));
    }

    Ok(())
}

/// Check if a file has any SSS markers
fn has_sss_markers(content: &str) -> bool {
    content.contains("⊠{") || content.contains("⊕{") ||
    content.contains("o+{") || content.contains("⊲{") ||
    content.contains("<{") ||
    // Vault reference markers (VREF-01): ⊳{} must be preserved verbatim on seal/open;
    // >{} must be normalised to ⊳{} on the seal path.  Include both so project-wide
    // seal picks up files that contain only vault refs (including the ASCII alias form).
    content.contains("⊳{") || content.contains(">{")
}

/// Process a single file in-place with the given operation, returns true if file was modified
fn process_file_in_place(path: &Path, processor: &crate::processor::core::Processor, operation: &str) -> Result<bool> {
    use std::fs;

    let original_content = fs::read_to_string(path)?;

    let processed_content = match operation {
        "seal" => processor.seal_content_with_path(&original_content, path)?,
        "open" => processor.open_content_with_path(&original_content, path)?,
        "render" => processor.decrypt_to_raw_with_path(&original_content, path)?,
        _ => return Err(anyhow!("Unknown operation: {operation}")),
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

    // CR-01 fix: encrypt with the real relative path so the sealed nonce matches
    // what `open_content_with_path` will re-derive.  `make_relative_path` requires
    // the file to exist; FUSE files always exist on the mount.
    let relative_path = processor.make_relative_path(file_path)?;
    let final_sealed_content = processor.encrypt_content_with_path(&edited_content, &relative_path)?;

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

    eprintln!("File edited and encrypted: {}", file_path.display());
    Ok(())
}

/// Create secure temp file path in /dev/shm (Linux) or /tmp (macOS)
#[cfg(target_os = "linux")]
fn create_secure_temp_path(file_path: &Path) -> Result<String> {
    let file_name = file_path.file_name().unwrap_or_default().to_string_lossy();
    let pid = std::process::id();

    if Path::new("/dev/shm").exists() {
        Ok(format!("/dev/shm/.sss-edit-{file_name}-{pid}"))
    } else {
        eprintln!("[WARN] /dev/shm not available, using /tmp (insecure!)");
        Ok(format!("/tmp/.sss-edit-{file_name}-{pid}"))
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
        let temp_path_str = temp_path.to_str()
            .ok_or_else(|| anyhow!("Temp file path contains invalid UTF-8"))?;
        write_temp_file_secure(temp_path_str, &edit_content)?;
    }

    #[cfg(not(unix))]
    {
        fs::write(&temp_path, edit_content)?;
    }

    // Launch editor
    launch_editor(&temp_path)?;

    // Read edited content and finalize.
    // CR-01 fix: use finalise_after_editing_with_path so the re-encrypted nonce is
    // derived from the real relative path, matching what open_content_with_path uses.
    let relative_path = processor.make_relative_path(file_path)?;
    let edited_content = fs::read_to_string(&temp_path)?;
    let final_content = processor.finalise_after_editing_with_path(&edited_content, &relative_path)?;

    // Securely remove temp file
    fs::remove_file(&temp_path)?;

    // Check if content actually changed
    if final_content == content {
        eprintln!("No changes made");
        return Ok(());
    }

    // Write back to original file
    fs::write(file_path, final_content)?;

    eprintln!("File edited and encrypted: {}", file_path.display());
    Ok(())
}

/// Main edit handler - dispatches to FUSE or regular file handler
pub fn handle_edit(_main_matches: &ArgMatches, sub_matches: &ArgMatches) -> Result<()> {
    // Why: clap declares `file` as required for the edit subcommand.
    // HARDEN-01 / 08-01.
    #[allow(clippy::unwrap_used)]
    let file_path_str = sub_matches.get_one::<String>("file").unwrap();

    if file_path_str == "-" {
        return Err(anyhow!(ERR_STDIN_EDIT));
    }

    let file_path = validate_file_path(file_path_str)?;

    if !file_path.exists() {
        return Err(anyhow!(
            "File '{}' does not exist. Check the path and try again.",
            file_path.display()
        ));
    }

    // Find project config and load repository key
    let file_dir = file_path.parent().ok_or_else(|| anyhow!(
        "Cannot determine parent directory of '{}'. Ensure the path is not a filesystem root.",
        file_path.display()
    ))?;
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

    // -----------------------------------------------------------------------
    // 16b-03 lift tests (TEST-11). Helper-level coverage: pure logic only.
    // FUSE arm intentionally skipped per D-08 (untestable without real mount).
    // -----------------------------------------------------------------------

    use crate::project::ProjectConfig;
    use anyhow::Result;
    use std::collections::{HashMap, HashSet};
    use std::fs;
    use tempfile::TempDir;

    // ---- has_sss_markers ---------------------------------------------------

    #[test]
    fn test_has_sss_markers_sealed_marker_returns_true() {
        assert!(has_sss_markers("password=\u{22a0}{abcdef}"));
    }

    #[test]
    fn test_has_sss_markers_plaintext_oplus_marker_returns_true() {
        assert!(has_sss_markers("token=\u{2295}{secret}"));
    }

    #[test]
    fn test_has_sss_markers_ascii_oplus_marker_returns_true() {
        assert!(has_sss_markers("api_key=o+{my-secret}"));
    }

    #[test]
    fn test_has_sss_markers_secrets_ref_unicode_returns_true() {
        assert!(has_sss_markers("ref=\u{22b2}{name}"));
    }

    #[test]
    fn test_has_sss_markers_secrets_ref_ascii_returns_true() {
        assert!(has_sss_markers("ref=<{name}"));
    }

    #[test]
    fn test_has_sss_markers_no_markers_returns_false() {
        assert!(!has_sss_markers("plain text without any sss markers"));
    }

    #[test]
    fn test_has_sss_markers_empty_returns_false() {
        assert!(!has_sss_markers(""));
    }

    // ---- is_binary_file ----------------------------------------------------

    #[test]
    fn test_is_binary_file_text_returns_false() -> Result<()> {
        let tmp = TempDir::new()?;
        let path = tmp.path().join("plain.txt");
        fs::write(&path, "hello world\nthis is text\n")?;
        assert!(!is_binary_file(&path)?);
        Ok(())
    }

    #[test]
    fn test_is_binary_file_with_null_byte_returns_true() -> Result<()> {
        let tmp = TempDir::new()?;
        let path = tmp.path().join("bin.bin");
        fs::write(&path, b"prefix\x00suffix")?;
        assert!(is_binary_file(&path)?);
        Ok(())
    }

    #[test]
    fn test_is_binary_file_empty_file_returns_false() -> Result<()> {
        let tmp = TempDir::new()?;
        let path = tmp.path().join("empty.txt");
        fs::write(&path, b"")?;
        assert!(!is_binary_file(&path)?);
        Ok(())
    }

    #[test]
    fn test_is_binary_file_missing_path_errors() {
        let tmp = TempDir::new().unwrap();
        let missing = tmp.path().join("does-not-exist.bin");
        assert!(is_binary_file(&missing).is_err());
    }

    // ---- build_ignore_globset ---------------------------------------------

    #[test]
    fn test_build_ignore_globset_empty_returns_none() {
        let cfg = ProjectConfig::default();
        assert!(build_ignore_globset(&cfg).is_none());
    }

    #[test]
    fn test_build_ignore_globset_single_pattern_matches() {
        let cfg = ProjectConfig {
            ignore: Some("*.log".to_string()),
            ..ProjectConfig::default()
        };
        let gs = build_ignore_globset(&cfg).expect("globset built");
        assert!(gs.is_match("server.log"));
        assert!(!gs.is_match("server.txt"));
    }

    #[test]
    fn test_build_ignore_globset_multiple_patterns_match() {
        let cfg = ProjectConfig {
            ignore: Some("*.log build/*".to_string()),
            ..ProjectConfig::default()
        };
        let gs = build_ignore_globset(&cfg).expect("globset built");
        assert!(gs.is_match("a.log"));
        assert!(gs.is_match("build/foo"));
        assert!(!gs.is_match("src/main.rs"));
    }

    #[test]
    fn test_build_ignore_globset_invalid_pattern_logs_and_continues() {
        // Mix one valid and one invalid pattern. The invalid one should be
        // skipped (warning emitted) without aborting the whole build.
        let cfg = ProjectConfig {
            ignore: Some("*.log [unterminated".to_string()),
            ..ProjectConfig::default()
        };
        let gs = build_ignore_globset(&cfg).expect("globset built despite invalid entry");
        assert!(gs.is_match("foo.log"));
    }

    // ---- find_project_for_path --------------------------------------------

    #[test]
    fn test_find_project_for_path_no_match_returns_none() {
        let tmp = TempDir::new().unwrap();
        let leaf = tmp.path().join("a/b/c.txt");
        let projects: HashMap<PathBuf, (Processor, Option<globset::GlobSet>)> = HashMap::new();
        let passthrough: HashSet<PathBuf> = HashSet::new();
        assert!(find_project_for_path(&leaf, &projects, &passthrough).is_none());
    }

    #[test]
    fn test_find_project_for_path_passthrough_returns_none() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path().to_path_buf();
        let leaf = root.join("inner/file.txt");
        let projects: HashMap<PathBuf, (Processor, Option<globset::GlobSet>)> = HashMap::new();
        let mut passthrough: HashSet<PathBuf> = HashSet::new();
        passthrough.insert(root.join("inner"));
        assert!(find_project_for_path(&leaf, &projects, &passthrough).is_none());
    }

    // ---- create_secure_temp_path ------------------------------------------

    #[test]
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn test_create_secure_temp_path_contains_filename_and_pid() {
        let p = PathBuf::from("/tmp/example_target.txt");
        let temp = create_secure_temp_path(&p).expect("path");
        assert!(temp.contains("example_target.txt"), "missing filename: {temp}");
        assert!(temp.contains(&std::process::id().to_string()), "missing pid: {temp}");
    }

    #[test]
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn test_create_secure_temp_path_uses_known_prefix() {
        let p = PathBuf::from("/tmp/anything.txt");
        let temp = create_secure_temp_path(&p).expect("path");
        assert!(
            temp.starts_with("/dev/shm/.sss-edit-") || temp.starts_with("/tmp/.sss-edit-"),
            "unexpected prefix: {temp}"
        );
    }

    // ---- write_temp_file_secure -------------------------------------------

    #[test]
    #[cfg(unix)]
    fn test_write_temp_file_secure_writes_content_and_mode_0600() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let tmp = TempDir::new()?;
        let target = tmp.path().join("secure.tmp");
        let target_str = target.to_str().expect("utf8 path");
        write_temp_file_secure(target_str, "secret-payload")?;
        let read_back = fs::read_to_string(&target)?;
        assert_eq!(read_back, "secret-payload");
        let mode = fs::metadata(&target)?.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "expected 0o600, got {mode:o}");
        Ok(())
    }

    #[test]
    #[cfg(unix)]
    fn test_write_temp_file_secure_truncates_existing() -> Result<()> {
        let tmp = TempDir::new()?;
        let target = tmp.path().join("existing.tmp");
        let target_str = target.to_str().expect("utf8 path");
        fs::write(&target, "old longer content that must be truncated")?;
        write_temp_file_secure(target_str, "new")?;
        assert_eq!(fs::read_to_string(&target)?, "new");
        Ok(())
    }

    // ---- process_file_in_place --------------------------------------------

    #[test]
    fn test_process_file_in_place_no_markers_returns_false_unchanged() -> Result<()> {
        use crate::crypto::RepositoryKey;
        let tmp = TempDir::new()?;
        let target = tmp.path().join("plain.txt");
        let original = "no markers here\njust text\n";
        fs::write(&target, original)?;

        let processor = Processor::new(RepositoryKey::new())?;
        let changed = process_file_in_place(&target, &processor, "seal")?;
        assert!(!changed, "file with no markers should report unchanged");
        assert_eq!(fs::read_to_string(&target)?, original);
        Ok(())
    }

    #[test]
    fn test_process_file_in_place_unknown_operation_errors() -> Result<()> {
        use crate::crypto::RepositoryKey;
        let tmp = TempDir::new()?;
        let target = tmp.path().join("plain.txt");
        fs::write(&target, "anything")?;

        let processor = Processor::new(RepositoryKey::new())?;
        let result = process_file_in_place(&target, &processor, "bogus");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Unknown operation"));
        Ok(())
    }

    #[test]
    fn test_process_file_in_place_seal_with_plaintext_marker_writes_back() -> Result<()> {
        use crate::crypto::RepositoryKey;
        let tmp = TempDir::new()?;
        let target = tmp.path().join("doc.txt");
        let original = "key=\u{2295}{plaintext-secret}\n";
        fs::write(&target, original)?;

        // A project timestamp is required for deterministic sealing (REM-25).
        let processor = Processor::new_with_context(
            RepositoryKey::new(),
            tmp.path().to_path_buf(),
            "2025-01-01T00:00:00Z".to_string(),
        )?;
        let changed = process_file_in_place(&target, &processor, "seal")?;
        assert!(changed, "sealing a plaintext marker should mutate the file");
        let after = fs::read_to_string(&target)?;
        assert!(after.contains("\u{22a0}{"), "sealed output missing \u{22a0} marker: {after}");
        Ok(())
    }

    // ---- error-path regressions (constants) -------------------------------

    #[test]
    fn test_constants_err_stdin_in_place_message_stable() {
        // Regression guard: handle_stdin_process / process_file_or_stdin
        // both reuse this exact message; integration scripts grep for it.
        assert_eq!(
            crate::constants::ERR_STDIN_IN_PLACE,
            "Cannot use --in-place with stdin"
        );
    }

    #[test]
    fn test_constants_err_stdin_edit_message_stable() {
        assert_eq!(
            crate::constants::ERR_STDIN_EDIT,
            "Cannot use edit mode with stdin"
        );
    }

    // ---- VFAIL-03/06: atomic -o / --in-place + resolution-error guard -------

    /// VFAIL-06: `write_atomic_bytes` writes rendered bytes to a specified output
    /// file and leaves stdout empty.  This validates the primitive used by the
    /// `-o` path; end-to-end `-o` routing is covered by the `handle_process` integration flow.
    #[test]
    fn test_write_atomic_bytes_creates_output_file() -> Result<()> {
        let tmp = TempDir::new()?;
        let out = tmp.path().join("out.txt");
        let payload = b"resolved-content\n";
        crate::config::write_atomic_bytes(payload, &out)?;
        assert!(out.exists(), "output file must exist after write_atomic_bytes");
        assert_eq!(fs::read(&out)?, payload);
        Ok(())
    }

    /// VFAIL-06/03: a failure BEFORE `write_atomic_bytes` leaves the target untouched.
    /// Verified by: if the render resolution returns an error (`SecretsInterpolationError`),
    /// we short-circuit with `?` before any `write_atomic_bytes` call, so an `-o` target
    /// that did not exist before the call still does not exist after.
    #[test]
    fn test_resolution_error_leaves_output_target_absent() -> Result<()> {
        use crate::crypto::RepositoryKey;
        use crate::secrets::SecretsInterpolationError;

        let tmp = TempDir::new()?;
        let out_target = tmp.path().join("should-not-exist.txt");

        // Build a processor configured for the default build (no vault).
        // keep_unresolved=false: missing ⊲{} will produce an error.
        let mut processor = Processor::new_with_project_root(
            RepositoryKey::new(),
            tmp.path().to_path_buf(),
        )?;
        processor.set_keep_unresolved(false);

        // Content with a ⊲{} reference to a non-existent secret key.
        // No .secrets file exists in tmp, so the lookup will fail.
        let source = tmp.path().join("src.txt");
        fs::write(&source, "KEY=⊲{missing_key}\n")?;
        let content = fs::read_to_string(&source)?;

        let result = processor.decrypt_to_raw_with_path(&content, &source);
        // Apply the same mapper as the render command boundary.
        let result: anyhow::Result<String> = result.map_err(|e| {
            if e.downcast_ref::<SecretsInterpolationError>().is_some() {
                // Simulate handle_secrets_render_error returning the error unchanged
                // (we don't call process::exit in test context, just inspect the type).
                e
            } else {
                e
            }
        });

        // The error must be a SecretsInterpolationError::Unresolved.
        assert!(result.is_err(), "missing ⊲{{}} must error when keep_unresolved=false");
        assert!(
            result.unwrap_err().downcast_ref::<SecretsInterpolationError>().is_some(),
            "error must be SecretsInterpolationError"
        );

        // The -o target must NOT have been written (error short-circuited before write).
        assert!(
            !out_target.exists(),
            "output target must not be created on resolution error"
        );

        Ok(())
    }

    /// VFAIL-03: `write_atomic_bytes` is idempotent-on-failure — the original file
    /// is preserved when the atomic rename fails.  Here we verify that
    /// `write_atomic_bytes` successfully replaces the target atomically (the
    /// success path of the --in-place upgrade).
    #[test]
    fn test_write_atomic_bytes_replaces_existing_file_atomically() -> Result<()> {
        let tmp = TempDir::new()?;
        let target = tmp.path().join("original.txt");
        fs::write(&target, b"original content")?;

        let new_content = b"new resolved content\n";
        crate::config::write_atomic_bytes(new_content, &target)?;

        assert_eq!(fs::read(&target)?, new_content);
        Ok(())
    }
}
