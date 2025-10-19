use anyhow::{anyhow, Result};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use widestring::{U16CStr, U16CString};
use winfsp::filesystem::{
    DirInfo, FileInfo, FileSecurity, FileSystemContext, OpenFileInfo, IoResult,
};
use winfsp::host::{FileSystemHost, VolumeParams};
use winapi::um::winnt::{FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL};

use crate::Processor;

// Sealed mode protocol constants
// Signal 1: Use FILE_FLAG_OPEN_NO_RECALL (0x00100000) to indicate sealed mode request
const FILE_FLAG_OPEN_NO_RECALL: u32 = 0x00100000;
// Signal 2: Open the :sss-sealed ADS to confirm sealed mode
const SEALED_MODE_STREAM: &str = ":sss-sealed";

/// File access mode for different views
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FileMode {
    /// Normal access: fully rendered (no markers)
    Rendered,
    /// .sss-opened suffix: opened with ⊕{} markers for editing
    Opened,
    /// .sss-sealed suffix: raw sealed content with ⊠{} markers
    Sealed,
}

/// File handle for tracking open files
struct FileHandle {
    path: PathBuf,
    /// Cached content (rendered, opened, or sealed)
    cached_content: Option<Vec<u8>>,
    /// Whether the file is open for writing
    writable: bool,
    /// Dirty flag for writes
    dirty: bool,
    /// File access mode
    mode: FileMode,
    /// Sealed mode requested (via FILE_FLAG_OPEN_NO_RECALL)
    sealed_mode: bool,
    /// Whether this is an ADS handle (for :sss-sealed stream)
    is_ads_handle: bool,
}

/// WinFsp filesystem for transparent encryption/decryption of sss-managed files.
///
/// `SssWinFsp` provides a WinFsp-based virtual filesystem that transparently renders
/// encrypted content on read and seals (encrypts) content on write. It supports:
///
/// - **Transparent rendering**: Files with `⊠{...}` markers are automatically decrypted
/// - **Virtual suffixes**: `.sss-opened` and `.sss-sealed` provide different views
/// - **Smart reconstruction**: Preserves encryption structure when writing edited files
///
/// # Architecture
///
/// - Maintains file handle mapping for open files
/// - Caches rendered content for performance
/// - Hides git-related files (`.git/`, `.gitignore`, etc.) from view
///
/// # Thread Safety
///
/// All internal state uses `RwLock` for thread-safe concurrent access.
pub struct SssWinFsp {
    /// Path to the real directory being mirrored
    source_path: PathBuf,
    /// Processor for encryption/decryption operations
    processor: Processor,
    /// Open file handles with cached content and mode flags
    file_handles: RwLock<HashMap<u64, FileHandle>>,
    /// Next available file handle ID (atomic counter)
    next_fh: RwLock<u64>,
    /// Cache of rendered file contents (path -> decrypted bytes)
    render_cache: RwLock<HashMap<PathBuf, Vec<u8>>>,
}

impl SssWinFsp {
    /// Creates a new WinFsp filesystem for transparent sss encryption/decryption.
    ///
    /// # Arguments
    ///
    /// * `source_path` - Path to the directory containing files to be transparently processed
    /// * `processor` - Configured [`Processor`] instance for encryption/decryption operations
    ///
    /// # Returns
    ///
    /// Returns `Ok(SssWinFsp)` if successful, or an error if:
    /// - The source path doesn't exist
    /// - The source path is not a directory
    pub fn new(source_path: PathBuf, processor: Processor) -> Result<Self> {
        if !source_path.exists() {
            return Err(anyhow!("Source path does not exist: {:?}", source_path));
        }

        if !source_path.is_dir() {
            return Err(anyhow!("Source path is not a directory: {:?}", source_path));
        }

        Ok(Self {
            source_path,
            processor,
            file_handles: RwLock::new(HashMap::new()),
            next_fh: RwLock::new(1),
            render_cache: RwLock::new(HashMap::new()),
        })
    }

    /// Get the real path for a given virtual path
    fn real_path(&self, virtual_path: &Path) -> PathBuf {
        // Strip leading slash/backslash if present
        let path_str = virtual_path.to_string_lossy();
        let stripped = path_str.trim_start_matches(['/', '\\']);

        if stripped.is_empty() {
            self.source_path.clone()
        } else {
            self.source_path.join(stripped)
        }
    }

    /// Check if a file has encrypted markers (should be processed)
    fn has_encrypted_markers(content: &str) -> bool {
        content.contains("⊠{")
    }

    /// Check if a file/directory should be hidden from view
    fn should_hide(name: &str) -> bool {
        matches!(
            name,
            ".git" | ".gitignore" | ".gitattributes" | ".gitmodules"
        )
    }

    /// Check if a path contains an Alternate Data Stream (ADS)
    /// Format: "filename.txt:streamname"
    fn is_ads_path(path: &str) -> bool {
        // Check for colon (but not drive letter like "C:")
        if let Some(colon_pos) = path.find(':') {
            // Skip if it's just a drive letter (position 1)
            if colon_pos > 1 {
                return true;
            }
        }
        false
    }

    /// Extract the base filename from an ADS path
    /// "C:\path\file.txt:sss-sealed" -> "C:\path\file.txt"
    fn extract_base_path(path: &str) -> String {
        if let Some(colon_pos) = path.rfind(':') {
            // Make sure it's not a drive letter
            if colon_pos > 1 {
                return path[..colon_pos].to_string();
            }
        }
        path.to_string()
    }

    /// Extract the stream name from an ADS path
    /// "C:\path\file.txt:sss-sealed" -> ":sss-sealed"
    fn extract_stream_name(path: &str) -> Option<String> {
        if let Some(colon_pos) = path.rfind(':') {
            if colon_pos > 1 {
                return Some(path[colon_pos..].to_string());
            }
        }
        None
    }

    /// Find file handles with pending sealed mode for a given base path
    /// Used when ADS is opened to confirm sealed mode
    fn find_pending_sealed_handles(&self, base_path: &Path) -> Vec<u64> {
        let handles = self.file_handles.read();
        handles
            .iter()
            .filter(|(_, h)| {
                h.sealed_mode && h.cached_content.is_none() && h.path == base_path
            })
            .map(|(fh, _)| *fh)
            .collect()
    }

    /// Confirm sealed mode for handles (called when ADS is opened)
    fn confirm_sealed_mode(&self, base_path: &Path) -> Result<()> {
        let pending_handles = self.find_pending_sealed_handles(base_path);

        if pending_handles.is_empty() {
            return Ok(()); // No pending handles to confirm
        }

        // Read sealed content once
        let sealed_content = self.read_sealed(base_path)?;

        // Update all pending handles for this file
        let mut handles = self.file_handles.write();
        for fh in pending_handles {
            if let Some(handle) = handles.get_mut(&fh) {
                handle.cached_content = Some(sealed_content.clone());
            }
        }

        Ok(())
    }

    /// Parse virtual file name and determine file mode
    /// Returns (actual_name, file_mode)
    fn parse_virtual_file_mode(name: &str) -> (&str, FileMode) {
        if let Some(actual) = name.strip_suffix(".sss-sealed") {
            (actual, FileMode::Sealed)
        } else if let Some(actual) = name.strip_suffix(".sss-opened") {
            (actual, FileMode::Opened)
        } else {
            (name, FileMode::Rendered)
        }
    }

    /// Read and render a file (decrypt and remove all markers)
    fn read_and_render(&self, path: &Path) -> Result<Vec<u8>> {
        let bytes = fs::read(path)?;

        // Try to convert to string
        let content = match String::from_utf8(bytes.clone()) {
            Ok(c) => c,
            Err(_) => {
                // Not a text file, return raw bytes
                return Ok(bytes);
            }
        };

        // Only process if file has encrypted markers
        if Self::has_encrypted_markers(&content) {
            // Decrypt and render (remove all markers)
            let rendered = self.processor.decrypt_to_raw(&content)?;
            Ok(rendered.into_bytes())
        } else {
            // Return as-is for non-encrypted files
            Ok(bytes)
        }
    }

    /// Read and open a file (decrypt ⊠{} → ⊕{} but keep markers for editing)
    fn read_and_open(&self, path: &Path) -> Result<Vec<u8>> {
        let bytes = fs::read(path)?;

        let content = match String::from_utf8(bytes.clone()) {
            Ok(c) => c,
            Err(_) => return Ok(bytes),
        };

        if Self::has_encrypted_markers(&content) {
            let opened = self.processor.decrypt_content(&content)?;
            Ok(opened.into_bytes())
        } else {
            Ok(bytes)
        }
    }

    /// Read sealed file (raw content with ⊠{} markers from backing store)
    fn read_sealed(&self, path: &Path) -> Result<Vec<u8>> {
        Ok(fs::read(path)?)
    }

    /// Read file based on mode
    fn read_with_mode(&self, path: &Path, mode: FileMode) -> Result<Vec<u8>> {
        match mode {
            FileMode::Rendered => self.read_and_render(path),
            FileMode::Opened => self.read_and_open(path),
            FileMode::Sealed => self.read_sealed(path),
        }
    }

    /// Check if a file should be processed by sss encryption
    fn should_process_with_sss(path: &Path) -> bool {
        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            // Skip vim swap files and temporary files
            if name.starts_with('.') && (name.ends_with(".swp") || name.ends_with(".swo") ||
                                         name.ends_with(".swn") || name.ends_with(".tmp")) {
                return false;
            }
            // Skip other temporary file patterns
            if name.ends_with('~') || name.starts_with("#") || name.ends_with("#") {
                return false;
            }
        }
        true
    }

    /// Write raw content directly to backing store (no sss processing)
    fn write_raw_to_backing(&self, path: &Path, content: &[u8]) -> Result<()> {
        fs::write(path, content)?;
        Ok(())
    }

    /// Write opened content (with ⊕{} markers) as sealed to backing store
    fn write_sealed_to_backing(&self, path: &Path, opened_content: &[u8]) -> Result<()> {
        let opened_str = String::from_utf8(opened_content.to_vec())
            .map_err(|_| anyhow!("Content is not valid UTF-8"))?;

        // Seal the opened content (⊕{} → ⊠{})
        let sealed_content = self.processor.encrypt_content(&opened_str)?;

        // Write using temporary file for atomicity
        let temp_path = path.with_extension("tmp");
        fs::write(&temp_path, sealed_content.as_bytes())?;
        fs::rename(&temp_path, path)?;

        Ok(())
    }

    /// Write rendered content back with smart reconstruction
    fn write_and_seal(&self, path: &Path, rendered_content: &[u8]) -> Result<()> {
        let rendered_str = String::from_utf8(rendered_content.to_vec())
            .map_err(|_| anyhow!("Content is not valid UTF-8"))?;

        // Read current sealed version from backing store
        let sealed_current = match fs::read_to_string(path) {
            Ok(content) => content,
            Err(_) => {
                // File doesn't exist, write as-is
                return self.write_raw_to_backing(path, rendered_content);
            }
        };

        // If current version has no markers, just write the rendered content
        if !Self::has_encrypted_markers(&sealed_current) {
            return self.write_raw_to_backing(path, rendered_content);
        }

        // Perform smart reconstruction:
        // 1. Open (decrypt) current sealed version to get markers
        let opened_current = self.processor.decrypt_content(&sealed_current)?;

        // 2. Render current version for comparison
        let rendered_current = self.processor.decrypt_to_raw(&sealed_current)?;

        // 3. Use smart reconstruction to preserve markers
        let reconstructed = crate::merge::smart_reconstruct(
            &rendered_str,
            &opened_current,
            &rendered_current,
        )?;

        // 4. Seal the reconstructed content
        let sealed_new = self.processor.encrypt_content(&reconstructed)?;

        // 5. Write to backing store atomically
        let temp_path = path.with_extension("tmp");
        fs::write(&temp_path, sealed_new.as_bytes())?;
        fs::rename(&temp_path, path)?;

        Ok(())
    }

    /// Convert Windows file attributes to FileInfo
    fn metadata_to_file_info(&self, path: &Path, metadata: &fs::Metadata) -> Result<FileInfo> {
        let file_attributes = if metadata.is_dir() {
            FILE_ATTRIBUTE_DIRECTORY
        } else {
            FILE_ATTRIBUTE_NORMAL
        };

        // Get timestamps
        let creation_time = metadata.created().unwrap_or(UNIX_EPOCH);
        let last_access_time = metadata.accessed().unwrap_or(UNIX_EPOCH);
        let last_write_time = metadata.modified().unwrap_or(UNIX_EPOCH);

        // Check if we need to override size for rendered content
        let size = if metadata.is_file() {
            if let Some(cached) = self.render_cache.read().get(path) {
                cached.len() as u64
            } else {
                metadata.len()
            }
        } else {
            metadata.len()
        };

        Ok(FileInfo {
            file_attributes,
            allocation_size: size,
            file_size: size,
            creation_time: filetime_from_system_time(creation_time),
            last_access_time: filetime_from_system_time(last_access_time),
            last_write_time: filetime_from_system_time(last_write_time),
            change_time: filetime_from_system_time(last_write_time),
            index_number: 0,
        })
    }

    /// Mount the filesystem at the specified mountpoint
    pub fn mount(&self, mountpoint: &str) -> Result<()> {
        let volume_params = VolumeParams {
            sector_size: 512,
            sectors_per_allocation_unit: 1,
            volume_creation_time: 0,
            volume_serial_number: 0,
            file_info_timeout: 1000,
            case_sensitive_search: false,
            case_preserved_names: true,
            unicode_on_disk: true,
            persistent_acls: false,
            reparse_points: false,
            reparse_points_access_check: false,
            named_streams: false,
            hard_links: 0,
            extended_attributes: false,
            read_only_volume: false,
            post_cleanup_when_modified_only: true,
            pass_query_directory_pattern: false,
            always_use_double_buffering: false,
            pass_query_directory_file_name: false,
            flush_and_purge_on_cleanup: false,
            device_control: false,
            um_file_context_is_user_context2: false,
            um_file_context_is_full_context: false,
            um_reserved_flags: 0,
            file_system_name: U16CString::from_str("sss-winfsp")?,
            prefix: U16CString::from_str(mountpoint)?,
            ..Default::default()
        };

        let _host = FileSystemHost::new(volume_params, self)?;

        // Keep host alive (in real implementation, this would run until unmount)
        println!("Mounted at {}", mountpoint);
        Ok(())
    }
}

/// Convert SystemTime to Windows FILETIME (100-nanosecond intervals since 1601-01-01)
fn filetime_from_system_time(time: SystemTime) -> u64 {
    const UNIX_EPOCH_IN_FILETIME: u64 = 116444736000000000;

    match time.duration_since(UNIX_EPOCH) {
        Ok(duration) => {
            let nanos = duration.as_nanos() as u64;
            let filetime_intervals = nanos / 100;
            UNIX_EPOCH_IN_FILETIME + filetime_intervals
        }
        Err(_) => UNIX_EPOCH_IN_FILETIME,
    }
}

impl FileSystemContext for SssWinFsp {
    type FileContext = u64; // File handle ID

    fn get_volume_info(&self) -> IoResult<winfsp::filesystem::VolumeInfo> {
        Ok(winfsp::filesystem::VolumeInfo {
            total_size: 1024 * 1024 * 1024 * 100, // 100 GB placeholder
            free_size: 1024 * 1024 * 1024 * 50,   // 50 GB placeholder
        })
    }

    fn set_volume_label(&self, _volume_label: &U16CStr) -> IoResult<()> {
        Err(winfsp::filesystem::IoError::NotSupported)
    }

    fn get_security_by_name(
        &self,
        _file_name: &U16CStr,
        _security_descriptor: Option<&mut [u8]>,
    ) -> IoResult<winfsp::filesystem::SecurityByName> {
        // Simplified security - allow all access
        Ok(winfsp::filesystem::SecurityByName {
            attributes: FILE_ATTRIBUTE_NORMAL,
            security_descriptor_size: 0,
            reparse: false,
        })
    }

    fn create(
        &self,
        file_name: &U16CStr,
        create_options: u32,
        _granted_access: u32,
        file_attributes: u32,
        _security_descriptor: &[u8],
        _allocation_size: u64,
    ) -> IoResult<OpenFileInfo<Self::FileContext>> {
        let path_str = file_name.to_string_lossy();
        let real_path = self.real_path(Path::new(&path_str));

        // Check if this is a directory creation
        let is_directory = (create_options & 0x00000001) != 0;

        if is_directory {
            fs::create_dir_all(&real_path)
                .map_err(|_| winfsp::filesystem::IoError::CannotMake)?;
        } else {
            // Create empty file
            fs::write(&real_path, &[])
                .map_err(|_| winfsp::filesystem::IoError::CannotMake)?;
        }

        // Create file handle
        let fh = {
            let mut next_fh = self.next_fh.write();
            let fh = *next_fh;
            *next_fh += 1;
            fh
        };

        let handle = FileHandle {
            path: real_path.clone(),
            cached_content: None,
            writable: true,
            dirty: false,
            mode: FileMode::Rendered,
            sealed_mode: false,
            is_ads_handle: false,
        };

        self.file_handles.write().insert(fh, handle);

        // Get file info
        let metadata = fs::metadata(&real_path)
            .map_err(|_| winfsp::filesystem::IoError::FileNotFound)?;
        let file_info = self.metadata_to_file_info(&real_path, &metadata)
            .map_err(|_| winfsp::filesystem::IoError::IoError)?;

        Ok(OpenFileInfo {
            context: fh,
            file_info,
        })
    }

    fn open(
        &self,
        file_name: &U16CStr,
        create_options: u32,
        _granted_access: u32,
    ) -> IoResult<OpenFileInfo<Self::FileContext>> {
        let path_str = file_name.to_string_lossy();

        // Check for sealed mode protocol: ADS access
        let is_ads = Self::is_ads_path(&path_str);
        let stream_name = Self::extract_stream_name(&path_str);

        // If this is the sealed mode ADS, confirm sealed mode and return success
        if is_ads && stream_name.as_deref() == Some(SEALED_MODE_STREAM) {
            let base_path_str = Self::extract_base_path(&path_str);
            let base_path = self.real_path(Path::new(&base_path_str));

            // Confirm sealed mode for all pending handles
            if let Err(_) = self.confirm_sealed_mode(&base_path) {
                return Err(winfsp::filesystem::IoError::IoError);
            }

            // Create a dummy ADS handle
            let fh = {
                let mut next_fh = self.next_fh.write();
                let fh = *next_fh;
                *next_fh += 1;
                fh
            };

            let handle = FileHandle {
                path: base_path.clone(),
                cached_content: Some(Vec::new()),
                writable: false,
                dirty: false,
                mode: FileMode::Sealed,
                sealed_mode: false,
                is_ads_handle: true,
            };

            self.file_handles.write().insert(fh, handle);

            // Return minimal file info for ADS
            let file_info = FileInfo {
                file_attributes: FILE_ATTRIBUTE_NORMAL,
                allocation_size: 0,
                file_size: 0,
                creation_time: 0,
                last_access_time: 0,
                last_write_time: 0,
                change_time: 0,
                index_number: 0,
            };

            return Ok(OpenFileInfo {
                context: fh,
                file_info,
            });
        }

        // Parse virtual suffix
        let (actual_name, file_mode) = Self::parse_virtual_file_mode(&path_str);

        // Check if file should be hidden
        if let Some(name) = Path::new(actual_name).file_name() {
            if let Some(name_str) = name.to_str() {
                if Self::should_hide(name_str) {
                    return Err(winfsp::filesystem::IoError::FileNotFound);
                }
            }
        }

        let real_path = self.real_path(Path::new(actual_name));

        if !real_path.exists() {
            return Err(winfsp::filesystem::IoError::FileNotFound);
        }

        // Detect sealed mode request (Signal 1: FILE_FLAG_OPEN_NO_RECALL)
        let sealed_mode_requested = (create_options & FILE_FLAG_OPEN_NO_RECALL) != 0;

        // Create file handle
        let fh = {
            let mut next_fh = self.next_fh.write();
            let fh = *next_fh;
            *next_fh += 1;
            fh
        };

        // Pre-cache content based on mode and sealed mode status
        let cached_content = if sealed_mode_requested {
            // Sealed mode: Don't cache yet, wait for ADS confirmation
            None
        } else if real_path.is_file() {
            self.read_with_mode(&real_path, file_mode).ok()
        } else {
            None
        };

        let handle = FileHandle {
            path: real_path.clone(),
            cached_content: cached_content.clone(),
            writable: false, // Will be updated on write
            dirty: false,
            mode: file_mode,
            sealed_mode: sealed_mode_requested,
            is_ads_handle: false,
        };

        self.file_handles.write().insert(fh, handle);

        // Update render cache if we cached content
        if let Some(ref content) = cached_content {
            if file_mode == FileMode::Rendered {
                self.render_cache.write().insert(real_path.clone(), content.clone());
            }
        }

        // Get file info
        let metadata = fs::metadata(&real_path)
            .map_err(|_| winfsp::filesystem::IoError::FileNotFound)?;
        let file_info = self.metadata_to_file_info(&real_path, &metadata)
            .map_err(|_| winfsp::filesystem::IoError::IoError)?;

        Ok(OpenFileInfo {
            context: fh,
            file_info,
        })
    }

    fn close(&self, context: Self::FileContext) {
        let mut handles = self.file_handles.write();

        if let Some(handle) = handles.remove(&context) {
            // Skip ADS handles (they're just for protocol confirmation)
            if handle.is_ads_handle {
                return;
            }

            // If file was written to, write back to backing store
            if handle.dirty && handle.writable {
                if let Some(content) = handle.cached_content {
                    let content_str = String::from_utf8_lossy(&content);
                    let is_already_sealed = Self::has_encrypted_markers(&content_str);

                    let write_result = if !Self::should_process_with_sss(&handle.path) {
                        // Temp files: write raw
                        self.write_raw_to_backing(&handle.path, &content)
                    } else if handle.sealed_mode {
                        // Sealed mode (via FILE_FLAG_OPEN_NO_RECALL): content is sealed, write raw
                        self.write_raw_to_backing(&handle.path, &content)
                    } else if handle.mode == FileMode::Sealed {
                        // Sealed mode (via .sss-sealed suffix): already sealed, write raw
                        self.write_raw_to_backing(&handle.path, &content)
                    } else if is_already_sealed {
                        // Already has markers, write directly
                        self.write_raw_to_backing(&handle.path, &content)
                    } else if handle.mode == FileMode::Opened {
                        // Opened mode: seal directly
                        self.write_sealed_to_backing(&handle.path, &content)
                    } else {
                        // Normal mode: smart reconstruction
                        self.write_and_seal(&handle.path, &content)
                    };

                    if let Err(e) = write_result {
                        eprintln!("Error writing file on close: {}", e);
                    }

                    // Invalidate render cache
                    self.render_cache.write().remove(&handle.path);
                }
            }
        }
    }

    fn read(
        &self,
        context: Self::FileContext,
        buffer: &mut [u8],
        offset: u64,
    ) -> IoResult<usize> {
        let handles = self.file_handles.read();

        let handle = handles.get(&context)
            .ok_or(winfsp::filesystem::IoError::InvalidHandle)?;

        // Sealed mode pending: wait for ADS confirmation
        // Return access denied which will cause the caller to retry
        if handle.sealed_mode && handle.cached_content.is_none() {
            return Err(winfsp::filesystem::IoError::AccessDenied);
        }

        // Get content from cache or read
        let content = if let Some(ref cached) = handle.cached_content {
            cached.clone()
        } else {
            self.read_with_mode(&handle.path, handle.mode)
                .map_err(|_| winfsp::filesystem::IoError::IoError)?
        };

        // Copy requested slice
        let start = offset as usize;
        let end = std::cmp::min(start + buffer.len(), content.len());

        if start < content.len() {
            let slice = &content[start..end];
            buffer[..slice.len()].copy_from_slice(slice);
            Ok(slice.len())
        } else {
            Ok(0)
        }
    }

    fn write(
        &self,
        context: Self::FileContext,
        buffer: &[u8],
        offset: u64,
        _write_to_end_of_file: bool,
        _constrained_io: bool,
    ) -> IoResult<usize> {
        let mut handles = self.file_handles.write();

        let handle = handles.get_mut(&context)
            .ok_or(winfsp::filesystem::IoError::InvalidHandle)?;

        handle.writable = true;

        // Initialize or extend cached content
        let mut content = handle.cached_content.take().unwrap_or_else(Vec::new);

        // Ensure content is large enough
        let end_offset = offset as usize + buffer.len();
        if content.len() < end_offset {
            content.resize(end_offset, 0);
        }

        // Write data at offset
        content[offset as usize..end_offset].copy_from_slice(buffer);

        handle.cached_content = Some(content);
        handle.dirty = true;

        Ok(buffer.len())
    }

    fn get_file_info(&self, context: Self::FileContext) -> IoResult<FileInfo> {
        let handles = self.file_handles.read();

        let handle = handles.get(&context)
            .ok_or(winfsp::filesystem::IoError::InvalidHandle)?;

        let metadata = fs::metadata(&handle.path)
            .map_err(|_| winfsp::filesystem::IoError::FileNotFound)?;

        self.metadata_to_file_info(&handle.path, &metadata)
            .map_err(|_| winfsp::filesystem::IoError::IoError)
    }

    fn set_file_size(&self, context: Self::FileContext, new_size: u64, _set_allocation_size: bool) -> IoResult<()> {
        let mut handles = self.file_handles.write();

        let handle = handles.get_mut(&context)
            .ok_or(winfsp::filesystem::IoError::InvalidHandle)?;

        // Resize cached content or file
        if let Some(ref mut content) = handle.cached_content {
            content.resize(new_size as usize, 0);
            handle.dirty = true;
        } else {
            let file = fs::OpenOptions::new()
                .write(true)
                .open(&handle.path)
                .map_err(|_| winfsp::filesystem::IoError::IoError)?;

            file.set_len(new_size)
                .map_err(|_| winfsp::filesystem::IoError::IoError)?;
        }

        Ok(())
    }

    fn flush(&self, context: Self::FileContext) -> IoResult<()> {
        let handles = self.file_handles.read();

        if handles.contains_key(&context) {
            Ok(())
        } else {
            Err(winfsp::filesystem::IoError::InvalidHandle)
        }
    }

    fn read_directory(
        &self,
        context: Self::FileContext,
        marker: Option<&U16CStr>,
    ) -> IoResult<Vec<DirInfo>> {
        let handles = self.file_handles.read();

        let handle = handles.get(&context)
            .ok_or(winfsp::filesystem::IoError::InvalidHandle)?;

        let mut entries = Vec::new();

        // Read directory
        let dir_entries = fs::read_dir(&handle.path)
            .map_err(|_| winfsp::filesystem::IoError::IoError)?;

        for entry in dir_entries {
            let entry = entry.map_err(|_| winfsp::filesystem::IoError::IoError)?;
            let file_name = entry.file_name();
            let name_str = file_name.to_string_lossy();

            // Skip hidden files
            if Self::should_hide(&name_str) {
                continue;
            }

            // Skip if before marker
            if let Some(marker_str) = marker {
                if name_str.as_ref() <= marker_str.to_string_lossy().as_ref() {
                    continue;
                }
            }

            let metadata = entry.metadata()
                .map_err(|_| winfsp::filesystem::IoError::IoError)?;

            let file_info = self.metadata_to_file_info(&entry.path(), &metadata)
                .map_err(|_| winfsp::filesystem::IoError::IoError)?;

            let wide_name = U16CString::from_str(&name_str)
                .map_err(|_| winfsp::filesystem::IoError::IoError)?;

            entries.push(DirInfo {
                file_name: wide_name,
                file_info,
            });
        }

        Ok(entries)
    }

    fn delete(
        &self,
        context: Self::FileContext,
        _file_name: &U16CStr,
    ) -> IoResult<()> {
        let handles = self.file_handles.read();

        let handle = handles.get(&context)
            .ok_or(winfsp::filesystem::IoError::InvalidHandle)?;

        let metadata = fs::metadata(&handle.path)
            .map_err(|_| winfsp::filesystem::IoError::FileNotFound)?;

        if metadata.is_dir() {
            fs::remove_dir(&handle.path)
                .map_err(|_| winfsp::filesystem::IoError::IoError)?;
        } else {
            fs::remove_file(&handle.path)
                .map_err(|_| winfsp::filesystem::IoError::IoError)?;
        }

        // Invalidate cache
        self.render_cache.write().remove(&handle.path);

        Ok(())
    }

    fn rename(
        &self,
        context: Self::FileContext,
        file_name: &U16CStr,
        new_file_name: &U16CStr,
        _replace_if_exists: bool,
    ) -> IoResult<()> {
        let handles = self.file_handles.read();

        let handle = handles.get(&context)
            .ok_or(winfsp::filesystem::IoError::InvalidHandle)?;

        let new_path_str = new_file_name.to_string_lossy();
        let new_real_path = self.real_path(Path::new(&new_path_str));

        fs::rename(&handle.path, &new_real_path)
            .map_err(|_| winfsp::filesystem::IoError::IoError)?;

        // Invalidate old cache entry
        self.render_cache.write().remove(&handle.path);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_has_encrypted_markers() {
        assert!(SssWinFsp::has_encrypted_markers("password: ⊠{abc123}"));
        assert!(!SssWinFsp::has_encrypted_markers("password: plaintext"));
    }

    #[test]
    fn test_should_hide() {
        assert!(SssWinFsp::should_hide(".git"));
        assert!(SssWinFsp::should_hide(".gitignore"));
        assert!(!SssWinFsp::should_hide("README.md"));
    }

    #[test]
    fn test_parse_virtual_file_mode() {
        let (name, mode) = SssWinFsp::parse_virtual_file_mode("file.txt.sss-sealed");
        assert_eq!(name, "file.txt");
        assert_eq!(mode, FileMode::Sealed);

        let (name, mode) = SssWinFsp::parse_virtual_file_mode("file.txt.sss-opened");
        assert_eq!(name, "file.txt");
        assert_eq!(mode, FileMode::Opened);

        let (name, mode) = SssWinFsp::parse_virtual_file_mode("file.txt");
        assert_eq!(name, "file.txt");
        assert_eq!(mode, FileMode::Rendered);
    }

    #[test]
    fn test_should_process_with_sss() {
        assert!(SssWinFsp::should_process_with_sss(Path::new("config.yml")));
        assert!(!SssWinFsp::should_process_with_sss(Path::new(".file.swp")));
        assert!(!SssWinFsp::should_process_with_sss(Path::new("file~")));
    }
}
