//! 9P filesystem for transparent sss encryption/decryption
//!
//! This module provides a 9P2000.L filesystem server that exposes sss-encrypted
//! projects with transparent rendering. It follows native 9p conventions:
//!
//! # File Access Modes
//!
//! Different views of encrypted files are exposed through file naming:
//! - `file` - **Default rendered view** (fully decrypted, no markers) - NORMAL ACCESS
//! - `file.open` - Opened form with ⊕{} markers for editing
//! - `file.sealed` - Sealed form with ⊠{} markers (as stored on disk)
//!
//! # Sealed Mode Protocol (Two-Factor Handshake)
//!
//! For secure editor integration (like `sss edit`), a two-factor handshake protocol
//! is supported, matching FUSE behavior exactly:
//!
//! 1. **Signal 1**: Access `file.sealed-request` to indicate sealed mode desired
//!    - Marks the fid as pending sealed mode
//!    - Reads will fail with EAGAIN until confirmed
//!
//! 2. **Signal 2**: Access `file.sealed-confirm` to confirm and cache sealed content
//!    - Caches sealed content for the base file
//!    - Subsequent reads return sealed (⊠{}) content
//!
//! This prevents accidental exposure of sealed content and matches FUSE's security model.
//!
//! # Usage
//!
//! Start the server:
//! ```bash
//! sss serve9p tcp:0.0.0.0:564
//! ```
//!
//! Mount with standard 9p clients:
//! ```bash
//! # Linux with v9fs
//! mount -t 9p -o trans=tcp,port=564 127.0.0.1 /mnt/project
//!
//! # Plan 9 / 9front
//! 9fs tcp!server!564
//!
//! # Using 9pfuse (macOS, etc.)
//! 9pfuse 'tcp!localhost!564' /mnt/project
//! ```
//!
//! # Architecture
//!
//! - Async tokio-based server using rs9p library
//! - Per-fid file state tracking with path and access mode
//! - Smart reconstruction on writes (preserves encryption markers)
//! - Uses sss Processor for XChaCha20-Poly1305 with deterministic nonces

use anyhow::anyhow;
use async_trait::async_trait;
use rs9p::{
    srv::{Fid, Filesystem},
    *,
};
type Result<T> = std::result::Result<T, rs9p::Error>;
use std::{
    io::SeekFrom,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
};
use tokio::{
    fs,
    io::{AsyncReadExt, AsyncSeekExt},
    sync::{Mutex, RwLock},
};
use tokio_stream::{wrappers::ReadDirStream, StreamExt};

use crate::Processor;

/// Convert anyhow errors to rs9p IO errors
fn to_9p_error(err: impl std::fmt::Display) -> rs9p::Error {
    std::io::Error::other(err.to_string()).into()
}

/// Filter supported UNIX flags to avoid compatibility issues
const UNIX_FLAGS: u32 = {
    use nix::fcntl::OFlag;
    (OFlag::O_WRONLY.bits()
        | OFlag::O_RDONLY.bits()
        | OFlag::O_RDWR.bits()
        | OFlag::O_CREAT.bits()
        | OFlag::O_TRUNC.bits()) as u32
};

/// File access mode for different views
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[derive(Default)]
enum FileMode {
    /// Normal access: fully rendered (no markers)
    #[default]
    Rendered,
    /// .open: opened with ⊕{} markers for editing
    Opened,
    /// .sealed: raw sealed content with ⊠{} markers
    Sealed,
}


/// Per-connection file state
#[derive(Default)]
pub struct SssFid {
    /// Actual filesystem path (without suffix)
    realpath: RwLock<PathBuf>,
    /// Open file handle (if any)
    file: Mutex<Option<fs::File>>,
    /// Access mode for this fid
    mode: RwLock<FileMode>,
    /// Cached content for this handle
    cached_content: Mutex<Option<Vec<u8>>>,
    /// Whether this handle is writable
    writable: RwLock<bool>,
    /// Whether cached content has been modified
    dirty: RwLock<bool>,
    /// Sealed mode requested (via .sealed-request)
    sealed_mode: RwLock<bool>,
    /// Whether this is a confirmation fid (.sealed-confirm or .sealed-request)
    is_confirmation: RwLock<bool>,
}

/// sss 9P filesystem
#[derive(Clone)]
pub struct SssNinepFS {
    /// Root directory to export
    root: PathBuf,
    /// Processor for encryption/decryption (wrapped for thread-safety in async context)
    processor: std::sync::Arc<tokio::sync::RwLock<Processor>>,
    /// Shared cache for confirmed sealed mode content (path -> sealed content)
    /// Used for two-factor sealed mode protocol
    sealed_cache: std::sync::Arc<tokio::sync::RwLock<std::collections::HashMap<PathBuf, Vec<u8>>>>,
}

impl SssNinepFS {
    /// Create a new 9P filesystem for an sss project
    pub fn new(root: PathBuf, processor: Processor) -> anyhow::Result<Self> {
        if !root.exists() {
            return Err(anyhow!("Root path does not exist: {:?}", root));
        }
        if !root.is_dir() {
            return Err(anyhow!("Root path is not a directory: {:?}", root));
        }

        Ok(Self {
            root,
            processor: std::sync::Arc::new(tokio::sync::RwLock::new(processor)),
            sealed_cache: std::sync::Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new())),
        })
    }

    /// Parse filename to extract real name and access mode
    /// Examples:
    ///   "file.txt" -> ("file.txt", Rendered, false, false)
    ///   "file.txt.open" -> ("file.txt", Opened, false, false)
    ///   "file.txt.sealed" -> ("file.txt", Sealed, false, false)
    ///   "file.txt.sealed-request" -> ("file.txt", Sealed, true, false)
    ///   "file.txt.sealed-confirm" -> ("file.txt", Sealed, false, true)
    ///
    /// Returns: (basename, mode, is_sealed_request, is_confirm)
    fn parse_filename(&self, name: &str) -> (String, FileMode, bool, bool) {
        if let Some(base) = name.strip_suffix(".sealed-confirm") {
            (base.to_string(), FileMode::Sealed, false, true)
        } else if let Some(base) = name.strip_suffix(".sealed-request") {
            (base.to_string(), FileMode::Sealed, true, false)
        } else if let Some(base) = name.strip_suffix(".sealed") {
            (base.to_string(), FileMode::Sealed, false, false)
        } else if let Some(base) = name.strip_suffix(".open") {
            (base.to_string(), FileMode::Opened, false, false)
        } else {
            (name.to_string(), FileMode::Rendered, false, false)
        }
    }

    /// Check if a path has sealed mode protocol suffixes
    fn is_sealed_protocol_path(name: &str) -> bool {
        name.ends_with(".sealed-request") || name.ends_with(".sealed-confirm")
    }

    /// Check if a file has encrypted markers
    fn has_encrypted_markers(content: &str) -> bool {
        content.contains("⊠{")
    }

    /// Read and render a file (decrypt and remove all markers)
    async fn read_and_render(&self, path: &Path) -> anyhow::Result<Vec<u8>> {
        let bytes = fs::read(path).await?;

        // Try to convert to string
        let content = match String::from_utf8(bytes.clone()) {
            Ok(c) => c,
            Err(_) => return Ok(bytes), // Not text, return as-is
        };

        // Only process if file has encrypted markers
        if Self::has_encrypted_markers(&content) {
            let processor = self.processor.read().await;
            let rendered = processor.decrypt_to_raw(&content)?;
            Ok(rendered.into_bytes())
        } else {
            Ok(content.into_bytes())
        }
    }

    /// Read and open a file (decrypt ⊠{} → ⊕{} but keep markers)
    async fn read_and_open(&self, path: &Path) -> anyhow::Result<Vec<u8>> {
        let bytes = fs::read(path).await?;

        let content = match String::from_utf8(bytes.clone()) {
            Ok(c) => c,
            Err(_) => return Ok(bytes),
        };

        if Self::has_encrypted_markers(&content) {
            let processor = self.processor.read().await;
            let opened = processor.decrypt_content(&content)?;
            Ok(opened.into_bytes())
        } else {
            Ok(content.into_bytes())
        }
    }

    /// Read sealed file (raw content as stored)
    async fn read_sealed(&self, path: &Path) -> anyhow::Result<Vec<u8>> {
        Ok(fs::read(path).await?)
    }

    /// Check if a file should be processed by sss
    fn should_process_with_sss(path: &Path) -> bool {
        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            // Skip vim swap files and temporary files
            if name.starts_with('.') && (name.ends_with(".swp") || name.ends_with(".swo")) {
                return false;
            }
            if name.ends_with('~') || name.starts_with('#') {
                return false;
            }
        }
        true
    }

    /// Write content directly (no processing)
    async fn write_raw(&self, path: &Path, content: &[u8]) -> anyhow::Result<()> {
        fs::write(path, content).await?;
        Ok(())
    }

    /// Write sealed content (with ⊕{} markers) to backing store
    async fn write_sealed(&self, path: &Path, opened_content: &[u8]) -> anyhow::Result<()> {
        let opened_str = String::from_utf8(opened_content.to_vec())
            .map_err(|_| anyhow!("Content is not valid UTF-8"))?;

        // Seal the content (⊕{} → ⊠{})
        let processor = self.processor.read().await;
        let sealed_content = processor.encrypt_content(&opened_str)?;

        // Write atomically via temp file
        let temp_path = path.with_extension("tmp");
        fs::write(&temp_path, sealed_content.as_bytes()).await?;
        fs::rename(&temp_path, path).await?;

        Ok(())
    }

    /// Write rendered content with smart reconstruction
    async fn write_and_seal(&self, path: &Path, rendered_content: &[u8]) -> anyhow::Result<()> {
        let rendered_str = String::from_utf8(rendered_content.to_vec())
            .map_err(|_| anyhow!("Content is not valid UTF-8"))?;

        // Read current sealed version
        let sealed_current = match fs::read_to_string(path).await {
            Ok(content) => content,
            Err(_) => {
                // File doesn't exist, write as-is
                return self.write_raw(path, rendered_content).await;
            }
        };

        // If no markers, just write rendered
        if !Self::has_encrypted_markers(&sealed_current) {
            return self.write_raw(path, rendered_content).await;
        }

        // Smart reconstruction:
        let processor = self.processor.read().await;
        // 1. Open current sealed version to get markers
        let opened_current = processor.decrypt_content(&sealed_current)?;

        // 2. Render current version for comparison
        let rendered_current = processor.decrypt_to_raw(&sealed_current)?;

        // 3. Reconstruct markers (from merge module)
        let reconstructed =
            crate::merge::smart_reconstruct(&rendered_str, &opened_current, &rendered_current)?;

        // 4. Seal the reconstructed content
        let sealed_new = processor.encrypt_content(&reconstructed)?;

        // 5. Write atomically
        let temp_path = path.with_extension("tmp");
        fs::write(&temp_path, sealed_new.as_bytes()).await?;
        fs::rename(&temp_path, path).await?;

        Ok(())
    }

    /// Read file content based on mode
    async fn read_with_mode(&self, path: &Path, mode: FileMode) -> anyhow::Result<Vec<u8>> {
        match mode {
            FileMode::Rendered => self.read_and_render(path).await,
            FileMode::Opened => self.read_and_open(path).await,
            FileMode::Sealed => self.read_sealed(path).await,
        }
    }
}

#[async_trait]
impl Filesystem for SssNinepFS {
    type Fid = SssFid;

    async fn rattach(
        &self,
        fid: &Fid<Self::Fid>,
        _afid: Option<&Fid<Self::Fid>>,
        _uname: &str,
        _aname: &str,
        _n_uname: u32,
    ) -> Result<Fcall> {
        // Initialize root fid
        let mut path = fid.aux.realpath.write().await;
        *path = self.root.clone();

        let meta = fs::metadata(&*path).await?;
        let qid = metadata_to_qid(&meta);

        Ok(Fcall::Rattach { qid })
    }

    async fn rwalk(
        &self,
        fid: &Fid<Self::Fid>,
        newfid: &Fid<Self::Fid>,
        wnames: &[String],
    ) -> Result<Fcall> {
        let mut wqids = Vec::new();
        let cur_path = fid.aux.realpath.read().await;
        let mut path = cur_path.clone();
        let mut mode = FileMode::Rendered;
        let mut sealed_request = false;
        let mut is_confirm = false;

        // Walk through path components
        for name in wnames {
            // Parse for access mode suffixes and protocol markers
            let (real_name, detected_mode, is_sealed_req, is_confirm_file) = self.parse_filename(name);
            mode = detected_mode;
            sealed_request = is_sealed_req;
            is_confirm = is_confirm_file;

            // If this is a sealed protocol path, use the base file for existence check
            if Self::is_sealed_protocol_path(name) {
                // Check base file exists
                let base_path = path.join(&real_name);
                let meta = fs::metadata(&base_path).await?;
                // Return qid for the base file (protocol files are virtual)
                wqids.push(metadata_to_qid(&meta));

                // If confirmation, trigger sealed mode for pending handles
                if is_confirm_file {
                    // This will be handled in rlopen when the fid is actually opened
                    // For now, just set the path to the base file
                    path.push(&real_name);
                } else {
                    // sealed-request: just set the path
                    path.push(&real_name);
                }
            } else {
                path.push(&real_name);

                // Check if file exists
                let meta = fs::metadata(&path).await?;
                wqids.push(metadata_to_qid(&meta));
            }
        }

        // Update newfid's path and mode
        *newfid.aux.realpath.write().await = path;
        *newfid.aux.mode.write().await = mode;
        *newfid.aux.sealed_mode.write().await = sealed_request;
        *newfid.aux.is_confirmation.write().await = is_confirm;

        Ok(Fcall::Rwalk { wqids })
    }

    async fn rlopen(&self, fid: &Fid<Self::Fid>, flags: u32) -> Result<Fcall> {
        let path = fid.aux.realpath.read().await.clone();
        let is_confirm = *fid.aux.is_confirmation.read().await;
        let sealed_mode = *fid.aux.sealed_mode.read().await;

        // If this is a confirmation file, cache sealed content and return
        if is_confirm {
            let meta = fs::metadata(&path).await?;
            let qid = metadata_to_qid(&meta);

            // Read sealed content and cache it in the shared cache
            if let Ok(sealed_content) = self.read_sealed(&path).await {
                self.sealed_cache.write().await.insert(path.clone(), sealed_content);
            }

            // Mark this fid as confirmation
            *fid.aux.is_confirmation.write().await = true;

            return Ok(Fcall::Rlopen { qid, iounit: 0 });
        }

        // Sanitize flags
        let oflags = nix::fcntl::OFlag::from_bits_truncate((flags & UNIX_FLAGS) as i32);

        let writable = oflags.contains(nix::fcntl::OFlag::O_WRONLY)
            || oflags.contains(nix::fcntl::OFlag::O_RDWR);

        let file = fs::OpenOptions::new()
            .read(
                oflags.contains(nix::fcntl::OFlag::O_RDONLY)
                    || oflags.contains(nix::fcntl::OFlag::O_RDWR),
            )
            .write(writable)
            .create(oflags.contains(nix::fcntl::OFlag::O_CREAT))
            .truncate(oflags.contains(nix::fcntl::OFlag::O_TRUNC))
            .open(&*path)
            .await?;

        let meta = file.metadata().await?;
        let qid = metadata_to_qid(&meta);

        // Cache content if read-only and NOT sealed mode pending
        let mode = *fid.aux.mode.read().await;
        if !writable && !sealed_mode {
            // Normal caching for non-sealed mode
            if let Ok(content) = self.read_with_mode(&path, mode).await {
                *fid.aux.cached_content.lock().await = Some(content);
            }
        }
        // If sealed_mode is true, DO NOT cache yet - wait for confirmation
        // Reads will fail with EAGAIN until sealed-confirm is accessed

        *fid.aux.file.lock().await = Some(file);
        *fid.aux.writable.write().await = writable;

        Ok(Fcall::Rlopen { qid, iounit: 0 })
    }

    async fn rread(&self, fid: &Fid<Self::Fid>, offset: u64, count: u32) -> Result<Fcall> {
        let sealed_mode = *fid.aux.sealed_mode.read().await;
        let path = fid.aux.realpath.read().await.clone();

        // Check sealed mode protocol first
        if sealed_mode {
            // Check if sealed content has been confirmed
            let sealed_cache = self.sealed_cache.read().await;
            if let Some(sealed_content) = sealed_cache.get(&path) {
                // Confirmed: return sealed content
                let start = offset as usize;
                let end = std::cmp::min(start + count as usize, sealed_content.len());
                let data = if start < sealed_content.len() {
                    sealed_content[start..end].to_vec()
                } else {
                    Vec::new()
                };
                return Ok(Fcall::Rread { data: Data(data) });
            } else {
                // Not confirmed yet: return EAGAIN equivalent
                // In 9P, we use EIO with a specific message, or we can use a custom error
                return Err(std::io::Error::from(std::io::ErrorKind::WouldBlock).into());
            }
        }

        // Try to use cached content first (non-sealed mode)
        let cached = fid.aux.cached_content.lock().await;
        if let Some(ref content) = *cached {
            let start = offset as usize;
            let end = std::cmp::min(start + count as usize, content.len());
            let data = if start < content.len() {
                content[start..end].to_vec()
            } else {
                Vec::new()
            };
            return Ok(Fcall::Rread { data: Data(data) });
        }
        drop(cached);

        // Fall back to reading from file
        let mode = *fid.aux.mode.read().await;
        let mut file_guard = fid.aux.file.lock().await;
        let file = file_guard
            .as_mut()
            .ok_or_else(|| to_9p_error("File not open"))?;

        // Read raw data
        file.seek(SeekFrom::Start(offset)).await?;
        let mut buf = vec![0u8; count as usize];
        let n = file.read(&mut buf).await?;
        buf.truncate(n);

        // Process based on mode (if it's text content)
        let data = if let Ok(content_str) = String::from_utf8(buf.clone()) {
            if Self::has_encrypted_markers(&content_str) {
                match mode {
                    FileMode::Sealed => buf, // Return as-is
                    FileMode::Opened => {
                        // Decrypt ⊠{} → ⊕{}
                        let processor = self.processor.read().await;
                        processor
                            .decrypt_content(&content_str)
                            .map(|s| s.into_bytes())
                            .unwrap_or(buf)
                    }
                    FileMode::Rendered => {
                        // Fully decrypt and render
                        let processor = self.processor.read().await;
                        processor
                            .decrypt_to_raw(&content_str)
                            .map(|s| s.into_bytes())
                            .unwrap_or(buf)
                    }
                }
            } else {
                buf // No markers, return as-is
            }
        } else {
            buf // Binary data, return as-is
        };

        Ok(Fcall::Rread { data: Data(data) })
    }

    async fn rwrite(&self, fid: &Fid<Self::Fid>, offset: u64, data: &Data) -> Result<Fcall> {
        let writable = *fid.aux.writable.read().await;
        if !writable {
            return Err(to_9p_error("File not open for writing"));
        }

        // Update cached content
        let mut cached = fid.aux.cached_content.lock().await;
        let mut content = cached.take().unwrap_or_else(Vec::new);

        let end_offset = offset as usize + data.0.len();
        if content.len() < end_offset {
            content.resize(end_offset, 0);
        }

        content[offset as usize..end_offset].copy_from_slice(&data.0);
        *cached = Some(content);
        *fid.aux.dirty.write().await = true;

        Ok(Fcall::Rwrite {
            count: data.0.len() as u32,
        })
    }

    async fn rreaddir(
        &self,
        fid: &Fid<Self::Fid>,
        offset: u64,
        count: u32,
    ) -> Result<Fcall> {
        let path = fid.aux.realpath.read().await;
        let mut entries = Vec::new();
        let mut stream = ReadDirStream::new(fs::read_dir(&*path).await?);
        let mut current_offset = 0u64;

        while let Some(entry_result) = stream.next().await {
            let entry = entry_result?;
            let name = entry.file_name().to_string_lossy().to_string();

            if current_offset >= offset {
                let meta = entry.metadata().await?;
                let qid = metadata_to_qid(&meta);

                entries.push(DirEntry {
                    qid,
                    offset: current_offset + 1,
                    typ: filetype_to_dirent_type(&meta),
                    name,
                });
            }
            current_offset += 1;
        }

        // Serialize entries
        let data = serialize_dirents(&entries, count as usize);

        Ok(Fcall::Rreaddir { data })
    }

    async fn rclunk(&self, fid: &Fid<Self::Fid>) -> Result<Fcall> {
        // Skip confirmation fids (they're virtual)
        let is_confirm = *fid.aux.is_confirmation.read().await;
        if is_confirm {
            return Ok(Fcall::Rclunk);
        }

        // Flush writes on close
        let dirty = *fid.aux.dirty.read().await;
        if dirty {
            let cached = fid.aux.cached_content.lock().await;
            if let Some(ref content) = *cached {
                let path = fid.aux.realpath.read().await;
                let mode = *fid.aux.mode.read().await;
                let sealed_mode = *fid.aux.sealed_mode.read().await;

                let result = if !Self::should_process_with_sss(&path) {
                    // Temp files: write raw
                    self.write_raw(&path, content).await
                } else {
                    let content_str = String::from_utf8_lossy(content);
                    let is_sealed = Self::has_encrypted_markers(&content_str);

                    // Check if sealed mode was used
                    if sealed_mode || (mode == FileMode::Sealed && is_sealed) {
                        // Sealed mode: content is already sealed, write raw
                        self.write_raw(&path, content).await
                    } else {
                        match (mode, is_sealed) {
                            (FileMode::Sealed, _) | (_, true) => {
                                // Already sealed or sealed mode
                                self.write_raw(&path, content).await
                            }
                            (FileMode::Opened, false) => {
                                // Opened mode: seal the content
                                self.write_sealed(&path, content).await
                            }
                            (FileMode::Rendered, false) => {
                                // Rendered mode: smart reconstruction
                                self.write_and_seal(&path, content).await
                            }
                        }
                    }
                };

                if let Err(e) = result {
                    eprintln!("Error writing file on close: {}", e);
                }
            }
        }

        *fid.aux.file.lock().await = None;
        Ok(Fcall::Rclunk)
    }

    async fn rgetattr(&self, fid: &Fid<Self::Fid>, _req_mask: GetattrMask) -> Result<Fcall> {
        let path = fid.aux.realpath.read().await;
        let meta = fs::metadata(&*path).await?;
        let qid = metadata_to_qid(&meta);

        let stat = Stat {
            mode: meta.permissions().mode(),
            uid: meta.uid(),
            gid: meta.gid(),
            nlink: meta.nlink(),
            rdev: meta.rdev(),
            size: meta.len(),
            blksize: meta.blksize(),
            blocks: meta.blocks(),
            atime: Time {
                sec: meta.atime() as u64,
                nsec: meta.atime_nsec() as u64,
            },
            mtime: Time {
                sec: meta.mtime() as u64,
                nsec: meta.mtime_nsec() as u64,
            },
            ctime: Time {
                sec: meta.ctime() as u64,
                nsec: meta.ctime_nsec() as u64,
            },
        };

        Ok(Fcall::Rgetattr {
            valid: GetattrMask::BASIC,
            qid,
            stat,
        })
    }

    async fn rlcreate(
        &self,
        fid: &Fid<Self::Fid>,
        name: &str,
        flags: u32,
        mode: u32,
        _gid: u32,
    ) -> Result<Fcall> {
        let mut path = fid.aux.realpath.write().await;

        // Parse filename for access modes and protocol markers
        let (real_name, open_mode, sealed_req, is_conf) = self.parse_filename(name);
        path.push(&real_name);

        *fid.aux.mode.write().await = open_mode;
        *fid.aux.sealed_mode.write().await = sealed_req;
        *fid.aux.is_confirmation.write().await = is_conf;

        let oflags = nix::fcntl::OFlag::from_bits_truncate((flags & UNIX_FLAGS) as i32);
        let writable = oflags.contains(nix::fcntl::OFlag::O_WRONLY)
            || oflags.contains(nix::fcntl::OFlag::O_RDWR);

        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .mode(mode)
            .open(&*path)
            .await?;

        let meta = file.metadata().await?;
        let qid = metadata_to_qid(&meta);

        *fid.aux.file.lock().await = Some(file);
        *fid.aux.writable.write().await = writable;

        Ok(Fcall::Rlcreate { qid, iounit: 0 })
    }

    async fn rmkdir(
        &self,
        fid: &Fid<Self::Fid>,
        name: &str,
        mode: u32,
        _gid: u32,
    ) -> Result<Fcall> {
        let path = fid.aux.realpath.read().await;
        let new_path = path.join(name);

        fs::create_dir(&new_path).await?;
        fs::set_permissions(&new_path, std::fs::Permissions::from_mode(mode)).await?;

        let meta = fs::metadata(&new_path).await?;
        let qid = metadata_to_qid(&meta);

        Ok(Fcall::Rmkdir { qid })
    }

    async fn rremove(&self, fid: &Fid<Self::Fid>) -> Result<Fcall> {
        let path = fid.aux.realpath.read().await;
        let meta = fs::metadata(&*path).await?;

        if meta.is_dir() {
            fs::remove_dir(&*path).await?;
        } else {
            fs::remove_file(&*path).await?;
        }

        Ok(Fcall::Rremove)
    }

    async fn rstatfs(&self, fid: &Fid<Self::Fid>) -> Result<Fcall> {
        let path = fid.aux.realpath.read().await;
        let statfs = get_statfs(&path)?;
        Ok(Fcall::Rstatfs { statfs })
    }
}

// Helper functions

fn metadata_to_qid(meta: &std::fs::Metadata) -> Qid {
    let typ = if meta.is_dir() {
        QidType::DIR
    } else if meta.is_symlink() {
        QidType::SYMLINK
    } else {
        QidType::FILE
    };

    Qid {
        typ,
        version: meta.mtime() as u32,
        path: meta.ino(),
    }
}

fn filetype_to_dirent_type(meta: &std::fs::Metadata) -> u8 {
    const DT_DIR: u8 = 4;
    const DT_LNK: u8 = 10;
    const DT_REG: u8 = 8;

    if meta.is_dir() {
        DT_DIR
    } else if meta.is_symlink() {
        DT_LNK
    } else {
        DT_REG
    }
}

fn serialize_dirents(entries: &[DirEntry], max_size: usize) -> DirEntryData {
    let mut result = DirEntryData::new();
    let mut current_size = 0u32;

    for entry in entries {
        let entry_size = entry.size();
        if current_size + entry_size > max_size as u32 {
            break;
        }
        result.push(entry.clone());
        current_size += entry_size;
    }

    result
}

fn get_statfs(path: &Path) -> Result<Statfs> {
    use nix::sys::statvfs::statvfs;

    let st = statvfs(path)?;

    Ok(Statfs {
        typ: 0x01021997, // V9FS_MAGIC
        bsize: st.block_size() as u32,
        blocks: st.blocks(),
        bfree: st.blocks_free(),
        bavail: st.blocks_available(),
        files: st.files(),
        ffree: st.files_free(),
        fsid: 0,
        namelen: st.name_max() as u32,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use tempfile::TempDir;

    #[test]
    fn test_has_encrypted_markers_true() {
        assert!(SssNinepFS::has_encrypted_markers("password: ⊠{abc123}"));
        assert!(SssNinepFS::has_encrypted_markers("⊠{secret}"));
        assert!(SssNinepFS::has_encrypted_markers("prefix ⊠{data} suffix"));
        assert!(SssNinepFS::has_encrypted_markers("multiple ⊠{one} and ⊠{two}"));
    }

    #[test]
    fn test_has_encrypted_markers_false() {
        assert!(!SssNinepFS::has_encrypted_markers("password: plaintext"));
        assert!(!SssNinepFS::has_encrypted_markers("⊕{plaintext_marker}"));
        assert!(!SssNinepFS::has_encrypted_markers(""));
        assert!(!SssNinepFS::has_encrypted_markers("no markers here"));
        assert!(!SssNinepFS::has_encrypted_markers("o+{ascii_marker}"));
    }

    #[test]
    fn test_should_process_with_sss_regular_files() {
        assert!(SssNinepFS::should_process_with_sss(Path::new("config.yml")));
        assert!(SssNinepFS::should_process_with_sss(Path::new("README.md")));
        assert!(SssNinepFS::should_process_with_sss(Path::new("src/main.rs")));
        assert!(SssNinepFS::should_process_with_sss(Path::new(".config")));
    }

    #[test]
    fn test_should_process_with_sss_vim_swap_files() {
        assert!(!SssNinepFS::should_process_with_sss(Path::new(".config.yml.swp")));
        assert!(!SssNinepFS::should_process_with_sss(Path::new(".file.swo")));
        assert!(!SssNinepFS::should_process_with_sss(Path::new(".test.swp")));
    }

    #[test]
    fn test_should_process_with_sss_temp_files() {
        assert!(!SssNinepFS::should_process_with_sss(Path::new("file~")));
        assert!(!SssNinepFS::should_process_with_sss(Path::new("#file")));
        assert!(!SssNinepFS::should_process_with_sss(Path::new("#backup#")));
    }

    #[test]
    fn test_filetype_to_dirent_type_regular() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.txt");
        std::fs::write(&file_path, "test").unwrap();

        let meta = std::fs::metadata(&file_path).unwrap();
        assert_eq!(filetype_to_dirent_type(&meta), 8); // DT_REG
    }

    #[test]
    fn test_filetype_to_dirent_type_directory() {
        let temp_dir = TempDir::new().unwrap();
        let meta = std::fs::metadata(temp_dir.path()).unwrap();
        assert_eq!(filetype_to_dirent_type(&meta), 4); // DT_DIR
    }

    #[test]
    #[cfg(unix)]
    fn test_filetype_to_dirent_type_symlink() {
        use std::os::unix::fs::symlink;

        let temp_dir = TempDir::new().unwrap();
        let target = temp_dir.path().join("target.txt");
        let link = temp_dir.path().join("link.txt");

        std::fs::write(&target, "test").unwrap();
        symlink(&target, &link).unwrap();

        let meta = std::fs::symlink_metadata(&link).unwrap();
        assert_eq!(filetype_to_dirent_type(&meta), 10); // DT_LNK
    }

    #[test]
    fn test_metadata_to_qid_file() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.txt");
        std::fs::write(&file_path, "test").unwrap();

        let meta = std::fs::metadata(&file_path).unwrap();
        let qid = metadata_to_qid(&meta);

        assert_eq!(qid.typ, QidType::FILE);
        assert!(qid.path > 0); // Inode number
    }

    #[test]
    fn test_metadata_to_qid_directory() {
        let temp_dir = TempDir::new().unwrap();
        let meta = std::fs::metadata(temp_dir.path()).unwrap();
        let qid = metadata_to_qid(&meta);

        assert_eq!(qid.typ, QidType::DIR);
        assert!(qid.path > 0);
    }

    #[test]
    #[cfg(unix)]
    fn test_metadata_to_qid_symlink() {
        use std::os::unix::fs::symlink;

        let temp_dir = TempDir::new().unwrap();
        let target = temp_dir.path().join("target.txt");
        let link = temp_dir.path().join("link.txt");

        std::fs::write(&target, "test").unwrap();
        symlink(&target, &link).unwrap();

        let meta = std::fs::symlink_metadata(&link).unwrap();
        let qid = metadata_to_qid(&meta);

        assert_eq!(qid.typ, QidType::SYMLINK);
    }

    #[test]
    fn test_to_9p_error_conversion() {
        let anyhow_err = anyhow::anyhow!("test error message");
        let p9_err = to_9p_error(anyhow_err);

        // Should convert to a 9p Error (which wraps io::Error)
        // Verify it contains our message
        let err_string = format!("{}", p9_err);
        assert!(err_string.contains("test error message"));
    }

    #[test]
    fn test_serialize_dirents_empty() {
        let entries: Vec<DirEntry> = vec![];
        let result = serialize_dirents(&entries, 1000);
        assert_eq!(result.data.len(), 0);
    }

    #[test]
    fn test_serialize_dirents_respects_max_size() {
        // Create a test entry
        let qid = Qid {
            typ: QidType::FILE,
            version: 0,
            path: 123,
        };

        let entry = DirEntry {
            qid,
            offset: 0,
            typ: 8, // DT_REG
            name: "test.txt".to_string(),
        };

        // Serialize with very small max_size (should truncate)
        let result = serialize_dirents(&[entry.clone()], 1);
        assert_eq!(result.data.len(), 0); // Too small, no entries fit

        // Serialize with large max_size (should include entry)
        let result = serialize_dirents(&[entry], 1000);
        assert_eq!(result.data.len(), 1);
    }

    // Note: Testing async methods and Filesystem trait implementation:
    // - new() requires a real directory and Processor
    // - read_and_render(), read_and_open(), read_sealed() require Processor
    // - write_*() methods require file I/O
    // - All Filesystem trait methods (attach, walk, open, read, write, etc.)
    //   require a 9P server context and are better tested via integration tests
    // - parse_filename() is a private method on SssFid, tested indirectly
}
