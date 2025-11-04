//! Full end-to-end FUSE integration tests
//!
//! These tests verify the complete workflow:
//! 1. Initialize SSS project
//! 2. Mount FUSE filesystem
//! 3. Edit files with marker inference
//! 4. Verify markers are correctly preserved/inferred
//! 5. Unmount and cleanup

#![cfg(all(any(target_os = "linux", target_os = "macos"), feature = "fuse"))]

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;
use tempfile::TempDir;

/// Test helper to create a temporary SSS project
struct TestProject {
    source_dir: TempDir,
    mount_dir: TempDir,
    mount_process: Option<std::process::Child>,
}

impl TestProject {
    /// Create and initialize a new test project
    fn new() -> anyhow::Result<Self> {
        let source_dir = TempDir::new()?;
        let mount_dir = TempDir::new()?;

        // Initialize the SSS project
        let output = Command::new(env!("CARGO_BIN_EXE_sss"))
            .arg("init")
            .current_dir(source_dir.path())
            .output()?;

        if !output.status.success() {
            anyhow::bail!(
                "Failed to initialize project: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        Ok(Self {
            source_dir,
            mount_dir,
            mount_process: None,
        })
    }

    /// Get the source directory path
    fn source_path(&self) -> &Path {
        self.source_dir.path()
    }

    /// Get the mount directory path
    fn mount_path(&self) -> &Path {
        self.mount_dir.path()
    }

    /// Mount the FUSE filesystem
    fn mount(&mut self) -> anyhow::Result<()> {
        let mut child = Command::new(env!("CARGO_BIN_EXE_sss"))
            .arg("mount")
            .arg(self.source_path())
            .arg(self.mount_path())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()?;

        // Wait for mount to be ready (check if mount point is accessible)
        let mount_path = self.mount_path().to_path_buf();
        let mut retries = 20;
        let mounted = loop {
            if retries == 0 {
                break false;
            }
            thread::sleep(Duration::from_millis(100));

            // Check if we can list the directory
            if fs::read_dir(&mount_path).is_ok() {
                break true;
            }

            // Check if process died
            if let Ok(Some(status)) = child.try_wait() {
                let stderr = child.stderr.take();
                if let Some(mut stderr) = stderr {
                    let mut buf = String::new();
                    use std::io::Read;
                    let _ = stderr.read_to_string(&mut buf);
                    eprintln!("Mount process failed: {}", buf);
                }
                anyhow::bail!("Mount process exited with status: {}", status);
            }

            retries -= 1;
        };

        if !mounted {
            child.kill()?;
            anyhow::bail!("Mount failed to become ready");
        }

        self.mount_process = Some(child);
        Ok(())
    }

    /// Unmount the FUSE filesystem
    fn unmount(&mut self) -> anyhow::Result<()> {
        if let Some(mut child) = self.mount_process.take() {
            // Try graceful unmount first
            #[cfg(target_os = "linux")]
            let _ = Command::new("fusermount")
                .arg("-u")
                .arg(self.mount_path())
                .status();

            #[cfg(target_os = "macos")]
            let _ = Command::new("umount")
                .arg(self.mount_path())
                .status();

            // Wait a bit for unmount
            thread::sleep(Duration::from_millis(100));

            // Kill the mount process
            let _ = child.kill();
            let _ = child.wait();
        }
        Ok(())
    }

    /// Write a file to the source directory (encrypted)
    fn write_source_file(&self, path: &str, content: &str) -> anyhow::Result<()> {
        let file_path = self.source_path().join(path);
        if let Some(parent) = file_path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(file_path, content)?;
        Ok(())
    }

    /// Read a file from the source directory
    fn read_source_file(&self, path: &str) -> anyhow::Result<String> {
        let file_path = self.source_path().join(path);
        Ok(fs::read_to_string(file_path)?)
    }

    /// Read a file from the mount point
    fn read_mount_file(&self, path: &str) -> anyhow::Result<String> {
        let file_path = self.mount_path().join(path);
        Ok(fs::read_to_string(file_path)?)
    }

    /// Edit a file noninteractively using ed
    fn edit_file_with_ed(&self, path: &str, commands: &str) -> anyhow::Result<()> {
        let file_path = self.mount_path().join(path);

        let mut child = Command::new("ed")
            .arg("-s")
            .arg(&file_path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;

        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(commands.as_bytes())?;
            stdin.write_all(b"w\nq\n")?;
        }

        let output = child.wait_with_output()?;
        if !output.status.success() {
            anyhow::bail!(
                "ed failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        Ok(())
    }
}

impl Drop for TestProject {
    fn drop(&mut self) {
        let _ = self.unmount();
    }
}

#[test]
#[ignore] // Requires FUSE to be available
fn test_fuse_mount_and_basic_read() {
    let mut project = TestProject::new().expect("Failed to create project");

    // Write a file with markers
    project
        .write_source_file("test.txt", "password: o+{secret123}")
        .expect("Failed to write source file");

    // Mount the filesystem
    project.mount().expect("Failed to mount");

    // Read the file through FUSE (should be rendered)
    let content = project
        .read_mount_file("test.txt")
        .expect("Failed to read from mount");

    // Should see rendered content (markers removed)
    assert_eq!(content, "password: secret123");
}

#[test]
#[ignore] // Requires FUSE to be available
fn test_fuse_marker_inference_simple_edit() {
    let mut project = TestProject::new().expect("Failed to create project");

    // Write a file with a marker
    project
        .write_source_file("config.txt", "api_key: o+{abc-123-def}")
        .expect("Failed to write source file");

    project.mount().expect("Failed to mount");

    // Edit the file to change the secret
    project
        .edit_file_with_ed(
            "config.txt",
            "s/abc-123-def/xyz-456-uvw/\n"
        )
        .expect("Failed to edit file");

    // Give FUSE time to process
    thread::sleep(Duration::from_millis(200));

    project.unmount().expect("Failed to unmount");

    // Read the source file and verify marker was preserved
    let source_content = project
        .read_source_file("config.txt")
        .expect("Failed to read source");

    // Should have marker in canonical form
    assert!(
        source_content.contains("⊕{xyz-456-uvw}") || source_content.contains("o+{xyz-456-uvw}"),
        "Marker not preserved. Content: {}",
        source_content
    );
}

#[test]
#[ignore] // Requires FUSE to be available
fn test_fuse_marker_inference_content_propagation() {
    let mut project = TestProject::new().expect("Failed to create project");

    // Write a file with one marked instance
    project
        .write_source_file("test.txt", "password: o+{secret}\nother text")
        .expect("Failed to write source file");

    project.mount().expect("Failed to mount");

    // Add a duplicate of the secret
    project
        .edit_file_with_ed(
            "test.txt",
            "$a\npassword again: secret\n.\n"
        )
        .expect("Failed to edit file");

    thread::sleep(Duration::from_millis(200));
    project.unmount().expect("Failed to unmount");

    // Read source and verify both instances are marked
    let source_content = project
        .read_source_file("test.txt")
        .expect("Failed to read source");

    // Count occurrences of marked "secret"
    let marker_count = source_content.matches("⊕{secret}").count()
        + source_content.matches("o+{secret}").count();

    assert!(
        marker_count >= 2,
        "Content propagation failed. Only {} instances marked. Content: {}",
        marker_count,
        source_content
    );
}

#[test]
#[ignore] // Requires FUSE to be available
fn test_fuse_marker_inference_adjacent_modification() {
    let mut project = TestProject::new().expect("Failed to create project");

    // Write a file with adjacent content to a marker
    project
        .write_source_file("test.txt", "value: o+{abc} more")
        .expect("Failed to write source file");

    project.mount().expect("Failed to mount");

    // Insert text adjacent to the marker
    project
        .edit_file_with_ed(
            "test.txt",
            "s/abc/abcx/\n"
        )
        .expect("Failed to edit file");

    thread::sleep(Duration::from_millis(200));
    project.unmount().expect("Failed to unmount");

    let source_content = project
        .read_source_file("test.txt")
        .expect("Failed to read source");

    // Marker should have expanded to include 'x'
    assert!(
        source_content.contains("⊕{abcx}") || source_content.contains("o+{abcx}"),
        "Adjacent modification not handled. Content: {}",
        source_content
    );
}

#[test]
#[ignore] // Requires FUSE to be available
fn test_fuse_user_inserted_marker() {
    let mut project = TestProject::new().expect("Failed to create project");

    // Write a plain file
    project
        .write_source_file("test.txt", "public text here")
        .expect("Failed to write source file");

    project.mount().expect("Failed to mount");

    // User adds a marker around some text
    project
        .edit_file_with_ed(
            "test.txt",
            "s/public/o+{secret}/\n"
        )
        .expect("Failed to edit file");

    thread::sleep(Duration::from_millis(200));
    project.unmount().expect("Failed to unmount");

    let source_content = project
        .read_source_file("test.txt")
        .expect("Failed to read source");

    // User-inserted marker should be converted to canonical form
    assert!(
        source_content.contains("⊕{secret}"),
        "User marker not processed. Content: {}",
        source_content
    );
}

#[test]
#[ignore] // Requires FUSE to be available
fn test_fuse_multiline_marker_edit() {
    let mut project = TestProject::new().expect("Failed to create project");

    // Write a file with multiline marker
    project
        .write_source_file("test.txt", "o+{line1\nline2\nline3}")
        .expect("Failed to write source file");

    project.mount().expect("Failed to mount");

    // Edit one of the lines
    project
        .edit_file_with_ed(
            "test.txt",
            "2s/line2/modified2/\n"
        )
        .expect("Failed to edit file");

    thread::sleep(Duration::from_millis(200));
    project.unmount().expect("Failed to unmount");

    let source_content = project
        .read_source_file("test.txt")
        .expect("Failed to read source");

    // Entire block should still be marked
    assert!(
        source_content.contains("⊕{line1\nmodified2\nline3}")
            || source_content.contains("o+{line1\nmodified2\nline3}"),
        "Multiline marker not preserved. Content: {}",
        source_content
    );
}

#[test]
#[ignore] // Requires FUSE to be available
fn test_fuse_complete_rewrite() {
    let mut project = TestProject::new().expect("Failed to create project");

    // Write a file with a marker
    project
        .write_source_file("test.txt", "old: o+{old_value}")
        .expect("Failed to write source file");

    project.mount().expect("Failed to mount");

    // Completely rewrite the file
    project
        .edit_file_with_ed(
            "test.txt",
            "1,$d\na\nnew: completely_different\n.\n"
        )
        .expect("Failed to edit file");

    thread::sleep(Duration::from_millis(200));
    project.unmount().expect("Failed to unmount");

    let source_content = project
        .read_source_file("test.txt")
        .expect("Failed to read source");

    // New content should be marked (expanded from original marker)
    assert!(
        source_content.contains("⊕{") || source_content.contains("o+{"),
        "Marker lost on complete rewrite. Content: {}",
        source_content
    );
}

#[test]
#[ignore] // Requires FUSE to be available
fn test_fuse_delimiter_handling() {
    let mut project = TestProject::new().expect("Failed to create project");

    // Write a file with quoted marker
    project
        .write_source_file("test.txt", "key: \"o+{value}\"")
        .expect("Failed to write source file");

    project.mount().expect("Failed to mount");

    // Modify the value
    project
        .edit_file_with_ed(
            "test.txt",
            "s/value/modified/\n"
        )
        .expect("Failed to edit file");

    thread::sleep(Duration::from_millis(200));
    project.unmount().expect("Failed to unmount");

    let source_content = project
        .read_source_file("test.txt")
        .expect("Failed to read source");

    // Quotes should stay with the marker
    assert!(
        source_content.contains("\"⊕{modified}\"") || source_content.contains("\"o+{modified}\""),
        "Delimiter handling failed. Content: {}",
        source_content
    );
}

#[test]
#[ignore] // Requires FUSE to be available
fn test_fuse_unicode_handling() {
    let mut project = TestProject::new().expect("Failed to create project");

    // Write a file with unicode in marker
    project
        .write_source_file("test.txt", "password: o+{日本語123}")
        .expect("Failed to write source file");

    project.mount().expect("Failed to mount");

    // Modify the unicode content
    project
        .edit_file_with_ed(
            "test.txt",
            "s/日本語123/中文456/\n"
        )
        .expect("Failed to edit file");

    thread::sleep(Duration::from_millis(200));
    project.unmount().expect("Failed to unmount");

    let source_content = project
        .read_source_file("test.txt")
        .expect("Failed to read source");

    assert!(
        source_content.contains("⊕{中文456}") || source_content.contains("o+{中文456}"),
        "Unicode handling failed. Content: {}",
        source_content
    );
}

#[test]
#[ignore] // Requires FUSE to be available
fn test_fuse_multiple_markers_in_file() {
    let mut project = TestProject::new().expect("Failed to create project");

    // Write a file with multiple markers
    project
        .write_source_file(
            "config.yaml",
            "username: o+{admin}\npassword: o+{secret}\napi_key: o+{abc-123}",
        )
        .expect("Failed to write source file");

    project.mount().expect("Failed to mount");

    // Edit multiple values
    project
        .edit_file_with_ed(
            "config.yaml",
            "s/admin/root/\ns/secret/newsecret/\ns/abc-123/xyz-789/\n"
        )
        .expect("Failed to edit file");

    thread::sleep(Duration::from_millis(200));
    project.unmount().expect("Failed to unmount");

    let source_content = project
        .read_source_file("config.yaml")
        .expect("Failed to read source");

    // All three values should be marked
    let marker_count = source_content.matches("⊕{").count() + source_content.matches("o+{").count();
    assert!(
        marker_count >= 3,
        "Not all markers preserved. Only {} markers found. Content: {}",
        marker_count,
        source_content
    );

    assert!(source_content.contains("root"));
    assert!(source_content.contains("newsecret"));
    assert!(source_content.contains("xyz-789"));
}
