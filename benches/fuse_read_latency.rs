//! FUSE read-path latency benchmarks
//!
//! These benchmarks exercise the same code path that the FUSE `read()` handler invokes
//! for every file access, without requiring an actual FUSE mount.
//!
//! FUSE read() call chain (from fuse_fs.rs):
//!   1. Kernel hands control to `SssFs::read()`
//!   2. If handle has `cached_content` → slice and reply (fast path)
//!   3. If no handle → `read_and_render()` → `read_and_process()`
//!      a. `read_file_via_fd()`  — disk I/O via openat() + BufReader
//!      b. `has_any_markers_bytes()` — fast byte scan (early exit for plain files)
//!      c. `String::from_utf8()` — validate UTF-8
//!      d. `has_balanced_markers()` — check for `⊠{}` balanced pairs
//!      e. `interpolate_secrets()` — resolve `⊲{}` references
//!      f. `decrypt_to_raw()` — decrypt `⊠{}` → raw plaintext
//!
//! The benchmarks below cover:
//!   - `read_no_markers`        : Read file with NO markers (fast path, exits at step b)
//!   - `read_decrypt_small`     : 1 KB file with 2 ciphertext markers
//!   - `read_decrypt_medium`    : 10 KB file with 20 ciphertext markers
//!   - `read_decrypt_large`     : 100 KB file with 50 ciphertext markers
//!   - `decrypt_only_cached`    : Decrypt pre-loaded content (simulates the cache-hit path)
//!
//! End-to-end FUSE mount testing requires a real FUSE environment. See the latency report
//! at `.planning/phases/10-performance/fuse-latency-report.txt` for manual verification steps.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkGroup, Criterion};
use sss::crypto::RepositoryKey;
use sss::filesystem_common::has_any_markers_bytes;
use sss::processor::Processor;
use std::time::Duration;
use tempfile::TempDir;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Create a Processor with a fresh random key (no project root needed for
/// encrypt/decrypt benchmarks).
fn make_processor() -> Processor {
    let key = RepositoryKey::new();
    Processor::new(key).expect("Processor::new failed")
}

/// Build a small file with `n_markers` plaintext markers and then seal it
/// so we have realistic ciphertext content to decrypt.
fn make_sealed_content(processor: &Processor, filler_kb: usize, n_markers: usize) -> String {
    // Filler text: `filler_kb` kilobytes of repeating ASCII lines
    let line = "# Configuration key: value pair with some context words here.\n";
    let n_lines = (filler_kb * 1024) / line.len();
    let mut content = String::with_capacity(filler_kb * 1024 + n_markers * 80);

    for i in 0..n_markers {
        // Spread markers evenly through the file
        let chunk = n_lines / (n_markers + 1);
        for j in 0..chunk {
            content.push_str(line);
            let _ = j; // suppress warning
        }
        content.push_str(&format!("secret_{i} = o+{{plaintext-secret-value-{i:04}}}\n"));
    }

    // Remaining filler after last marker
    let remaining = n_lines - (n_lines / (n_markers + 1)) * n_markers;
    for _ in 0..remaining {
        content.push_str(line);
    }

    processor
        .process_content(&content)
        .expect("seal failed during fixture build")
}

/// Write content to a temp file and return the tempdir (to keep it alive) and path.
fn write_temp_file(dir: &TempDir, name: &str, content: &str) -> std::path::PathBuf {
    let path = dir.path().join(name);
    std::fs::write(&path, content).expect("write temp file");
    path
}

// ---------------------------------------------------------------------------
// Benchmarks
// ---------------------------------------------------------------------------

/// Fast path: file has no markers at all — `has_any_markers_bytes()` exits early.
fn bench_read_no_markers(c: &mut Criterion) {
    let dir = TempDir::new().expect("tempdir");
    let content = "# Plain config file\nhost = localhost\nport = 5432\n".repeat(200); // ~10 KB
    let path = write_temp_file(&dir, "plain.txt", &content);

    c.bench_function("read_no_markers_10kb", |b| {
        b.iter(|| {
            let bytes = std::fs::read(black_box(&path)).expect("read");
            // Simulate the fast-exit marker scan
            let has_markers = has_any_markers_bytes(&bytes);
            black_box(has_markers)
        });
    });
}

/// Small file (1 KB + 2 ciphertext markers): full decrypt path.
fn bench_read_decrypt_small(c: &mut Criterion) {
    let processor = make_processor();
    let sealed = make_sealed_content(&processor, 1, 2);
    let dir = TempDir::new().expect("tempdir");
    let path = write_temp_file(&dir, "small.txt", &sealed);

    let mut group: BenchmarkGroup<criterion::measurement::WallTime> =
        c.benchmark_group("fuse_read_latency");
    group.sample_size(50);
    group.measurement_time(Duration::from_secs(10));

    group.bench_function("read_decrypt_small_1kb_2markers", |b| {
        b.iter(|| {
            let bytes = std::fs::read(black_box(&path)).expect("read");
            // Step b: fast marker scan
            if has_any_markers_bytes(&bytes) {
                // Step c: UTF-8 conversion
                let content = String::from_utf8(bytes).expect("utf8");
                // Step f: decrypt (simulates FUSE decrypt_to_raw via read_and_render)
                let result = processor.decrypt_content(black_box(&content)).expect("decrypt");
                black_box(result)
            } else {
                black_box(String::from_utf8(bytes).unwrap())
            }
        });
    });

    group.finish();
}

/// Medium file (10 KB + 20 ciphertext markers): full decrypt path.
fn bench_read_decrypt_medium(c: &mut Criterion) {
    let processor = make_processor();
    let sealed = make_sealed_content(&processor, 10, 20);
    let dir = TempDir::new().expect("tempdir");
    let path = write_temp_file(&dir, "medium.txt", &sealed);

    let mut group: BenchmarkGroup<criterion::measurement::WallTime> =
        c.benchmark_group("fuse_read_latency");
    group.sample_size(50);
    group.measurement_time(Duration::from_secs(15));

    group.bench_function("read_decrypt_medium_10kb_20markers", |b| {
        b.iter(|| {
            let bytes = std::fs::read(black_box(&path)).expect("read");
            if has_any_markers_bytes(&bytes) {
                let content = String::from_utf8(bytes).expect("utf8");
                let result = processor.decrypt_content(black_box(&content)).expect("decrypt");
                black_box(result)
            } else {
                black_box(String::from_utf8(bytes).unwrap())
            }
        });
    });

    group.finish();
}

/// Large file (100 KB + 50 ciphertext markers): full decrypt path.
fn bench_read_decrypt_large(c: &mut Criterion) {
    let processor = make_processor();
    let sealed = make_sealed_content(&processor, 100, 50);
    let dir = TempDir::new().expect("tempdir");
    let path = write_temp_file(&dir, "large.txt", &sealed);

    let mut group: BenchmarkGroup<criterion::measurement::WallTime> =
        c.benchmark_group("fuse_read_latency");
    group.sample_size(50);
    group.measurement_time(Duration::from_secs(20));

    group.bench_function("read_decrypt_large_100kb_50markers", |b| {
        b.iter(|| {
            let bytes = std::fs::read(black_box(&path)).expect("read");
            if has_any_markers_bytes(&bytes) {
                let content = String::from_utf8(bytes).expect("utf8");
                let result = processor.decrypt_content(black_box(&content)).expect("decrypt");
                black_box(result)
            } else {
                black_box(String::from_utf8(bytes).unwrap())
            }
        });
    });

    group.finish();
}

/// Cached-content path: content already in memory, only decrypt (no disk I/O).
/// Simulates the `FileHandle.cached_content` fast path in `SssFs::read()`.
fn bench_decrypt_only_cached(c: &mut Criterion) {
    let processor = make_processor();

    // Pre-load content for each size into memory
    let small_sealed = make_sealed_content(&processor, 1, 2);
    let medium_sealed = make_sealed_content(&processor, 10, 20);

    let mut group: BenchmarkGroup<criterion::measurement::WallTime> =
        c.benchmark_group("fuse_read_latency");
    group.sample_size(50);
    group.measurement_time(Duration::from_secs(10));

    group.bench_function("decrypt_only_cached_small", |b| {
        b.iter(|| {
            let result = processor
                .decrypt_content(black_box(&small_sealed))
                .expect("decrypt");
            black_box(result)
        });
    });

    group.bench_function("decrypt_only_cached_medium", |b| {
        b.iter(|| {
            let result = processor
                .decrypt_content(black_box(&medium_sealed))
                .expect("decrypt");
            black_box(result)
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_read_no_markers,
    bench_read_decrypt_small,
    bench_read_decrypt_medium,
    bench_read_decrypt_large,
    bench_decrypt_only_cached,
);
criterion_main!(benches);
