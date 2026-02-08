//! Performance benchmarks for project-wide seal/open operations on 1000+ files.
//!
//! This benchmark exercises the per-file processing path that is the hot path
//! for `sss project seal` and `sss project open` across large repositories.

use criterion::{criterion_group, criterion_main, BenchmarkGroup, Criterion};
use sss::crypto::RepositoryKey;
use sss::processor::Processor;
use std::path::PathBuf;
use std::time::Duration;

// ---------------------------------------------------------------------------
// Fixture generation
// ---------------------------------------------------------------------------

struct FileFixture {
    /// In-memory representation of file path (relative string) and content
    files: Vec<(PathBuf, String)>,
    /// A pre-sealed copy of every file (used by the open benchmark)
    sealed_files: Vec<(PathBuf, String)>,
}

fn build_fixture(processor: &Processor) -> FileFixture {
    let n_dirs = 10usize;
    let files_per_dir = 120usize; // 10 × 120 = 1 200 files

    let mut files: Vec<(PathBuf, String)> = Vec::with_capacity(n_dirs * files_per_dir);

    for dir_idx in 0..n_dirs {
        for file_idx in 0..files_per_dir {
            let path = PathBuf::from(format!(
                "bench_project/dir{dir_idx:02}/file{file_idx:04}.txt"
            ));
            // Each file contains 1–3 plaintext markers
            let content = format!(
                "# Config file {dir_idx}-{file_idx}\n\
                 api_key = o+{{secret-api-{dir_idx:02}-{file_idx:04}}}\n\
                 db_pass = o+{{secret-db-{dir_idx:02}-{file_idx:04}}}\n\
                 token   = o+{{secret-tok-{dir_idx:02}-{file_idx:04}}}\n"
            );
            files.push((path, content));
        }
    }

    // Pre-seal all files for the open benchmark
    let sealed_files: Vec<(PathBuf, String)> = files
        .iter()
        .map(|(path, content)| {
            let sealed = processor
                .seal_content_with_path(content, path)
                .expect("pre-seal failed");
            (path.clone(), sealed)
        })
        .collect();

    FileFixture {
        files,
        sealed_files,
    }
}

// ---------------------------------------------------------------------------
// Benchmarks
// ---------------------------------------------------------------------------

fn bench_seal_1000_files(c: &mut Criterion) {
    let key = RepositoryKey::new();
    let processor = Processor::new(key).expect("Processor::new failed");
    let fixture = build_fixture(&processor);

    let mut group: BenchmarkGroup<criterion::measurement::WallTime> =
        c.benchmark_group("project_ops");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(30));

    group.bench_function("seal_1200_files", |b| {
        b.iter(|| {
            let mut count = 0usize;
            for (path, content) in &fixture.files {
                processor
                    .seal_content_with_path(content, path)
                    .expect("seal failed");
                count += 1;
            }
            count
        });
    });

    group.finish();
}

fn bench_open_1000_files(c: &mut Criterion) {
    let key = RepositoryKey::new();
    let processor = Processor::new(key).expect("Processor::new failed");
    let fixture = build_fixture(&processor);

    let mut group: BenchmarkGroup<criterion::measurement::WallTime> =
        c.benchmark_group("project_ops_open");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(30));

    group.bench_function("open_1200_files", |b| {
        b.iter(|| {
            let mut count = 0usize;
            for (path, sealed) in &fixture.sealed_files {
                processor
                    .open_content_with_path(sealed, path)
                    .expect("open failed");
                count += 1;
            }
            count
        });
    });

    group.finish();
}

criterion_group!(benches, bench_seal_1000_files, bench_open_1000_files);
criterion_main!(benches);
