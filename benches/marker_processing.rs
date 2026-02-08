//! Performance benchmarks for single-file marker processing with 100+ markers.
//!
//! Exercises `find_balanced_markers`, `seal_content_with_path`, and
//! `open_content_with_path` on content containing 120 plaintext/ciphertext
//! markers to capture the hot path inside the marker parser and crypto layer.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkGroup, Criterion};
use sss::crypto::RepositoryKey;
use sss::processor::{find_balanced_markers, Processor};
use std::path::PathBuf;

// ---------------------------------------------------------------------------
// Fixture generation
// ---------------------------------------------------------------------------

/// Build a string containing `n` plaintext markers.
fn build_plaintext_content(n: usize) -> String {
    let mut s = String::with_capacity(n * 50);
    for i in 0..n {
        s.push_str(&format!("line {i:04}: api_key_{i} = o+{{secret-value-{i:04}}}\n"));
    }
    s
}

// ---------------------------------------------------------------------------
// Benchmarks
// ---------------------------------------------------------------------------

fn bench_parse_markers(c: &mut Criterion) {
    let content = build_plaintext_content(120);

    let mut group: BenchmarkGroup<criterion::measurement::WallTime> =
        c.benchmark_group("marker_processing");
    group.sample_size(20);

    group.bench_function("parse_120_markers", |b| {
        b.iter(|| {
            find_balanced_markers(black_box(&content), black_box(&["o+", "⊕"]))
        });
    });

    group.finish();
}

fn bench_seal_markers(c: &mut Criterion) {
    let content = build_plaintext_content(120);
    let path = PathBuf::from("bench.txt");

    let key = RepositoryKey::new();
    let processor = Processor::new(key).expect("Processor::new failed");

    let mut group: BenchmarkGroup<criterion::measurement::WallTime> =
        c.benchmark_group("marker_seal");
    group.sample_size(20);

    group.bench_function("seal_120_markers", |b| {
        b.iter(|| {
            processor
                .seal_content_with_path(black_box(&content), black_box(&path))
                .expect("seal failed")
        });
    });

    group.finish();
}

fn bench_open_markers(c: &mut Criterion) {
    let content = build_plaintext_content(120);
    let path = PathBuf::from("bench.txt");

    let key = RepositoryKey::new();
    let processor = Processor::new(key).expect("Processor::new failed");

    // Pre-seal the content so we can benchmark opening
    let sealed = processor
        .seal_content_with_path(&content, &path)
        .expect("pre-seal failed");

    let mut group: BenchmarkGroup<criterion::measurement::WallTime> =
        c.benchmark_group("marker_open");
    group.sample_size(20);

    group.bench_function("open_120_markers", |b| {
        b.iter(|| {
            processor
                .open_content_with_path(black_box(&sealed), black_box(&path))
                .expect("open failed")
        });
    });

    group.finish();
}

/// Benchmark `process_content` which exercises the optimised single-scan path
/// in `process_content_with_path` (auto-detect seal/open direction).
fn bench_process_content(c: &mut Criterion) {
    let content = build_plaintext_content(120);

    let key = RepositoryKey::new();
    let processor = Processor::new(key).expect("Processor::new failed");

    let mut group: BenchmarkGroup<criterion::measurement::WallTime> =
        c.benchmark_group("marker_process");
    group.sample_size(20);

    // Benchmark the auto-detect path (plaintext input → encrypt)
    group.bench_function("process_120_plaintext_markers", |b| {
        b.iter(|| {
            processor
                .process_content(black_box(&content))
                .expect("process failed")
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_parse_markers,
    bench_seal_markers,
    bench_open_markers,
    bench_process_content
);
criterion_main!(benches);
