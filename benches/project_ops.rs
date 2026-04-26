//! Performance benchmarks for project-wide seal/open operations on 1000+ files.
//!
//! This benchmark exercises the per-file processing path that is the hot path
//! for `sss project seal` and `sss project open` across large repositories.

use criterion::{criterion_group, criterion_main, BenchmarkGroup, Criterion};
use sss::crypto::RepositoryKey;
use sss::processor::Processor;
use std::path::PathBuf;
use std::time::Duration;

use sss::crypto::{ClassicSuite, CryptoSuite, KeyPair};
use sss::crypto::classic::ClassicKeyPair;
use base64::prelude::{BASE64_STANDARD, Engine as _};

#[cfg(feature = "hybrid")]
use sss::crypto::{hybrid::{HybridCryptoSuite, HybridKeyPair}, PublicKey};

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

// ---------------------------------------------------------------------------
// Classic crypto benchmarks (always compiled — for comparison baseline)
// ---------------------------------------------------------------------------

fn bench_classic_keygen(c: &mut Criterion) {
    let mut group = c.benchmark_group("crypto_keygen");
    group.sample_size(20);

    group.bench_function("classic_keygen", |b| {
        b.iter(|| ClassicKeyPair::generate().expect("classic keygen failed"))
    });

    group.finish();
}

fn bench_classic_wrap_unwrap(c: &mut Criterion) {
    let kp = ClassicKeyPair::generate().expect("classic keygen failed");
    let repo_key = RepositoryKey::new();
    let classic = ClassicSuite;
    let public = kp.public_key.clone();
    let keypair = KeyPair::Classic(kp);
    let sealed = classic
        .seal_repo_key(&repo_key, &public)
        .expect("classic seal failed");

    let mut group = c.benchmark_group("crypto_wrap");
    group.sample_size(50);

    group.bench_function("classic_wrap", |b| {
        b.iter(|| {
            classic
                .seal_repo_key(&repo_key, &public)
                .expect("classic seal failed")
        })
    });

    group.bench_function("classic_unwrap", |b| {
        b.iter(|| {
            classic
                .open_repo_key(&sealed, &keypair)
                .expect("classic open failed")
        })
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Hybrid crypto benchmarks (gated: only compiled and run with --features hybrid)
// ---------------------------------------------------------------------------

#[cfg(feature = "hybrid")]
fn bench_hybrid_keygen(c: &mut Criterion) {
    let mut group = c.benchmark_group("crypto_keygen");
    group.sample_size(10); // Hybrid keygen is slower; fewer samples

    group.bench_function("hybrid_keygen", |b| {
        b.iter(|| HybridKeyPair::generate().expect("hybrid keygen failed"))
    });

    group.finish();
}

#[cfg(feature = "hybrid")]
fn bench_hybrid_wrap_unwrap(c: &mut Criterion) {
    let kp = HybridKeyPair::generate().expect("hybrid keygen failed");
    let repo_key = RepositoryKey::new();
    let suite = HybridCryptoSuite;
    let public = PublicKey::Hybrid(kp.public_key());
    let keypair = KeyPair::Hybrid(kp);
    let sealed = suite
        .seal_repo_key(&repo_key, &public)
        .expect("hybrid seal failed");

    let mut group = c.benchmark_group("crypto_wrap");
    group.sample_size(20);

    group.bench_function("hybrid_wrap", |b| {
        b.iter(|| {
            suite
                .seal_repo_key(&repo_key, &public)
                .expect("hybrid seal failed")
        })
    });

    group.bench_function("hybrid_unwrap", |b| {
        b.iter(|| {
            suite
                .open_repo_key(&sealed, &keypair)
                .expect("hybrid open failed")
        })
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// .sss.toml size delta: print raw and base64 sizes for sealed key entries
// This is not a timing benchmark — it is a compile-time constant check.
// ---------------------------------------------------------------------------

fn bench_sealed_key_size_delta(c: &mut Criterion) {
    let repo_key = RepositoryKey::new();

    // Classic sealed key size — seal_repo_key returns Result<String> (base64).
    // Decode to bytes to get the true raw byte count.
    let classic_kp = ClassicKeyPair::generate().expect("classic keygen");
    let classic_public = classic_kp.public_key.clone();
    let classic_sealed_b64 = ClassicSuite
        .seal_repo_key(&repo_key, &classic_public)
        .expect("classic seal");
    let classic_raw = BASE64_STANDARD.decode(&classic_sealed_b64).unwrap().len();
    let classic_b64_chars = classic_sealed_b64.len();

    eprintln!(
        "\n[size delta] classic sealed key: {} bytes raw, {} chars base64",
        classic_raw, classic_b64_chars
    );

    #[cfg(feature = "hybrid")]
    {
        // Hybrid sealed key size — same pattern: decode base64 string to get raw bytes.
        let hybrid_kp = HybridKeyPair::generate().expect("hybrid keygen");
        let hybrid_public = PublicKey::Hybrid(hybrid_kp.public_key());
        let hybrid_sealed_b64 = HybridCryptoSuite
            .seal_repo_key(&repo_key, &hybrid_public)
            .expect("hybrid seal");
        let hybrid_raw = BASE64_STANDARD.decode(&hybrid_sealed_b64).unwrap().len();
        let hybrid_b64_chars = hybrid_sealed_b64.len();

        eprintln!(
            "[size delta]  hybrid sealed key: {} bytes raw, {} chars base64",
            hybrid_raw, hybrid_b64_chars
        );
        eprintln!(
            "[size delta]  delta per user .sss.toml entry: +{} bytes raw, +{} chars base64",
            hybrid_raw.saturating_sub(classic_raw),
            hybrid_b64_chars.saturating_sub(classic_b64_chars)
        );
    }

    // Trivial timing benchmark so criterion accepts this function
    let mut group = c.benchmark_group("sealed_key_size");
    group.sample_size(10);
    group.bench_function("size_delta_report", |b| {
        b.iter(|| classic_raw + classic_b64_chars)
    });
    group.finish();
}

#[cfg(feature = "hybrid")]
criterion_group!(
    hybrid_benches,
    bench_classic_keygen,
    bench_classic_wrap_unwrap,
    bench_hybrid_keygen,
    bench_hybrid_wrap_unwrap,
    bench_sealed_key_size_delta,
);

#[cfg(not(feature = "hybrid"))]
criterion_group!(
    hybrid_benches,
    bench_classic_keygen,
    bench_classic_wrap_unwrap,
    bench_sealed_key_size_delta,
);

criterion_group!(benches, bench_seal_1000_files, bench_open_1000_files);
criterion_main!(benches, hybrid_benches);
