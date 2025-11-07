//! Performance benchmarks for marker inference

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use sss::marker_inference::infer_markers;

fn bench_small_file(c: &mut Criterion) {
    let source = "password: o+{secret123}";
    let edited = "password: newsecret456";

    c.bench_function("infer_small", |b| {
        b.iter(|| infer_markers(black_box(source), black_box(edited)))
    });
}

fn bench_multiple_markers(c: &mut Criterion) {
    let source = "user: o+{admin} password: o+{secret123} api_key: o+{abc-def-ghi}";
    let edited = "user: root password: newsecret456 api_key: xyz-uvw-rst";

    c.bench_function("infer_multiple", |b| {
        b.iter(|| infer_markers(black_box(source), black_box(edited)))
    });
}

fn bench_content_propagation(c: &mut Criterion) {
    let source = "o+{secret} and more text";
    let edited = "secret and secret and secret";

    c.bench_function("infer_propagation", |b| {
        b.iter(|| infer_markers(black_box(source), black_box(edited)))
    });
}

fn bench_adjacent_markers(c: &mut Criterion) {
    let source = "o+{a}o+{b}o+{c}";
    let edited = "axbycz";

    c.bench_function("infer_adjacent", |b| {
        b.iter(|| infer_markers(black_box(source), black_box(edited)))
    });
}

criterion_group!(
    benches,
    bench_small_file,
    bench_multiple_markers,
    bench_content_propagation,
    bench_adjacent_markers
);
criterion_main!(benches);
