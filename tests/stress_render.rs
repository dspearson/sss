// Why: integration tests use .unwrap()/.expect()/panic! freely; test code is exempt
// from the panic-surface lint policy per CONTEXT.md Area 1 carve-out.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#![cfg(feature = "slow-tests")]
//! Stress test for `sss render` (TEST-13 part-B).
//!
//! Builds a single sealed-secrets repo whose project file contains
//! `MIN_SECRETS` (>=1000) sealed `⊠{}` markers, then fires `N_RENDERS`
//! (1000) child-process invocations of `sss render` against that file
//! with bounded concurrency (~`MAX_CONCURRENT` in flight). All `N_RENDERS`
//! invocations must exit 0.
//!
//! The "concurrent" word in TEST-13 is interpreted as fan-out, not literal
//! simultaneous-1000-process load — see Phase 17 CONTEXT D-13 for the RAM
//! rationale (1000 simultaneous OS processes ≈ infeasible RAM; bounded ~64
//! in flight is comfortable on arm64-builder 16GB). The concurrency primitive
//! is `std::thread::scope` + `Arc<AtomicUsize>` — explicitly NOT tokio
//! (CONTEXT D-13 refinement; preserves Phase 10 DEPS-01 audit gate).
//!
//! Belt-and-braces gating per Phase 15 D-13:
//!   - source-level: `#![cfg(feature = "slow-tests")]` (this line)
//!   - Cargo.toml:   `[[test]] required-features = ["hybrid", "slow-tests"]`
//!
//! Suite: Classic, no-password keypair. Marker-based fixture (one file with
//! 1000 `⊕{}` plaintext markers, sealed once in-place via `sss seal -x`).
//! `sss seal --name X --value Y` from the plan's interface block does not
//! match the live CLI (`seal [-x] <file>`); the executor adjusted to the
//! real surface per the plan's CONTRACT escape hatch ("build a repo with
//! >=MIN_SECRETS sealed secrets that `sss render` can subsequently render
//! in a single invocation").

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

const N_RENDERS: usize = 1000;
const MIN_SECRETS: usize = 1_000;
// Bounded fan-out cap — hard-coded to avoid a new dev-dep (num_cpus etc.).
// On arm64-builder 16GB, ~64 in-flight `sss render` processes peak well under
// available RAM (CONTEXT D-13 rationale).
const MAX_CONCURRENT: usize = 64;

fn sss_bin() -> &'static str {
    env!("CARGO_BIN_EXE_sss")
}

fn apply_test_env(cmd: &mut Command, home: &Path) {
    cmd.env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env("SSS_NONINTERACTIVE", "1")
        .env("SSS_PASSPHRASE", "")
        .env("NO_COLOR", "1")
        .env("USER", "stress-user");
}

fn run_sss(home: &Path, project_dir: &Path, args: &[&str]) {
    let mut cmd = Command::new(sss_bin());
    apply_test_env(&mut cmd, home);
    cmd.current_dir(project_dir)
        .arg("--kdf-level")
        .arg("interactive");
    for a in args {
        cmd.arg(a);
    }
    let out = cmd.output().expect("sss must spawn");
    assert!(
        out.status.success(),
        "sss {args:?} failed: status={:?}\nstdout: {}\nstderr: {}",
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

// Build a fresh sealed-secrets repo with a project file containing
// MIN_SECRETS sealed markers. Returns (project_dir, secrets_file).
fn build_fixture(home: &Path) -> (PathBuf, PathBuf) {
    let username = "stress-user";
    let project_dir = home.join("project");
    std::fs::create_dir_all(&project_dir).expect("mkdir project");

    run_sss(
        home,
        &project_dir,
        &["keys", "generate", "--suite", "classic", "--no-password"],
    );
    // `keys generate --suite classic` signs on write (format_version=2), so the
    // entry is immediately loadable. Seal with the CLASSIC key — plain `init`
    // now defaults to --crypto hybrid (v2.2).
    run_sss(home, &project_dir, &["init", "--crypto", "classic", username]);

    // Write a single file with MIN_SECRETS plaintext markers (⊕{value}).
    // U+2295 (⊕) is the open/plaintext marker (matches migrate_e2e.rs:261).
    let mut content = String::with_capacity(MIN_SECRETS * 32);
    for i in 0..MIN_SECRETS {
        content.push_str(&format!("secret_{i:05}=\u{2295}{{value-for-{i:05}}}\n"));
    }
    let secrets_file = project_dir.join("secrets.txt");
    std::fs::write(&secrets_file, &content).expect("write secrets.txt");

    // Seal in-place: ⊕{} → ⊠{} for all MIN_SECRETS markers.
    run_sss(home, &project_dir, &["seal", "-x", "secrets.txt"]);

    // Sanity: file now contains sealed markers (U+22A0 ⊠).
    let sealed = std::fs::read_to_string(&secrets_file).expect("read sealed");
    assert!(
        sealed.contains("\u{22A0}{"),
        "fixture seal did not produce ⊠{{ markers; got first 200 bytes: {}",
        &sealed.chars().take(200).collect::<String>()
    );

    (project_dir, secrets_file)
}

// Run `sss render <file>` in the project dir; returns the exit status.
fn run_render(home: &Path, project_dir: &Path, secrets_file: &Path) -> std::process::ExitStatus {
    let mut cmd = Command::new(sss_bin());
    apply_test_env(&mut cmd, home);
    cmd.current_dir(project_dir)
        .arg("--kdf-level")
        .arg("interactive")
        .arg("render")
        .arg(secrets_file)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    cmd.status().expect("sss render must spawn")
}

#[test]
fn stress_render_1000_concurrent_invocations_all_exit_zero() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let home = tmp.path().to_path_buf();

    eprintln!("stress_render: building fixture with {MIN_SECRETS} secrets...");
    let fixture_start = std::time::Instant::now();
    let (project_dir, secrets_file) = build_fixture(&home);
    let fixture_elapsed = fixture_start.elapsed();
    eprintln!(
        "stress_render: fixture built at {} in {:.1}s",
        project_dir.display(),
        fixture_elapsed.as_secs_f64()
    );

    let in_flight = Arc::new(AtomicUsize::new(0));
    let failures = Arc::new(AtomicUsize::new(0));

    let fanout_start = std::time::Instant::now();
    std::thread::scope(|s| {
        for i in 0..N_RENDERS {
            // Acquire a slot — spin-with-sleep when at MAX_CONCURRENT cap.
            loop {
                let cur = in_flight.load(Ordering::Acquire);
                if cur < MAX_CONCURRENT
                    && in_flight
                        .compare_exchange(cur, cur + 1, Ordering::AcqRel, Ordering::Acquire)
                        .is_ok()
                {
                    break;
                }
                std::thread::sleep(Duration::from_millis(5));
            }

            let in_flight_w = in_flight.clone();
            let failures_w = failures.clone();
            let home_w = home.clone();
            let project_dir_w = project_dir.clone();
            let secrets_file_w = secrets_file.clone();
            s.spawn(move || {
                let status = run_render(&home_w, &project_dir_w, &secrets_file_w);
                if !status.success() {
                    eprintln!("stress_render: invocation {i} exit={status:?}");
                    failures_w.fetch_add(1, Ordering::Relaxed);
                }
                in_flight_w.fetch_sub(1, Ordering::Release);
            });
        }
        // scope() implicitly joins all spawned threads on exit.
    });
    let fanout_elapsed = fanout_start.elapsed();

    let f = failures.load(Ordering::Acquire);
    assert_eq!(
        f, 0,
        "stress_render: {f}/{N_RENDERS} invocations failed; expected all 0 exits"
    );
    eprintln!(
        "stress_render: all {N_RENDERS} invocations exited 0 (fan-out {:.1}s, fixture {:.1}s)",
        fanout_elapsed.as_secs_f64(),
        fixture_elapsed.as_secs_f64()
    );
}
