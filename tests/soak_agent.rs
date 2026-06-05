// Why: integration tests use .unwrap()/.expect()/panic! freely; test code is exempt
// from the panic-surface lint policy per CONTEXT.md Area 1 carve-out.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#![cfg(feature = "slow-tests")]
//! Long-duration soak test for the SSS agent unseal hot-path.
//!
//! Pre-seals one repository key during setup via `sss keys generate --suite
//! classic` plus `sss init <username>` (which writes `.sss.toml` with
//! `users[*].sealed_key`), spawns `sss-agent --foreground` as a child process
//! in a per-test tempdir HOME, then drives 10 000 `unseal_repository_key`
//! calls against the single sealed_key. Samples `/proc/<pid>/status` VmRSS
//! at start (post 30 s warmup) and end, asserts RSS growth <= 10 MB AND
//! total runtime >= 10 minutes, then SIGTERM-s the agent and confirms a
//! clean exit.
//!
//! Suite choice: Classic. Plan 17-03 explicitly authorises Suite::Classic at
//! the unseal call site (lines 359-362). The agent's startup `load_keypair`
//! returns `KeyPair::Classic` unconditionally (keystore.rs::decrypt_stored_keypair
//! always wraps as Classic; the agent has no analogue of the client's
//! load_hybrid_keypair branch in config.rs:307-314), so even a hybrid-sealed
//! key would not be unsealable by the agent today. Exercising the soak hot
//! path under Classic still validates the bounded-RSS guarantee under
//! sustained load — that is the property TEST-13 part-A is gating on.
//!
//! Belt-and-braces gating per Phase 15 D-13:
//!   - source-level: `#![cfg(feature = "slow-tests")]` (this line)
//!   - Cargo.toml:   `[[test]] required-features = ["hybrid", "slow-tests"]`
//!
//! Linux-only `/proc/<pid>/status` is acceptable per Phase 17 CONTEXT D-12
//! because the slow-tests gate prevents this test from being compiled on
//! non-Linux developer hosts in default CI.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use sss::agent::client::AgentClient;
use sss::agent::protocol::RequestContext;
use sss::crypto::Suite;

const UNSEAL_CALLS: usize = 10_000;
const MIN_DURATION_SEC: u64 = 600;
const MAX_RSS_GROWTH_BYTES: u64 = 10 * 1024 * 1024;
const WARMUP_SEC: u64 = 30;
// Inter-call sleep keeps us under the agent's hardcoded 10/min/host rate
// limit (sss-agent.rs:69) when combined with HOSTNAME_BUCKETS-way rotation.
// 10 ms → ~100 calls/s; per-bucket: 100 * 60 / 2048 ≈ 2.9/min, well under
// the 10/min ceiling. Floor of 10k calls in 600 s only needs ~17 cps, so
// this still oversamples by ~6x.
const INTER_CALL_SLEEP_MICROS: u64 = 10_000;
const HOSTNAME_BUCKETS: usize = 2048;

fn read_rss_bytes(pid: u32) -> Option<u64> {
    let path = format!("/proc/{pid}/status");
    let status = std::fs::read_to_string(&path).ok()?;
    let line = status.lines().find(|l| l.starts_with("VmRSS:"))?;
    let kb: u64 = line.split_whitespace().nth(1)?.parse().ok()?;
    Some(kb * 1024)
}

fn apply_test_env(cmd: &mut Command, home: &Path) {
    cmd.env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env("SSS_NONINTERACTIVE", "1")
        .env("SSS_PASSPHRASE", "")
        .env("NO_COLOR", "1")
        .env("USER", "soak-user");
}

fn run_sss(home: &Path, project_dir: &Path, args: &[&str]) {
    let bin = env!("CARGO_BIN_EXE_sss");
    let mut cmd = Command::new(bin);
    apply_test_env(&mut cmd, home);
    cmd.current_dir(project_dir)
        .arg("--kdf-level")
        .arg("interactive");
    for a in args {
        cmd.arg(a);
    }
    let status = cmd.status().expect("sss must spawn");
    assert!(status.success(), "sss {args:?} failed: {status:?}");
}

fn write_permissive_agent_policy(home: &Path) {
    // Default agent-policy denies all requests (require_confirmation=true,
    // default_action=deny). The soak loop runs non-interactively so the
    // built-in AskUser prompt would fail. Write a permissive policy file
    // at the path sss-agent::get_policy_path() reads ($XDG_CONFIG_HOME/sss
    // /agent-policy.toml) before spawning the agent.
    let policy_dir = home.join(".config").join("sss");
    std::fs::create_dir_all(&policy_dir).expect("mkdir agent policy dir");
    let policy_path = policy_dir.join("agent-policy.toml");
    std::fs::write(
        &policy_path,
        "[settings]\nrequire_confirmation = false\ndefault_action = \"allow\"\ntimeout_seconds = 30\n",
    )
    .expect("write agent-policy.toml");
}

fn setup_sealed_key(home: &Path) -> (PathBuf, String, String) {
    let username = "soak-user".to_string();
    let project_dir = home.join("project");
    std::fs::create_dir_all(&project_dir).expect("mkdir project");

    run_sss(
        home,
        &project_dir,
        &["keys", "generate", "--suite", "classic", "--no-password"],
    );
    // `keys generate --suite classic` signs on write (format_version=2), so the
    // entry is immediately loadable. Seal the repo key with the CLASSIC key so
    // the classic-only agent can unseal it — plain `init` now defaults to
    // --crypto hybrid (v2.2).
    run_sss(home, &project_dir, &["init", "--crypto", "classic", &username]);

    let toml_path = project_dir.join(".sss.toml");
    let toml_text = std::fs::read_to_string(&toml_path)
        .unwrap_or_else(|e| panic!("read .sss.toml: {e}"));
    let cfg: sss::project::ProjectConfig =
        toml::from_str(&toml_text).expect("parse .sss.toml");
    let sealed_key = cfg
        .get_sealed_key_for_user(&username)
        .expect("sealed_key for soak-user");
    (project_dir, sealed_key, username)
}

fn spawn_agent(home: &Path) -> Child {
    let bin = env!("CARGO_BIN_EXE_sss-agent");
    let mut cmd = Command::new(bin);
    apply_test_env(&mut cmd, home);
    cmd.arg("--foreground")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    cmd.spawn().expect("sss-agent --foreground must spawn")
}

fn shutdown_agent(mut child: Child) {
    use std::os::unix::process::ExitStatusExt;
    // sss-agent has SIGTERM/SIGINT handlers (src/bin/sss-agent.rs:123) that
    // shut down cleanly. std::process::Child::kill sends SIGKILL on Unix
    // which the agent cannot trap — use libc::kill explicitly so the
    // graceful-shutdown handler runs.
    let pid = child.id() as libc::pid_t;
    unsafe {
        libc::kill(pid, libc::SIGTERM);
    }
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let signal_ok = status.signal().map(|s| s == 15).unwrap_or(false);
                assert!(
                    status.success() || signal_ok,
                    "sss-agent exited with non-success non-SIGTERM status: {status:?}"
                );
                return;
            }
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    panic!("sss-agent did not exit within 30 s of SIGTERM");
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => panic!("waitpid on sss-agent failed: {e}"),
        }
    }
}

fn wait_for_socket(socket_path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if socket_path.exists() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("agent socket did not appear within 10 s: {socket_path:?}");
}

#[test]
fn soak_agent_unseals_for_at_least_10_minutes_with_bounded_rss() {
    // Allow developer override for fast iteration; production gate is the
    // unset path (10-min floor). `SSS_SOAK_DURATION_SEC=60` for a smoke run.
    let min_duration = std::env::var("SSS_SOAK_DURATION_SEC")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(MIN_DURATION_SEC);

    let tmp = tempfile::tempdir().expect("tempdir");
    let home: PathBuf = tmp.path().to_path_buf();

    let (_project_dir, sealed_key, username) = setup_sealed_key(&home);

    write_permissive_agent_policy(&home);

    let agent = spawn_agent(&home);
    let pid = agent.id();

    let socket_path = home.join(".sss-agent.sock");
    wait_for_socket(&socket_path);

    let client = AgentClient::with_socket_path(socket_path.clone());
    client.ping().expect("agent ping must succeed before soak loop");

    // Warmup before initial RSS sample (heap settles after first connect).
    std::thread::sleep(Duration::from_secs(WARMUP_SEC));
    let rss_initial = read_rss_bytes(pid)
        .expect("VmRSS readable from /proc; /proc must be available on Linux test host");

    let started = Instant::now();
    let mut calls_done: usize = 0;
    // Rotate hostnames across HOSTNAME_BUCKETS so no rate-limit bucket exceeds
    // the agent's hardcoded 10/min ceiling (sss-agent.rs:69 +
    // audit_log.rs::RateLimiter::check_rate_limit). Tripping the limit
    // permanently locks the agent (sss-agent.rs:183-196). Combined with the
    // INTER_CALL_SLEEP_MICROS throttle, per-bucket arrival is well under
    // ~3 calls/min — comfortably below the 10/min ceiling.

    for i in 0..UNSEAL_CALLS {
        let mut context = RequestContext::new(username.clone());
        context.hostname = Some(format!("soak-{:04x}", i % HOSTNAME_BUCKETS));
        let repo_key = client
            .unseal_repository_key(&sealed_key, context, Suite::Classic)
            .unwrap_or_else(|e| panic!("unseal_repository_key #{i} failed: {e}"));
        drop(repo_key);
        calls_done += 1;
        std::thread::sleep(Duration::from_micros(INTER_CALL_SLEEP_MICROS));
    }

    while started.elapsed().as_secs() < min_duration {
        let mut context = RequestContext::new(username.clone());
        context.hostname = Some(format!("soak-{:04x}", calls_done % HOSTNAME_BUCKETS));
        let repo_key = client
            .unseal_repository_key(&sealed_key, context, Suite::Classic)
            .unwrap_or_else(|e| panic!("padding unseal #{calls_done} failed: {e}"));
        drop(repo_key);
        calls_done += 1;
        std::thread::sleep(Duration::from_micros(INTER_CALL_SLEEP_MICROS));
    }

    let rss_final = read_rss_bytes(pid).expect("VmRSS readable post-soak");

    shutdown_agent(agent);

    let total_elapsed = started.elapsed().as_secs();
    assert!(
        total_elapsed >= min_duration,
        "soak duration too short: elapsed={total_elapsed}s, min={min_duration}s"
    );
    assert!(
        calls_done >= UNSEAL_CALLS,
        "soak unseal-call count too low: did {calls_done}, want >={UNSEAL_CALLS}"
    );
    let growth = rss_final.saturating_sub(rss_initial);
    assert!(
        growth <= MAX_RSS_GROWTH_BYTES,
        "RSS growth exceeded budget: initial={rss_initial}, final={rss_final}, growth={growth}, budget={MAX_RSS_GROWTH_BYTES} ({}MB)",
        MAX_RSS_GROWTH_BYTES / 1024 / 1024
    );

    eprintln!(
        "soak: unseal_calls={calls_done}, duration={total_elapsed}s, rss_initial={rss_initial}, rss_final={rss_final}, growth={growth}"
    );
}
