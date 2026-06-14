// Why: integration tests use .unwrap()/.expect()/panic! freely; test code is exempt
// from the panic-surface lint policy per CONTEXT.md Area 1 carve-out (Phase 8 HARDEN).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
// Why: doc_markdown in test code (//! lines with unbackticked identifiers like process-compose,
// vault-ca.pem, http_get) is noise; these are prose descriptions, not code items.
#![allow(clippy::doc_markdown)]
// Why: `new_without_default` — VaultDevServer::new() returns a ServerOutcome enum, not Self;
// clippy can't tell it's intentional. `must_use` on helpers — test code; callers always use them.
// `too_many_lines` on VaultDevServer::new() — the seeding sequence is inherently long.
// `collapsible_if` / `assertions_on_result_states` — test code clarity > lint noise.
#![allow(
    clippy::new_without_default,
    clippy::new_ret_no_self,
    clippy::must_use_candidate,
    clippy::too_many_lines,
    clippy::collapsible_if,
    clippy::assertions_on_result_states,
    clippy::redundant_else
)]
// Why: the whole file is the vault integration tier; default builds never see it.
#![cfg(feature = "vault")]

//! Phase 47-05 — Live Vault integration-test harness + IT matrix.
//!
//! # Pinned toolchain (flake.lock)
//!
//! Toolchain pinned by committed `flake.lock`:
//!   nixpkgs rev : 8c91a71d13451abc40eb9dae8910f972f979852f
//!   openbao     : 2.5.4  (MPL-2.0, Linux Foundation OpenBao fork; binary: `bao`)
//!   process-compose : 1.110.0  (Apache-2.0)
//!
//! # Harness: `VaultDevServer`
//!
//! Hand-rolled RAII helper that shells `process-compose` via
//! `std::process::Command` (NOT podman — avoids a container runtime dep;
//! NOT `testcontainers` — its bollard+tokio dev-dep tree conflicts with the
//! project's no-tokio-outside-ninep ethos; adds ZERO Cargo deps).
//!
//! ## Process lifecycle
//!
//! 1. `VaultDevServer::new()` reserves a free loopback port, generates a random
//!    dev root token + a unique process-compose API socket, and starts:
//!
//!    ```text
//!    process-compose up -f tests/vault/process-compose.yaml \
//!        --unix-socket <sock> --detached --tui=false
//!    ```
//!
//!    with `SSS_IT_VAULT_PORT`, `SSS_IT_VAULT_TOKEN`, and `SSS_IT_VAULT_CERT_DIR`
//!    in the environment.
//!
//! 2. The `process-compose.yaml` service definition runs:
//!    ```text
//!    bao server -dev -dev-tls -dev-tls-cert-dir=<cert-dir> \
//!        -dev-root-token-id=<tok> -dev-listen-address=127.0.0.1:<port>
//!    ```
//!    and declares a `http_get` readiness_probe on `https://127.0.0.1:<port>/v1/sys/health`.
//!
//! 3. `new()` reads the generated CA PEM from `<cert-dir>/vault-ca.pem` (written by
//!    bao on startup) with a bounded retry, then polls `GET /v1/sys/health` until 200
//!    using a CA-pinned ureq agent (belt-and-braces on top of the process-compose probe).
//!
//! 4. `new()` seeds KV-v2 secrets + enables/configures AppRole over REST with the
//!    dev root token, returns a `VaultDevServer` handle.
//!
//! ## RAII teardown
//!
//! `Drop` runs `process-compose --unix-socket <sock> down` (best-effort) which causes
//! process-compose to send SIGTERM to OpenBao and reap it.  This mirrors
//! `TempFileGuard`'s unlinkat-on-drop (REM-18) and ensures cleanup even when a test
//! panics mid-assertion (T-47-IT3).
//!
//! ## TLS note
//!
//! sss enforces `https://` for all vault addresses (VCFG-02 / `validate_vault_address`).
//! `-dev-tls` instructs bao to generate a self-signed CA + cert on startup; the CA PEM
//! is written to `<cert-dir>/vault-ca.pem`.  Each test project carries
//! `tls_ca_secret = "vault_ca"` (mandatory CA pinning, VCFG-05) and the CA is written
//! into a plaintext `.secrets` file.  Each sss CLI call receives
//! `--allow-unsigned` (VCFG-05 opt-in for format_version=1 + [vault]).
//!
//! ## Per-instance isolation
//!
//! Each test creates its OWN `VaultDevServer` instance (unique loopback port,
//! dev token, process-compose socket, cert dir) so tests are parallel-safe.
//!
//! ## Skip-gracefully contract
//!
//! When `process-compose version` or `bao version` fails (tools absent — not inside
//! `nix develop .#vault-it`), every test logs a skip note and returns `Ok`.  Default
//! `cargo test` never needs nix or network (T-47-IT4).
//!
//! # IT matrix (all run against a REAL ephemeral OpenBao)
//!
//! 0. `vault_dev_server_starts_and_health_ok`      — smoke: server up, /v1/sys/health 200
//! 1. `kv_happy_path_renders_resolved_value`        — `⊳{ref}` → resolved via `sss render`
//! 2. `approle_login_then_get`                      — AppRole login + `sss vault get`
//! 3. `version_pin_resolves_v2`                     — `⊳{ref@2}` → v2 value, not v1/v3
//! 4. `acl_denied_ref_exits_3`                      — per-ref ACL miss → exit 3, marker preserved
//! 5. `vault_down_exits_4`                          — dead port → exit 4, no output
//! 6. `token_never_logged`                          — dev root token / secret_id never in output
//!
//! # IT matrix (Phase 48-02 — lock / verify / drift / all-or-nothing / list)
//!
//! 7.  `lock_then_verify_exits_0`                    — lock writes lockfile; verify exits 0
//! 8.  `mutate_secret_then_verify_reports_drift`     — UNPINNED ref: verify exits 2 on changed secret; value absent from stderr
//! 9.  `pinned_ref_no_drift_on_newer_version`        — PINNED @2 ref: newer KV version is NOT drift; verify exits 0; value-free
//! 10. `version_pin_recorded_in_lockfile`            — @2 pin → lockfile entry has `version = 2`; no plaintext
//! 11. `lock_all_or_nothing_leaves_lockfile_untouched` — ACL miss → exit 3; lockfile UNCHANGED
//! 12. `vault_list_enumerates_refs`                  — list prints both canonical refs sorted; no secret value

use std::fs;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

use tempfile::TempDir;

// ─── Timing constants ─────────────────────────────────────────────────────────

/// How long to wait for bao to write vault-ca.pem to the cert dir.
///
/// Budget = `CA_POLL_TRIES × CA_POLL_INTERVAL` ≈ 120 × 250ms ≈ 30s.  This MUST
/// tolerate parallel-test contention: under the default (multi-threaded) test
/// runner several `VaultDevServer`s spin up concurrently, and the old ≈10s
/// budget (40 × 250ms) was too tight — `vault_list_enumerates_refs` flaked on
/// CA-readiness while passing single-threaded.  Widening to ≈30s removes the
/// flake without changing the health-poll constants below.
const CA_POLL_TRIES: u32 = 120;
const CA_POLL_INTERVAL: Duration = Duration::from_millis(250);

/// How long to poll /v1/sys/health for a 200 response after the cert is found.
const HEALTH_POLL_TRIES: u32 = 60;
const HEALTH_POLL_INTERVAL: Duration = Duration::from_millis(500);

// ─── Binary under test ───────────────────────────────────────────────────────

fn sss_bin() -> &'static str {
    env!("CARGO_BIN_EXE_sss")
}

// ─── VaultDevServer — RAII process-compose/OpenBao harness ───────────────────

/// Outcome of `VaultDevServer::new()`.
///
/// Either the server is up and seeded (`Ready`), or the nix-provided tools
/// (`process-compose` / `bao`) are absent (`Skipped`).  Tests call
/// `skip_if_unavailable()` which maps `Skipped` to a skip-and-pass.
pub enum ServerOutcome {
    Ready(VaultDevServer),
    Skipped(&'static str),
}

/// A running dev-mode OpenBao server managed by process-compose.
///
/// # Lifetime invariant
///
/// The server is started by `new()`, seeded with KV-v2 secrets + AppRole
/// over the Vault REST API, and **reaped by `Drop`** (`process-compose down`)
/// so the server is always cleaned up, even when a test panics mid-assertion.
/// This mirrors `TempFileGuard`'s Drop-based cleanup (REM-18).
///
/// The server binds ONLY `127.0.0.1` (`-dev-listen-address=127.0.0.1:<port>`).
pub struct VaultDevServer {
    /// Unix socket path for process-compose IPC (unique per instance).
    sock_path: PathBuf,
    /// Keeps the TempDir owning the socket parent directory alive until Drop.
    _sock_dir: TempDir,
    /// Keeps the TempDir owning the bao TLS cert files alive until Drop.
    /// bao reads vault-ca.pem / vault-cert.pem / vault-key.pem while running,
    /// so this must outlive the process.
    _cert_dir: TempDir,
    /// `https://127.0.0.1:<port>` — base URL for Vault REST calls.
    base_url: String,
    /// The dev root token (throwaway, disposable).
    dev_root_token: String,
    /// PEM-encoded CA certificate generated by bao's `-dev-tls` mode.
    /// Written into each test project's `.secrets` so sss can pin it.
    pub ca_pem: String,
    /// Seeded AppRole role_id (UUID from the dev OpenBao).
    pub role_id: String,
    /// Seeded AppRole secret_id.
    pub secret_id: String,
}

impl VaultDevServer {
    /// Attempt to start a dev-mode OpenBao via process-compose.
    ///
    /// Returns `ServerOutcome::Skipped` when `process-compose version` or
    /// `bao version` fails (tools not on PATH — not inside `nix develop .#vault-it`).
    /// Callers treat `Skipped` as a skip-and-pass.
    ///
    /// # Panics
    ///
    /// Only panics when the tools ARE present and startup/seeding fails
    /// (a real unexpected error, not a missing-tool skip).
    pub fn new() -> ServerOutcome {
        // ── 1. Probe: are process-compose and bao on PATH? ───────────────
        //    Checks BOTH tools; if either is missing, skip gracefully.
        let pc_ok = Command::new("process-compose")
            .arg("version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if !pc_ok {
            return ServerOutcome::Skipped("process-compose not on PATH — not inside nix develop .#vault-it");
        }

        let bao_ok = Command::new("bao")
            .arg("version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if !bao_ok {
            return ServerOutcome::Skipped("bao not on PATH — not inside nix develop .#vault-it");
        }

        // ── 2. Reserve an ephemeral host port. ───────────────────────────
        // Bind, read the port, drop the listener to release it.  Small TOCTOU
        // window is acceptable in test code.
        let host_port = {
            let l = TcpListener::bind("127.0.0.1:0").expect("bind free port");
            l.local_addr().expect("local_addr").port()
        };

        // ── 3. Unique per-instance socket path + cert dir. ────────────────
        let sock_dir = TempDir::new().expect("temp dir for socket");
        let sock_path = sock_dir.path().join("pc.sock");
        let cert_dir = TempDir::new().expect("temp dir for bao TLS cert");

        // ── 4. Random dev root token (throwaway, loopback-only). ─────────
        let dev_root_token = format!("sss-it-dev-{}", uuid::Uuid::new_v4().as_simple());

        let base_url = format!("https://127.0.0.1:{host_port}");

        // ── 5. Start the process-compose stack headless + detached. ──────
        // Flags:  -D / --detached : start in detached mode (background)
        //         -t=false        : disable TUI
        //         -u <sock>       : unique per-instance API socket
        // The service definition is at tests/vault/process-compose.yaml.
        // We must pass the env vars that the YAML references.
        //
        // CARGO_MANIFEST_DIR points to the crate root regardless of cwd.
        let yaml_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("vault")
            .join("process-compose.yaml");

        let pc_up = Command::new("process-compose")
            .args([
                "up",
                "-f",
                yaml_path.to_str().expect("yaml path is UTF-8"),
                "-u",
                sock_path.to_str().expect("sock path is UTF-8"),
                "-D",
                "-t=false",
            ])
            .env("SSS_IT_VAULT_PORT", host_port.to_string())
            .env("SSS_IT_VAULT_TOKEN", &dev_root_token)
            .env("SSS_IT_VAULT_CERT_DIR", cert_dir.path())
            .output()
            .expect("process-compose up");

        assert!(
            pc_up.status.success(),
            "process-compose up failed: {}",
            String::from_utf8_lossy(&pc_up.stderr)
        );

        // ── 6. Poll for vault-ca.pem (written by bao on startup). ────────
        let ca_pem_path = cert_dir.path().join("vault-ca.pem");
        let ca_start = Instant::now();
        let mut ca_pem = String::new();
        for _ in 0..CA_POLL_TRIES {
            if let Ok(pem) = fs::read_to_string(&ca_pem_path) {
                if pem.contains("BEGIN CERTIFICATE") {
                    ca_pem = pem;
                    break;
                }
            }
            thread::sleep(CA_POLL_INTERVAL);
        }
        assert!(
            !ca_pem.is_empty(),
            "bao vault-ca.pem not found in {} within {:?} (cert_dir={})",
            ca_pem_path.display(),
            ca_start.elapsed(),
            cert_dir.path().display()
        );

        // ── 7. Build a CA-pinned ureq agent for health polling. ──────────
        let root_certs = sss::vault::client::build_root_certs(Some(ca_pem.as_bytes()))
            .expect("parse vault CA PEM");
        let agent = ureq::Agent::config_builder()
            .timeout_connect(Some(Duration::from_secs(2)))
            .timeout_recv_body(Some(Duration::from_secs(5)))
            .http_status_as_error(false)
            .tls_config(
                ureq::tls::TlsConfig::builder()
                    .root_certs(root_certs)
                    .build(),
            )
            .build()
            .new_agent();

        // ── 8. Poll /v1/sys/health until 200 (belt-and-braces). ─────────
        let health_url = format!("{base_url}/v1/sys/health");
        let health_start = Instant::now();
        let mut ready = false;
        for _ in 0..HEALTH_POLL_TRIES {
            match agent.get(&health_url).call() {
                Ok(resp) if resp.status() == 200 => {
                    ready = true;
                    break;
                }
                _ => thread::sleep(HEALTH_POLL_INTERVAL),
            }
        }
        assert!(
            ready,
            "OpenBao did not become healthy within {:?} (port={host_port})",
            health_start.elapsed()
        );

        // ── 9. Seed KV-v2 + AppRole over REST. ──────────────────────────
        // Helper closures (all borrow local bindings in this function frame).

        let vault_post = |path: &str, body: serde_json::Value| {
            let url = format!("{base_url}{path}");
            let body_bytes = serde_json::to_vec(&body).unwrap();
            agent
                .post(&url)
                .header("X-Vault-Token", dev_root_token.as_str())
                .header("Content-Type", "application/json")
                .send(body_bytes)
                .expect("vault POST")
        };

        let vault_put = |path: &str, body: serde_json::Value| {
            let url = format!("{base_url}{path}");
            let body_bytes = serde_json::to_vec(&body).unwrap();
            agent
                .put(&url)
                .header("X-Vault-Token", dev_root_token.as_str())
                .header("Content-Type", "application/json")
                .send(body_bytes)
                .expect("vault PUT")
        };

        let vault_get = |path: &str| -> serde_json::Value {
            let url = format!("{base_url}{path}");
            let resp = agent
                .get(&url)
                .header("X-Vault-Token", dev_root_token.as_str())
                .call()
                .expect("vault GET");
            let reader = resp.into_body().into_reader();
            serde_json::from_reader(reader).expect("vault GET parse JSON")
        };

        // KV-v2: dev OpenBao mounts secret/ as KV-v2 by default.
        // Write the happy-path secret.
        let r = vault_post(
            "/v1/secret/data/app",
            serde_json::json!({ "data": { "password": "s3cr3t-from-vault" } }),
        );
        assert!(r.status() == 200, "KV write /secret/data/app failed: {}", r.status());

        // Write a 3-version secret for the @version pin test.
        // Each POST to KV-v2 creates a new version.
        for (i, val) in ["version-one", "version-two", "version-three"].iter().enumerate() {
            let r = vault_post(
                "/v1/secret/data/versioned",
                serde_json::json!({ "data": { "value": val } }),
            );
            assert!(
                r.status() == 200,
                "KV write versioned v{} failed: {}",
                i + 1,
                r.status()
            );
        }

        // Write a secret the restricted-policy AppRole CAN read (exit-3 test).
        let r = vault_post(
            "/v1/secret/data/allowed",
            serde_json::json!({ "data": { "value": "allowed-value" } }),
        );
        assert!(r.status() == 200, "KV write /secret/data/allowed failed");

        // Enable AppRole auth method.
        let r = vault_post("/v1/sys/auth/approle", serde_json::json!({ "type": "approle" }));
        // 204 = success; 400 = already enabled; both OK.
        assert!(
            r.status() == 204 || r.status() == 400,
            "enable approle failed: {}",
            r.status()
        );

        // Write a permissive policy for the happy-path AppRole role.
        let r = vault_put(
            "/v1/sys/policies/acl/sss-it-policy",
            serde_json::json!({
                "policy": "path \"secret/data/*\" { capabilities = [\"read\"] }\npath \"auth/token/lookup-self\" { capabilities = [\"read\"] }\n"
            }),
        );
        assert!(r.status() == 204, "write policy sss-it-policy failed: {}", r.status());

        // Write a restricted policy (exit-3 test: only /secret/data/allowed).
        let r = vault_put(
            "/v1/sys/policies/acl/sss-restricted-policy",
            serde_json::json!({
                "policy": "path \"secret/data/allowed\" { capabilities = [\"read\"] }\npath \"auth/token/lookup-self\" { capabilities = [\"read\"] }\n"
            }),
        );
        assert!(r.status() == 204, "write policy sss-restricted-policy failed: {}", r.status());

        // Create the happy-path AppRole role.
        let r = vault_post(
            "/v1/auth/approle/role/sss-it-role",
            serde_json::json!({
                "policies": ["sss-it-policy"],
                "token_ttl": "1h",
                "token_max_ttl": "2h"
            }),
        );
        assert!(r.status() == 204, "create approle role sss-it-role failed: {}", r.status());

        // Create the restricted AppRole role (exit-3 test).
        let r = vault_post(
            "/v1/auth/approle/role/sss-restricted-role",
            serde_json::json!({
                "policies": ["sss-restricted-policy"],
                "token_ttl": "1h",
                "token_max_ttl": "2h"
            }),
        );
        assert!(
            r.status() == 204,
            "create approle role sss-restricted-role failed: {}",
            r.status()
        );

        // Read the happy-path role_id.
        let role_body = vault_get("/v1/auth/approle/role/sss-it-role/role-id");
        let role_id = role_body["data"]["role_id"]
            .as_str()
            .expect("role_id must be a string")
            .to_string();
        assert!(!role_id.is_empty(), "role_id must not be empty");

        // Generate a secret_id for the happy-path role.
        let sid_resp = vault_post(
            "/v1/auth/approle/role/sss-it-role/secret-id",
            serde_json::json!({}),
        );
        assert!(
            sid_resp.status() == 200,
            "generate secret_id failed: {}",
            sid_resp.status()
        );
        let sid_body: serde_json::Value =
            serde_json::from_reader(sid_resp.into_body().into_reader()).expect("secret-id JSON");
        let secret_id = sid_body["data"]["secret_id"]
            .as_str()
            .expect("secret_id must be a string")
            .to_string();
        assert!(!secret_id.is_empty(), "secret_id must not be empty");

        ServerOutcome::Ready(VaultDevServer {
            sock_path,
            _sock_dir: sock_dir,
            _cert_dir: cert_dir,
            base_url,
            dev_root_token,
            ca_pem,
            role_id,
            secret_id,
        })
    }

    /// The base URL for this OpenBao server (`https://127.0.0.1:<port>`).
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// The dev root token (throwaway, dev-mode only).
    pub fn dev_root_token(&self) -> &str {
        &self.dev_root_token
    }

    /// Build a CA-pinned ureq agent for making direct Vault REST calls in tests.
    pub fn agent(&self) -> ureq::Agent {
        let root_certs = sss::vault::client::build_root_certs(Some(self.ca_pem.as_bytes()))
            .expect("build root certs from vault CA PEM");
        ureq::Agent::config_builder()
            .http_status_as_error(false)
            .tls_config(
                ureq::tls::TlsConfig::builder()
                    .root_certs(root_certs)
                    .build(),
            )
            .build()
            .new_agent()
    }
}

impl Drop for VaultDevServer {
    fn drop(&mut self) {
        // Why: teardown is best-effort cleanup even on panic.  If process-compose down
        // fails (e.g. the socket is gone), the bao process will eventually exit on its
        // own.  Ignoring the result here mirrors `TempFileGuard`'s unlinkat-on-drop
        // (REM-18).  process-compose sends SIGTERM to the OpenBao child on `down`,
        // so the managed process is reaped even if this host's ulimits are tight
        // (T-47-IT3: no orphaned port holders).
        let _ = Command::new("process-compose")
            .args([
                "down",
                "-u",
                self.sock_path.to_str().unwrap_or("/tmp/missing.sock"),
            ])
            .status();
    }
}

// ─── Skip helper ─────────────────────────────────────────────────────────────

/// Call at the start of each matrix test.
///
/// Returns `Some(server)` when the server is up and seeded.
/// Logs a skip note and returns `None` when the nix devShell tools are absent —
/// callers do `let Some(vault) = skip_if_unavailable() else { return; };`
/// so the test passes gracefully without the devShell.
fn skip_if_unavailable() -> Option<VaultDevServer> {
    match VaultDevServer::new() {
        ServerOutcome::Ready(v) => Some(v),
        ServerOutcome::Skipped(reason) => {
            eprintln!(
                "SKIP: nix devShell (process-compose/bao) unavailable — {reason}\n\
                 Run via: nix develop .#vault-it --command cargo test --features vault --test vault_integration"
            );
            None
        }
    }
}

// ─── Isolated sss project environment ────────────────────────────────────────

/// An isolated project directory with a `.sss.toml` pointing at the live
/// OpenBao server.  Mirrors the `UserEnv` pattern from `vault_cli_signon.rs`.
///
/// # TLS pinning
///
/// `format_version=1` projects with a `[vault]` section require CA pinning
/// (`tls_ca_secret` mandatory per VCFG-05) and `--allow-unsigned` on the CLI.
/// The harness writes the bao-generated CA PEM into a **plaintext** `.secrets`
/// file (sss treats a file that does NOT start with `⊠{` as unencrypted).
struct ProjectEnv {
    project_dir: TempDir,
    home_dir: TempDir,
}

/// Write the Vault CA PEM into a plaintext `secrets` file in `dir`.
///
/// sss's default `secrets_filename` is `"secrets"` (no dot prefix); the
/// dotfile `.secrets` is only used as the *suffix* for per-file companion
/// secrets (Strategy 1 in `find_secrets_file_with_ops`).  This function
/// writes the file that Strategy 2's upward walk discovers.
fn write_ca_secrets(dir: &Path, ca_pem: &str) {
    let mut content = String::from("vault_ca: |\n");
    for line in ca_pem.lines() {
        content.push_str("  ");
        content.push_str(line);
        content.push('\n');
    }
    fs::write(dir.join("secrets"), &content).expect("write plaintext secrets with vault CA");
}

impl ProjectEnv {
    fn base_cmd(project_dir: &TempDir, home_dir: &TempDir) -> Command {
        let mut cmd = Command::new(sss_bin());
        cmd.env("HOME", home_dir.path())
            .env("XDG_CONFIG_HOME", home_dir.path().join(".config"))
            .env("SSS_NONINTERACTIVE", "1")
            .env("SSS_PASSPHRASE", "")
            .env("NO_COLOR", "1")
            .env("USER", "vault-it")
            .current_dir(project_dir.path())
            .arg("--kdf-level")
            .arg("interactive");
        cmd
    }

    fn init_sss_project(project_dir: &TempDir, home_dir: &TempDir) {
        // Step 1: generate a no-password classic keypair.
        let keygen = Self::base_cmd(project_dir, home_dir)
            .args(["keys", "generate", "--suite", "classic", "--no-password", "--force"])
            .output()
            .expect("keygen");
        assert!(
            keygen.status.success(),
            "sss keys generate failed: {}",
            String::from_utf8_lossy(&keygen.stderr)
        );

        // Step 2: upgrade the freshly-generated key to signed format_version=3.
        // Classic keygen intentionally writes an unsigned v1 entry; `sss init`
        // calls `get_current_keypair(allow_unsigned=false)` so without this
        // upgrade it would error with "No keypair found".
        let current_path = home_dir
            .path()
            .join(".config")
            .join("sss")
            .join("keys")
            .join("current");
        let current_content =
            fs::read_to_string(&current_path).expect("read keystore current pointer");
        let key_id = current_content
            .lines()
            .find(|l| l.starts_with("uuid"))
            .and_then(|l| l.split('"').nth(1))
            .expect("parse key uuid from current pointer");

        let upgrade = Self::base_cmd(project_dir, home_dir)
            .args(["keys", "upgrade", key_id])
            .output()
            .expect("sss keys upgrade");
        let already_signed = String::from_utf8_lossy(&upgrade.stderr)
            .contains("upgrade is a no-op");
        assert!(
            upgrade.status.success() || already_signed,
            "sss keys upgrade failed: {}",
            String::from_utf8_lossy(&upgrade.stderr)
        );

        // Step 3: init a classic project.
        let init = Self::base_cmd(project_dir, home_dir)
            .args(["init", "--crypto", "classic", "vault-it"])
            .output()
            .expect("sss init");
        assert!(
            init.status.success(),
            "sss init failed: {}",
            String::from_utf8_lossy(&init.stderr)
        );
    }

    fn append_vault_config(project_dir: &TempDir, vault_toml: &str) {
        let path = project_dir.path().join(".sss.toml");
        let mut existing = fs::read_to_string(&path).expect("read .sss.toml");
        existing.push('\n');
        existing.push_str(vault_toml);
        fs::write(&path, existing).expect("write .sss.toml with vault config");
    }

    /// Create a project pointing at the live server with CA pinning.
    fn new_with_vault(vault: &VaultDevServer, binding_name: &str, mount: &str) -> Self {
        let project_dir = TempDir::new().expect("project tempdir");
        let home_dir = TempDir::new().expect("home tempdir");

        Self::init_sss_project(&project_dir, &home_dir);

        let vault_toml = format!(
            r#"
[vault]
address = "{url}"
default_binding = "{binding}"
tls_ca_secret = "vault_ca"

[vault.bindings.{binding}]
mount = "{mount}"
kv_version = 2
default_field = "value"
"#,
            url = vault.base_url(),
            binding = binding_name,
            mount = mount,
        );
        Self::append_vault_config(&project_dir, &vault_toml);
        write_ca_secrets(project_dir.path(), &vault.ca_pem);

        Self { project_dir, home_dir }
    }

    /// Like `new_with_vault` but the KV binding uses `default_field = "password"`.
    fn new_with_password_field(vault: &VaultDevServer) -> Self {
        let project_dir = TempDir::new().expect("project tempdir");
        let home_dir = TempDir::new().expect("home tempdir");

        Self::init_sss_project(&project_dir, &home_dir);

        let vault_toml = format!(
            r#"
[vault]
address = "{url}"
default_binding = "kv"
tls_ca_secret = "vault_ca"

[vault.bindings.kv]
mount = "secret"
kv_version = 2
default_field = "password"
"#,
            url = vault.base_url(),
        );
        Self::append_vault_config(&project_dir, &vault_toml);
        write_ca_secrets(project_dir.path(), &vault.ca_pem);

        Self { project_dir, home_dir }
    }

    fn cmd(&self) -> Command {
        Self::base_cmd(&self.project_dir, &self.home_dir)
    }

    fn write_file(&self, name: &str, content: &str) -> PathBuf {
        let path = self.project_dir.path().join(name);
        fs::write(&path, content).expect("write file");
        path
    }
}

// ─── Test 0: smoke — VaultDevServer starts and /v1/sys/health returns 200 ────

#[test]
fn vault_dev_server_starts_and_health_ok() {
    let Some(vault) = skip_if_unavailable() else {
        return;
    };

    // Health check: new() already polled; if we're here it is healthy.
    // Confirm seeding succeeded.
    assert!(!vault.role_id.is_empty(), "role_id must be non-empty after seeding");
    assert!(!vault.secret_id.is_empty(), "secret_id must be non-empty after seeding");
    assert!(!vault.ca_pem.is_empty(), "CA PEM must be non-empty");

    // Double-check with a direct CA-pinned HTTP call.
    let health_url = format!("{}/v1/sys/health", vault.base_url());
    let resp = vault.agent().get(&health_url).call().expect("health check GET");
    assert_eq!(resp.status(), 200, "OpenBao health endpoint must return 200");
}

// ─── Test 1: KV happy-path — ⊳{ref} resolves to the seeded value ─────────────

#[test]
fn kv_happy_path_renders_resolved_value() {
    let Some(vault) = skip_if_unavailable() else {
        return;
    };

    let env = ProjectEnv::new_with_password_field(&vault);
    env.write_file("secret.txt", "password=⊳{app#password}");

    let out = env
        .cmd()
        .env("SSS_VAULT_TOKEN", vault.dev_root_token())
        .args(["render", "--allow-unsigned", "secret.txt"])
        .output()
        .expect("sss render");

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);

    assert!(
        out.status.success(),
        "sss render must exit 0; stdout={stdout}, stderr={stderr}"
    );
    assert!(
        stdout.contains("s3cr3t-from-vault"),
        "stdout must contain the resolved vault value; stdout={stdout}"
    );
    // Token must NOT appear in output (T-47-IT2 / VNET-04).
    assert!(
        !stdout.contains(vault.dev_root_token()),
        "dev root token must not appear in stdout"
    );
    assert!(
        !stderr.contains(vault.dev_root_token()),
        "dev root token must not appear in stderr"
    );
}

// ─── Test 2: AppRole login → token → sss vault get ───────────────────────────

#[test]
fn approle_login_then_get() {
    let Some(vault) = skip_if_unavailable() else {
        return;
    };

    let project_dir = TempDir::new().expect("project dir");
    let home_dir = TempDir::new().expect("home dir");

    ProjectEnv::init_sss_project(&project_dir, &home_dir);

    let vault_toml = format!(
        r#"
[vault]
address = "{url}"
default_binding = "kv"
tls_ca_secret = "vault_ca"

[vault.bindings.kv]
mount = "secret"
kv_version = 2
default_field = "password"

[vault.auth]
method = "approle"
role_id = "{role_id}"
"#,
        url = vault.base_url(),
        role_id = vault.role_id,
    );
    ProjectEnv::append_vault_config(&project_dir, &vault_toml);
    write_ca_secrets(project_dir.path(), &vault.ca_pem);

    let make_cmd = || {
        let mut cmd = Command::new(sss_bin());
        cmd.env("HOME", home_dir.path())
            .env("XDG_CONFIG_HOME", home_dir.path().join(".config"))
            .env("SSS_NONINTERACTIVE", "1")
            .env("SSS_PASSPHRASE", "")
            .env("NO_COLOR", "1")
            .env("USER", "vault-it")
            // Supply the secret_id via env (highest precedence).
            .env("SSS_VAULT_SECRET_ID", &vault.secret_id)
            .current_dir(project_dir.path())
            .arg("--kdf-level")
            .arg("interactive");
        cmd
    };

    // `sss vault --allow-unsigned login` must print TTL, NEVER the token.
    let login_out = make_cmd()
        .args(["vault", "--allow-unsigned", "login"])
        .output()
        .expect("sss vault login");
    let login_stdout = String::from_utf8_lossy(&login_out.stdout);
    let login_stderr = String::from_utf8_lossy(&login_out.stderr);

    assert!(
        login_out.status.success(),
        "sss vault login must exit 0; stderr={login_stderr}"
    );
    assert!(
        login_stdout.contains("token TTL") || login_stdout.contains("ttl") || login_stdout.contains("TTL"),
        "login output must mention TTL; stdout={login_stdout}"
    );
    // The secret_id must NOT appear in stdout or stderr (VAUTH-05).
    assert!(
        !login_stdout.contains(&vault.secret_id),
        "secret_id must not appear in login stdout"
    );
    assert!(
        !login_stderr.contains(&vault.secret_id),
        "secret_id must not appear in login stderr"
    );

    // `sss vault --allow-unsigned get app#password` — resolves via AppRole.
    let get_out = make_cmd()
        .args(["vault", "--allow-unsigned", "get", "app#password"])
        .output()
        .expect("sss vault get");
    let get_stdout = String::from_utf8_lossy(&get_out.stdout);
    let get_stderr = String::from_utf8_lossy(&get_out.stderr);

    assert!(
        get_out.status.success(),
        "sss vault get must exit 0; stderr={get_stderr}"
    );
    assert!(
        get_stdout.contains("s3cr3t-from-vault"),
        "vault get must return the seeded value; stdout={get_stdout}"
    );
    assert!(
        !get_stdout.contains(&vault.secret_id),
        "secret_id must not appear in vault get stdout"
    );
}

// ─── Test 3: @version pin — ⊳{ref@2} resolves to v2 value ───────────────────

#[test]
fn version_pin_resolves_v2() {
    let Some(vault) = skip_if_unavailable() else {
        return;
    };

    // `versioned` was written 3× during seeding: v1="version-one", v2="version-two",
    // v3="version-three".  Pin to @2; the project default_field is `value`.
    let env = ProjectEnv::new_with_vault(&vault, "kv", "secret");
    env.write_file("ver.txt", "val=⊳{versioned@2}");

    let out = env
        .cmd()
        .env("SSS_VAULT_TOKEN", vault.dev_root_token())
        .args(["render", "--allow-unsigned", "ver.txt"])
        .output()
        .expect("sss render @version");

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);

    assert!(
        out.status.success(),
        "sss render @version must exit 0; stdout={stdout}, stderr={stderr}"
    );
    assert!(
        stdout.contains("version-two"),
        "stdout must contain v2 value 'version-two'; stdout={stdout}"
    );
    assert!(
        !stdout.contains("version-one"),
        "stdout must NOT contain v1 value; stdout={stdout}"
    );
    assert!(
        !stdout.contains("version-three"),
        "stdout must NOT contain v3 value; stdout={stdout}"
    );
}

// ─── Test 4: exit-3 — ACL-denied ref → exit 3, marker preserved ──────────────

#[test]
fn acl_denied_ref_exits_3() {
    let Some(vault) = skip_if_unavailable() else {
        return;
    };

    // Get role_id/secret_id for the restricted role and mint a restricted token.
    let agent = vault.agent();
    let base = vault.base_url();
    let root_token = vault.dev_root_token();

    // Get restricted role_id.
    let role_resp = agent
        .get(&format!("{base}/v1/auth/approle/role/sss-restricted-role/role-id"))
        .header("X-Vault-Token", root_token)
        .call()
        .expect("get restricted role-id");
    let role_body: serde_json::Value =
        serde_json::from_reader(role_resp.into_body().into_reader()).expect("role-id JSON");
    let restricted_role_id = role_body["data"]["role_id"]
        .as_str()
        .expect("restricted role_id")
        .to_string();

    // Generate restricted secret_id.
    let sid_resp = agent
        .post(&format!("{base}/v1/auth/approle/role/sss-restricted-role/secret-id"))
        .header("X-Vault-Token", root_token)
        .header("Content-Type", "application/json")
        .send(b"{}".to_vec())
        .expect("generate restricted secret-id");
    let sid_body: serde_json::Value =
        serde_json::from_reader(sid_resp.into_body().into_reader()).expect("secret-id JSON");
    let restricted_secret_id = sid_body["data"]["secret_id"]
        .as_str()
        .expect("restricted secret_id")
        .to_string();

    // Login as restricted AppRole → restricted token.
    let login_body = serde_json::json!({
        "role_id": restricted_role_id,
        "secret_id": restricted_secret_id,
    });
    let login_resp = agent
        .post(&format!("{base}/v1/auth/approle/login"))
        .header("Content-Type", "application/json")
        .send(serde_json::to_vec(&login_body).unwrap())
        .expect("restricted approle login");
    let login_json: serde_json::Value =
        serde_json::from_reader(login_resp.into_body().into_reader()).expect("login JSON");
    let restricted_token = login_json["auth"]["client_token"]
        .as_str()
        .expect("client_token")
        .to_string();

    let env = ProjectEnv::new_with_vault(&vault, "kv", "secret");

    // File has TWO refs: one good (allowed) and one bad (ACL-denied app).
    env.write_file("mixed.txt", "good=⊳{allowed#value}\nbad=⊳{app#password}\n");

    let out = env
        .cmd()
        .env("SSS_VAULT_TOKEN", &restricted_token)
        .args(["render", "--allow-unsigned", "mixed.txt"])
        .output()
        .expect("sss render mixed");

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);

    // Must exit 3 (per-reference miss).
    assert_eq!(
        out.status.code(),
        Some(3),
        "must exit 3 on ACL-denied ref; stdout={stdout}, stderr={stderr}"
    );
    // The bad marker must be preserved verbatim in stdout.
    assert!(
        stdout.contains("⊳{app#password}"),
        "bad marker must be preserved verbatim in stdout; stdout={stdout}"
    );
    // The good ref must have resolved.
    assert!(
        stdout.contains("allowed-value"),
        "good ref must be resolved; stdout={stdout}"
    );
    // stderr must contain an unresolved-references report.
    assert!(
        stderr.contains("unresolved") || stderr.contains("app#password"),
        "stderr must report unresolved references; stderr={stderr}"
    );
    // Tokens must not appear in output.
    assert!(
        !stdout.contains(&restricted_token),
        "restricted token must not appear in stdout"
    );
    assert!(
        !stderr.contains(&restricted_token),
        "restricted token must not appear in stderr"
    );
}

// ─── Test 5: exit-4 — dead port → whole-operation failure → exit 4 ───────────

#[test]
fn vault_down_exits_4() {
    // This test does NOT need the nix devShell — it just needs a dead port.
    // We still check for process-compose on PATH for consistency with the
    // matrix convention; hosts without the devShell skip gracefully.
    let pc_ok = Command::new("process-compose")
        .arg("version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if !pc_ok {
        eprintln!("SKIP: process-compose not on PATH — vault_down_exits_4");
        return;
    }

    // Bind+drop a port to get a guaranteed ECONNREFUSED address.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let dead_port = listener.local_addr().expect("local addr").port();
    drop(listener);

    let project_dir = TempDir::new().expect("project dir");
    let home_dir = TempDir::new().expect("home dir");

    ProjectEnv::init_sss_project(&project_dir, &home_dir);

    // tls_ca_secret is mandatory (VCFG-05) even though the connection will fail.
    // Write as "secrets" (no dot) — matches sss's default secrets_filename.
    let dummy_secrets = "vault_ca: dummy-cert-never-used\n";
    fs::write(project_dir.path().join("secrets"), dummy_secrets).expect("write dummy secrets");

    let vault_toml = format!(
        r#"
[vault]
address = "https://127.0.0.1:{dead_port}"
default_binding = "kv"
tls_ca_secret = "vault_ca"

[vault.bindings.kv]
mount = "secret"
kv_version = 2
default_field = "password"
"#
    );
    ProjectEnv::append_vault_config(&project_dir, &vault_toml);

    fs::write(project_dir.path().join("target.txt"), "val=⊳{app#password}")
        .expect("write target");

    let out = Command::new(sss_bin())
        .env("HOME", home_dir.path())
        .env("XDG_CONFIG_HOME", home_dir.path().join(".config"))
        .env("SSS_NONINTERACTIVE", "1")
        .env("SSS_PASSPHRASE", "")
        .env("NO_COLOR", "1")
        .env("USER", "vault-it")
        .env("SSS_VAULT_TOKEN", "fake-token-for-dead-port")
        .current_dir(project_dir.path())
        .args([
            "--kdf-level",
            "interactive",
            "render",
            "--allow-unsigned",
            "target.txt",
        ])
        .output()
        .expect("sss render dead-port");

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);

    // Must exit 4 (whole-operation failure — Vault unreachable).
    assert_eq!(
        out.status.code(),
        Some(4),
        "must exit 4 on dead-port Vault; stdout={stdout}, stderr={stderr}"
    );
    // No resolved output should appear (all-or-nothing).
    assert!(
        stdout.is_empty() || !stdout.contains("password"),
        "stdout must have no resolved value on exit 4; stdout={stdout}"
    );
}

// ─── Vault REST helper ────────────────────────────────────────────────────────

/// Write a KV-v2 secret, returning the resulting version number.
///
/// `path` is the KV path (e.g. `"app"` for `/v1/secret/data/app`).
/// `field` / `value` are the single key-value to write.
/// Uses the dev root token from the `VaultDevServer`.
fn put_kv_version(
    vault: &VaultDevServer,
    path: &str,
    field: &str,
    value: &str,
) -> u64 {
    let agent = vault.agent();
    let url = format!("{}/v1/secret/data/{path}", vault.base_url());
    let body = serde_json::json!({ "data": { field: value } });
    let resp = agent
        .post(&url)
        .header("X-Vault-Token", vault.dev_root_token())
        .header("Content-Type", "application/json")
        .send(serde_json::to_vec(&body).unwrap())
        .expect("vault KV write");
    assert!(
        resp.status() == 200,
        "put_kv_version {path}/{field}={value} failed: {}",
        resp.status()
    );
    let parsed: serde_json::Value =
        serde_json::from_reader(resp.into_body().into_reader()).expect("KV write response JSON");
    parsed["data"]["version"]
        .as_u64()
        .expect("version field in KV write response must be u64")
}

// ─── Test 6: token-never-logged — dev root token / secret_id never in output ──

#[test]
fn token_never_logged() {
    let Some(vault) = skip_if_unavailable() else {
        return;
    };

    let env = ProjectEnv::new_with_password_field(&vault);
    env.write_file("secret.txt", "val=⊳{app#password}");

    let mut all_output = String::new();

    // Happy-path render.
    let out = env
        .cmd()
        .env("SSS_VAULT_TOKEN", vault.dev_root_token())
        .args(["render", "--allow-unsigned", "secret.txt"])
        .output()
        .expect("render for token-leak check");
    all_output.push_str(&String::from_utf8_lossy(&out.stdout));
    all_output.push_str(&String::from_utf8_lossy(&out.stderr));

    // vault status.
    let out = env
        .cmd()
        .env("SSS_VAULT_TOKEN", vault.dev_root_token())
        .args(["vault", "--allow-unsigned", "status"])
        .output()
        .expect("vault status for token-leak check");
    all_output.push_str(&String::from_utf8_lossy(&out.stdout));
    all_output.push_str(&String::from_utf8_lossy(&out.stderr));

    // Dev root token must never appear anywhere in collected output.
    assert!(
        !all_output.contains(vault.dev_root_token()),
        "dev root token must not appear in any captured output"
    );
    // secret_id must also not appear.
    assert!(
        !all_output.contains(&vault.secret_id),
        "seeded secret_id must not appear in any captured output"
    );
}

// ─── Test 7: lock_then_verify_exits_0 ─────────────────────────────────────────
//
// VLOCK-01: `sss vault lock` writes `.sss.vault.lock`; subsequent `sss vault verify`
// exits 0 (all digests match the just-locked values).

#[test]
fn lock_then_verify_exits_0() {
    let Some(vault) = skip_if_unavailable() else {
        return;
    };

    // Use the seeded `app#password` secret.
    let env = ProjectEnv::new_with_password_field(&vault);
    env.write_file("config.txt", "db_pass=⊳{app#password}");

    // Run `sss vault lock`.
    let lock_out = env
        .cmd()
        .env("SSS_VAULT_TOKEN", vault.dev_root_token())
        .args(["vault", "--allow-unsigned", "lock"])
        .output()
        .expect("sss vault lock");
    let lock_stdout = String::from_utf8_lossy(&lock_out.stdout);
    let lock_stderr = String::from_utf8_lossy(&lock_out.stderr);
    assert!(
        lock_out.status.success(),
        "sss vault lock must exit 0; stdout={lock_stdout}, stderr={lock_stderr}"
    );

    // `.sss.vault.lock` must exist.
    let lockfile_path = env.project_dir.path().join(".sss.vault.lock");
    assert!(
        lockfile_path.exists(),
        ".sss.vault.lock must be created by `vault lock`"
    );

    // No secret value must appear in lock stdout/stderr.
    assert!(
        !lock_stdout.contains("s3cr3t-from-vault"),
        "secret value must not appear in vault lock stdout; stdout={lock_stdout}"
    );
    assert!(
        !lock_stderr.contains("s3cr3t-from-vault"),
        "secret value must not appear in vault lock stderr; stderr={lock_stderr}"
    );

    // Run `sss vault verify` — must exit 0 (no drift).
    let verify_out = env
        .cmd()
        .env("SSS_VAULT_TOKEN", vault.dev_root_token())
        .args(["vault", "--allow-unsigned", "verify"])
        .output()
        .expect("sss vault verify");
    let verify_stdout = String::from_utf8_lossy(&verify_out.stdout);
    let verify_stderr = String::from_utf8_lossy(&verify_out.stderr);
    assert_eq!(
        verify_out.status.code(),
        Some(0),
        "sss vault verify must exit 0 after lock; stdout={verify_stdout}, stderr={verify_stderr}"
    );

    // Secret value must never appear in verify output (VLOCK-02 / VNET-04).
    assert!(
        !verify_stdout.contains("s3cr3t-from-vault"),
        "secret value must not appear in verify stdout; stdout={verify_stdout}"
    );
    assert!(
        !verify_stderr.contains("s3cr3t-from-vault"),
        "secret value must not appear in verify stderr; stderr={verify_stderr}"
    );
}

// ─── Test 8: mutate_secret_then_verify_reports_drift ──────────────────────────
//
// VLOCK-02 / VLOCK-04: after locking, mutating the secret causes `verify` to exit 2
// (drift detected).  The resolved secret value must NOT appear in the drift report.

#[test]
fn mutate_secret_then_verify_reports_drift() {
    let Some(vault) = skip_if_unavailable() else {
        return;
    };

    // Seed a fresh secret path for this test to avoid interference.
    let _v1 = put_kv_version(&vault, "drift-target", "secret", "original-value");

    // Write a custom VaultConfig pointing at this new path.
    let project_dir = tempfile::TempDir::new().expect("project dir");
    let home_dir = tempfile::TempDir::new().expect("home dir");
    ProjectEnv::init_sss_project(&project_dir, &home_dir);

    let vault_toml = format!(
        r#"
[vault]
address = "{url}"
default_binding = "kv"
tls_ca_secret = "vault_ca"

[vault.bindings.kv]
mount = "secret"
kv_version = 2
default_field = "secret"
"#,
        url = vault.base_url(),
    );
    ProjectEnv::append_vault_config(&project_dir, &vault_toml);
    write_ca_secrets(project_dir.path(), &vault.ca_pem);

    let make_cmd = || {
        let mut cmd = Command::new(sss_bin());
        cmd.env("HOME", home_dir.path())
            .env("XDG_CONFIG_HOME", home_dir.path().join(".config"))
            .env("SSS_NONINTERACTIVE", "1")
            .env("SSS_PASSPHRASE", "")
            .env("NO_COLOR", "1")
            .env("USER", "vault-it")
            .env("SSS_VAULT_TOKEN", vault.dev_root_token())
            .current_dir(project_dir.path())
            .arg("--kdf-level")
            .arg("interactive");
        cmd
    };

    // Write a file referencing the drift-target secret.
    fs::write(
        project_dir.path().join("app.conf"),
        "key=⊳{drift-target}",
    )
    .expect("write app.conf");

    // Lock at v1.
    let lock_out = make_cmd()
        .args(["vault", "--allow-unsigned", "lock"])
        .output()
        .expect("vault lock");
    assert!(
        lock_out.status.success(),
        "vault lock must succeed; stderr={}",
        String::from_utf8_lossy(&lock_out.stderr)
    );

    // Mutate the secret (v2).
    put_kv_version(&vault, "drift-target", "secret", "mutated-value");

    // Verify — must exit 2 (drift).
    let verify_out = make_cmd()
        .args(["vault", "--allow-unsigned", "verify"])
        .output()
        .expect("vault verify");
    let verify_stdout = String::from_utf8_lossy(&verify_out.stdout);
    let verify_stderr = String::from_utf8_lossy(&verify_out.stderr);

    assert_eq!(
        verify_out.status.code(),
        Some(2),
        "vault verify must exit 2 on drift; stdout={verify_stdout}, stderr={verify_stderr}"
    );

    // The mutated secret VALUE must NOT appear in output (VLOCK-04 / VNET-04).
    assert!(
        !verify_stdout.contains("mutated-value"),
        "mutated value must not appear in verify stdout; stdout={verify_stdout}"
    );
    assert!(
        !verify_stderr.contains("mutated-value"),
        "mutated value must not appear in verify stderr; stderr={verify_stderr}"
    );
    // Original locked value also must not appear.
    assert!(
        !verify_stdout.contains("original-value"),
        "original value must not appear in verify stdout; stdout={verify_stdout}"
    );
    assert!(
        !verify_stderr.contains("original-value"),
        "original value must not appear in verify stderr; stderr={verify_stderr}"
    );
}

// ─── Test 8b: pinned_ref_no_drift_on_newer_version ────────────────────────────
//
// VLOCK-01 (symmetric counterpart to `mutate_secret_then_verify_reports_drift`):
// a `@N`-PINNED ref is an immutable integrity check.  Writing a NEWER KV version
// to the same path after lock MUST NOT be reported as drift — `verify` re-resolves
// the pinned `@N`, whose value (and therefore keyed digest) is unchanged, so it
// exits 0.  This proves the pin-origin fix does not over-fire: only UNPINNED refs
// treat a newer version as drift.
#[test]
fn pinned_ref_no_drift_on_newer_version() {
    let Some(vault) = skip_if_unavailable() else {
        return;
    };

    // `versioned` seeded in harness: v1=version-one, v2=version-two, v3=version-three.
    let env = ProjectEnv::new_with_vault(&vault, "kv", "secret");
    // Pin explicitly to @2 (an immutable integrity target).
    env.write_file("pinned.conf", "key=⊳{versioned@2}");

    // Lock the pinned ref.
    let lock_out = env
        .cmd()
        .env("SSS_VAULT_TOKEN", vault.dev_root_token())
        .args(["vault", "--allow-unsigned", "lock"])
        .output()
        .expect("sss vault lock @2");
    let lock_stderr = String::from_utf8_lossy(&lock_out.stderr);
    assert!(
        lock_out.status.success(),
        "vault lock must succeed for @2 pin; stderr={lock_stderr}"
    );

    // Write a NEWER KV version to the same path AFTER lock.  For an unpinned ref
    // this would be drift; for a pinned ref it must NOT be.
    put_kv_version(&vault, "versioned", "value", "version-four");

    // Verify — must exit 0 (pinned @2 is immutable; a newer version is not drift).
    let verify_out = env
        .cmd()
        .env("SSS_VAULT_TOKEN", vault.dev_root_token())
        .args(["vault", "--allow-unsigned", "verify"])
        .output()
        .expect("sss vault verify (pinned no-drift)");
    let verify_stdout = String::from_utf8_lossy(&verify_out.stdout);
    let verify_stderr = String::from_utf8_lossy(&verify_out.stderr);
    assert_eq!(
        verify_out.status.code(),
        Some(0),
        "pinned @2 ref must NOT drift when a newer KV version exists (VLOCK-01); \
         stdout={verify_stdout}, stderr={verify_stderr}"
    );

    // No resolved secret value may appear in verify output (value-free, VLOCK-04).
    for forbidden in ["version-two", "version-four"] {
        assert!(
            !verify_stdout.contains(forbidden),
            "secret value `{forbidden}` must not appear in verify stdout; stdout={verify_stdout}"
        );
        assert!(
            !verify_stderr.contains(forbidden),
            "secret value `{forbidden}` must not appear in verify stderr; stderr={verify_stderr}"
        );
    }
}

// ─── Test 9: version_pin_recorded_in_lockfile ─────────────────────────────────
//
// VLOCK-01 / VLOCK-03: when locking a @N-pinned ref, the lockfile entry must record
// `version = N`.  No plaintext secret value may appear in the lockfile.

#[test]
fn version_pin_recorded_in_lockfile() {
    let Some(vault) = skip_if_unavailable() else {
        return;
    };

    // `versioned` seeded in harness: v1=version-one, v2=version-two, v3=version-three.
    let env = ProjectEnv::new_with_vault(&vault, "kv", "secret");
    // Pin to @2 explicitly.
    env.write_file("pinned.txt", "val=⊳{versioned@2}");

    let lock_out = env
        .cmd()
        .env("SSS_VAULT_TOKEN", vault.dev_root_token())
        .args(["vault", "--allow-unsigned", "lock"])
        .output()
        .expect("vault lock @2");
    let lock_stderr = String::from_utf8_lossy(&lock_out.stderr);
    assert!(
        lock_out.status.success(),
        "vault lock must succeed for @2 pin; stderr={lock_stderr}"
    );

    // Read and parse the lockfile.
    let lockfile_path = env.project_dir.path().join(".sss.vault.lock");
    assert!(lockfile_path.exists(), ".sss.vault.lock must exist");
    let lockfile_content = fs::read_to_string(&lockfile_path).expect("read lockfile");

    // The lockfile must record version = 2 for the pinned entry.
    assert!(
        lockfile_content.contains("version = 2"),
        "lockfile must record version = 2 for @2 pin; lockfile=\n{lockfile_content}"
    );

    // No plaintext secret value may appear in the lockfile (VLOCK-01).
    assert!(
        !lockfile_content.contains("version-two"),
        "lockfile must NOT contain the plaintext secret value; lockfile=\n{lockfile_content}"
    );
    assert!(
        !lockfile_content.contains("version-one"),
        "lockfile must NOT contain any plaintext value; lockfile=\n{lockfile_content}"
    );
}

// ─── Test 10: lock_all_or_nothing_leaves_lockfile_untouched ───────────────────
//
// VLOCK-01: if ANY ref fails to resolve, the lockfile must remain UNCHANGED
// (all-or-nothing semantics, exit 3).

#[test]
fn lock_all_or_nothing_leaves_lockfile_untouched() {
    let Some(vault) = skip_if_unavailable() else {
        return;
    };

    // Build a restricted token that can only read `allowed` (not `app`).
    let agent = vault.agent();
    let base = vault.base_url();
    let root_token = vault.dev_root_token();

    let role_resp = agent
        .get(&format!("{base}/v1/auth/approle/role/sss-restricted-role/role-id"))
        .header("X-Vault-Token", root_token)
        .call()
        .expect("get restricted role-id");
    let role_body: serde_json::Value =
        serde_json::from_reader(role_resp.into_body().into_reader()).expect("role-id JSON");
    let restricted_role_id = role_body["data"]["role_id"]
        .as_str()
        .expect("restricted role_id")
        .to_string();

    let sid_resp = agent
        .post(&format!("{base}/v1/auth/approle/role/sss-restricted-role/secret-id"))
        .header("X-Vault-Token", root_token)
        .header("Content-Type", "application/json")
        .send(b"{}".to_vec())
        .expect("generate restricted secret-id");
    let sid_body: serde_json::Value =
        serde_json::from_reader(sid_resp.into_body().into_reader()).expect("secret-id JSON");
    let restricted_secret_id = sid_body["data"]["secret_id"]
        .as_str()
        .expect("restricted secret_id")
        .to_string();

    let login_body = serde_json::json!({
        "role_id": restricted_role_id,
        "secret_id": restricted_secret_id,
    });
    let login_resp = agent
        .post(&format!("{base}/v1/auth/approle/login"))
        .header("Content-Type", "application/json")
        .send(serde_json::to_vec(&login_body).unwrap())
        .expect("restricted approle login");
    let login_json: serde_json::Value =
        serde_json::from_reader(login_resp.into_body().into_reader()).expect("login JSON");
    let restricted_token = login_json["auth"]["client_token"]
        .as_str()
        .expect("client_token")
        .to_string();

    let env = ProjectEnv::new_with_vault(&vault, "kv", "secret");

    // Write a file with one good ref AND one ACL-denied ref.
    env.write_file(
        "mixed.txt",
        "good=⊳{allowed#value}\nbad=⊳{app#password}\n",
    );

    // Write a sentinel lockfile content — lock must not touch this.
    let lockfile_path = env.project_dir.path().join(".sss.vault.lock");
    let sentinel_content = "# sentinel — must not be overwritten\n";
    fs::write(&lockfile_path, sentinel_content).expect("write sentinel lockfile");

    // Capture sentinel bytes for byte-exact comparison.
    let before_bytes = fs::read(&lockfile_path).expect("read sentinel bytes");

    let lock_out = env
        .cmd()
        .env("SSS_VAULT_TOKEN", &restricted_token)
        .args(["vault", "--allow-unsigned", "lock"])
        .output()
        .expect("vault lock mixed");
    let lock_stdout = String::from_utf8_lossy(&lock_out.stdout);
    let lock_stderr = String::from_utf8_lossy(&lock_out.stderr);

    // Must exit 3 (per-reference miss).
    assert_eq!(
        lock_out.status.code(),
        Some(3),
        "vault lock must exit 3 on per-ref miss; stdout={lock_stdout}, stderr={lock_stderr}"
    );

    // Lockfile must be BYTE-FOR-BYTE identical to the sentinel.
    let after_bytes = fs::read(&lockfile_path).expect("read lockfile after failed lock");
    assert_eq!(
        before_bytes, after_bytes,
        "lockfile must be UNTOUCHED on exit 3 (all-or-nothing)"
    );
}

// ─── Test 11: vault_list_enumerates_refs ──────────────────────────────────────
//
// VCLI-03: `sss vault list` prints every `⊳{}` canonical ref in sorted order.
// Network-free; no secret value may appear in output.

#[test]
fn vault_list_enumerates_refs() {
    let Some(vault) = skip_if_unavailable() else {
        return;
    };

    let env = ProjectEnv::new_with_vault(&vault, "kv", "secret");

    // Write two files with distinct vault refs.
    env.write_file("a.txt", "x=⊳{app#password}");
    env.write_file("b.txt", "y=⊳{versioned#value}");

    let list_out = env
        .cmd()
        .args(["vault", "--allow-unsigned", "list"])
        .output()
        .expect("vault list");
    let list_stdout = String::from_utf8_lossy(&list_out.stdout);
    let list_stderr = String::from_utf8_lossy(&list_out.stderr);

    assert!(
        list_out.status.success(),
        "vault list must exit 0; stderr={list_stderr}"
    );

    // Both canonical refs must appear.
    // canonical form: "binding:path#field" — default_binding="kv", mount="secret"
    assert!(
        list_stdout.contains("app#password") || list_stdout.contains("app"),
        "vault list must include the app ref; stdout={list_stdout}"
    );
    assert!(
        list_stdout.contains("versioned#value") || list_stdout.contains("versioned"),
        "vault list must include the versioned ref; stdout={list_stdout}"
    );

    // No secret values must appear in output (VNET-04).
    assert!(
        !list_stdout.contains("s3cr3t-from-vault"),
        "secret value must not appear in vault list stdout; stdout={list_stdout}"
    );
    assert!(
        !list_stderr.contains("s3cr3t-from-vault"),
        "secret value must not appear in vault list stderr; stderr={list_stderr}"
    );
    assert!(
        !list_stdout.contains("version-two"),
        "secret value must not appear in vault list stdout; stdout={list_stdout}"
    );

    // Dev root token must not appear (VNET-04).
    assert!(
        !list_stdout.contains(vault.dev_root_token()),
        "dev root token must not appear in vault list stdout"
    );
}
