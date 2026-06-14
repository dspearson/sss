// Why: sss-agent is deliberately excluded from the structural-unsafe-ban scope per locked CONTEXT.md decision because it has libc-FFI-adjacent code paths via re-export of sss::* modules that use libc/sodium FFI; future internal refactor may inline FFI. Pedantic noise has no audit benefit on the tiny CLI dispatch surface (per REQUIREMENTS.md agent-binary carve-out).
#![allow(clippy::pedantic)]
// Why: sss-agent is a thin CLI dispatcher; .unwrap()/.expect() on Mutex locks and
// stdin reads is the appropriate behaviour (failure = exit) — refactor to ?
// would require restructuring the agent loop without semantic gain. Panic in
// this binary is treated as program-termination, not error-handling.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use anyhow::{anyhow, Result};
use clap::Parser;
use std::collections::HashSet;
use std::fs;
use std::os::unix::io::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

// WR-02: libc::umask used in bind_filesystem_socket to set 0177 before bind,
// eliminating the world-accessible socket window between bind and chmod.

/// Shutdown flag set by the ctrlc handler (REM-18 / CON-13-001).
///
/// When the handler receives SIGINT or SIGTERM it sets this flag and returns
/// (instead of calling `process::exit`).  The accept loop polls the
/// flag and breaks on `true`, allowing `main` to return normally so Rust drop
/// glue runs on all owned resources (socket fds, audit logger, etc.).
static SHUTDOWN: AtomicBool = AtomicBool::new(false);

/// Represents the address the agent is bound to.
///
/// On Linux, when no `--socket` flag is given, the agent binds an abstract
/// socket (kernel-namespaced, no inode) and exposes the `@sss-agent-{uid}`
/// address string.  On all other platforms, or when an explicit `--socket`
/// path is supplied, a filesystem socket is used and the path string is
/// the advertised address.
enum BoundSocket {
    /// Linux abstract socket — no filesystem path; kernel reclaims the name
    /// when all fds are closed.  The `String` is the `@`-prefixed name
    /// (e.g. `@sss-agent-1000`) used in `SSS_AUTH_SOCK`.
    #[cfg(target_os = "linux")]
    Abstract(String),
    /// Filesystem socket — the `PathBuf` is the path that must be removed on
    /// shutdown.
    Path(PathBuf),
}

/// Bind the agent's Unix socket.
///
/// # Linux default (no explicit `--socket`)
///
/// Constructs an abstract socket address `sss-agent-{uid}` via
/// `SocketAddr::from_abstract_name` and binds via `UnixListener::bind_addr`.
/// There is no filesystem path → no `remove_file`→`bind` race (REM-11 /
/// CON-01) and no post-bind `chmod` window.  Returns
/// `BoundSocket::Abstract("@sss-agent-{uid}")`.
///
/// # macOS / all platforms / explicit `--socket <path>`
///
/// Refuses to start if the path already exists (another agent may be running
/// or a stale socket was not cleaned up) rather than blindly removing it.
/// The caller is instructed to remove a stale socket manually.  If the path
/// is clear, binds normally and sets mode 0o600.  Returns
/// `BoundSocket::Path(path)`.
///
/// An explicit `--socket <path>` always forces the filesystem branch on every
/// platform (including Linux) so that tests and macOS CI use a pinned path.
#[cfg(target_os = "linux")]
fn bind_agent_socket(explicit_path: Option<PathBuf>) -> Result<(UnixListener, BoundSocket)> {
    if let Some(path) = explicit_path {
        // Explicit path forces filesystem mode even on Linux.
        bind_filesystem_socket(path)
    } else {
        // Linux default: abstract socket — no filesystem path.
        use std::os::linux::net::SocketAddrExt;
        use std::os::unix::net::SocketAddr;

        let uid = nix::unistd::getuid().as_raw();
        let name = format!("sss-agent-{uid}");
        let addr = SocketAddr::from_abstract_name(name.as_bytes())
            .map_err(|e| anyhow!("abstract socket addr construction failed: {e}"))?;
        let listener = UnixListener::bind_addr(&addr)
            .map_err(|e| anyhow!("bind to abstract socket @{name} failed: {e}"))?;
        Ok((listener, BoundSocket::Abstract(format!("@{name}"))))
    }
}

#[cfg(not(target_os = "linux"))]
fn bind_agent_socket(explicit_path: Option<PathBuf>) -> Result<(UnixListener, BoundSocket)> {
    let path = match explicit_path {
        Some(p) => p,
        None => {
            let home = std::env::var("HOME")
                .map_err(|_| anyhow!("HOME environment variable not set"))?;
            PathBuf::from(home).join(".sss-agent.sock")
        }
    };
    bind_filesystem_socket(path)
}

/// Bind a filesystem Unix socket, refusing if the path already exists.
///
/// This eliminates the remove/bind TOCTOU window: if another agent is running
/// or a stale socket exists, this agent refuses to start rather than blindly
/// removing the existing socket.  The caller must remove a stale socket
/// manually (`rm <path>`) before restarting the agent.
fn bind_filesystem_socket(path: PathBuf) -> Result<(UnixListener, BoundSocket)> {
    if path.exists() {
        return Err(anyhow!(
            "socket path {} already exists; another sss-agent may be running. \
             Remove it manually if stale: rm {:?}",
            path.display(),
            path
        ));
    }
    // WR-02: set umask to 0177 BEFORE bind so the kernel creates the socket at
    // mode 0600 from the start — no world-accessible window between bind and
    // chmod.  Restore the prior umask immediately after bind (before any `?`
    // propagation) so we never leave the process with a modified umask.
    // The peer-cred gate (REM-09) remains the primary access control; this
    // eliminates the narrow window entirely.
    // SAFETY: libc::umask is always safe to call — it cannot fail and has no
    // preconditions.  We capture the old umask so we can restore it immediately
    // after the bind syscall, ensuring we never leave the process with an
    // unexpectedly restrictive umask.
    #[cfg(unix)]
    let old_umask = unsafe { libc::umask(0o177) };

    let bind_result = UnixListener::bind(&path)
        .map_err(|e| anyhow!("bind to socket {:?} failed: {e}", path));

    // Restore umask unconditionally before propagating any bind error.
    // SAFETY: libc::umask is always safe to call; old_umask is valid because
    // it was returned by the preceding umask() call.
    #[cfg(unix)]
    unsafe { libc::umask(old_umask) };

    let listener = bind_result?;
    Ok((listener, BoundSocket::Path(path)))
}

// Import SSS modules
// WR-03: import get_peer_creds (single SO_PEERCRED call) instead of the old
// two-call split (verify_peer_credentials + verified_peer_pid).
use sss::agent::peer_cred::{enforce_peer_identity, get_peer_creds};
use sss::agent::policy::{PolicyDecision, PolicyManager, UserDecision};
use sss::agent::protocol::{
    AgentRequest, AgentResponse, RequestType, ResponseStatus, SUITE_WIRE_CLASSIC,
    SUITE_WIRE_HYBRID,
};
use sss::askpass::{prompt_user, AskpassConfig};
use sss::audit_log::{AuditEvent, AuditLogger, RateLimiter};
use sss::crypto::{suite_for, KeyPair, Suite};
use sss::keystore::{get_passphrase_or_prompt, Keystore};

/// SSS Agent - Key Management Daemon
#[derive(Parser)]
#[command(name = "sss-agent")]
#[command(about = "SSS agent daemon for secure key forwarding")]
struct Args {
    /// Socket path (default: ~/.sss-agent.sock)
    #[arg(long)]
    socket: Option<PathBuf>,

    /// Run in foreground (don't daemonize)
    #[arg(long)]
    foreground: bool,

    /// Key ID to load
    #[arg(long)]
    key_id: Option<String>,
}

struct AgentState {
    keypair: KeyPair,
    policy_manager: Arc<Mutex<PolicyManager>>,
    audit_logger: Arc<AuditLogger>,
    rate_limiter: Arc<RateLimiter>,
    askpass_config: AskpassConfig,
}

fn main() -> Result<()> {
    let args = Args::parse();

    // Set up audit logger
    let log_path = get_log_path()?;
    let audit_logger = Arc::new(AuditLogger::new(log_path)?);

    // Set up policy manager
    let policy_path = get_policy_path()?;
    let policy_manager = Arc::new(Mutex::new(PolicyManager::new(policy_path)?));

    // Set up rate limiter (max 10 requests per minute per host)
    let rate_limiter = Arc::new(RateLimiter::new(10));

    // Load keypair
    let keypair = load_keypair(args.key_id.as_deref())?;

    audit_logger.log(
        AuditEvent::KeyLoaded,
        &format!("Loaded key: {}", keypair.public_key().to_base64()),
    )?;

    // Create agent state
    let state = Arc::new(AgentState {
        keypair,
        policy_manager,
        audit_logger: audit_logger.clone(),
        rate_limiter,
        askpass_config: AskpassConfig::default(),
    });

    audit_logger.log(AuditEvent::AgentStarted, "Agent starting")?;

    // REM-11 / CON-01: race-free socket bind.
    //   Linux (no --socket): abstract socket via from_abstract_name/bind_addr —
    //     no filesystem path, no remove/bind race, no post-bind chmod window.
    //   All platforms / explicit --socket: filesystem socket, refuse-if-exists
    //     (never blindly remove a pre-existing socket).
    let (listener, bound) = bind_agent_socket(args.socket)?;

    // Export socket address to environment.
    //
    // Abstract sockets (Linux default): emit ONLY SSS_AUTH_SOCK.  An abstract
    // socket name (e.g. `@sss-agent-1000`) is NOT a filesystem path — tools
    // that read SSH_AUTH_SOCK as a Unix socket path would silently fail, and
    // the user's existing ssh-agent forwarding would be clobbered (WR-01).
    //
    // Filesystem sockets (macOS / explicit --socket): emit both SSH_AUTH_SOCK
    // and SSS_AUTH_SOCK with the real path, preserving ssh-agent compat.
    match &bound {
        #[cfg(target_os = "linux")]
        BoundSocket::Abstract(name) => {
            // Do NOT export SSH_AUTH_SOCK — abstract socket name is not a
            // filesystem path and would break legitimate ssh-agent usage.
            println!("SSS_AUTH_SOCK={name}; export SSS_AUTH_SOCK;");
        }
        BoundSocket::Path(p) => {
            let s = p.display();
            println!("SSH_AUTH_SOCK={s}; export SSH_AUTH_SOCK;");
            println!("SSS_AUTH_SOCK={s}; export SSS_AUTH_SOCK;");
        }
    }
    println!("Agent pid: {}", std::process::id());

    if !args.foreground {
        eprintln!("Agent running in background");
    }

    // Handle SIGTERM and SIGINT for graceful shutdown (REM-18 / CON-13-001).
    //
    // Previously this handler called process::exit, which bypasses Rust
    // drop glue — RAII destructors on the agent's owned resources (socket fds,
    // audit logger, policy state) were never run.  The new approach:
    //   1. Perform any side-effectful cleanup that cannot wait (socket file removal
    //      on the filesystem branch; abstract sockets are kernel-reclaimed on fd close).
    //   2. Set SHUTDOWN to true.
    //   3. Return from the handler — do NOT call exit().
    // The accept loop below polls SHUTDOWN and breaks, letting main() return so Rust
    // drop glue runs.  REM-09/REM-10/REM-12 invariants in handle_client are unaffected
    // (they operate per-connection, independent of the shutdown path).
    let state_clone = state.clone();
    ctrlc::set_handler(move || {
        let _ = state_clone
            .audit_logger
            .log(AuditEvent::AgentStopped, "Agent shutting down");
        match &bound {
            #[cfg(target_os = "linux")]
            BoundSocket::Abstract(_) => {
                // Abstract socket: kernel reclaims the name when all fds close.
                // Nothing to remove from the filesystem.
            }
            BoundSocket::Path(p) => {
                let _ = fs::remove_file(p);
            }
        }
        // Signal the accept loop to break (REM-18 agent leg: drop glue runs instead of exit).
        SHUTDOWN.store(true, Ordering::SeqCst);
    })?;

    // Make the listener non-blocking so the accept loop can poll SHUTDOWN.
    // The loop uses a short sleep on WouldBlock to yield the CPU between polls.
    listener.set_nonblocking(true)?;

    // WR-02: collect JoinHandles so we can join in-flight threads on shutdown,
    // ensuring their Zeroizing<...> destructors run before main() returns.
    let mut handles: Vec<std::thread::JoinHandle<()>> = Vec::new();

    // Main loop: accept connections until SHUTDOWN is set.
    loop {
        if SHUTDOWN.load(Ordering::SeqCst) {
            break;
        }
        match listener.accept() {
            Ok((stream, _)) => {
                // WR-02: set a read timeout so a stuck handler can't block shutdown
                // indefinitely — the handler will return with an I/O error after 30 s.
                if let Err(e) = stream.set_read_timeout(Some(std::time::Duration::from_secs(30))) {
                    eprintln!("Warning: could not set read timeout on accepted stream: {e}");
                }
                let state_clone = state.clone();
                let h = std::thread::spawn(move || {
                    if let Err(e) = handle_client(stream, state_clone) {
                        eprintln!("Error handling client: {e}");
                    }
                });
                handles.push(h);
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // No pending connection — yield and retry.
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            Err(e) => {
                eprintln!("Error accepting connection: {e}");
            }
        }
    }

    // WR-02: join all in-flight handler threads so their Zeroizing<...> drops run
    // before main() returns (and the process exits). The 30-second read timeout set
    // above bounds how long each join can block.
    for h in handles {
        let _ = h.join();
    }

    Ok(())
}

fn handle_client(mut stream: UnixStream, state: Arc<AgentState>) -> Result<()> {
    // INVARIANT: every `state.policy_manager.lock().unwrap()` in this function (and
    // any helper it calls) is sound because the PolicyManager mutex is never poisoned
    // in this single-binary process scope. A poisoned mutex here is a fatal bug, not
    // a recoverable state — propagating it would mean the agent silently swallows
    // unrecoverable corruption. Audit: HARDEN-01 / 08-01.
    //
    // REM-10 / CON-03: the policy lock is acquired ONCE for the
    // evaluate→prompt→re-evaluate→apply sequence and is intentionally HELD
    // across the askpass prompt.  This serialises concurrent prompts (one at a
    // time) rather than permitting a second thread to apply a conflicting
    // decision while the first thread is waiting for user input.  Low
    // connection concurrency makes prompt-window contention acceptable;
    // concurrent policy mutation is the worse alternative (40-RESEARCH.md
    // Pattern 2 trade-off).

    // REM-09 / CON-02-001: verify kernel-attested peer credentials BEFORE reading
    // any wire bytes.  Fail-closed: if peer creds cannot be read, refuse the
    // connection immediately.
    //
    // WR-03: one get_peer_creds call returns both uid and pid (pid is None on
    // macOS) via a single SO_PEERCRED syscall — avoids the old double-call.
    let fd = stream.as_raw_fd();
    let peer_creds = get_peer_creds(fd)?;
    let peer_uid = peer_creds.uid;
    let peer_pid = peer_creds.pid;

    // REM-12 / CON-18-001: per-connection nonce store.
    //
    // Tracks nonces seen on THIS connection so a captured v3 request frame
    // cannot be replayed verbatim on the same connection.
    //
    // Per Critical Finding 6 (40-RESEARCH.md §CF-6), handle_client processes
    // exactly ONE request per connection, so this set is trivially bounded at
    // 1 entry.  Its real security value is that a replayed frame is always
    // rejected even in the degenerate case where an attacker manages to re-use
    // the same connection fd — combined with the peer-cred gate (REM-09) a new
    // connection requires the full peer-cred re-check.
    //
    // Gating: the nonce check is enforced ONLY for v3 frames
    // (`request.wire_version == 3`).  v1/v2 frames carry no nonce field; the
    // decoder returns a zeroed sentinel for them.  Inserting that zeroed
    // sentinel would cause a second legacy request on the same connection to
    // be spuriously rejected.  v1/v2 frames have no per-request replay
    // protection — this is the documented legacy gap, not a silent bypass.
    let mut seen_nonces: HashSet<[u8; 16]> = HashSet::new();

    // Read request
    let request = AgentRequest::read_from(&mut stream)?;

    match request.request_type {
        RequestType::Ping => {
            // Simple ping/pong
            let response = AgentResponse::success(String::new());
            response.write_to(&mut stream)?;
        }
        RequestType::UnsealRepositoryKey => {
            // REM-12 / CON-18-001: replay rejection — check the nonce BEFORE
            // any unsealing work so a replayed frame never reaches open_repo_key.
            //
            // Only enforce for v3 frames; legacy v1/v2 frames carry no nonce
            // and must not be spuriously rejected (see seen_nonces comment above).
            if request.wire_version == 3
                && !seen_nonces.insert(request.nonce)
            {
                return Err(anyhow!("duplicate nonce — replay rejected"));
            }

            // Handle unsealing request
            let sealed_key = request
                .sealed_key
                .ok_or_else(|| anyhow!("Missing sealed key in request"))?;

            let mut context = request
                .context
                .ok_or_else(|| anyhow!("Missing context in request"))?;

            // REM-09: enforce that the kernel-verified peer uid resolves to the
            // claimed sss_username.  Reject before any policy evaluation.
            enforce_peer_identity(peer_uid, &context)?;

            // On Linux, overwrite the self-reported client_pid with the
            // kernel-attested pid so downstream logging reflects the verified pid.
            // On macOS, peer_pid is None and we leave client_pid as-is.
            if let Some(kpid) = peer_pid {
                context.client_pid = Some(kpid);
            }

            // Log the request
            state.audit_logger.log_request(&context)?;

            // Check rate limit
            if !state.rate_limiter.check_rate_limit(&context) {
                state
                    .audit_logger
                    .log(AuditEvent::Denied, "Rate limit exceeded")?;

                // Check if we should auto-lock on suspicious activity
                // INVARIANT: see handle_client docblock — mutex never poisoned.
                let mut policy = state.policy_manager.lock().unwrap();
                policy.lock();

                let response = AgentResponse::locked();
                response.write_to(&mut stream)?;
                return Ok(());
            }

            // REM-10 / CON-03: acquire the policy lock ONCE and hold it across
            // the full evaluate→prompt→re-evaluate→apply sequence.  The explicit
            // early lock release that freed the guard before the askpass prompt has
            // been removed.  A second thread that calls apply_decision while this
            // thread waits for user input will block on the mutex, preventing the
            // double-allow / cross-decision race documented in CON-03-001.
            //
            // INVARIANT: see handle_client docblock — mutex never poisoned.
            let mut policy = state.policy_manager.lock().unwrap();
            let pre_decision = policy.evaluate(&context);

            let user_decision = match pre_decision {
                PolicyDecision::Allow => UserDecision::AllowOnce,
                PolicyDecision::Deny => UserDecision::DenyOnce,
                PolicyDecision::AskUser => {
                    // Lock IS STILL HELD while waiting for the user.  Concurrent
                    // connections block here rather than racing to apply a
                    // conflicting decision.
                    let ud = match prompt_user(&context, &state.askpass_config) {
                        Ok(d) => d,
                        Err(e) => {
                            state
                                .audit_logger
                                .log(AuditEvent::Error, &format!("Askpass error: {}", e))?;
                            let response =
                                AgentResponse::error(format!("Confirmation failed: {}", e));
                            response.write_to(&mut stream)?;
                            return Ok(());
                        }
                    };
                    // Re-evaluate under the held lock after the user answers.
                    // If the policy was externally modified while the prompt was
                    // running (e.g. `sss-agent --unlock` from another terminal),
                    // honour the fresh decision rather than the stale pre-prompt
                    // result.
                    let post_decision = policy.evaluate(&context);
                    match post_decision {
                        PolicyDecision::Allow => UserDecision::AllowOnce,
                        PolicyDecision::Deny => UserDecision::DenyOnce,
                        // Policy unchanged — use the user's answer.
                        PolicyDecision::AskUser => ud,
                    }
                }
            };

            // Log the decision
            state.audit_logger.log_decision(user_decision, &context)?;

            // Apply decision under the same held lock.
            policy.apply_decision(user_decision, &context)?;
            // Lock released here as `policy` (MutexGuard) drops at end of scope.

            // Send response based on decision
            let response = match user_decision {
                UserDecision::DenyOnce => AgentResponse::denied(),
                UserDecision::DenyAll => AgentResponse::locked(),
                UserDecision::AllowOnce | UserDecision::AllowAlways => {
                    // CR-01 / 08-03: dispatch through suite_for(suite) instead
                    // of hardcoding ClassicSuite. The wire-format `suite`
                    // field is mapped here:
                    //   None or SUITE_WIRE_CLASSIC → Suite::Classic (v1
                    //     back-compat retains the legacy behaviour)
                    //   SUITE_WIRE_HYBRID         → Suite::Hybrid
                    //   any other value           → wire-format error
                    //     (already rejected at AgentRequest::read_from)
                    let suite = match request.suite {
                        None | Some(SUITE_WIRE_CLASSIC) => Suite::Classic,
                        Some(SUITE_WIRE_HYBRID) => Suite::Hybrid,
                        Some(other) => {
                            // Defence-in-depth: AgentRequest::read_from has
                            // already rejected unknown words, but we must not
                            // silently default if a future change widens that
                            // gate.
                            state.audit_logger.log(
                                AuditEvent::Error,
                                &format!("Unknown suite wire value: {}", other),
                            )?;
                            let response = AgentResponse::error(format!(
                                "Unknown suite wire value: {}",
                                other
                            ));
                            response.write_to(&mut stream)?;
                            return Ok(());
                        }
                    };
                    let crypto_suite = match suite_for(suite) {
                        Ok(s) => s,
                        Err(e) => {
                            state
                                .audit_logger
                                .log(AuditEvent::Error, &format!("suite_for error: {}", e))?;
                            let response = AgentResponse::error(format!(
                                "Failed to resolve crypto suite: {}",
                                e
                            ));
                            response.write_to(&mut stream)?;
                            return Ok(());
                        }
                    };
                    // Unseal the repository key via the resolved suite.
                    match crypto_suite.open_repo_key(&sealed_key, &state.keypair) {
                        Ok(repo_key) => {
                            state
                                .audit_logger
                                .log_response(ResponseStatus::Success, &context)?;
                            AgentResponse::success(repo_key.to_base64())
                        }
                        Err(e) => {
                            state
                                .audit_logger
                                .log(AuditEvent::Error, &format!("Unseal error: {}", e))?;
                            AgentResponse::error(format!("Failed to unseal: {}", e))
                        }
                    }
                }
            };

            response.write_to(&mut stream)?;
        }
        RequestType::ListKeys => {
            // TODO: Implement list keys
            let response = AgentResponse::error("Not implemented".to_string());
            response.write_to(&mut stream)?;
        }
    }

    Ok(())
}

fn load_keypair(key_id: Option<&str>) -> Result<KeyPair> {
    let keystore = Keystore::new()?;

    // Get passphrase from SSS_PASSPHRASE environment variable or prompt
    let passphrase = get_passphrase_or_prompt("Enter passphrase for SSS key: ")?;

    let keypair = if let Some(id) = key_id {
        keystore.load_keypair(id, Some(&passphrase), false)?
    } else {
        keystore.get_current_keypair(Some(&passphrase))?
    };

    Ok(keypair)
}

fn get_log_path() -> Result<PathBuf> {
    let config_dir = get_config_dir()?;
    Ok(config_dir.join("agent.log"))
}

fn get_policy_path() -> Result<PathBuf> {
    let config_dir = get_config_dir()?;
    Ok(config_dir.join("agent-policy.toml"))
}

fn get_config_dir() -> Result<PathBuf> {
    let home = std::env::var("HOME").map_err(|_| anyhow!("HOME environment variable not set"))?;

    #[cfg(target_os = "macos")]
    let config_dir = PathBuf::from(home)
        .join("Library")
        .join("Application Support")
        .join("sss");

    #[cfg(not(target_os = "macos"))]
    let config_dir = std::env::var("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(home).join(".config"))
        .join("sss");

    Ok(config_dir)
}
