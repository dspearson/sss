use anyhow::{anyhow, Result};
use clap::Parser;
use std::fs;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

// Import SSS modules
use sss::agent_policy::{PolicyDecision, PolicyManager, UserDecision};
use sss::agent_protocol::{AgentRequest, AgentResponse, RequestType, ResponseStatus};
use sss::askpass::{prompt_user, AskpassConfig};
use sss::audit_log::{AuditEvent, AuditLogger, RateLimiter};
use sss::crypto::{open_repository_key, KeyPair};
use sss::keystore::Keystore;

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

    // Get socket path
    let socket_path = args.socket.unwrap_or_else(|| {
        let home = std::env::var("HOME").expect("HOME not set");
        PathBuf::from(home).join(".sss-agent.sock")
    });

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
        &format!("Loaded key: {}", keypair.public_key.to_base64()),
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

    // Remove existing socket if present
    if socket_path.exists() {
        fs::remove_file(&socket_path)?;
    }

    // Create Unix socket
    let listener = UnixListener::bind(&socket_path)?;

    // Set socket permissions
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata = fs::metadata(&socket_path)?;
        let mut perms = metadata.permissions();
        perms.set_mode(0o600); // Owner read/write only
        fs::set_permissions(&socket_path, perms)?;
    }

    // Export socket path to environment
    println!(
        "SSH_AUTH_SOCK={}; export SSH_AUTH_SOCK;",
        socket_path.display()
    );
    println!(
        "SSS_AUTH_SOCK={}; export SSS_AUTH_SOCK;",
        socket_path.display()
    );
    println!("Agent pid: {}", std::process::id());

    if !args.foreground {
        eprintln!("Agent running in background");
    }

    // Handle SIGTERM and SIGINT for graceful shutdown
    let state_clone = state.clone();
    let socket_path_clone = socket_path.clone();
    ctrlc::set_handler(move || {
        let _ = state_clone
            .audit_logger
            .log(AuditEvent::AgentStopped, "Agent shutting down");
        let _ = fs::remove_file(&socket_path_clone);
        std::process::exit(0);
    })?;

    // Main loop: accept connections
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let state_clone = state.clone();
                std::thread::spawn(move || {
                    if let Err(e) = handle_client(stream, state_clone) {
                        eprintln!("Error handling client: {}", e);
                    }
                });
            }
            Err(e) => {
                eprintln!("Error accepting connection: {}", e);
            }
        }
    }

    Ok(())
}

fn handle_client(mut stream: UnixStream, state: Arc<AgentState>) -> Result<()> {
    // Read request
    let request = AgentRequest::read_from(&mut stream)?;

    match request.request_type {
        RequestType::Ping => {
            // Simple ping/pong
            let response = AgentResponse::success(String::new());
            response.write_to(&mut stream)?;
        }
        RequestType::UnsealRepositoryKey => {
            // Handle unsealing request
            let sealed_key = request
                .sealed_key
                .ok_or_else(|| anyhow!("Missing sealed key in request"))?;

            let context = request
                .context
                .ok_or_else(|| anyhow!("Missing context in request"))?;

            // Log the request
            state.audit_logger.log_request(&context)?;

            // Check rate limit
            if !state.rate_limiter.check_rate_limit(&context) {
                state
                    .audit_logger
                    .log(AuditEvent::Denied, "Rate limit exceeded")?;

                // Check if we should auto-lock on suspicious activity
                let mut policy = state.policy_manager.lock().unwrap();
                policy.lock();

                let response = AgentResponse::locked();
                response.write_to(&mut stream)?;
                return Ok(());
            }

            // Evaluate policy
            let policy = state.policy_manager.lock().unwrap();
            let decision = policy.evaluate(&context);
            drop(policy);

            let user_decision = match decision {
                PolicyDecision::Allow => UserDecision::AllowOnce,
                PolicyDecision::Deny => UserDecision::DenyOnce,
                PolicyDecision::AskUser => {
                    // Prompt user for decision
                    match prompt_user(&context, &state.askpass_config) {
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
                    }
                }
            };

            // Log the decision
            state.audit_logger.log_decision(user_decision, &context)?;

            // Apply policy decision
            let mut policy = state.policy_manager.lock().unwrap();
            policy.apply_decision(user_decision, &context)?;
            drop(policy);

            // Send response based on decision
            let response = match user_decision {
                UserDecision::DenyOnce => AgentResponse::denied(),
                UserDecision::DenyAll => AgentResponse::locked(),
                UserDecision::AllowOnce | UserDecision::AllowAlways => {
                    // Unseal the repository key
                    match open_repository_key(&sealed_key, &state.keypair) {
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

    // Prompt for passphrase
    let passphrase = rpassword::prompt_password("Enter passphrase for SSS key: ")?;

    let keypair = if let Some(id) = key_id {
        keystore.load_keypair(id, Some(&passphrase))?
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
