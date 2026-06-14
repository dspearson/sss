// Peer-credential verification helpers (REM-09 / CON-02-001).
//
// These functions provide the OS-kernel-attested identity anchor for the
// sss-agent accept path.  They MUST be called on the accepted socket fd
// BEFORE any wire bytes are read from the connection.
//
// Platform support:
//   - Linux/Android: `getsockopt(SO_PEERCRED)` → uid + pid + gid (one syscall).
//   - macOS/iOS:     `getpeereid(fd)`           → uid + gid (no pid).
//   - Other Unix:    fail-closed — returns Err immediately (connection refused).
//
// WR-03: the old split into `verify_peer_credentials` + `verified_peer_pid`
// issued `getsockopt(SO_PEERCRED)` TWICE per connection.  The `ucred` struct
// returned by a single call contains uid, gid, and pid simultaneously.  Both
// callers read the same immutable data.  The fix is to combine them into a
// single `get_peer_creds` call that returns the full kernel-attested identity
// (uid + optional pid), and update the two `handle_client` call sites to use
// it once (WR-03 / cleanup — no behaviour change).
//
// No unsafe blocks are required: every nix function used here is `pub fn`
// (not `pub unsafe fn`).  The `clippy::undocumented_unsafe_blocks = "deny"`
// lint is not triggered.
#![allow(clippy::pedantic)] // consistent with other agent/ modules

use anyhow::{anyhow, Result};
use nix::unistd::{Uid, User};
use std::os::unix::io::RawFd;

use crate::agent::protocol::RequestContext;

/// Kernel-attested peer identity returned by a single `SO_PEERCRED` / `getpeereid`
/// call (WR-03).
///
/// On Linux/Android both `uid` and `pid` are populated from one `getsockopt`
/// call.  On macOS/iOS `pid` is `None` because `getpeereid` does not return a
/// pid.  The `uid` is always present — failure to read it causes an immediate
/// `Err` (fail-closed).
pub struct PeerCreds {
    /// Kernel-attested UID of the connected peer.
    pub uid: Uid,
    /// Kernel-attested PID of the connected peer (Linux/Android only; `None` on
    /// macOS/iOS).
    pub pid: Option<u32>,
}

/// Read the kernel-attested peer identity (uid + optional pid) in a single
/// syscall (WR-03).
///
/// # Errors
///
/// Returns `Err` (fail-closed) if:
/// - The `getsockopt`/`getpeereid` syscall fails.
/// - The current platform is not one of Linux, Android, macOS, or iOS
///   (unsupported — refuse the connection rather than silently allowing).
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn get_peer_creds(fd: RawFd) -> Result<PeerCreds> {
    use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
    let creds = getsockopt(fd, PeerCredentials)
        .map_err(|e| anyhow!("SO_PEERCRED failed — connection refused: {e}"))?;
    // pid_t is i32; cast to u32 matching client_pid field type.
    // A negative pid from the kernel is pathological; treat as absent.
    let pid = if creds.pid() > 0 {
        Some(creds.pid() as u32)
    } else {
        None
    };
    Ok(PeerCreds {
        uid: Uid::from_raw(creds.uid()),
        pid,
    })
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
pub fn get_peer_creds(fd: RawFd) -> Result<PeerCreds> {
    use nix::unistd::getpeereid;
    let (uid, _gid) = getpeereid(fd)
        .map_err(|e| anyhow!("getpeereid failed — connection refused: {e}"))?;
    Ok(PeerCreds { uid, pid: None })
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios"
)))]
pub fn get_peer_creds(_fd: RawFd) -> Result<PeerCreds> {
    Err(anyhow!(
        "peer credential verification unsupported on this platform — connection refused"
    ))
}

/// Verify that the kernel-attested `peer_uid` resolves to a username that
/// matches the `sss_username` claimed in the `RequestContext`.
///
/// # Errors
///
/// Returns `Err` (connection refused) if:
/// - `User::from_uid` fails (system error during passwd lookup).
/// - The uid has no passwd entry.
/// - The resolved username does not match `context.sss_username`.
pub fn enforce_peer_identity(peer_uid: Uid, context: &RequestContext) -> Result<()> {
    let user = User::from_uid(peer_uid)
        .map_err(|e| anyhow!("peer uid lookup failed: {e}"))?
        .ok_or_else(|| {
            anyhow!(
                "peer uid {} has no passwd entry — connection refused",
                peer_uid
            )
        })?;
    if user.name != context.sss_username {
        return Err(anyhow!(
            "peer uid {} resolves to '{}', claimed sss_username '{}' — connection refused",
            peer_uid,
            user.name,
            context.sss_username
        ));
    }
    Ok(())
}
