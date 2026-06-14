// Why: integration tests use .unwrap()/.expect()/panic! freely; test code is exempt
// from the panic-surface lint policy per REQUIREMENTS.md carve-out.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
// Why: pedantic enforcement has no audit benefit on test-support code.
#![allow(clippy::pedantic)]
// Unix-only: peer-credential APIs are not available on Windows.
#![cfg(unix)]

//! Socketpair-based unit tests for REM-09 peer-credential verification.
//!
//! These tests exercise `get_peer_creds` and `enforce_peer_identity` directly
//! over a real `UnixStream::pair()` (kernel socketpair), without spawning an
//! agent process.
//!
//! WR-03: the old split into `verify_peer_credentials` + `verified_peer_pid`
//! issued `getsockopt(SO_PEERCRED)` twice per connection.  These tests use
//! `get_peer_creds` which combines both into one syscall.
//!
//! Test matrix:
//!   (1) verified uid matches the running test process uid.
//!   (2) matching username is accepted by enforce_peer_identity.
//!   (3) forged sss_username is rejected with a descriptive error.
//!   (4) unknown uid (no passwd entry) fails closed.

use nix::unistd::{Uid, User};
use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixStream;

use sss::agent::peer_cred::{enforce_peer_identity, get_peer_creds};
use sss::agent::protocol::RequestContext;

/// A `UnixStream::pair()` socketpair has both ends in the same process with
/// the same UID.  `get_peer_creds` on one end must return the current
/// process's effective UID (WR-03: one syscall for uid + pid).
#[test]
fn verified_uid_matches_running_uid() {
    let (a, _b) = UnixStream::pair().expect("socketpair");
    let creds = get_peer_creds(a.as_raw_fd()).expect("get_peer_creds");
    let expected = nix::unistd::getuid();
    assert_eq!(
        creds.uid, expected,
        "verified uid {} must equal running uid {expected}",
        creds.uid
    );
}

/// When the RequestContext claims the correct username (the one the running
/// uid resolves to), enforce_peer_identity must return Ok.
#[test]
fn matching_username_accepted() {
    let uid = nix::unistd::getuid();
    let user = User::from_uid(uid)
        .expect("User::from_uid")
        .expect("current user must have a passwd entry");
    let ctx = RequestContext::new(user.name.clone());
    enforce_peer_identity(uid, &ctx).expect("should accept matching username");
}

/// When the RequestContext claims a username that does not match the resolved
/// uid, enforce_peer_identity must return an error mentioning the claimed
/// name or "refused".
#[test]
fn forged_username_rejected() {
    let uid = nix::unistd::getuid();
    let ctx = RequestContext::new("definitely-not-me".to_string());
    let err = enforce_peer_identity(uid, &ctx)
        .expect_err("should reject forged username");
    let msg = err.to_string();
    assert!(
        msg.contains("definitely-not-me") || msg.contains("refused"),
        "error message should mention the claimed name or 'refused': {msg}"
    );
}

/// When the RequestContext claims a REAL, resolvable account name ("root")
/// that does NOT match the name the running uid resolves to,
/// enforce_peer_identity must return Err — the rejection holds for real
/// passwd accounts, not only nonexistent names (item-8 belt-and-suspenders;
/// the sibling test `forged_username_rejected` uses a nonexistent name).
///
/// Edge case: if the test itself runs as root, the claimed name matches, so
/// the test instead asserts the opposite (Ok) to stay correct in a root CI
/// container rather than forcing a skip.
#[test]
fn forged_real_account_name_rejected() {
    let uid = nix::unistd::getuid();
    let running_name = User::from_uid(uid)
        .expect("User::from_uid")
        .expect("current user must have a passwd entry")
        .name;

    if running_name == "root" {
        // Running as root: "root" is the correct name → enforce_peer_identity
        // must accept it (not reject it). Assert Ok to remain correct.
        let ctx = RequestContext::new("root".to_string());
        enforce_peer_identity(uid, &ctx)
            .expect("root uid with ctx claiming 'root' must be accepted");
        return;
    }

    // Running as a non-root user: "root" is a real passwd account whose
    // resolved name does NOT match the running uid → must be rejected.
    let ctx = RequestContext::new("root".to_string());
    let err = enforce_peer_identity(uid, &ctx)
        .expect_err("claiming a real account 'root' that does not match the running uid must be rejected");
    let msg = err.to_string();
    assert!(
        msg.contains("root") || msg.contains("refused"),
        "error message should mention the claimed name ('root') or 'refused': {msg}"
    );
}

/// Calling enforce_peer_identity with a UID almost certainly absent from
/// passwd (4_000_000_000) must return Err — fail-closed.
/// uid_t is u32; 4,000,000,000 is below 2^32 and is not assigned on any
/// normal Linux or macOS system.
#[test]
fn fail_closed_on_unknown_uid() {
    let phantom_uid = Uid::from_raw(4_000_000_000);
    // On both Linux and macOS, User::from_uid returns Ok(None) for an
    // unassigned uid (or an error), both of which enforce_peer_identity
    // maps to Err.
    let err = enforce_peer_identity(phantom_uid, &RequestContext::new("ghost".to_string()))
        .expect_err("unknown uid must fail closed");
    let msg = err.to_string();
    assert!(
        msg.contains("passwd") || msg.contains("refused") || msg.contains("lookup"),
        "error message should indicate a passwd/lookup failure: {msg}"
    );
}
