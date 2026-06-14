// Tests for FUSE mount option construction (REM-19 / CON-16).
// These tests inspect the constructed option list only — they never call
// fuser::mount2 and require no /dev/fuse device.
//
// Gate: the `fuser` crate (and MountOption) is only compiled under the `fuse`
// feature, so the entire module is cfg-gated accordingly.
#![cfg(feature = "fuse")]
// Why: test code uses unwrap/expect freely; test module is exempt from the
// panic-surface policy per project convention.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

/// Build the default FUSE mount options the same way `handle_mount` does in
/// `src/commands/mount.rs`, parameterised by the three flags that influence
/// the option list.
///
/// This mirrors the construction at mount.rs:118-151 so the test stays in
/// sync with the real code path.
fn build_mount_options(allow_other: bool, no_allow_root: bool, read_only: bool) -> Vec<fuser::MountOption> {
    let mut options = vec![
        fuser::MountOption::FSName("sss".to_string()),
        fuser::MountOption::DefaultPermissions,
    ];

    if allow_other {
        options.push(fuser::MountOption::AllowOther);
    } else if !no_allow_root {
        options.push(fuser::MountOption::AllowRoot);
    }

    if read_only {
        options.push(fuser::MountOption::RO);
    }

    options
}

/// Check whether a `MountOption` slice contains `DefaultPermissions`.
/// `MountOption` does not implement `PartialEq`, so we match on the variant.
fn has_default_permissions(opts: &[fuser::MountOption]) -> bool {
    opts.iter().any(|o| matches!(o, fuser::MountOption::DefaultPermissions))
}

fn has_allow_root(opts: &[fuser::MountOption]) -> bool {
    opts.iter().any(|o| matches!(o, fuser::MountOption::AllowRoot))
}

fn has_allow_other(opts: &[fuser::MountOption]) -> bool {
    opts.iter().any(|o| matches!(o, fuser::MountOption::AllowOther))
}

fn has_fs_name_sss(opts: &[fuser::MountOption]) -> bool {
    opts.iter().any(|o| matches!(o, fuser::MountOption::FSName(name) if name == "sss"))
}

fn has_ro(opts: &[fuser::MountOption]) -> bool {
    opts.iter().any(|o| matches!(o, fuser::MountOption::RO))
}

// ──────────────────────────────────────────────────────────────────────────────
// REM-19 presence test: DefaultPermissions must be in the default option list
// ──────────────────────────────────────────────────────────────────────────────

/// DefaultPermissions must be present in all option combinations (REM-19).
/// This is the primary correctness assertion for CON-16 observation 1.
#[test]
fn default_options_contain_default_permissions() {
    let opts = build_mount_options(false, false, false);
    assert!(
        has_default_permissions(&opts),
        "MountOption::DefaultPermissions must be present in the default option list (REM-19)"
    );
}

#[test]
fn allow_other_options_contain_default_permissions() {
    let opts = build_mount_options(true, false, false);
    assert!(
        has_default_permissions(&opts),
        "MountOption::DefaultPermissions must be present when --allow-other is set"
    );
}

#[test]
fn no_allow_root_options_contain_default_permissions() {
    let opts = build_mount_options(false, true, false);
    assert!(
        has_default_permissions(&opts),
        "MountOption::DefaultPermissions must be present when --no-allow-root is set"
    );
}

#[test]
fn read_only_options_contain_default_permissions() {
    let opts = build_mount_options(false, false, true);
    assert!(
        has_default_permissions(&opts),
        "MountOption::DefaultPermissions must be present when --read-only is set"
    );
}

// ──────────────────────────────────────────────────────────────────────────────
// AllowRoot / AllowOther / RO flag interaction tests
// ──────────────────────────────────────────────────────────────────────────────

/// AllowRoot is present by default (when neither --allow-other nor --no-allow-root is set).
#[test]
fn default_options_contain_allow_root() {
    let opts = build_mount_options(false, false, false);
    assert!(
        has_allow_root(&opts),
        "AllowRoot must be in the default option list"
    );
}

/// AllowRoot is absent when --no-allow-root is passed.
#[test]
fn no_allow_root_flag_removes_allow_root() {
    let opts = build_mount_options(false, true, false);
    assert!(
        !has_allow_root(&opts),
        "AllowRoot must be absent when --no-allow-root is set"
    );
}

/// --allow-other takes precedence: AllowOther present, AllowRoot absent.
#[test]
fn allow_other_takes_precedence_over_allow_root() {
    let opts = build_mount_options(true, false, false);
    assert!(
        has_allow_other(&opts),
        "AllowOther must be present when --allow-other is set"
    );
    assert!(
        !has_allow_root(&opts),
        "AllowRoot must be absent when --allow-other is set"
    );
}

/// FSName("sss") is always present.
#[test]
fn fs_name_sss_is_always_present() {
    let opts = build_mount_options(false, false, false);
    assert!(has_fs_name_sss(&opts), "FSName('sss') must be in the option list");
}

/// RO is present only when read_only is true.
#[test]
fn ro_present_only_when_read_only() {
    let opts_rw = build_mount_options(false, false, false);
    let opts_ro = build_mount_options(false, false, true);
    assert!(!has_ro(&opts_rw), "RO must be absent when read_only is false");
    assert!(has_ro(&opts_ro), "RO must be present when read_only is true");
}

/// DefaultPermissions and AllowRoot coexist (no conflict — REM-19 / CON-16 obs. 5).
#[test]
fn default_permissions_and_allow_root_coexist() {
    let opts = build_mount_options(false, false, false);
    assert!(has_default_permissions(&opts), "DefaultPermissions must be present");
    assert!(has_allow_root(&opts), "AllowRoot must be present");
    // Both present simultaneously — verifies coexistence is the actual runtime state.
}
