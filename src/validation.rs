#![allow(clippy::missing_errors_doc, clippy::missing_panics_doc, clippy::items_after_statements)]
use crate::error::Result;
use crate::validation_error;
use std::path::{Path, PathBuf};

/// Security constants for input validation
pub const MAX_USERNAME_LENGTH: usize = 255;
pub const MAX_KEY_ID_LENGTH: usize = 64;

/// Validate and canonicalize a file path with minimal restrictions
///
/// This function accepts absolute paths, relative paths, and resolves symlinks.
/// No security restrictions are enforced - it's up to the client to use safely.
///
/// Processing:
/// - Null bytes rejected (filesystem limitation)
/// - Symlinks resolved for consistent behavior
pub fn validate_file_path(file_path: &str) -> Result<PathBuf> {
    // Check for null bytes (filesystem limitation)
    if file_path.contains('\0') {
        return Err(validation_error!("Path contains null bytes"));
    }

    let path = Path::new(file_path);

    // Resolve the path
    let full_path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        let current_dir = std::env::current_dir()
            .map_err(|e| validation_error!("Failed to get current directory: {}", e))?;
        current_dir.join(path)
    };

    // Canonicalize to resolve symlinks for consistent behavior
    let canonical_path = full_path.canonicalize().unwrap_or(full_path);

    Ok(canonical_path)
}

/// Strip characters that could inject ANSI/terminal control sequences, bidi-override
/// characters, or NUL bytes from untrusted text before it is included in an error
/// message or terminal output (REM-34, REM-35).
///
/// Preserves `\t` (U+0009), `\n` (U+000A), `\r` (U+000D) as safe whitespace.
///
/// Strips:
/// - C0 control characters: U+0000–U+001F (except `\t`, `\n`, `\r` above).
///   This range includes NUL (U+0000) and ESC (U+001B); removing ESC neutralises
///   all ANSI/VT100 escape sequences without a dedicated state machine.
/// - DEL: U+007F
/// - C1 control characters: U+0080–U+009F
/// - Bidi override characters (Unicode category Cf, NOT Cc — `char::is_control()`
///   does NOT catch these): U+200F, U+202A–U+202E, U+2066–U+2069
/// - Line/paragraph separators (Zl/Zp): U+2028, U+2029 — force a terminal line
///   break, enabling fake-log-line injection (MN-01).
/// - U+061C ARABIC LETTER MARK — bidi control (Cf), same Trojan-Source family as
///   U+200F (MN-01).
#[must_use]
pub fn sanitize_for_display(s: &str) -> String {
    s.chars()
        .filter(|&c| {
            let cp = c as u32;
            // Preserve common safe whitespace
            if c == '\t' || c == '\n' || c == '\r' {
                return true;
            }
            // Strip C0 (includes NUL U+0000 and ESC U+001B that initiates ANSI sequences)
            if cp <= 0x1F {
                return false;
            }
            // Strip DEL
            if cp == 0x7F {
                return false;
            }
            // Strip C1 control characters
            if (0x80..=0x9F).contains(&cp) {
                return false;
            }
            // Strip bidi overrides — Cf category, NOT caught by char::is_control().
            // U+200F RIGHT-TO-LEFT MARK
            if cp == 0x200F {
                return false;
            }
            // U+202A–U+202E: LRE, RLE, PDF, LRO, RLO
            if (0x202A..=0x202E).contains(&cp) {
                return false;
            }
            // U+2066–U+2069: LRI, RLI, FSI, PDI
            if (0x2066..=0x2069).contains(&cp) {
                return false;
            }
            // MN-01: U+2028 LINE SEPARATOR / U+2029 PARAGRAPH SEPARATOR (Zl/Zp) —
            // force a line break in many terminals/editors, enabling fake-log-line
            // injection. Not Cc/Cf, so is_control() and the bidi ranges miss them.
            if cp == 0x2028 || cp == 0x2029 {
                return false;
            }
            // MN-01: U+061C ARABIC LETTER MARK — a bidi control (Cf) in the
            // Unicode Bidi_Control set, same Trojan-Source family as U+200F.
            if cp == 0x061C {
                return false;
            }
            true
        })
        .collect()
}

/// Validate a `secrets_filename` or `secrets_suffix` value from `.sss.toml`.
///
/// Rejects values that could cause `Path::join` to escape the project root:
/// - NUL bytes (filesystem / OS restriction)
/// - Absolute paths (leading `/`, `//`, Windows `C:\` / `C:/`, UNC `\\`)
/// - Any `..` path component (traversal)
///
/// This is intentionally stricter than `validate_file_path`, which explicitly
/// allows absolute paths and `..` per its own documented contract.
///
/// The error message names `field_name` but never echoes `value` — this avoids
/// leaking path fragments that may be sensitive (T-39-04).
///
/// # Errors
/// Returns a `SssError::Validation` naming the rejected field and the reason.
pub fn validate_secrets_path(value: &str, field_name: &str) -> Result<()> {
    // (0) Empty string — `Path::join(dir, "")` yields the directory itself, producing a
    //     confusing `IsADirectory` I/O error at use-time instead of a clean validation error.
    if value.is_empty() {
        return Err(validation_error!(
            "secrets config field `{}` must not be empty",
            field_name
        ));
    }

    // (1) NUL bytes — rejected by every filesystem; also an injection vector.
    if value.contains('\0') {
        return Err(validation_error!(
            "secrets config field `{}` contains a NUL byte, which is not allowed",
            field_name
        ));
    }

    // (2) Unix absolute path: leading `/` or `//`
    if value.starts_with('/') {
        return Err(validation_error!(
            "secrets config field `{}` must be a relative filename, not an absolute path",
            field_name
        ));
    }

    // (3) Windows absolute and UNC forms (cross-platform safety — the CLI has
    //     winfsp/winapi features).
    //     - Windows drive-absolute and drive-relative: any `X:...` form (byte[1] == b':').
    //       This covers `C:\foo`, `C:/foo`, and the drive-relative `C:foo` (no slash after
    //       colon) which Path::join resolves outside the project on Windows.
    //     - UNC: `\\server\share`
    //     Note: `//server/share` is already caught by the Unix-absolute branch above.
    if value.starts_with("\\\\") {
        return Err(validation_error!(
            "secrets config field `{}` must be a relative filename, not an absolute path",
            field_name
        ));
    }
    if value.len() >= 2 {
        let bytes = value.as_bytes();
        if bytes[1] == b':' {
            return Err(validation_error!(
                "secrets config field `{}` must be a relative filename, not an absolute path",
                field_name
            ));
        }
    }

    // (4) `..` traversal: iterate std::path components using the typed-component
    //     check so that `foo/../bar`, `../foo`, and `..\foo` all trigger.
    //     A naive `contains("..")` would miss normalised forms and over-match
    //     legitimate filenames like `a..b` (see research "Don't Hand-Roll" table).
    use std::path::{Component, Path};
    for component in Path::new(value).components() {
        if component == Component::ParentDir {
            return Err(validation_error!(
                "secrets config field `{}` must not contain `..` traversal components",
                field_name
            ));
        }
    }

    Ok(())
}

/// Validate a Vault address for use in `[vault].address`.
///
/// Requirements:
/// - Must not be empty (a missing address is represented as `None`, not `""`).
/// - Scheme must be exactly `https` — plain `http` is rejected even for local dev
///   (a dev-http opt-in can be added later; VCFG-SC-01).
/// - The host component (everything after `https://`) must be non-empty; bare
///   `https://` with no host is rejected.
///
/// The error message names the `address` field but **never echoes the value** —
/// this avoids logging potentially sensitive hostnames (T-46-04 / T-39-04 mirror).
///
/// No external URL-parsing library is required; validation is intentionally minimal
/// (scheme prefix + non-empty host) because the Vault client will perform full URL
/// parsing at connection time.
///
/// # Errors
/// Returns `SssError::Validation` with a field-name prefix and a reason.
pub fn validate_vault_address(value: &str) -> Result<()> {
    // (0) Empty string is never a valid address; `None` is used for "not set".
    if value.is_empty() {
        return Err(validation_error!(
            "vault config field `address` must not be empty"
        ));
    }

    // (1) Scheme must be exactly `https` (case-sensitive per RFC 3986 § 3.1 normalisation;
    //     the Vault server should always present a normalised URI).
    //     We deliberately reject `http`, `HTTPS`, and anything else.
    if !value.starts_with("https://") {
        return Err(validation_error!(
            "vault config field `address` must use the https scheme; plain http and custom schemes are not permitted"
        ));
    }

    // (2) After stripping `https://` the host must be non-empty.
    //     A bare `https://` (17 bytes) with nothing following is invalid.
    let after_scheme = &value["https://".len()..];
    if after_scheme.is_empty() {
        return Err(validation_error!(
            "vault config field `address` must include a host after `https://`"
        ));
    }

    // (3) Reject link-local and cloud metadata SSRF ranges (T-47-03 / PITFALLS
    //     Pitfall 4).  Link-local 169.254.0.0/16 is blocked because it includes
    //     the AWS/GCP/Azure instance metadata endpoint (169.254.169.254) and other
    //     link-local addresses that must never receive a Vault token.  RFC1918
    //     private ranges (10.x, 172.16.x, 192.168.x) are intentionally NOT blocked
    //     here — many Vault deployments run on RFC1918 addresses.
    //
    // Why: A repointed `[vault].address` pointing at 169.254.169.254 would cause
    // the Vault token to be transmitted to the cloud instance-metadata service,
    // potentially leaking credentials.  The scheme check above (https-only) and
    // the signed-envelope check (VCFG-06) are complementary layers; this check
    // guards the raw transport before any DNS/TCP occurs.
    let host_part = after_scheme
        .split(['/', ':', '?', '#'])
        .next()
        .unwrap_or(after_scheme);
    if host_part.starts_with("169.254.") {
        return Err(validation_error!(
            "vault config field `address` must not use a link-local (169.254.x.x) address; \
             such addresses include the cloud instance-metadata endpoint and must not receive vault credentials"
        ));
    }

    Ok(())
}

/// Validate a username for security and consistency
pub fn validate_username(username: &str) -> Result<()> {
    if username.is_empty() {
        return Err(validation_error!("Username cannot be empty"));
    }

    if username.len() > MAX_USERNAME_LENGTH {
        return Err(validation_error!(
            "Username too long: {} characters (max: {})",
            username.len(),
            MAX_USERNAME_LENGTH
        ));
    }

    // Check for invalid characters
    if !username
        .chars()
        .all(|c| c.is_alphanumeric() || c == '_' || c == '-' || c == '.')
    {
        return Err(validation_error!(
            "Username contains invalid characters. Only alphanumeric, underscore, hyphen, and dot are allowed"
        ));
    }

    // Prevent leading/trailing dots or hyphens
    const FORBIDDEN_BOUNDARY_CHARS: &[char] = &['.', '-'];
    if FORBIDDEN_BOUNDARY_CHARS
        .iter()
        .any(|&c| username.starts_with(c) || username.ends_with(c))
    {
        return Err(validation_error!(
            "Username cannot start or end with dots or hyphens"
        ));
    }

    // Prevent reserved names
    const RESERVED_NAMES: &[&str] = &[
        "root",
        "admin",
        "administrator",
        "system",
        "daemon",
        "nobody",
        "null",
        "void",
        "test",
        "guest",
        "anonymous",
    ];

    if RESERVED_NAMES.contains(&username.to_lowercase().as_str()) {
        return Err(validation_error!("Username '{}' is reserved", username));
    }

    Ok(())
}

/// Validate a key ID for consistency
pub fn validate_key_id(key_id: &str) -> Result<()> {
    if key_id.is_empty() {
        return Err(validation_error!("Key ID cannot be empty"));
    }

    if key_id.len() > MAX_KEY_ID_LENGTH {
        return Err(validation_error!(
            "Key ID too long: {} characters (max: {})",
            key_id.len(),
            MAX_KEY_ID_LENGTH
        ));
    }

    // Key IDs should be hexadecimal
    if !key_id.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(validation_error!(
            "Key ID contains invalid characters. Only hexadecimal characters are allowed"
        ));
    }

    Ok(())
}

/// Validate Base64 input for security
pub fn validate_base64(input: &str, max_length: usize) -> Result<()> {
    if input.is_empty() {
        return Err(validation_error!("Base64 input cannot be empty"));
    }

    if input.len() > max_length {
        return Err(validation_error!(
            "Base64 input too long: {} characters (max: {})",
            input.len(),
            max_length
        ));
    }

    // Check for valid Base64 characters
    if !input
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
    {
        return Err(validation_error!("Invalid characters in Base64 input"));
    }

    // Check padding
    let padding_count = input.chars().rev().take_while(|&c| c == '=').count();
    if padding_count > 2 {
        return Err(validation_error!("Invalid Base64 padding"));
    }

    // Check that padding only appears at the end
    if let Some(first_padding) = input.find('=') {
        let expected_padding_start = input.len() - padding_count;
        if first_padding != expected_padding_start {
            return Err(validation_error!("Invalid Base64 padding position"));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use serial_test::serial;

    #[test]
    fn test_validate_username() {
        // Valid usernames
        assert!(validate_username("alice").is_ok());
        assert!(validate_username("bob123").is_ok());
        assert!(validate_username("user_name").is_ok());
        assert!(validate_username("user-name").is_ok());
        assert!(validate_username("user.name").is_ok());

        // Invalid usernames
        assert!(validate_username("").is_err());
        assert!(validate_username("user@domain").is_err());
        assert!(validate_username(".invalid").is_err());
        assert!(validate_username("invalid.").is_err());
        assert!(validate_username("-invalid").is_err());
        assert!(validate_username("invalid-").is_err());
        assert!(validate_username("root").is_err());
        assert!(validate_username("admin").is_err());
    }

    #[test]
    fn test_validate_key_id() {
        // Valid key IDs
        assert!(validate_key_id("abc123").is_ok());
        assert!(validate_key_id("deadbeef").is_ok());
        assert!(validate_key_id("123ABC").is_ok());

        // Invalid key IDs
        assert!(validate_key_id("").is_err());
        assert!(validate_key_id("invalid-key").is_err());
        assert!(validate_key_id("key@123").is_err());
    }

    #[test]
    fn test_validate_base64() {
        // Valid Base64
        assert!(validate_base64("SGVsbG8=", 100).is_ok());
        assert!(validate_base64("SGVsbG93b3JsZA==", 100).is_ok());

        // Invalid Base64
        assert!(validate_base64("", 100).is_err());
        assert!(validate_base64("Invalid@Base64", 100).is_err());
        assert!(validate_base64("SGVsbG8===", 100).is_err()); // Too much padding
        assert!(validate_base64("SGVsbG8=invalid", 100).is_err()); // Invalid characters after padding
    }

    // -------------------------------------------------------------------------
    // validate_secrets_path — unit tests (REM-06)
    // -------------------------------------------------------------------------

    #[test]
    fn test_validate_secrets_path_rejects_unix_absolute() {
        assert!(
            validate_secrets_path("/etc/shadow", "secrets_filename").is_err(),
            "Unix absolute path must be rejected"
        );
    }

    #[test]
    fn test_validate_secrets_path_rejects_double_slash_unc() {
        // `//server/share` — caught by Unix-absolute branch (starts_with('/'))
        assert!(
            validate_secrets_path("//server/share", "secrets_filename").is_err(),
            "UNC // path must be rejected"
        );
    }

    #[test]
    fn test_validate_secrets_path_rejects_windows_unc_backslash() {
        assert!(
            validate_secrets_path("\\\\server\\share", "secrets_filename").is_err(),
            "Windows UNC \\\\ path must be rejected"
        );
    }

    #[test]
    fn test_validate_secrets_path_rejects_windows_drive_backslash() {
        assert!(
            validate_secrets_path("C:\\secrets", "secrets_filename").is_err(),
            "Windows drive-absolute C:\\ path must be rejected"
        );
    }

    #[test]
    fn test_validate_secrets_path_rejects_windows_drive_forward_slash() {
        assert!(
            validate_secrets_path("C:/secrets", "secrets_filename").is_err(),
            "Windows drive-absolute C:/ path must be rejected"
        );
    }

    #[test]
    fn test_validate_secrets_path_rejects_leading_dotdot() {
        assert!(
            validate_secrets_path("../../etc/passwd", "secrets_suffix").is_err(),
            "Leading .. traversal must be rejected"
        );
    }

    #[test]
    fn test_validate_secrets_path_rejects_interior_dotdot() {
        assert!(
            validate_secrets_path("foo/../bar", "secrets_filename").is_err(),
            "Interior .. component must be rejected"
        );
    }

    #[test]
    fn test_validate_secrets_path_rejects_nul_byte() {
        assert!(
            validate_secrets_path("with\0nul", "secrets_filename").is_err(),
            "NUL byte must be rejected"
        );
    }

    #[test]
    fn test_validate_secrets_path_accepts_plain_relative() {
        assert!(
            validate_secrets_path("my-secrets", "secrets_filename").is_ok(),
            "Plain relative filename must be accepted"
        );
    }

    #[test]
    fn test_validate_secrets_path_accepts_leading_dot_suffix() {
        // ".sealed" is a relative suffix with a leading dot — NOT `..`
        assert!(
            validate_secrets_path(".sealed", "secrets_suffix").is_ok(),
            "Relative suffix with leading dot must be accepted"
        );
    }

    #[test]
    fn test_validate_secrets_path_accepts_relative_subpath() {
        assert!(
            validate_secrets_path("nested/dir/secrets", "secrets_filename").is_ok(),
            "Relative subpath without traversal must be accepted"
        );
    }

    #[test]
    fn test_validate_secrets_path_error_names_field_not_value() {
        // The error message must name the field but NOT echo the rejected value
        // (T-39-04: avoid leaking path fragments).
        let err = validate_secrets_path("/etc/shadow", "secrets_filename").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("secrets_filename"),
            "Error must name the field 'secrets_filename'"
        );
        assert!(
            !msg.contains("/etc/shadow"),
            "Error must NOT echo the rejected value '/etc/shadow'"
        );
    }

    #[test]
    fn test_validate_secrets_path_rejects_empty_string() {
        // WR-02: empty string passes all prior checks but Path::join(dir, "") yields the
        // directory itself, producing a confusing IsADirectory I/O error at use-time.
        assert!(
            validate_secrets_path("", "secrets_filename").is_err(),
            "Empty string must be rejected"
        );
    }

    #[test]
    fn test_validate_secrets_path_rejects_windows_drive_relative() {
        // WR-01: drive-relative form `C:secrets` (no separator after colon) is also
        // rejected now that the check tests bytes[1] == b':' rather than requiring
        // bytes[2] to be a slash. C:\ and C:/ remain rejected (covered by the same branch).
        assert!(
            validate_secrets_path("C:secrets", "secrets_filename").is_err(),
            "Windows drive-relative C:secrets must be rejected"
        );
        // Existing slash-form cases must still be rejected.
        assert!(
            validate_secrets_path("C:\\secrets", "secrets_filename").is_err(),
            "Windows drive-absolute C:\\ must still be rejected"
        );
        assert!(
            validate_secrets_path("C:/secrets", "secrets_filename").is_err(),
            "Windows drive-absolute C:/ must still be rejected"
        );
    }

    // -------------------------------------------------------------------------
    // sanitize_for_display — unit tests (REM-34 + REM-35)
    // -------------------------------------------------------------------------

    #[test]
    fn test_sanitize_preserves_normal_text() {
        assert_eq!(sanitize_for_display("hello world"), "hello world");
        assert_eq!(sanitize_for_display("ASCII 123!@#"), "ASCII 123!@#");
        assert_eq!(sanitize_for_display("Unicode café naïve"), "Unicode café naïve");
        assert_eq!(sanitize_for_display(""), "");
    }

    #[test]
    fn test_sanitize_preserves_tab_newline_cr() {
        // \t, \n, \r are explicitly preserved as safe whitespace
        assert_eq!(sanitize_for_display("\t"), "\t");
        assert_eq!(sanitize_for_display("\n"), "\n");
        assert_eq!(sanitize_for_display("\r"), "\r");
        assert_eq!(sanitize_for_display("line1\nline2\r\n"), "line1\nline2\r\n");
        assert_eq!(sanitize_for_display("col1\tcol2"), "col1\tcol2");
    }

    #[test]
    fn test_sanitize_strips_ansi_esc() {
        // ESC is U+001B (C0 range); stripping it neutralises ANSI sequences.
        // The remaining "[1;31m" bytes are printable ASCII and harmless.
        let ansi = "\u{1b}[1;31mX\u{1b}[0m";
        let sanitised = sanitize_for_display(ansi);
        assert!(
            !sanitised.contains('\u{1b}'),
            "ESC byte must be stripped, got: {sanitised:?}"
        );
        // Printable ASCII characters in the ANSI sequence are kept
        assert!(sanitised.contains('X'));
    }

    #[test]
    fn test_sanitize_strips_nul() {
        let with_nul = "before\u{0000}after";
        let sanitised = sanitize_for_display(with_nul);
        assert_eq!(sanitised, "beforeafter");
    }

    #[test]
    fn test_sanitize_strips_c0_c1() {
        // C0: U+0001–U+001F excluding \t (U+0009), \n (U+000A), \r (U+000D)
        let c0 = "\u{0001}\u{0002}\u{001F}";
        assert_eq!(sanitize_for_display(c0), "");
        // DEL: U+007F
        assert_eq!(sanitize_for_display("\u{007F}"), "");
        // C1: U+0080–U+009F (e.g. NEL U+0085)
        let nel = "\u{0085}";
        assert_eq!(sanitize_for_display(nel), "");
        let c1_range = "\u{0080}\u{0090}\u{009F}";
        assert_eq!(sanitize_for_display(c1_range), "");
        // Normal text around control chars is preserved
        assert_eq!(sanitize_for_display("a\u{0001}b"), "ab");
    }

    #[test]
    fn test_sanitize_strips_bidi() {
        // Bidi overrides are Unicode Cf, NOT caught by char::is_control().
        // This test proves the explicit-codepoint path is active.
        let bidi_overrides = [
            '\u{200F}', // RIGHT-TO-LEFT MARK
            '\u{202A}', // LEFT-TO-RIGHT EMBEDDING
            '\u{202B}', // RIGHT-TO-LEFT EMBEDDING
            '\u{202C}', // POP DIRECTIONAL FORMATTING
            '\u{202D}', // LEFT-TO-RIGHT OVERRIDE
            '\u{202E}', // RIGHT-TO-LEFT OVERRIDE
            '\u{2066}', // LEFT-TO-RIGHT ISOLATE
            '\u{2067}', // RIGHT-TO-LEFT ISOLATE
            '\u{2068}', // FIRST STRONG ISOLATE
            '\u{2069}', // POP DIRECTIONAL ISOLATE
        ];
        for ch in bidi_overrides {
            let s = format!("before{ch}after");
            let sanitised = sanitize_for_display(&s);
            assert_eq!(
                sanitised, "beforeafter",
                "Bidi codepoint U+{:04X} must be stripped",
                ch as u32
            );
            // Confirm is_control() would NOT have caught it (documents the Pitfall 4 gap)
            assert!(
                !ch.is_control(),
                "U+{:04X} is not Cc — is_control() alone would miss it",
                ch as u32
            );
        }
        // Verify U+202E (RLO) specifically, as it is the classic Trojan-Source codepoint
        let trojan = "\u{202E}secret\u{202C}";
        assert_eq!(sanitize_for_display(trojan), "secret");
    }

    #[test]
    fn test_sanitize_strips_separators_and_alm() {
        // MN-01: U+2028 LINE SEPARATOR / U+2029 PARAGRAPH SEPARATOR (Zl/Zp) and
        // U+061C ARABIC LETTER MARK (Cf bidi control) must be stripped. None of the
        // three are Cc, so char::is_control() alone would miss them — this asserts the
        // explicit-codepoint path covers them (mirrors the bidi-override test above).
        let extra = [
            '\u{2028}', // LINE SEPARATOR
            '\u{2029}', // PARAGRAPH SEPARATOR
            '\u{061C}', // ARABIC LETTER MARK
        ];
        for ch in extra {
            let s = format!("before{ch}after");
            let sanitised = sanitize_for_display(&s);
            assert_eq!(
                sanitised, "beforeafter",
                "Codepoint U+{:04X} must be stripped",
                ch as u32
            );
            assert!(
                !ch.is_control(),
                "U+{:04X} is not Cc — is_control() alone would miss it",
                ch as u32
            );
        }
        // Fake-log-line injection attempt via U+2028 must collapse to one line.
        let injected = "name\u{2028}fake log line";
        assert_eq!(sanitize_for_display(injected), "namefake log line");
    }

    #[test]
    #[serial]
    fn test_validate_file_path() {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();

        // Create test files
        let test_file = temp_path.join("test.txt");
        std::fs::write(&test_file, "test content").unwrap();

        let subdir = temp_path.join("subdir");
        std::fs::create_dir(&subdir).unwrap();
        let subdir_file = subdir.join("test.txt");
        std::fs::write(&subdir_file, "test content").unwrap();

        // Save original directory (create guard early, before any test may have changed it)
        // Use a fallback to temp_path if current_dir fails (handles tests run in deleted directories)
        let original_dir = std::env::current_dir().unwrap_or_else(|_| temp_path.to_path_buf());

        // Change to temp directory for testing
        std::env::set_current_dir(temp_path).unwrap();

        // All valid paths should work (no restrictions)
        assert!(validate_file_path("test.txt").is_ok());
        assert!(validate_file_path("subdir/test.txt").is_ok());
        assert!(validate_file_path("../").is_ok()); // Parent directories allowed
        assert!(validate_file_path("/etc/passwd").is_ok()); // Absolute paths allowed

        // Symlinks should be resolved
        assert!(validate_file_path(test_file.to_str().unwrap()).is_ok());

        // Invalid: null bytes (filesystem limitation)
        assert!(validate_file_path("test\0file.txt").is_err());

        // Restore original directory before temp_dir cleanup
        let _ = std::env::set_current_dir(&original_dir);
    }

    // ── validate_vault_address ───────────────────────────────────────────────
    //
    // Tests cover: empty, non-https schemes (http, custom, empty-scheme, just
    // the scheme), bare https://, and valid https addresses.  No value is
    // echoed by the function; tests only check Ok/Err status.

    #[test]
    fn test_validate_vault_address_valid_https() {
        assert!(validate_vault_address("https://vault.example.com").is_ok());
        assert!(validate_vault_address("https://vault.example.com:8200").is_ok());
        assert!(validate_vault_address("https://vault.example.com/v1/").is_ok());
        assert!(validate_vault_address("https://localhost:8200").is_ok());
        assert!(validate_vault_address("https://10.0.0.1:8200").is_ok());
    }

    #[test]
    fn test_validate_vault_address_empty() {
        let err = validate_vault_address("").unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("address"),
            "error should name the `address` field; got: {msg}"
        );
        // Must not echo any value (value was empty anyway, but enforce the convention)
        assert!(!msg.contains("http"), "error must not echo the value");
    }

    #[test]
    fn test_validate_vault_address_plain_http_rejected() {
        let err = validate_vault_address("http://vault.example.com").unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("address"), "error must name the field; got: {msg}");
        // The error message explains the requirement but must not re-emit the value
        assert!(
            !msg.contains("vault.example.com"),
            "error must not echo the value; got: {msg}"
        );
    }

    #[test]
    fn test_validate_vault_address_uppercase_https_rejected() {
        // RFC 3986 scheme normalisation is the server's job; we require lowercase https.
        assert!(validate_vault_address("HTTPS://vault.example.com").is_err());
        assert!(validate_vault_address("Https://vault.example.com").is_err());
    }

    #[test]
    fn test_validate_vault_address_custom_scheme_rejected() {
        assert!(validate_vault_address("vault://vault.example.com").is_err());
        assert!(validate_vault_address("ftp://vault.example.com").is_err());
    }

    #[test]
    fn test_validate_vault_address_bare_scheme_only_rejected() {
        // Bare "https://" with nothing after is invalid.
        let err = validate_vault_address("https://").unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("address"), "error must name the field; got: {msg}");
    }
}
