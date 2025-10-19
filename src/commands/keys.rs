use anyhow::{anyhow, Result};
use clap::ArgMatches;
use std::io::{self, Write};

use crate::{
    commands::utils::{create_keystore, get_password_if_protected},
    constants::KEY_ID_DISPLAY_LENGTH,
    crypto::KeyPair,
    secure_memory::password,
};

fn handle_keys_generate_command(main_matches: &ArgMatches, matches: &ArgMatches) -> Result<()> {
    let force = matches.get_flag("force");
    let no_password = matches.get_flag("no-password");

    let keystore = create_keystore(main_matches)?;

    // Check if current keypair exists
    if !force && keystore.get_current_keypair(None).is_ok() {
        return Err(anyhow!(
            "A keypair already exists. Use --force to overwrite."
        ));
    }

    let password_option = if no_password {
        None
    } else {
        let passphrase = password::read_password_with_confirmation(
            "Enter passphrase for new keypair: ",
            "Confirm passphrase: ",
        )?;

        if passphrase.is_empty() {
            return Err(anyhow!(
                "Passphrase cannot be empty. Use --no-password for passwordless keys."
            ));
        }

        Some(passphrase.as_str()?.to_string())
    };

    let keypair = KeyPair::generate()?;
    let key_id = keystore.store_keypair(&keypair, password_option.as_deref())?;

    println!("Generated new keypair: {}", key_id);
    println!("Public key: {}", keypair.public_key.to_base64());

    if no_password {
        println!("Warning: Keypair stored without password protection. Consider using a passphrase for better security.");
    }

    Ok(())
}

pub fn handle_keys(main_matches: &ArgMatches, matches: &ArgMatches) -> Result<()> {
    match matches.subcommand() {
        Some(("generate", sub_matches)) => handle_keys_generate_command(main_matches, sub_matches)?,
        Some(("list", _)) => handle_keys_list(main_matches)?,
        Some(("pubkey", sub_matches)) => handle_keys_pubkey(main_matches, sub_matches)?,
        Some(("delete", sub_matches)) => handle_keys_delete(main_matches, sub_matches)?,
        Some(("current", sub_matches)) => handle_keys_current(main_matches, sub_matches)?,
        Some(("rotate", sub_matches)) => {
            handle_keys_rotate_command(main_matches, sub_matches)?;
        }
        None => {
            // No subcommand provided, show available subcommands
            return Err(anyhow!(
                "No subcommand provided\n\n\
                Available subcommands:\n\
                  generate    Generate a new keypair\n\
                  list        List your private keys\n\
                  pubkey      Show your public key\n\
                  current     Show or set current keypair\n\
                  delete      Delete a keypair\n\
                  rotate      Rotate repository encryption key\n\n\
                Use 'sss keys <subcommand> --help' for more information on a subcommand."
            ));
        }
        _ => unreachable!(),
    }

    Ok(())
}

fn handle_keys_list(main_matches: &ArgMatches) -> Result<()> {
    let keystore = create_keystore(main_matches)?;
    let keys = keystore.list_key_ids()?;

    if keys.is_empty() {
        println!("No keypairs found. Generate one with: sss keys generate");
    } else {
        println!("Found {} keypair(s):", keys.len());

        let current_id = keystore.get_current_key_id().ok();

        for (key_id, stored) in keys {
            let is_current = current_id.as_ref() == Some(&key_id);
            let status = if is_current { " (current)" } else { "" };
            let protection = if stored.is_password_protected {
                " [protected]"
            } else {
                ""
            };

            println!(
                "  {}... - Created: {}{}{}",
                &key_id[..KEY_ID_DISPLAY_LENGTH],
                stored.created_at.format("%Y-%m-%d %H:%M"),
                protection,
                status
            );
        }
    }

    Ok(())
}

fn handle_keys_pubkey(main_matches: &ArgMatches, sub_matches: &ArgMatches) -> Result<()> {
    let keystore = create_keystore(main_matches)?;
    let show_fingerprint = sub_matches.get_flag("fingerprint");
    let username = sub_matches.get_one::<String>("user");

    let full_key = if let Some(user) = username {
        // Show public key from project config for specified user
        use crate::constants::CONFIG_FILE_NAME;
        use crate::project::ProjectConfig;
        use std::path::Path;

        if !Path::new(CONFIG_FILE_NAME).exists() {
            return Err(anyhow!(
                "No project configuration found. You must be in an SSS project to view user public keys."
            ));
        }

        let config = ProjectConfig::load_from_file(CONFIG_FILE_NAME)?;

        // Find the user in the config
        let user_config = config.users.get(user).ok_or_else(|| {
            anyhow!(
                "User '{}' not found in project.\nAvailable users: {}",
                user,
                config
                    .users
                    .keys()
                    .map(|k| k.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        })?;

        user_config.public.clone()
    } else {
        // Show own public key from keystore
        let password_opt = get_password_if_protected(&keystore, "Enter passphrase: ")?;
        let keypair = keystore.get_current_keypair(password_opt.as_deref())?;
        keypair.public_key.to_base64()
    };

    if show_fingerprint {
        // Generate SHA256 fingerprint (like SSH)
        use libsodium_sys::{crypto_hash_sha256, crypto_hash_sha256_BYTES};

        // Get the raw public key bytes
        let pubkey_bytes = full_key.as_bytes();

        let mut hash = vec![0u8; crypto_hash_sha256_BYTES as usize];
        unsafe {
            crypto_hash_sha256(
                hash.as_mut_ptr(),
                pubkey_bytes.as_ptr(),
                pubkey_bytes.len() as u64,
            );
        }

        // Generate visual randomart with hex fingerprint (like SSH's VisualHostKey)
        generate_randomart(&hash, "SSS KEY");
    } else {
        println!("{}", full_key);
    }

    Ok(())
}

fn handle_keys_delete(main_matches: &ArgMatches, sub_matches: &ArgMatches) -> Result<()> {
    let keystore = create_keystore(main_matches)?;
    let key_name = sub_matches.get_one::<String>("name").unwrap();

    print!(
        "Are you sure you want to delete keypair '{}'? [y/N]: ",
        key_name
    );
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;

    if input.trim().to_lowercase() == "y" {
        keystore.delete_keypair(key_name)?;
        println!("Deleted keypair: {}", key_name);
    } else {
        println!("Cancelled");
    }

    Ok(())
}

fn handle_keys_current(main_matches: &ArgMatches, sub_matches: &ArgMatches) -> Result<()> {
    let keystore = create_keystore(main_matches)?;

    if let Some(key_name) = sub_matches.get_one::<String>("name") {
        // Set current key
        let keys = keystore.list_key_ids()?;
        let key_to_set = keys.iter().find(|(id, _)| id.starts_with(key_name));

        match key_to_set {
            Some((key_id, _)) => {
                keystore.set_current_key(key_id)?;
                println!("Set current key to: {}", key_id);
            }
            None => {
                println!("Key not found: {}", key_name);
                println!("Available keys:");
                for (key_id, stored) in keys {
                    println!(
                        "  {} (created: {})",
                        &key_id[..KEY_ID_DISPLAY_LENGTH],
                        stored.created_at.format("%Y-%m-%d")
                    );
                }
            }
        }
    } else {
        // Show current key
        match keystore.get_current_key_id() {
            Ok(current_id) => {
                println!("Current key ID: {}", current_id);
                match keystore.get_current_keypair(None) {
                    Ok(keypair) => {
                        println!("Public key: {}", keypair.public_key.to_base64());
                    }
                    Err(_) => {
                        println!("(Key is password protected)");
                    }
                }
            }
            Err(_) => {
                println!("No current key set");
            }
        }
    }

    Ok(())
}

fn handle_keys_rotate_command(_main_matches: &ArgMatches, matches: &ArgMatches) -> Result<()> {
    use crate::{
        config::load_project_config_with_repository_key,
        constants::CONFIG_FILE_NAME,
        rotation::{confirm_rotation, RotationManager, RotationOptions, RotationReason},
    };

    let force = matches.get_flag("force");
    let no_backup = matches.get_flag("no-backup");
    let dry_run = matches.get_flag("dry-run");

    // Check if we're in a project
    let config_path = CONFIG_FILE_NAME;
    if !std::path::Path::new(config_path).exists() {
        return Err(anyhow!(
            "No project configuration found. Run 'sss init' first."
        ));
    }

    let reason = RotationReason::ManualRotation;

    // Confirm rotation unless forced or dry run
    if !dry_run && !confirm_rotation(&reason, force)? {
        println!("Key rotation cancelled");
        return Ok(());
    }

    // Get current user and repository key
    let (_, repository_key, _) = load_project_config_with_repository_key(config_path)?;

    // Set up rotation options
    let options = RotationOptions {
        no_backup,
        force,
        dry_run,
        show_progress: true,
    };

    // Perform the rotation
    let rotation_manager = RotationManager::new(options);
    let result = rotation_manager.rotate_repository_key(
        &std::path::PathBuf::from(config_path),
        &repository_key,
        reason,
    )?;

    result.print_summary();

    if dry_run {
        println!("This was a dry run. Use 'sss keys rotate' (without --dry-run) to perform the actual rotation.");
    }

    Ok(())
}

pub fn handle_keygen_deprecated(main_matches: &ArgMatches, matches: &ArgMatches) -> Result<()> {
    eprintln!("Warning: 'sss keygen' is deprecated. Use 'sss keys generate' instead.");
    handle_keys_generate_command(main_matches, matches)
}

/// Generate ASCII art representation of a fingerprint (Drunken Bishop algorithm)
/// This is the same algorithm used by OpenSSH for visual host key verification
// Randomart constants
const RANDOMART_WIDTH: usize = 17;
const RANDOMART_HEIGHT: usize = 9;
const RANDOMART_CHARS: &[char] = &[
    ' ', '.', 'o', '+', '=', '*', 'B', 'O', 'X', '@', '%', '&', '#', '/', '^',
];
const BITS_PER_DIRECTION: usize = 2;
const DIRECTIONS_PER_BYTE: usize = 4;
const MEDALLION_COLUMNS: usize = 9;

/// Perform the Drunken Bishop walk to generate randomart field
fn walk_drunken_bishop(fingerprint: &[u8]) -> ([[u8; RANDOMART_WIDTH]; RANDOMART_HEIGHT], (usize, usize)) {
    let mut field = [[0u8; RANDOMART_WIDTH]; RANDOMART_HEIGHT];
    let mut x = RANDOMART_WIDTH / 2;
    let mut y = RANDOMART_HEIGHT / 2;

    for byte in fingerprint {
        for i in 0..DIRECTIONS_PER_BYTE {
            let direction = (byte >> (i * BITS_PER_DIRECTION)) & 0x3;

            // Move based on 2-bit direction (NW=0, NE=1, SW=2, SE=3)
            match direction {
                0 => {
                    x = x.saturating_sub(1);
                    y = y.saturating_sub(1);
                }
                1 => {
                    if x < RANDOMART_WIDTH - 1 {
                        x += 1;
                    }
                    y = y.saturating_sub(1);
                }
                2 => {
                    x = x.saturating_sub(1);
                    if y < RANDOMART_HEIGHT - 1 {
                        y += 1;
                    }
                }
                3 => {
                    if x < RANDOMART_WIDTH - 1 {
                        x += 1;
                    }
                    if y < RANDOMART_HEIGHT - 1 {
                        y += 1;
                    }
                }
                _ => {}
            }

            // Increment visit count (cap at chars length - 1)
            if field[y][x] < (RANDOMART_CHARS.len() - 1) as u8 {
                field[y][x] += 1;
            }
        }
    }

    (field, (x, y))
}

/// Convert HSV to RGB color space
fn hsv_to_rgb(h: f64, s: f64, v: f64) -> (u8, u8, u8) {
    let c = v * s;
    let x = c * (1.0 - ((h / 60.0) % 2.0 - 1.0).abs());
    let m = v - c;

    let (r, g, b) = if h < 60.0 {
        (c, x, 0.0)
    } else if h < 120.0 {
        (x, c, 0.0)
    } else if h < 180.0 {
        (0.0, c, x)
    } else if h < 240.0 {
        (0.0, x, c)
    } else if h < 300.0 {
        (x, 0.0, c)
    } else {
        (c, 0.0, x)
    };

    (
        ((r + m) * 255.0) as u8,
        ((g + m) * 255.0) as u8,
        ((b + m) * 255.0) as u8,
    )
}

/// Calculate relative luminance for contrast determination (WCAG)
fn relative_luminance(r: u8, g: u8, b: u8) -> f64 {
    let r = r as f64 / 255.0;
    let g = g as f64 / 255.0;
    let b = b as f64 / 255.0;

    let r = if r <= 0.03928 {
        r / 12.92
    } else {
        ((r + 0.055) / 1.055).powf(2.4)
    };
    let g = if g <= 0.03928 {
        g / 12.92
    } else {
        ((g + 0.055) / 1.055).powf(2.4)
    };
    let b = if b <= 0.03928 {
        b / 12.92
    } else {
        ((b + 0.055) / 1.055).powf(2.4)
    };

    0.2126 * r + 0.7152 * g + 0.0722 * b
}

/// Map byte value to color using high/low nibble split
fn byte_to_color(byte_val: u8) -> (u8, u8, u8) {
    let high = (byte_val >> 4) & 0x0F;
    let low = byte_val & 0x0F;

    // Map high nibble to hue (16 distinct hues)
    let hues = [
        0.0, 25.0, 45.0, 65.0, 90.0, 120.0, 150.0, 180.0, 210.0, 240.0, 270.0, 290.0, 310.0,
        330.0, 345.0, 360.0,
    ];
    let hue = hues[high as usize];

    // Checkerboard pattern for adjacent differentiation
    let pattern = ((high + low) % 2) as f64;

    let (sat, val) = if low < 4 {
        (0.9, if pattern > 0.5 { 0.45 } else { 0.55 })
    } else if low < 8 {
        (0.85, if pattern > 0.5 { 0.65 } else { 0.75 })
    } else if low < 12 {
        (0.75, if pattern > 0.5 { 0.85 } else { 0.92 })
    } else {
        (0.65, 0.95)
    };

    hsv_to_rgb(hue, sat, val)
}

/// Colorize a hex byte with background color and contrasting text
fn colorize_hex_byte(byte_val: u8, use_colors: bool) -> String {
    if !use_colors {
        return format!("{:02x}", byte_val);
    }

    let (r, g, b) = byte_to_color(byte_val);

    // Determine text color based on background luminance (WCAG compliant)
    let lum = relative_luminance(r, g, b);
    let (fr, fg, fb) = if lum > 0.4 {
        (0, 0, 0) // Black text for light backgrounds
    } else {
        (255, 255, 255) // White text for dark backgrounds
    };

    format!(
        "\x1b[38;2;{};{};{}m\x1b[48;2;{};{};{}m{:02x}\x1b[0m",
        fr, fg, fb, r, g, b, byte_val
    )
}

/// Generate geometric medallion using avalanche effect
fn generate_medallion(fingerprint: &[u8], use_colors: bool) -> Vec<String> {
    let num_chunks = fingerprint.chunks(4).count();
    let mut medallion = vec![String::new(); num_chunks];

    if !use_colors {
        return medallion;
    }

    // Create hash-like seed with avalanche properties
    let mut state = [0u64; 4];
    for (i, chunk) in fingerprint.chunks(8).enumerate() {
        let mut val = 0u64;
        for &b in chunk.iter() {
            val = val.wrapping_shl(8) | (b as u64);
        }
        state[i % 4] ^= val.wrapping_mul(0x9E3779B97F4A7C15);
        state[i % 4] = state[i % 4].wrapping_add(state[(i + 1) % 4]);
        state[i % 4] = state[i % 4].rotate_left(23);
    }

    // Final mixing rounds for strong avalanche
    for _ in 0..3 {
        for i in 0..4 {
            state[i] ^= state[(i + 1) % 4];
            state[i] = state[i].wrapping_mul(0x85EBCA6B);
            state[i] ^= state[i] >> 13;
            state[i] = state[i].wrapping_mul(0xC2B2AE35);
            state[i] ^= state[i] >> 16;
        }
    }

    // Generate medallion pattern for each row
    for (row_idx, medallion_line) in medallion.iter_mut().enumerate().take(num_chunks) {
        let mut line = String::new();
        for col in 0..MEDALLION_COLUMNS {
            let pos = (row_idx * MEDALLION_COLUMNS + col) as u64;
            let cell_seed = state[(pos % 4) as usize]
                .wrapping_add(pos.wrapping_mul(0x517CC1B727220A95))
                .rotate_left((pos % 64) as u32);

            let pattern_type = cell_seed & 0x7;
            let color_seed = (cell_seed >> 3) & 0xFFFFFF;

            let hue = ((color_seed & 0xFFF) as f64 / 4095.0) * 360.0;
            let sat = 0.6 + ((color_seed >> 12) & 0xFF) as f64 / 255.0 * 0.3;
            let val = 0.5 + ((color_seed >> 20) & 0xF) as f64 / 15.0 * 0.4;

            let (r, g, b) = hsv_to_rgb(hue, sat, val);

            let ch = match pattern_type {
                0 => '▀', 1 => '▄', 2 => '█', 3 => '▌',
                4 => '▐', 5 => '░', 6 => '▒', _ => '▓',
            };

            line.push_str(&format!("\x1b[38;2;{};{};{}m{}\x1b[0m", r, g, b, ch));
        }
        *medallion_line = line;
    }

    medallion
}

/// Colorize a character based on visit count (heat map style)
fn colorize_char(ch: char, count: u8, use_colors: bool) -> String {
    if !use_colors {
        return ch.to_string();
    }

    let color_code = match count {
        0 => "38;5;236",
        1 => "38;5;240",
        2..=3 => "38;5;33",
        4..=5 => "38;5;39",
        6..=7 => "38;5;46",
        8..=9 => "38;5;226",
        10..=11 => "38;5;208",
        _ => "38;5;196",
    };

    format!("\x1b[{}m{}\x1b[0m", color_code, ch)
}

/// Main randomart generation function
fn generate_randomart(fingerprint: &[u8], key_type: &str) {
    let use_colors = std::env::var("NO_COLOR").is_err() && atty::is(atty::Stream::Stdout);

    // Generate the field using Drunken Bishop walk
    let (field, (end_x, end_y)) = walk_drunken_bishop(fingerprint);
    let start_x = RANDOMART_WIDTH / 2;
    let start_y = RANDOMART_HEIGHT / 2;

    // Print header
    let header = format!("[{}]", key_type);
    let padding = RANDOMART_WIDTH.saturating_sub(header.len()) / 2;
    let right_padding = RANDOMART_WIDTH - padding - header.len();
    println!(
        "+{}[{}]{}+",
        "-".repeat(padding),
        key_type,
        "-".repeat(right_padding)
    );

    // Format hex fingerprint in groups of 4 bytes per line
    let mut hex_lines: Vec<String> = fingerprint
        .chunks(4)
        .map(|chunk| {
            chunk
                .iter()
                .map(|b| colorize_hex_byte(*b, use_colors))
                .collect::<Vec<_>>()
                .join(":")
        })
        .collect();

    // Insert blank line after 4th line for better alignment
    if hex_lines.len() > crate::constants::FINGERPRINT_ART_MAX_LINES {
        hex_lines.insert(crate::constants::FINGERPRINT_ART_MAX_LINES, String::new());
    }

    // Generate medallion and insert blank line to match hex_lines
    let mut medallion_lines = generate_medallion(fingerprint, use_colors);
    if medallion_lines.len() > crate::constants::FINGERPRINT_ART_MAX_LINES {
        medallion_lines.insert(crate::constants::FINGERPRINT_ART_MAX_LINES, String::new());
    }

    // Render the randomart field
    for (row_idx, row) in field.iter().enumerate() {
        print!("|");
        for (col_idx, &count) in row.iter().enumerate() {
            if col_idx == start_x && row_idx == start_y {
                // Start position - cyan/bold
                if use_colors {
                    print!("\x1b[1;36mS\x1b[0m");
                } else {
                    print!("S");
                }
            } else if col_idx == end_x && row_idx == end_y {
                // End position - green/bold
                if use_colors {
                    print!("\x1b[1;32mE\x1b[0m");
                } else {
                    print!("E");
                }
            } else {
                let char_idx = (count as usize).min(RANDOMART_CHARS.len() - 1);
                print!("{}", colorize_char(RANDOMART_CHARS[char_idx], count, use_colors));
            }
        }
        print!("|");

        // Print hex line and medallion if available
        if row_idx < hex_lines.len() {
            print!("  {}", hex_lines[row_idx]);

            if !hex_lines[row_idx].is_empty()
                && row_idx < medallion_lines.len()
                && !medallion_lines[row_idx].is_empty()
            {
                print!("  {}", medallion_lines[row_idx]);
            }
        }

        println!();
    }
    println!("+{}+", "-".repeat(RANDOMART_WIDTH));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_walk_drunken_bishop_deterministic() {
        // Same input should produce same output
        let fingerprint = b"test_fingerprint_12345678";
        let (grid1, pos1) = walk_drunken_bishop(fingerprint);
        let (grid2, pos2) = walk_drunken_bishop(fingerprint);

        assert_eq!(grid1, grid2);
        assert_eq!(pos1, pos2);
    }

    #[test]
    fn test_walk_drunken_bishop_different_inputs() {
        // Different inputs should (very likely) produce different outputs
        let fp1 = b"fingerprint_one_12345678";
        let fp2 = b"fingerprint_two_87654321";

        let (grid1, end1) = walk_drunken_bishop(fp1);
        let (grid2, end2) = walk_drunken_bishop(fp2);

        // Grids should be different (or extremely unlikely to be identical)
        assert_ne!(grid1, grid2);

        // Both should be valid positions (x, y) where x < WIDTH, y < HEIGHT
        assert!(end1.0 < RANDOMART_WIDTH);  // x (column)
        assert!(end1.1 < RANDOMART_HEIGHT); // y (row)
        assert!(end2.0 < RANDOMART_WIDTH);
        assert!(end2.1 < RANDOMART_HEIGHT);
    }

    #[test]
    fn test_walk_drunken_bishop_grid_bounds() {
        // Walk should never go out of bounds
        let fingerprint = b"bounds_test_fingerprint_";
        let (grid, (end_x, end_y)) = walk_drunken_bishop(fingerprint);

        // Check grid dimensions
        assert_eq!(grid.len(), RANDOMART_HEIGHT);
        for row in &grid {
            assert_eq!(row.len(), RANDOMART_WIDTH);
        }

        // Check end position is within bounds (x, y)
        assert!(end_x < RANDOMART_WIDTH);  // x (column)
        assert!(end_y < RANDOMART_HEIGHT); // y (row)
    }

    #[test]
    fn test_hsv_to_rgb_pure_red() {
        // Pure red: H=0, S=1, V=1 should give (255, 0, 0)
        let (r, g, b) = hsv_to_rgb(0.0, 1.0, 1.0);
        assert_eq!(r, 255);
        assert_eq!(g, 0);
        assert_eq!(b, 0);
    }

    #[test]
    fn test_hsv_to_rgb_pure_green() {
        // Pure green: H=120, S=1, V=1 should give (0, 255, 0)
        let (r, g, b) = hsv_to_rgb(120.0, 1.0, 1.0);
        assert_eq!(r, 0);
        assert_eq!(g, 255);
        assert_eq!(b, 0);
    }

    #[test]
    fn test_hsv_to_rgb_pure_blue() {
        // Pure blue: H=240, S=1, V=1 should give (0, 0, 255)
        let (r, g, b) = hsv_to_rgb(240.0, 1.0, 1.0);
        assert_eq!(r, 0);
        assert_eq!(g, 0);
        assert_eq!(b, 255);
    }

    #[test]
    fn test_hsv_to_rgb_grayscale() {
        // When saturation is 0, result should be grayscale
        let (r, g, b) = hsv_to_rgb(180.0, 0.0, 0.5);
        assert_eq!(r, g);
        assert_eq!(g, b);
    }

    #[test]
    fn test_relative_luminance_white() {
        // White should have high luminance
        let lum = relative_luminance(255, 255, 255);
        assert!(lum > 0.9);
    }

    #[test]
    fn test_relative_luminance_black() {
        // Black should have zero luminance
        let lum = relative_luminance(0, 0, 0);
        assert_eq!(lum, 0.0);
    }

    #[test]
    fn test_relative_luminance_monotonic() {
        // Luminance should increase as brightness increases
        let lum1 = relative_luminance(50, 50, 50);
        let lum2 = relative_luminance(100, 100, 100);
        let lum3 = relative_luminance(200, 200, 200);

        assert!(lum1 < lum2);
        assert!(lum2 < lum3);
    }

    #[test]
    fn test_byte_to_color_range() {
        // Test various byte values produce valid RGB (all u8 values are valid)
        for byte_val in [0, 64, 128, 192, 255] {
            let (_r, _g, _b) = byte_to_color(byte_val);
            // RGB values are u8, so they're always in valid range
        }
    }

    #[test]
    fn test_byte_to_color_deterministic() {
        // Same input should give same output
        let (r1, g1, b1) = byte_to_color(123);
        let (r2, g2, b2) = byte_to_color(123);
        assert_eq!((r1, g1, b1), (r2, g2, b2));
    }

    #[test]
    fn test_colorize_hex_byte_no_color() {
        // Without colors, should just return plain hex
        let result = colorize_hex_byte(0xAB, false);
        assert_eq!(result, "ab");
    }

    #[test]
    fn test_colorize_hex_byte_with_color() {
        // With colors, should contain ANSI escape codes
        let result = colorize_hex_byte(0xAB, true);
        assert!(result.contains("\x1b["));
        assert!(result.contains("ab"));
    }

    #[test]
    fn test_colorize_hex_byte_all_values() {
        // Test all possible byte values produce valid output
        for byte_val in 0u8..=255 {
            let result = colorize_hex_byte(byte_val, false);
            assert_eq!(result.len(), 2); // Two hex digits
            let _ = u8::from_str_radix(&result, 16).unwrap(); // Should parse as hex
        }
    }

    #[test]
    fn test_generate_medallion_length() {
        // Medallion should have num_chunks lines (fingerprint.chunks(4).count())
        let fingerprint = b"test_fingerprint_12345678901234567890123456"; // 44 bytes
        let medallion = generate_medallion(fingerprint, false);
        let expected_chunks = fingerprint.chunks(4).count(); // 11 chunks
        assert_eq!(medallion.len(), expected_chunks);
    }

    #[test]
    fn test_generate_medallion_deterministic() {
        // Same fingerprint should produce same medallion
        let fingerprint = b"test_fingerprint_12345678901234567890123456";
        let med1 = generate_medallion(fingerprint, false);
        let med2 = generate_medallion(fingerprint, false);
        assert_eq!(med1, med2);
    }

    #[test]
    fn test_generate_medallion_no_color() {
        // Without colors, output should not contain ANSI codes
        let fingerprint = b"test_fingerprint_12345678901234567890123456";
        let medallion = generate_medallion(fingerprint, false);

        for line in medallion {
            assert!(!line.contains("\x1b["));
        }
    }

    #[test]
    fn test_colorize_char_no_color() {
        // Without colors, should just return the character
        let result = colorize_char('X', 5, false);
        assert_eq!(result, "X");
    }

    #[test]
    fn test_colorize_char_with_color() {
        // With colors, should contain ANSI escape codes
        let result = colorize_char('S', 10, true);
        assert!(result.contains("\x1b["));
        assert!(result.contains('S'));
    }

    #[test]
    fn test_colorize_char_all_chars() {
        // Test all randomart characters
        for &ch in RANDOMART_CHARS {
            let result = colorize_char(ch, 5, false);
            assert_eq!(result.len(), 1);
            assert_eq!(result.chars().next().unwrap(), ch);
        }
    }
}
