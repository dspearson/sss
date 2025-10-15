use anyhow::{anyhow, Result};
use clap::ArgMatches;
use std::io::{self, Write};
use std::path::PathBuf;

use crate::{crypto::KeyPair, keystore::Keystore, secure_memory::password};

/// Create keystore instance based on global confdir parameter
fn create_keystore(matches: &ArgMatches) -> Result<Keystore> {
    if let Some(confdir) = matches.get_one::<String>("confdir") {
        Keystore::new_with_config_dir(PathBuf::from(confdir))
    } else {
        Keystore::new()
    }
}

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
    let keystore = create_keystore(main_matches)?;

    match matches.subcommand() {
        Some(("generate", sub_matches)) => handle_keys_generate_command(main_matches, sub_matches)?,
        Some(("list", _)) => {
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
                        &key_id[..8],
                        stored.created_at.format("%Y-%m-%d %H:%M"),
                        protection,
                        status
                    );
                }
            }
        }
        Some(("pubkey", sub_matches)) => {
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
                let is_protected = keystore.is_current_key_password_protected()?;
                let password_opt = if is_protected {
                    let password = password::read_password("Enter passphrase: ")?;
                    Some(password.as_str()?.to_string())
                } else {
                    None
                };

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
        }
        Some(("delete", sub_matches)) => {
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
        }
        Some(("current", sub_matches)) => {
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
                                &key_id[..8],
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
        }
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
    let current_user = std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "unknown".to_string());

    let (_, repository_key) = load_project_config_with_repository_key(config_path, &current_user)?;

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
fn generate_randomart(fingerprint: &[u8], key_type: &str) {
    const WIDTH: usize = 17;
    const HEIGHT: usize = 9;

    // Characters for different visit counts (same as OpenSSH)
    const CHARS: &[char] = &[
        ' ', '.', 'o', '+', '=', '*', 'B', 'O', 'X', '@', '%', '&', '#', '/', '^',
    ];

    // Check if terminal supports colours (respects NO_COLOR environment variable)
    let use_colours = std::env::var("NO_COLOR").is_err() && atty::is(atty::Stream::Stdout);

    let mut field = [[0u8; WIDTH]; HEIGHT];
    let mut x = WIDTH / 2;
    let mut y = HEIGHT / 2;

    // Walk the field based on fingerprint bytes (Drunken Bishop walk)
    for byte in fingerprint {
        for i in 0..4 {
            let direction = (byte >> (i * 2)) & 0x3;

            // Move based on 2-bit direction
            match direction {
                0 => {
                    // NW
                    x = x.saturating_sub(1);
                    y = y.saturating_sub(1);
                }
                1 => {
                    // NE
                    if x < WIDTH - 1 {
                        x += 1;
                    }
                    y = y.saturating_sub(1);
                }
                2 => {
                    // SW
                    x = x.saturating_sub(1);
                    if y < HEIGHT - 1 {
                        y += 1;
                    }
                }
                3 => {
                    // SE
                    if x < WIDTH - 1 {
                        x += 1;
                    }
                    if y < HEIGHT - 1 {
                        y += 1;
                    }
                }
                _ => {}
            }

            // Increment visit count (cap at chars length - 1)
            if field[y][x] < (CHARS.len() - 1) as u8 {
                field[y][x] += 1;
            }
        }
    }

    // Mark start and end positions
    let start_x = WIDTH / 2;
    let start_y = HEIGHT / 2;

    // Print the art with hex fingerprint on the right
    let header = format!("[{}]", key_type);
    let padding = WIDTH.saturating_sub(header.len()) / 2;
    let right_padding = WIDTH - padding - header.len();
    println!(
        "+{}[{}]{}+",
        "-".repeat(padding),
        key_type,
        "-".repeat(right_padding)
    );

    // HSV to RGB conversion
    let hsv_to_rgb = |h: f64, s: f64, v: f64| -> (u8, u8, u8) {
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
    };

    // Calculate relative luminance for contrast determination
    let relative_luminance = |r: u8, g: u8, b: u8| -> f64 {
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
    };

    // Enhanced byte to colour mapping
    let byte_to_colour = |byte_val: u8| -> (u8, u8, u8) {
        // Split byte into high and low nibbles
        let high = (byte_val >> 4) & 0x0F; // High nibble (0-15)
        let low = byte_val & 0x0F; // Low nibble (0-15)

        // Map high nibble to hue (16 distinct hues)
        let hues = [
            0.0, 25.0, 45.0, 65.0, 90.0, 120.0, 150.0, 180.0, 210.0, 240.0, 270.0, 290.0, 310.0,
            330.0, 345.0, 360.0,
        ];
        let hue = hues[high as usize];

        // Map low nibble to saturation/value
        // Checkerboard pattern for adjacent differentiation
        let pattern = ((high + low) % 2) as f64;

        let (sat, val) = if low < 4 {
            // Dark, saturated
            (0.9, if pattern > 0.5 { 0.45 } else { 0.55 })
        } else if low < 8 {
            // Medium brightness, saturated
            (0.85, if pattern > 0.5 { 0.65 } else { 0.75 })
        } else if low < 12 {
            // Bright, saturated
            (0.75, if pattern > 0.5 { 0.85 } else { 0.92 })
        } else {
            // Very bright, less saturated
            (0.65, 0.95)
        };

        hsv_to_rgb(hue, sat, val)
    };

    // Helper function to colourise hex bytes based on their value
    let colourise_hex_byte = |byte_val: u8| -> String {
        if !use_colours {
            return format!("{:02x}", byte_val);
        }

        let (r, g, b) = byte_to_colour(byte_val);

        // Determine text colour based on background luminance (WCAG compliant)
        let lum = relative_luminance(r, g, b);
        let (fr, fg, fb) = if lum > 0.4 {
            (0, 0, 0) // Black text for light backgrounds
        } else {
            (255, 255, 255) // White text for dark backgrounds
        };

        // Use 24-bit RGB colours for precise control
        format!(
            "\x1b[38;2;{};{};{}m\x1b[48;2;{};{};{}m{:02x}\x1b[0m",
            fr, fg, fb, r, g, b, byte_val
        )
    };

    // Format hex fingerprint in groups of 4 bytes (8 hex chars) per line
    // Split into two groups with a blank line in between for better alignment
    let mut hex_lines: Vec<String> = fingerprint
        .chunks(4)
        .map(|chunk| {
            chunk
                .iter()
                .map(|b| colourise_hex_byte(*b))
                .collect::<Vec<_>>()
                .join(":")
        })
        .collect();

    // Insert blank line after 4th line (in the middle)
    if hex_lines.len() > 4 {
        hex_lines.insert(4, String::new());
    }

    // Generate geometric medallion using avalanche effect
    // Uses SHA256-like mixing to ensure small changes create dramatically different patterns
    // Generate for ALL 8 rows of hex data (don't skip the middle separator line)
    let generate_medallion = || -> Vec<String> {
        let num_chunks = fingerprint.chunks(4).count(); // Should be 8 for 32 bytes
        let mut medallion = vec![String::new(); num_chunks];

        if !use_colours {
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
            // Mix the state (avalanche)
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

        // Generate medallion pattern for each row (8 rows total)
        for (row_idx, medallion_line) in medallion.iter_mut().enumerate().take(num_chunks) {
            let mut line = String::new();
            // Each row gets 9 cells
            for col in 0..9 {
                // Position in medallion influences the pattern
                let pos = (row_idx * 9 + col) as u64;
                let cell_seed = state[(pos % 4) as usize]
                    .wrapping_add(pos.wrapping_mul(0x517CC1B727220A95))
                    .rotate_left((pos % 64) as u32);

                // Extract pattern type and colour from hash
                let pattern_type = cell_seed & 0x7; // 8 different patterns
                let colour_seed = (cell_seed >> 3) & 0xFFFFFF;

                // Generate colour with good distribution
                let hue = ((colour_seed & 0xFFF) as f64 / 4095.0) * 360.0;
                let sat = 0.6 + ((colour_seed >> 12) & 0xFF) as f64 / 255.0 * 0.3;
                let val = 0.5 + ((colour_seed >> 20) & 0xF) as f64 / 15.0 * 0.4;

                let (r, g, b) = hsv_to_rgb(hue, sat, val);

                // Choose character based on pattern type
                let ch = match pattern_type {
                    0 => '▀', // Upper half block
                    1 => '▄', // Lower half block
                    2 => '█', // Full block
                    3 => '▌', // Left half block
                    4 => '▐', // Right half block
                    5 => '░', // Light shade
                    6 => '▒', // Medium shade
                    _ => '▓', // Dark shade
                };

                line.push_str(&format!("\x1b[38;2;{};{};{}m{}\x1b[0m", r, g, b, ch));
            }
            *medallion_line = line;
        }

        medallion
    };

    let mut medallion_lines = generate_medallion();

    // Insert blank line at position 4 to match the hex_lines blank separator
    if medallion_lines.len() > 4 {
        medallion_lines.insert(4, String::new());
    }

    // Helper function to colourise character based on visit count
    let colourise = |ch: char, count: u8| -> String {
        if !use_colours {
            return ch.to_string();
        }

        // Apply colours based on density (heat map style)
        let colour_code = match count {
            0 => "38;5;236",       // Dark gray for empty
            1 => "38;5;240",       // Gray
            2..=3 => "38;5;33",    // Blue (low density)
            4..=5 => "38;5;39",    // Cyan
            6..=7 => "38;5;46",    // Green (medium density)
            8..=9 => "38;5;226",   // Yellow
            10..=11 => "38;5;208", // Orange
            _ => "38;5;196",       // Red (high density)
        };

        format!("\x1b[{}m{}\x1b[0m", colour_code, ch)
    };

    for (row_idx, row) in field.iter().enumerate() {
        print!("|");
        for (col_idx, &count) in row.iter().enumerate() {
            if col_idx == start_x && row_idx == start_y {
                // Start position - cyan/bold
                if use_colours {
                    print!("\x1b[1;36mS\x1b[0m");
                } else {
                    print!("S");
                }
            } else if col_idx == x && row_idx == y {
                // End position - green/bold
                if use_colours {
                    print!("\x1b[1;32mE\x1b[0m");
                } else {
                    print!("E");
                }
            } else {
                let char_idx = (count as usize).min(CHARS.len() - 1);
                print!("{}", colourise(CHARS[char_idx], count));
            }
        }
        print!("|");

        // Print hex line if available
        if row_idx < hex_lines.len() {
            print!("  {}", hex_lines[row_idx]);

            // Print medallion only on lines with hex content (not on blank separator line)
            if !hex_lines[row_idx].is_empty()
                && row_idx < medallion_lines.len()
                && !medallion_lines[row_idx].is_empty()
            {
                print!("  {}", medallion_lines[row_idx]);
            }
        }

        println!();
    }
    println!("+{}+", "-".repeat(WIDTH));
}
