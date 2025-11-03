use std::env;
use std::path::Path;
use std::process::Command;

fn main() {
    // Handle macOS FUSE linking
    let target = env::var("TARGET").unwrap_or_default();
    if target.contains("apple-darwin") {
        // During cross-compilation, add search path for libfuse3 in the SDK
        if env::var("CROSS_COMPILE").is_ok() || env::var("CC_aarch64_apple_darwin").is_ok() {
            let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
            let lib_path = format!("{}/cross/osxcross/target/SDK/MacOSX14.5.sdk/usr/local/lib", manifest_dir);
            println!("cargo:rustc-link-search=native={}", lib_path);
        }
    }

    // Always check for rust-9p, even if ninep feature isn't enabled
    // This prevents chicken-and-egg problem with cargo dependency resolution
    let p9_dir = Path::new("vendor/rust-9p");

        // Clone pfpacket/rust-9p if it doesn't exist
        if !p9_dir.exists() {
            println!("cargo:warning=Cloning pfpacket/rust-9p...");

            // Create vendor directory if needed
            std::fs::create_dir_all("vendor").expect("Failed to create vendor directory");

            let status = Command::new("git")
                .args([
                    "clone",
                    "--depth", "1",
                    "https://github.com/pfpacket/rust-9p",
                    "vendor/rust-9p",
                ])
                .status()
                .expect("Failed to execute git clone");

            if !status.success() {
                panic!("Failed to clone pfpacket/rust-9p");
            }

            println!("cargo:warning=Successfully cloned pfpacket/rust-9p");

            // Patch Cargo.toml for nix 0.26 compatibility
            let cargo_toml_path = Path::new("vendor/rust-9p/Cargo.toml");
            if cargo_toml_path.exists() {
                println!("cargo:warning=Patching rust-9p for nix 0.26 compatibility...");

                let content = std::fs::read_to_string(cargo_toml_path)
                    .expect("Failed to read rust-9p Cargo.toml");

                // Replace nix dependency version
                let patched = content.replace(r#"nix = "0.23""#, r#"nix = "0.26""#)
                    .replace(r#"nix = { version = "0.23""#, r#"nix = { version = "0.26""#);

                std::fs::write(cargo_toml_path, patched)
                    .expect("Failed to write patched Cargo.toml");

                println!("cargo:warning=Successfully patched rust-9p");
            }
        }
        // Note: vendor/rust-9p already exists (no action needed)

    // Tell cargo to rerun if the vendor directory changes
    println!("cargo:rerun-if-changed=vendor/rust-9p");
}
