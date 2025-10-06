use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Attempt to locate the workspace root based on the manifest directory.
fn workspace_root() -> Option<PathBuf> {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").ok()?);
    manifest_dir.parent()?.parent().map(Path::to_path_buf)
}

/// Determine the path to the example configuration file.
fn locate_config_example(workspace_root: &Path) -> Option<PathBuf> {
    if let Ok(custom) = env::var("OXIDE_CONFIG_EXAMPLE") {
        let custom_path = PathBuf::from(custom);
        if custom_path.exists() {
            return Some(custom_path);
        } else {
            println!(
                "cargo:warning=OXIDE_CONFIG_EXAMPLE was set but the file was not found: {}",
                custom_path.display()
            );
        }
    }

    let default_path = workspace_root.join("config.toml.example");
    if default_path.exists() {
        Some(default_path)
    } else {
        None
    }
}

/// Copy `config.toml.example` into the ox-build target directory without
/// overwriting an existing file. Errors are emitted as cargo warnings so the
/// build can continue even if the copy fails (for example, in read-only
/// environments).
fn copy_config_example(config_src: &Path, workspace_root: &Path) {
    let target_root = workspace_root.join("ox-build").join("target");

    let profile = env::var("PROFILE").unwrap_or_else(|_| "release".to_owned());
    let mut destinations = vec![target_root.join(&profile)];

    // When building release binaries also ensure the debug directory gets a
    // copy so developers have a ready-to-use template when switching profiles.
    if profile == "release" {
        destinations.push(target_root.join("debug"));
    }

    for dest_dir in destinations {
        if let Err(err) = fs::create_dir_all(&dest_dir) {
            println!(
                "cargo:warning=Failed to create config output directory {}: {}",
                dest_dir.display(),
                err
            );
            continue;
        }

        let dest_path = dest_dir.join("config.toml.example");
        if dest_path.exists() {
            // Avoid overwriting existing files so users can customize the copy.
            continue;
        }

        if let Err(err) = fs::copy(config_src, &dest_path) {
            println!(
                "cargo:warning=Failed to copy {} to {}: {}",
                config_src.display(),
                dest_path.display(),
                err
            );
        }
    }
}

fn git_output(args: &[&str]) -> Option<String> {
    Command::new("git")
        .args(args)
        .output()
        .ok()
        .and_then(|out| {
            if out.status.success() {
                Some(String::from_utf8_lossy(&out.stdout).trim().to_owned())
            } else {
                None
            }
        })
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/refs");

    if let Some(workspace_root) = workspace_root() {
        if let Some(config_path) = locate_config_example(&workspace_root) {
            println!("cargo:rerun-if-changed={}", config_path.display());
            copy_config_example(&config_path, &workspace_root);
        } else {
            println!("cargo:warning=config.toml.example was not found; skipping copy step");
        }
    } else {
        println!("cargo:warning=Unable to determine workspace root; skipping config copy");
    }

    if let Some(commit) = git_output(&["rev-parse", "HEAD"]) {
        println!("cargo:rustc-env=OXIDE_GIT_COMMIT={commit}");
    }

    if let Some(short_commit) = git_output(&["rev-parse", "--short", "HEAD"]) {
        println!("cargo:rustc-env=OXIDE_GIT_COMMIT_SHORT={short_commit}");
    }

    if let Some(commit_timestamp) = git_output(&["log", "-1", "--format=%cI", "HEAD"]) {
        println!("cargo:rustc-env=OXIDE_GIT_COMMIT_TIMESTAMP={commit_timestamp}");
    }

    let build_timestamp = chrono::Utc::now().to_rfc3339();
    println!("cargo:rustc-env=OXIDE_BUILD_TIMESTAMP={build_timestamp}");
}
