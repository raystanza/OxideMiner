use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

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

fn workspace_root(manifest_dir: &str) -> PathBuf {
    Path::new(manifest_dir)
        .ancestors()
        .nth(2)
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from(manifest_dir))
}

fn locate_config_template(root: &Path) -> Option<PathBuf> {
    if let Ok(explicit_path) = env::var("OXIDE_CONFIG_TEMPLATE") {
        let candidate = PathBuf::from(explicit_path);
        if candidate.is_file() {
            return Some(candidate);
        }
        println!(
            "cargo:warning=OXIDE_CONFIG_TEMPLATE was set but {} is not a file",
            candidate.display()
        );
        return None;
    }

    let default = root.join("config.toml.example");
    if default.is_file() {
        Some(default)
    } else {
        None
    }
}

fn copy_config_example(root: &Path) {
    println!("cargo:rerun-if-env-changed=OXIDE_CONFIG_TEMPLATE");

    let Some(template) = locate_config_template(root) else {
        println!("cargo:warning=Skipping config.toml.example copy: template not found");
        return;
    };

    if template.exists() {
        println!("cargo:rerun-if-changed={}", template.display());
    }

    let profile = env::var("PROFILE").unwrap_or_else(|_| "debug".to_owned());
    let dest_dir = root.join("ox-build").join("target").join(&profile);
    if let Err(err) = fs::create_dir_all(&dest_dir) {
        println!(
            "cargo:warning=Failed to create config destination directory {}: {}",
            dest_dir.display(),
            err
        );
        return;
    }

    let dest_path = dest_dir.join(
        template
            .file_name()
            .unwrap_or_else(|| std::ffi::OsStr::new("config.toml.example")),
    );

    if dest_path.exists() {
        // Respect existing configuration artifacts to avoid clobbering manual edits.
        return;
    }

    if let Err(err) = fs::copy(&template, &dest_path) {
        println!(
            "cargo:warning=Failed to copy {} to {}: {}",
            template.display(),
            dest_path.display(),
            err
        );
    }
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/refs");

    let manifest_dir = env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is set by Cargo");
    let root = workspace_root(&manifest_dir);

    copy_config_example(&root);

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
