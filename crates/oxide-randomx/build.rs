use std::env;
use std::path::Path;
use std::process::Command;

fn main() {
    emit_rerun_if_changed(".git/HEAD");
    emit_rerun_if_changed(".git/index");

    let git_sha = git_rev_parse();
    let git_dirty = git_is_dirty();
    let rustc_version = rustc_version();
    let beta_release_id =
        env::var("OXIDE_RANDOMX_BETA_RELEASE_ID").unwrap_or_else(|_| "local-dev".to_string());

    println!("cargo:rustc-env=OXIDE_RANDOMX_GIT_SHA={}", git_sha);
    println!(
        "cargo:rustc-env=OXIDE_RANDOMX_GIT_SHA_SHORT={}",
        git_sha_short(&git_sha)
    );
    println!("cargo:rustc-env=OXIDE_RANDOMX_GIT_DIRTY={}", git_dirty);
    println!(
        "cargo:rustc-env=OXIDE_RANDOMX_RUSTC_VERSION={}",
        rustc_version
    );
    println!(
        "cargo:rustc-env=OXIDE_RANDOMX_BETA_RELEASE_ID={}",
        beta_release_id
    );
}

fn emit_rerun_if_changed(path: &str) {
    if Path::new(path).exists() {
        println!("cargo:rerun-if-changed={path}");
    }
}

fn git_rev_parse() -> String {
    run_git(&["rev-parse", "HEAD"]).unwrap_or_else(|| "unknown".to_string())
}

fn git_is_dirty() -> String {
    match run_git(&["status", "--porcelain"]) {
        Some(output) => {
            if output.trim().is_empty() {
                "false".to_string()
            } else {
                "true".to_string()
            }
        }
        None => "unknown".to_string(),
    }
}

fn git_sha_short(full: &str) -> String {
    if full != "unknown" && full.len() >= 7 {
        full[..7].to_string()
    } else {
        full.to_string()
    }
}

fn rustc_version() -> String {
    let rustc = env::var("RUSTC").unwrap_or_else(|_| "rustc".to_string());
    match Command::new(rustc).arg("--version").output() {
        Ok(output) if output.status.success() => {
            let version = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if version.is_empty() {
                "unknown".to_string()
            } else {
                version
            }
        }
        _ => "unknown".to_string(),
    }
}

fn run_git(args: &[&str]) -> Option<String> {
    let output = Command::new("git").args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
}
