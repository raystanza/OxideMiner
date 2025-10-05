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

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/refs");

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
