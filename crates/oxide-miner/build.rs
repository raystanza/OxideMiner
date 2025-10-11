use std::env;
use std::fs;
use std::io;
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

/// Recursively copy a directory tree using only std.
fn copy_dir_recursive(src: &Path, dst: &Path) -> io::Result<()> {
    if !dst.exists() {
        fs::create_dir_all(dst)?;
    }
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        let to = dst.join(entry.file_name());
        if ty.is_dir() {
            copy_dir_recursive(&entry.path(), &to)?;
        } else if ty.is_file() {
            if let Some(parent) = to.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::copy(entry.path(), &to)?;
        }
    }
    Ok(())
}

/// Emit rerun-if-changed for every file under a directory.
fn emit_rerun_for_dir(dir: &Path) -> io::Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let ty = entry.file_type()?;
        if ty.is_dir() {
            emit_rerun_for_dir(&path)?;
        } else if ty.is_file() {
            println!("cargo:rerun-if-changed={}", path.display());
        }
    }
    Ok(())
}

/// Copy workspace-level `scripts/` into the active target profile dir.
fn copy_scripts_to_target_profile() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    // crates/oxide-miner -> crates -> (workspace root)
    let workspace_root = manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .unwrap_or(&manifest_dir)
        .to_path_buf();

    let scripts_src = workspace_root.join("scripts");
    if !scripts_src.exists() {
        println!(
            "cargo:warning=scripts/ not found at {}",
            scripts_src.display()
        );
        return;
    }

    // Watch for changes in scripts/
    if let Err(e) = emit_rerun_for_dir(&scripts_src) {
        println!("cargo:warning=Failed to register rerun-if-changed for scripts/: {e}");
    }

    // OUT_DIR looks like:
    //   target/[<triple>/]<profile>/build/<pkg-hash>/out
    // profile_dir is: target/[<triple>/]<profile>
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let profile_dir = out_dir
        .ancestors()
        .nth(3) // out -> <pkg-hash> -> build -> <profile>
        .unwrap()
        .to_path_buf();

    // Primary destination (always exists)
    let dst_primary = profile_dir.join("scripts");

    // Optional secondary destination if binaries are in target/<profile> (no triple)
    // When profile_dir includes a triple (target/<triple>/<profile>), also mirror to target/<profile> if it exists.
    let dst_secondary = profile_dir
        .parent() // target/<triple>
        .and_then(|p| p.parent()) // target
        .map(|target_root| target_root.join(env::var("PROFILE").unwrap()));

    // Copy to primary
    if let Err(e) = fs::remove_dir_all(&dst_primary) {
        // ignore missing dir; report other errors
        if e.kind() != io::ErrorKind::NotFound {
            println!(
                "cargo:warning=Failed to clean {}: {e}",
                dst_primary.display()
            );
        }
    }
    match copy_dir_recursive(&scripts_src, &dst_primary) {
        Ok(_) => println!("cargo:warning=Copied scripts/ -> {}", dst_primary.display()),
        Err(e) => println!(
            "cargo:warning=Failed to copy scripts/ -> {}: {e}",
            dst_primary.display()
        ),
    }

    // Copy to secondary (if that directory exists)
    if let Some(profile_no_triple) = dst_secondary {
        if profile_no_triple.exists() {
            let dst2 = profile_no_triple.join("scripts");
            if let Err(e) = fs::remove_dir_all(&dst2) {
                if e.kind() != io::ErrorKind::NotFound {
                    println!("cargo:warning=Failed to clean {}: {e}", dst2.display());
                }
            }
            match copy_dir_recursive(&scripts_src, &dst2) {
                Ok(_) => println!("cargo:warning=Copied scripts/ -> {}", dst2.display()),
                Err(e) => println!(
                    "cargo:warning=Failed to copy scripts/ -> {}: {e}",
                    dst2.display()
                ),
            }
        }
    }

    // React to env changes too
    println!("cargo:rerun-if-env-changed=CARGO_TARGET_DIR");
    println!("cargo:rerun-if-env-changed=PROFILE");
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

    copy_scripts_to_target_profile();
}
