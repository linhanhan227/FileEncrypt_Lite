use std::env;

#[cfg(windows)]
use std::path::Path;

#[cfg(windows)]
fn compile_windows_icon(manifest_dir: &str) {
    let icon_path = Path::new(manifest_dir).join("icon.ico");
    if !icon_path.exists() {
        return;
    }

    let mut res = winres::WindowsResource::new();
    res.set_icon(icon_path.to_str().unwrap());
    res.compile().expect("Failed to compile icon resource");
    println!("cargo:rerun-if-changed=icon.ico");
}

#[cfg(not(windows))]
fn compile_windows_icon(_manifest_dir: &str) {}

fn main() {
    let target = env::var("TARGET").unwrap_or_default();

    if target.contains("windows") {
        if let Ok(manifest_dir) = env::var("CARGO_MANIFEST_DIR") {
            compile_windows_icon(&manifest_dir);
        }
    }

    println!("cargo:rerun-if-changed=build.rs");
}
