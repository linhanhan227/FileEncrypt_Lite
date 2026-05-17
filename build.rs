use std::env;
use std::path::Path;

fn main() {
    let target = env::var("TARGET").unwrap();

    if target.contains("windows") {
        let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
        let icon_path = Path::new(&manifest_dir).join("icon.ico");

        if icon_path.exists() {
            let mut res = winres::WindowsResource::new();
            res.set_icon(icon_path.to_str().unwrap());
            res.compile().expect("Failed to compile icon resource");
            println!("cargo:rerun-if-changed=icon.ico");
        }
    }

    println!("cargo:rerun-if-changed=build.rs");
}
