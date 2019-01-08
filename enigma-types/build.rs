// client/build.rs

extern crate cbindgen;

use cbindgen::{Config, ExportConfig, Language};
use std::env;
use std::path::PathBuf;

fn main() {
    let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();

    let package_name = env::var("CARGO_PKG_NAME").unwrap();
    let output_file = target_dir().join(format!("{}.h", package_name)).display().to_string();

    let config = Config {
        language: Language::C,
        no_includes: true,
        export: ExportConfig { include: vec!["EnclaveReturn".to_string()], ..Default::default() },
        ..Default::default()
    };

    cbindgen::generate_with_config(&crate_dir, config).unwrap().write_to_file(&output_file);
}

/// Find the location of the `target/` directory. Note that this may be
/// overridden by `cmake`, so we also need to check the `CARGO_TARGET_DIR`
/// variable.
fn target_dir() -> PathBuf {
    let mut target = PathBuf::from(env::var("OUT_DIR").unwrap());
    target.pop();
    target.pop();
    target.pop();
    target.pop();
    target.pop();

    target
}
