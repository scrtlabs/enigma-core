// client/build.rs

use cbindgen::Language;
use std::{env, path::{PathBuf, Path}, io::{Write, self}, fs::File};
use tempfile::NamedTempFile;

fn main() {
    let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let package_name = env::var("CARGO_PKG_NAME").unwrap();
    let output_file = target_dir().join(format!("{}.h", package_name)).display().to_string();

    cbindgen::Builder::new()
        .with_no_includes()
        .with_language(Language::C)
        .include_item("EnclaveReturn")
        .include_item("ExecuteResult")
        .include_item("Hash256")
        .include_item("StateKey")
        .include_item("ContractAddress")
        .include_item("MsgID")
        .include_item("PubKey")
        .include_item("RawPointer")
        .with_crate(&crate_dir)
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file(&output_file);

    add_header(output_file, b"#include <stdbool.h>");
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

/// This function receives a File Path and a header, it then adds the header to the top of the file.
fn add_header<P: AsRef<Path>>(file_path: P, header: &[u8]) {
    let file_path = file_path.as_ref();
    let mut original = File::open(file_path.clone()).unwrap();
    let mut temp = NamedTempFile::new_in(".").unwrap();
    temp.write_all(header).unwrap();
    temp.write(b"\n").unwrap();
    io::copy(&mut original, &mut temp).unwrap();
    drop(original);
    temp.persist(file_path).unwrap();
}