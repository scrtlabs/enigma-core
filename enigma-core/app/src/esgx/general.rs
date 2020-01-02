use enigma_tools_u::{self, esgx::general::storage_dir};
use sgx_types::*;
use sgx_urts::SgxEnclave;
use std::{fs, path};
use log;

static ENCLAVE_FILE: &'static str = "../bin/enclave.signed.so";
static ENCLAVE_TOKEN: &'static str = "enclave.token";
pub static ENCLAVE_DIR: &'static str = ".enigma";

#[logfn(INFO)]
pub fn init_enclave_wrapper() -> SgxResult<SgxEnclave> {
    // Create a folder for storage (Sealed, token, etc)
    // If the storage folder is inaccessible, the enclave would not be able to seal info
    let storage_path = storage_dir(ENCLAVE_DIR).unwrap();
    fs::create_dir_all(&storage_path).map_err(|e| { format_err!("Unable to create storage directory {}: {}", storage_path.display(), e) }).unwrap();
    let token_file: path::PathBuf = storage_path.join(ENCLAVE_TOKEN);

    enigma_tools_u::esgx::init_enclave(&token_file, &ENCLAVE_FILE)
}
