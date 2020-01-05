use enigma_tools_u::{self, esgx::general::storage_dir};
use sgx_types::*;
use sgx_urts::SgxEnclave;
use std::{fs, path};

static ENCLAVE_FILE: &'static str = "../bin/enclave.signed.so";
pub static ENCLAVE_DIR: &'static str = ".enigma";
pub static EPOCH_DIR: &'static str = "epoch";
pub static EPOCH_FILE: &'static str = "epoch-state.msgpack";
pub static STATE_KEYS_DIR: &'static str = "state-keys";

#[logfn(INFO)]
pub fn init_enclave_wrapper() -> SgxResult<SgxEnclave> {
    // Create folders for storage (Sealed info, epoch, etc)
    // If the storage folders are inaccessible, km wouldn't operate properly
    let storage_path = storage_dir(ENCLAVE_DIR).unwrap();
    fs::create_dir_all(&storage_path).map_err(|e| { format_err!("Unable to create the storage directory {}: {}", storage_path.display(), e) }).unwrap();
    let epoch_storage_path = storage_path.join(EPOCH_DIR);
    fs::create_dir_all(&epoch_storage_path).map_err(|e| { format_err!("Unable to create the epoch storage directory {}: {}", epoch_storage_path.display(), e) }).unwrap();
    let state_storage_path = storage_path.join(STATE_KEYS_DIR);
    fs::create_dir_all(&state_storage_path).map_err(|e| { format_err!("Unable to create the state storage directory {}: {}", state_storage_path.display(), e) }).unwrap();

    enigma_tools_u::esgx::init_enclave(&ENCLAVE_FILE)
}
