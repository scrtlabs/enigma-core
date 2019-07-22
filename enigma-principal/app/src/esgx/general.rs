use dirs;
use enigma_tools_u::{self, esgx::general::storage_dir};
use sgx_types::*;
use sgx_urts::SgxEnclave;
use std::{fs, io::Write, path};

static ENCLAVE_FILE: &'static str = "../bin/enclave.signed.so";
static ENCLAVE_TOKEN: &'static str = "enclave.token";
pub static ENCLAVE_DIR: &'static str = ".enigma";
pub static EPOCH_DIR: &'static str = "epoch";
pub static EPOCH_FILE: &'static str = "epoch-state.msgpack";
pub static STATE_KEYS_DIR: &'static str = "state-keys";

#[logfn(INFO)]
pub fn init_enclave_wrapper() -> SgxResult<SgxEnclave> {
    // Step 1: try to retrieve the launch token saved by last transaction
    //         if there is no token, then create a new one.
    //
    // try to get the token saved in $HOME */
    // let mut home_dir = path::PathBuf::new();
    let use_token = match dirs::home_dir() {
        Some(path) => {
            println!("[+] Home dir is {}", path.display());
            // home_dir = path;
            true
        }
        None => {
            println!("[-] Cannot get home dir");
            false
        }
    };

    // Step : try to create a .enigma folder for storing all the files
    // Create a directory, returns `io::Result<()>`
    // let storage_path = home_dir.join(ENCLAVE_DIR);
    let storage_path = storage_dir(ENCLAVE_DIR).unwrap();
    match fs::create_dir(&storage_path) {
        Err(why) => {
            println!("[-] Create .enigma folder => {:?}", why.kind());
        }
        Ok(_) => {
            println!("[+] Created new .enigma folder => {:?}", storage_path);
        }
    };
    match fs::create_dir(&storage_path.join(EPOCH_DIR)) {
        Err(why) => {
            println!("[-] Create .enigma/epoch folder => {:?}", why.kind());
        }
        Ok(_) => {
            println!("[+] Created new .enigma/epoch folder => {:?}", storage_path);
        }
    };
    match fs::create_dir(&storage_path.join(STATE_KEYS_DIR)) {
        Err(why) => {
            println!("[-] Create .enigma/state-keys folder => {:?}", why.kind());
        }
        Ok(_) => {
            println!("[+] Created new .enigma/state-keys folder => {:?}", storage_path);
        }
    };
    // Create the home/dir/.enigma folder for storage (Sealed, token , etc )
    let token_file: path::PathBuf = storage_path.join(ENCLAVE_TOKEN);

    let (enclave, launch_token) = enigma_tools_u::esgx::init_enclave(&token_file, use_token, &ENCLAVE_FILE)?;
    // Step 3: save the launch token if it is updated
    if use_token && launch_token.is_some() {
        // reopen the file with write capability
        match fs::File::create(&token_file) {
            Ok(mut f) => match f.write_all(&launch_token.unwrap()) {
                Ok(_) => println!("[+] Saved updated launch token!"),
                Err(_) => println!("[-] Failed to save updated launch token!"),
            },
            Err(_) => {
                println!("[-] Failed to save updated enclave token, but doesn't matter");
            }
        }
    }
    Ok(enclave)
}
