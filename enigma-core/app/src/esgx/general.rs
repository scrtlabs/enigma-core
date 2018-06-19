use sgx_types::*;
use sgx_urts::SgxEnclave;
use std::io::{Read, Write};
use std::fs;
use std::path;
use std::env;
//use std::slice;
//use std::io;
use std::ptr;

static ENCLAVE_FILE: &'static str = "../bin/enclave.signed.so";
static ENCLAVE_TOKEN: &'static str = "enclave.token";
pub static ENCLAVE_DIR: &'static str = ".enigma";


#[no_mangle]
pub extern "C" fn ocall_get_home(output: *mut u8, result_len: &mut usize) {
    let path = storage_dir();
    let path_str = path.to_str().unwrap();
    unsafe { ptr::copy_nonoverlapping(path_str.as_ptr(), output, path_str.len()); }
    *result_len = path_str.len();
}

pub fn storage_dir()-> path::PathBuf{
    let mut home_dir = path::PathBuf::new();
    match env::home_dir() {
        Some(path) => {
            println!("[+] Home dir is {}", path.display());
            home_dir = path;
            true
        },
        None => {
            println!("[-] Cannot get home dir");
            false
        }
    };
     home_dir.join(ENCLAVE_DIR)
}
pub fn init_enclave() -> SgxResult<SgxEnclave> {
    let mut launch_token: sgx_launch_token_t = [0; 1024];
    let mut launch_token_updated: i32 = 0;
    // Step 1: try to retrieve the launch token saved by last transaction 
    //         if there is no token, then create a new one.
    // 
    // try to get the token saved in $HOME */
    //let mut home_dir = path::PathBuf::new();
    let use_token = match env::home_dir() {
        Some(path) => {
            println!("[+] Home dir is {}", path.display());
            //home_dir = path;
            true
        },
        None => {
            println!("[-] Cannot get home dir");
            false
        }
    };

    // Step : try to create a .enigma folder for storing all the files 
    // Create a directory, returns `io::Result<()>`
    //let storage_path = home_dir.join(ENCLAVE_DIR);    
    let storage_path = storage_dir();
    match fs::create_dir(&storage_path) {
        Err(why) => {
            println!("[-] Create .enigma folder => {:?}", why.kind());
        },
        Ok(_) => {
            println!("[+] Created new .enigma folder => {:?}", storage_path);
        },
    };
    // Create the home/dir/.enigma folder for storage (Sealed, token , etc )
    let token_file: path::PathBuf = storage_path.join(ENCLAVE_TOKEN);;
    if use_token == true {
        match fs::File::open(&token_file) {
            Err(_) => {
                println!("[-] Open token file {} error! Will create one.", token_file.as_path().to_str().unwrap());
            },
            Ok(mut f) => {
                println!("[+] Open token file success! ");
                match f.read(&mut launch_token) {
                    Ok(1024) => {
                        println!("[+] Token file valid!");
                    },
                    _ => println!("[+] Token file invalid, will create new token file"),
                }
            }
        }
    }
    // Step 2: call sgx_create_enclave to initialize an enclave instance
    // Debug Support: set 2nd parameter to 1 
    let debug = 1;
    let mut misc_attr = sgx_misc_attribute_t {secs_attr: sgx_attributes_t { flags:0, xfrm:0}, misc_select:0};
    let enclave = SgxEnclave::create(ENCLAVE_FILE,
                                          debug, 
                                          &mut launch_token,
                                          &mut launch_token_updated,
                                          &mut misc_attr)?;
    
    // Step 3: save the launch token if it is updated 
    if use_token == true && launch_token_updated != 0 {
        // reopen the file with write capablity 
        match fs::File::create(&token_file) {
            Ok(mut f) => {
                match f.write_all(&launch_token) {
                    Ok(()) => println!("[+] Saved updated launch token!"),
                    Err(_) => println!("[-] Failed to save updated launch token!"),
                }
            },
            Err(_) => {
                println!("[-] Failed to save updated enclave token, but doesn't matter");
            },
        }
    }
    Ok(enclave)
}