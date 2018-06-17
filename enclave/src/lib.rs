
#![crate_name = "helloworldsampleenclave"]
#![crate_type = "staticlib"]

#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]
#![cfg_attr(not(feature = "std"), feature(alloc))]

#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgx_tstd as std;
#[macro_use]
extern crate sgx_tunittest;
extern crate sgx_types;
extern crate sgx_tse;
extern crate sgx_trts;
// sealing
extern crate sgx_tseal;
extern crate sgx_rand;

#[macro_use]
extern crate lazy_static;

extern crate sputnikvm;
extern crate hexutil;
extern crate bigint;
extern crate sputnikvm_network_classic;
extern crate ring;
extern crate secp256k1;
extern crate tiny_keccak;

mod common;
mod cryptography_t;
mod storage_t;
mod quote_t;
mod evm_t;
mod ocalls_t;

use sgx_trts::*;
use sgx_types::*;
use sgx_tse::*;

use std::ptr;
use std::string::String;
use std::vec::Vec;
use std::io::{self, Write, Read};
use std::slice;
use std::str::from_utf8;
use std::string::ToString;
use std::ffi::{CString, CStr};
use std::os::raw::c_char;
use std::path;
use std::untrusted::fs::{File, remove_file};

use hexutil::read_hex;
use evm_t::call_sputnikvm;
use cryptography_t::assymetric;
use common::utils_t::{ToHex, FromHex};
use storage_t::SecretKeyStorage;

lazy_static! { static ref SIGNINING_KEY: assymetric::KeyPair = get_sealed_keys(); }


#[no_mangle]
pub extern "C" fn ecall_get_registration_quote( target_info: &sgx_target_info_t , real_report: &mut sgx_report_t,
                                       home_ptr: *const u8, home_len: usize) -> sgx_status_t {
    println!("Generating Report with: {:?}", SIGNINING_KEY.get_pubkey()[..].to_hex());
    quote_t::create_report_with_data(&target_info ,real_report,&SIGNINING_KEY.get_pubkey())
}

fn get_sealed_keys() -> assymetric::KeyPair {
    // Get Home path via Ocall
    let mut path_buf = ocalls_t::get_home_path();
    // add the filename to the path: `keypair.sealed`
    path_buf.push("keypair.sealed");
    let sealed_path = path_buf.to_str().unwrap();

    // Open the file
    match File::open(sealed_path) {
        Ok(mut file) => {
            let mut sealed:[u8;storage_t::SEAL_LOG_SIZE] = [0;storage_t::SEAL_LOG_SIZE];
            let result = file.read(&mut sealed);
            match SecretKeyStorage::unseal_key(&mut sealed) {
                // If the data is unsealed correctly return this KeyPair.
                Some(unsealed_data) => {
                    println!("Succeeded reading key from file");
                    return assymetric::KeyPair::from_slice(&unsealed_data.data);
                },
                // If the data couldn't get unsealed remove the file.
                None => {
                    println!("Failed reading file, Removing");
                    remove_file(sealed_path)
                }
            };
        },

        Err(err) => {
            if err.kind() == io::ErrorKind::PermissionDenied { panic!("No Permissions for: {}", sealed_path) }
        }
    }

    // Generate a new Keypair and seal it.
    let keypair = assymetric::KeyPair::new();
    let data = storage_t::SecretKeyStorage {version: 0x1, data: keypair.get_privkey()};
    let mut output: [u8; storage_t::SEAL_LOG_SIZE] = [0; storage_t::SEAL_LOG_SIZE];
    data.seal_key(&mut output);
    storage_t::save_sealed_key(&sealed_path, &output);
    println!("Generated a new key");

    keypair
}

#[no_mangle]
pub extern "C" fn ecall_get_signing_pubkey(pubkey: &mut [u8; 64]) {
    pubkey.clone_from_slice(&SIGNINING_KEY.get_pubkey());
}


//#[allow(unused_variables, unused_mut)]
//#[no_mangle]
//pub extern "C" fn ecall_test_sealing_storage_key() -> sgx_status_t{
//    storage_t::test_full_sealing_storage();
//    sgx_status_t::SGX_SUCCESS
//}

#[no_mangle]
pub extern "C" fn ecall_evm(code: *const u8, code_len: usize, data: *const u8, data_len: usize, output: *mut u8, vm_status: &mut u8, result_len: &mut usize) -> sgx_status_t {
    let code_slice = unsafe { slice::from_raw_parts(code, code_len) };
    let data_slice = unsafe { slice::from_raw_parts(data, data_len) };

    let code = read_hex(from_utf8(code_slice).unwrap()).unwrap();
    let data = read_hex(from_utf8(data_slice).unwrap()).unwrap();

    let mut res = call_sputnikvm(code, data);
    let mut s: &mut [u8] = &mut res.1[..];
    *result_len = s.len();

    *vm_status = res.0;
    unsafe {
        ptr::copy_nonoverlapping(s.as_ptr(), output, s.len());
    }
    sgx_status_t::SGX_SUCCESS
}

pub mod tests {
//    #[macro_use]
    extern crate sgx_tunittest;
//    #[macro_use]
    extern crate sgx_tstd as std;
    use sgx_tunittest::*;
    use std::vec::Vec;
    use std::string::String;
    use cryptography_t::assymetric::tests::*;
    use storage_t::tests::*;

    #[no_mangle]
    pub extern "C" fn ecall_run_tests() {
        rsgx_unit_tests!(
        test_full_sealing_storage,
        test_signing,
        test_ecdh
    );

    }
}
