
#![crate_name = "enigmacoreenclave"]
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
extern crate enigma_tools_t;

mod evm_t;
mod ocalls_t;


//use sgx_trts::*;
use sgx_types::*;
//use sgx_tse::*;

use std::ptr;

use std::slice;
use std::str::from_utf8;

use hexutil::read_hex;
use evm_t::call_sputnikvm;

use enigma_tools_t::cryptography_t;
use enigma_tools_t::cryptography_t::asymmetric;
use enigma_tools_t::common::utils_t::{ToHex};
use enigma_tools_t::quote_t;


lazy_static! { static ref SIGNINING_KEY: asymmetric::KeyPair = get_sealed_keys_wrapper(); }


#[no_mangle]
pub extern "C" fn ecall_get_registration_quote( target_info: &sgx_target_info_t , real_report: &mut sgx_report_t) -> sgx_status_t {
    println!("Generating Report with: {:?}", SIGNINING_KEY.get_pubkey()[..].to_hex());
    quote_t::create_report_with_data(&target_info ,real_report,&SIGNINING_KEY.get_pubkey())
}

fn get_sealed_keys_wrapper() -> asymmetric::KeyPair {
    // Get Home path via Ocall
    let mut path_buf = ocalls_t::get_home_path();
    // add the filename to the path: `keypair.sealed`
    path_buf.push("keypair.sealed");
    let sealed_path = path_buf.to_str().unwrap();

    cryptography_t::get_sealed_keys(&sealed_path)
}

#[no_mangle]
pub extern "C" fn ecall_get_signing_pubkey(pubkey: &mut [u8; 64]) {
    pubkey.clone_from_slice(&SIGNINING_KEY.get_pubkey());
}

#[no_mangle]
pub extern "C" fn ecall_evm(code: *const u8, code_len: usize, data: *const u8, data_len: usize, output: *mut u8, vm_status: &mut u8, result_len: &mut usize) -> sgx_status_t {
    let code_slice = unsafe { slice::from_raw_parts(code, code_len) };
    let data_slice = unsafe { slice::from_raw_parts(data, data_len) };

    let code = read_hex(from_utf8(code_slice).unwrap()).unwrap();
    let data = read_hex(from_utf8(data_slice).unwrap()).unwrap();

    let mut res = call_sputnikvm(code, data);
    let s: &mut [u8] = &mut res.1[..];
    *result_len = s.len();

    *vm_status = res.0;
    unsafe {
        ptr::copy_nonoverlapping(s.as_ptr(), output, s.len());
    }
    sgx_status_t::SGX_SUCCESS
}

pub mod tests {
    extern crate sgx_tunittest;
    extern crate sgx_tstd as std;
    extern crate enigma_tools_t;

    use sgx_tunittest::*;
    use std::vec::Vec;
    use std::string::String;
    use enigma_tools_t::cryptography_t::asymmetric::tests::*;
    use enigma_tools_t::cryptography_t::symmetric::tests::*;
    use enigma_tools_t::storage_t::tests::*;

    // TODO: Fix the tests.
    #[no_mangle]
    pub extern "C" fn ecall_run_tests() {
        rsgx_unit_tests!(
        test_full_sealing_storage,
        test_signing,
        test_ecdh,
        test_rand_encrypt_decrypt,
        test_encryption,
        test_decryption
    );

    }
}
