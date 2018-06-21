
#![crate_name = "enigmacoreenclave"]
#![crate_type = "staticlib"]

#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]
#![cfg_attr(not(feature = "std"), feature(alloc))]
#![feature(slice_concat_ext)]


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

extern crate ring;


#[macro_use]
extern crate error_chain;
extern crate rustc_hex as hex;
extern crate ethabi;
extern crate rlp;
mod evm_t;
mod ocalls_t;

use sgx_types::*;

use std::ptr;
use std::str::from_utf8;
use std::slice;
use hexutil::read_hex;
use evm_t::evm::call_sputnikvm;
use enigma_tools_t::cryptography_t;
use enigma_tools_t::common;
use enigma_tools_t::cryptography_t::asymmetric;
use enigma_tools_t::common::utils_t::{ToHex};
use enigma_tools_t::quote_t;
use evm_t::abi::prepare_evm_input;
use evm_t::EvmResult;


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
pub extern "C" fn ecall_evm(bytecode: *const u8, bytecode_len: usize,
                            callable: *const u8, callable_len: usize,
                            callable_args: *const u8, callable_args_len: usize,
                            preprocessor: *const u8, preprocessor_len: usize,
                            callback: *const u8, callback_len: usize,
                            output: *mut u8, vm_status: &mut u8, result_len: &mut usize) -> sgx_status_t {

    let bytecode_slice = unsafe { slice::from_raw_parts(bytecode, bytecode_len) };
    let callable_slice = unsafe { slice::from_raw_parts(callable, callable_len) };
    let callable_args_slice = unsafe { slice::from_raw_parts(callable_args, callable_args_len) };

    let callable_args = read_hex(from_utf8(callable_args_slice).unwrap()).unwrap();
    let bytecode = read_hex(from_utf8(bytecode_slice).unwrap()).unwrap();

    let data = match  prepare_evm_input(callable_slice, &callable_args){
        Ok(v) => {
            v
        },
        Err(_e) => {
            *vm_status = EvmResult::FAULT as u8;
            return sgx_status_t::SGX_ERROR_UNEXPECTED
        },
    };

    let mut res = call_sputnikvm(bytecode, data);
    *vm_status = res.0;
    match *vm_status{
        0 => {
            let s: &mut [u8] = &mut res.1[..];
            *result_len = s.len();

            unsafe {
                ptr::copy_nonoverlapping(s.as_ptr(), output, s.len());
            }
            sgx_status_t::SGX_SUCCESS

        }
        _ => sgx_status_t::SGX_ERROR_UNEXPECTED
    }
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
