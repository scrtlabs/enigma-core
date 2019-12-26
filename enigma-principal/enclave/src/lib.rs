#![crate_name = "enigma_principal_enclave"]
#![crate_type = "staticlib"]
#![no_std]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]
#![feature(slice_concat_ext)]

#![deny(unused_extern_crates)]
#![allow(unused_attributes)] // https://github.com/rust-lang/rust/issues/60050

extern crate enigma_crypto;
extern crate enigma_tools_m;
#[macro_use]
extern crate enigma_tools_t;
extern crate enigma_types;
extern crate ethabi;
extern crate ethereum_types;
#[macro_use]
extern crate lazy_static;
extern crate sgx_trts;
#[macro_use]
extern crate sgx_tstd as std;
extern crate sgx_tunittest;
extern crate sgx_types;
extern crate rustc_hex;

use enigma_tools_m::utils::EthereumAddress;
use sgx_types::{sgx_report_t, sgx_status_t, sgx_target_info_t, uint8_t};
use std::{mem, slice};

use enigma_crypto::asymmetric;
use enigma_tools_t::{esgx::ocalls_t, quote_t, storage_t};
use enigma_types::{ContractAddress, EnclaveReturn};

use crate::{epoch_keeper_t::ecall_set_worker_params_internal, keys_keeper_t::ecall_get_enc_state_keys_internal};

mod epoch_keeper_t;
mod keys_keeper_t;
lazy_static! {
    static ref SIGNING_KEY: asymmetric::KeyPair = get_sealed_keys_wrapper();
}

lazy_static! {
    static ref ETHEREUM_KEY: asymmetric::KeyPair = get_ethereum_keys_wrapper();
}


#[no_mangle]
pub extern "C" fn ecall_get_registration_quote(target_info: &sgx_target_info_t, real_report: &mut sgx_report_t) -> sgx_status_t {
    quote_t::create_report_with_data(target_info, real_report, &SIGNING_KEY.get_pubkey().address())
}

#[no_mangle]
pub extern "C" fn ecall_get_signing_address(pubkey: &mut [u8; 20]) { pubkey.copy_from_slice(&SIGNING_KEY.get_pubkey().address()); }

#[no_mangle]
pub extern "C" fn ecall_get_ethereum_address(pubkey: &mut [u8; 20]) { pubkey.copy_from_slice(&ETHEREUM_KEY.get_pubkey().address()); }

#[no_mangle]
pub unsafe extern "C" fn ecall_sign_ethereum(data: &[u8; 32], sig: &mut [u8; 65]) {
        sig.copy_from_slice(&ETHEREUM_KEY.sign_hashed(data).unwrap())
}

fn get_sealed_keys_wrapper() -> asymmetric::KeyPair {
    // Get Home path via Ocall
    let mut path_buf = ocalls_t::get_home_path().unwrap();
    // add the filename to the path: `km_keypair.sealed`,
    // in order to distinguish from core's enclave in a local build
    path_buf.push("km_keypair.sealed");
    let sealed_path = path_buf.to_str().unwrap();

    // TODO: Decide what to do if failed to obtain keys.
    match storage_t::get_sealed_keys(&sealed_path) {
        Ok(key) => key,
        Err(err) => panic!("Failed obtaining keys: {:?}", err),
    }
}

fn get_ethereum_keys_wrapper() -> asymmetric::KeyPair {
    // Get Home path via Ocall
    let mut path_buf = ocalls_t::get_home_path().unwrap();
    // add the filename to the path: `km_keypair.sealed`,
    // in order to distinguish from core's enclave in a local build
    path_buf.push("km_ethereum.sealed");
    let sealed_path = path_buf.to_str().unwrap();

    // TODO: Decide what to do if failed to obtain keys.
    match storage_t::get_sealed_keys(&sealed_path) {
        Ok(key) => key,
        Err(err) => panic!("Failed obtaining keys: {:?}", err),
    }
}

#[no_mangle]
pub unsafe extern "C" fn ecall_set_worker_params(worker_params_rlp: *const u8, worker_params_rlp_len: usize,
                                                 seed_in: &[u8; 32], nonce_in: &[u8; 32],
                                                 rand_out: &mut [u8; 32], nonce_out: &mut [u8; 32],
                                                 sig_out: &mut [u8; 65]) -> EnclaveReturn {
    // Assembling byte arrays with the RLP data
    let worker_params_rlp = slice::from_raw_parts(worker_params_rlp, worker_params_rlp_len);

    match ecall_set_worker_params_internal(worker_params_rlp, seed_in, nonce_in, rand_out, nonce_out, sig_out) {
        Ok(_) => EnclaveReturn::Success,
        Err(err) => err.into(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn ecall_get_enc_state_keys(msg: *const u8, msg_len: usize,
                                                  addrs: *const u8, addrs_len: usize, sig: &[u8; 65],
                                                  epoch_nonce: &[u8; 32], serialized_ptr: *mut u64,
                                                  sig_out: &mut [u8; 65]) -> EnclaveReturn {
    let msg_bytes = slice::from_raw_parts(msg, msg_len);
    let addrs_bytes = slice::from_raw_parts(addrs as *const ContractAddress, addrs_len / mem::size_of::<ContractAddress>()).to_vec();
    let response = match ecall_get_enc_state_keys_internal(msg_bytes, addrs_bytes, *sig, *epoch_nonce, sig_out) {
        Ok(response) => response,
        Err(err) => {
            debug_println!("get_enc_state_keys error: {:?}", err);
            return err.into();
        }
    };

    *serialized_ptr = match ocalls_t::save_to_untrusted_memory(&response) {
        Ok(ptr) => ptr,
        Err(e) => return e.into(),
    };
    EnclaveReturn::Success
}

pub mod tests {
    use sgx_tunittest::*;
    use std::{string::String, vec::Vec};

    use enigma_tools_t::{document_storage_t::tests::*, storage_t::tests::*};

    use crate::{epoch_keeper_t::tests::*, keys_keeper_t::tests::*, epoch_keeper_t::nested_encoding::tests::*};

    #[no_mangle]
    pub extern "C" fn ecall_run_tests() {
        rsgx_unit_tests!(
            test_full_sealing_storage,
            test_document_sealing_storage,
            test_get_epoch_worker_internal,
            test_state_keys_storage,
            test_create_epoch_image,
            test_u256_nested,
            test_h160_nested,
            test_vec_u256_nested,
            test_double_nested_vec_h160
        );
    }
}
