#![crate_name = "enigma_principal_enclave"]
#![crate_type = "staticlib"]
#![no_std]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]
#![cfg_attr(not(feature = "std"), feature(alloc))]
#![feature(tool_lints)]
#![feature(try_from)]

extern crate enigma_tools_t;
extern crate enigma_types;
extern crate ethabi;
extern crate ethereum_types;
extern crate hexutil;
#[macro_use]
extern crate lazy_static;
extern crate rustc_hex as hex;
extern crate secp256k1;
extern crate serde;
extern crate serde_derive;
extern crate serde_json;
extern crate sgx_rand;
extern crate sgx_trts;
extern crate sgx_tse;
extern crate sgx_tseal;
//#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgx_tstd as std;
extern crate sgx_tunittest;
extern crate sgx_types;

use sgx_types::*;
use std::slice;
extern crate enigma_crypto;

use enigma_tools_t::common::utils_t::EthereumAddress;
use enigma_crypto::asymmetric;
use enigma_tools_t::quote_t;
use enigma_types::{EnclaveReturn, traits::SliceCPtr};

use crate::epoch_keeper_t::{
    ecall_generate_epoch_seed_internal,
    ecall_set_worker_params_internal,
};
use crate::keys_keeper_t::ecall_get_enc_state_keys_internal;
use std::ptr;

mod ocalls_t;
mod epoch_keeper_t;
mod keys_keeper_t;

lazy_static! { static ref SIGNINING_KEY: asymmetric::KeyPair = get_sealed_keys_wrapper(); }


#[no_mangle]
pub extern "C" fn ecall_get_registration_quote(target_info: &sgx_target_info_t, real_report: &mut sgx_report_t) -> sgx_status_t {
    quote_t::create_report_with_data(&target_info, real_report, &SIGNINING_KEY.get_pubkey().address().as_bytes())
}

fn get_sealed_keys_wrapper() -> asymmetric::KeyPair {
    // Get Home path via Ocall
    let mut path_buf = ocalls_t::get_home_path();
    // add the filename to the path: `keypair.sealed`
    path_buf.push("keypair.sealed");
    let sealed_path = path_buf.to_str().unwrap();

    // TODO: Decide what to do if failed to obtain keys.
    match storage_t::get_sealed_keys(&sealed_path) {
        Ok(key) => return key,
        Err(err) => panic!("Failed obtaining keys: {:?}", err)
    };
}

#[no_mangle]
pub extern "C" fn ecall_get_signing_address(pubkey: &mut [u8; 42]) {
    pubkey.clone_from_slice(SIGNINING_KEY.get_pubkey().address().as_bytes());
}


/// This is an ecall function that returns a signed seed and a signature.
/// Use this from outside of the enclave
/// # Examples
/// ```
/// extern { fn ecall_get_random_seed(eid: sgx_enclave_id_t, retval: &mut sgx_status_t, rand_out: &mut [u8; 32], sig_out: &mut [u8; 65]) -> sgx_status_t; }
/// let enclave = esgx::general::init_enclave.unwrap();
/// let mut rand_out: [u8; 32] = [0; 32];
/// let mut sig_out: [u8; 65] = [0; 65];
/// let mut retval = sgx_status_t::default();
/// unsafe { ecall_get_random_seed(enclave.geteid(), &mut retval, &mut rand_out, &mut sig_out); }
/// ```
#[no_mangle]
pub extern "C" fn ecall_generate_epoch_seed(rand_out: &mut [u8; 32], nonce_out: &mut [u8; 32], sig_out: &mut [u8; 65]) -> EnclaveReturn {
    match ecall_generate_epoch_seed_internal(rand_out, nonce_out, sig_out) {
        Ok(nonce) => println!("the new epoch nonce: {:?}", nonce),
        Err(err) => return err.into(),
    }
    EnclaveReturn::Success
}

#[no_mangle]
pub unsafe extern "C" fn ecall_set_worker_params(receipt_rlp: *const u8, receipt_rlp_len: usize,
                                                 receipt_hashes_rlp: *const u8, receipt_hashes_rlp_len: usize,
                                                 headers_rlp: *const u8, headers_rlp_len: usize,
                                                 sig_out: &mut [u8; 65]) -> EnclaveReturn {
    // Assembling byte arrays with the RLP data
    let receipt_rlp = slice::from_raw_parts(receipt_rlp, receipt_rlp_len);
    let receipt_hashes_rlp = slice::from_raw_parts(receipt_hashes_rlp, receipt_hashes_rlp_len);
    let block_headers_rlp = slice::from_raw_parts(headers_rlp, headers_rlp_len);

    match ecall_set_worker_params_internal(receipt_rlp, receipt_hashes_rlp, block_headers_rlp, sig_out) {
        Ok(_) => println!("Worker parameters set successfully"),
        Err(err) => return err.into(),
    };
    EnclaveReturn::Success
}

#[no_mangle]
pub unsafe extern "C" fn ecall_get_enc_state_keys(msg: *const u8, msg_len: usize, sig: &[u8; 65],
                                                  enc_response_out: *mut u8, enc_response_len: &mut usize,
                                                  pubkey_out: &mut [u8; 64],
                                                  sig_out: &mut [u8; 65]) -> EnclaveReturn {
    let msg_bytes = slice::from_raw_parts(msg, msg_len).to_vec();
    let response = match ecall_get_enc_state_keys_internal(msg_bytes, sig.clone(), sig_out, pubkey_out) {
        Ok(response) => response,
        Err(err) => return err.into(),
    };
    // std magic
    ptr::copy_nonoverlapping(response.as_c_ptr(), enc_response_out, response.len());
    *enc_response_len = response.len();
    EnclaveReturn::Success
}

pub mod tests {
    extern crate sgx_tunittest;
    extern crate sgx_tstd as std;
    extern crate enigma_tools_t;

    use sgx_tunittest::*;
    use std::string::String;
    use std::vec::Vec;

    use enigma_tools_t::cryptography_t::asymmetric::tests::*;
    use enigma_tools_t::storage_t::tests::*;
    use enigma_tools_t::document_storage_t::tests::*;
    use crate::epoch_keeper_t::tests::*;
    use crate::keys_keeper_t::tests::*;

    #[no_mangle]
    pub extern "C" fn ecall_run_tests() {
        rsgx_unit_tests!(
            test_full_sealing_storage,
            test_document_sealing_storage,
            test_signing,
            test_ecdh,
            test_get_epoch_workers_internal,
            test_state_keys_storage
        );
    }
}
