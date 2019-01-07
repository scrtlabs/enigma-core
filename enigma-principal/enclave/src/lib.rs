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
extern crate hexutil;
#[macro_use]
extern crate lazy_static;
extern crate rustc_hex as hex;
extern crate secp256k1;
extern crate serde;
#[macro_use]
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

use ethabi::{Address, Bytes, Event, EventParam, Hash, Log, ParamType, RawLog, Token, Uint};
use sgx_trts::trts::rsgx_read_rand;
use sgx_types::*;
use std::{mem, ptr, slice, str};
use std::borrow::ToOwned;
use std::cell::RefCell;
use std::collections::HashMap;
use std::prelude::v1::Box;
use std::string::ToString;
use std::sync::SgxMutex;
use std::vec::Vec;

use enigma_tools_t::common::errors_t::EnclaveError;
use enigma_tools_t::common::utils_t::{EthereumAddress, FromHex, ToHex};
use enigma_tools_t::common::utils_t::LockExpectMutex;
use enigma_tools_t::cryptography_t;
use enigma_tools_t::cryptography_t::asymmetric;
use enigma_tools_t::cryptography_t::asymmetric::KeyPair;
use enigma_tools_t::eth_tools_t::keeper_types_t::{BlockHeader, BlockHeaders, decode, Decodable, Receipt, ReceiptHashes};
use enigma_tools_t::km_primitives::MsgID;
use enigma_tools_t::quote_t;
use enigma_tools_t::storage_t;
use enigma_types::EnclaveReturn;
use enigma_types::traits::SliceCPtr;

use crate::epoch_keeper_t::{
    ecall_generate_epoch_seed_internal,
    ecall_get_verified_worker_params_internal,
    ecall_set_worker_params_internal,
};
use crate::keys_keeper_t::ecall_get_enc_state_keys_internal;

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
    match cryptography_t::get_sealed_keys(&sealed_path) {
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
pub extern "C" fn ecall_get_random_seed(rand_out: &mut [u8; 32], sig_out: &mut [u8; 65]) -> EnclaveReturn {
    match ecall_generate_epoch_seed_internal(rand_out, sig_out) {
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
    let headers_rlp = slice::from_raw_parts(headers_rlp, headers_rlp_len);
    println!("Successfully assembled RLP arguments");

    // RLP decoding the necessary data
    let receipt: Receipt = decode(receipt_rlp);
    let receipt_hashes: ReceiptHashes = decode(receipt_hashes_rlp);
    let block_headers: BlockHeaders = decode(headers_rlp);
    println!("Successfully decoded RLP objects");

    let worker_params = match ecall_get_verified_worker_params_internal(receipt, receipt_hashes, block_headers) {
        Ok(params) => params,
        Err(err) => return err.into(),
    };
    println!("Successfully verified the worker parameters in the receipt");
    match ecall_set_worker_params_internal(worker_params) {
        Ok(_) => println!("worker parameters set successfully"),
        Err(err) => return err.into(),
    };
    EnclaveReturn::Success
}

#[no_mangle]
pub unsafe extern "C" fn ecall_get_enc_state_keys(enc_msg: *const u8, enc_msg_len: usize, sig: &[u8; 65],
                                                  enc_result_out: *mut u8, enc_result_len_out: &mut usize,
                                                  sig_out: &mut [u8; 65]) -> EnclaveReturn {
    println!("Fetching the state encryption keys");
    let enc_msg_slice = slice::from_raw_parts(enc_msg, enc_msg_len);
    let enc_msg_ser = enc_msg_slice.to_vec();
    println!("The encoded message: {:?}", enc_msg_ser);
    let enc_response = match ecall_get_enc_state_keys_internal(enc_msg_ser, sig.clone()) {
        Ok(response) => response,
        Err(err) => {
            println!("got error: {:?}", err);
            return err.into();
        }
    };
    println!("The encoded response: {:?}", enc_response);
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

    #[no_mangle]
    pub extern "C" fn ecall_run_tests() {
        rsgx_unit_tests!(
            test_full_sealing_storage,
            test_signing,
            test_ecdh
        );
    }
}
