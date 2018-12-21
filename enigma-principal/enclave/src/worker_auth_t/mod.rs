use ethabi::{Address, Bytes, decode, encode, Event, EventParam, FixedBytes, Hash, Log, ParamType, RawLog, Token, Uint};
use ethabi::token::{LenientTokenizer, Tokenizer};
use hexutil;
use serde::{Deserialize, Serialize};
use sgx_trts::trts::rsgx_read_rand;
use sgx_types::*;
use std::{mem, ptr, slice, str};
use std::borrow::ToOwned;
use std::cell::RefCell;
use std::collections::HashMap;
use std::panic;
use std::prelude::v1::Box;
use std::string::String;
use std::string::ToString;
use std::sync::SgxMutex;
use std::vec::Vec;

use enigma_tools_t::common::errors_t::EnclaveError;
use enigma_tools_t::common::utils_t::LockExpectMutex;
use enigma_tools_t::eth_tools_t::epoch_t::{Epoch, WorkerParams};

use crate::SIGNINING_KEY;

const INIT_NONCE: uint32_t = 0;

// The epoch seed contains the seeds + a nonce that must match the Ethereum tx
// TODO: Seal / unseal
lazy_static! { pub static ref EPOCH: SgxMutex< HashMap<Uint, Epoch >> = SgxMutex::new(HashMap::new()); }

pub(crate) fn ecall_generate_epoch_seed_internal(rand_out: &mut [u8; 32], sig_out: &mut [u8; 65]) -> Result<Uint, EnclaveError> {
    let mut guard = EPOCH.lock_expect("Epoch");
    let nonce: Uint;
    if guard.is_empty() {
        nonce = Uint::from(INIT_NONCE);
    } else {
        match guard.keys().max() {
            Some(n) => nonce = n.clone() + 1,
            None => {
                panic!("Fatal error! Cannot get max nonce from non-empty mutex.");
            }
        }
    }
    // TODO: Check if needs to check the random is within the curve.
    rsgx_read_rand(&mut rand_out[..])?;

    let sig = SIGNINING_KEY.sign(&rand_out[..])?;
    sig_out.copy_from_slice(&sig[..]);

    let seed_token = Token::Uint(rand_out[..].into());
    println!("The random seed token: {:?}", seed_token);
    let seed = seed_token.to_uint().unwrap();

    let epoch = Epoch { seed, worker_params: None };
    // TODO: catch error
    guard.insert(nonce, epoch);
    // EnclaveError::WorkerAuthError { err: format!("Cannot insert data for epoch nonce: {:?}", nonce) }
    println!("Random inside Enclave: {:?}", hexutil::to_hex(&rand_out[..]));
    Ok(nonce)
}

pub(crate) fn ecall_get_verified_log_internal(receipt_tokens: Vec<Token>, receipt_hashes: Vec<Hash>,
                                              block_header_tokens: Vec<Token>) -> Result<(Uint, RawLog), EnclaveError> {
    let mut epoch_guard = EPOCH.lock_expect("Epoch");
    let nonce: Uint = match epoch_guard.keys().max() {
        Some(n) => n.clone(),
        None => {
            return Err(EnclaveError::WorkerAuthError {
                err: "Cannot verify receipt without a nonce in the Epoch mutex.".to_string(),
            });
        }
    };
    println!("Verifying receipt for epoch nonce: {:?}", nonce);

    println!("Creating log from receipt tokens: {:?}", receipt_tokens);
    // TODO: add error handling for token conversion
    // TODO: merkle up the receipt root
    // To validate tries: https://github.com/paritytech/parity-common/tree/master/triehash
    // TODO: verify hash of the block header
    // TODO: verify the linkage between the block header and last verified block
    let address = receipt_tokens[0].clone().to_address().unwrap();
    let topic_tokens = receipt_tokens[1].clone().to_array().unwrap();
    let topics: Vec<Hash> = topic_tokens.into_iter().map(|t| Hash::from(t.to_uint().unwrap())).collect();
    let data: Bytes = receipt_tokens[2].clone().to_bytes().unwrap();
    Ok((nonce, RawLog { topics, data }))
}

pub(crate) fn ecall_set_worker_params_internal(nonce: Uint, raw_log: RawLog) -> Result<(), EnclaveError> {
    let mut params_guard = EPOCH.lock_expect("Epoch");
    let epoch = match params_guard.get_mut(&nonce) {
        Some(value) => value,
        None => {
            return Err(EnclaveError::WorkerAuthError {
                err: "Cannot set the workers parameters without a nonce in the Epoch mutex.".to_string(),
            });
        }
    };
    epoch.set_worker_params(raw_log)?;
    println!("Worker parameters set for nonce: {:?} => {:?}", nonce, epoch);
    Ok(())
}

pub(crate) fn ecall_get_epoch_workers_internal(sc_addr: Address, block_number: Option<Uint>) -> Result<(Vec<Address>), EnclaveError> {
    let mut epoch_guard = EPOCH.lock_expect("Epoch");
    let epoch: Epoch;
    if block_number.is_none() {
        let nonce: Uint = match epoch_guard.keys().max() {
            Some(n) => n.clone(),
            None => {
                return Err(EnclaveError::WorkerAuthError {
                    err: "Cannot verify receipt without a nonce in the Epoch mutex.".to_string(),
                });
            }
        };
        // Since we just got the key from the make, we know that the key will resolve
        epoch = epoch_guard.get(&nonce).unwrap().clone();
    } else {
        return Err(EnclaveError::WorkerAuthError {
            err: "Epoch lookup by block number not implemented.".to_string(),
        });
    }
    println!("Running worker selection using Epoch: {:?}", epoch);
    let workers = epoch.get_selected_workers(sc_addr)?;
    Ok(workers)
}
