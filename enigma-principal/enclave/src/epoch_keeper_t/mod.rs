use ethabi::{Address, Bytes, decode, encode, Event, EventParam, FixedBytes, Hash, ParamType, RawLog, Token, Uint};
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
use core::convert::TryFrom;

use enigma_tools_t::common::errors_t::EnclaveError;
use enigma_tools_t::common::utils_t::LockExpectMutex;
use enigma_tools_t::eth_tools_t::epoch_t::{Epoch, WorkerParams};
use enigma_tools_t::eth_tools_t::keeper_types_t::{ReceiptHashes, Receipt, BlockHeader, BlockHeaders, Log};
use enigma_tools_t::eth_tools_t::verifier_t::{verify_block_chain, verify_receipt};
use ethereum_types::H256;

use crate::SIGNINING_KEY;

const INIT_NONCE: uint32_t = 0;
const PREVERIFIED_BLOCK_HASH: &str = "0xae67b813aa89d47d4ba4d34dcd8b77a57bd433338ac0980137f5a6ca81ff9566";

// The epoch seed contains the seeds + a nonce that must match the Ethereum tx
// TODO: Seal / unseal
lazy_static! { pub static ref EPOCH: SgxMutex< HashMap<Uint, Epoch >> = SgxMutex::new(HashMap::new()); }

fn get_epoch(block_number: Option<Uint>) -> Result<Option<Epoch>, EnclaveError> {
    if block_number.is_some() {
        return Err(EnclaveError::WorkerAuthError {
            err: "Epoch lookup by block number not implemented.".to_string(),
        });
    }
    let mut epoch_guard = EPOCH.lock_expect("Epoch");
    let nonce: Uint = match epoch_guard.keys().max() {
        Some(n) => n.clone(),
        None => {
            return Ok(None);
        }
    };
    // Since we just got the key from the make, we know that the key will resolve
    let epoch: Epoch = epoch_guard.get(&nonce).unwrap().clone();
    Ok(Some(epoch))
}

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
    let seed = seed_token.to_uint().unwrap();

    // If no stored epoch, use the hardcoded preverified block hash
    // Otherwise, use the block hash verified in the previous epoch
    let epoch = match get_epoch(None)? {
        Some(epoch) => Epoch {
            seed,
            worker_params: None,
            preverified_block_hash: epoch.preverified_block_hash.clone(),
        },
        None => Epoch {
            seed,
            worker_params: None,
            preverified_block_hash: H256(LenientTokenizer::tokenize_uint(PREVERIFIED_BLOCK_HASH).unwrap()),
        },
    };
    match guard.insert(nonce, epoch) {
        Some(_) => println!("New epoch stored successfully"),
        None => {
            return Err(EnclaveError::WorkerAuthError {
                err: format!("Unable to store new Epoch"),
            });
        }
    }
    Ok(nonce)
}

pub(crate) fn ecall_get_verified_worker_params_internal(receipt: Receipt, receipt_hashes: ReceiptHashes,
                                                        block_headers: BlockHeaders) -> Result<WorkerParams, EnclaveError> {
    // TODO: is cloning the whole Vec necessary here?
    let block_headers_raw = block_headers.0.clone();
    let block_header: &BlockHeader = match block_headers_raw.get(0) {
        Some(block_header) => block_header,
        None => {
            return Err(EnclaveError::WorkerAuthError {
                err: "The BlockHeaders parameter is empty.".to_string(),
            });
        }
    };
    let epoch = match get_epoch(None)? {
        Some(epoch) => epoch,
        None => {
            return Err(EnclaveError::WorkerAuthError {
                err: "No Epoch found in storage.".to_string(),
            });
        }
    };
    verify_block_chain(epoch.preverified_block_hash, block_headers)?;
    verify_receipt(block_header.clone(), receipt.clone(), receipt_hashes)?;

    let mut epoch_guard = EPOCH.lock_expect("Epoch");
    let nonce: Uint = match epoch_guard.keys().max() {
        Some(n) => n.clone(),
        None => {
            return Err(EnclaveError::WorkerAuthError {
                err: "Cannot verify receipt without a nonce in the Epoch mutex.".to_string(),
            });
        }
    };
    println!("Verifying receipt for epoch nonce: {:?}...", nonce);
    let params: WorkerParams = WorkerParams::try_from(receipt.logs[0].clone())?;
    // TODO: verify the nonce against the receipt
    println!("Against the worker parameters: {:?}", params);

    Ok(params)
}

pub(crate) fn ecall_set_worker_params_internal(params: WorkerParams) -> Result<(), EnclaveError> {
    // TODO: Get the nonce from the worker params
    let nonce = Uint::from(1);
    let mut epoch_guard = EPOCH.lock_expect("Epoch");
    let epoch = match epoch_guard.get_mut(&nonce) {
        Some(value) => value,
        None => {
            return Err(EnclaveError::WorkerAuthError {
                err: "Cannot set the workers parameters without a nonce in the Epoch mutex.".to_string(),
            });
        }
    };
    epoch.set_worker_params(params)?;
    Ok(())
}

pub(crate) fn ecall_get_epoch_workers_internal(sc_addr: Address, block_number: Option<Uint>) -> Result<(Vec<Address>), EnclaveError> {
    let epoch = match get_epoch(block_number)? {
        Some(epoch) => epoch,
        None => {
            return Err(EnclaveError::WorkerAuthError {
                err: "Cannot verify receipt without a nonce in the Epoch mutex.".to_string(),
            });
        }
    };
    println!("Running worker selection using Epoch: {:?}", epoch);
    let workers = epoch.get_selected_workers(sc_addr)?;
    Ok(workers)
}
