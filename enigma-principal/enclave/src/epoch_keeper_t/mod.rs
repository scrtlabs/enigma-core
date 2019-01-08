use core::convert::TryFrom;

use ethabi::{Address, Bytes, encode, Event, EventParam, FixedBytes, Hash, ParamType, RawLog, Token, Uint};
use ethabi::token::{LenientTokenizer, Tokenizer};
use ethereum_types::H256;
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
use std::sync::SgxMutexGuard;
use std::collections::hash_map::RandomState;
use std::vec::Vec;

use enigma_tools_t::common::errors_t::EnclaveError;
use enigma_tools_t::common::utils_t::LockExpectMutex;
use enigma_tools_t::eth_tools_t::epoch_t::{Epoch, WorkerParams};
use enigma_tools_t::eth_tools_t::keeper_types_t::{BlockHeader, BlockHeaders, Log, Receipt, ReceiptHashes, decode};
use enigma_tools_t::eth_tools_t::verifier_t::BlockVerifier;

use crate::SIGNINING_KEY;

const INIT_NONCE: uint32_t = 0;
const PREVERIFIED_BLOCK_HASH: &str = "ae67b813aa89d47d4ba4d34dcd8b77a57bd433338ac0980137f5a6ca81ff9566";

// The epoch seed contains the seeds + a nonce that must match the Ethereum tx
// TODO: Seal / unseal
lazy_static! { pub static ref EPOCH: SgxMutex< HashMap<Uint, Epoch >> = SgxMutex::new(HashMap::new()); }

fn get_max_nonce(guard: &SgxMutexGuard<HashMap<Uint, Epoch, RandomState>>) -> Uint {
    guard.keys().max().unwrap().clone()
}

fn get_epoch(guard: &SgxMutexGuard<HashMap<Uint, Epoch, RandomState>>, block_number: Option<Uint>) -> Result<Option<Epoch>, EnclaveError> {
    println!("Getting epoch for block number: {:?}", block_number);
    if block_number.is_some() {
        return Err(EnclaveError::WorkerAuthError {
            err: "Epoch lookup by block number not implemented.".to_string(),
        });
    }
    if guard.is_empty() {
        println!("Epoch not found");
        return Ok(None);
    }
    let nonce = get_max_nonce(&guard);
    let epoch: Epoch = guard.get(&nonce).unwrap().clone();
    Ok(Some(epoch))
}

pub(crate) fn ecall_generate_epoch_seed_internal(rand_out: &mut [u8; 32], nonce_out: &mut [u8; 32], sig_out: &mut [u8; 65]) -> Result<Uint, EnclaveError> {
    let mut guard = EPOCH.lock_expect("Epoch");
    let epoch = get_epoch(&guard, None)?;
    let nonce: Uint = match epoch {
        Some(_) => guard.keys().max().unwrap() + 1,
        None => Uint::from(INIT_NONCE),
    };
    println!("Got nonce {:?}, generating number", nonce);
    let nonce_bytes: [u8; 32] = nonce.into();
    nonce_out.copy_from_slice(&nonce_bytes[..]);

    // TODO: Check if needs to check the random is within the curve.
    rsgx_read_rand(&mut rand_out[..])?;
    let sig = SIGNINING_KEY.sign(&rand_out[..])?;
    sig_out.copy_from_slice(&sig[..]);
    let seed_token = Token::Uint(rand_out[..].into());
    let seed = seed_token.to_uint().unwrap();

    // If no stored epoch, use the hardcoded preverified block hash
    // Otherwise, use the block hash verified in the previous epoch
    let new_epoch = match epoch {
        Some(epoch) => {
            println!("Epoch found: {:?}", epoch);
            Epoch {
                seed,
                worker_params: None,
                preverified_block_hash: epoch.preverified_block_hash.clone(),
            }
        }
        None => {
            let init_block_hash = H256(LenientTokenizer::tokenize_uint(PREVERIFIED_BLOCK_HASH).unwrap());
            println!("Epoch not found, using hardcoded block hash: {:?}", init_block_hash);
            Epoch {
                seed,
                worker_params: None,
                preverified_block_hash: init_block_hash,
            }
        }
    };
    println!("Storing epoch: {:?}", new_epoch);
    match guard.insert(nonce, new_epoch) {
        Some(prev) => println!("New epoch stored successfully, previous epoch: {:?}", prev),
        None => println!("Initial epoch stored successfully"),
    }
    Ok(nonce)
}

pub(crate) fn ecall_set_worker_params_internal(receipt_rlp: &[u8], receipt_hashes_rlp: &[u8],
                                               block_headers_rlp: &[u8], sig_out: &mut [u8; 65]) -> Result<(), EnclaveError> {
    // RLP decoding the necessary data
    let receipt: Receipt = decode(receipt_rlp);
    let receipt_hashes: ReceiptHashes = decode(receipt_hashes_rlp);
    let block_headers: BlockHeaders = decode(block_headers_rlp);

    println!("Successfully decoded RLP objects");
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
    let mut guard = EPOCH.lock_expect("Epoch");
    if guard.is_empty() {
        return Err(EnclaveError::WorkerAuthError {
            err: format!("The Epoch store is empty."),
        });
    }
    let nonce = get_max_nonce(&guard);
    let epoch = match guard.get_mut(&nonce) {
        Some(value) => value,
        None => {
            return Err(EnclaveError::WorkerAuthError {
                err: format!("Epoch not found for WorkerParams nonce: {:?}", nonce),
            });
        }
    };
    // TODO: Implement verifier
//    let mut verifier = BlockVerifier::new(epoch.preverified_block_hash);
//    for header in block_headers.0 {
//        verifier.add_block(header.clone())?;
//    }
//    verifier.verify_receipt(receipt.clone(), receipt_hashes)?;

    let params: WorkerParams = WorkerParams::try_from(receipt.logs[0].clone())?;
    epoch.set_worker_params(params)?;
    // TODO: Replace the preverified block hash of the epoch with last block header
    let sig = SIGNINING_KEY.sign(&receipt_rlp[..])?;
    sig_out.copy_from_slice(&sig[..]);
    Ok(())
}

pub(crate) fn ecall_get_epoch_workers_internal(sc_addr: Address, block_number: Option<Uint>) -> Result<(Vec<Address>), EnclaveError> {
    let guard = EPOCH.lock_expect("Epoch");
    let epoch = match get_epoch(&guard, block_number)? {
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
