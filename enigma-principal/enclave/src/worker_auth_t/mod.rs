use crate::SIGNINING_KEY;

use sgx_types::*;
use sgx_trts::trts::rsgx_read_rand;
use std::sync::SgxMutex;

use std::string::ToString;
use std::vec::Vec;
use std::{ptr, slice, str, mem};
use std::cell::RefCell;
use std::borrow::ToOwned;
use std::collections::HashMap;
use ethabi::{Hash, Bytes, RawLog, Token, EventParam, ParamType, Event, Address, Uint, Log, FixedBytes, encode, decode};
use ethabi::token::{LenientTokenizer, Tokenizer};
use enigma_tools_t::common::errors_t::EnclaveError;
use enigma_tools_t::common::utils_t::LockExpectMutex;
use std::string::String;
use std::prelude::v1::Box;
use std::panic;
use hexutil;
use serde::{Deserialize, Serialize};

const INIT_NONCE: uint32_t = 0;

#[derive(Debug, Clone)]
pub struct WorkerParams {
    block_number: Uint,
    workers: Vec<Address>,
    balances: Vec<Uint>,
}

// TODO: Write serializer/deserializer using the Token module to encode ABI types to bytes
#[derive(Debug, Clone)]
pub struct Epoch {
    seed: Uint,
    worker_params: Option<WorkerParams>,
}
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
    // TODO: verify hash of the block header
    // TODO: verify the linkage between the block header and last verified block
    let address = receipt_tokens[0].clone().to_address().unwrap();
    let topic_tokens = receipt_tokens[1].clone().to_array().unwrap();
    let topics: Vec<Hash> = topic_tokens.into_iter().map(|t| Hash::from(t.to_uint().unwrap())).collect();
    let data: Bytes = receipt_tokens[2].clone().to_bytes().unwrap();
    Ok((nonce, RawLog { topics, data }))
}

pub(crate) fn ecall_set_worker_params_internal(nonce: Uint, rawLog: RawLog) -> Result<(), EnclaveError> {
    println!("Parsing raw log: {:?}", rawLog);
    let event = Event {
        name: "WorkersParameterized".to_string(),
        inputs: vec![EventParam {
            name: "seed".to_string(),
            kind: ParamType::Uint(256),
            indexed: false,
        }, EventParam {
            name: "blockNumber".to_string(),
            kind: ParamType::Uint(256),
            indexed: false,
        }, EventParam {
            name: "workers".to_string(),
            kind: ParamType::Array(Box::new(ParamType::Address)),
            indexed: false,
        }, EventParam {
            name: "balances".to_string(),
            kind: ParamType::Array(Box::new(ParamType::Uint(256))),
            indexed: false,
        }],
        anonymous: false,
    };
    let log = match event.parse_log(rawLog) {
        Ok(log) => {
            println!("the decoded log: {:?}", log);
            log
        }
        Err(err) => {
            return Err(EnclaveError::WorkerAuthError {
                err: format!("Unable to parse the log: {:?}", err),
            });
        }
    };
    let block_number = panic::catch_unwind(|| {
        log.params[1].value.clone().to_uint().unwrap()
    }).expect("Unable to cast block number");
    let workers = panic::catch_unwind(|| {
        log.params[2].value.clone().to_array().unwrap().iter().map(|t| t.clone().to_address().unwrap()).collect()
    }).expect("Unable to cast workers.");
    let balances = panic::catch_unwind(|| {
        log.params[3].value.clone().to_array().unwrap().iter().map(|t| t.clone().to_uint().unwrap()).collect()
    }).expect("Unable to cast balances.");
    let mut params_guard = EPOCH.lock_expect("Epoch");
    let worker_params = WorkerParams { block_number, workers, balances };
    let epoch = match params_guard.get_mut(&nonce) {
        Some(value) => value,
        None => {
            return Err(EnclaveError::WorkerAuthError {
                err: "Cannot set the workers parameters without a nonce in the Epoch mutex.".to_string(),
            });
        }
    };
    epoch.worker_params = Some(worker_params);
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

    // TODO: implement the worker selection algo
    let workers = epoch.worker_params.unwrap().workers;
    Ok(workers)
}
