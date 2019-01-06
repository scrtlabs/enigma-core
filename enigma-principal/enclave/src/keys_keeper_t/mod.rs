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
use std::panic;
use ethabi::{Hash, Bytes, RawLog, Token, EventParam, ParamType, Event, Address, Uint, Log, FixedBytes, decode};
use ethabi::token::{LenientTokenizer, Tokenizer};
use enigma_tools_t::common::errors_t::EnclaveError;
use enigma_tools_t::common::utils_t::LockExpectMutex;
use enigma_tools_t::storage_t::SEAL_LOG_SIZE;
use std::string::String;
use std::prelude::v1::Box;
use secp256k1;
use crate::epoch_keeper_t::ecall_get_epoch_workers_internal;
use enigma_tools_t::cryptography_t::asymmetric::KeyPair;
use enigma_tools_t::common::EthereumAddress;
use enigma_tools_t::km_primitives::{MessageType, StateKey, Message, ContractAddress};
use enigma_tools_t::cryptography_t::Encryption;

lazy_static! { pub static ref STATE_KEY_STORE: SgxMutex< HashMap<ContractAddress, StateKey >> = SgxMutex::new(HashMap::new()); }

pub(crate) fn ecall_get_enc_state_keys_internal(enc_msg: Vec<u8>, sig: [u8; 65]) -> Result<Vec<u8>, EnclaveError> {
    println!("Decoding msg: {:?}", enc_msg);
    println!("The signature: {:?}", sig.to_vec());

    let msg = Message::from_message(&enc_msg)?;
    println!("The deserialized message: {:?}", msg);
    let req_addrs: Vec<ContractAddress> = match msg.clone().data {
        MessageType::Request(addrs) => addrs,
        _ => {
            return Err(EnclaveError::MessagingError {
                err: "Could not deserialize the KM Message into a Request.".to_string(),
            });
        }
    };
    let recovered = KeyPair::recover(&enc_msg, &sig).unwrap();
    println!("The recovered address: {:?}", recovered.address());

    let mut response_data: Vec<(ContractAddress, StateKey)> = Vec::new();
    for raw_addr in req_addrs {
        let types = &vec![ParamType::Address];
        let sc_addr = decode(types, &raw_addr).unwrap()[0].clone().to_address().unwrap();
        let workers = ecall_get_epoch_workers_internal(sc_addr, None)?;
        let epoch_worker = workers[0];
        println!("Found the epoch worker {:?} for contract {:?}", epoch_worker, sc_addr);
        if recovered.address() != format!("{:?}", epoch_worker) {
            return Err(EnclaveError::KeyProvisionError {
                err: format!("Signer address of the KM message {} is not the selected worker {}.", recovered.address(), epoch_worker),
            });
        }
        let mut key: StateKey = [0u8; 32];
        let mut guard = STATE_KEY_STORE.lock_expect("State Key Store");
        if guard.contains_key(&raw_addr) {
            let key_slice = guard.get(&raw_addr).unwrap();
            key.copy_from_slice(&key_slice[..]);
        } else {
            let mut rand_seed: [u8; 1072] = [0; 1072];
            rsgx_read_rand(&mut rand_seed)?;
            key.copy_from_slice(&rand_seed[..32]);
            // TODO: catch error
            guard.insert(raw_addr, key);
            println!("Key {:?} inserted for contract {:?}", key.to_vec(), sc_addr);
        }
        let response_item: (ContractAddress, StateKey) = (raw_addr, key);
        response_data.push(response_item);
    }

    let response_msg_data = MessageType::Response(response_data);
    let id = msg.get_id();
    let pubkey = msg.get_pubkey();

    let response_msg = Message::new_id(response_msg_data, id, pubkey);
    if !response_msg.is_response() {
        return Err(EnclaveError::KeyProvisionError {
            err: "Unable instantiate the response".to_string()
        });
    }
    // TODO: Derive from a separate encryption key, not the signing key
    let derived_key = SIGNINING_KEY.get_aes_key(&pubkey)?;
    let mut rand_seed: [u8; 1072] = [0; 1072];
    rsgx_read_rand(&mut rand_seed)?;
    let mut iv: [u8; 12] = [0; 12];
    iv.clone_from_slice(&rand_seed[32..44]);
    let response = response_msg.encrypt_with_nonce(&derived_key, Some(iv))?;
    if !response.is_encrypted_response() {
        return Err(EnclaveError::KeyProvisionError {
            err: "Unable encrypt the response".to_string()
        });
    }
    Ok(response.to_message()?)
}
