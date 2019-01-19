use crate::SIGNINING_KEY;

use sgx_trts::trts::rsgx_read_rand;
use std::sync::SgxMutex;
use std::sync::SgxMutexGuard;

use std::string::ToString;
use std::vec::Vec;
use std::collections::HashMap;
use std::collections::hash_map::RandomState;
use enigma_tools_t::common::errors_t::EnclaveError;
use enigma_tools_t::common::utils_t::LockExpectMutex;
use crate::epoch_keeper_t::ecall_get_epoch_workers_internal;
use enigma_tools_t::cryptography_t::asymmetric::KeyPair;
use enigma_tools_t::common::{EthereumAddress, ToHex};
use enigma_tools_t::km_primitives::{PrincipalMessageType, StateKey, PrincipalMessage, ContractAddress};
use enigma_tools_t::cryptography_t::Encryption;
use ethereum_types::H256;
use ocalls_t;
use std::path;
use enigma_tools_t::document_storage_t::{is_document, load_sealed_document, save_sealed_document, SEAL_LOG_SIZE, SealedDocumentStorage};
use sgx_types::marker::ContiguousMemory;

const STATE_KEYS_DIR: &str = "state-keys";

lazy_static! { pub static ref STATE_KEY_STORE: SgxMutex< HashMap<ContractAddress, StateKey >> = SgxMutex::new(HashMap::new()); }

/// The state keys root path is guaranteed to exist of the enclave was initialized
fn get_state_keys_root_path() -> path::PathBuf {
    let mut path_buf = ocalls_t::get_home_path();
    path_buf.push(STATE_KEYS_DIR);
    path_buf
}

fn get_document_path(sc_addr: &ContractAddress) -> path::PathBuf {
    get_state_keys_root_path().join(format!("{}.{}", sc_addr.to_hex(), "sealed"))
}

/// Read state keys from the cache and sealed documents.
/// Adds keys to the cache after unsealing.
fn get_state_keys(guard: &mut SgxMutexGuard<HashMap<ContractAddress, StateKey, RandomState>>, sc_addrs: &Vec<ContractAddress>) -> Result<Vec<Option<StateKey>>, EnclaveError> {
    let mut results: Vec<Option<StateKey>> = Vec::new();
    for addr in sc_addrs {
        let mut key: Option<StateKey> = match guard.get(addr) {
            Some(key) => Some(key.clone()),
            None => None,
        };
        if key.is_none() {
            println!("State key not found in cache, fetching sealed document.");
            let path = get_document_path(addr);
            if is_document(&path) {
                println!("Unsealing state key.");
                let mut sealed_log_out = [0u8; SEAL_LOG_SIZE];
                load_sealed_document(&path, &mut sealed_log_out)?;
                let doc = SealedDocumentStorage::<StateKey>::unseal(&mut sealed_log_out)?;
                match doc {
                    Some(doc) => {
                        guard.insert(addr.clone(), doc.data).ok_or(EnclaveError::KeyProvisionError {
                            err: format!("Unable to store key in cache: {:?}", addr)
                        });
                        key = Some(doc.data);
                    }
                    None => ()
                }
            }
        }
        results.push(key);
    }
    Ok(results)
}

/// Creates new state keys both in the cache and as sealed documents
fn new_state_keys(guard: &mut SgxMutexGuard<HashMap<ContractAddress, StateKey, RandomState>>, sc_addrs: &Vec<ContractAddress>) -> Result<Vec<StateKey>, EnclaveError> {
    let mut results: Vec<StateKey> = Vec::new();
    for addr in sc_addrs {
        let mut rand_seed: [u8; 1072] = [0; 1072];
        // Generate a new key randomly
        rsgx_read_rand(&mut rand_seed)?;
        let mut doc: SealedDocumentStorage<StateKey> = SealedDocumentStorage {
            version: 0x1234, //TODO: what's this?
            data: [0; 32],
        };
        doc.data.copy_from_slice(&rand_seed[..32]);
        let mut sealed_log_in = [0u8; SEAL_LOG_SIZE];
        doc.seal(&mut sealed_log_in)?;
        // Save sealed_log to file
        let path = get_document_path(addr);
        save_sealed_document(&path, &sealed_log_in)?;
        // Add to cache
        guard.insert(addr.clone(), doc.data).ok_or(EnclaveError::KeyProvisionError {
            err: format!("Unable to store key in cache: {:?}", addr)
        });
        results.push(doc.data);
    }
    Ok(results)
}

pub(crate) fn ecall_get_enc_state_keys_internal(msg_bytes: Vec<u8>, sig: [u8; 65], sig_out: &mut [u8; 65]) -> Result<Vec<u8>, EnclaveError> {
    // TODO: Break up this function for better readability
    let msg = PrincipalMessage::from_message(&msg_bytes)?;
    let req_addrs: Vec<ContractAddress> = match msg.data.clone() {
        PrincipalMessageType::Request(addrs) => addrs,
        _ => {
            return Err(EnclaveError::MessagingError {
                err: format!("Unable to deserialize message: {:?}", msg_bytes),
            });
        }
    };
    let recovered = KeyPair::recover(&msg_bytes, &sig).unwrap();
    println!("Recovered signer address from the message signature: {:?}", recovered.address());

    // TODO: Verify that the worker is selected for all addresses or throw
    let mut response_data: Vec<(ContractAddress, StateKey)> = Vec::new();
    let mut guard: SgxMutexGuard<HashMap<[u8; 32], [u8; 32], RandomState>> = STATE_KEY_STORE.lock_expect("State Key Store");
    let mut keys = get_state_keys(&mut guard, &req_addrs)?;
    let mut new_addrs: Vec<ContractAddress> = Vec::new();
    for (i, key) in keys.iter().enumerate() {
        if key.is_none() {
            new_addrs.push(req_addrs[i]);
        }
    }
    if !new_addrs.is_empty() {
        // Creates keys in cache and seal
        new_state_keys(&mut guard, &new_addrs)?;
    }
    //Now we have keys for all addresses in cache
    for addr in req_addrs {
        match guard.get(&addr) {
            Some(key) => {
                response_data.push((addr, key.clone()));
            }
            None => {
                return Err(EnclaveError::KeyProvisionError {
                    err: format!("State key not found in cache: {:?}", addr.to_hex())
                });
            }
        }
    }

    let response_msg_data = PrincipalMessageType::Response(response_data);
    let id = msg.get_id();
    let pubkey = msg.get_pubkey();

    let response_msg = PrincipalMessage::new_id(response_msg_data, id, pubkey);
    if !response_msg.is_response() {
        return Err(EnclaveError::KeyProvisionError {
            err: "Unable create response".to_string()
        });
    }
    // TODO: Derive from a separate encryption key, not the signing key
    let derived_key = SIGNINING_KEY.get_aes_key(&pubkey)?;
    let mut rand_num: [u8; 1072] = [0; 1072];
    rsgx_read_rand(&mut rand_num)?;
    // Generate the iv from the first 12 bytes of a new random number
    let mut iv: [u8; 12] = [0; 12];
    iv.clone_from_slice(&rand_num[32..44]);
    let response = response_msg.encrypt_with_nonce(&derived_key, Some(iv))?;
    if !response.is_encrypted_response() {
        return Err(EnclaveError::KeyProvisionError {
            err: "Unable encrypt the response".to_string()
        });
    }
    // TODO: The bytes don't seem to change between request.
    let response_bytes = response.to_message()?;
    println!("The encrypted response bytes: {:?}", response_bytes);
    // Signing the encrypted response
    // This is important because the response might be delivered by an intermediary
    let sig = SIGNINING_KEY.sign(&response_bytes[..])?;
    sig_out.copy_from_slice(&sig[..]);
    Ok(response_bytes)
}
