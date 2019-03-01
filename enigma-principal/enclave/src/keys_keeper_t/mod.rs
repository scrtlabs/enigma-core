use crate::SIGNING_KEY;

use sgx_trts::trts::rsgx_read_rand;
use std::string::ToString;
use enigma_tools_t::common::errors_t::EnclaveError;
use crate::epoch_keeper_t::ecall_get_epoch_workers_internal;
use enigma_crypto::asymmetric::KeyPair;
use enigma_crypto::Encryption;
use enigma_tools_t::common::{EthereumAddress, ToHex};
use enigma_tools_t::km_primitives::{PrincipalMessageType, PrincipalMessage};
use enigma_types::{StateKey, ContractAddress, Hash256};
use ocalls_t;
use std::path;
use enigma_tools_t::document_storage_t::{is_document, load_sealed_document, save_sealed_document, SEAL_LOG_SIZE, SealedDocumentStorage};
use enigma_tools_t::common::utils_t::LockExpectMutex;
use std::{sync::SgxMutex, sync::SgxMutexGuard, vec::Vec, collections::HashMap, collections::hash_map::RandomState};
use enigma_crypto::hash::Keccak256;

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
                            err: format!("Unable to store key in cache: {:?}", addr.to_hex())
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
        match guard.insert(addr.clone(), doc.data) {
            Some(prev) => println!("New key stored successfully, previous key: {:?}", prev),
            None => println!("Initial key stored successfully"),
        }
        results.push(doc.data);
    }
    Ok(results)
}

pub(crate) fn ecall_get_enc_state_keys_internal(msg_bytes: Vec<u8>, sig: [u8; 65], sig_out: &mut [u8; 65]) -> Result<Vec<u8>, EnclaveError> {
    // TODO: Break up this function for better readability
    let msg = PrincipalMessage::from_message(&msg_bytes)?;
    let req_addrs: Vec<ContractAddress> = match msg.data.clone() {
        PrincipalMessageType::Request(addrs) => match addrs {
            Some(addrs) => addrs,
            None => {
                return Err(EnclaveError::MessagingError {
                    err: format!("Empty addresses: {:?}", msg_bytes),
                });
            }
        },
        _ => {
            return Err(EnclaveError::MessagingError {
                err: format!("Unable to deserialize message: {:?}", msg_bytes),
            });
        }
    };
    let recovered = KeyPair::recover(&msg_bytes, sig)?;
    println!("Recovered signer address from the message signature: {:?}", recovered.address());

    // TODO: Verify that the worker is selected for all addresses or throw
    let mut response_data: Vec<(ContractAddress, StateKey)> = Vec::new();
    let mut guard = STATE_KEY_STORE.lock_expect("State Key Store");
    let keys = get_state_keys(&mut guard, &req_addrs)?;
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
            Some(_key) => {
                let mut key = [0; 32];
                key.copy_from_slice(_key);
                response_data.push((addr, key));
            }
            None => {
                return Err(EnclaveError::KeyProvisionError {
                    err: format!("State key not found in cache: {:?}", addr.to_hex())
                });
            }
        }
    }
    // Generate the encryption key material
    let mut rand_num: [u8; 1072] = [0; 1072];
    rsgx_read_rand(&mut rand_num)?;
    let mut privkey_slice = [0u8; 32];
    privkey_slice.copy_from_slice(&rand_num[..32]);
    let my_keypair = KeyPair::from_slice(&privkey_slice)?;
    let derived_key = my_keypair.derive_key(&msg.get_pubkey())?;

    // Create the response message
    let response_msg_data = PrincipalMessageType::Response(response_data);
    let id = msg.get_id();
    let pubkey = my_keypair.get_pubkey();
    let response_msg = PrincipalMessage::new_id(response_msg_data, id, pubkey);
    if !response_msg.is_response() {
        return Err(EnclaveError::KeyProvisionError {
            err: "Unable create response".to_string()
        });
    }
    // Generate the iv from the first 12 bytes of a new random number
    let mut iv: [u8; 12] = [0; 12];
    iv.clone_from_slice(&rand_num[32..44]);
    let response = response_msg.encrypt_with_nonce(&derived_key, Some(iv))?;
    // TODO: The bytes don't seem to change between request.
    let response_bytes = response.to_message()?;
    println!("The partially encrypted response: {:?}", response_bytes.to_hex());
    // Signing the encrypted response
    // This is important because the response might be delivered by an intermediary
    let hash = response_bytes.clone().keccak256();
    let sig = SIGNING_KEY.sign(hash.as_ref())?;
    sig_out.copy_from_slice(&sig[..]);
    Ok(response_bytes)
}

pub mod tests {
    use super::*;
    use enigma_tools_t::common::FromHex;

    //noinspection RsTypeCheck
    pub fn test_state_keys_storage() {
        let data = vec![
            "9F86D081884C7D659A2FEAA0C55AD015A3BF4F1B2B0B822CD15D6C15B0F00A08".from_hex().unwrap(),
            "60303AE22B998861BCE3B28F33EEC1BE758A213C86C93C076DBE9F558C11C752".from_hex().unwrap(),
        ];
        let mut sc_addrs: Vec<ContractAddress> = Vec::new();
        for (_i, addr) in data.iter().enumerate() {
            let mut a: Hash256 = [0u8; 32].into();
            a.copy_from_slice(addr);
            sc_addrs.push(a);
        }
        let mut guard = STATE_KEY_STORE.lock_expect("State Key Store");
        let new_keys = new_state_keys(&mut guard, &sc_addrs).expect("Unable to store state keys");

        let cached_keys = get_state_keys(&mut guard, &sc_addrs).expect("Unable to get state keys from cache")
            .iter()
            .map(|k| k.unwrap())
            .collect::<Vec<StateKey>>();
        assert_eq!(new_keys, cached_keys);

        // Clearing the cache to test retrieval of sealed keys form disk
        guard.clear();

        let stored_keys = get_state_keys(&mut guard, &sc_addrs).expect("Unable to get state keys from sealed files")
            .iter()
            .map(|k| k.unwrap())
            .collect::<Vec<StateKey>>();
        assert_eq!(new_keys, stored_keys);
    }
}
