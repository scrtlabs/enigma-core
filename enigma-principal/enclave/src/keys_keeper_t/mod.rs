use enigma_tools_m::{
    primitives::km_primitives::{PrincipalMessage, PrincipalMessageType},
    utils::EthereumAddress,
};
use sgx_trts::trts::rsgx_read_rand;
use std::{collections::HashMap, path, sync::SgxMutex, vec::Vec, string::String};

use enigma_crypto::{asymmetric::KeyPair, Encryption};
use enigma_crypto::hash::Keccak256;
use enigma_tools_t::{
    common::errors_t::{
            EnclaveError::{self, *},
            EnclaveSystemError::*,
        },
    document_storage_t::{is_document, load_sealed_document, save_sealed_document, SEAL_LOG_SIZE, SealedDocumentStorage},
};
use enigma_tools_m::utils::LockExpectMutex;
use enigma_types::{ContractAddress, Hash256, StateKey};
use epoch_keeper_t::ecall_get_epoch_worker_internal;
use ocalls_t;
use ethereum_types::U256;
use rustc_hex::ToHex;

use crate::SIGNING_KEY;
use sgx_types::uint8_t;

const STATE_KEYS_DIR: &str = "state-keys";

lazy_static! {
    pub static ref STATE_KEY_STORE: SgxMutex<HashMap<ContractAddress, StateKey>> = SgxMutex::new(HashMap::new());
}

/// The state keys root path is guaranteed to exist of the enclave was initialized
fn get_state_keys_root_path() -> path::PathBuf {
    let mut path_buf = ocalls_t::get_home_path().unwrap();
    path_buf.push(STATE_KEYS_DIR);
    path_buf
}

fn get_document_path(sc_addr: &ContractAddress) -> path::PathBuf {
    get_state_keys_root_path().join(format!("{}.{}", sc_addr.to_hex::<String>(), "sealed"))
}

/// Read state keys from the cache and sealed documents.
/// Adds keys to the cache after unsealing.
fn get_state_keys(keys_map: &mut HashMap<ContractAddress, StateKey>,
                  sc_addrs: &[ContractAddress]) -> Result<Vec<Option<StateKey>>, EnclaveError> {
    let mut results: Vec<Option<StateKey>> = Vec::new();
    for &addr in sc_addrs {
        let key = match keys_map.get(&addr) {
            Some(&key) => Some(key),
            None => {
              //  let p = addr.to_vec().to_hex();
                debug_println!("State key for contract {:?} not found in cache, fetching sealed document.", addr.to_vec().to_hex::<String>());
                let path = get_document_path(&addr);
                if is_document(&path) {
                    let mut sealed_log_out = [0u8; SEAL_LOG_SIZE];
                    load_sealed_document(&path, &mut sealed_log_out)?;
                    let doc = SealedDocumentStorage::<StateKey>::unseal(&mut sealed_log_out)?;
                    match doc {
                        Some(doc) => {
                            debug_println!("State key for contract {:?} is unsealed", addr.to_hex::<String>());
                            keys_map.insert(addr, doc.data);
                            Some(doc.data)
                        }
                        None => {
                            debug_println!("Contract {:?} is new, state key does not exist", addr.to_hex::<String>());
                            None
                        }
                    }
                } else {
                    None
                }
            }
        };
        results.push(key);
    }
    Ok(results)
}

/// Creates new state keys both in the cache and as sealed documents
fn new_state_keys(keys_map: &mut HashMap<ContractAddress, StateKey>,
                  sc_addrs: &[ContractAddress]) -> Result<Vec<StateKey>, EnclaveError> {
    let mut results: Vec<StateKey> = Vec::new();
    for &addr in sc_addrs {
        let mut doc: SealedDocumentStorage<StateKey> = SealedDocumentStorage {
            version: 0x1234, // TODO: what's this?
            data: [0; 32],
        };
        // Generate a new key randomly
        rsgx_read_rand(&mut doc.data)?;

        let mut sealed_log_in = [0u8; SEAL_LOG_SIZE];
        doc.seal(&mut sealed_log_in)?;
        // Save sealed_log to file
        let path = get_document_path(&addr);
        save_sealed_document(&path, &sealed_log_in)?;
        // Add to cache
        keys_map.insert(addr, doc.data);
        debug_println!("New key for contract {:?} is stored successfully", addr.to_hex::<String>());

        results.push(doc.data);
    }
    Ok(results)
}

fn build_get_state_keys_response(sc_addrs: Vec<ContractAddress>) -> Result<Vec<(ContractAddress, StateKey)>, EnclaveError> {
    let mut response_data: Vec<(ContractAddress, StateKey)> = Vec::new();
    if sc_addrs.is_empty() {
        return Ok(response_data);
    }
    let mut guard = STATE_KEY_STORE.lock_expect("State Key Store");
    let keys = get_state_keys(&mut guard, &sc_addrs)?;
    // Create the state keys not found in storage
    let mut new_addrs: Vec<ContractAddress> = Vec::new();
    for (i, key) in keys.iter().enumerate() {
        if key.is_none() {
            new_addrs.push(sc_addrs[i]);
        }
    }
    new_state_keys(&mut guard, &new_addrs)?; // If the vector is empty this won't do anything.
    // Now we have keys for all addresses in cache
    for addr in sc_addrs {
        match guard.get(&addr) {
            Some(&key) => response_data.push((addr, key)),
            None => {
                return Err(SystemError(KeyProvisionError { err: format!("State key not found in cache: {:?}", addr.to_hex::<String>()) }));
            }
        }
    }
    Ok(response_data)
}

/// Get encrypted state keys
pub(crate) fn ecall_get_enc_state_keys_internal(
    msg_bytes: &[u8], sc_addrs: Vec<ContractAddress>, sig: [u8; 65], epoch_nonce: [u8; 32],
    sig_out: &mut [u8; 65]) -> Result<Vec<u8>, EnclaveError> {
    let msg = PrincipalMessage::from_message(msg_bytes)?;
    let user_pubkey = msg.get_pubkey();
    let msg_id = msg.get_id();
    // Create the request image before the worker selection guard to avoid cloning the message data
    let image = msg.to_sign()?;
    let recovered_addr = KeyPair::recover(&image, sig)?.address();
    let nonce = U256::from(epoch_nonce.as_ref());
    for sc_addr in sc_addrs.clone() {
        let worker_addr = ecall_get_epoch_worker_internal(sc_addr, nonce)?;
        if worker_addr != recovered_addr {
            return Err(SystemError(WorkerAuthError {
                err: format!("Selected worker for contract: {} is not the message signer {} != {}",
                             sc_addr.to_hex::<String>(), worker_addr.to_hex::<String>(), recovered_addr.to_hex::<String>())
            }));
        }
    }
    let response_data = build_get_state_keys_response(sc_addrs)?;

    // Generate the encryption key material
    let key_pair = KeyPair::new()?;
    let derived_key = key_pair.derive_key(&user_pubkey)?;

    // Create the response message
    let response_msg_data = PrincipalMessageType::Response(response_data);
    let pubkey = key_pair.get_pubkey();
    let response_msg = PrincipalMessage::new_id(response_msg_data, msg_id, pubkey);
    // Generate the iv from the first 12 bytes of a new random number
    let response = response_msg.encrypt(&derived_key)?.into_message()?;
    // Signing the encrypted response
    // This is important because the response might be delivered by an intermediary
    *sig_out = SIGNING_KEY.sign(&response)?;
    debug_println!("Get state key response requested for secret contract {:?}: {:?}", recovered_addr.to_hex::<String>(), response.to_hex::<String>());
    Ok(response)
}

pub mod tests {
    use rustc_hex::FromHex;

    use super::*;

    // noinspection RsTypeCheck
    pub fn test_state_keys_storage() {
        let data: Vec<Vec<u8>> = vec![
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

        let cached_keys = get_state_keys(&mut guard, &sc_addrs)
            .expect("Unable to get state keys from cache")
            .iter()
            .map(|k| k.unwrap())
            .collect::<Vec<StateKey>>();
        assert_eq!(new_keys, cached_keys);

        // Clearing the cache to test retrieval of sealed keys form disk
        guard.clear();

        let stored_keys = get_state_keys(&mut guard, &sc_addrs)
            .expect("Unable to get state keys from sealed files")
            .iter()
            .map(|k| k.unwrap())
            .collect::<Vec<StateKey>>();
        assert_eq!(new_keys, stored_keys);
    }
}
