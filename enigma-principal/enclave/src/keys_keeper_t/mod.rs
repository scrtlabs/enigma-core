use ethabi::{decode, ParamType};
use sgx_trts::trts::rsgx_read_rand;
use std::{collections::hash_map::RandomState, collections::HashMap, sync::SgxMutex, sync::SgxMutexGuard, vec::Vec};
use std::path;
use std::string::ToString;

use enigma_crypto::asymmetric::KeyPair;
use enigma_crypto::Encryption;
use enigma_crypto::hash::Keccak256;
use enigma_tools_t::common::{EthereumAddress, ToHex};
use enigma_tools_t::common::errors_t::EnclaveError;
use enigma_tools_t::common::utils_t::LockExpectMutex;
use enigma_tools_t::document_storage_t::{is_document, load_sealed_document, save_sealed_document, SEAL_LOG_SIZE, SealedDocumentStorage};
use enigma_tools_t::km_primitives::{PrincipalMessage, PrincipalMessageType};
use enigma_types::{ContractAddress, Hash256, StateKey};
use ocalls_t;

use crate::SIGNING_KEY;

pub mod keeper_types_t;

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
            Some(key) => {
                let mut buf: StateKey = [0; 32];
                buf.copy_from_slice(&key[..]);
                Some(buf)
            }
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
                        guard.insert(addr.clone(), doc.data);
                        key = Some(doc.data);
                    }
                    None => println!("State key {:?} does not exist", addr)
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
        let mut rand_seed: [u8; 32] = [0; 32];
        // Generate a new key randomly
        rsgx_read_rand(&mut rand_seed)?;
        let mut doc: SealedDocumentStorage<StateKey> = SealedDocumentStorage {
            version: 0x1234, //TODO: what's this?
            data: [0; 32],
        };
        doc.data.copy_from_slice(&rand_seed);
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
    if !new_addrs.is_empty() {
        // Creates keys in cache and seal
        new_state_keys(&mut guard, &new_addrs)?;
    }
    //Now we have keys for all addresses in cache
    for addr in sc_addrs {
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
    Ok(response_data)
}

/// Get encrypted state keys
pub(crate) fn ecall_get_enc_state_keys_internal(msg_bytes: Vec<u8>, addrs_bytes: Vec<u8>, sig: [u8; 65], sig_out: &mut [u8; 65]) -> Result<Vec<u8>, EnclaveError> {
    let msg = PrincipalMessage::from_message(&msg_bytes)?;
    let sc_addrs: Vec<ContractAddress> = match msg.data.clone() {
        PrincipalMessageType::Request(addrs) => match addrs {
            Some(addrs) => addrs,
            None => {
                let sc_addrs;
                if addrs_bytes == vec![0] {
                    sc_addrs = Vec::new();
                } else {
                    let tokens = match decode(&vec![ParamType::FixedBytes(256)], &addrs_bytes) {
                        Ok(tokens) => tokens,
                        Err(err) => {
                            return Err(EnclaveError::MessagingError {
                                err: format!("Unable to deserialize contract addresses {:?}: {:?}", addrs_bytes, err),
                            });
                        }
                    };
                    sc_addrs = tokens.into_iter().map(|t| {
                        let mut sc_addr: ContractAddress = Hash256::from([0; 32]);
                        sc_addr.copy_from_slice(&t.to_fixed_bytes().unwrap());
                        sc_addr
                    }).collect();
                }
                sc_addrs
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
    let response_data = build_get_state_keys_response(sc_addrs)?;

    // Generate the encryption key material
    let key_pair = KeyPair::new()?;
    let derived_key = key_pair.derive_key(&msg.get_pubkey())?;

    // Create the response message
    let response_msg_data = PrincipalMessageType::Response(response_data);
    let id = msg.get_id();
    let pubkey = key_pair.get_pubkey();
    let response_msg = PrincipalMessage::new_id(response_msg_data, id, pubkey);
    // Generate the iv from the first 12 bytes of a new random number
    let mut iv: [u8; 12] = [0; 12];
    rsgx_read_rand(&mut iv)?;
    let response = response_msg.encrypt_with_nonce(&derived_key, Some(iv))?;
    let response_bytes = response.to_message()?;
    println!("The partially encrypted response: {:?}", response_bytes.to_hex());
    // Signing the encrypted response
    // This is important because the response might be delivered by an intermediary
    let sig = SIGNING_KEY.sign(&response_bytes)?;
    sig_out.copy_from_slice(&sig[..]);
    Ok(response_bytes)
}

pub mod tests {
    use enigma_tools_t::common::FromHex;

    use super::*;

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
