use crate::SIGNINING_KEY;

use sgx_trts::trts::rsgx_read_rand;
use std::sync::SgxMutex;

use std::string::ToString;
use std::vec::Vec;
use std::collections::HashMap;
use enigma_tools_t::common::errors_t::EnclaveError;
use enigma_tools_t::common::utils_t::LockExpectMutex;
use crate::epoch_keeper_t::ecall_get_epoch_workers_internal;
use enigma_tools_t::cryptography_t::asymmetric::KeyPair;
use enigma_tools_t::common::EthereumAddress;
use enigma_tools_t::km_primitives::{PrincipalMessageType, StateKey, PrincipalMessage, ContractAddress};
use enigma_tools_t::cryptography_t::Encryption;
use ethereum_types::H256;

lazy_static! { pub static ref STATE_KEY_STORE: SgxMutex< HashMap<ContractAddress, StateKey >> = SgxMutex::new(HashMap::new()); }

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

    let mut response_data: Vec<(ContractAddress, StateKey)> = Vec::new();
    for raw_addr in req_addrs {
        let sc_addr: H256 = H256(raw_addr);
        // Run the worker selection algorithm for the current epoch
        // TODO: The epoch mutex guard is not happy with locking from here, need to understand this better
        // TODO: Enable after further testing
//        let epoch_worker = ecall_get_epoch_workers_internal(sc_addr, None)?[0];
//        println!("Found the epoch worker {:?} for contract {:?}", epoch_worker, sc_addr);
//        if recovered.address() != format!("{:?}", epoch_worker) {
//            return Err(EnclaveError::KeyProvisionError {
//                err: format!("Signer address of the KM message {} is not the selected worker {}.", recovered.address(), epoch_worker),
//            });
//        }
        // TODO: Clean up and move to separate function
        // TODO: Seal state key mapping to disk
        // Get the state key from the Mutex or create if it does not exist
        let mut key: StateKey = [0u8; 32];
        let mut guard = STATE_KEY_STORE.lock_expect("State Key Store");
        if guard.contains_key(&raw_addr) {
            let key_slice = guard.get(&raw_addr).unwrap();
            key.copy_from_slice(&key_slice[..]);
            println!("Found state key for contract {:?}", sc_addr);
        } else {
            let mut rand_seed: [u8; 1072] = [0; 1072];
            // Generate a new key randomly
            rsgx_read_rand(&mut rand_seed)?;
            key.copy_from_slice(&rand_seed[..32]);
            guard.insert(raw_addr, key)
                .ok_or(EnclaveError::KeyProvisionError {
                    err: format!("Unable to store key for contract: {:?}", sc_addr)
                });
            println!("Stored state key for contract {:?}", sc_addr);
        }
        let response_item: (ContractAddress, StateKey) = (raw_addr, key);
        response_data.push(response_item);
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
