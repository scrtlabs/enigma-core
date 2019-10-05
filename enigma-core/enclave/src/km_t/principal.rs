use super::STATE_KEYS;
use crate::SIGNING_KEY;
use enigma_runtime_t::data::{ContractState, DeltasInterface};
use enigma_runtime_t::ocalls_t as runtime_ocalls_t;
use enigma_tools_t::common::errors_t::EnclaveError;
use enigma_tools_m::utils::LockExpectMutex;
use enigma_crypto::asymmetric::KeyPair;
use enigma_crypto::{Encryption, CryptoError};
use enigma_tools_m::primitives::km_primitives::MsgID;
use enigma_tools_m::primitives::km_primitives::{PrincipalMessage, PrincipalMessageType};
use enigma_types::{ContractAddress, StateKey, RawPointer};
use std::collections::HashMap;
use std::sync::SgxMutex;
use std::u32;
use std::vec::Vec;

lazy_static! {
    pub static ref DH_KEYS: SgxMutex<HashMap<MsgID, KeyPair>> = SgxMutex::new(HashMap::new());
}

pub(crate) unsafe fn ecall_ptt_req_internal(sig: &mut [u8; 65]) -> Result<Vec<u8>, EnclaveError> {
    let keys = KeyPair::new()?;
    let data = PrincipalMessageType::Request;
    let req = PrincipalMessage::new(data, keys.get_pubkey())?;
    let id = req.get_id();
    *sig = SIGNING_KEY.sign(&req.to_sign()?)?;
    let msg = req.into_message()?;
    DH_KEYS.lock_expect("DH Keys").insert(id, keys);
    Ok(msg)
}

pub(crate) fn ecall_ptt_res_internal(msg_slice: &[u8]) -> Result<(), EnclaveError> {
    let res = PrincipalMessage::from_message(msg_slice)?;

    let mut guard = DH_KEYS.lock_expect("DH Keys");
    let id = res.get_id();
    let msg;
    {
        let keys = guard.get(&id).ok_or(CryptoError::MissingKeyError { key_type: "DH Keys" })?;
        let aes = keys.derive_key(&res.get_pubkey())?;
        msg = PrincipalMessage::decrypt(res, &aes)?;
    }
    if let PrincipalMessageType::Response(v) = msg.data {
        for (addr, key) in v {
            STATE_KEYS.lock_expect("state keys").insert(addr, key);
        }
    } else {
        unreachable!() // This should never execute. // TODO: Replace with an error.
    }
    guard.remove(&id);
    Ok(())
}

pub(crate) unsafe fn ecall_build_state_internal(db_ptr: *const RawPointer) -> Result<Vec<ContractAddress>, EnclaveError> {
    let guard = STATE_KEYS.lock_expect("State Keys");
    let mut failed_contracts = Vec::with_capacity(guard.len());
    debug_println!("building state for {} contracts", guard.len());

    'contract: for (addrs, key) in guard.iter() {
        // Get the state and decrypt it.
        // if no state exists create a new one and if failed decrypting, push to failed_contracts and move on.
        let (mut start, mut state ) = match runtime_ocalls_t::get_state(db_ptr, *addrs) {
            Ok(enc_state) => match ContractState::decrypt(enc_state, &key) {
                Ok(state) => (state.delta_index+1, state),
                Err(_) => {
                    failed_contracts.push(*addrs);
                    continue 'contract;
                }
            }, // don't throw error if only one failed, somehow tell that but continue
            Err(_) => (0, ContractState::new(*addrs)),
        };

        'deltas: while start < u32::MAX {
            let end = start + 500;
            // Get deltas from start to end, if fails save the latest state and move on.
            let deltas = match runtime_ocalls_t::get_deltas(db_ptr, *addrs, start, end) {
                Ok(deltas) => deltas,
                Err(_) => {
                    // If it failed to get deltas, encrypt the latest state and save it
                    let enc = match state.encrypt(key) {
                        Ok(s) => s,
                        Err(_) => {
                            // If Failed to encrypt the latest state push to failed_contracts and move on.
                            failed_contracts.push(*addrs);
                            continue 'contract;
                        }
                    };
                    runtime_ocalls_t::save_state(db_ptr, &enc)?;
                    continue 'contract;
                }
            };
            let deltas_len = deltas.len();
            // decrypt the deltas and apply them to the state.
            // If failed, encrypt the latest state and move on.
            for delta in deltas {
                match state.apply_delta(delta, key) {
                    Ok(()) => (),
                    Err(e) => {
                        debug_println!("Failed applying delta: {:?}", e);
                        let enc = match state.encrypt(key) {
                            Ok(s) => s,
                            Err(e) => {
                                // If Failed to encrypt the latest state push to failed_contracts and move on.
                                debug_println!("Failed encrypting the state: {:?}", e);
                                failed_contracts.push(*addrs);
                                continue 'contract;
                            }
                        };
                        failed_contracts.push(*addrs);
                        runtime_ocalls_t::save_state(db_ptr, &enc)?;
                        continue 'contract;
                    }
                };
            }
            if deltas_len == (end - start) as usize {
                start = end;
            } else {
                start = u32::MAX;
            }
        }

        let enc = match state.encrypt(key) {
            Ok(d) => d,
            Err(_) => {
                // If Failed to encrypt the latest state push to failed_contracts and move on.
                failed_contracts.push(*addrs);
                continue 'contract;
            }
        };
        runtime_ocalls_t::save_state(db_ptr, &enc)?;
    }
    Ok(failed_contracts)
}

#[cfg(debug_assertions)]
pub mod tests {
    use super::*;
    use enigma_runtime_t::data::IOInterface;
    use enigma_runtime_t::data::{EncryptedContractState, EncryptedPatch};
    use enigma_crypto::hash::Sha256;
    use enigma_crypto::asymmetric::KeyPair;
    use enigma_tools_m::primitives::km_primitives::{PrincipalMessage, PrincipalMessageType};
    use enigma_types::{ContractAddress, RawPointer};
    use std::string::ToString;


    pub unsafe fn test_state_internal(db_ptr: *const RawPointer) {
        // Making the ground work
        let address = vec![b"meee".sha256(), b"moo".sha256(), b"maa".sha256()];
        let state_keys = vec![*b"first_key".sha256(), *b"second_key".sha256(), *b"third_key".sha256()];
        let enc_states_and_deltas = get_states_deltas(&address, &state_keys);

        //        // Saving the encrypted states and deltas to the db
        for enc_deltas in enc_states_and_deltas {
            for delta in enc_deltas {
                runtime_ocalls_t::save_delta(db_ptr, &delta).unwrap();
            }
        }
        let gibrish_state = EncryptedContractState { contract_address: address[2], json: vec![8u8; 65] };
        runtime_ocalls_t::save_state(db_ptr, &gibrish_state).unwrap();
        // Generating the request
        let mut _sig = [0u8; 65];
        let req_msg = ecall_ptt_req_internal(&mut _sig).unwrap();
        let req_obj = PrincipalMessage::from_message(&req_msg).unwrap();

        // Mimicking the Principal/KM Node
        let km_node_keys = KeyPair::new().unwrap();
        let restype: Vec<(ContractAddress, StateKey)> = address.clone().into_iter().zip(state_keys.into_iter()).collect();

        let res_obj = PrincipalMessage::new_id(PrincipalMessageType::Response(restype), req_obj.get_id(), km_node_keys.get_pubkey());
        let dh_key = km_node_keys.derive_key(&req_obj.get_pubkey()).unwrap();
        let enc_req = res_obj.encrypt(&dh_key).unwrap();

        let enc_res_slice = enc_req.into_message().unwrap();

        // Enclave Process Response
        ecall_ptt_res_internal(&enc_res_slice).unwrap();

        // Initiate the building
        assert_eq!(ecall_build_state_internal(db_ptr).unwrap(), vec![address[2]])
    }

    fn get_states_deltas(address: &[ContractAddress], keys: &[StateKey]) -> Vec<Vec<EncryptedPatch>> {
        let jsons: Vec<serde_json::Value> = vec![
            json!({"widget":{"debug":"on","window":{"title":"Sample Konfabulator Widget","name":"main_window","width":500,"height":500},"image":{"src":"Images/Sun.png","name":"sun1","hOffset":250,"vOffset":250,"alignment":"center"},"text":{"data":"Click Here","size":36,"style":"bold","name":"text1","hOffset":250,"vOffset":100,"alignment":"center","onMouseUp":"sun1.opacity = (sun1.opacity / 100) * 90;"}}}),
            serde_json::from_str(r#"{ "name": "John Doe", "age": 43, "phones": [ "+44 1234567", "+44 2345678" ] }"#).unwrap(),
        ];
        let states = vec![
            ContractState::new(address[0]),
            ContractState::new(address[1]),
        ];

        let mut result = Vec::with_capacity(states.len());
        for ((mut state, key), json) in states.into_iter().zip(keys.iter()).zip(jsons.into_iter()) {
            let mut patches = Vec::with_capacity(15);
            let original_state = state.clone();
            state.json = json;
            let delta0 = ContractState::generate_delta_and_update_state(&original_state, &mut state, key).unwrap();
            patches.push(delta0);
            for i in 1..15 {
                let old_state = state.clone();
                state.write_key(&i.to_string(), &json!(i)).unwrap();
                let delta = ContractState::generate_delta_and_update_state(&old_state, &mut state, key).unwrap();
                patches.push(delta);
            }
            result.push(patches);
        }
        result
    }

}
