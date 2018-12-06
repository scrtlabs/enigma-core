use crate::SIGNINING_KEY;
use enigma_runtime_t::data::{ContractState, DeltasInterface, StatePatch};
use enigma_runtime_t::ocalls_t as runtime_ocalls_t;
use enigma_tools_t::common::errors_t::EnclaveError;
use enigma_tools_t::common::utils_t::LockExpectMutex;
use enigma_tools_t::cryptography_t::asymmetric::KeyPair;
use enigma_tools_t::cryptography_t::Encryption;
use std::collections::HashMap;
use std::string::ToString;
use std::sync::SgxMutex;
use std::vec::Vec;
use std::u32;

pub(crate) use enigma_tools_t::km_primitives::{ContractAddress, Message, MessageType, MsgID, StateKey};
pub mod db;

lazy_static! { pub static ref DH_KEYS: SgxMutex< HashMap<MsgID, KeyPair >> = SgxMutex::new(HashMap::new()); }
lazy_static! { pub static ref STATE_KEYS: SgxMutex< HashMap<ContractAddress, StateKey >> = SgxMutex::new(HashMap::new()); }

pub(crate) unsafe fn ecall_ptt_req_internal(addresses: &[ContractAddress], sig: &mut [u8; 65]) -> Result<Vec<u8>, EnclaveError> {
    let keys = KeyPair::new()?;
    let data = MessageType::Request(addresses.to_vec());
    let req = Message::new(data, keys.get_pubkey())?;
    let msg = req.to_message()?;
    *sig = SIGNINING_KEY.sign(&msg[..])?;
    DH_KEYS.lock_expect("DH Keys").insert(req.get_id(), keys);
    Ok(msg)
}

pub(crate) fn ecall_ptt_res_internal(msg_slice: &[u8]) -> Result<(), EnclaveError> {
    let res = Message::from_message(msg_slice)?;

    let mut guard = DH_KEYS.lock_expect("DH Keys");
    let id = res.get_id();
    let msg;
    {
        let keys = guard.get(&id).ok_or(EnclaveError::KeyError{key_type: "dh keys".to_string(), key: "".to_string()})?;
        let aes = keys.get_aes_key(&res.get_pubkey())?;
        msg = Message::decrypt(res, &aes)?;
    }
    if let MessageType::Response(v) = msg.data {
        for (addr, key) in v {
            STATE_KEYS.lock_expect("state keys").insert(addr, key);
        }
    } else {
        unreachable!() // This should never execute.
    }
    guard.remove(&id);
    Ok(())
}


pub(crate) fn ecall_build_state_internal() -> Result<Vec<ContractAddress>, EnclaveError> {
    let guard = STATE_KEYS.lock_expect("State Keys");
    let mut failed_contracts = Vec::with_capacity(guard.len());

    'contract: for (addrs, key) in guard.iter() {
        // Get the state and decrypt it.
        // if no state exist create new one and if failed decrypting push to failed_contracts and move on.
        let mut state =  match runtime_ocalls_t::get_state(*addrs) {
            Ok(enc_state) => match ContractState::decrypt(enc_state, &key) {
                Ok(s) => s,
                Err(_) => {
                    failed_contracts.push(*addrs);
                    continue 'contract;
                }
            }, // don't throw error if only one failed, somehow tell that but continue
            Err(_) => ContractState::new(*addrs),
        };

        let mut start = state.delta_index;

        'deltas: while start < u32::MAX {
            let mut end = start+500;
            // Get deltas from start to end, if fails save the latest state and move on.
            let deltas = match runtime_ocalls_t::get_deltas(*addrs, start, end) {
                Ok(deltas) => deltas,
                Err(_) => { // If it failed to get deltas, encrypt the latest state and save it
                    let enc = match state.encrypt(key) {
                        Ok(s) => s,
                        Err(_) => { // If Failed to encrypt the latest state push to failed_contracts and move on.
                            failed_contracts.push(*addrs);
                            continue 'contract;
                        }
                    };
                    runtime_ocalls_t::save_state(&enc)?;
                    continue 'contract;
                }
            };
            let deltas_len = deltas.len();
            // decrypt the deltas and apply them to the state.
            // If failed, encrypt the latest state and move on.
            for delta in deltas {
                let patch = match StatePatch::decrypt(delta, key) {
                    Ok(p) => p,
                    Err(_) => {
                        let enc = match state.encrypt(key) {
                            Ok(s) => s,
                            Err(_) => { // If Failed to encrypt the latest state push to failed_contracts and move on.
                                failed_contracts.push(*addrs);
                                continue 'contract;
                            }
                        };
                        failed_contracts.push(*addrs);
                        runtime_ocalls_t::save_state(&enc)?;
                        continue 'contract;
                    }
                };

                match state.apply_delta(&patch) {
                    Err(_) => {
                        failed_contracts.push(*addrs);
                        continue 'contract;
                    }
                    _ => (),
                }
            }
            if deltas_len == (end-start) as usize { start = end; } else { start = u32::MAX; }
        }

        let enc = match state.encrypt(key) {
            Ok(d) => d,
            Err(_) => { // If Failed to encrypt the latest state push to failed_contracts and move on.
                failed_contracts.push(*addrs);
                continue 'contract;
            }
        };
        runtime_ocalls_t::save_state(&enc)?;
    }
    Ok(failed_contracts)
}

    Ok(())
}
