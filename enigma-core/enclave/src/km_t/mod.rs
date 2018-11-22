pub mod db;

use std::sync::SgxMutex;
use std::collections::HashMap;
use std::string::ToString;
use enigma_tools_t::cryptography_t::asymmetric::KeyPair;
use crate::SIGNINING_KEY;
use crate::ocalls_t;
use enigma_tools_t::common::utils_t::LockExpectMutex;
use enigma_tools_t::common::errors_t::EnclaveError;
use enigma_tools_t::cryptography_t::Encryption;

pub(crate) use enigma_tools_t::km_primitives::{ContractAddress, StateKey, Message, MsgID, MessageType};

lazy_static! { pub static ref DH_KEYS: SgxMutex< HashMap<MsgID, KeyPair >> = SgxMutex::new(HashMap::new()); }
lazy_static! { pub static ref STATE_KEYS: SgxMutex< HashMap<ContractAddress, StateKey >> = SgxMutex::new(HashMap::new()); }

pub(crate) unsafe fn ecall_ptt_req_internal(addresses: &[ContractAddress], sig: &mut [u8; 65], serialized_ptr: *mut u64) -> Result<(), EnclaveError> {
    let keys = KeyPair::new()?;
    let data = MessageType::Request(addresses.to_vec());
    let req = Message::new(data, keys.get_pubkey())?;
    let msg = req.to_message()?;
    *sig = SIGNINING_KEY.sign(&msg[..])?;
    *serialized_ptr = ocalls_t::save_to_untrusted_memory(&msg[..])?;
    DH_KEYS.lock_expect("DH Keys").insert(req.get_id(), keys);
    Ok(())
}

pub(crate) fn ecall_ptt_res_internal(msg_slice: &[u8]) -> Result<(), EnclaveError> {
    let res = Message::from_message(msg_slice)?;

    let mut guard = DH_KEYS.lock_expect("DH Keys");
    let id = res.get_id();
    let msg;
    {
        let keys = guard.get(&id).ok_or(EnclaveError::KeyError{key_type: "dh keys".to_string(), key: "".to_string()})?;
        let aes = keys.get_aes_key(&res.get_pubkey())?;
        msg = Message::decrypt(res, &aes[..])?;
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


pub(crate) fn ecall_build_state_internal() -> Result<(), EnclaveError> {
    let guard = STATE_KEYS.lock_expect("DH Keys");

    for (addrs, key) in guard.iter() {


    }

    Ok(())
}
