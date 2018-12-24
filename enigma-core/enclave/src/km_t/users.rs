use crate::SIGNINING_KEY;
use super::DH_KEYS;
use enigma_tools_t::common::errors_t::EnclaveError;
use enigma_tools_t::common::utils_t::LockExpectMutex;
use enigma_tools_t::cryptography_t::asymmetric::KeyPair;
use std::vec::Vec;
use enigma_tools_t::km_primitives::Message;


pub(crate) unsafe fn ecall_get_user_key_internal(sig: &mut [u8; 65]) -> Result<Vec<u8>, EnclaveError> {
    let keys = KeyPair::new()?;
    let req = Message::new(None, keys.get_pubkey())?;
    let msg = req.to_message()?;
    *sig = SIGNINING_KEY.sign(&msg[..])?;
    DH_KEYS.lock_expect("DH Keys").insert(req.get_id(), keys);
    Ok(msg)
}





