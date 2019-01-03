use crate::SIGNINING_KEY;
use enigma_tools_t::common::errors_t::EnclaveError;
use enigma_tools_t::common::utils_t::LockExpectMutex;
use enigma_tools_t::cryptography_t::asymmetric::KeyPair;
use std::vec::Vec;
use enigma_tools_t::km_primitives::{UserMessage, PubKey};
use std::sync::SgxMutex;
use std::collections::HashMap;

lazy_static! { pub static ref DH_KEYS: SgxMutex< HashMap<Vec<u8>, KeyPair> > = SgxMutex::new(HashMap::new()); }

pub(crate) unsafe fn ecall_get_user_key_internal(sig: &mut [u8; 65], user_pubkey: &PubKey) -> Result<Vec<u8>, EnclaveError> {
    let keys = KeyPair::new()?;
    let req = UserMessage::new(keys.get_pubkey());
    let msg = req.to_message()?;
    *sig = SIGNINING_KEY.sign(&msg[..])?;
    DH_KEYS.lock_expect("DH Keys").insert(user_pubkey.to_vec(), keys);
    Ok(msg)
}


pub fn get_encryption_key(user_key: &PubKey) -> Option<[u8; 32]> {
    let guard = DH_KEYS.lock_expect("users DH");
    let keypair = guard.get(&user_key[..])?;
    keypair.get_aes_key(user_key).ok()
}