pub mod db;

use sgx_trts::trts::rsgx_read_rand;
use std::sync::SgxMutex;
use std::collections::HashMap;
use std::vec::Vec;
use std::slice;
use std::mem;
use enigma_tools_t::cryptography_t::asymmetric::KeyPair;
use crate::SIGNINING_KEY;
use crate::ocalls_t;
use enigma_types::EnclaveReturn;
use enigma_tools_t::common::utils_t::LockExpectMutex;
use enigma_tools_t::common::errors_t::EnclaveError;
pub(crate) use enigma_tools_t::km_primitives::{ContractAddress, StateKey, Request, MsgID};

lazy_static! { pub static ref DH_KEYS: SgxMutex< HashMap<MsgID, KeyPair >> = SgxMutex::new(HashMap::new()); }

lazy_static! { pub static ref State_Keys: SgxMutex< HashMap<ContractAddress, StateKey >> = SgxMutex::new(HashMap::new()); }



pub(crate) unsafe fn ecall_ptt_req_internal (addresses: &[ContractAddress], sig: &mut [u8; 65], serialized_ptr: *mut u64) -> Result<(), EnclaveError> {
    let keys = KeyPair::new()?;
    let req = Request::new(addresses.to_vec(), keys.get_pubkey())?;
    let msg = req.to_message()?;
    *sig = SIGNINING_KEY.sign(&msg[..])?;
    *serialized_ptr = ocalls_t::save_to_untrusted_memory(&msg[..])?;
    DH_KEYS.lock_expect("DH Keys").insert(req.get_id(), keys);
    Ok(())
}
