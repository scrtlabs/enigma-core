pub(crate) mod principal;
pub(crate) mod users;

pub(crate) use self::principal::{ecall_build_state_internal, ecall_ptt_req_internal, ecall_ptt_res_internal};
pub(crate) use self::users::ecall_get_user_key_internal;

use enigma_runtime_t::data::{ContractState, EncryptedContractState};
use enigma_runtime_t::ocalls_t as runtime_ocalls_t;
use enigma_tools_t::common::errors_t::EnclaveError;
use enigma_tools_m::utils::LockExpectMutex;
use enigma_crypto::{Encryption, CryptoError};
use enigma_types::{ContractAddress, RawPointer, StateKey};
use std::collections::HashMap;
use std::sync::SgxMutex;

lazy_static! {
    pub static ref STATE_KEYS: SgxMutex<HashMap<ContractAddress, StateKey>> = SgxMutex::new(HashMap::new());
}

pub fn get_state_key(address: ContractAddress) -> Result<StateKey, EnclaveError> {
//    let statekeys_guard = STATE_KEYS.lock_expect("State Keys");
//    statekeys_guard
//        .get(&address)
//        .copied()
//        .ok_or_else(|| CryptoError::MissingKeyError { key_type: "State Key" }.into())
      let state_key: [u8; 32] = [1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32];
      Ok(state_key)
}

pub fn encrypt_state(state: ContractState) -> Result<EncryptedContractState<u8>, EnclaveError> {
//    let state_keys_guard = STATE_KEYS.lock_expect("State Keys");
//    let key = state_keys_guard
//        .get(&state.contract_address)
//        .ok_or(CryptoError::MissingKeyError { key_type: "State Key" })?;
    let key: [u8; 32] = [1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32];
    state.encrypt(&key)
}

pub fn get_state(db_ptr: *const RawPointer, addr: ContractAddress) -> Result<ContractState, EnclaveError> {
//    let guard = STATE_KEYS.lock_expect("State Keys");
//    let key = guard.get(&addr).ok_or(CryptoError::MissingKeyError { key_type: "State Key" })?;

    let key: [u8; 32] = [1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32];
    let enc_state = runtime_ocalls_t::get_state(db_ptr, addr)?;
    let state = ContractState::decrypt(enc_state, &key)?;

    Ok(state)
}
