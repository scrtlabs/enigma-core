pub(crate) mod principal;
pub(crate) mod users;

pub(crate) use self::principal::{ecall_build_state_internal, ecall_ptt_req_internal, ecall_ptt_res_internal};
pub(crate) use self::users::ecall_get_user_key_internal;

use enigma_runtime_t::data::{ContractState, EncryptedContractState, EncryptedPatch, StatePatch};
use enigma_tools_t::common::errors_t::EnclaveError;
use enigma_tools_t::common::LockExpectMutex;
use enigma_crypto::{Encryption, CryptoError};
use enigma_types::{ContractAddress, StateKey};
use std::collections::HashMap;
use std::string::ToString;
use std::sync::SgxMutex;

lazy_static! {
    pub static ref STATE_KEYS: SgxMutex<HashMap<ContractAddress, StateKey>> = SgxMutex::new(HashMap::new());
}

pub fn encrypt_delta(del: StatePatch) -> Result<EncryptedPatch, EnclaveError> {
    let statekeys_guard = STATE_KEYS.lock_expect("State Keys");
    let key = statekeys_guard
        .get(&del.contract_address)
        .ok_or(CryptoError::KeyError { key_type: "State Key".to_string(), err: "Missing".to_string() })?;
    del.encrypt(&key)
}

pub fn encrypt_state(state: ContractState) -> Result<EncryptedContractState<u8>, EnclaveError> {
    let statekeys_guard = STATE_KEYS.lock_expect("State Keys");
    let key = statekeys_guard
        .get(&state.contract_address)
        .ok_or(CryptoError::KeyError { key_type: "State Key".to_string(), err: "Missing".to_string() })?;
    state.encrypt(&key)
}
