use crate::common::utils_t::Sha256;
use enigma_runtime_t::data::{ContractState, EncryptedContractState, EncryptedPatch, StatePatch};
use enigma_tools_t::cryptography_t::Encryption;

pub fn encrypt_delta(del: StatePatch) -> EncryptedPatch {
    let key = get_delta_key();
    del.encrypt(&key).unwrap()
}

pub fn get_delta_key() -> [u8; 32] { b"Enigma".sha256() }

pub fn encrypt_state(state: ContractState) -> EncryptedContractState<u8> {
    let key = get_state_key();
    state.encrypt(&key).unwrap()
    //TODO: Consume the state?
}

pub fn get_state_key() -> [u8; 32] { b"Enigma".sha256() }
