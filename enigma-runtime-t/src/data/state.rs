use crate::data::{DeltasInterface, IOInterface, StatePatch};
use enigma_tools_t::common::errors_t::{EnclaveError, EnclaveError::*, EnclaveSystemError::*};
use enigma_types::{ContractAddress, StateKey};
use enigma_crypto::{symmetric, Encryption};
use enigma_types::Hash256;
use json_patch;
use rmps::{Deserializer, Serializer};
use serde::{Deserialize, Serialize};
use serde_json::{from_value, Error, Value};
use std::string::ToString;
use std::vec::Vec;
use data::EncryptedPatch;

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize, Default)]
pub struct ContractState {
    #[serde(skip)]
    pub contract_address: ContractAddress,
    pub json: Value,
    pub delta_hash: Hash256,
    pub delta_index: u32,
}

#[derive(Debug, PartialEq, Clone)]
pub struct EncryptedContractState<T> {
    pub contract_address: ContractAddress,
    pub json: Vec<T>,
}

impl ContractState {
    pub fn new(contract_address: ContractAddress) -> ContractState {
        let json = serde_json::from_str("{}").unwrap();
        ContractState { contract_address, json,.. Default::default() }
    }

    pub fn is_initial(&self) -> bool{
        self.delta_index == 0 && self.delta_hash.is_zero()
    }
}

impl IOInterface<EnclaveError, u8> for ContractState {
    fn read_key<T>(&self, key: &str) -> Result<T, Error>
    where for<'de> T: Deserialize<'de> {
        from_value(self.json[key].clone())
    }

    fn write_key(&mut self, key: &str, value: &Value) -> Result<(), EnclaveError> {
        self.json[key] = value.clone();
        Ok(())
    }

    fn remove_key(&mut self, key: &str) {
        if let Some(ref mut v) = self.json.as_object_mut() {
            v.remove(key);
        }
    }
}

impl<'a> DeltasInterface<EnclaveError, EncryptedPatch, &'a StateKey> for ContractState {
    fn apply_delta(&mut self, delta: EncryptedPatch, key: &'a StateKey) -> Result<(), EnclaveError> {
        let delta_hash = delta.keccak256_patch();
        let dec_delta = StatePatch::decrypt(delta.clone(), key)?;
        if dec_delta.previous_hash != self.delta_hash {
            return Err(SystemError(StateError { err: "Hashes don't match, Failed Applying the delta".to_string() }));
        }
        json_patch::patch(&mut self.json, &dec_delta.patch)?;
        self.delta_hash = delta_hash;
        self.delta_index = dec_delta.index;
        Ok(())
    }

    fn generate_delta_and_update_state(old: &Self, new: &mut Self, key: &'a StateKey) -> Result<EncryptedPatch, EnclaveError> {
        if old.delta_hash.is_zero() {
            new.delta_index = 0;
        } else {
            new.delta_index = &old.delta_index+1;
        }
        let delta = StatePatch{
            patch: json_patch::diff(&old.json, &new.json),
            previous_hash: old.delta_hash,
            contract_address: old.contract_address,
            index: new.delta_index,
        };
        let enc_delta = delta.encrypt(key)?;
        new.delta_hash = enc_delta.keccak256_patch();
        Ok(enc_delta)
    }
}

impl<'a> Encryption<&'a StateKey, EnclaveError, EncryptedContractState<u8>, [u8; 12]> for ContractState {
    fn encrypt_with_nonce(self, key: &StateKey, _iv: Option<[u8; 12]>) -> Result<EncryptedContractState<u8>, EnclaveError> {
        let mut buf = Vec::new();
        self.serialize(&mut Serializer::new(&mut buf))?;
        let enc = symmetric::encrypt_with_nonce(&buf, key, _iv)?;
        Ok(EncryptedContractState { contract_address: self.contract_address, json: enc })
    }

    fn decrypt(enc: EncryptedContractState<u8>, key: &StateKey) -> Result<ContractState, EnclaveError> {
        let dec = symmetric::decrypt(&enc.json, key)?;
        let mut des = Deserializer::new(&dec[..]);
        let mut state: ContractState = Deserialize::deserialize(&mut des)?;
        state.contract_address = enc.contract_address;
        Ok(state)
    }
}
