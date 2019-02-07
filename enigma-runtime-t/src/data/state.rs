use crate::data::{DeltasInterface, IOInterface, StatePatch};
use enigma_tools_t::common::errors_t::EnclaveError;
use enigma_types::{ContractAddress, StateKey};
use enigma_crypto::{symmetric, Encryption};
use enigma_types::Hash256;
use json_patch;
use rmps::{Deserializer, Serializer};
use serde::{Deserialize, Serialize};
use serde_json::{from_value, Error, Value};
use std::string::ToString;
use std::vec::Vec;

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize, Default)]
pub struct ContractState {
    #[serde(skip)]
    pub contract_id: ContractAddress,
    pub json: Value,
    pub delta_hash: Hash256,
    pub delta_index: u32,
}

#[derive(Debug, PartialEq, Clone)]
pub struct EncryptedContractState<T> {
    pub contract_id: ContractAddress,
    pub json: Vec<T>,
}

impl ContractState {
    pub fn new(contract_id: ContractAddress) -> ContractState {
        ContractState { contract_id, .. Default::default() }
    }

    pub fn is_initial(&self) -> bool{
        self.delta_index == 0
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
}

impl DeltasInterface<EnclaveError, StatePatch> for ContractState {
    fn apply_delta(&mut self, delta: &StatePatch) -> Result<(), EnclaveError> {
        if delta.previous_hash != self.delta_hash {
            return Err(EnclaveError::StateError { err: "Applying the delta".to_string() });
        }
        json_patch::patch(&mut self.json, &delta.patch)?;
        self.delta_hash = delta.sha256_patch()?;
        Ok(())
    }

    fn generate_delta_and_update_state(old: &Self, new: &mut Self) -> Result<StatePatch, EnclaveError> {
        new.delta_index = &old.delta_index+1;
        let result = StatePatch{
            patch: json_patch::diff(&old.json, &new.json),
            previous_hash: old.delta_hash,
            contract_id: old.contract_id,
            index: old.delta_index + 1,
        };

        new.delta_hash = result.sha256_patch()?;
        Ok(result)
    }
}

impl<'a> Encryption<&'a StateKey, EnclaveError, EncryptedContractState<u8>, [u8; 12]> for ContractState {
    fn encrypt_with_nonce(self, key: &StateKey, _iv: Option<[u8; 12]>) -> Result<EncryptedContractState<u8>, EnclaveError> {
        let mut buf = Vec::new();
        self.serialize(&mut Serializer::new(&mut buf))?;
        let enc = symmetric::encrypt_with_nonce(&buf, key, _iv)?;
        Ok(EncryptedContractState { contract_id: self.contract_id, json: enc })
    }

    fn decrypt(enc: EncryptedContractState<u8>, key: &StateKey) -> Result<ContractState, EnclaveError> {
        let dec = symmetric::decrypt(&enc.json, key)?;
        let mut des = Deserializer::new(&dec[..]);
        let mut state: ContractState = Deserialize::deserialize(&mut des)?;
        state.contract_id = enc.contract_id;
        Ok(state)
    }
}
