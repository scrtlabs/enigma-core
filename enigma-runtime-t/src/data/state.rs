use enigma_tools_t::cryptography_t::{Encryption, symmetric};
use enigma_tools_t::common::errors_t::EnclaveError;
use std::vec::Vec;
use serde_json::{Value, from_value, Error};
use crate::data::{IOInterface, StatePatch, DeltasInterface};
use serde::{Deserialize, Serialize};
use rmps::{Deserializer, Serializer};
use json_patch;


// TODO: Add to the state the hash of the latest delta
// TODO: Check the hash when applying delta, and use it to make new deltas.
// TODO: Verify a delta using the new hash.
// TODO: Do this all over the code.

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize, Default)]
pub struct ContractState {
    #[serde(skip)]
    pub contract_id: [u8; 32],
    pub json: Value,
    pub delta_hash: [u8; 32],
}

#[derive(Debug, PartialEq, Clone)]
pub struct EncryptedContractState<T> {
    pub contract_id: [u8; 32],
    pub json: Vec<T>,
}


impl ContractState {
    pub fn new(contract_id: [u8; 32]) -> ContractState {
        ContractState {
            contract_id,
            .. Default::default()
        }
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
        json_patch::patch(&mut self.json, &delta.data)?;
        Ok( () )
    }

    fn generate_delta(old: &Self, new: &Self) -> Result<StatePatch, EnclaveError> {
        Ok(StatePatch{ data: json_patch::diff(&old.json, &new.json), previous_hash: [0u8; 32] })
    }
}


impl<'a> Encryption<&'a [u8], EnclaveError, EncryptedContractState<u8>, [u8; 12]> for ContractState {
    fn encrypt_with_nonce(self, key: &[u8], _iv: Option< [u8; 12] >) -> Result<EncryptedContractState<u8>, EnclaveError> {
        let mut buf = Vec::new();
        self.serialize(&mut Serializer::new(&mut buf))?;
        let enc = symmetric::encrypt_with_nonce(&buf, key, _iv)?;
        Ok( EncryptedContractState {
            contract_id: self.contract_id,
            json: enc,
        } )
    }
    fn decrypt(enc: EncryptedContractState<u8>, key: &[u8]) -> Result<ContractState, EnclaveError> {
        let dec = symmetric::decrypt(&enc.json, key)?;
        let mut des = Deserializer::new(&dec[..]);
        let mut state: ContractState = Deserialize::deserialize(&mut des)?;
        state.contract_id = enc.contract_id;
        Ok ( state )
    }
}