use enigma_tools_t::cryptography_t::symmetric;
use enigma_tools_t::common::errors_t::EnclaveError;
use std::vec::Vec;
use std::string::ToString;
use serde_json::{Value, from_value, Error};
use data::{IOInterface, StatePatch, DeltasInterface, Encryption};
use serde::{Deserialize, Serialize};
use rmps::{Deserializer, Serializer};
use json_patch;


#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct ContractState {
    pub contract_id: [u8; 32],
    pub json: Value,
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
            json: Value::default(),
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
        json_patch::patch(&mut self.json, &delta.0)?;
        Ok( () )
    }
    // TODO: Why did I do that?. This should be 1 function, and if necessary another to wrap the first and just switch places. Or maybe even a class method?
    fn generate_delta(&self, old: Option<&Self>, new: Option<&Self>) -> Result<StatePatch, EnclaveError> {
        if old.is_some() { return Ok(StatePatch( json_patch::diff(&old.unwrap().json, &self.json) )) }

            else if new.is_some() { return Ok(StatePatch( json_patch::diff(&self.json, &new.unwrap().json) )) }

                else { return Err( EnclaveError::StateError {  err: "Generating a delta, Both old and new are None".to_string() } ) }

    }
}


impl<'a> Encryption<&'a [u8], EnclaveError, EncryptedContractState<u8>, [u8; 12]> for ContractState {
    fn encrypt(&self, key: &[u8]) -> Result<EncryptedContractState<u8>, EnclaveError> {
        self.encrypt_with_nonce(key, None)
    }
    fn encrypt_with_nonce(&self, key: &[u8], _iv: Option< [u8; 12] >) -> Result<EncryptedContractState<u8>, EnclaveError> {
        let mut buf = Vec::new();
        self.json.serialize(&mut Serializer::new(&mut buf))?;
        let enc = symmetric::encrypt_with_nonce(&buf, &key[..], _iv)?;
        Ok( EncryptedContractState {
            contract_id: self.contract_id.clone(),
            json: enc.clone()
        } )
    }
    fn decrypt(enc: &EncryptedContractState<u8>, key: &[u8]) -> Result<ContractState, EnclaveError> {
        let dec = symmetric::decrypt(&enc.json, &key[..])?;
        let mut des = Deserializer::new(&dec[..]);
        let json: Value = Deserialize::deserialize(&mut des)?;

        Ok ( ContractState {
            contract_id: enc.contract_id.clone(),
            json
        } )
    }
}