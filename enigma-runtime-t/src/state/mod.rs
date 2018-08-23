use serde_json::{Value, from_value, Error};
use std::string::String;
use std::vec::Vec;
use serde::{Deserialize, Serialize};
use rmps::{Deserializer, Serializer};
use enigma_tools_t::common::errors_t::EnclaveError;

#[derive(Debug, PartialEq, Clone)]
pub struct ContractState {
    contract_id: String,
    json: Value,
}

pub trait ContractStateInterface {
    fn new(contract_id: &str) -> ContractState;
    fn parse(contract_id: &str, buf: Vec<u8>) -> Result<ContractState, EnclaveError>;
    fn read_key<T>(&self, key: &str) -> Result<T, Error> where for<'de> T: Deserialize<'de>;
    fn write_key(&mut self, key: &str, value: Value) -> Result<(), EnclaveError>;
    fn serialize(&self) -> Result<Vec<u8>, EnclaveError>;
}

impl ContractStateInterface for ContractState {

    fn new(contract_id: &str) -> ContractState {
        ContractState {
            contract_id: String::from(contract_id),
            json: Value::default()
        }
    }

    fn parse(contract_id: &str, buf: Vec<u8>) -> Result<ContractState, EnclaveError> {
        let mut de = Deserializer::new(&buf[..]);
        let backed: Value = Deserialize::deserialize(&mut de)?;

        Ok(ContractState {
            contract_id: String::from(contract_id),
            json: backed
        })
    }

    fn read_key<T>(&self, key: &str) -> Result<T, Error>
    where for<'de> T: Deserialize<'de> {
        from_value(self.json[key].clone())
    }

    fn write_key(&mut self, key: &str, value: Value) -> Result<(), EnclaveError>{
        self.json[key] = value;
        Ok(())
    }

    fn serialize(&self) -> Result<Vec<u8>, EnclaveError> {
        let mut buf = Vec::new();
        self.json.serialize(&mut Serializer::new(&mut buf))?;
        Ok(buf)
    }

    fn read_key(&self, key: &str) -> Value {
        self[key]
    }

    fn write_key(&mut self, key: &str, value: Value) -> Option {
        self[key] = value;
        None
    }
}