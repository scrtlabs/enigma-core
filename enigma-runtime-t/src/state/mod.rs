use serde_json::Value;
use std::option::Option;

struct ContractState {
    contract_id: String,
    json: Value,
}

pub trait ContractStateInterface {
    fn new(contract_id: String) -> ContractState;
    fn read_key(&self, key: &str) -> Value;
    fn write_key(&mut self, key: &str, value: Value) -> Option;
}

impl ContractStateInterface for ContractState {

    fn new(contract_id: String) -> ContractState {
        ContractState {
            contract_id,
            json: Value::Default()
        }
    }

    fn read_key(&self, key: &str) -> Value {
        self[key]
    }

    fn write_key(&mut self, key: &str, value: Value) -> Option {
        self[key] = value;
        None
    }
}