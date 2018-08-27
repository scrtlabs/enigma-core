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

impl ContractState {

    pub fn new(contract_id: &str) -> ContractState {
        ContractState {
            contract_id: String::from(contract_id),
            json: Value::default()
        }
    }

    pub fn parse(contract_id: &str, buf: Vec<u8>) -> Result<ContractState, EnclaveError> {
        let mut de = Deserializer::new(&buf[..]);
        let backed: Value = Deserialize::deserialize(&mut de)?;

        Ok(ContractState {
            contract_id: String::from(contract_id),
            json: backed
        })
    }
}


pub trait IOInterface {
    fn read_key<T>(&self, key: &str) -> Result<T, Error> where for<'de> T: Deserialize<'de>;
    fn write_key(&mut self, key: &str, value: Value) -> Result<(), EnclaveError>;
    fn serialize(&self) -> Result<Vec<u8>, EnclaveError>;
}

impl IOInterface for ContractState {

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

}


pub mod tests {
    use state::*;
    use std::string::ToString;
    use serde_json::{Value, Map};

    pub fn test_serialization() {
        let con = ContractState {
            contract_id: "Enigma".to_string(),
            json: json!({"widget":{"debug":"on","window":{"title":"Sample Konfabulator Widget","name":"main_window","width":500,"height":500},"image":{"src":"Images/Sun.png","name":"sun1","hOffset":250,"vOffset":250,"alignment":"center"},"text":{"data":"Click Here","size":36,"style":"bold","name":"text1","hOffset":250,"vOffset":100,"alignment":"center","onMouseUp":"sun1.opacity = (sun1.opacity / 100) * 90;"}}})
        };
        assert_eq!(con.serialize().unwrap(), vec![129, 166, 119, 105, 100, 103, 101, 116, 132, 165, 100, 101, 98, 117, 103, 162, 111, 110, 165, 105, 109, 97, 103, 101, 133, 169, 97, 108, 105, 103, 110, 109, 101, 110, 116, 166, 99, 101, 110, 116, 101, 114, 167, 104, 79, 102, 102, 115, 101, 116, 204, 250, 164, 110, 97, 109, 101, 164, 115, 117, 110, 49, 163, 115, 114, 99, 174, 73, 109, 97, 103, 101, 115, 47, 83, 117, 110, 46, 112, 110, 103, 167, 118, 79, 102, 102, 115, 101, 116, 204, 250, 164, 116, 101, 120, 116, 136, 169, 97, 108, 105, 103, 110, 109, 101, 110, 116, 166, 99, 101, 110, 116, 101, 114, 164, 100, 97, 116, 97, 170, 67, 108, 105, 99, 107, 32, 72, 101, 114, 101, 167, 104, 79, 102, 102, 115, 101, 116, 204, 250, 164, 110, 97, 109, 101, 165, 116, 101, 120, 116, 49, 169, 111, 110, 77, 111, 117, 115, 101, 85, 112, 217, 41, 115, 117, 110, 49, 46, 111, 112, 97, 99, 105, 116, 121, 32, 61, 32, 40, 115, 117, 110, 49, 46, 111, 112, 97, 99, 105, 116, 121, 32, 47, 32, 49, 48, 48, 41, 32, 42, 32, 57, 48, 59, 164, 115, 105, 122, 101, 36, 165, 115, 116, 121, 108, 101, 164, 98, 111, 108, 100, 167, 118, 79, 102, 102, 115, 101, 116, 100, 166, 119, 105, 110, 100, 111, 119, 132, 166, 104, 101, 105, 103, 104, 116, 205, 1, 244, 164, 110, 97, 109, 101, 171, 109, 97, 105, 110, 95, 119, 105, 110, 100, 111, 119, 165, 116, 105, 116, 108, 101, 186, 83, 97, 109, 112, 108, 101, 32, 75, 111, 110, 102, 97, 98, 117, 108, 97, 116, 111, 114, 32, 87, 105, 100, 103, 101, 116, 165, 119, 105, 100, 116, 104, 205, 1, 244]);
    }

    pub fn test_deserialization() {
        let con = ContractState {
            contract_id: "Enigma".to_string(),
            json: json!({"widget":{"debug":"on","window":{"title":"Sample Konfabulator Widget","name":"main_window","width":500,"height":500},"image":{"src":"Images/Sun.png","name":"sun1","hOffset":250,"vOffset":250,"alignment":"center"},"text":{"data":"Click Here","size":36,"style":"bold","name":"text1","hOffset":250,"vOffset":100,"alignment":"center","onMouseUp":"sun1.opacity = (sun1.opacity / 100) * 90;"}}})
        };

        assert_eq!(con, ContractState::parse("Enigma", vec![129, 166, 119, 105, 100, 103, 101, 116, 132, 165, 100, 101, 98, 117, 103, 162, 111, 110, 165, 105, 109, 97, 103, 101, 133, 169, 97, 108, 105, 103, 110, 109, 101, 110, 116, 166, 99, 101, 110, 116, 101, 114, 167, 104, 79, 102, 102, 115, 101, 116, 204, 250, 164, 110, 97, 109, 101, 164, 115, 117, 110, 49, 163, 115, 114, 99, 174, 73, 109, 97, 103, 101, 115, 47, 83, 117, 110, 46, 112, 110, 103, 167, 118, 79, 102, 102, 115, 101, 116, 204, 250, 164, 116, 101, 120, 116, 136, 169, 97, 108, 105, 103, 110, 109, 101, 110, 116, 166, 99, 101, 110, 116, 101, 114, 164, 100, 97, 116, 97, 170, 67, 108, 105, 99, 107, 32, 72, 101, 114, 101, 167, 104, 79, 102, 102, 115, 101, 116, 204, 250, 164, 110, 97, 109, 101, 165, 116, 101, 120, 116, 49, 169, 111, 110, 77, 111, 117, 115, 101, 85, 112, 217, 41, 115, 117, 110, 49, 46, 111, 112, 97, 99, 105, 116, 121, 32, 61, 32, 40, 115, 117, 110, 49, 46, 111, 112, 97, 99, 105, 116, 121, 32, 47, 32, 49, 48, 48, 41, 32, 42, 32, 57, 48, 59, 164, 115, 105, 122, 101, 36, 165, 115, 116, 121, 108, 101, 164, 98, 111, 108, 100, 167, 118, 79, 102, 102, 115, 101, 116, 100, 166, 119, 105, 110, 100, 111, 119, 132, 166, 104, 101, 105, 103, 104, 116, 205, 1, 244, 164, 110, 97, 109, 101, 171, 109, 97, 105, 110, 95, 119, 105, 110, 100, 111, 119, 165, 116, 105, 116, 108, 101, 186, 83, 97, 109, 112, 108, 101, 32, 75, 111, 110, 102, 97, 98, 117, 108, 97, 116, 111, 114, 32, 87, 105, 100, 103, 101, 116, 165, 119, 105, 100, 116, 104, 205, 1, 244]).unwrap());
    }

    pub fn test_reserialization() {
        let con = ContractState {
            contract_id: "Enigma".to_string(),
            json: json!({"widget":{"debug":"on","window":{"title":"Sample Konfabulator Widget","name":"main_window","width":500,"height":500},"image":{"src":"Images/Sun.png","name":"sun1","hOffset":250,"vOffset":250,"alignment":"center"},"text":{"data":"Click Here","size":36,"style":"bold","name":"text1","hOffset":250,"vOffset":100,"alignment":"center","onMouseUp":"sun1.opacity = (sun1.opacity / 100) * 90;"}}})
        };
        let ser = con.serialize().unwrap();
        let de = ContractState::parse("Enigma", ser).unwrap();

        assert_eq!(de, con);
    }

    pub fn test_write() {
        let mut con = ContractState::new("Enigma");
        con.write_key("code", json!(200)).unwrap();
        con.write_key("success", json!(true)).unwrap();
        con.write_key("payload", json!({ "features": ["serde", "json"] })).unwrap();

        let cmp = ContractState {
            contract_id: "Enigma".to_string(),
            json: json!({"code": 200,"success": true,"payload": {"features": ["serde","json"]}})
        };
        assert_eq!(con, cmp);
    }

    pub fn test_read() {
        let con = ContractState {
            contract_id: "Enigma".to_string(),
            json: json!({"code": 200,"success": true,"payload": {"features": ["serde","json"]}})
        };
        assert_eq!(con.read_key::<u64>("code").unwrap(), 200);
        assert_eq!(con.read_key::<bool>("success").unwrap(), true);
        assert_eq!(con.read_key::<Map<String, Value>>("payload").unwrap()["features"], json!(["serde","json"]));

    }
}