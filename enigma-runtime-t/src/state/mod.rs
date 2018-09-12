use serde_json::{Value, from_value, Error};
use std::string::{String, ToString};
use std::vec::Vec;
use serde::{Deserialize, Serialize};
use rmps::{Deserializer, Serializer};
use enigma_tools_t::common::errors_t::EnclaveError;
use json_patch;

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct StatePatch ( json_patch::Patch );

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct ContractState {
    contract_id: String,
    json: Value,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct StatePatch ( json_patch::Patch );

impl ContractState {

    pub fn new(contract_id: &str) -> ContractState {
        ContractState {
            contract_id: String::from(contract_id),
            json: Value::default(),
        }
    }
}


pub trait IOInterface<E, U> {
    fn read_key<T>(&self, key: &str) -> Result<T, Error> where for<'de> T: Deserialize<'de>;
    fn write_key(&mut self, key: &str, value: &Value) -> Result<(), E>;
}

pub trait DeltasInterface<E, T> {
    fn apply_delta(&mut self, delta: &T) -> Result<(), E>;
    fn generate_delta(&self, old: Option<&Self>, new: Option<&Self>) -> Result<T, E> where Self: Sized;
}

pub trait SerializeToVec<E, T> {
    fn serialize_to_vec(&self) -> Result<Vec<T>, E>;
    fn parse(ser: &Vec<T>) -> Result<Self, E> where Self: Sized;
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
    fn generate_delta(&self, old: Option<&Self>, new: Option<&Self>) -> Result<StatePatch, EnclaveError> {
        if old.is_some() { return Ok(StatePatch( json_patch::diff(&old.unwrap().json, &self.json) )) }

        else if new.is_some() { return Ok(StatePatch( json_patch::diff(&self.json, &new.unwrap().json) )) }

       else { return Err( EnclaveError::StateErr {  err: "Generating a delta, Both old and new are None".to_string() } ) }

    }
}


impl SerializeToVec<EnclaveError, u8> for StatePatch {
    fn serialize_to_vec(&self) -> Result< Vec<u8>, EnclaveError> {
        let mut buf = Vec::new();
        self.0.serialize(&mut Serializer::new(&mut buf))?;
        Ok(buf)
    }

    fn parse(ser: &Vec<u8>) -> Result<StatePatch, EnclaveError> {
        let mut de = Deserializer::new(&ser[..]);
        let back: StatePatch = Deserialize::deserialize(&mut de).unwrap();
        Ok(back)
    }
}

impl SerializeToVec<EnclaveError, u8> for ContractState {
    fn serialize_to_vec(&self) -> Result<Vec<u8>, EnclaveError> {
        let mut buf = Vec::new();
        self.serialize(&mut Serializer::new(&mut buf))?;
        Ok(buf)
    }

    fn parse(buf: &Vec<u8>) -> Result<ContractState, EnclaveError> {
        let mut de = Deserializer::new(&buf[..]);
        let backed: ContractState = Deserialize::deserialize(&mut de)?;
        Ok( backed )
    }

}


// TODO: All these macros should be in eng_wasm
macro_rules! write_state {
    ( $($key: expr => $val: expr),+ ) => {
        {
        // TODO: How do we maintain contract state?
        let mut con = ContractState::new( "Enigma" );
            $(
            // TODO: How are we handling errors in wasm?
                con.write_key($key, &json!($val)).unwrap();
            )+
        }
    }
}

macro_rules! read_state {
    ( $key: expr ) => {
        {
            let con = ContractState { contract_id: "Enigma".to_string(), json: json!({"Hey!": "We!"}) };
            con.read_key($key).unwrap()
        }
    }
}

pub mod tests {
    #[macro_use]
    use state::*;
    use std::string::{ToString, String};
    use std::vec::Vec;
    use serde_json::{Value, Map, self};
    use json_patch;

    pub fn test_macros() {
        write_state!("Hey!" => "We!");
        let a: String = read_state!("Hey!");
        assert_eq!(a, "We!");
    }
    pub fn test_serialize_state() {
        let con = ContractState {
            contract_id: "Enigma".to_string(),
            json: json!({"widget":{"debug":"on","window":{"title":"Sample Konfabulator Widget","name":"main_window","width":500,"height":500},"image":{"src":"Images/Sun.png","name":"sun1","hOffset":250,"vOffset":250,"alignment":"center"},"text":{"data":"Click Here","size":36,"style":"bold","name":"text1","hOffset":250,"vOffset":100,"alignment":"center","onMouseUp":"sun1.opacity = (sun1.opacity / 100) * 90;"}}}),
        };
        println!("{:?}", con.serialize_to_vec().unwrap());
        assert_eq!(con.serialize_to_vec().unwrap(), vec![129, 166, 119, 105, 100, 103, 101, 116, 132, 165, 100, 101, 98, 117, 103, 162, 111, 110, 165, 105, 109, 97, 103, 101, 133, 169, 97, 108, 105, 103, 110, 109, 101, 110, 116, 166, 99, 101, 110, 116, 101, 114, 167, 104, 79, 102, 102, 115, 101, 116, 204, 250, 164, 110, 97, 109, 101, 164, 115, 117, 110, 49, 163, 115, 114, 99, 174, 73, 109, 97, 103, 101, 115, 47, 83, 117, 110, 46, 112, 110, 103, 167, 118, 79, 102, 102, 115, 101, 116, 204, 250, 164, 116, 101, 120, 116, 136, 169, 97, 108, 105, 103, 110, 109, 101, 110, 116, 166, 99, 101, 110, 116, 101, 114, 164, 100, 97, 116, 97, 170, 67, 108, 105, 99, 107, 32, 72, 101, 114, 101, 167, 104, 79, 102, 102, 115, 101, 116, 204, 250, 164, 110, 97, 109, 101, 165, 116, 101, 120, 116, 49, 169, 111, 110, 77, 111, 117, 115, 101, 85, 112, 217, 41, 115, 117, 110, 49, 46, 111, 112, 97, 99, 105, 116, 121, 32, 61, 32, 40, 115, 117, 110, 49, 46, 111, 112, 97, 99, 105, 116, 121, 32, 47, 32, 49, 48, 48, 41, 32, 42, 32, 57, 48, 59, 164, 115, 105, 122, 101, 36, 165, 115, 116, 121, 108, 101, 164, 98, 111, 108, 100, 167, 118, 79, 102, 102, 115, 101, 116, 100, 166, 119, 105, 110, 100, 111, 119, 132, 166, 104, 101, 105, 103, 104, 116, 205, 1, 244, 164, 110, 97, 109, 101, 171, 109, 97, 105, 110, 95, 119, 105, 110, 100, 111, 119, 165, 116, 105, 116, 108, 101, 186, 83, 97, 109, 112, 108, 101, 32, 75, 111, 110, 102, 97, 98, 117, 108, 97, 116, 111, 114, 32, 87, 105, 100, 103, 101, 116, 165, 119, 105, 100, 116, 104, 205, 1, 244]);
    }

    pub fn test_deserialize_state() {
        let con = ContractState {
            contract_id: "Enigma".to_string(),
            json: json!({"widget":{"debug":"on","window":{"title":"Sample Konfabulator Widget","name":"main_window","width":500,"height":500},"image":{"src":"Images/Sun.png","name":"sun1","hOffset":250,"vOffset":250,"alignment":"center"},"text":{"data":"Click Here","size":36,"style":"bold","name":"text1","hOffset":250,"vOffset":100,"alignment":"center","onMouseUp":"sun1.opacity = (sun1.opacity / 100) * 90;"}}}),
        };

        assert_eq!(con, ContractState::parse(&vec![129, 166, 119, 105, 100, 103, 101, 116, 132, 165, 100, 101, 98, 117, 103, 162, 111, 110, 165, 105, 109, 97, 103, 101, 133, 169, 97, 108, 105, 103, 110, 109, 101, 110, 116, 166, 99, 101, 110, 116, 101, 114, 167, 104, 79, 102, 102, 115, 101, 116, 204, 250, 164, 110, 97, 109, 101, 164, 115, 117, 110, 49, 163, 115, 114, 99, 174, 73, 109, 97, 103, 101, 115, 47, 83, 117, 110, 46, 112, 110, 103, 167, 118, 79, 102, 102, 115, 101, 116, 204, 250, 164, 116, 101, 120, 116, 136, 169, 97, 108, 105, 103, 110, 109, 101, 110, 116, 166, 99, 101, 110, 116, 101, 114, 164, 100, 97, 116, 97, 170, 67, 108, 105, 99, 107, 32, 72, 101, 114, 101, 167, 104, 79, 102, 102, 115, 101, 116, 204, 250, 164, 110, 97, 109, 101, 165, 116, 101, 120, 116, 49, 169, 111, 110, 77, 111, 117, 115, 101, 85, 112, 217, 41, 115, 117, 110, 49, 46, 111, 112, 97, 99, 105, 116, 121, 32, 61, 32, 40, 115, 117, 110, 49, 46, 111, 112, 97, 99, 105, 116, 121, 32, 47, 32, 49, 48, 48, 41, 32, 42, 32, 57, 48, 59, 164, 115, 105, 122, 101, 36, 165, 115, 116, 121, 108, 101, 164, 98, 111, 108, 100, 167, 118, 79, 102, 102, 115, 101, 116, 100, 166, 119, 105, 110, 100, 111, 119, 132, 166, 104, 101, 105, 103, 104, 116, 205, 1, 244, 164, 110, 97, 109, 101, 171, 109, 97, 105, 110, 95, 119, 105, 110, 100, 111, 119, 165, 116, 105, 116, 108, 101, 186, 83, 97, 109, 112, 108, 101, 32, 75, 111, 110, 102, 97, 98, 117, 108, 97, 116, 111, 114, 32, 87, 105, 100, 103, 101, 116, 165, 119, 105, 100, 116, 104, 205, 1, 244]).unwrap());
    }

    pub fn test_reserialize_state() {
        let con = ContractState {
            contract_id: "Enigma".to_string(),
            json: json!({"widget":{"debug":"on","window":{"title":"Sample Konfabulator Widget","name":"main_window","width":500,"height":500},"image":{"src":"Images/Sun.png","name":"sun1","hOffset":250,"vOffset":250,"alignment":"center"},"text":{"data":"Click Here","size":36,"style":"bold","name":"text1","hOffset":250,"vOffset":100,"alignment":"center","onMouseUp":"sun1.opacity = (sun1.opacity / 100) * 90;"}}}),
        };
        let ser = con.serialize_to_vec().unwrap();
        let de = ContractState::parse(&ser).unwrap();

        assert_eq!(de, con);
    }

    pub fn test_write_state() {
        let mut con = ContractState::new("Enigma" );
        con.write_key("code", &json!(200)).unwrap();
        con.write_key("success", &json!(true)).unwrap();
        con.write_key("payload", &json!({ "features": ["serde", "json"] })).unwrap();

        let cmp = ContractState {
            contract_id: "Enigma".to_string(),
            json: json!({"code": 200,"success": true,"payload": {"features": ["serde","json"]}}),
        };
        assert_eq!(con, cmp);
    }

    pub fn test_read_state() {
        let con = ContractState {
            contract_id: "Enigma".to_string(),
            json: json!({"code": 200,"success": true,"payload": {"features": ["serde","json"]}}),
        };
        assert_eq!(con.read_key::<u64>("code").unwrap(), 200);
        assert_eq!(con.read_key::<bool>("success").unwrap(), true);
        assert_eq!(con.read_key::<Map<String, Value>>("payload").unwrap()["features"], json!(["serde","json"]));

    }

    pub fn test_diff_patch() {
        let before = json!({ "title": "Goodbye!","author" : { "name1" : "John", "name2" : "Doe"}, "tags":[ "first", "second" ] });
        let after = json!({ "author" : {"name1" : "John", "name2" : "Lennon"},"tags": [ "first", "second", "third"] });
        let patch = StatePatch( json_patch::diff(&before, &after) );
        assert_eq!(serde_json::to_string(&patch.0).unwrap(), "[{\"op\":\"replace\",\"path\":\"/author/name2\",\"value\":\"Lennon\"},{\"op\":\"add\",\"path\":\"/tags/2\",\"value\":\"third\"},{\"op\":\"remove\",\"path\":\"/title\"}]");
    }

    pub fn test_serialize_patch() {
        let s = "[{\"op\":\"replace\",\"path\":\"/author/name2\",\"value\":\"Lennon\"},{\"op\":\"add\",\"path\":\"/tags/2\",\"value\":\"third\"},{\"op\":\"remove\",\"path\":\"/title\"}]";
        let patch: StatePatch = serde_json::from_str(s).unwrap();
        let ser = patch.serialize_to_vec().unwrap();
        assert_eq!(ser, vec![129, 166, 119, 105, 100, 103, 101, 116, 132, 165, 100, 101, 98, 117, 103, 162, 111, 110, 165, 105, 109, 97, 103, 101, 133, 169, 97, 108, 105, 103, 110, 109, 101, 110, 116, 166, 99, 101, 110, 116, 101, 114, 167, 104, 79, 102, 102, 115, 101, 116, 204, 250, 164, 110, 97, 109, 101, 164, 115, 117, 110, 49, 163, 115, 114, 99, 174, 73, 109, 97, 103, 101, 115, 47, 83, 117, 110, 46, 112, 110, 103, 167, 118, 79, 102, 102, 115, 101, 116, 204, 250, 164, 116, 101, 120, 116, 136, 169, 97, 108, 105, 103, 110, 109, 101, 110, 116, 166, 99, 101, 110, 116, 101, 114, 164, 100, 97, 116, 97, 170, 67, 108, 105, 99, 107, 32, 72, 101, 114, 101, 167, 104, 79, 102, 102, 115, 101, 116, 204, 250, 164, 110, 97, 109, 101, 165, 116, 101, 120, 116, 49, 169, 111, 110, 77, 111, 117, 115, 101, 85, 112, 217, 41, 115, 117, 110, 49, 46, 111, 112, 97, 99, 105, 116, 121, 32, 61, 32, 40, 115, 117, 110, 49, 46, 111, 112, 97, 99, 105, 116, 121, 32, 47, 32, 49, 48, 48, 41, 32, 42, 32, 57, 48, 59, 164, 115, 105, 122, 101, 36, 165, 115, 116, 121, 108, 101, 164, 98, 111, 108, 100, 167, 118, 79, 102, 102, 115, 101, 116, 100, 166, 119, 105, 110, 100, 111, 119, 132, 166, 104, 101, 105, 103, 104, 116, 205, 1, 244, 164, 110, 97, 109, 101, 171, 109, 97, 105, 110, 95, 119, 105, 110, 100, 111, 119, 165, 116, 105, 116, 108, 101, 186, 83, 97, 109, 112, 108, 101, 32, 75, 111, 110, 102, 97, 98, 117, 108, 97, 116, 111, 114, 32, 87, 105, 100, 103, 101, 116, 165, 119, 105, 100, 116, 104, 205, 1, 244]);
    }

    pub fn test_deserialize_patch() {
        let s = "[{\"op\":\"replace\",\"path\":\"/author/name2\",\"value\":\"Lennon\"},{\"op\":\"add\",\"path\":\"/tags/2\",\"value\":\"third\"},{\"op\":\"remove\",\"path\":\"/title\"}]";
        let patch: StatePatch = serde_json::from_str(s).unwrap();
        let ser = patch.serialize_to_vec().unwrap();
        assert_eq!( patch, StatePatch::parse(&ser).unwrap() );
    }

    pub fn test_apply_delta() {
        let p = "[{\"op\":\"replace\",\"path\":\"/author/name2\",\"value\":\"Lennon\"},{\"op\":\"add\",\"path\":\"/tags/2\",\"value\":\"third\"},{\"op\":\"remove\",\"path\":\"/title\"}]";
        let patch: StatePatch = serde_json::from_str(p).unwrap();
        let mut contract = ContractState{
            contract_id: "Enigma".to_string(),
            json: json!({ "title": "Goodbye!","author" : { "name1" : "John", "name2" : "Doe"}, "tags":[ "first", "second" ] }),
        };
        contract.apply_delta(&patch).unwrap();
        assert_eq!(contract, ContractState { contract_id: "Enigma".to_string(),  json: json!({ "author" : {"name1" : "John", "name2" : "Lennon"},"tags": [ "first", "second", "third"] }) } );
    }

    pub fn test_generate_delta() {
        let p = "[{\"op\":\"replace\",\"path\":\"/author/name2\",\"value\":\"Lennon\"},{\"op\":\"add\",\"path\":\"/tags/2\",\"value\":\"third\"},{\"op\":\"remove\",\"path\":\"/title\"}]";
        let result: StatePatch = serde_json::from_str(p).unwrap();
        let id = "Enigma".to_string();
        let before = ContractState {
            contract_id: id.clone(),
            json: json!({ "title": "Goodbye!","author" : { "name1" : "John", "name2" : "Doe"}, "tags":[ "first", "second" ] }),
        };
        let after = ContractState {
            contract_id: id.clone(),
            json: json!({ "author" : {"name1" : "John", "name2" : "Lennon"},"tags": [ "first", "second", "third"] }),
        };

        let delta_old = after.generate_delta(Some(&before), None).unwrap();
        let delta_new = before.generate_delta(None, Some(&after)).unwrap();
        assert!(delta_old == result && result == delta_new);
    }
}