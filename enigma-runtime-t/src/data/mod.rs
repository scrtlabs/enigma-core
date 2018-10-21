mod delta;
mod state;

pub use data::delta::{StatePatch, EncryptedPatch};
pub use data::state::{ContractState, EncryptedContractState};
use serde_json::{Error, Value};
use serde::Deserialize;
use std::vec::Vec;

pub trait IOInterface<E, U> {
    fn read_key<T>(&self, key: &str) -> Result<T, Error> where for<'de> T: Deserialize<'de>;
    fn write_key(&mut self, key: &str, value: &Value) -> Result<(), E>;
}

pub trait DeltasInterface<E, T> {
    fn apply_delta(&mut self, delta: &T) -> Result<(), E>;
    fn generate_delta(&self, old: Option<&Self>, new: Option<&Self>) -> Result<T, E> where Self: Sized;
}

pub trait Encryption<T, E, R, N> {
    fn encrypt(&self, key: T) -> Result<R, E> where R: Sized;
    fn encrypt_with_nonce(&self, key: T, _iv: Option< &N>) -> Result<R, E> where R: Sized;
    fn decrypt(enc: &R, key: T) -> Result<Self, E> where Self: Sized;
}


// TODO: All these macros should be in eng_wasm
macro_rules! write_state {
    ( $($key: expr => $val: expr),+ ) => {
        {
        // TODO: How do we maintain contract state?
        let mut con = ContractState::new( b"Enigma".sha256() );
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
            let con = ContractState { contract_id: b"Enigma".sha256(), json: json!({"Hey!": "We!"}) };
            con.read_key($key).unwrap()
        }
    }
}

pub mod tests {
//    #[macro_use]
    use data::*;
    use std::string::String;
    use serde_json::{Value, Map, self};
    use json_patch;
    use enigma_tools_t::common::utils_t::Sha256;

    pub fn test_macros() {
        write_state!("Hey!" => "We!");
        let a: String = read_state!("Hey!");
        assert_eq!(a, "We!");
    }

    pub fn test_encrypt_state() {
        let id = b"Enigma".sha256();
        let con = ContractState {
            contract_id: id.clone(),
            json: json!({"widget":{"debug":"on","window":{"title":"Sample Konfabulator Widget","name":"main_window","width":500,"height":500},"image":{"src":"Images/Sun.png","name":"sun1","hOffset":250,"vOffset":250,"alignment":"center"},"text":{"data":"Click Here","size":36,"style":"bold","name":"text1","hOffset":250,"vOffset":100,"alignment":"center","onMouseUp":"sun1.opacity = (sun1.opacity / 100) * 90;"}}}),
        };
        let key = b"EnigmaMPC".sha256();
        let iv = [0,1,2,3,4,5,6,7,8,9,10,11];

        let enc_json = vec![215, 18, 107, 35, 28, 119, 236, 243, 75, 146, 131, 19, 155, 72, 164, 66, 80, 170, 84, 3, 35, 201, 202, 190, 74, 191, 203, 12, 19, 212, 170, 28, 211, 254, 8, 37, 129, 81, 171, 255, 108, 133, 117, 41, 189, 223, 169, 148, 180, 186, 123, 179, 38, 105, 24, 51, 170, 30, 119, 41, 216, 132, 156, 197, 183, 105, 14, 131, 142, 77, 205, 8, 17, 139, 152, 196, 117, 216, 241, 102, 227, 171, 158, 39, 228, 4, 232, 98, 253, 149, 139, 31, 177, 182, 199, 130, 233, 217, 38, 156, 203, 196, 157, 68, 171, 26, 225, 129, 58, 143, 42, 127, 97, 158, 93, 55, 214, 123, 232, 240, 250, 44, 168, 203, 156, 207, 172, 211, 169, 52, 241, 219, 186, 94, 201, 111, 185, 180, 219, 222, 123, 201, 167, 154, 173, 54, 51, 242, 121, 136, 203, 254, 135, 68, 127, 14, 248, 187, 99, 223, 19, 184, 108, 182, 230, 191, 89, 255, 103, 127, 183, 89, 166, 37, 93, 56, 147, 68, 184, 19, 20, 150, 241, 5, 45, 120, 254, 238, 164, 26, 154, 232, 54, 213, 1, 215, 248, 58, 172, 41, 195, 147, 68, 83, 34, 208, 23, 127, 95, 240, 87, 53, 202, 60, 224, 60, 209, 225, 33, 65, 193, 204, 185, 207, 146, 221, 251, 161, 31, 144, 237, 152, 209, 130, 146, 177, 37, 54, 107, 137, 111, 191, 134, 92, 0, 5, 46, 252, 136, 105, 37, 49, 143, 144, 45, 104, 79, 157, 87, 177, 199, 172, 67, 245, 44, 163, 102, 103, 240, 41, 159, 215, 149, 182, 103, 92, 144, 213, 112, 5, 248, 129, 128, 0, 55, 185, 137, 255, 87, 138, 231, 128, 222, 235, 253, 136, 166, 187, 21, 73, 238, 116, 89, 96, 3, 140, 193, 168, 142, 8, 247, 167, 246, 89, 199, 214, 199, 61, 92, 44, 203, 209, 211, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];
        assert_eq!(EncryptedContractState { contract_id: id.clone(), json: enc_json }, con.encrypt_with_nonce(&key, Some( &iv )).unwrap() )
    }

    pub fn test_decrypt_state() {
        let key = b"EnigmaMPC".sha256();
        let enc_json = vec![215, 18, 107, 35, 28, 119, 236, 243, 75, 146, 131, 19, 155, 72, 164, 66, 80, 170, 84, 3, 35, 201, 202, 190, 74, 191, 203, 12, 19, 212, 170, 28, 211, 254, 8, 37, 129, 81, 171, 255, 108, 133, 117, 41, 189, 223, 169, 148, 180, 186, 123, 179, 38, 105, 24, 51, 170, 30, 119, 41, 216, 132, 156, 197, 183, 105, 14, 131, 142, 77, 205, 8, 17, 139, 152, 196, 117, 216, 241, 102, 227, 171, 158, 39, 228, 4, 232, 98, 253, 149, 139, 31, 177, 182, 199, 130, 233, 217, 38, 156, 203, 196, 157, 68, 171, 26, 225, 129, 58, 143, 42, 127, 97, 158, 93, 55, 214, 123, 232, 240, 250, 44, 168, 203, 156, 207, 172, 211, 169, 52, 241, 219, 186, 94, 201, 111, 185, 180, 219, 222, 123, 201, 167, 154, 173, 54, 51, 242, 121, 136, 203, 254, 135, 68, 127, 14, 248, 187, 99, 223, 19, 184, 108, 182, 230, 191, 89, 255, 103, 127, 183, 89, 166, 37, 93, 56, 147, 68, 184, 19, 20, 150, 241, 5, 45, 120, 254, 238, 164, 26, 154, 232, 54, 213, 1, 215, 248, 58, 172, 41, 195, 147, 68, 83, 34, 208, 23, 127, 95, 240, 87, 53, 202, 60, 224, 60, 209, 225, 33, 65, 193, 204, 185, 207, 146, 221, 251, 161, 31, 144, 237, 152, 209, 130, 146, 177, 37, 54, 107, 137, 111, 191, 134, 92, 0, 5, 46, 252, 136, 105, 37, 49, 143, 144, 45, 104, 79, 157, 87, 177, 199, 172, 67, 245, 44, 163, 102, 103, 240, 41, 159, 215, 149, 182, 103, 92, 144, 213, 112, 5, 248, 129, 128, 0, 55, 185, 137, 255, 87, 138, 231, 128, 222, 235, 253, 136, 166, 187, 21, 73, 238, 116, 89, 96, 3, 140, 193, 168, 142, 8, 247, 167, 246, 89, 199, 214, 199, 61, 92, 44, 203, 209, 211, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];
        let id = b"Enigma".sha256();
        let enc = EncryptedContractState { contract_id: id.clone(), json: enc_json };
        let result = ContractState {
            contract_id: id.clone(),
            json: json!({"widget":{"debug":"on","window":{"title":"Sample Konfabulator Widget","name":"main_window","width":500,"height":500},"image":{"src":"Images/Sun.png","name":"sun1","hOffset":250,"vOffset":250,"alignment":"center"},"text":{"data":"Click Here","size":36,"style":"bold","name":"text1","hOffset":250,"vOffset":100,"alignment":"center","onMouseUp":"sun1.opacity = (sun1.opacity / 100) * 90;"}}}),
        };

        assert_eq!(ContractState::decrypt(&enc, &key).unwrap(), result)
    }

    pub fn test_encrypt_decrypt_state() {
        let id = b"Enigma".sha256();
        let con = ContractState {
            contract_id: id.clone(),
            json: json!({"widget":{"debug":"on","window":{"title":"Sample Konfabulator Widget","name":"main_window","width":500,"height":500},"image":{"src":"Images/Sun.png","name":"sun1","hOffset":250,"vOffset":250,"alignment":"center"},"text":{"data":"Click Here","size":36,"style":"bold","name":"text1","hOffset":250,"vOffset":100,"alignment":"center","onMouseUp":"sun1.opacity = (sun1.opacity / 100) * 90;"}}}),
        };
        let key = b"EnigmaMPC".sha256();
        let iv = [0,1,2,3,4,5,6,7,8,9,10,11];

        let enc = con.encrypt_with_nonce(&key, Some( &iv )).unwrap();
        assert_eq!( ContractState::decrypt(&enc, &key).unwrap(), con )

    }

    pub fn test_write_state() {
        let mut con = ContractState::new(b"Enigma".sha256() );
        con.write_key("code", &json!(200)).unwrap();
        con.write_key("success", &json!(true)).unwrap();
        con.write_key("payload", &json!({ "features": ["serde", "json"] })).unwrap();

        let cmp = ContractState {
            contract_id: b"Enigma".sha256(),
            json: json!({"code": 200,"success": true,"payload": {"features": ["serde","json"]}}),
        };
        assert_eq!(con, cmp);
    }

    pub fn test_read_state() {
        let con = ContractState {
            contract_id: b"Enigma".sha256(),
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

    pub fn test_encrypt_patch() {
        let s = "[{\"op\":\"replace\",\"path\":\"/author/name2\",\"value\":\"Lennon\"},{\"op\":\"add\",\"path\":\"/tags/2\",\"value\":\"third\"},{\"op\":\"remove\",\"path\":\"/title\"}]";
        let patch: StatePatch = serde_json::from_str(s).unwrap();

        let key = b"EnigmaMPC".sha256();
        let iv = [0,1,2,3,4,5,6,7,8,9,10,11];

        let enc_data = vec![197, 39, 187, 56, 29, 96, 229, 230, 172, 82, 74, 89, 152, 72, 183, 136, 80, 182, 222, 4, 47, 197, 200, 233, 105, 90, 207, 14, 20, 220, 170, 226, 21, 241, 24, 231, 69, 27, 177, 234, 110, 132, 253, 115, 87, 205, 167, 142, 163, 170, 37, 239, 240, 98, 20, 49, 185, 223, 162, 115, 194, 220, 75, 218, 160, 17, 83, 134, 247, 239, 213, 207, 59, 32, 76, 204, 206, 134, 80, 234, 88, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];
        let enc_hash = enc_data.sha256();
        let enc_patch = EncryptedPatch {
            data: enc_data,
            hash: enc_hash,
            index: 0 // TODO: Change this
        };

        assert_eq!( patch.encrypt_with_nonce(&key, Some( &iv )).unwrap(), enc_patch)
    }

    pub fn test_decrypt_patch() {
        let s = "[{\"op\":\"replace\",\"path\":\"/author/name2\",\"value\":\"Lennon\"},{\"op\":\"add\",\"path\":\"/tags/2\",\"value\":\"third\"},{\"op\":\"remove\",\"path\":\"/title\"}]";
        let patch: StatePatch = serde_json::from_str(s).unwrap();

        let key = b"EnigmaMPC".sha256();
        let enc_data: Vec<u8> = vec![197, 39, 187, 56, 29, 96, 229, 230, 172, 82, 74, 89, 152, 72, 183, 136, 80, 182, 222, 4, 47, 197, 200, 233, 105, 90, 207, 14, 20, 220, 170, 226, 21, 241, 24, 231, 69, 27, 177, 234, 110, 132, 253, 115, 87, 205, 167, 142, 163, 170, 37, 239, 240, 98, 20, 49, 185, 223, 162, 115, 194, 220, 75, 218, 160, 17, 83, 134, 247, 239, 213, 207, 59, 32, 76, 204, 206, 134, 80, 234, 88, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];

        let mut enc_patch = EncryptedPatch::default();
        enc_patch.data = enc_data;
        assert_eq!(patch, StatePatch::decrypt(&enc_patch, &key).unwrap())
    }

    pub fn test_encrypt_decrypt_patch() {
        let s = "[{\"op\":\"replace\",\"path\":\"/author/name2\",\"value\":\"Lennon\"},{\"op\":\"add\",\"path\":\"/tags/2\",\"value\":\"third\"},{\"op\":\"remove\",\"path\":\"/title\"}]";
        let patch: StatePatch = serde_json::from_str(s).unwrap();

        let key = b"EnigmaMPC".sha256();
        let iv = [0,1,2,3,4,5,6,7,8,9,10,11];

        let enc = patch.encrypt_with_nonce(&key, Some( &iv )).unwrap();

        assert_eq!(patch, StatePatch::decrypt(&enc, &key).unwrap())

    }

    pub fn test_apply_delta() {
        let p = "[{\"op\":\"replace\",\"path\":\"/author/name2\",\"value\":\"Lennon\"},{\"op\":\"add\",\"path\":\"/tags/2\",\"value\":\"third\"},{\"op\":\"remove\",\"path\":\"/title\"}]";
        let patch: StatePatch = serde_json::from_str(p).unwrap();
        let mut contract = ContractState{
            contract_id: b"Enigma".sha256(),
            json: json!({ "title": "Goodbye!","author" : { "name1" : "John", "name2" : "Doe"}, "tags":[ "first", "second" ] }),
        };
        contract.apply_delta(&patch).unwrap();
        assert_eq!(contract, ContractState { contract_id: b"Enigma".sha256(),  json: json!({ "author" : {"name1" : "John", "name2" : "Lennon"},"tags": [ "first", "second", "third"] }) } );
    }

    pub fn test_generate_delta() {
        let p = "[{\"op\":\"replace\",\"path\":\"/author/name2\",\"value\":\"Lennon\"},{\"op\":\"add\",\"path\":\"/tags/2\",\"value\":\"third\"},{\"op\":\"remove\",\"path\":\"/title\"}]";
        let result: StatePatch = serde_json::from_str(p).unwrap();
        let id = b"Enigma".sha256();
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