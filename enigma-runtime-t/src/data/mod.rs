mod delta;
mod state;

pub use data::delta::{EncryptedPatch, StatePatch};
pub use data::state::{ContractState, EncryptedContractState};
use serde::Deserialize;
use serde_json::{Error, Value};

pub trait IOInterface<E, U> {
    fn read_key<T>(&self, key: &str) -> Result<T, Error> where for<'de> T: Deserialize<'de>;
    fn write_key(&mut self, key: &str, value: &Value) -> Result<(), E>;
    fn remove_key(&mut self, key: &str);
}

pub trait DeltasInterface<E, T, K> {
    fn apply_delta(&mut self, delta: T, key: K) -> Result<(), E>;
    fn generate_delta_and_update_state(old: &Self, new: &mut Self, key: K) -> Result<T, E> where Self: Sized;
}

#[cfg(debug_assertions)]
pub mod tests {
    use crate::data::*;
    use enigma_crypto::hash::Sha256;
    use enigma_crypto::Encryption;
    use enigma_types::ContractAddress;
    use json_patch;
    use serde_json::{self, Map, Value};
    use std::string::String;

    pub fn test_encrypt_state() {
        let contract_address = b"Enigma".sha256();
        let con = ContractState {
            contract_address,
            json: json!({"widget":{"debug":"on","window":{"title":"Sample Konfabulator Widget","name":"main_window","width":500,"height":500},"image":{"src":"Images/Sun.png","name":"sun1","hOffset":250,"vOffset":250,"alignment":"center"},"text":{"data":"Click Here","size":36,"style":"bold","name":"text1","hOffset":250,"vOffset":100,"alignment":"center","onMouseUp":"sun1.opacity = (sun1.opacity / 100) * 90;"}}}),
            .. Default::default()
        };
        let key = b"EnigmaMPC".sha256();
        let iv = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];

        let enc_data = vec![197, 53, 186, 61, 17, 116, 238, 226, 187, 179, 66, 18, 156, 95, 182, 135, 157, 171, 159, 207, 39, 197, 204, 188, 170, 147, 3, 1, 22, 218, 163, 31, 219, 245, 18, 247, 68, 87, 160, 229, 125, 146, 160, 230, 154, 246, 169, 129, 162, 171, 195, 133, 120, 163, 23, 63, 162, 223, 160, 47, 195, 219, 14, 21, 182, 120, 195, 100, 170, 65, 203, 10, 7, 215, 228, 226, 110, 152, 175, 120, 234, 107, 79, 30, 205, 4, 253, 116, 236, 45, 189, 65, 97, 167, 218, 142, 21, 248, 238, 145, 206, 202, 148, 71, 163, 17, 251, 83, 255, 137, 33, 101, 112, 137, 139, 247, 211, 110, 253, 59, 19, 3, 173, 193, 148, 132, 196, 254, 190, 35, 51, 20, 157, 119, 201, 122, 175, 165, 99, 232, 37, 3, 168, 150, 165, 246, 226, 227, 100, 132, 142, 102, 65, 69, 92, 44, 226, 189, 117, 239, 54, 17, 156, 236, 224, 164, 6, 224, 38, 96, 166, 91, 172, 56, 80, 97, 142, 89, 176, 72, 18, 141, 174, 26, 108, 103, 239, 236, 174, 7, 151, 177, 57, 218, 16, 214, 248, 35, 165, 35, 201, 138, 77, 88, 189, 7, 13, 108, 64, 177, 214, 227, 205, 49, 245, 53, 16, 39, 44, 66, 201, 15, 104, 246, 187, 221, 238, 183, 14, 128, 47, 73, 207, 133, 152, 186, 61, 197, 73, 71, 98, 179, 136, 83, 28, 188, 226, 9, 216, 163, 42, 61, 135, 94, 235, 100, 71, 154, 102, 153, 217, 171, 73, 254, 52, 113, 183, 122, 237, 49, 150, 8, 124, 132, 107, 65, 140, 220, 53, 110, 220, 128, 136, 7, 52, 174, 144, 242, 66, 145, 250, 210, 169, 213, 240, 139, 164, 170, 196, 155, 240, 121, 73, 124, 166, 64, 52, 84, 55, 213, 146, 82, 150, 222, 8, 163, 215, 45, 220, 166, 28, 177, 136, 253, 239, 248, 196, 119, 148, 10, 185, 223, 53, 216, 242, 152, 215, 60, 235, 22, 212, 254, 99, 139, 251, 238, 174, 82, 115, 171, 239, 45, 99, 161, 133, 187, 118, 253, 174, 13, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, ];
        let enc_contract = con.encrypt_with_nonce(&key, Some(iv)).unwrap();
        assert_eq!(EncryptedContractState { contract_address, json: enc_data }, enc_contract)
    }

    pub fn test_decrypt_state() {
        let key = b"EnigmaMPC".sha256();
        let enc_data = vec![197, 53, 186, 61, 17, 116, 238, 226, 187, 179, 66, 18, 156, 95, 182, 135, 157, 171, 159, 207, 39, 197, 204, 188, 170, 147, 3, 1, 22, 218, 163, 31, 219, 245, 18, 247, 68, 87, 160, 229, 125, 146, 160, 230, 154, 246, 169, 129, 162, 171, 195, 133, 120, 163, 23, 63, 162, 223, 160, 47, 195, 219, 14, 21, 182, 120, 195, 100, 170, 65, 203, 10, 7, 215, 228, 226, 110, 152, 175, 120, 234, 107, 79, 30, 205, 4, 253, 116, 236, 45, 189, 65, 97, 167, 218, 142, 21, 248, 238, 145, 206, 202, 148, 71, 163, 17, 251, 83, 255, 137, 33, 101, 112, 137, 139, 247, 211, 110, 253, 59, 19, 3, 173, 193, 148, 132, 196, 254, 190, 35, 51, 20, 157, 119, 201, 122, 175, 165, 99, 232, 37, 3, 168, 150, 165, 246, 226, 227, 100, 132, 142, 102, 65, 69, 92, 44, 226, 189, 117, 239, 54, 17, 156, 236, 224, 164, 6, 224, 38, 96, 166, 91, 172, 56, 80, 97, 142, 89, 176, 72, 18, 141, 174, 26, 108, 103, 239, 236, 174, 7, 151, 177, 57, 218, 16, 214, 248, 35, 165, 35, 201, 138, 77, 88, 189, 7, 13, 108, 64, 177, 214, 227, 205, 49, 245, 53, 16, 39, 44, 66, 201, 15, 104, 246, 187, 221, 238, 183, 14, 128, 47, 73, 207, 133, 152, 186, 61, 197, 73, 71, 98, 179, 136, 83, 28, 188, 226, 9, 216, 163, 42, 61, 135, 94, 235, 100, 71, 154, 102, 153, 217, 171, 73, 254, 52, 113, 183, 122, 237, 49, 150, 8, 124, 132, 107, 65, 140, 220, 53, 110, 220, 128, 136, 7, 52, 174, 144, 242, 66, 145, 250, 210, 169, 213, 240, 139, 164, 170, 196, 155, 240, 121, 73, 124, 166, 64, 52, 84, 55, 213, 146, 82, 150, 222, 8, 163, 215, 45, 220, 166, 28, 177, 136, 253, 239, 248, 196, 119, 148, 10, 185, 223, 53, 216, 242, 152, 215, 60, 235, 22, 212, 254, 99, 139, 251, 238, 174, 82, 115, 171, 239, 45, 99, 161, 133, 187, 118, 253, 174, 13, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];
        let contract_address = b"Enigma".sha256();
        let enc = EncryptedContractState { contract_address, json: enc_data };
        let result = ContractState {
            contract_address,
            json: json!({"widget":{"debug":"on","window":{"title":"Sample Konfabulator Widget","name":"main_window","width":500,"height":500},"image":{"src":"Images/Sun.png","name":"sun1","hOffset":250,"vOffset":250,"alignment":"center"},"text":{"data":"Click Here","size":36,"style":"bold","name":"text1","hOffset":250,"vOffset":100,"alignment":"center","onMouseUp":"sun1.opacity = (sun1.opacity / 100) * 90;"}}}),
            .. Default::default()
        };

        assert_eq!(ContractState::decrypt(enc, &key).unwrap(), result)
    }

    pub fn test_encrypt_decrypt_state() {
        let contract_address = b"Enigma".sha256();
        let con = ContractState {
            contract_address,
            json: json!({"widget":{"debug":"on","window":{"title":"Sample Konfabulator Widget","name":"main_window","width":500,"height":500},"image":{"src":"Images/Sun.png","name":"sun1","hOffset":250,"vOffset":250,"alignment":"center"},"text":{"data":"Click Here","size":36,"style":"bold","name":"text1","hOffset":250,"vOffset":100,"alignment":"center","onMouseUp":"sun1.opacity = (sun1.opacity / 100) * 90;"}}}),
            .. Default::default()
        };
        let key = b"EnigmaMPC".sha256();
        let iv = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];

        let enc = con.clone().encrypt_with_nonce(&key, Some(iv)).unwrap();
        assert_eq!(ContractState::decrypt(enc, &key).unwrap(), con)
    }

    pub fn test_write_state() {
        let mut con = ContractState::new(b"Enigma".sha256());
        con.write_key("code", &json!(200)).unwrap();
        con.write_key("success", &json!(true)).unwrap();
        con.write_key("payload", &json!({ "features": ["serde", "json"] })).unwrap();

        let cmp = ContractState {
            contract_address: b"Enigma".sha256(),
            json: json!({"code": 200,"success": true,"payload": {"features": ["serde","json"]}}),
            .. Default::default()
        };
        assert_eq!(con, cmp);
    }

    pub fn test_read_state() {
        let con = ContractState {
            contract_address: b"Enigma".sha256(),
            json: json!({"code": 200,"success": true,"payload": {"features": ["serde","json"]}}),
            .. Default::default()
        };
        assert_eq!(con.read_key::<u64>("code").unwrap(), 200);
        assert_eq!(con.read_key::<bool>("success").unwrap(), true);
        assert_eq!(con.read_key::<Map<String, Value>>("payload").unwrap()["features"], json!(["serde", "json"]));
    }

    pub fn test_diff_patch() {
        let before = json!({ "title": "Goodbye!","author" : { "name1" : "John", "name2" : "Doe"}, "tags":[ "first", "second" ] });
        let after = json!({ "author" : {"name1" : "John", "name2" : "Lennon"},"tags": [ "first", "second", "third"] });
        let patch =
            StatePatch { patch: json_patch::diff(&before, &after), previous_hash: [0u8; 32].into(), contract_address: [1u8; 32].into(), index: 0 };
        assert_eq!(serde_json::to_string(&patch.patch).unwrap(), "[{\"op\":\"replace\",\"path\":\"/author/name2\",\"value\":\"Lennon\"},{\"op\":\"add\",\"path\":\"/tags/2\",\"value\":\"third\"},{\"op\":\"remove\",\"path\":\"/title\"}]");
    }

    pub fn test_encrypt_patch() {
        let s = "[{\"op\":\"replace\",\"path\":\"/author/name2\",\"value\":\"Lennon\"},{\"op\":\"add\",\"path\":\"/tags/2\",\"value\":\"third\"},{\"op\":\"remove\",\"path\":\"/title\"}]";
        let contract_address: ContractAddress = [1u8; 32].into();
        let index = 99;
        let patch = StatePatch { patch: serde_json::from_str(s).unwrap(), previous_hash: [0u8; 32].into(), contract_address, index };

        let key = b"EnigmaMPC".sha256();
        let iv = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];

        let enc_data = vec![196, 39, 143, 237, 10, 117, 249, 235, 174, 84, 130, 219, 214, 92, 182, 148, 87, 171, 131, 69, 32, 201, 192, 190, 253, 176, 230, 5, 20, 221, 171, 31, 37, 51, 29, 231, 134, 147, 234, 255, 104, 144, 161, 110, 192, 28, 187, 143, 184, 188, 211, 219, 36, 117, 28, 51, 160, 204, 97, 250, 153, 193, 86, 194, 169, 111, 124, 202, 195, 44, 170, 109, 98, 164, 203, 177, 27, 246, 129, 8, 132, 12, 232, 104, 130, 98, 155, 7, 137, 89, 113, 187, 197, 211, 191, 246, 97, 112, 71, 240, 162, 35, 176, 216, 26, 97, 90, 218, 197, 244, 94, 225, 184, 235, 75, 198, 205, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, ];
        let enc_patch = EncryptedPatch { data: enc_data, contract_address, index };
        let a = patch.encrypt_with_nonce(&key, Some(iv)).unwrap();
        assert_eq!(a, enc_patch)
    }

    pub fn test_decrypt_patch() {
        let s = "[{\"op\":\"replace\",\"path\":\"/author/name2\",\"value\":\"Lennon\"},{\"op\":\"add\",\"path\":\"/tags/2\",\"value\":\"third\"},{\"op\":\"remove\",\"path\":\"/title\"}]";
        let contract_address: ContractAddress = [1u8; 32].into();
        let patch = StatePatch { patch: serde_json::from_str(s).unwrap(), previous_hash: [0u8; 32].into(), contract_address, index: 0 };

        let key = b"EnigmaMPC".sha256();
        let enc_data = vec![196, 39, 143, 237, 10, 117, 249, 235, 174, 84, 130, 219, 214, 92, 182, 148, 87, 171, 131, 69, 32, 201, 192, 190, 253, 176, 230, 5, 20, 221, 171, 31, 37, 51, 29, 231, 134, 147, 234, 255, 104, 144, 161, 110, 192, 28, 187, 143, 184, 188, 211, 219, 36, 117, 28, 51, 160, 204, 97, 250, 153, 193, 86, 194, 169, 111, 124, 202, 195, 44, 170, 109, 98, 164, 203, 177, 27, 246, 129, 8, 132, 12, 232, 104, 130, 98, 155, 7, 137, 89, 113, 187, 197, 211, 191, 246, 97, 112, 71, 240, 162, 35, 176, 216, 26, 97, 90, 218, 197, 244, 94, 225, 184, 235, 75, 198, 205, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];

        let enc_patch = EncryptedPatch { data: enc_data, contract_address, index: 0 };
        let dec = StatePatch::decrypt(enc_patch, &key).unwrap();
        assert_eq!(patch, dec)
    }

    pub fn test_encrypt_decrypt_patch() {
        let s = "[{\"op\":\"replace\",\"path\":\"/author/name2\",\"value\":\"Lennon\"},{\"op\":\"add\",\"path\":\"/tags/2\",\"value\":\"third\"},{\"op\":\"remove\",\"path\":\"/title\"}]";
        let patch = StatePatch { patch: serde_json::from_str(s).unwrap(), previous_hash: [0u8; 32].into(), contract_address: [1u8; 32].into(), index: 0 };

        let key = b"EnigmaMPC".sha256();
        let iv = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];
        let enc = patch.clone().encrypt_with_nonce(&key, Some(iv)).unwrap();

        assert_eq!(patch, StatePatch::decrypt(enc, &key).unwrap())
    }

    pub fn test_apply_delta() {
        let p = "[{\"op\":\"replace\",\"path\":\"/author/name2\",\"value\":\"Lennon\"},{\"op\":\"add\",\"path\":\"/tags/2\",\"value\":\"third\"},{\"op\":\"remove\",\"path\":\"/title\"}]";
        let contract_address = b"Enigma".sha256();
        let key = [1u8; 32];
        let patch = StatePatch { patch: serde_json::from_str(p).unwrap(), previous_hash: [4u8; 32].into(), contract_address, index: 1 };
        let enc_patch = patch.encrypt(&key).unwrap();
        let delta_hash = enc_patch.keccak256_patch();
        let mut contract = ContractState {
            contract_address,
            json: json!({ "title": "Goodbye!","author" : { "name1" : "John", "name2" : "Doe"}, "tags":[ "first", "second" ] }),
            delta_hash: [4u8; 32].into(),
            delta_index: 0,
        };
        contract.apply_delta(enc_patch, &key).unwrap();
        assert_eq!(
            contract,
            ContractState {
                contract_address,
                json: json!({ "author" : {"name1" : "John", "name2" : "Lennon"},"tags": [ "first", "second", "third"] }),
                delta_hash,
                delta_index: 1,
            }
        );
    }

    pub fn test_generate_delta() {
        let p = "[{\"op\":\"replace\",\"path\":\"/author/name2\",\"value\":\"Lennon\"},{\"op\":\"add\",\"path\":\"/tags/2\",\"value\":\"third\"},{\"op\":\"remove\",\"path\":\"/title\"}]";
        let contract_address = b"Enigma".sha256();
        let key = [1u8; 32];
        let result = StatePatch { patch: serde_json::from_str(p).unwrap(), previous_hash: [4u8; 32].into(), contract_address, index: 1 };
        let before = ContractState {
            contract_address,
            json: json!({ "title": "Goodbye!","author" : { "name1" : "John", "name2" : "Doe"}, "tags":[ "first", "second" ] }),
            delta_hash: [4u8; 32].into(),
            delta_index: 0,
        };
        let mut after = ContractState {
            contract_address,
            json: json!({ "author" : {"name1" : "John", "name2" : "Lennon"},"tags": [ "first", "second", "third"] }),
            delta_hash: [4u8; 32].into(),
            delta_index: 0,
        };

        let delta = ContractState::generate_delta_and_update_state(&before, &mut after, &key).unwrap();
        let delta = StatePatch::decrypt(delta, &key).unwrap();
        assert_eq!(delta, result);
    }
}
