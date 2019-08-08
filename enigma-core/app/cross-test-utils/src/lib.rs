
extern crate enigma_types;
#[cfg_attr(test, macro_use)]
extern crate serde_json;
extern crate serde_derive;
extern crate serde;
extern crate rmp_serde;
extern crate enigma_crypto;
extern crate futures;

use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use std::process::Command;
pub use enigma_types::{ContractAddress, StateKey, Hash256};
use enigma_crypto::{KeyPair, symmetric, rand};
use enigma_crypto::hash::{Sha256, Keccak256};
use serde_json::{*, Value};
use rmp_serde::{Serializer};
use serde::{Serialize};

pub fn generate_contract_address() -> ContractAddress {
    let mut address = ContractAddress::default();
    rand::random(address.as_mut()).unwrap();
    address
}
pub type ERC20UserAddress = Hash256;
pub fn generate_user_address() -> (ERC20UserAddress, KeyPair) {
    let keys = KeyPair::new().unwrap();
    (keys.get_pubkey().keccak256(), keys)
}

pub fn sign_message(key: KeyPair, address: ERC20UserAddress, amount: u64) -> [u8;65] {
    let to_sign = [&address.to_vec()[..], &amount.to_be_bytes()] ;
    key.sign_multiple(&to_sign).unwrap()
}

pub fn get_bytecode_from_path(contract_path: &str) -> Vec<u8> {
    let mut dir = PathBuf::new();
    dir.push(contract_path);
    let mut output = Command::new("cargo")
        .current_dir(&dir)
        .args(&["build", "--release"]) // In real contract we should use --release
//        .args(&["build"])
        .spawn()
        .unwrap_or_else(|_| panic!("Failed compiling wasm contract: {:?}", &dir));

    assert!(output.wait().unwrap().success());
//    dir.push("target/wasm32-unknown-unknown/debug/contract.wasm");
    dir.push("target/wasm32-unknown-unknown/release/contract.wasm");

    let mut f = File::open(&dir).unwrap_or_else(|_| panic!("Can't open the contract.wasm file: {:?}", &dir));
    let mut wasm_code = Vec::new();
    f.read_to_end(&mut wasm_code).expect("Failed reading the wasm file");
    wasm_code
}

// creates a non trivial reproducible stateKey from the contract address
pub fn get_fake_state_key(contract_address: ContractAddress) -> [u8; 32] {
    contract_address.keccak256().sha256().into()
}

pub fn make_encrypted_response(req: &Value, addresses: Vec<ContractAddress>, keys: Option<Vec<StateKey>>) -> Value {
    // Making the response
    if !req["data"]["Request"].is_null() { // Just makes sure that {data:{Request}} Exists.
        assert_eq!(serde_json::from_value::<Vec<ContractAddress>>(req["data"]["Request"].clone()).unwrap(), addresses);
    }

    let _response_data: Vec<(ContractAddress, StateKey)> = if let Some(keys) = keys {
        addresses.into_iter().zip(keys.into_iter()).collect()
    } else {
        addresses.into_iter().map(|addr| (addr, get_fake_state_key(addr))).collect()
    };
    let mut response_data = Vec::new();
    _response_data.serialize(&mut Serializer::new(&mut response_data)).unwrap();

    // Getting the node DH Public Key
    let _node_pubkey: Vec<u8> = serde_json::from_value(req["pubkey"].clone()).unwrap();
    let mut node_pubkey = [0u8; 64];
    node_pubkey.copy_from_slice(&_node_pubkey);

    // Generating a second pair of priv-pub keys for the DH
    let keys = KeyPair::new().unwrap();

    // Generating the ECDH key for AES
    let shared_key = keys.derive_key(&node_pubkey).unwrap();
    // Encrypting the response
    let response_data = symmetric::encrypt(&response_data, &shared_key).unwrap();

    // Building the Encrypted Response.
    let mut enc_template: Value = serde_json::from_str(
        "{\"data\":{\
                    \"EncryptedResponse\":[239,255,23,228,191,26,143,198,128,188,100,241,178,217,234,168,108,235,78,65,238,186,149,171,226,107,165,133,44,177,27,14,128,38,137,97,202,160,120,230,88,226,218,127,41,16,29,135,167,0,186,110,21,164,73,226,244,202,243,227,78,75,216,216,138,135,158,26,136,143,45,118,11,248,0,66,204,94,63,193,31,148,110,58,35,104,219,233,159,244,176,244,33,8,214,223,107,103,44,243,28,237,155,104,3,243,217,122,233,16,192,163,112,164,66,250,116,194,45,111,174,65,142,179,228,132,195,118,123,34,219,135,245,83,113,8,141,6,241,156,136,70,134,206,238,227,26,106,248,215,20,130,181,231,216,193,238,87,241,150,14,45,180,22,191,100,207,148,82,89,5,158,241,173,193,140,214,109,139,18,91,200,251,121,16,119,21,243,177,104,46,254,48,41,115,56,8,37,27,155,95,51,125,244,75,154,90,47,181,110,126,174,96,90,25,34,92,89,250,240,5,200,147,228,148,158,193,54,12,249,243,47,172,27,131,158,32,167,116,200,110,29,151,13,78,23,41,199,188,127,142,109,3,130,202,179,168,111,128,246,242,23,7,247,87,151,110,102,30,226,94,135,249,244,48,250,32,177,155,28,217,175,25,89,231,167,1,54,204,124,20,196,168,239,148,200,45,213,185,37,144,138,244,194,211,141,5,171,93,146,138,154,5,4,243,9,123,237,186,233,215,42,121,152,75,208,13,156,53,86,254,123,182,21,210,230,235,237,12]\
                },\
                \"id\":[99,31,224,64,105,252,120,51,200,241,224,56],\
                \"prefix\":[69,110,105,103,109,97,32,77,101,115,115,97,103,101],\
                \"pubkey\":[127,228,135,71,145,246,191,25,182,250,194,154,40,157,166,47,6,214,203,209,7,71,48,253,171,195,26,131,255,59,181,47,202,186,164,88,190,47,24,102,237,57,130,227,253,190,12,121,200,130,221,255,42,121,136,131,170,143,132,174,21,219,245,153]\
            }"
    ).unwrap();
    enc_template["data"]["EncryptedResponse"] = json!(response_data);
    enc_template["id"] = req["id"].clone();
    enc_template["pubkey"] = json!(&keys.get_pubkey()[..]);

    enc_template
}

