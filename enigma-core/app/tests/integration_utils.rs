pub extern crate enigma_core_app as app;

extern crate zmq;
extern crate regex;
pub extern crate ethabi;
extern crate serde;
extern crate rmp_serde as rmps;
extern crate enigma_crypto;
extern crate rustc_hex as hex;
pub extern crate cross_test_utils;
extern crate futures;

use self::cross_test_utils::*;
use self::app::*;
use self::futures::Future;
use self::app::networking::*;
use self::serde::{Deserialize, Serialize};
use self::rmps::{Deserializer, Serializer};
use self::app::serde_json;
#[macro_use]
use app::serde_json::*;
use std::thread;
use self::regex::Regex;
use hex::{ToHex, FromHex};
use self::ethabi::{Token};
use enigma_crypto::asymmetric::KeyPair;
use enigma_crypto::symmetric;
use std::env;
use std::fs;
use std::path::PathBuf;

pub static ENCLAVE_DIR: &'static str = ".enigma";

pub fn get_storage_path() -> PathBuf {
    let home_dir = match env::home_dir() {
        Some(path) => path,
        None => panic!("Impossible to get your home dir!"),
    };
    home_dir.join(ENCLAVE_DIR)
}

pub fn create_storage_dir() {
    let home_dir = get_storage_path();

    if home_dir.exists() {
        fs::remove_dir_all(home_dir.clone()).unwrap();
    }
    fs::create_dir(&home_dir).unwrap();
}

pub fn remove_storage_dir() {
    let home_dir = get_storage_path();

    if home_dir.exists() {
        fs::remove_dir_all(home_dir).unwrap();
    }
}

pub fn run_core(port: &'static str) {
    thread::spawn(move || {
        let enclave = esgx::general::init_enclave_wrapper().unwrap();
        let server = IpcListener::new(&format!("tcp://*:{}", port));
        server.run(move |multi| ipc_listener::handle_message(multi, enclave.geteid())).wait().unwrap();
    });
}

pub fn is_hex(msg: &str) -> bool {
    let re = Regex::new(r"^(0x|0X)?[0-9a-fA-F]*$").unwrap();
    re.is_match(msg)
}

pub fn conn_and_call_ipc(msg: &str, port: &'static str) -> Value {
    let context = zmq::Context::new();
    let requester = context.socket(zmq::REQ).unwrap();
    assert!(requester.connect(&format!("tcp://localhost:{}", port)).is_ok());

    requester.send(msg, 0).unwrap();

    let mut msg = zmq::Message::new();
    requester.recv(&mut msg, 0).unwrap();
    serde_json::from_str(msg.as_str().unwrap()).unwrap()
}

pub fn set_encryption_msg(id: &str, type_req: &str, user_pubkey: [u8; 64]) -> Value {
    json!({"id" : id, "type" : type_req, "userPubKey": user_pubkey.to_hex()})
}

#[derive(Debug)]
pub struct ParsedMessage {
    prefix: String,
    pub data: Vec<String>,
    pub pub_key: Vec<u8>,
    id: [u8; 12],
}

impl ParsedMessage {
    pub fn from_value(msg: Value) -> Self {
        let prefix_bytes: Vec<u8> = serde_json::from_value(msg["prefix"].clone()).unwrap();
        let prefix: String = std::str::from_utf8(&prefix_bytes[..]).unwrap().to_string();

        let data_bytes: Vec<Vec<u8>> = serde_json::from_value(msg["data"].as_object().unwrap()["Request"].clone()).unwrap();
        let mut data: Vec<String> = Vec::new();
        for a in data_bytes {
            data.push(a.to_hex());
        }
        let pub_key: Vec<u8> = serde_json::from_value(msg["pubkey"].clone()).unwrap();
        let id: [u8; 12] = serde_json::from_value(msg["id"].clone()).unwrap();

        Self { prefix, data, pub_key, id }
    }
}

pub fn parse_packed_msg(msg: &str) -> Value {
    let msg_bytes = msg.from_hex().unwrap();
    let mut de = Deserializer::new(&msg_bytes[..]);
    Deserialize::deserialize(&mut Deserializer::new(&msg_bytes[..])).unwrap()
}

pub fn set_ptt_req_msg(id: &str, type_req: &str, addrs: Vec<String>) -> Value {
    json!({"id" : id, "type" : type_req, "addresses": addrs})
}

pub fn mock_principal_res(msg: &str) -> Vec<u8> {
    let unpacked_msg: Value = parse_packed_msg(msg);
    let enc_response: Value = make_encrypted_response(unpacked_msg);

    let mut serialized_enc_response = Vec::new();
    enc_response.serialize(&mut Serializer::new(&mut serialized_enc_response)).unwrap();
    serialized_enc_response
}

pub fn set_ptt_res_msg(id: &str, type_res: &str, response: Vec<u8>) -> Value {
    json!({"id" : id, "type" : type_res, "response": response.to_hex()})
}

pub fn run_ptt_round(port: &'static str, addrs: Vec<String>, id_res: &str, type_res: &str) -> Value {
    let id_req = "536";
    let type_req = "GetPTTRequest";

    // set encrypted request message to send to the principal node
    let msg_req = set_ptt_req_msg(id_req, type_req, addrs.clone());
    let req_val: Value = conn_and_call_ipc(&msg_req.to_string(), port);
    let packed_msg = req_val["result"].as_object().unwrap()["request"].as_str().unwrap();

    let enc_response = mock_principal_res(packed_msg);
    let msg = set_ptt_res_msg(id_res, type_res, enc_response);
    conn_and_call_ipc(&msg.to_string(), port)
}

pub fn produce_shared_key(port: &'static str) -> ([u8; 32], [u8; 64]) {
    // get core's pubkey
    let id_enc = "7698";
    let type_enc = "NewTaskEncryptionKey";
    let keys = KeyPair::new().unwrap();
    let msg = set_encryption_msg(id_enc, type_enc, keys.get_pubkey());

    let v: Value = conn_and_call_ipc(&msg.to_string(), port);
    let core_pubkey: String = serde_json::from_value(v["result"]["workerEncryptionKey"].clone()).unwrap();
    let _pubkey_vec: Vec<u8> = core_pubkey.from_hex().unwrap();
    let mut pubkey_arr = [0u8; 64];
    pubkey_arr.copy_from_slice(&_pubkey_vec);

    let shared_key = keys.get_aes_key(&pubkey_arr).unwrap();
    (shared_key, keys.get_pubkey())
}

pub fn set_deploy_msg(id: &str, type_dep: &str, pre_code: &str, args: &str, callable: &str, usr_pubkey: &str, gas_limit: u64, addr: &str) -> Value {
    json!({"id" : id, "type" : type_dep, "input":
            {"preCode": &pre_code, "encryptedArgs": args,
            "encryptedFn": callable, "userDHKey": usr_pubkey,
            "gasLimit": gas_limit, "contractAddress": addr}
            })
}

pub fn full_simple_deployment(port: &'static str, id_dep: &str) -> (Value, [u8; 32]) {
    // address generation and ptt
    let address = generate_address();
    let id_ptt = "876";
    let type_ptt = "PTTResponse";
    let _ = run_ptt_round(port, vec![address.to_hex()], id_ptt, type_ptt);

    // WUKE- get the arguments encryption key
    let (shared_key, user_pubkey) = produce_shared_key(port);

    let type_dep = "DeploySecretContract";
    let pre_code = get_bytecode_from_path("../../examples/eng_wasm_contracts/simplest");
    let fn_deploy = "construct(uint)";
    let args_deploy = [Token::Uint(17.into())];
    let encrypted_callable = symmetric::encrypt(fn_deploy.as_bytes(), &shared_key).unwrap();
    let encrypted_args = symmetric::encrypt(&ethabi::encode(&args_deploy), &shared_key).unwrap();
    let gas_limit = 100_000_000;

    let msg = set_deploy_msg(id_dep, type_dep, &pre_code.to_hex(), &encrypted_args.to_hex(),
                             &encrypted_callable.to_hex(), &user_pubkey.to_hex(), gas_limit, &address.to_hex());
    let v: Value = conn_and_call_ipc(&msg.to_string(), port);

    (v, address.into())
}

pub fn set_compute_msg(id: &str, type_cmp: &str, task_id: &str, callable: &str, args: &str, user_pubkey: &str, gas_limit: u64, con_addr: &str) -> Value {
    json!({"id": id, "type": type_cmp, "input": { "taskID": task_id, "encryptedArgs": args,
    "encryptedFn": callable, "userDHKey": user_pubkey, "gasLimit": gas_limit, "contractAddress": con_addr}})
}

pub fn full_addition_compute(port: &'static str, id: &str, a: u64, b: u64) -> (Value, [u8; 32]) {
    let id_dep = "78436";
    let (_, contract_address): (_, [u8; 32]) = full_simple_deployment(port, id_dep);
    // WUKE- get the arguments encryption key
    let (shared_key, user_pubkey) = produce_shared_key(port);

    let type_cmp = "ComputeTask";
    let task_id: String = generate_address().to_hex();
    let fn_cmp = "addition(uint,uint)";
    let args_cmp = [Token::Uint(a.into()), Token::Uint(b.into())];
    let encrypted_callable = symmetric::encrypt(fn_cmp.as_bytes(), &shared_key).unwrap();
    let encrypted_args = symmetric::encrypt(&ethabi::encode(&args_cmp), &shared_key).unwrap();
    let gas_limit = 100_000_000;

    let msg = set_compute_msg(id, type_cmp, &task_id, &encrypted_callable.to_hex(), &encrypted_args.to_hex(),
                              &user_pubkey.to_hex(), gas_limit, &contract_address.to_hex());
    (conn_and_call_ipc(&msg.to_string(), port), contract_address)
}

pub fn set_get_tip_msg(id: &str, type_tip: &str, input: &str) -> Value {
    json!({"id": id, "type": type_tip, "input": input})
}

pub fn get_decrypted_delta(addr: [u8; 32], delta: &str) -> Vec<u8> {
    let state_key = get_fake_state_key(&addr);
    let delta_bytes: Vec<u8> = delta.from_hex().unwrap();
    symmetric::decrypt(&delta_bytes, &state_key).unwrap()
}

pub fn set_get_tips_msg(id: &str, type_tip: &str, input: Vec<String>) -> Value {
    json!({"id": id, "type": type_tip, "input": input})
}

pub fn deploy_and_compute_few_contracts(port: &'static str, ids: &[&str]) -> Vec<[u8; 32]> {
    let (_, contract_address_a): (_, [u8; 32]) = full_addition_compute(port, ids[0], 56, 87);
    let (_, contract_address_b): (_, [u8; 32]) = full_addition_compute(port, ids[1], 75, 43);
    let (_, contract_address_c): (_, [u8; 32]) = full_addition_compute(port, ids[2], 34, 68);
    vec![contract_address_a, contract_address_b, contract_address_c]
}

pub fn set_get_all_msg(id: &str, type_tip: &str) -> Value {
    json!({"id": id, "type": type_tip})
}
