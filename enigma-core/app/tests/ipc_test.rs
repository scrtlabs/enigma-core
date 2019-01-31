pub mod integration_utils;

use integration_utils::*;
pub extern crate enigma_core_app as app;

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
use hex::{ToHex, FromHex};
use self::ethabi::{Token};
use enigma_crypto::asymmetric::KeyPair;

#[test]
fn test_registration_params() {
    let port = "5555";
    let id = "867";
    let type_req = "GetRegistrationParams";
    let mut msg = json!({"id" : id, "type" : type_req});

    run_core(port);
    let v: Value = conn_and_call_ipc(&msg.to_string(), port);

    let id_accepted = v["id"].as_str().unwrap();
    let result_key: String = serde_json::from_value(v["result"]["signingKey"].clone()).unwrap();
    let result_rep: String = serde_json::from_value(v["result"]["report"].clone()).unwrap();
    let result_sig: String = serde_json::from_value(v["result"]["signature"].clone()).unwrap();
    let type_res = v["type"].as_str().unwrap();

    assert_eq!(id_accepted, id);
    assert_eq!(type_res, type_req);
    assert!(is_hex(&result_key));
    assert!(is_hex(&result_rep));
    assert!(is_hex(&result_sig));
}

#[test]
fn test_new_task_encryption_key(){
    let port = "5556";
    let id = "534";
    let type_req = "NewTaskEncryptionKey";
    let keys = KeyPair::new().unwrap();

    run_core(port);
    let msg = set_encryption_msg(id, type_req, keys.get_pubkey());
    let v: Value = conn_and_call_ipc(&msg.to_string(), port);
    let id_accepted = v["id"].as_str().unwrap();
    let result_key = v["result"].as_object().unwrap()["workerEncryptionKey"].as_str().unwrap();
    let result_sig = v["result"].as_object().unwrap()["workerSig"].as_str().unwrap();
    let type_res = v["type"].as_str().unwrap();

    assert_eq!(id_accepted, id);
    assert_eq!(type_res, type_req);
    assert!(is_hex(result_key));
    assert!(is_hex(result_sig));
}

#[test]
fn test_get_ptt_request() {
    let port = "5558";
    let id = "535";
    let type_req = "GetPTTRequest";
    let addresses: Vec<String> = vec![generate_address().to_hex(), generate_address().to_hex()];

    run_core(port);
    let msg = set_ptt_req_msg(id, type_req,addresses.clone());
    let v: Value = conn_and_call_ipc(&msg.to_string(), port);

    let id_accepted = v["id"].as_str().unwrap();
    let packed_msg = v["result"].as_object().unwrap()["request"].as_str().unwrap();
    let result_sig = v["result"].as_object().unwrap()["workerSig"].as_str().unwrap();
    let type_res = v["type"].as_str().unwrap();
    let unpacked_msg: ParsedMessage = ParsedMessage::from_value(parse_packed_msg(packed_msg));

    assert_eq!(id_accepted, id);
    assert_eq!(type_res, type_req);
    assert_eq!(addresses.len(), unpacked_msg.data.len());
    assert_eq!(unpacked_msg.pub_key.len(), 64);
    assert!(is_hex(result_sig));
}

#[test]
fn test_ptt_response() {
    let port = "5559";
    run_core(port);
    let id_res = "537";
    let type_res = "PTTResponse";
    let addresses: Vec<String> = vec![generate_address().to_hex(), generate_address().to_hex()];
    let res_val: Value = run_ptt_round(port, addresses, id_res, type_res);
    let id_accepted = res_val["id"].as_str().unwrap();
    let result: Vec<u8> = serde_json::from_value(res_val["result"]["errors"].clone()).unwrap();
    let type_accepted = res_val["type"].as_str().unwrap();

    assert_eq!(type_res, type_accepted);
    assert_eq!(id_res, id_accepted);
    assert_eq!(result.len(), 0);
}

#[test]
fn test_deploy_secret_contract() {
    let port =  "5557";
    run_core(port);
    let id_dep = "5784";

    let (res, _): (Value, _) = full_simple_deployment(port, id_dep);

    let accepted_id = res["id"].as_str().unwrap();
    let accepted_used_gas: u64 = serde_json::from_value(res["result"]["usedGas"].clone()).unwrap();
    let type_res = res["type"].as_str().unwrap();

    assert_eq!(id_dep, accepted_id);
    assert_eq!("DeploySecretContract", type_res);
    assert!(accepted_used_gas > 0);
}

#[test]
fn test_compute_task() {
    let port =  "5560";
    let id_cmp = "9801";
    run_core(port);
    let (a, b) : (u64, u64) = (24, 67);
    let (res, _): (Value, _) = full_addition_compute(port, id_cmp, a, b);

    let output: String = serde_json::from_value(res["result"]["output"].clone()).unwrap();
    let id_accepted = res["id"].as_str().unwrap();
    let type_accepted = res["type"].as_str().unwrap();
    let accepted_sum: Token = ethabi::decode(&[ethabi::ParamType::Uint(256)], &output.from_hex().unwrap()).unwrap().pop().unwrap();

    assert_eq!(accepted_sum.to_uint().unwrap().as_u64(), a+b);
    assert_eq!(id_cmp, id_accepted);
    assert_eq!("ComputeTask", type_accepted);
}

#[test]
fn test_ipc_get_tips() {
    create_storage_dir();
    let port =  "5562";
    run_core(port);

    let id_cmp_a = "234623";
    let id_cmp_b = "79890";
    let id_cmp_c = "7098350";
    let mut addresses = deploy_and_compute_few_contracts(port, &vec![id_cmp_a, id_cmp_b, id_cmp_c]);

    let id_tips = "8960";
    let type_tips = "GetTips";
    let missing_addr = addresses.pop().unwrap().to_hex();
    let addresses = addresses.iter().map(|addr| addr.to_hex()).collect();
    let msg = set_get_tips_msg(id_tips, type_tips, addresses);
    let res: Value = conn_and_call_ipc(&msg.to_string(), port);

    let id_accepted = res["id"].as_str().unwrap();
    let type_accepted = res["type"].as_str().unwrap();
    let tips = res["result"].as_object().unwrap()["tips"].as_array().unwrap();

    let mut accepted_addrs = Vec::new();
    for val in tips {
        assert_eq!(val["key"].as_u64().unwrap(), 1);
        accepted_addrs.push(val["address"].as_str().unwrap())
    }
    assert_eq!(id_accepted, id_tips);
    assert_eq!(type_accepted, type_tips);
    assert_eq!(tips.len(), 2);
    // make sure that the address we didn't send does not exist in the result
    assert_eq!(accepted_addrs.iter().find(|&&addr| addr == missing_addr), None);
    remove_storage_dir();
}
