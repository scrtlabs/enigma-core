pub mod integration_utils;
pub extern crate enigma_core_app as app;
pub extern crate ethabi;
pub extern crate cross_test_utils;
extern crate rustc_hex as hex;

use integration_utils::{get_simple_msg_format, conn_and_call_ipc, is_hex, run_core,
                        set_encryption_msg, run_ptt_round, set_ptt_res_msg, full_simple_deployment,
                        set_ptt_req_msg, full_addition_compute, ParsedMessage, parse_packed_msg};
use self::cross_test_utils::{generate_address};
use self::app::*;
use integration_utils::serde::*;
use self::app::serde_json;
use app::serde_json::*;
use hex::{ToHex, FromHex};
use integration_utils::ethabi::{Token};
use integration_utils::enigma_crypto::asymmetric::KeyPair;

#[test]
fn test_registration_params() {
    let port = "5555";

    run_core(port);
    let type_req = "GetRegistrationParams";
    let msg = get_simple_msg_format(type_req);
    let v: Value = conn_and_call_ipc(&msg.to_string(), port);

    let result_key: String = serde_json::from_value(v["result"]["signingKey"].clone()).unwrap();
    let result_rep: String = serde_json::from_value(v["result"]["report"].clone()).unwrap();
    let result_sig: String = serde_json::from_value(v["result"]["signature"].clone()).unwrap();
    let type_res = v["type"].as_str().unwrap();

    assert_eq!(type_res, type_req);
    assert!(is_hex(&result_key));
    assert!(is_hex(&result_rep));
    assert!(is_hex(&result_sig));
}

#[test]
fn test_new_task_encryption_key(){
    let port = "5556";
    run_core(port);

    let type_req = "NewTaskEncryptionKey";
    let keys = KeyPair::new().unwrap();
    let msg = set_encryption_msg(type_req, keys.get_pubkey());

    let v: Value = conn_and_call_ipc(&msg.to_string(), port);
    let result_key = v["result"].as_object().unwrap()["workerEncryptionKey"].as_str().unwrap();
    let result_sig = v["result"].as_object().unwrap()["workerSig"].as_str().unwrap();
    let type_res = v["type"].as_str().unwrap();

    assert_eq!(type_res, type_req);
    assert!(is_hex(result_key));
    assert!(is_hex(result_sig));
}

#[test]
fn test_get_ptt_request() {
    let port = "5558";
    run_core(port);

    let type_req = "GetPTTRequest";
    let addresses: Vec<String> = vec![generate_address().to_hex(), generate_address().to_hex()];
    let msg = set_ptt_req_msg(type_req,addresses.clone());
    let v: Value = conn_and_call_ipc(&msg.to_string(), port);

    let packed_msg = v["result"].as_object().unwrap()["request"].as_str().unwrap();
    let result_sig = v["result"].as_object().unwrap()["workerSig"].as_str().unwrap();
    let type_res = v["type"].as_str().unwrap();
    let unpacked_msg: ParsedMessage = ParsedMessage::from_value(parse_packed_msg(packed_msg));

    assert_eq!(type_res, type_req);
    assert_eq!(addresses.len(), unpacked_msg.data.len());
    assert_eq!(unpacked_msg.pub_key.len(), 64);
    assert!(is_hex(result_sig));
}

#[test]
fn test_ptt_response() {
    let port = "5559";
    run_core(port);
    let type_res = "PTTResponse";
    let addresses: Vec<String> = vec![generate_address().to_hex(), generate_address().to_hex()];
    let res_val: Value = run_ptt_round(port, addresses, type_res);
    let result: Vec<u8> = serde_json::from_value(res_val["result"]["errors"].clone()).unwrap();
    let type_accepted = res_val["type"].as_str().unwrap();

    assert_eq!(type_res, type_accepted);
    assert_eq!(result.len(), 0);
}

#[test]
fn test_deploy_secret_contract() {
    let port =  "5557";
    run_core(port);

    let (res, _): (Value, _) = full_simple_deployment(port);
    let accepted_used_gas: u64 = serde_json::from_value(res["result"]["usedGas"].clone()).unwrap();
    let type_res = res["type"].as_str().unwrap();

    assert_eq!("DeploySecretContract", type_res);
    assert!(accepted_used_gas > 0);
}

#[test]
fn test_compute_task() {
    let port =  "5560";
    run_core(port);

    let (a, b) : (u64, u64) = (24, 67);
    let (res, _): (Value, _) = full_addition_compute(port, a, b);

    let output: String = serde_json::from_value(res["result"]["output"].clone()).unwrap();
    let type_accepted = res["type"].as_str().unwrap();
    let accepted_sum: Token = ethabi::decode(&[ethabi::ParamType::Uint(256)], &output.from_hex().unwrap()).unwrap().pop().unwrap();

    assert_eq!(accepted_sum.to_uint().unwrap().as_u64(), a+b);
    assert_eq!("ComputeTask", type_accepted);
}
