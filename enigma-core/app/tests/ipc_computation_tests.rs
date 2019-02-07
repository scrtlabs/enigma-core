pub mod integration_utils;
pub extern crate enigma_core_app as app;
pub extern crate ethabi;
extern crate rustc_hex as hex;

use integration_utils::{conn_and_call_ipc, is_hex, run_core,
                        set_encryption_msg, full_simple_deployment, full_addition_compute};
use self::app::*;
use integration_utils::serde::*;
use self::app::serde_json;
use app::serde_json::*;
use hex::FromHex;
use integration_utils::ethabi::{Token};
use integration_utils::enigma_crypto::{asymmetric::KeyPair, symmetric};

#[test]
fn test_new_task_encryption_key(){
    let port = "5556";
    run_core(port);

    let keys = KeyPair::new().unwrap();
    let msg = set_encryption_msg(keys.get_pubkey());

    let v: Value = conn_and_call_ipc(&msg.to_string(), port);
    let result_key = v["result"].as_object().unwrap()["workerEncryptionKey"].as_str().unwrap();
    let result_sig = v["result"].as_object().unwrap()["workerSig"].as_str().unwrap();

    assert!(is_hex(result_key));
    assert!(is_hex(result_sig));
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
    let (res, key, _): (Value, [u8;32], _) = full_addition_compute(port, a, b);

    let output: String = serde_json::from_value(res["result"]["output"].clone()).unwrap();
    let type_accepted = res["type"].as_str().unwrap();
    let accepted_sum: Token = ethabi::decode(&[ethabi::ParamType::Uint(256)], &symmetric::decrypt(&output.from_hex().unwrap(),&key).unwrap()).unwrap().pop().unwrap();
    assert_eq!(accepted_sum.to_uint().unwrap().as_u64(), a+b);
    assert_eq!("ComputeTask", type_accepted);
}