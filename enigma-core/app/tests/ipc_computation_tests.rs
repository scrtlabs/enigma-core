pub mod integration_utils;
pub extern crate enigma_core_app as app;
pub extern crate ethabi;
extern crate rustc_hex as hex;
extern crate cross_test_utils;

use integration_utils::{conn_and_call_ipc, is_hex, run_core, set_msg_format_update_contract,
                        set_encryption_msg, full_simple_deployment, full_addition_compute,
                        send_update_contract, full_erc20_deployment, run_ptt_round, contract_compute, set_update_deltas_msg};
use self::app::*;
use cross_test_utils::generate_contract_address;
use integration_utils::serde::*;
use self::app::serde_json;
use app::serde_json::*;
use hex::{ToHex, FromHex};
use integration_utils::ethabi::{Token};
use integration_utils::enigma_crypto::{asymmetric::KeyPair, symmetric};

#[test]
fn test_new_task_encryption_key(){
    let port = "5555";
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
    let port =  "5556";
    run_core(port);

    let (res, _): (Value, _) = full_simple_deployment(port);
    let accepted_used_gas: u64 = serde_json::from_value(res["result"]["usedGas"].clone()).unwrap();
    let type_res = res["type"].as_str().unwrap();

    assert_eq!("DeploySecretContract", type_res);
    assert!(accepted_used_gas > 0);
}

#[test]
fn test_compute_task() {
    let port =  "5557";
    run_core(port);

    let (a, b) : (u64, u64) = (24, 67);
    let (res, key, _): (Value, [u8;32], _) = full_addition_compute(port, a, b);

    let output: String = serde_json::from_value(res["result"]["output"].clone()).unwrap();
    let type_accepted = res["type"].as_str().unwrap();
    let accepted_sum: Token = ethabi::decode(&[ethabi::ParamType::Uint(256)], &symmetric::decrypt(&output.from_hex().unwrap(),&key).unwrap()).unwrap().pop().unwrap();
    assert_eq!(accepted_sum.to_uint().unwrap().as_u64(), a+b);
    assert_eq!("ComputeTask", type_accepted);
}

#[test]
#[ignore]
fn test_execute_on_existing_contract() {
   // update a contract in a new address and then run an execution on it.
    pub extern crate log;
    pub extern crate simplelog;
    use simplelog::TermLogger;
//    TermLogger::init(log::LevelFilter::Debug, Default::default()).unwrap();
    let port =  "5571";
    run_core(port);

    let (deployed_res, _) = full_erc20_deployment(port, None);
    let deployed_bytecode = deployed_res["result"].as_object().unwrap()["output"].as_str().unwrap();
    let new_addr = generate_contract_address();
    let _msg = set_msg_format_update_contract(&new_addr.to_hex(), deployed_bytecode);
    let res_a = send_update_contract(port, &new_addr.to_hex(), deployed_bytecode);
    println!("contract: {:?}", res_a);
    let deployed_delta = deployed_res["result"].as_object().unwrap()["delta"].as_object().unwrap();
    let deltas = vec![(new_addr.to_hex(), serde_json::from_value(deployed_delta["key"].clone()).unwrap(), serde_json::from_value(deployed_delta["delta"].clone()).unwrap())];
    let msg = set_update_deltas_msg(deltas);
    println!("msg: {:?}", msg);
    let update_deltas_res: Value = conn_and_call_ipc(&msg.to_string(), port);
    println!("deltas: {:?}", update_deltas_res);
    let res_b = run_ptt_round(port, vec![new_addr.to_hex()]);
    let args = [Token::FixedBytes(generate_contract_address().to_vec()), Token::Uint(100.into())];
    let callable  = "mint(bytes32,uint256)";
    let (res, _key) = contract_compute(port, new_addr.into(), &args, callable);
    println!("res: {:?}", res);
}