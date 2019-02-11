pub mod integration_utils;

use integration_utils::{run_core, full_simple_deployment, deploy_and_compute_few_contracts,
                        conn_and_call_ipc, set_msg_format_with_input, set_get_tips_msg, set_delta_msg,
                        set_deltas_msg, get_simple_msg_format, decrypt_delta, is_hex};
pub extern crate enigma_core_app as app;
extern crate serde;
extern crate rustc_hex as hex;

use self::app::serde_json;
use app::serde_json::*;
use hex::{ToHex, FromHex};

#[test]
fn test_ipc_get_tip() {
    let port =  "5561";
    run_core(port);

    let (_, contract_address): (_, [u8; 32]) = full_simple_deployment(port);
    let type_tip = "GetTip";
    let msg = set_msg_format_with_input(type_tip, &contract_address.to_hex());
    let res: Value = conn_and_call_ipc(&msg.to_string(), port);

    let type_accepted = res["type"].as_str().unwrap();
    let _delta_str: String = serde_json::from_value(res["result"]["delta"].clone()).unwrap();
    let key: u64 = serde_json::from_value(res["result"]["key"].clone()).unwrap();

    assert_eq!(type_accepted, type_tip);
    assert_eq!(key, 1);
}

#[test]
fn test_ipc_get_tips() {
    let port =  "5562";
    run_core(port);

    let mut _addresses = deploy_and_compute_few_contracts(port);

    let missing_addr = _addresses.pop().unwrap().to_hex();
    let _addresses: Vec<String> = _addresses.iter().map(|addr| addr.to_hex()).collect();
    let _msg = set_get_tips_msg(&_addresses);
    let res: Value = conn_and_call_ipc(&_msg.to_string(), port);

    let tips = res["result"].as_object().unwrap()["tips"].as_array().unwrap();

    let mut accepted_addrs = Vec::new();
    for val in tips {
        assert_eq!(val["key"].as_u64().unwrap(), 2);
        accepted_addrs.push(val["address"].as_str().unwrap())
    }
    assert_eq!(tips.len(), 2);
    // make sure that the address we didn't send does not exist in the result
    assert_eq!(accepted_addrs.iter().find(|&&addr| addr == missing_addr), None);
}

#[test]
fn test_ipc_get_all_tips() {
    let port =  "5563";
    run_core(port);

    let _addresses = deploy_and_compute_few_contracts(port);

    let type_tips = "GetAllTips";
    let msg = get_simple_msg_format(type_tips);
    let res: Value = conn_and_call_ipc(&msg.to_string(), port);
    let type_accepted = res["type"].as_str().unwrap();
    let tips = res["result"].as_object().unwrap()["tips"].as_array().unwrap();
    assert_eq!(tips.len(), 3);
    for val in tips {
        assert_eq!(val["key"].as_u64().unwrap(), 2)
    }
    assert_eq!(type_accepted, type_tips);
}

#[test]
fn test_ipc_all_addrs() {
    let port =  "5564";
    run_core(port);
    let _addresses = deploy_and_compute_few_contracts(port);
    let addresses: Vec<String> = _addresses.iter().map(|addr| {addr.to_hex()}).collect();
    let type_addrs = "GetAllAddrs";
    let msg = get_simple_msg_format(type_addrs);
    let res: Value = conn_and_call_ipc(&msg.to_string(), port);
    let _addrs = res["result"].as_object().unwrap()["addresses"].as_array().unwrap();
    let addrs: Vec<String> = _addrs.iter().map(|addr| serde_json::from_value(addr.clone()).unwrap()).collect();
    assert!(addresses.iter().zip(addrs.iter()).all(|(expected, accepted)| expected == accepted));
}

#[test]
fn test_ipc_get_delta() {
    let port =  "5565";
    run_core(port);

    let addresses = deploy_and_compute_few_contracts(port);

    let msg = set_delta_msg(&addresses[1].to_hex(), 2);
    let res: Value = conn_and_call_ipc(&msg.to_string(), port);
    let delta_accepted = res["result"].as_object().unwrap()["delta"].as_str().unwrap();
    let decrypted_delta = decrypt_delta(&addresses[1], &delta_accepted.from_hex().unwrap());
    let add_result: u64 = serde_json::from_value(decrypted_delta[0][0][2].clone()).unwrap();
    // values that were sent in deploy_and_compute_few_contracts in the second contract
    assert_eq!(add_result, 75 + 43);
}

#[test]
fn test_ipc_get_deltas() {
    let port =  "5566";
    run_core(port);

    let addresses = deploy_and_compute_few_contracts(port);

    // receives only delta 2 from address 1 and delta 1 from address 0
    let _input = vec![(addresses[1].to_hex(),2, 3), (addresses[0].to_hex(), 1, 2)];
    let msg = set_deltas_msg(&_input);
    let res: Value = conn_and_call_ipc(&msg.to_string(), port);
    let deltas_accepted = res["result"].as_object().unwrap()["deltas"].as_array().unwrap();
    let first_address: String = serde_json::from_value(deltas_accepted[0]["address"].clone()).unwrap();
    let second_address: String = serde_json::from_value(deltas_accepted[1]["address"].clone()).unwrap();
    let first_key: u64 = serde_json::from_value(deltas_accepted[0]["key"].clone()).unwrap();
    let second_key: u64 = serde_json::from_value(deltas_accepted[1]["key"].clone()).unwrap();
    let delta: String = serde_json::from_value(deltas_accepted[0]["delta"].clone()).unwrap();
    assert_eq!(first_address, addresses[1].to_hex());
    assert_eq!(second_address, addresses[0].to_hex());
    assert_eq!(first_key, 2);
    assert_eq!(second_key, 1);
    assert!(is_hex(&delta));
}

#[test]
fn test_ipc_get_contract() {
    let port =  "5567";
    run_core(port);

    let (deployed_res, address) = full_simple_deployment(port);

    let type_msg = "GetContract";
    let msg = set_msg_format_with_input(type_msg, &address.to_hex());
    let res: Value = conn_and_call_ipc(&msg.to_string(), port);
    let type_accepted = res["type"].as_str().unwrap();
    let accepted_bytecode = res["result"].as_object().unwrap()["bytecode"].as_str().unwrap();
    let deployed_bytecode = deployed_res["result"].as_object().unwrap()["output"].as_str().unwrap();
    assert_eq!(type_accepted, type_msg);
    assert_eq!(deployed_bytecode, accepted_bytecode);
}