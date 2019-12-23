pub mod integration_utils;

use integration_utils::{run_core, full_simple_deployment, conn_and_call_ipc,
                        send_update_contract, get_update_deltas_msg, contract_compute,
                        send_update_contract_on_deployment, remove_contract, remove_deltas};
pub extern crate enigma_core_app as app;
extern crate serde;
extern crate rustc_hex as hex;
extern crate ethabi;

use self::app::serde_json;
use app::serde_json::*;
use hex::{ToHex, FromHex};
use integration_utils::cross_test_utils::{generate_contract_address};
use ethabi::Token::Uint;

#[test]
fn test_ipc_update_contract() {
    let port =  "5572";
    run_core(port);

    let (deployed_res, _) = full_simple_deployment(port);
    let deployed_bytecode = deployed_res["result"]["output"].as_str().unwrap();
    let new_addr = generate_contract_address();
    let res: Value = send_update_contract(port, &new_addr.to_hex(), deployed_bytecode.from_hex().unwrap());

    let updated: u64 = serde_json::from_value(res["result"]["status"].clone()).unwrap();
    let updated_addr = res["address"].as_str().unwrap();

    assert_eq!(updated, 0);
    assert_eq!(updated_addr, new_addr.to_hex());
}

#[test]
fn test_ipc_remove_contract() {
    let port =  "5575";
    run_core(port);

    let (_, address) = full_simple_deployment(port);
    let res = remove_contract(port, &address.to_hex());
    let status: u64 = serde_json::from_value(res["result"]["status"].clone()).unwrap();
    let accepted_addr: &str = res["address"].as_str().unwrap();

    assert_eq!(status, 0);
    assert_eq!(accepted_addr, address.to_hex());
}

#[test]
fn test_ipc_remove_contract_no_addr() {
    let port =  "5576";
    run_core(port);

    let addr = generate_contract_address();
    let res = remove_contract(port, &addr.to_hex());
    let status: u64 = serde_json::from_value(res["result"]["status"].clone()).unwrap();
    let accepted_addr: &str = res["address"].as_str().unwrap();

    assert_eq!(status, 0);
    assert_eq!(accepted_addr, addr.to_hex());
}

#[test]
fn test_ipc_update_contract_on_deployment() {
    let port =  "5574";
    run_core(port);

    let (deployed_res, _) = full_simple_deployment(port);
    let deployed_bytecode = deployed_res["result"]["output"].as_str().unwrap();
    let deployed_delta = deployed_res["result"]["delta"].as_object().unwrap();
    let new_addr = generate_contract_address();
    let delta_to_update = (new_addr.to_hex(), deployed_delta["key"].as_u64().unwrap(), serde_json::from_value(deployed_delta["data"].clone()).unwrap());
    let res: Value = send_update_contract_on_deployment(port, &new_addr.to_hex(), deployed_bytecode, &delta_to_update);
    let updated: i8 = serde_json::from_value(res["result"]["status"].clone()).unwrap();
    let updated_addr = res["address"].as_str().unwrap();

    assert_eq!(updated, 0);
    assert_eq!(updated_addr, new_addr.to_hex());
}

#[test]
fn test_ipc_update_deltas() {
    let port = "5573";
    run_core(port);

    let (deployed_res_a, address_a) = full_simple_deployment(port);
    let (deployed_res_b, _address_b) = full_simple_deployment(port);
    let (compute_res_a, _) = contract_compute(port, address_a, &[Uint(45.into()), Uint(73.into())], "addition(uint,uint)");

    // create a new address that contains a bytecode we just deployed.
    let deployed_bytecode_a = deployed_res_a["result"]["output"].as_str().unwrap();
    let new_addr_a = generate_contract_address();
    let _update_contract_a: Value = send_update_contract(port, &new_addr_a.to_hex(), deployed_bytecode_a.from_hex().unwrap());

    let deployed_bytecode_b = deployed_res_b["result"]["output"].as_str().unwrap();
    let new_addr_b = generate_contract_address();
    let _update_contract_b: Value = send_update_contract(port, &new_addr_b.to_hex(), deployed_bytecode_b.from_hex().unwrap());

    // get the delta for each of the computations above and push it to the input/ deltas vec with their new addr.
    let deployed_delta_a = deployed_res_a["result"]["delta"].as_object().unwrap();
    let deployed_delta_b = deployed_res_b["result"]["delta"].as_object().unwrap();
    let computed_delta_a = compute_res_a["result"]["delta"].as_object().unwrap();
    let mut deltas: Vec<(String, u64, Vec<u8>)> = Vec::new();
    deltas.push((new_addr_a.to_hex(), deployed_delta_a["key"].as_u64().unwrap(), serde_json::from_value(deployed_delta_a["data"].clone()).unwrap()));
    deltas.push((new_addr_b.to_hex(), serde_json::from_value(deployed_delta_b["key"].clone()).unwrap(), serde_json::from_value(deployed_delta_b["data"].clone()).unwrap()));
    deltas.push((new_addr_a.to_hex(), serde_json::from_value(computed_delta_a["key"].clone()).unwrap(), serde_json::from_value(computed_delta_a["data"].clone()).unwrap()));
    let msg = get_update_deltas_msg(&deltas);
    let update_deltas_res: Value = conn_and_call_ipc(&msg.to_string(), port);

    let updated: u64 = serde_json::from_value(update_deltas_res["result"]["status"].clone()).unwrap();
    let errors = update_deltas_res["result"].as_object().unwrap()["errors"].as_array().unwrap();
    for err in errors {
        assert_eq!(err["status"].as_u64().unwrap(), 0);
    }
    assert_eq!(updated, 0);
}

#[test]
fn test_ipc_remove_deltas() {
    let port = "5577";
    run_core(port);

    let (deployed_res_a, address_a) = full_simple_deployment(port);
    let (deployed_res_b, address_b) = full_simple_deployment(port);
    let (compute_res_a, _) = contract_compute(port, address_a, &[Uint(45.into()), Uint(73.into())], "addition(uint,uint)");

    let deployed_delta_num_a = deployed_res_a["result"]["delta"]["key"].as_u64().unwrap();
    let deployed_delta_num_b = deployed_res_b["result"]["delta"]["key"].as_u64().unwrap();
    let computed_delta_num_a = compute_res_a["result"]["delta"]["key"].as_u64().unwrap();
    let mut input: Vec<(String, u64, u64)> = Vec::with_capacity(1);
    // in order to remove the last element as well we need the `to` field to be one more
    // than the delta_num of the the actual delta, because it is not included.
    input.push((address_a.to_hex(), deployed_delta_num_a, computed_delta_num_a + 1));
    input.push((address_b.to_hex(), deployed_delta_num_b, deployed_delta_num_b + 1));
    let res = remove_deltas(port, &input);
    let errors = res["result"]["errors"].as_array().unwrap();
    let status = res["result"]["status"].as_u64().unwrap();
    assert_eq!(errors.len(), 0);
    assert_eq!(status, 0);
}