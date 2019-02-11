pub mod integration_utils;

use integration_utils::{run_core, full_simple_deployment, conn_and_call_ipc,
                        set_msg_format_update_contract, send_update_contract, set_update_deltas_msg, contract_compute};
pub extern crate enigma_core_app as app;
extern crate serde;
extern crate rustc_hex as hex;
extern crate ethabi;

use self::app::serde_json;
use app::serde_json::*;
use hex::ToHex;
use integration_utils::cross_test_utils::{generate_contract_address};
use ethabi::Token::Uint;

#[test]
fn test_ipc_update_contract() {
    let port =  "5572";
    run_core(port);

    let (deployed_res, _) = full_simple_deployment(port);
    let deployed_bytecode = deployed_res["result"].as_object().unwrap()["output"].as_str().unwrap();
    let new_addr = generate_contract_address();
    let res: Value = send_update_contract(port, &new_addr.to_hex(), deployed_bytecode);

    let updated: u64 = serde_json::from_value(res["result"]["status"].clone()).unwrap();
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
    let deployed_bytecode_a = deployed_res_a["result"].as_object().unwrap()["output"].as_str().unwrap();
    let new_addr_a = generate_contract_address();
    let _update_contract_a: Value = send_update_contract(port, &new_addr_a.to_hex(), deployed_bytecode_a);

    let deployed_bytecode_b = deployed_res_b["result"].as_object().unwrap()["output"].as_str().unwrap();
    let new_addr_b = generate_contract_address();
    let _update_contract_b: Value = send_update_contract(port, &new_addr_b.to_hex(), deployed_bytecode_b);

    // get the delta for each of the computations above and push it to the input/ deltas vec with their new addr.
    let deployed_delta_a = deployed_res_a["result"].as_object().unwrap()["delta"].as_object().unwrap();
    let deployed_delta_b = deployed_res_b["result"].as_object().unwrap()["delta"].as_object().unwrap();
    let computed_delta_a = compute_res_a["result"].as_object().unwrap()["delta"].as_object().unwrap();
    let mut deltas: Vec<(String, u64, String)> = Vec::new();
    deltas.push((new_addr_a.to_hex(), serde_json::from_value(deployed_delta_a["key"].clone()).unwrap(), serde_json::from_value(deployed_delta_a["delta"].clone()).unwrap()));
    deltas.push((new_addr_b.to_hex(), serde_json::from_value(deployed_delta_b["key"].clone()).unwrap(), serde_json::from_value(deployed_delta_b["delta"].clone()).unwrap()));
    deltas.push((new_addr_a.to_hex(), serde_json::from_value(computed_delta_a["key"].clone()).unwrap(), serde_json::from_value(computed_delta_a["delta"].clone()).unwrap()));
    let msg = set_update_deltas_msg(&deltas);
    let update_deltas_res: Value = conn_and_call_ipc(&msg.to_string(), port);

    let updated: u64 = serde_json::from_value(update_deltas_res["result"]["status"].clone()).unwrap();
    let errors = update_deltas_res["result"].as_object().unwrap()["errors"].as_array().unwrap();
    for err in errors {
        assert_eq!(err["status"].as_u64().unwrap(), 0);
    }
    assert_eq!(updated, 0);
}