pub mod integration_utils;
pub extern crate enigma_core_app as app;
pub extern crate cross_test_utils;
extern crate rustc_hex as hex;

use integration_utils::{conn_and_call_ipc, is_hex, run_core, run_ptt_round,
                        get_ptt_req_msg, parse_packed_msg};
use self::cross_test_utils::{generate_contract_address};
use self::app::serde_json;
use app::serde_json::*;

#[test]
fn test_get_ptt_request() {
    let port = "5558";
    run_core(port);

    let msg = get_ptt_req_msg();
    let v: Value = conn_and_call_ipc(&msg.to_string(), port);

    let packed_msg = v["result"]["request"].as_str().unwrap();
    let result_sig = v["result"]["workerSig"].as_str().unwrap();
    let msg = parse_packed_msg(packed_msg);
    assert!(msg["data"]["Request"].is_null());
    assert_eq!(msg["pubkey"].as_array().unwrap().len(), 64);
    assert!(is_hex(result_sig));
}

#[test]
fn test_ptt_response() {
    let port = "5559";
    run_core(port);
    let addresses = vec![generate_contract_address(), generate_contract_address()];
    let res_val: Value = run_ptt_round(port, addresses);

    let errors: Vec<u8> = serde_json::from_value(res_val["result"]["errors"].clone()).unwrap();
    assert_eq!(errors.len(), 0);
}