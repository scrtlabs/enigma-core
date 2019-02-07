pub mod integration_utils;
pub extern crate enigma_core_app as app;

use integration_utils::{get_simple_msg_format, conn_and_call_ipc, is_hex, run_core};
use self::app::*;
use integration_utils::serde::*;
use self::app::serde_json;
use app::serde_json::*;

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