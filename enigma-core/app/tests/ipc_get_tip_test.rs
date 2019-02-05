pub mod integration_utils;

use integration_utils::{create_storage_dir, run_core, full_simple_deployment,
                        set_msg_format_with_input, conn_and_call_ipc, remove_storage_dir};
pub extern crate enigma_core_app as app;
extern crate serde;
extern crate rustc_hex as hex;

use self::app::*;
use self::app::serde_json;
use app::serde_json::*;
use hex::{ToHex, FromHex};

#[test]
fn test_ipc_get_tip() {
    create_storage_dir();
    let port =  "5561";
    run_core(port);

    let (_, contract_address): (_, [u8; 32]) = full_simple_deployment(port);
    let type_tip = "GetTip";
    let msg = set_msg_format_with_input(type_tip, &contract_address.to_hex());
    let res: Value = conn_and_call_ipc(&msg.to_string(), port);

    let type_accepted = res["type"].as_str().unwrap();
    let delta_str: String = serde_json::from_value(res["result"]["delta"].clone()).unwrap();
    let key: u64 = serde_json::from_value(res["result"]["key"].clone()).unwrap();

    assert_eq!(type_accepted, type_tip);
    assert_eq!(key, 1);
    remove_storage_dir();
}