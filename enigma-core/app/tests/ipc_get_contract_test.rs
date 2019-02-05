pub mod integration_utils;

use integration_utils::{create_storage_dir, run_core, full_simple_deployment,
                        conn_and_call_ipc, remove_storage_dir, decrypt_delta,
                        set_msg_format_with_input};
pub extern crate enigma_core_app as app;
extern crate serde;
extern crate rustc_hex as hex;

use self::app::*;
use self::app::serde_json;
use app::serde_json::*;
use hex::{ToHex, FromHex};


#[test]
fn test_ipc_get_contract() {
    create_storage_dir();
    let port =  "5571";
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
    remove_storage_dir();
}
