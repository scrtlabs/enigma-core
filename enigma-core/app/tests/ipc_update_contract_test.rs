pub mod integration_utils;

use integration_utils::{create_storage_dir, run_core, full_simple_deployment,
                        conn_and_call_ipc, remove_storage_dir, set_msg_format_update_contract,
                        send_update_contract};
pub extern crate enigma_core_app as app;
extern crate serde;
extern crate rustc_hex as hex;

use self::app::*;
use self::app::serde_json;
use app::serde_json::*;
use hex::{ToHex, FromHex};
use integration_utils::cross_test_utils::{generate_address};

#[test]
fn test_ipc_update_contract() {
    create_storage_dir();
    let port =  "5572";
    run_core(port);

    let (deployed_res, _) = full_simple_deployment(port);
    let deployed_bytecode = deployed_res["result"].as_object().unwrap()["output"].as_str().unwrap();
    let new_addr = generate_address();
    let msg = set_msg_format_update_contract(&new_addr.to_hex(), deployed_bytecode);
    let res: Value =send_update_contract(port, &new_addr.to_hex(), deployed_bytecode);

    let updated: u64 = serde_json::from_value(res["status"].clone()).unwrap();
    let updated_addr = res["address"].as_str().unwrap();

    assert_eq!(updated, 0);
    assert_eq!(updated_addr, new_addr.to_hex());
    remove_storage_dir();
}