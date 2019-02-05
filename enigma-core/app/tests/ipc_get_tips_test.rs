pub mod integration_utils;

use integration_utils::{create_storage_dir, run_core, deploy_and_compute_few_contracts,
                        set_get_tips_msg, conn_and_call_ipc, remove_storage_dir};
pub extern crate enigma_core_app as app;

extern crate serde;
extern crate rustc_hex as hex;

use self::app::*;
use self::app::serde_json;
use app::serde_json::*;
use hex::{ToHex, FromHex};

#[test]
fn test_ipc_get_tips() {
    create_storage_dir();
    let port =  "5562";
    run_core(port);

    let mut _addresses = deploy_and_compute_few_contracts(port);

    let type_tips = "GetTips";
    let missing_addr = _addresses.pop().unwrap().to_hex();
    let _addresses = _addresses.iter().map(|addr| addr.to_hex()).collect();
    let _msg = set_get_tips_msg(type_tips, _addresses);
    let res: Value = conn_and_call_ipc(&_msg.to_string(), port);

    let type_accepted = res["type"].as_str().unwrap();
    let tips = res["result"].as_object().unwrap()["tips"].as_array().unwrap();

    let mut accepted_addrs = Vec::new();
    for val in tips {
        assert_eq!(val["key"].as_u64().unwrap(), 2);
        accepted_addrs.push(val["address"].as_str().unwrap())
    }
    assert_eq!(type_accepted, type_tips);
    assert_eq!(tips.len(), 2);
    // make sure that the address we didn't send does not exist in the result
    assert_eq!(accepted_addrs.iter().find(|&&addr| addr == missing_addr), None);
    remove_storage_dir();
}
