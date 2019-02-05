pub mod integration_utils;

use integration_utils::{run_core, deploy_and_compute_few_contracts, get_simple_msg_format,
                        conn_and_call_ipc, create_storage_dir, remove_storage_dir};
pub extern crate enigma_core_app as app;
extern crate rustc_hex;
extern crate serde;
use self::app::*;
use self::app::serde_json;
use app::serde_json::*;
use rustc_hex::{FromHex, ToHex};
use integration_utils::ethabi::{Token};

#[test]
fn test_ipc_all_addrs() {
    create_storage_dir();
    let port =  "5566";
    run_core(port);
    let _addresses = deploy_and_compute_few_contracts(port);
    let addresses: Vec<String> = _addresses.iter().map(|addr| {addr.to_hex()}).collect();
    let type_addrs = "GetAllAddrs";
    let msg = get_simple_msg_format(type_addrs);
    let res: Value = conn_and_call_ipc(&msg.to_string(), port);
    let _addrs = res["result"].as_object().unwrap()["addresses"].as_array().unwrap();
    let addrs: Vec<String> = _addrs.iter().map(|addr| serde_json::from_value(addr.clone()).unwrap()).collect();
    assert!(addresses.iter().zip(addrs.iter()).all(|(expected, accepted)| expected == accepted));
    remove_storage_dir();
}