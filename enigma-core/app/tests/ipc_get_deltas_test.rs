pub mod integration_utils;

use integration_utils::{create_storage_dir, run_core, deploy_and_compute_few_contracts,
                        conn_and_call_ipc, remove_storage_dir, set_deltas_msg, decrypt_delta, is_hex};
pub extern crate enigma_core_app as app;
extern crate serde;
extern crate rustc_hex as hex;

use self::app::*;
use self::app::serde_json;
use app::serde_json::*;
use hex::{ToHex, FromHex};


#[test]
fn test_ipc_get_deltas() {
    create_storage_dir();
    let port =  "5570";
    run_core(port);

    let addresses = deploy_and_compute_few_contracts(port);

    // receives only delta 2 from address 1 and delta 1 from address 0
    let _input = vec![(addresses[1].to_hex(),2, 3), (addresses[0].to_hex(), 1, 2)];
    let msg = set_deltas_msg(_input);
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
    remove_storage_dir();
}
