pub mod integration_utils;

use integration_utils::{create_storage_dir, run_core, deploy_and_compute_few_contracts,
                        conn_and_call_ipc, remove_storage_dir, set_delta_msg, decrypt_delta};
pub extern crate enigma_core_app as app;
extern crate serde;
extern crate rustc_hex as hex;

use self::app::serde_json;
use app::serde_json::*;
use hex::{ToHex, FromHex};


#[test]
fn test_ipc_get_delta() {
    create_storage_dir();
    let port =  "5570";
    run_core(port);

    let addresses = deploy_and_compute_few_contracts(port);

    let msg = set_delta_msg(&addresses[1].to_hex(), 2);
    let res: Value = conn_and_call_ipc(&msg.to_string(), port);
    let delta_accepted = res["result"].as_object().unwrap()["delta"].as_str().unwrap();
    let mut decrypted_delta = decrypt_delta(&addresses[1], &delta_accepted.from_hex().unwrap());
    let add_result: u64 = serde_json::from_value(decrypted_delta[0][0][2].clone()).unwrap();
    // values that were sent in deploy_and_compute_few_contracts in the second contract
    assert_eq!(add_result, 75 + 43);
    remove_storage_dir();
}
