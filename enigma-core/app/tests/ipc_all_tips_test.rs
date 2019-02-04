pub mod integration_utils;

use integration_utils::{create_storage_dir, run_core, deploy_and_compute_few_contracts,
                        get_simple_msg_format, conn_and_call_ipc, remove_storage_dir};
pub extern crate enigma_core_app as app;
extern crate serde;

use self::app::*;
use self::app::serde_json;
#[macro_use]
use app::serde_json::*;


#[test]
fn test_ipc_get_all_tips() {
    create_storage_dir();
    let port =  "5567";
    run_core(port);

    let addresses = deploy_and_compute_few_contracts(port);

    let type_tips = "GetAllTips";
    let msg = get_simple_msg_format(type_tips);
    let res: Value = conn_and_call_ipc(&msg.to_string(), port);
    let type_accepted = res["type"].as_str().unwrap();
    let tips = res["result"].as_object().unwrap()["tips"].as_array().unwrap();
    assert_eq!(tips.len(), 3);
    for val in tips {
        assert_eq!(val["key"].as_u64().unwrap(), 2)
    }
    assert_eq!(type_accepted, type_tips);
    remove_storage_dir();
}
