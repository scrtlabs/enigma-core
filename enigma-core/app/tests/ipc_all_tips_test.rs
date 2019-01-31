pub mod integration_utils;

use integration_utils::*;
pub extern crate enigma_core_app as app;

extern crate serde;
extern crate rmp_serde as rmps;
extern crate enigma_crypto;
extern crate rustc_hex as hex;
pub extern crate cross_test_utils;
extern crate futures;

use self::cross_test_utils::*;
use self::app::*;
use self::futures::Future;
use self::app::networking::*;
use self::serde::{Deserialize, Serialize};
use self::rmps::{Deserializer, Serializer};
use self::app::serde_json;
#[macro_use]
use app::serde_json::*;
use hex::{ToHex, FromHex};
use self::ethabi::{Token};


#[test]
fn test_ipc_get_all_tips() {
    create_storage_dir();
    let port =  "5567";
    run_core(port);

    let id_cmp_a = "209134";
    let id_cmp_b = "7895";
    let id_cmp_c = "2309";
    let addresses = deploy_and_compute_few_contracts(port, &vec![id_cmp_a, id_cmp_b, id_cmp_c]);

    let id_tips = "25";
    let type_tips = "GetAllTips";
    let msg = set_get_all_msg(id_tips, type_tips);
    let res: Value = conn_and_call_ipc(&msg.to_string(), port);
    let id_accepted = res["id"].as_str().unwrap();
    let type_accepted = res["type"].as_str().unwrap();
    let tips = res["result"].as_object().unwrap()["tips"].as_array().unwrap();
    assert_eq!(tips.len(), 3);
    for val in tips {
        assert_eq!(val["key"].as_u64().unwrap(), 1)
    }
    assert_eq!(id_accepted, id_tips);
    assert_eq!(type_accepted, type_tips);
    remove_storage_dir();
}
