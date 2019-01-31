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
fn test_ipc_get_tip() {
    create_storage_dir();
    let port =  "5561";
    run_core(port);

    let id_cmp = "49086";
    let (_, contract_address): (_, [u8; 32]) = full_addition_compute(port, id_cmp, 56, 87);
    let id_tip = "98708";
    let type_tip = "GetTip";
    let msg = set_get_tip_msg(id_tip, type_tip, &contract_address.to_hex());
    let res: Value = conn_and_call_ipc(&msg.to_string(), port);

    let id_accepted = res["id"].as_str().unwrap();
    let type_accepted = res["type"].as_str().unwrap();
    let delta_str: String = serde_json::from_value(res["result"]["delta"].clone()).unwrap();
    let key: u64 = serde_json::from_value(res["result"]["key"].clone()).unwrap();

    assert_eq!(id_accepted, id_tip);
    assert_eq!(type_accepted, type_tip);
    assert_eq!(key, 1);
    remove_storage_dir();
}