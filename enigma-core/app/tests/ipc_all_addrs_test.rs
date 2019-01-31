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
fn test_ipc_all_addrs() {
    create_storage_dir();
    let port =  "5566";
    run_core(port);

    let id_cmp_a = "209136";
    let id_cmp_b = "7835";
    let id_cmp_c = "25649";
    let addresses = deploy_and_compute_few_contracts(port, &vec![id_cmp_a, id_cmp_b, id_cmp_c]);

    let id_addrs = "6585";
    let type_addrs = "GetAllAddrs";
    let msg = set_get_all_msg(id_addrs, type_addrs);
    let res: Value = conn_and_call_ipc(&msg.to_string(), port);
    let addrs = res["result"].as_object().unwrap()["addresses"].as_array().unwrap();
    remove_storage_dir();
    // todo: finish test
}