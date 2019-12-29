pub mod integration_utils;
pub extern crate enigma_core_app as app;
pub extern crate ethabi;
extern crate rustc_hex as hex;
extern crate cross_test_utils;
extern crate enigma_types;

use integration_utils::{conn_and_call_ipc, is_hex, run_core, get_encryption_msg, full_simple_deployment,
                        send_update_contract, run_ptt_round, contract_compute, get_update_deltas_msg,
                        decrypt_addr_delta, encrypt_addr_delta, replace_previous_hash_in_delta_data,
                        full_supply_compute, full_addition_compute, decrypt_output_to_uint};
use cross_test_utils::generate_contract_address;
use self::app::serde_json;
use app::serde_json::*;
use hex::{ToHex, FromHex};
use integration_utils::ethabi::{Token};
use integration_utils::enigma_crypto::{asymmetric::KeyPair, hash::Keccak256};

#[test]
fn test_new_task_encryption_key(){
    let port = "5555";
    run_core(port);

    let keys = KeyPair::new().unwrap();
    let msg = get_encryption_msg(keys.get_pubkey());

    let v: Value = conn_and_call_ipc(&msg.to_string(), port);
    let result_key = v["result"]["workerEncryptionKey"].as_str().unwrap();
    let result_sig = v["result"]["workerSig"].as_str().unwrap();

    assert!(is_hex(result_key));
    assert!(is_hex(result_sig));
}

#[test]
fn test_deploy_secret_contract() {
    let port =  "5556";
    run_core(port);

    let (res, _): (Value, _) = full_simple_deployment(port);
    let accepted_used_gas: u64 = serde_json::from_value(res["result"]["usedGas"].clone()).unwrap();
    let type_res = res["type"].as_str().unwrap();
    let sig = res["result"]["signature"].as_str().unwrap();
    assert_eq!("DeploySecretContract", type_res);
    assert!(is_hex(sig));
    assert!(accepted_used_gas > 0);
}

#[test]
fn test_compute_task() {
    let port =  "5557";
    run_core(port);

    let (a, b) : (u64, u64) = (24, 67);
    let (res, key, _): (Value, [u8;32], _) = full_addition_compute(port, a, b);

    let output: String = serde_json::from_value(res["result"]["output"].clone()).unwrap();
    let type_accepted = res["type"].as_str().unwrap();
    let accepted_sum: Token = decrypt_output_to_uint(&output.from_hex().unwrap(), &key);
    assert_eq!(accepted_sum.to_uint().unwrap().as_u64(), a + b);
    assert_eq!("ComputeTask", type_accepted);
}

#[test]
fn test_compute_task_no_delta() {
    let port =  "5560";
    run_core(port);

    let supply = 100_000;
    let (res, key, _): (Value, [u8;32], _) = full_supply_compute(port, supply);

    let output: String = serde_json::from_value(res["result"]["output"].clone()).unwrap();
    let delta = res["result"]["delta"].as_object().unwrap();
    let type_accepted = res["type"].as_str().unwrap();
    let accepted_supply: Token = decrypt_output_to_uint(&output.from_hex().unwrap(), &key);

    // check that the data field does not exist in the delta object.
    assert!(delta.keys().find(|&k| *k == "data").is_none());
    assert_eq!(accepted_supply.to_uint().unwrap().as_u64(), supply);
    assert_eq!("ComputeTask", type_accepted);
}

#[test]
fn test_execute_on_existing_contract_with_constructor() {
    let port =  "5572";
    run_core(port);

    let (deployed_res, _old_addr) = full_simple_deployment(port);
    let deployed_bytecode = deployed_res["result"]["output"].as_str().unwrap();
    let delta0 = deployed_res["result"]["delta"].as_object().unwrap();
    let delta0_data: Vec<u8> = serde_json::from_value(delta0["data"].clone()).unwrap();

    // done this execution in order to check if the new worker would be able to use data stored in the state
    let a = Token::Uint(1051.into());
    let b = Token::Uint(43.into());
    let args = [a.clone(), b.clone()];
    let callable  = "addition(uint256,uint256)";
    let (_res_add, _) = contract_compute(port, _old_addr, &args, callable);
    let add_delta = _res_add["result"].as_object().unwrap()["delta"].as_object().unwrap();
    let computed_data: Vec<u8> = serde_json::from_value(add_delta["data"].clone()).unwrap();

    let new_addr = generate_contract_address();
    let _res_a = send_update_contract(port, &new_addr.to_hex(), deployed_bytecode.from_hex().unwrap());

    let decrypted_delta0_data = decrypt_addr_delta(_old_addr, &delta0_data);
    let encrypted_delta0_data_new = encrypt_addr_delta(new_addr.into(), &decrypted_delta0_data);
    let decrypted_delta1_data = decrypt_addr_delta(_old_addr, &computed_data);
    let decrypted_delta1_data = replace_previous_hash_in_delta_data(&decrypted_delta1_data, encrypted_delta0_data_new.keccak256());

    let encrypted_delta1_data_new = encrypt_addr_delta(new_addr.into(), &decrypted_delta1_data);
    let deltas = vec![
        (new_addr.to_hex(), delta0["key"].as_u64().unwrap(), encrypted_delta0_data_new),
        (new_addr.to_hex(),add_delta["key"].as_u64().unwrap(), encrypted_delta1_data_new)
    ];
    let msg = get_update_deltas_msg(&deltas);
    let _update_deltas_res: Value = conn_and_call_ipc(&msg.to_string(), port);

    let _res_b = run_ptt_round(port, vec![new_addr]);

    let (res, _key) = contract_compute(port, new_addr.into(), &[], "get_last_sum()");
    let output: String = serde_json::from_value(res["result"]["output"].clone()).unwrap();
    let accepted_sum: Token = decrypt_output_to_uint(&output.from_hex().unwrap(), &_key);
    assert_eq!(accepted_sum, Token::Uint(a.to_uint().unwrap() + b.to_uint().unwrap()));

    let a = Token::Uint(134.into());
    let b = Token::Uint(43.into());
    let args = [a.clone(), b.clone()];
    let callable  = "addition(uint256,uint256)";
    let (_res_add2, _) = contract_compute(port, new_addr.into(), &args, callable);
    let add_new_delta = _res_add2["result"]["delta"].as_object().unwrap();
    let last_delta_key = add_new_delta["key"].as_u64().unwrap();
    // it should be 3 since construct and add in the old address add each one a delta (1 & 2 respectively),
    // get_last_sum does not add a delta, hence is 0 and the last add does add a delta
    let expected_key = add_delta["key"].as_u64().unwrap();
    assert_eq!(last_delta_key, expected_key + 1);


}