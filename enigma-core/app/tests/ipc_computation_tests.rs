pub mod integration_utils;
pub extern crate enigma_core_app as app;
pub extern crate ethabi;
extern crate rustc_hex as hex;
extern crate cross_test_utils;

use integration_utils::{conn_and_call_ipc, is_hex, run_core, set_msg_format_update_contract, set_delta_msg,
                        set_encryption_msg, full_simple_deployment, full_addition_compute, decrypt_int_output,
                        send_update_contract, full_erc20_deployment, run_ptt_round, contract_compute, set_update_deltas_msg, get_decrypted_delta, get_encrypted_delta};
use cross_test_utils::generate_contract_address;
use self::app::serde_json;
use app::serde_json::*;
use hex::{ToHex, FromHex};
use integration_utils::ethabi::{Token};
use integration_utils::enigma_crypto::asymmetric::KeyPair;

#[test]
fn test_new_task_encryption_key(){
    let port = "5555";
    run_core(port);

    let keys = KeyPair::new().unwrap();
    let msg = set_encryption_msg(keys.get_pubkey());

    let v: Value = conn_and_call_ipc(&msg.to_string(), port);
    let result_key = v["result"].as_object().unwrap()["workerEncryptionKey"].as_str().unwrap();
    let result_sig = v["result"].as_object().unwrap()["workerSig"].as_str().unwrap();

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
    let sig = res["result"].as_object().unwrap()["signature"].as_str().unwrap();
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
    let accepted_sum: Token = decrypt_int_output(&output.from_hex().unwrap(), &key);
    assert_eq!(accepted_sum.to_uint().unwrap().as_u64(), a + b);
    assert_eq!("ComputeTask", type_accepted);
}

#[test]
fn test_execute_on_existing_contract_no_construct() {
    let port =  "5571";
    run_core(port);

    let (deployed_res, _old_addr) = full_erc20_deployment(port, None);
    let deployed_bytecode = deployed_res["result"].as_object().unwrap()["output"].as_str().unwrap();
    let deployed_delta = deployed_res["result"].as_object().unwrap()["delta"].as_object().unwrap();
    let deployed_data: String = serde_json::from_value(deployed_delta["delta"].clone()).unwrap();

    let amount_before = Token::Uint(60.into());
    let to_addr = Token::FixedBytes(generate_contract_address().to_vec());
    let args = [to_addr, amount_before.clone()];
    let callable  = "mint(bytes32,uint256)";
    let (_res_mint, _) = contract_compute(port, _old_addr, &args, callable);
    let mint_delta = _res_mint["result"].as_object().unwrap()["delta"].as_object().unwrap();
    let computed_data: String = serde_json::from_value(mint_delta["delta"].clone()).unwrap();

    let new_addr = generate_contract_address();
    let _msg = set_msg_format_update_contract(&new_addr.to_hex(), deployed_bytecode);
    let _res_a = send_update_contract(port, &new_addr.to_hex(), deployed_bytecode);

    let decrypt_dep_data_from_old = get_decrypted_delta(_old_addr, &deployed_data);
    let encrypted_dep_data_new = get_encrypted_delta(new_addr.into(), &decrypt_dep_data_from_old);
    let decrypt_exe_data_from_old = get_decrypted_delta(_old_addr, &computed_data);
    let encrypted_exe_data_new = get_encrypted_delta(new_addr.into(), &get_decrypted_delta(_old_addr, &computed_data));
    let deltas = vec![
        (new_addr.to_hex(), serde_json::from_value(deployed_delta["key"].clone()).unwrap(), encrypted_dep_data_new),
        (new_addr.to_hex(), serde_json::from_value(mint_delta["key"].clone()).unwrap(), encrypted_exe_data_new)
    ];

    let msg = set_update_deltas_msg(&deltas);
    let _update_deltas_res: Value = conn_and_call_ipc(&msg.to_string(), port);
    let _res_b = run_ptt_round(port, &[new_addr.to_hex()]);

    let (res, _key) = contract_compute(port, new_addr.into(), &[], "total_supply()");
    let output: String = serde_json::from_value(res["result"]["output"].clone()).unwrap();
    let accepted_amount: Token = decrypt_int_output(&output.from_hex().unwrap(), &_key);
    assert_eq!(amount_before, accepted_amount);

    let amount = Token::Uint(100.into());
    let to_addr = Token::FixedBytes(generate_contract_address().to_vec());
    let args = [to_addr, amount.clone()];
    let callable  = "mint(bytes32,uint256)";
    let (_res_mint, _) = contract_compute(port, new_addr.into(), &args, callable);
    let mint_new_delta = _res_mint["result"].as_object().unwrap()["delta"].as_object().unwrap();
    let last_delta_key: u64 = serde_json::from_value(mint_new_delta["key"].clone()).unwrap();
    let expected_key: u64 = serde_json::from_value(mint_delta["key"].clone()).unwrap();
    assert_eq!(last_delta_key, expected_key + 1);
}

#[test]
fn test_execute_on_existing_contract_with_constructor() {
    let port =  "5572";
    run_core(port);

    let (deployed_res, _old_addr) = full_simple_deployment(port);
    let deployed_bytecode = deployed_res["result"].as_object().unwrap()["output"].as_str().unwrap();
    let deployed_delta = deployed_res["result"].as_object().unwrap()["delta"].as_object().unwrap();
    let deployed_data: String = serde_json::from_value(deployed_delta["delta"].clone()).unwrap();

    // done this execution in order to check if the new worker would be able to use data stored in the state
    let a = Token::Uint(1051.into());
    let b = Token::Uint(43.into());
    let args = [a.clone(), b.clone()];
    let callable  = "addition(uint256,uint256)";
    let (_res_add, _) = contract_compute(port, _old_addr, &args, callable);
    let add_delta = _res_add["result"].as_object().unwrap()["delta"].as_object().unwrap();
    let computed_data: String = serde_json::from_value(add_delta["delta"].clone()).unwrap();

    let new_addr = generate_contract_address();
    let _msg = set_msg_format_update_contract(&new_addr.to_hex(), deployed_bytecode);
    let _res_a = send_update_contract(port, &new_addr.to_hex(), deployed_bytecode);

    let decrypt_dep_data_from_old = get_decrypted_delta(_old_addr, &deployed_data);
    let encrypted_dep_data_new = get_encrypted_delta(new_addr.into(), &decrypt_dep_data_from_old);
    let decrypt_exe_data_from_old = get_decrypted_delta(_old_addr, &computed_data);
    let encrypted_exe_data_new = get_encrypted_delta(new_addr.into(), &get_decrypted_delta(_old_addr, &computed_data));
    let deltas = vec![
        (new_addr.to_hex(), serde_json::from_value(deployed_delta["key"].clone()).unwrap(), encrypted_dep_data_new),
        (new_addr.to_hex(), serde_json::from_value(add_delta["key"].clone()).unwrap(), encrypted_exe_data_new)
    ];
    let msg = set_update_deltas_msg(&deltas);
    let _update_deltas_res: Value = conn_and_call_ipc(&msg.to_string(), port);

    let _res_b = run_ptt_round(port, &[new_addr.to_hex()]);

    let (res, _key) = contract_compute(port, new_addr.into(), &[], "get_last_sum()");
    let output: String = serde_json::from_value(res["result"]["output"].clone()).unwrap();
    let accepted_sum: Token = decrypt_int_output(&output.from_hex().unwrap(), &_key);
    assert_eq!(accepted_sum, Token::Uint(a.to_uint().unwrap() + b.to_uint().unwrap()));

    let a = Token::Uint(134.into());
    let b = Token::Uint(43.into());
    let args = [a.clone(), b.clone()];
    let callable  = "addition(uint256,uint256)";
    let (_res_add2, _) = contract_compute(port, new_addr.into(), &args, callable);
    let add_new_delta = _res_add2["result"].as_object().unwrap()["delta"].as_object().unwrap();
    let last_delta_key: u64 = serde_json::from_value(add_new_delta["key"].clone()).unwrap();
    // it should be 3 since construct and add in the old address add each one a delta (1 & 2 respectively),
    // get_last_sum does not add a delta, hence is 0 and the last add does add a delta
    let expected_key: u64 = serde_json::from_value(add_delta["key"].clone()).unwrap();
    assert_eq!(last_delta_key, expected_key + 1);


}