pub mod integration_utils;
pub extern crate enigma_core_app as app;
extern crate cross_test_utils;
extern crate rustc_hex;
extern crate ethabi;

use integration_utils::{get_simple_msg_format, conn_and_call_ipc, is_hex, run_core, erc20_deployment_without_ptt_to_addr,
                        run_ptt_round, contract_compute, full_simple_deployment, full_erc20_deployment};
use cross_test_utils::generate_contract_address;
use rustc_hex::ToHex;
use ethabi::Token;
use app::serde_json::*;

#[test]
fn test_registration_params() {
    let port = "5570";

    run_core(port);
    let type_req = "GetRegistrationParams";
    let msg = get_simple_msg_format(type_req);
    let v: Value = conn_and_call_ipc(&msg.to_string(), port);

    let result_key = v["result"]["signingKey"].as_str().unwrap();
    let result_rep= v["result"]["report"].as_str().unwrap();
    let result_sig = v["result"]["signature"].as_str().unwrap();
    let type_res = v["type"].as_str().unwrap();

    assert_eq!(type_res, type_req);
    assert!(is_hex(result_key));
    assert!(is_hex(result_rep));
    assert!(is_hex(result_sig));
}

#[test]
fn test_deploy_with_no_ptt() {
    let port = "5575";
    run_core(port);
    let _val = erc20_deployment_without_ptt_to_addr(port, &generate_contract_address().to_hex());
    let accepted_err =  _val["msg"].as_str().unwrap();
    assert_eq!(accepted_err, "EnclaveFailError { err: KeysError, status: SGX_SUCCESS }");
}

#[test]
fn test_compute_on_empty_address() {
    let port = "5576";
    run_core(port);
    let _address = generate_contract_address();
    let _ = run_ptt_round(port, &[_address.to_hex()]);
    let args = [Token::FixedBytes(generate_contract_address().to_vec()), Token::Uint(100.into())];
    let callable  = "mint(bytes32,uint256)";
    let (_val,_) = contract_compute(port, _address.into(), &args, callable);
    let accepted_err =  _val["msg"].as_str().unwrap();
    assert_eq!(accepted_err, "DBErr { command: \"read\", kind: MissingKey }");
}

#[test]
fn test_run_ptt_twice() {
    let port = "5577";
    run_core(port);
    let address = generate_contract_address();
    let _val_first = run_ptt_round(port, &[address.to_hex()]);
    let _val_second = run_ptt_round(port, &[address.to_hex()]);
    //todo what should we expect to happen?
}

#[test]
fn test_deploy_same_contract_twice() {
    let port = "5578";
    run_core(port);
    let address = generate_contract_address().to_hex();
    let _val_ptt = run_ptt_round(port, &[address.clone()]);
    let _deploy_first = erc20_deployment_without_ptt_to_addr(port, &address.clone());
    let _deploy_second = erc20_deployment_without_ptt_to_addr(port, &address);
    let accepted_err =  _deploy_second["msg"].as_str().unwrap();
    assert_eq!(accepted_err, "DBErr { command: \"create\", kind: KeyExists }");
}

#[test]
fn test_wrong_arguments() {
    let port = "5579";
    run_core(port);
    let (_, _address) = full_simple_deployment(port);
    let args = [Token::FixedBytes(generate_contract_address().to_vec()), Token::FixedBytes(generate_contract_address().to_vec())];
    let callable  = "mint(bytes32,bytes32)";
    let (_val, _) = contract_compute(port, _address, &args, callable);
    let accepted_err =  _val["msg"].as_str().unwrap();
    assert_eq!(accepted_err, "EnclaveFailError { err: WasmCodeExecutionError, status: SGX_SUCCESS }");
}

#[test]
fn test_out_of_gas() {
    let port = "5580";
    run_core(port);
    let (_val,_) = full_erc20_deployment(port, Some(2));
    let accepted_err =  _val["msg"].as_str().unwrap();
    assert_eq!(accepted_err, "EnclaveFailError { err: GasLimitError, status: SGX_SUCCESS }");
}