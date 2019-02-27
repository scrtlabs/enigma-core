#![crate_name = "enigmacoreenclave"]
#![crate_type = "staticlib"]
#![no_std]
//#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]
#![cfg_attr(not(feature = "std"), feature(alloc))]
#![feature(tool_lints)]
#![feature(int_to_from_bytes)]
#![warn(clippy::all)]
#![allow(clippy::cast_ptr_alignment)] // TODO: Try to remove it when fixing the sealing
#![warn(unused_extern_crates)]

extern crate enigma_runtime_t;
#[macro_use]
extern crate enigma_tools_t;
extern crate enigma_types;
extern crate enigma_crypto;

//#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgx_tstd as std;
extern crate sgx_trts;
extern crate sgx_types;

#[macro_use]
extern crate serde_json;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate error_chain;

extern crate bigint;
extern crate ethabi;
extern crate hexutil;
extern crate parity_wasm;
extern crate sputnikvm;
extern crate sputnikvm_network_classic;
extern crate wasmi;

/// This module builds Wasm code for contract deployment from the Wasm contract.
/// The contract should be written in rust and then compiled to Wasm with wasm32-unknown-unknown target.
/// The code is based on Parity wasm_utils::cli.
extern crate pwasm_utils as wasm_utils;

mod evm_t;
mod km_t;
mod ocalls_t;
mod wasm_g;

use crate::evm_t::{abi::{create_callback, prepare_evm_input},
                   evm::call_sputnikvm};
use crate::km_t::{ecall_build_state_internal, ecall_get_user_key_internal, ecall_ptt_req_internal, ecall_ptt_res_internal};
use crate::wasm_g::execution;
use enigma_runtime_t::data::{ContractState, StatePatch, EncryptedPatch};
use enigma_runtime_t::EthereumData;
use enigma_crypto::hash::Keccak256;
use enigma_crypto::{asymmetric, CryptoError, symmetric};
use enigma_tools_t::common::{errors_t::EnclaveError, LockExpectMutex, EthereumAddress};
use enigma_tools_t::{build_arguments_g::*, quote_t, storage_t};
use enigma_types::{traits::SliceCPtr, EnclaveReturn, ExecuteResult, Hash256, ContractAddress, PubKey, ResultStatus, RawPointer, DhKey};
use wasm_utils::{build, SourceTarget};

use sgx_types::*;
use std::{mem, ptr, slice, str};
use std::{boxed::Box, string::{String, ToString}, vec::Vec};

lazy_static! { pub(crate) static ref SIGNING_KEY: asymmetric::KeyPair = get_sealed_keys_wrapper(); }

#[no_mangle]
pub extern "C" fn ecall_get_registration_quote(target_info: &sgx_target_info_t, real_report: &mut sgx_report_t) -> sgx_status_t {
    quote_t::create_report_with_data(&target_info, real_report, &SIGNING_KEY.get_pubkey().address())
}

#[no_mangle]
pub extern "C" fn ecall_get_signing_address(pubkey: &mut [u8; 20]) {
    pubkey.copy_from_slice(&SIGNING_KEY.get_pubkey().address());
}

#[no_mangle]
pub unsafe extern "C" fn ecall_evm(bytecode: *const u8, bytecode_len: usize, callable: *const u8,
                                   callable_len: usize, callable_args: *const u8, callable_args_len: usize,
                                   preprocessor: *const u8, preprocessor_len: usize, callback: *const u8,
                                   callback_len: usize, output: *mut u8, signature: &mut [u8; 65],
                                   result_len: &mut usize) -> EnclaveReturn {
    let bytecode_slice = slice::from_raw_parts(bytecode, bytecode_len);
    let callable_slice = slice::from_raw_parts(callable, callable_len);
    let callable_args_slice = slice::from_raw_parts(callable_args, callable_args_len);
    let preprocessor_slice = slice::from_raw_parts(preprocessor, preprocessor_len);
    let callback_slice = slice::from_raw_parts(callback, callback_len);

    ecall_evm_internal(bytecode_slice,
                       callable_slice,
                       callable_args_slice,
                       preprocessor_slice,
                       callback_slice,
                       output,
                       signature,
                       result_len).into()
}

#[no_mangle]
/// Ecall for invocation of the external function `callable` of deployed contract with code `bytecode`.
/// arguments:
/// * `bytecode` - WASM bytecode of the deployed contract
/// * `bytecode_len` - the length of the `bytecode`.
/// * `callable` - the encrypted signature of the contract function to call
/// * `callable_len` - the length of the `callable`
/// * `args` - the encrypted arguments for the function
/// * `args_len` - the length of the `args`
/// * `user_key` - the DH key of the user to decrypt `callable` and `args`
/// * `contract_address` - the address of the deployed contract with code `bytecode`
/// * `gas_limit` - the gas limit for the function execution
/// * `result` - the result of the function invocation
// TODO: add arguments of callable.
pub unsafe extern "C" fn ecall_execute(bytecode: *const u8, bytecode_len: usize,
                                       callable: *const u8, callable_len: usize,
                                       args: *const u8, args_len: usize,
                                       user_key: &[u8; 64], contract_address: &ContractAddress,
                                       gas_limit: *const u64, db_ptr: *const RawPointer, result: &mut ExecuteResult) -> EnclaveReturn {
    let bytecode = slice::from_raw_parts(bytecode, bytecode_len);
    let callable = slice::from_raw_parts(callable, callable_len);
    let args = slice::from_raw_parts(args, args_len);

    let mut pre_execution_data = vec![];
    // in order to view the specific error print out the result of the function
    let internal_result = ecall_execute_internal(&mut pre_execution_data, bytecode,
                           callable,
                           args,
                           &user_key,
                           (*contract_address).into(),
                           *gas_limit,
                           db_ptr,
                           result);
    if let Err(ref mut e) = internal_result.clone() {
        debugln!("Error in execution of smart contract function: {}", e);
        sign_if_error(&pre_execution_data, e, result);
    }
    internal_result.into()
}

#[no_mangle]
/// Ecall for deploying contract.
/// arguments:
/// * `bytecode` - WASM pre-deployed bytecode.
/// * `bytecode_len` - the length of `bytecode`.
/// * `constructor` - the encrypted constructor signature
/// * `constructor_len` - the length of `constructor`
/// * `args` - the encrypted arguments for the constructor
/// * `args_len` - the length of `args`
/// * `address` - the address of the contract to be deployed
/// * `user_key` - the DH key of the user to decrypt `constructor` and `args`
/// * `gas_limit` - the gas limit for the constructor execution
/// * `result` - the result of the deployment
pub unsafe extern "C" fn ecall_deploy(bytecode: *const u8, bytecode_len: usize,
                                      constructor: *const u8, constructor_len: usize,
                                      args: *const u8, args_len: usize,
                                      address: &ContractAddress, user_key: &PubKey,
                                      gas_limit: *const u64, db_ptr: *const RawPointer,
                                      result: &mut ExecuteResult) -> EnclaveReturn {
    let args = slice::from_raw_parts(args, args_len);
    let bytecode = slice::from_raw_parts(bytecode, bytecode_len);
    let constructor = slice::from_raw_parts(constructor, constructor_len);
    let mut pre_execution_data = vec![];
    let internal_result = ecall_deploy_internal(&mut pre_execution_data, bytecode, constructor, args, (*address).into(), user_key, *gas_limit, db_ptr, result);
    if let Err(ref mut e) = internal_result.clone() {
        debugln!("Error in deployment of smart contract: {}", e);
        sign_if_error(&pre_execution_data, e, result);
    }
    internal_result.into()
}

#[no_mangle]
pub unsafe extern "C" fn ecall_ptt_req(address: *const ContractAddress, len: usize, sig: &mut [u8; 65], serialized_ptr: *mut u64) -> EnclaveReturn {
    let address_list = slice::from_raw_parts(address, len/mem::size_of::<ContractAddress>());
    let address_list: Vec<Hash256> = address_list.into_iter().map(|a| (*a).into()).collect();
    let msg = match ecall_ptt_req_internal(&address_list, sig) {
        Ok(msg) => msg,
        Err(e) => return e.into(),
    };
    *serialized_ptr = match ocalls_t::save_to_untrusted_memory(&msg[..]) {
        Ok(ptr) => ptr,
        Err(e) => return e.into(),
    };
    EnclaveReturn::Success
}

#[no_mangle]
pub unsafe extern "C" fn ecall_ptt_res(msg_ptr: *const u8, msg_len: usize) -> EnclaveReturn {
    let msg_slice = slice::from_raw_parts(msg_ptr, msg_len);
    ecall_ptt_res_internal(msg_slice).into()
}

#[no_mangle]
pub unsafe extern "C" fn ecall_build_state(db_ptr: *const RawPointer, failed_ptr: *mut u64) -> EnclaveReturn {
    let failed_contracts = match ecall_build_state_internal(db_ptr) {
        Ok(c) => c,
        Err(e) => return e.into(),
    };
    let flatten = failed_contracts.iter().flat_map(|a| a.iter()).cloned().collect::<Vec<u8>>();
    *failed_ptr = match ocalls_t::save_to_untrusted_memory(&flatten) {
        Ok(ptr) => ptr,
        Err(e) => return e.into(),
    };
    EnclaveReturn::Success
}

#[no_mangle]
pub unsafe extern "C" fn ecall_get_user_key(sig: &mut [u8; 65], user_pubkey: &PubKey, serialized_ptr: *mut u64) -> EnclaveReturn {
    let msg = match ecall_get_user_key_internal(sig, user_pubkey) {
        Ok(msg) => msg,
        Err(e) => return e.into(),
    };
    *serialized_ptr = match ocalls_t::save_to_untrusted_memory(&msg[..]) {
        Ok(ptr) => ptr,
        Err(e) => return e.into(),
    };
    EnclaveReturn::Success
}


unsafe fn ecall_evm_internal(bytecode_slice: &[u8], callable_slice: &[u8], callable_args_slice: &[u8],
                             preprocessor_slice: &[u8], callback_slice: &[u8], output: *mut u8,
                             signature: &mut [u8; 65], result_len: &mut usize) -> Result<(), EnclaveError> {

    let callable_args = hexutil::read_hex(str::from_utf8(callable_args_slice)?)?;
    let bytecode = hexutil::read_hex(str::from_utf8(bytecode_slice)?)?;
    let key = get_key();
    let data = prepare_evm_input(callable_slice, &callable_args, preprocessor_slice, &key)?;
    let mut res = call_sputnikvm(&bytecode, data);
    let callback_data: Vec<u8>;
    if !callback_slice.is_empty() {
        callback_data = create_callback(&mut res.1, callback_slice)?;
        *signature = SIGNING_KEY.sign_multiple(&[&callable_args[..], &callback_data, &bytecode])?;
    } else {
        debugln!("Callback cannot be empty");
        return Err(EnclaveError::InputError { message: "Callback cannot be empty".to_string() });
    }

    match res.0 {
        0 => {
            *result_len = callback_data.len();
            ptr::copy_nonoverlapping(callback_data.as_c_ptr(), output, callback_data.len());
            Ok(())
        }
        _ => {
            debugln!("Error in EVM execution");
            Err(EnclaveError::EvmError { err: "Error in EVM execution".to_string() })
        }
    }
}

fn decrypt_inputs(callable: &[u8], args: &[u8], user_key: &PubKey) -> Result<(Vec<u8>, Vec<u8>, String, String, DhKey), EnclaveError>{
    let inputs_key = km_t::users::DH_KEYS.lock_expect("User DH Key")
        .remove(&user_key[..])
        .ok_or(CryptoError::MissingKeyError { key_type: "DH Key" })?;

    let decrypted_callable = decrypt_callable(callable, &inputs_key)?;
    let decrypted_args = decrypt_args(&args, &inputs_key)?;
    let (types, function_name) = {
        let decrypted_callable_str = str::from_utf8(&decrypted_callable)?;
        get_types(&decrypted_callable_str)?
    };
    Ok((decrypted_args, decrypted_callable, types, function_name, inputs_key))
}

fn encrypt_and_save_delta(db_ptr: *const RawPointer, delta: &Option<StatePatch>) -> Result<(Option<EncryptedPatch>, Hash256), EnclaveError> {
    if let Some(delta) = delta {
        let enc_delta = km_t::encrypt_delta(delta.clone())?;
        enigma_runtime_t::ocalls_t::save_delta(db_ptr, &enc_delta)?;
        return Ok((Some(enc_delta.clone()), enc_delta.data.keccak256()))
    }
    Ok((None, Default::default()))
}

fn encrypt_and_save_state(db_ptr: *const RawPointer, state: &ContractState) -> Result<(), EnclaveError>{
    let enc_state = km_t::encrypt_state(state.clone())?;
    enigma_runtime_t::ocalls_t::save_state(db_ptr, &enc_state)?;
    Ok(())
}

fn create_eth_data_to_sign(input: Option<EthereumData>) -> (Vec<u8>, [u8;20]){
    if let Some(bridge) = input {
        (bridge.ethereum_payload, bridge.ethereum_contract_addr)
    }
    else{
        (vec![], [0u8;20])
    }
}

fn sign_if_error (pre_execution_data: &[Box<[u8]>], internal_result: &mut EnclaveError, result: &mut ExecuteResult) {
    // Signing: S(pre-execution data, usedGas, Failure)
    let used_gas = result.used_gas.to_be_bytes();
    let failure = [ResultStatus::Failure.into()];
    let mut to_sign: Vec<&[u8]> = Vec::with_capacity(pre_execution_data.len()+2);
    pre_execution_data.into_iter().for_each(|x| { to_sign.push(&x) });
    to_sign.push(&used_gas);
    to_sign.push(&failure);
    let signature = SIGNING_KEY.sign_multiple(&to_sign);
    match signature {
        Ok(v) => {
            result.signature = v;
        }
        Err(e) => {
            *internal_result = EnclaveError::CryptoError{err: e};
        }
    }
}

unsafe fn ecall_execute_internal(pre_execution_data: &mut Vec<Box<[u8]>>, bytecode: &[u8], callable: &[u8],
                                 args: &[u8], user_key: &PubKey,
                                 address: ContractAddress, gas_limit: u64,
                                 db_ptr: *const RawPointer, result: &mut ExecuteResult) -> Result<(), EnclaveError> {

    let inputs_hash = enigma_crypto::hash::prepare_hash_multiple(&[callable, args, &*address, user_key]).keccak256();
    let exe_code_hash = bytecode.keccak256();
    pre_execution_data.push(Box::new(*inputs_hash));
    pre_execution_data.push(Box::new(*exe_code_hash));
    let pre_execution_state = execution::get_state(db_ptr, address)?;

    let (decrypted_args, _decrypted_callable, types, function_name, key) = decrypt_inputs(callable, args, user_key)?;

    let exec_res = execution::execute_call(&bytecode, gas_limit, pre_execution_state.clone(), function_name, types, decrypted_args.clone())?;

    let (delta, delta_hash) = encrypt_and_save_delta(db_ptr, &exec_res.state_delta)?;

    let encrypted_output = symmetric::encrypt(&exec_res.result, &key)?;
    prepare_wasm_result(delta.clone(),
                        &encrypted_output,
                        exec_res.ethereum_bridge.clone(),
                        exec_res.used_gas,
                        result)?;

    if delta.is_some() {
        encrypt_and_save_state(db_ptr, &exec_res.updated_state)?;
    }

    let (ethereum_payload, ethereum_address) = create_eth_data_to_sign(exec_res.ethereum_bridge);
    // Signing: S(exeCodeHash, inputsHash, delta(X-1)Hash, deltaXHash, outputHash, usedGas, optionalEthereumData, Success)
    let used_gas = result.used_gas.to_be_bytes();
    let output_hash = encrypted_output.keccak256();
    let to_sign = [
        &*exe_code_hash,
        &*inputs_hash,
        &*pre_execution_state.delta_hash,
        &*delta_hash,
        &*output_hash,
        &used_gas[..],
        &ethereum_payload[..],
        &ethereum_address[..],
        &[ResultStatus::Success.into()]];
    result.signature = SIGNING_KEY.sign_multiple(&to_sign)?;
    Ok(())
}

/// Builds Wasm code for contract deployment from the Wasm contract.
/// Gets byte vector with Wasm code.
/// Created code contains one function `call`, which invokes `deploy`.
/// `deploy` invokes the contract constructor from `wasm_code` and returns the bytecode to be deployed
/// Writes created code to a file constructor.wasm in a current directory.
/// This code is based on https://github.com/paritytech/wasm-utils/blob/master/cli/build/main.rs#L68
/// The parameters' values to build function are default parameters as they appear in the original code.
pub fn build_constructor(wasm_code: &[u8]) -> Result<Vec<u8>, EnclaveError> {
    let module = parity_wasm::deserialize_buffer(wasm_code)?;

    let (module, ctor_module) = match build(
        module,
        SourceTarget::Unknown,
        None,
        &Vec::new(),
        false,
        "49152".parse().expect("New stack size is not valid u32"),
        false,
    ) {
        Ok(v) => v,
        Err(e) => panic!("build_constructor: {:?}", e), // TODO: Return error
    };

    let result;

    if let Some(ctor_module) = ctor_module {
        result = parity_wasm::serialize(ctor_module); /*.map_err(Error::Encoding)*/
    } else {
        result = parity_wasm::serialize(module); /*.map_err(Error::Encoding)*/
    }

    match result {
        Ok(v) => Ok(v),
        Err(e) => panic!("build_constructor: {:?}", e), // TODO: Return Error
    }
}

unsafe fn ecall_deploy_internal(pre_execution_data: &mut Vec<Box<[u8]>>, bytecode: &[u8], constructor: &[u8], args: &[u8],
                                address: ContractAddress, user_key: &PubKey,
                                gas_limit: u64, db_ptr: *const RawPointer,
                                result: &mut ExecuteResult) -> Result<(), EnclaveError> {

    let pre_code_hash = bytecode.keccak256();
    let inputs_hash = enigma_crypto::hash::prepare_hash_multiple(&[constructor, args, &pre_code_hash[..], user_key][..]).keccak256();
    pre_execution_data.push(Box::new(*inputs_hash));
    let deploy_bytecode = build_constructor(bytecode)?;

    let (decrypted_args, _, _types, _, _) = decrypt_inputs(constructor, args, user_key)?;

    let state = ContractState::new(address);

    let exec_res = execution::execute_constructor(&deploy_bytecode, gas_limit, state, decrypted_args.clone())?;

    let exe_code = &exec_res.result[..];

    let (delta, delta_hash) = encrypt_and_save_delta(db_ptr, &exec_res.state_delta)?;

    prepare_wasm_result(delta.clone(),
                        exe_code,
                        exec_res.ethereum_bridge.clone(),
                        exec_res.used_gas,
                        result)?;

    encrypt_and_save_state(db_ptr, &exec_res.updated_state)?;

//    let exe_code = &exec_res.result[..];
//    *output_ptr = ocalls_t::save_to_untrusted_memory(&exe_code)?;

    // Signing: S(inputsHash, exeCodeHash, delta0Hash, usedGas, optionalEthereumData, Success)
    let used_gas = result.used_gas.to_be_bytes();
    let (ethereum_payload, ethereum_address) = create_eth_data_to_sign(exec_res.ethereum_bridge);
    let to_sign = [
        &*(inputs_hash),
        &*(exec_res.result.keccak256()),
        &*delta_hash,
        &used_gas[..],
        &ethereum_payload[..],
        &ethereum_address[..],
        &[ResultStatus::Success.into()]
    ];
    result.signature = SIGNING_KEY.sign_multiple(&to_sign)?;
    Ok(())
}

unsafe fn prepare_wasm_result(delta_option: Option<EncryptedPatch>, execute_result: &[u8],
                              ethereum_bridge: Option<EthereumData>, used_gas: u64,
                              result: &mut ExecuteResult ) -> Result<(), EnclaveError>
{
    result.output = ocalls_t::save_to_untrusted_memory(&execute_result)? as *const u8;
    result.used_gas = used_gas;
    match delta_option {
        Some(enc_delta) => {
            result.delta_ptr = ocalls_t::save_to_untrusted_memory(&enc_delta.data)? as *const u8;
            result.delta_index = enc_delta.index;
        }
        None => {
            result.delta_ptr = ocalls_t::save_to_untrusted_memory(&[])? as *const u8;
            result.delta_index = 0;
        }
    }

    match ethereum_bridge{
        Some(ethereum_bridge) => {
            result.ethereum_payload_ptr = ocalls_t::save_to_untrusted_memory(&ethereum_bridge.ethereum_payload)? as *const u8;
            result.ethereum_address.clone_from_slice(&ethereum_bridge.ethereum_contract_addr);
        }
        None => {
            result.ethereum_payload_ptr = ocalls_t::save_to_untrusted_memory(&[])? as *const u8;
            result.ethereum_address = [0u8;20];
        }
    }
    Ok(())
}

fn get_sealed_keys_wrapper() -> asymmetric::KeyPair {
    // Get Home path via Ocall
    let mut path_buf = ocalls_t::get_home_path().unwrap();
    // add the filename to the path: `keypair.sealed`
    path_buf.push("keypair.sealed");
    let sealed_path = path_buf.to_str().unwrap();

    // TODO: Decide what to do if failed to obtain keys.
    match storage_t::get_sealed_keys(&sealed_path) {
        Ok(key) => key,
        Err(err) => panic!("Failed obtaining keys: {:?}", err),
    }
}

pub mod tests {
    extern crate sgx_tstd as std;
    extern crate sgx_tunittest;

    use crate::km_t::principal::tests::*;
    use crate::wasm_g::execution::tests::*;
    use enigma_runtime_t::data::tests::*;
    use enigma_runtime_t::ocalls_t::tests::*;
    use enigma_tools_t::km_primitives::tests::*;
    use enigma_tools_t::storage_t::tests::*;
    use self::sgx_tunittest::*;
    use std::{vec::Vec, string::String};
    use enigma_types::RawPointer;
    //    use crate::km_t::users::tests::*;

    #[no_mangle]
    pub extern "C" fn ecall_run_tests(db_ptr: *const RawPointer) {
        let mut ctr = 0u64;
        let mut failures = Vec::new();
        rsgx_unit_test_start();

        // The reason I had to make our own tests is because baidu's unittest lib supports only static functions that get no inputs.
        core_unitests(&mut ctr, &mut failures, test_full_sealing_storage, "test_full_sealing_storage" );
//        core_unitests(&mut ctr, &mut failures,  test_ecall_evm_signning, "test_ecall_evm_signning" );
        core_unitests(&mut ctr, &mut failures, test_encrypt_state, "test_encrypt_state" );
        core_unitests(&mut ctr, &mut failures, test_decrypt_state, "test_decrypt_state" );
        core_unitests(&mut ctr, &mut failures, test_encrypt_decrypt_state, "test_encrypt_decrypt_state" );
        core_unitests(&mut ctr, &mut failures, test_write_state, "test_write_state" );
        core_unitests(&mut ctr, &mut failures, test_read_state, "test_read_state" );
        core_unitests(&mut ctr, &mut failures, test_diff_patch, "test_diff_patch" );
        core_unitests(&mut ctr, &mut failures, test_encrypt_patch, "test_encrypt_patch" );
        core_unitests(&mut ctr, &mut failures, test_decrypt_patch, "test_decrypt_patch" );
        core_unitests(&mut ctr, &mut failures, test_encrypt_decrypt_patch, "test_encrypt_decrypt_patch" );
        core_unitests(&mut ctr, &mut failures, test_apply_delta, "test_apply_delta" );
        core_unitests(&mut ctr, &mut failures, test_generate_delta, "test_generate_delta" );
        core_unitests(&mut ctr, &mut failures, ||test_me(db_ptr), "test_me" );
        core_unitests(&mut ctr, &mut failures, test_execute_contract, "test_execute_contract" );
        core_unitests(&mut ctr, &mut failures, test_to_message, "test_to_message" );
        core_unitests(&mut ctr, &mut failures, test_from_message, "test_from_message" );
        core_unitests(&mut ctr, &mut failures, test_from_to_message, "test_from_to_message" );
        core_unitests(&mut ctr, &mut failures, test_encrypt_decrypt_response, "test_encrypt_decrypt_response" );
        core_unitests(&mut ctr, &mut failures, test_encrypt_response, "test_encrypt_response" );
        core_unitests(&mut ctr, &mut failures, test_decrypt_reponse, "test_decrypt_reponse" );
        core_unitests(&mut ctr, &mut failures, ||test_get_deltas(db_ptr), "test_get_deltas" );
        core_unitests(&mut ctr, &mut failures, ||test_get_deltas_more(db_ptr), "test_get_deltas_more" );
        core_unitests(&mut ctr, &mut failures, ||test_state_internal(db_ptr), "test_state_internal" );
        core_unitests(&mut ctr, &mut failures, || {test_state(db_ptr)}, "test_state" );


        rsgx_unit_test_end(ctr, failures);

    }

//    fn test_ecall_evm_signning() {
//        let bytecode_hex = "6080604052600436106100ae5763ffffffff7c010000000000000000000000000000000000000000000000000000000060003504166303988f8481146100b357806310f11e84146101165780632aaf281b146102095780633b8332451461028457806357f5fc28146102b4578063850d86191461034a578063a06a58561461035d578063b24fd5c51461037b578063d10e1e69146103ac578063daefe7381461040c578063dd20866e1461045d575b600080fd5b3480156100bf57600080fd5b506100cb60043561051a565b60408051600160a060020a0390991689526020890197909752878701959095526060870193909352608086019190915260a085015260c084015260e083015251908190036101000190f35b34801561012257600080fd5b5061012b610578565b60405180806020018060200180602001848103845287818151815260200191508051906020019060200280838360005b8381101561017357818101518382015260200161015b565b50505050905001848103835286818151815260200191508051906020019060200280838360005b838110156101b257818101518382015260200161019a565b50505050905001848103825285818151815260200191508051906020019060200280838360005b838110156101f15781810151838201526020016101d9565b50505050905001965050505050505060405180910390f35b60408051602060046024803582810135601f810185900485028601850190965285855261026095833563ffffffff1695369560449491939091019190819084018382808284375094975061070e9650505050505050565b6040518082600181111561027057fe5b60ff16815260200191505060405180910390f35b34801561029057600080fd5b506102a263ffffffff60043516610ac2565b60408051918252519081900360200190f35b3480156102c057600080fd5b506102d563ffffffff60043516602435610af3565b6040805160208082528351818301528351919283929083019185019080838360005b8381101561030f5781810151838201526020016102f7565b50505050905090810190601f16801561033c5780820380516001836020036101000a031916815260200191505b509250505060405180910390f35b61035b63ffffffff60043516610bc3565b005b34801561036957600080fd5b50610260600435602435604435610cae565b34801561038757600080fd5b50610390610faf565b60408051600160a060020a039092168252519081900360200190f35b3480156103b857600080fd5b5060408051602060046024803582810135848102808701860190975280865261026096843563ffffffff1696369660449591949091019291829185019084908082843750949750610fbe9650505050505050565b34801561041857600080fd5b5061042a63ffffffff60043516611233565b604080519687526020870195909552858501939093526060850191909152608084015260a0830152519081900360c00190f35b34801561046957600080fd5b506040805160206004602480358281013584810280870186019097528086526104bf96843563ffffffff169636966044959194909101929182918501908490808284375094975050933594506113519350505050565b6040518083815260200180602001828103825283818151815260200191508051906020019060200280838360005b838110156105055781810151838201526020016104ed565b50505050905001935050505060405180910390f35b600180548290811061052857fe5b60009182526020909120600b909102018054600182015460038301546004840154600585015460068601546007870154600a90970154600160a060020a0390961697509395929491939092909188565b60608060608060608060006001805490506040519080825280602002602001820160405280156105b2578160200160208202803883390190505b5060015460408051828152602080840282010190915291955080156105e1578160200160208202803883390190505b506001546040805182815260208084028201019091529194508015610610578160200160208202803883390190505b509150600090505b60015481101561070157600180548290811061063057fe5b90600052602060002090600b0201600a0154848281518110151561065057fe5b6020908102909101015260018054600091908390811061066c57fe5b600091825260208083203384526002600b90930201919091019052604090205411156106ad57600183828151811015156106a257fe5b602090810290910101525b60018054339190839081106106be57fe5b60009182526020909120600b9091020154600160a060020a031614156106f957600182828151811015156106ee57fe5b602090810290910101525b600101610618565b5091959094509092509050565b600080348110610768576040805160e560020a62461bcd02815260206004820152601f60248201527f4465706f7369742076616c7565206d75737420626520706f7369746976652e00604482015290519081900360640190fd5b6001805463ffffffff861690811061077c57fe5b90600052602060002090600b0201600a015460001415156107e7576040805160e560020a62461bcd02815260206004820152601b60248201527f496c6c6567616c20737461746520666f72206465706f736974732e0000000000604482015290519081900360640190fd5b6001805463ffffffff86169081106107fb57fe5b90600052602060002090600b0201905080600601543481151561081a57fe5b0615610896576040805160e560020a62461bcd02815260206004820152602f60248201527f4465706f7369742076616c7565206d7573742062652061206d756c7469706c6560448201527f206f6620636c61696d2076616c75650000000000000000000000000000000000606482015290519081900360840190fd5b33600090815260028201602052604090205415610923576040805160e560020a62461bcd02815260206004820152602a60248201527f43616e6e6f74206465706f73697420747769636520776974682074686520736160448201527f6d65206164647265737300000000000000000000000000000000000000000000606482015290519081900360840190fd5b600381018054349081019091553360009081526002830160205260409020556004810154600882018054859290811061095857fe5b906000526020600020019080519060200190610975929190611477565b506004810180546001908101909155604080513460208083018290529282018490526080808352875190830152865163ffffffff89169433947fce7036acc3606aaa1ec3a2e7b4d13b3f4da34ee1eac298fc47524074de74a3bf948a949390918291606083019160a08401919088019080838360005b83811015610a035781810151838201526020016109eb565b50505050905090810190601f168015610a305780820380516001836020036101000a031916815260200191505b50928303905250600881527f616c6c20676f6f6400000000000000000000000000000000000000000000000060208201526040805191829003019350915050a36007810154600482015410610ab8576001600a82015560405163ffffffff8516907fa98c11bc69afe22b520fe800f82e421f9594d4f06259a7600711b75af05a43b990600090a25b5060009392505050565b600060018263ffffffff16815481101515610ad957fe5b600091825260209091206008600b90920201015492915050565b606060018363ffffffff16815481101515610b0a57fe5b90600052602060002090600b020160080182815481101515610b2857fe5b600091825260209182902001805460408051601f6002600019610100600187161502019094169390930492830185900485028101850190915281815292830182828015610bb65780601f10610b8b57610100808354040283529160200191610bb6565b820191906000526020600020905b815481529060010190602001808311610b9957829003601f168201915b5050505050905092915050565b600060608060018463ffffffff16815481101515610bdd57fe5b6000918252602090912060408051818152606081018252600b909302909101945081602001602082028038833950506040805160018082528183019092529294509050602080830190803883390190505090507f72616e6428290000000000000000000000000000000000000000000000000000816000815181101515610c6057fe5b60209081029091018101919091526040805160018152905163ffffffff8716927fb37f76c8ba24e6a6d20d203681329001f2cacd9ab37c09d8b2aee57b8a31b874928290030190a250505050565b600180546000918190610cc3908281016114f5565b503360018263ffffffff16815481101515610cda57fe5b90600052602060002090600b020160000160006101000a815481600160a060020a030219169083600160a060020a031602179055508460018263ffffffff16815481101515610d2557fe5b90600052602060002090600b02016001018160001916905550600060018263ffffffff16815481101515610d5557fe5b90600052602060002090600b020160030181905550600060018263ffffffff16815481101515610d8157fe5b90600052602060002090600b0201600401819055504260018263ffffffff16815481101515610dac57fe5b90600052602060002090600b0201600501819055508360018263ffffffff16815481101515610dd757fe5b90600052602060002090600b0201600601819055508260018263ffffffff16815481101515610e0257fe5b90600052602060002090600b02016007018190555082604051908082528060200260200182016040528015610e4b57816020015b6060815260200190600190039081610e365790505b506001805463ffffffff8416908110610e6057fe5b90600052602060002090600b02016008019080519060200190610e84929190611526565b5082604051908082528060200260200182016040528015610eaf578160200160208202803883390190505b506001805463ffffffff8416908110610ec457fe5b90600052602060002090600b02016009019080519060200190610ee892919061157f565b50600060018263ffffffff16815481101515610f0057fe5b6000918252602091829020600a600b90920201019190915560408051428152918201879052818101869052606082018590526001608083015260c060a083018190526008908301527f616c6c20676f6f6400000000000000000000000000000000000000000000000060e08301525163ffffffff83169133917f8c2ac5e09d37c38a96fb20791b6ed6f2ccaaaf26c4115680b9257504d32bcdc3918190036101000190a3506000949350505050565b600054600160a060020a031681565b60008060018463ffffffff16815481101515610fd657fe5b90600052602060002090600b0201600a01546001141515611041576040805160e560020a62461bcd02815260206004820152601560248201527f4465616c206973206e6f742065786563757465642e0000000000000000000000604482015290519081900360640190fd5b8260018563ffffffff1681548110151561105757fe5b90600052602060002090600b0201600901908051906020019061107b92919061157f565b50600090505b6001805463ffffffff861690811061109557fe5b90600052602060002090600b02016009018054905081101561115a576001805463ffffffff86169081106110c557fe5b90600052602060002090600b0201600901818154811015156110e357fe5b60009182526020909120015460018054600160a060020a03909216916108fc919063ffffffff881690811061111457fe5b90600052602060002090600b0201600601549081150290604051600060405180830381858888f19350505050158015611151573d6000803e3d6000fd5b50600101611081565b6001805463ffffffff8616917f61347ea145bc2f7f5814e4a2b5e70991c5c42870bfd4df70ab8ea10c41cfa89d918390811061119257fe5b90600052602060002090600b02016006015460018763ffffffff168154811015156111b957fe5b60009182526020918290206009600b9092020101546040805193845263ffffffff909116918301919091526001828201526080606083018190526008908301527f616c6c20676f6f6400000000000000000000000000000000000000000000000060a0830152519081900360c00190a25060009392505050565b60008060008060008060008060008060008060018d63ffffffff1681548110151561125a57fe5b90600052602060002090600b020160010154955060018d63ffffffff1681548110151561128357fe5b90600052602060002090600b020160070154945060018d63ffffffff168154811015156112ac57fe5b90600052602060002090600b020160060154935060018d63ffffffff168154811015156112d557fe5b90600052602060002090600b020160040154925060018d63ffffffff168154811015156112fe57fe5b90600052602060002090600b020160030154915060018d63ffffffff1681548110151561132757fe5b600091825260209091206009600b909202010154959d949c50929a50909850965091945092505050565b815160009060609082805b600083111561146357604080516001880181529051908190036020019020839081151561138557fe5b069150866001840381518110151561139957fe5b90602001906020020151600160a060020a031687838151811015156113ba57fe5b60209081029091010151600160a060020a0316146114575786600184038151811015156113e357fe5b90602001906020020151905086828151811015156113fd57fe5b90602001906020020151876001850381518110151561141857fe5b600160a060020a039092166020928302909101909101528651819088908490811061143f57fe5b600160a060020a039092166020928302909101909101525b6000199092019161135c565b50505063ffffffff94909416949293505050565b828054600181600116156101000203166002900490600052602060002090601f016020900481019282601f106114b857805160ff19168380011785556114e5565b828001600101855582156114e5579182015b828111156114e55782518255916020019190600101906114ca565b506114f19291506115ed565b5090565b81548183558181111561152157600b0281600b028360005260206000209182019101611521919061160a565b505050565b828054828255906000526020600020908101928215611573579160200282015b828111156115735782518051611563918491602090910190611477565b5091602001919060010190611546565b506114f192915061168a565b8280548282559060005260206000209081019282156115e1579160200282015b828111156115e1578251825473ffffffffffffffffffffffffffffffffffffffff1916600160a060020a0390911617825560209092019160019091019061159f565b506114f19291506116ad565b61160791905b808211156114f157600081556001016115f3565b90565b61160791905b808211156114f157805473ffffffffffffffffffffffffffffffffffffffff19168155600060018201819055600382018190556004820181905560058201819055600682018190556007820181905561166c60088301826116de565b61167a6009830160006116ff565b506000600a820155600b01611610565b61160791905b808211156114f15760006116a4828261171d565b50600101611690565b61160791905b808211156114f157805473ffffffffffffffffffffffffffffffffffffffff191681556001016116b3565b50805460008255906000526020600020908101906116fc919061168a565b50565b50805460008255906000526020600020908101906116fc91906115ed565b50805460018160011615610100020316600290046000825580601f1061174357506116fc565b601f0160209004906000526020600020908101906116fc91906115ed5600a165627a7a7230582051910926ea55049d447d261d007a8b619986a8d7905958f802cb0688c27259bd0029".from_hex().unwrap();
//        let callable_args_hex = "f9015c80f90158b8aa3031646436386239366330613337303466303036653431393432356163613962636464633537303465333539356332393735303031343733336266373536653936366465626335393561343466613666383361343065363232393263316262616636313061373933356538613034623333373064363437323837333764636132346463653866323064393935323339643836616630333463636633323631663937623831333762393732b8aa3031646436386239366330613337303466303036653431393432356163613962636464633537303465333539356332393735303031343733336266373536653936366465626335393561343466613666383361343065363232393263316262616636313061373933356538613034623333373064363437323837333764636132346463653866323064393935323339643836616630333463636633323631663937623831333762393732".from_hex().unwrap();
//        let real_output_hex = "d10e1e690000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000020000000000000000000000006330a553fc93768f612722bb8c2ec78ac90b3bbc0000000000000000000000005aeda56215b167893e80b4fe645ba6d5bab767de".to_string().from_hex().unwrap();
//
//        // real_output, bytecode, callable_args
//        let mut to_be_signed: Vec<u8> = Vec::with_capacity(bytecode_hex.len() + callable_args_hex.len() + real_output_hex.len());
//        to_be_signed.extend_from_slice(&callable_args_hex);
//        to_be_signed.extend_from_slice(&real_output_hex);
//        to_be_signed.extend_from_slice(&bytecode_hex);
//        let sig = SIGNING_KEY.sign(&to_be_signed.as_slice()).unwrap();
//
//        // Recover address.
//        let msg = secp256k1::Message::parse(&to_be_signed.keccak256());
//        let mut _sig_obj = [0u8; 64];
//        _sig_obj.copy_from_slice(&sig[..64]);
//        let sig_obj = secp256k1::Signature::parse(&_sig_obj);
//        let rec_id = secp256k1::RecoveryId::parse(*sig.last().unwrap() - 27).unwrap();
//        let recovered_pubkey = secp256k1::recover(&msg, &sig_obj, &rec_id).unwrap();
//        let mut recovered = [0u8; 64];
//        recovered.copy_from_slice(&recovered_pubkey.serialize()[1..65]);
//        assert_eq!(recovered.address(), SIGNING_KEY.get_pubkey().address())
////    }


    use std::panic::UnwindSafe;
    /// Perform one test case at a time.
    ///
    /// This is the core function of sgx_tunittest. It runs one test case at a
    /// time and saves the result. On test passes, it increases the passed counter
    /// and on test fails, it records the failed test.
    fn core_unitests<F, R>(ncases: &mut u64, failurecases: &mut Vec<String>, f:F, name: &str )
        where F: FnOnce() -> R + UnwindSafe {
        *ncases = *ncases + 1;
        match std::panic::catch_unwind (|| { f(); } ).is_ok() {
            true => {
                debugln!("{} {} ... {}!",
                         "testing",
                         name,
                         "\x1B[1;32mok\x1B[0m");
            },
            false => {
                debugln!("{} {} ... {}!",
                         "testing",
                         name,
                         "\x1B[1;31mfailed\x1B[0m");
                failurecases.push(String::from(name));
            },
        }
    }



}
