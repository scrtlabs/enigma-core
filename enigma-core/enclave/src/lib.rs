#![crate_name = "enigmacoreenclave"]
#![crate_type = "staticlib"]
#![no_std]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]
#![warn(clippy::all)]
#![warn(unused_extern_crates)]
#![allow(clippy::cast_ptr_alignment)] // TODO: Try to remove it when fixing the sealing
#![allow(unused_attributes)] // TODO: Remove on future nightly https://github.com/rust-lang/rust/issues/60050

extern crate enigma_runtime_t;
#[macro_use]
extern crate enigma_tools_t;
extern crate enigma_crypto;
extern crate enigma_tools_m;
extern crate enigma_types;

//#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgx_tstd as std;
extern crate sgx_types;

#[macro_use]
extern crate serde_json;
#[macro_use]
extern crate lazy_static;

mod km_t;

use crate::{
    km_t::{ecall_build_state_internal, ecall_get_user_key_internal, ecall_ptt_req_internal, ecall_ptt_res_internal},
};
use enigma_crypto::{asymmetric, hash::Keccak256, symmetric, CryptoError};
use enigma_runtime_t::{
    data::{ContractState, EncryptedPatch},
    wasm_execution::WasmEngine,
    EthereumData,
};
use enigma_tools_m::utils::{EthereumAddress, LockExpectMutex};
use enigma_tools_t::{
    build_arguments_g::*,
    common::errors_t::{
        EnclaveError::{self, *},
        FailedTaskError::*,
    },
    esgx::ocalls_t,
    quote_t, storage_t,
};
use enigma_types::{
    ContractAddress, DhKey, EnclaveReturn, ExecuteResult, Hash256, PubKey, RawPointer, ResultStatus,
};

use sgx_types::*;
use std::{
    boxed::Box, slice, str,
    string::String,
    vec::Vec,
};

lazy_static! {
    pub(crate) static ref SIGNING_KEY: asymmetric::KeyPair = get_sealed_keys_wrapper();
    pub(crate) static ref ETHEREUM_KEY: asymmetric::KeyPair = get_ethereum_keys_wrapper();
}

#[no_mangle]
pub extern "C" fn ecall_get_registration_quote(target_info: &sgx_target_info_t, real_report: &mut sgx_report_t) -> sgx_status_t {
    quote_t::create_report_with_data(&target_info, real_report, &SIGNING_KEY.get_pubkey().address())
}

#[no_mangle]
pub extern "C" fn ecall_get_signing_address(pubkey: &mut [u8; 20]) { pubkey.copy_from_slice(&SIGNING_KEY.get_pubkey().address()); }

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
pub unsafe extern "C" fn ecall_execute(
    bytecode: *const u8,
    bytecode_len: usize,
    callable: *const u8,
    callable_len: usize,
    args: *const u8,
    args_len: usize,
    user_key: &[u8; 64],
    contract_address: &ContractAddress,
    gas_limit: *const u64,
    db_ptr: *const RawPointer,
    result: &mut ExecuteResult,
) -> EnclaveReturn
{
    let bytecode = slice::from_raw_parts(bytecode, bytecode_len);
    let callable = slice::from_raw_parts(callable, callable_len);
    let args = slice::from_raw_parts(args, args_len);

    let mut pre_execution_data = vec![];
    let io_key = match get_io_key(user_key) {
        Ok(v) => v,
        Err(e) => return e.into(),
    };

    // in order to view the specific error print out the result of the function
    let mut internal_result = ecall_execute_internal(
        &mut pre_execution_data,
        bytecode,
        callable,
        args,
        user_key,
        &io_key,
        (*contract_address).into(),
        *gas_limit,
        db_ptr,
        result,
    );
    if let Err(e) = &internal_result {
        debug_println!("Error in execution of secret contract function: {}", e);
        internal_result = output_task_failure(&pre_execution_data, *gas_limit, e, result, &io_key);
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
pub unsafe extern "C" fn ecall_deploy(
    bytecode: *const u8,
    bytecode_len: usize,
    constructor: *const u8,
    constructor_len: usize,
    args: *const u8,
    args_len: usize,
    address: &ContractAddress,
    user_key: &PubKey,
    gas_limit: *const u64,
    db_ptr: *const RawPointer,
    result: &mut ExecuteResult,
) -> EnclaveReturn
{
    let args = slice::from_raw_parts(args, args_len);
    let bytecode = slice::from_raw_parts(bytecode, bytecode_len);
    let constructor = slice::from_raw_parts(constructor, constructor_len);
    let mut pre_execution_data = vec![];
    let io_key;
    match get_io_key(user_key) {
        Ok(v) => io_key = v,
        Err(e) => return e.into(),
    }
    let mut internal_result = ecall_deploy_internal(
        &mut pre_execution_data,
        bytecode,
        constructor,
        args,
        (*address).into(),
        user_key,
        &io_key,
        *gas_limit,
        db_ptr,
        result,
    );
    if let Err(e) = &internal_result {
        debug_println!("Error in deployment of secret contract function: {}", e);
        internal_result = output_task_failure(&pre_execution_data, *gas_limit, e, result, &io_key);
    }
    internal_result.into()
}

#[no_mangle]
pub unsafe extern "C" fn ecall_ptt_req(sig: &mut [u8; 65], serialized_ptr: *mut u64) -> EnclaveReturn {
    let msg = match ecall_ptt_req_internal(sig) {
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

fn get_io_key(user_key: &PubKey) -> Result<DhKey, EnclaveError> {
    let io_key = km_t::users::DH_KEYS
        .lock_expect("User DH Key")
        .remove(&user_key[..])
        .ok_or(CryptoError::MissingKeyError { key_type: "DH Key" })?;
    Ok(io_key)
}

fn decrypt_inputs(callable: &[u8], args: &[u8], inputs_key: &DhKey) -> Result<(Vec<u8>, String), EnclaveError> {
    let decrypted_callable = decrypt_callable(callable, &inputs_key)?;
    let decrypted_args = decrypt_args(&args, &inputs_key)?;
    let (_, function_name) = {
        let decrypted_callable_str = str::from_utf8(&decrypted_callable)?;
        get_types(&decrypted_callable_str)?
    };
    Ok((decrypted_args, function_name))
}

fn get_enc_delta(delta: &Option<EncryptedPatch>) -> Hash256 {
    if let Some(delta) = delta {
        delta.keccak256_patch()
    } else {
        Hash256::default()
    }
}

unsafe fn store_delta_and_state(
    db_ptr: *const RawPointer,
    delta: &Option<EncryptedPatch>,
    state: &ContractState,
) -> Result<(), EnclaveError>
{
    match delta {
        Some(d) => {
            let enc_state = km_t::encrypt_state(state.clone())?;
            enigma_runtime_t::ocalls_t::save_delta(db_ptr, d)?;
            // if the state isn't able to be stored, then remove the delta as well and fail the task
            enigma_runtime_t::ocalls_t::save_state(db_ptr, &enc_state).
                or_else(|_| enigma_runtime_t::ocalls_t::remove_delta(db_ptr, d))
        }
        None => Ok(()),
    }
}

fn create_eth_data_to_sign(input: Option<EthereumData>) -> (Vec<u8>, [u8; 20]) {
    if let Some(bridge) = input {
        (bridge.ethereum_payload, bridge.ethereum_contract_addr)
    } else {
        (vec![], [0u8; 20])
    }
}

fn output_task_failure(
    pre_execution_data: &[Box<[u8]>],
    gas_limit: u64,
    err: &EnclaveError,
    result: &mut ExecuteResult,
    key: &DhKey,
) -> Result<(), EnclaveError>
{
    // Signing: S(pre-execution data, usedGas, Failure)
    result.used_gas = 0;
    let return_error = match err {
        FailedTaskError(_) => err.clone(),
        FailedTaskErrorWithGas { used_gas, err } => {
            result.used_gas = *used_gas;
            FailedTaskError(err.clone())
        }
        SystemError(e) => return Err(SystemError(e.clone())),
    };
    let used_gas = result.used_gas.to_be_bytes();
    let serialised_gas_limit = gas_limit.to_be_bytes();
    let failure = [ResultStatus::Failure as u8];
    let mut to_sign: Vec<&[u8]> = Vec::with_capacity(pre_execution_data.len() + 2);
    pre_execution_data.into_iter().for_each(|x| to_sign.push(&x));
    to_sign.push(&serialised_gas_limit);
    to_sign.push(&used_gas);
    to_sign.push(&failure);
    result.signature = SIGNING_KEY.sign_multiple(&to_sign)?;
    let error_text = format!("{}", return_error);
    let encrypted_result = symmetric::encrypt(error_text.as_bytes(), &key)?;
    result.output = ocalls_t::save_to_untrusted_memory(&encrypted_result)? as *const u8;
    Err(return_error)
}

unsafe fn ecall_execute_internal(
    pre_execution_data: &mut Vec<Box<[u8]>>,
    bytecode: &[u8],
    callable: &[u8],
    args: &[u8],
    user_key: &PubKey,
    io_key: &DhKey,
    address: ContractAddress,
    gas_limit: u64,
    db_ptr: *const RawPointer,
    result: &mut ExecuteResult,
) -> Result<(), EnclaveError>
{
    // TODO: make sure the state is up to date.
    // TODO: Should this be here or on the untrusted side via build_state?;

    let inputs_hash = enigma_crypto::hash::prepare_hash_multiple(&[callable, args, &*address, user_key]).keccak256();
    let exe_code_hash = bytecode.keccak256();
    pre_execution_data.push(Box::new(*inputs_hash));
    pre_execution_data.push(Box::new(*exe_code_hash));
    let pre_execution_state = km_t::get_state(db_ptr, address)?;

    let (decrypted_args, function_name) =
        decrypt_inputs(callable, args, io_key).map_err(|e| FailedTaskError(InputError { message: format!("{}", e) }))?;

    let state_key = km_t::get_state_key(address)?;
    let mut engine =
        WasmEngine::new_compute(&bytecode, gas_limit, decrypted_args.clone(), pre_execution_state.clone(), function_name, state_key)?;
    engine.compute()?;
    let exec_res = engine.into_result()?;

    let delta_hash = get_enc_delta(&exec_res.state_delta);
    let encrypted_output = symmetric::encrypt(&exec_res.result, io_key)?;
    prepare_wasm_result(&exec_res.state_delta, &encrypted_output, exec_res.ethereum_bridge.clone(), exec_res.used_gas, result)?;

    let (ethereum_payload, ethereum_address) = create_eth_data_to_sign(exec_res.ethereum_bridge);
    // Signing: S(exeCodeHash, inputsHash, delta(X-1)Hash, deltaXHash, outputHash, gasLimit, usedGas, optionalEthereumData, Success)
    let used_gas = result.used_gas.to_be_bytes();
    let output_hash = encrypted_output.keccak256();
    let to_sign: &[&[u8]] = &[
        &*exe_code_hash,
        &*inputs_hash,
        &*pre_execution_state.delta_hash,
        &*delta_hash,
        &*output_hash,
        &gas_limit.to_be_bytes(),
        &used_gas,
        &ethereum_payload,
        &ethereum_address,
        &[ResultStatus::Ok as u8],
    ];
    result.signature = SIGNING_KEY.sign_multiple(to_sign)?;
    store_delta_and_state(db_ptr, &exec_res.state_delta, &exec_res.updated_state)?;
    Ok(())
}

unsafe fn ecall_deploy_internal(
    pre_execution_data: &mut Vec<Box<[u8]>>,
    bytecode: &[u8],
    constructor: &[u8],
    args: &[u8],
    address: ContractAddress,
    user_key: &PubKey,
    io_key: &DhKey,
    gas_limit: u64,
    db_ptr: *const RawPointer,
    result: &mut ExecuteResult,
) -> Result<(), EnclaveError>
{
    let pre_code_hash = bytecode.keccak256();
    let inputs_hash = enigma_crypto::hash::prepare_hash_multiple(&[constructor, args, &pre_code_hash[..], user_key][..]).keccak256();
    pre_execution_data.push(Box::new(*inputs_hash));

    let (decrypted_args, function_name) =
        decrypt_inputs(constructor, args, io_key).map_err(|e| FailedTaskError(InputError { message: format!("{}", e) }))?;

    let state = ContractState::new(address);

    let state_key = km_t::get_state_key(address)?;
    let mut engine = WasmEngine::new_deploy(bytecode, gas_limit, decrypted_args.clone(), state, function_name, state_key)?;
    engine.deploy()?;
    let exec_res = engine.into_result()?;

    let exe_code = &exec_res.result[..];

    let delta_hash = get_enc_delta(&exec_res.state_delta);

    prepare_wasm_result(&exec_res.state_delta, exe_code, exec_res.ethereum_bridge.clone(), exec_res.used_gas, result)?;

    // Signing: S(inputsHash, exeCodeHash, delta0Hash, gasLimit, usedGas, optionalEthereumData, Success)
    let used_gas = result.used_gas.to_be_bytes();
    let (ethereum_payload, ethereum_address) = create_eth_data_to_sign(exec_res.ethereum_bridge);
    let to_sign: &[&[u8]] = &[
        &*inputs_hash,
        &*exec_res.result.keccak256(),
        &*delta_hash,
        &gas_limit.to_be_bytes(),
        &used_gas,
        &ethereum_payload,
        &ethereum_address,
        &[ResultStatus::Ok as u8],
    ];
    result.signature = SIGNING_KEY.sign_multiple(to_sign)?;
    store_delta_and_state(db_ptr, &exec_res.state_delta, &exec_res.updated_state)?;
    Ok(())
}

unsafe fn prepare_wasm_result(
    delta_option: &Option<EncryptedPatch>,
    execute_result: &[u8],
    ethereum_bridge: Option<EthereumData>,
    used_gas: u64,
    result: &mut ExecuteResult,
) -> Result<(), EnclaveError>
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

    match ethereum_bridge {
        Some(ethereum_bridge) => {
            result.ethereum_payload_ptr = ocalls_t::save_to_untrusted_memory(&ethereum_bridge.ethereum_payload)? as *const u8;
            result.ethereum_address.clone_from_slice(&ethereum_bridge.ethereum_contract_addr);
        }
        None => {
            result.ethereum_payload_ptr = ocalls_t::save_to_untrusted_memory(&[])? as *const u8;
            result.ethereum_address = [0u8; 20];
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

fn get_ethereum_keys_wrapper() -> asymmetric::KeyPair {
    // Get Home path via Ocall
    let mut path_buf = ocalls_t::get_home_path().unwrap();
    // add the filename to the path: `keypair.sealed`
    path_buf.push("eth_keypair.sealed");
    let sealed_path = path_buf.to_str().unwrap();

    // TODO: Decide what to do if failed to obtain keys.
    match storage_t::get_sealed_keys(&sealed_path) {
        Ok(key) => key,
        Err(err) => panic!("Failed obtaining keys: {:?}", err),
    }
}

pub mod tests {
    use enigma_types::{RawPointer, ResultStatus};

    #[cfg(debug_assertions)]
    mod internal_tests {
        extern crate sgx_tstd as std;
        extern crate sgx_tunittest;

        use self::sgx_tunittest::*;
        use crate::km_t::principal::tests::*;
        use enigma_runtime_t::{data::tests::*, ocalls_t::tests::*, wasm_execution::tests::*};
        use enigma_tools_t::storage_t::tests::*;
        use enigma_types::{RawPointer, ResultStatus};
        use std::{panic::UnwindSafe, string::String, vec::Vec};

        pub unsafe fn internal_tests(db_ptr: *const RawPointer) -> ResultStatus {
            let mut ctr = 0u64;
            let mut failures = Vec::new();
            rsgx_unit_test_start();

            // The reason I had to make our own tests is because baidu's unittest lib supports only static functions that get no inputs.
            core_unitests(&mut ctr, &mut failures, test_full_sealing_storage, "test_full_sealing_storage");
            core_unitests(&mut ctr, &mut failures, test_encrypt_state, "test_encrypt_state");
            core_unitests(&mut ctr, &mut failures, test_decrypt_state, "test_decrypt_state");
            core_unitests(&mut ctr, &mut failures, test_encrypt_decrypt_state, "test_encrypt_decrypt_state");
            core_unitests(&mut ctr, &mut failures, test_write_state, "test_write_state");
            core_unitests(&mut ctr, &mut failures, test_read_state, "test_read_state");
            core_unitests(&mut ctr, &mut failures, test_diff_patch, "test_diff_patch");
            core_unitests(&mut ctr, &mut failures, test_encrypt_patch, "test_encrypt_patch");
            core_unitests(&mut ctr, &mut failures, test_decrypt_patch, "test_decrypt_patch");
            core_unitests(&mut ctr, &mut failures, test_encrypt_decrypt_patch, "test_encrypt_decrypt_patch");
            core_unitests(&mut ctr, &mut failures, test_apply_delta, "test_apply_delta");
            core_unitests(&mut ctr, &mut failures, test_generate_delta, "test_generate_delta");
            core_unitests(&mut ctr, &mut failures, || test_me(db_ptr), "test_me");
            core_unitests(&mut ctr, &mut failures, test_execute_contract, "test_execute_contract");
            core_unitests(&mut ctr, &mut failures, || test_get_deltas(db_ptr), "test_get_deltas");
            core_unitests(&mut ctr, &mut failures, || test_get_deltas_more(db_ptr), "test_get_deltas_more");
            core_unitests(&mut ctr, &mut failures, || test_state_internal(db_ptr), "test_state_internal");
            core_unitests(&mut ctr, &mut failures, || test_state(db_ptr), "test_state");
            core_unitests(&mut ctr, &mut failures, || {test_remove_delta(db_ptr)}, "test_remove_delta");
            let result = failures.is_empty();
            rsgx_unit_test_end(ctr, failures);
            result.into()
        }

        /// Perform one test case at a time.
        ///
        /// This is the core function of sgx_tunittest. It runs one test case at a
        /// time and saves the result. On test passes, it increases the passed counter
        /// and on test fails, it records the failed test.
        fn core_unitests<F, R>(ncases: &mut u64, failurecases: &mut Vec<String>, f: F, name: &str)
        where F: FnOnce() -> R + UnwindSafe {
            *ncases = *ncases + 1;
            match std::panic::catch_unwind(|| {
                f();
            })
            .is_ok()
            {
                true => {
                    debug_println!("{} {} ... {}!", "testing", name, "\x1B[1;32mok\x1B[0m");
                }
                false => {
                    debug_println!("{} {} ... {}!", "testing", name, "\x1B[1;31mfailed\x1B[0m");
                    failurecases.push(String::from(name));
                }
            }
        }
    }

    //    use crate::km_t::users::tests::*;

    #[no_mangle]
    pub unsafe extern "C" fn ecall_run_tests(db_ptr: *const RawPointer, result: *mut ResultStatus) {
        *result = ResultStatus::Ok;
        #[cfg(debug_assertions)]
        {
            let internal_tests_result = self::internal_tests::internal_tests(db_ptr);
            *result = internal_tests_result;
        }
    }
}
