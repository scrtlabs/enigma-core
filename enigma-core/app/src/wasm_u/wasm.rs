#![allow(dead_code)]
extern crate sgx_types;
extern crate sgx_urts;

use crate::common_u::errors::EnclaveFailError;
use crate::db::{DeltaKey, Stype};
use crate::km_u::{ContractAddress, PubKey};
use enigma_types::traits::SliceCPtr;
use enigma_types::{EnclaveReturn, ExecuteResult};
use failure::Error;
use sgx_types::*;

extern "C" {
    fn ecall_deploy(eid: sgx_enclave_id_t, retval: *mut EnclaveReturn,
                    bytecode: *const u8, bytecode_len: usize, args: *const u8,
                    args_len: usize, address: &ContractAddress, user_key: &PubKey,
                    gas_limit: *const u64, output_ptr: *mut u64, sig: &mut [u8; 65] ) -> sgx_status_t;

    fn ecall_execute(eid: sgx_enclave_id_t, retval: *mut EnclaveReturn,
                     bytecode: *const u8, bytecode_len: usize, callable: *const u8,
                     callable_len: usize, callable_args: *const u8, callable_args_len: usize,
                     user_key: &PubKey, contract_address: &ContractAddress,
                     gas_limit: *const u64, result: &mut ExecuteResult ) -> sgx_status_t;
}

const MAX_EVM_RESULT: usize = 100_000;
pub fn deploy(eid: sgx_enclave_id_t, bytecode: &[u8], args: &[u8], contract_address: ContractAddress,
              user_pubkey: &PubKey, gas_limit: u64, ) -> Result<(Box<[u8]>, [u8; 65]), Error> {
    let mut retval = EnclaveReturn::Success;
    let mut output_ptr: u64 = 0;
    let mut signature = [0u8; 65];

    let status = unsafe {
        ecall_deploy(
            eid,
            &mut retval,
            bytecode.as_c_ptr(),
            bytecode.len(),
            args.as_c_ptr(),
            args.len(),
            &contract_address,
            &user_pubkey,
            &gas_limit as *const u64,
            &mut output_ptr as *mut u64,
            &mut signature,
        )
    };
    if retval != EnclaveReturn::Success || status != sgx_status_t::SGX_SUCCESS {
        return Err(EnclaveFailError { err: retval, status }.into());
    }
    let box_ptr = output_ptr as *mut Box<[u8]>;
    assert!(!box_ptr.is_null()); // TODO: Think about this
    let part = unsafe { Box::from_raw(box_ptr) };
    Ok((*part, signature))
}

#[derive(Clone, Debug, PartialEq, PartialOrd, Eq, Ord, Hash, Default)]
pub struct WasmResult {
    pub bytecode: Vec<u8>,
    pub output: Vec<u8>,
    pub delta: ::db::Delta,
    pub eth_payload: Vec<u8>,
    pub eth_contract_addr: [u8; 20],
    pub signature: Vec<u8>,
}

pub fn execute(eid: sgx_enclave_id_t, bytecode: &[u8], callable: &str, args: &str,
               user_pubkey: &PubKey, address: &ContractAddress, gas_limit: u64, ) -> Result<WasmResult, Error> {
    let mut retval = EnclaveReturn::Success;
    let mut result = ExecuteResult::default();


    let status = unsafe {
        ecall_execute(eid,
                      &mut retval,
                      bytecode.as_c_ptr() as *const u8,
                      bytecode.len(),
                      callable.as_c_ptr() as *const u8,
                      callable.len(),
                      args.as_c_ptr() as *const u8,
                      args.len(),
                      &user_pubkey,
                      &address,
                      &gas_limit as *const u64,
                      &mut result)
    };

    if retval != EnclaveReturn::Success || status != sgx_status_t::SGX_SUCCESS {
        return Err(EnclaveFailError { err: retval, status }.into());
    }
    // TODO: Write a handle wrapper that will free the pointers memory in case of an Error.

    let mut new_result: WasmResult = Default::default();

    new_result.signature = result.signature.to_vec();

    assert!(!result.output.is_null()); // TODO: Think about this
    let box_ptr = result.output as *mut Box<[u8]>;
    let output = unsafe { Box::from_raw(box_ptr) };
    new_result.output = output.to_vec();

    assert!(!result.ethereum_payload_ptr.is_null()); // TODO: Think about this
    let box_payload_ptr = result.ethereum_payload_ptr as *mut Box<[u8]>;
    let payload = unsafe { Box::from_raw(box_payload_ptr) };
    new_result.eth_payload = payload.to_vec();

    new_result.eth_contract_addr = result.ethereum_address;
    if !result.delta_ptr.is_null() && result.delta_hash != [0u8; 32] && result.delta_index != 0 {
//    if result.delta_ptr != 0 && result.delta_hash != [0u8; 32] && result.delta_index != 0 {
        // TODO: Replace 0 with maybe max int(accordingly).
        let box_ptr = result.delta_ptr as *mut Box<[u8]>;
        assert!(!box_ptr.is_null()); // TODO: Think about this
        let delta_data = unsafe { Box::from_raw(box_ptr) };
        new_result.delta.value = delta_data.to_vec();
        new_result.delta.key = DeltaKey::new(result.delta_hash, Stype::Delta(result.delta_index));
    } else {
        bail!("Weird delta results")
    }
    Ok(new_result)
}

#[cfg(test)]
pub mod tests {
    extern crate ring;

    use self::ring::rand::*;
    use super::ContractAddress;
    use crate::esgx::general::init_enclave_wrapper;
    use crate::km_u::tests::exchange_keys;
    use crate::km_u::tests::instantiate_encryption_key;
    use crate::wasm_u::wasm;
    use enigma_tools_u::common_u::Sha256;
    use sgx_types::*;
    use std::fs::File;
    use std::io::Read;
    use std::path::PathBuf;
    use std::process::Command;
    use std::str::from_utf8;

    fn generate_address() -> ContractAddress {
        let mut address = [0u8; 32];
        SystemRandom::new().fill(&mut address).unwrap();
        address
    }

    fn compile_and_deploy_wasm_contract(eid: sgx_enclave_id_t, test_path: &str, address: ContractAddress) -> (Box<[u8]>, [u8; 65]) {
        let mut dir = PathBuf::new();
        dir.push(test_path);
        let mut output = Command::new("cargo")
            .current_dir(&dir)
            .args(&["build", "--release"])
            .spawn()
            .expect(&format!("Failed compiling wasm contract: {:?}", &dir));

        assert!(output.wait().unwrap().success());
        dir.push("target/wasm32-unknown-unknown/release/contract.wasm");

        let mut f = File::open(&dir).expect(&format!("Can't open the contract.wasm file: {:?}", &dir));
        let mut wasm_code = Vec::new();
        f.read_to_end(&mut wasm_code).expect("Failed reading the wasm file");
        println!("Bytecode size: {}KB\n", wasm_code.len() / 1024);

        let (pubkey, ..) = exchange_keys(eid);
        wasm::deploy(eid, &wasm_code, &[], address, &pubkey, 100_000).expect("Deploy Failed")
    }

    #[test]
    fn simple() {
        let enclave = init_enclave_wrapper().unwrap();
        let address = generate_address();
        instantiate_encryption_key(&[address], enclave.geteid());

        let (contract_code, _) =
            compile_and_deploy_wasm_contract(enclave.geteid(), "../../examples/eng_wasm_contracts/simplest", address);
        //        let result = wasm::execute(enclave.geteid(),contract_code, "test(uint256,uint256)", "c20102").expect("Execution failed");
        let (pubkey, ..) = exchange_keys(enclave.geteid());
        let result =
            wasm::execute(enclave.geteid(), &contract_code, "write()", "", &pubkey, &address, 100_000).expect("Execution failed");
        enclave.destroy();
        assert_eq!(from_utf8(&result.output).unwrap(), "\"157\"");
    }

    #[test]
    fn eth_bridge() {
        let enclave = init_enclave_wrapper().unwrap();
        let address = generate_address();
        instantiate_encryption_key(&[address], enclave.geteid());

        let (contract_code, _) =
            compile_and_deploy_wasm_contract(enclave.geteid(), "../../examples/eng_wasm_contracts/contract_with_eth_calls", address);
        let (pubkey, ..) = exchange_keys(enclave.geteid());
        let result =
            wasm::execute(enclave.geteid(), &contract_code, "test()", "", &pubkey, &address, 100_000).expect("Execution failed");
        enclave.destroy();
    }

    #[ignore]
    #[test]
    pub fn contract() {
        let mut f =
            File::open("../../examples/eng_wasm_contracts/simplest/target/wasm32-unknown-unknown/release/contract.wasm").unwrap();
        let mut wasm_code = Vec::new();
        f.read_to_end(&mut wasm_code).unwrap();
        println!("Bytecode size: {}KB\n", wasm_code.len() / 1024);
        let enclave = init_enclave_wrapper().unwrap();

        let address = b"Enigma".sha256();
        instantiate_encryption_key(&[address], enclave.geteid());

        let (pubkey, ..) = exchange_keys(enclave.geteid());
        let (contract_code, _) =
            wasm::deploy(enclave.geteid(), &wasm_code, &[], b"enigma".sha256(), &pubkey, 100_000).expect("Deploy Failed");
        let (pubkey, ..) = exchange_keys(enclave.geteid());
        let result =
            wasm::execute(enclave.geteid(), &contract_code, "call", "", &pubkey, &address, 100_000).expect("Execution failed");
        assert_eq!(from_utf8(&result.output).unwrap(), "157");
    }
}
