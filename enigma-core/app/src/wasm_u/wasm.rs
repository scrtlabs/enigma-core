#![allow(dead_code,unused_assignments,unused_variables)]
extern crate sgx_types;
extern crate sgx_urts;

use common_u::errors::EnclaveFailError;
use enigma_types::EnclaveReturn;
use enigma_types::traits::SliceCPtr;
use failure::Error;
use sgx_types::*;

extern "C" {
    fn ecall_deploy(eid: sgx_enclave_id_t, retval: *mut sgx_status_t, bytecode: *const u8, bytecode_len: usize,
                    gas_limit: *const u64, output_ptr: *mut u64) -> sgx_status_t;

    fn ecall_execute(eid: sgx_enclave_id_t, retval: *mut EnclaveReturn,
                     bytecode: *const u8, bytecode_len: usize,
                     callable: *const u8, callable_len: usize,
                     callable_args: *const u8, callable_args_len: usize,
                     gas_limit: *const u64,
                     output: *mut u64, delta_data_ptr: *mut u64,
                     delta_hash_out: &mut [u8; 32], delta_index_out: *mut u32,
                     ethereum_payload: *mut u64,
                     ethereum_contract_addr: &mut [u8; 20]) -> sgx_status_t;
}

const MAX_EVM_RESULT: usize = 100_000;
pub fn deploy(eid: sgx_enclave_id_t,  bytecode: &[u8], gas_limit: u64)-> Result<Box<[u8]>, Error> {
    let mut retval: sgx_status_t = sgx_status_t::SGX_SUCCESS;
    let mut output_ptr: u64 = 0;

    let result = unsafe {
        ecall_deploy(eid,
                     &mut retval,
                     bytecode.as_c_ptr() as *const u8,
                     bytecode.len(),
                     &gas_limit as *const u64,
                     &mut output_ptr as *mut u64)
    };
    let box_ptr = output_ptr as *mut Box<[u8]>;
    let part = unsafe { Box::from_raw(box_ptr ) };
    Ok(*part)
}

#[derive(Clone, Debug, PartialEq, PartialOrd, Eq, Ord, Hash, Default)]
pub struct WasmResult {
    pub bytecode: Vec<u8>,
    pub output: Vec<u8>,
    pub delta: ::db::Delta,
    pub eth_payload: Vec<u8>,
    pub eth_contract_addr: [u8;20],
}

pub fn execute(eid: sgx_enclave_id_t,  bytecode: &[u8], callable: &str, args: &str, gas_limit: u64)-> Result<WasmResult,Error>{
    let mut retval: EnclaveReturn = EnclaveReturn::Success;
    let mut output = 0u64;
    let mut delta_data_ptr = 0u64;
    let mut delta_hash = [0u8; 32];
    let mut delta_index = 0u32;
    let mut ethereum_payload = 0u64;
    let mut ethereum_contract_addr = [0u8; 20];

    let status = unsafe {
        ecall_execute(eid,
                      &mut retval,
                      bytecode.as_c_ptr() as *const u8,
                      bytecode.len(),
                      callable.as_c_ptr() as *const u8,
                      callable.len(),
                      args.as_c_ptr() as *const u8,
                      args.len(),
                      &gas_limit as *const u64,
                      &mut output as *mut u64,
                      &mut delta_data_ptr as *mut u64,
                      &mut delta_hash,
                      &mut delta_index as *mut u32,
                      &mut ethereum_payload as *mut u64,
                      &mut ethereum_contract_addr)
    };

    if retval != EnclaveReturn::Success  || status != sgx_status_t::SGX_SUCCESS {
        return Err(EnclaveFailError{err: retval, status}.into());
    }
    // TODO: Write a handle wrapper that will free the pointers memory in case of an Error.

    let mut result: WasmResult = Default::default();
    let box_ptr = output as *mut Box<[u8]>;
    let output = unsafe { Box::from_raw(box_ptr) };
    result.output = output.to_vec();
    let box_payload_ptr = ethereum_payload as *mut Box<[u8]>;
    let payload = unsafe { Box::from_raw(box_payload_ptr) };
    result.eth_payload = payload.to_vec();
    result.eth_contract_addr = ethereum_contract_addr;
    if delta_data_ptr != 0 && delta_hash != [0u8; 32] && delta_index != 0 {
        // TODO: Replace 0 with maybe max int(accordingly).
        let box_ptr = delta_data_ptr as *mut Box<[u8]>;
        let delta_data = unsafe { Box::from_raw(box_ptr) };
        result.delta.value = delta_data.to_vec();
        // TODO: Elichai look at this please.
        use db::{DeltaKey, Stype};
        result.delta.key = DeltaKey::new(delta_hash, Stype::Delta(delta_index));
    } else {
        bail!("Weird delta results")
    }
    Ok(result)
}

#[cfg(test)]
pub mod tests {
    #![allow(dead_code, unused_assignments, unused_variables)]

    use esgx;
    use sgx_urts::SgxEnclave;
    use std::fs::File;
    use std::io::Read;
    use std::path::PathBuf;
    use sgx_types::*;
    use std::process::Command;
    use wasm_u::wasm;
    use std::str::from_utf8;

    fn init_enclave() -> SgxEnclave {
        let enclave = match esgx::general::init_enclave_wrapper() {
            Ok(r) => {
                println!("[+] Init Enclave Successful {}!", r.geteid());
                r
            }
            Err(x) => {
                panic!("[-] Init Enclave Failed {}!", x.as_str());
            }
        };
        enclave
    }

    fn compile_and_deploy_wasm_contract(eid: sgx_enclave_id_t, test_path: &str) -> Box<[u8]>{
        let mut dir = PathBuf::new();
        dir.push(test_path);
        let mut output = Command::new("cargo")
            .current_dir(&dir)
            .args(&["build", "--release"])
            .spawn()
            .expect(&format!("Failed compiling wasm contract: {:?}", &dir) );

        assert!(output.wait().unwrap().success());
        dir.push("target/wasm32-unknown-unknown/release/contract.wasm");

        let mut f = File::open(&dir).expect(&format!("Can't open the contract.wasm file: {:?}", &dir));
        let mut wasm_code = Vec::new();
        f.read_to_end(&mut wasm_code).expect("Failed reading the wasm file");
        println!("Bytecode size: {}KB\n", wasm_code.len()/1024);
        wasm::deploy(eid, &wasm_code, 100_000).expect("Deploy Failed")
    }

    #[test]
    fn simple() {
        let enclave = init_enclave();
        let contract_code = compile_and_deploy_wasm_contract(enclave.geteid(), "../../examples/eng_wasm_contracts/simplest");
//        let result = wasm::execute(enclave.geteid(),contract_code, "test(uint256,uint256)", "c20102").expect("Execution failed");
        let result = wasm::execute(enclave.geteid(), &contract_code, "write()", "", 100_000).expect("Execution failed");
        enclave.destroy();
        assert_eq!(from_utf8(&result.output).unwrap(), "\"157\"");
    }

    #[test]
    fn eth_bridge() {
        let enclave = init_enclave();
        let contract_code = compile_and_deploy_wasm_contract(enclave.geteid(), "../../examples/eng_wasm_contracts/contract_with_eth_calls");
        let result = wasm::execute(enclave.geteid(), &contract_code, "test()", "", 100_000).expect("Execution failed");
        enclave.destroy();
    }

    #[ignore]
    #[test]
    pub fn contract() {
        let mut f = File::open(
            "../../examples/eng_wasm_contracts/simplest/target/wasm32-unknown-unknown/release/contract.wasm",
        )
        .unwrap();
        let mut wasm_code = Vec::new();
        f.read_to_end(&mut wasm_code).unwrap();
        println!("Bytecode size: {}KB\n", wasm_code.len() / 1024);
        let enclave = init_enclave();
        let contract_code = wasm::deploy(enclave.geteid(), &wasm_code, 100_000).expect("Deploy Failed");
        let result = wasm::execute(enclave.geteid(),&contract_code, "call", "", 100_000).expect("Execution failed");
        assert_eq!(from_utf8(&result.output).unwrap(), "157");
    }
}
