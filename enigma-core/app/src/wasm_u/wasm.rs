#![allow(dead_code,unused_assignments,unused_variables)]
extern crate sgx_types;
extern crate sgx_urts;


use sgx_types::*;
use failure::Error;

extern {
    fn ecall_deploy(eid: sgx_enclave_id_t,
                 retval: *mut sgx_status_t,
                 bytecode: *const u8, bytecode_len: usize,
                 output_ptr: *mut u64) -> sgx_status_t;

    fn ecall_execute(eid: sgx_enclave_id_t, retval: *mut sgx_status_t,
                     bytecode: *const u8, bytecode_len: usize,
                     callable: *const u8, callable_len: usize,
                     output: *mut u64, delta_data_ptr: *mut u64,
                     delta_hash_out: &mut [u8; 32], delta_index_out: *mut u32) -> sgx_status_t;
}


/// This module builds Wasm code for contract deployment from the Wasm contract.
/// The contract should be written in rust and then compiled to Wasm with wasm32-unknown-unknown target.
/// The code is based on Parity wasm_utils::cli.

extern crate pwasm_utils as utils;
extern crate parity_wasm;

use self::utils::{build, SourceTarget};

/// Builds Wasm code for contract deployment from the Wasm contract.
/// Gets byte vector with Wasm code.
/// Writes created code to a file constructor.wasm in a current directory.
/// This code is based on https://github.com/paritytech/wasm-utils/blob/master/cli/build/main.rs#L68
/// The parameters' values to build function are default parameters as they appear in the original code.
pub fn build_constructor(wasm_code: &[u8]) -> Result<Vec<u8>, Error> {

    let module = parity_wasm::deserialize_buffer(wasm_code)?;

    let (module, ctor_module) = match build(
        module,
        SourceTarget::Unknown,
        None,
        &Vec::new(),
        false,
        "49152".parse().expect("New stack size is not valid u32"),
        false,
    ){
        Ok(v) => v,
        Err(e) => panic!(""),
    };

    let result;

    if let Some(ctor_module) = ctor_module {
        result = parity_wasm::serialize(ctor_module);/*.map_err(Error::Encoding)*/
    } else {
        result = parity_wasm::serialize(module);/*.map_err(Error::Encoding)*/
    }

    match result{
        Ok(v) => Ok(v),
        Err(e) => panic!(""),
    }
}


const MAX_EVM_RESULT: usize = 100_000;
pub fn deploy(eid: sgx_enclave_id_t,  bytecode: &[u8])-> Result<Vec<u8>, Error> {

    let deploy_bytecode = build_constructor(&bytecode)?;
    let mut retval: sgx_status_t = sgx_status_t::SGX_SUCCESS;
    let mut output_ptr: u64 = 0;

    let result = unsafe {
        ecall_deploy(eid,
                  &mut retval,
                  deploy_bytecode.as_ptr() as *const u8,
                  deploy_bytecode.len(),
                  &mut output_ptr as *mut u64)
    };
    let box_ptr = output_ptr as *mut Box<[u8]>;
    let part = unsafe { Box::from_raw(box_ptr ) };
    Ok(part.to_vec())
}

#[derive(Clone, Debug, PartialEq, PartialOrd, Eq, Ord, Hash, Default)]
pub struct WasmResult {
    pub bytecode: Vec<u8>,
    pub output: Vec<u8>,
    pub delta: ::db::Delta,
}

pub fn execute(eid: sgx_enclave_id_t,  bytecode: &[u8], callable: &str)-> Result<WasmResult, Error> {
    let mut retval: sgx_status_t = sgx_status_t::SGX_SUCCESS;
    let mut output = 0u64;
    let mut delta_data_ptr = 0u64;
    let mut delta_hash = [0u8; 32];
    let mut delta_index = 0u32;


    let result = unsafe {
        ecall_execute(eid, &mut retval,
                      bytecode.as_ptr() as *const u8,
                      bytecode.len(),
                      callable.as_ptr() as *const u8,
                      callable.len(),
                      &mut output as *mut u64,
                      &mut delta_data_ptr as *mut u64,
                      &mut delta_hash,
                      &mut delta_index as *mut u32)
    };

    let mut result: WasmResult = Default::default();
    let box_ptr = output as *mut Box<[u8]>;
    let output = unsafe { Box::from_raw(box_ptr) };
    result.output = output.to_vec();

    if delta_data_ptr != 0 && delta_hash != [0u8; 32] && delta_index != 0 { // TODO: Replace 0 with maybe max int(accordingly).
        let box_ptr = delta_data_ptr as *mut Box<[u8]>;
        let delta_data = unsafe { Box::from_raw(box_ptr) };
        result.delta.value = delta_data.to_vec();
        result.delta.key = ::db::DeltaKey::new(delta_hash, Some(delta_index));
    } else { bail!("Weird delta results") }
    Ok(result)
}

#[cfg(test)]
pub mod tests {
    #![allow(dead_code, unused_assignments, unused_variables)]

    use esgx;
    use std::fs::File;
    use std::io::Read;
    use sgx_urts::SgxEnclave;
    use wasm_u::wasm;
    use std::str::from_utf8;
    use std::process::Command;
    use std::path::PathBuf;

    fn init_enclave() -> SgxEnclave{
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

    #[test]
    fn compile_test_contract() {
        let mut dir = PathBuf::new();
        dir.push("../../examples/eng_wasm_contracts/simplest");
        let mut output = Command::new("cargo")
            .current_dir(&dir)
            .args(&["build", "--release"])
            .spawn()
            .expect(&format!("Failed compiling simplest wasm exmaple: {:?}", &dir) );

        assert!(output.wait().unwrap().success());
        dir.push("target/wasm32-unknown-unknown/release/contract.wasm");

        let mut f = File::open(&dir).expect(&format!("Can't open the contract.wasm file: {:?}", &dir) );
        let mut wasm_code = Vec::new();
        f.read_to_end(&mut wasm_code).expect("Failed reading the wasm file");
        println!("Bytecode size: {}KB\n", wasm_code.len()/1024);

        let enclave = init_enclave();
        let contract_code = wasm::deploy(enclave.geteid(), &wasm_code).expect("Deploy Failed");
        let result = wasm::execute(enclave.geteid(),&contract_code, "call").expect("Execution failed");
        enclave.destroy();
        assert_eq!(from_utf8(&result.output).unwrap(), "\"157\"");
    }

    #[ignore]
    #[test]
    pub fn contract() {
        let mut f = File::open("../../examples/eng_wasm_contracts/simplest/target/wasm32-unknown-unknown/release/contract.wasm").unwrap();
        let mut wasm_code = Vec::new();
        f.read_to_end(&mut wasm_code).unwrap();
        println!("Bytecode size: {}KB\n", wasm_code.len()/1024);
        let enclave = init_enclave();
        let contract_code = wasm::deploy(enclave.geteid(), &wasm_code).expect("Deploy Failed");
        let result = wasm::execute(enclave.geteid(),&contract_code, "call").expect("Execution failed");
        assert_eq!(from_utf8(&result.output).unwrap(),"157");
    }
}
