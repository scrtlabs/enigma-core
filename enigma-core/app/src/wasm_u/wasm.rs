#![allow(dead_code,unused_assignments,unused_variables)]
extern crate sgx_types;
extern crate sgx_urts;
extern crate rustc_hex;

use crate::db::{DeltaKey, Stype};
use crate::km_u::{PubKey, ContractAddress};
use crate::common_u::errors::EnclaveFailError;
use enigma_types::EnclaveReturn;
use enigma_types::traits::SliceCPtr;
use failure::Error;
use sgx_types::*;

extern "C" {
    fn ecall_deploy(eid: sgx_enclave_id_t, retval: *mut EnclaveReturn,
                    bytecode: *const u8, bytecode_len: usize,
                    args: *const u8, args_len: usize,
                    address: &ContractAddress, user_key: &PubKey,
                    gas_limit: *const u64, output_ptr: *mut u64, sig: &mut [u8; 65]) -> sgx_status_t;

    fn ecall_execute(eid: sgx_enclave_id_t, retval: *mut EnclaveReturn,
                     bytecode: *const u8, bytecode_len: usize,
                     callable: *const u8, callable_len: usize,
                     callable_args: *const u8, callable_args_len: usize,
                     user_key: &PubKey, contract_address: &ContractAddress,
                     gas_limit: *const u64,
                     output_ptr: *mut u64, delta_data_ptr: *mut u64,
                     delta_hash_out: &mut [u8; 32], delta_index_out: *mut u32,
                     ethereum_payload_ptr: *mut u64,
                     ethereum_contract_addr: &mut [u8; 20],
                     sig: &mut [u8; 65]) -> sgx_status_t;
}

const MAX_EVM_RESULT: usize = 100_000;
pub fn deploy(eid: sgx_enclave_id_t,  bytecode: &[u8], args: &[u8],
              contract_address: ContractAddress, user_pubkey: &PubKey, gas_limit: u64)-> Result<(Box<[u8]>, [u8;65]), Error> {
    let mut retval = EnclaveReturn::default();
    let mut output_ptr: u64 = 0;
    let mut signature = [0u8; 65];

    let status = unsafe {
        ecall_deploy(eid,
                     &mut retval,
                     bytecode.as_c_ptr(),
                     bytecode.len(),
                     args.as_c_ptr(),
                     args.len(),
                     &contract_address,
                     &user_pubkey,
                     &gas_limit as *const u64,
                     &mut output_ptr as *mut u64,
        &mut signature)
    };
    let box_ptr = output_ptr as *mut Box<[u8]>;
    assert!(!box_ptr.is_null()); // TODO: Think about this
    let part = unsafe { Box::from_raw(box_ptr ) };
    Ok((*part, signature))
}

#[derive(Clone, Debug, PartialEq, PartialOrd, Eq, Ord, Hash, Default)]
pub struct WasmResult {
    pub bytecode: Vec<u8>,
    pub output: Vec<u8>,
    pub delta: ::db::Delta,
    pub eth_payload: Vec<u8>,
    pub eth_contract_addr: [u8;20],
    pub signature: Vec<u8>,
}

pub fn execute(eid: sgx_enclave_id_t,  bytecode: &[u8], callable: &str, args: &[u8],
               user_pubkey: &PubKey, address: &ContractAddress, gas_limit: u64)-> Result<WasmResult,Error>{
    let mut retval = EnclaveReturn::default();
    let mut output = 0u64;
    let mut delta_data_ptr = 0u64;
    let mut delta_hash = [0u8; 32];
    let mut delta_index = 0u32;
    let mut ethereum_payload = 0u64;
    let mut ethereum_contract_addr = [0u8; 20];
    let mut signature = [0u8; 65];

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
                      &mut output as *mut u64,
                      &mut delta_data_ptr as *mut u64,
                      &mut delta_hash,
                      &mut delta_index as *mut u32,
                      &mut ethereum_payload as *mut u64,
                      &mut ethereum_contract_addr,
                      &mut signature)
    };

    if retval != EnclaveReturn::Success  || status != sgx_status_t::SGX_SUCCESS {
        return Err(EnclaveFailError{err: retval, status}.into());
    }
    // TODO: Write a handle wrapper that will free the pointers memory in case of an Error.

    let mut result: WasmResult = Default::default();
    result.signature = signature.to_vec();
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
        assert!(!box_ptr.is_null()); // TODO: Think about this
        let delta_data = unsafe { Box::from_raw(box_ptr) };
        result.delta.value = delta_data.to_vec();
        result.delta.key = DeltaKey::new(delta_hash, Stype::Delta(delta_index));
    } else {
        bail!("Weird delta results")
    }
    Ok(result)
}

#[cfg(test)]
pub mod tests {
    extern crate ring;
    extern crate ethabi;

    use crate::esgx::general::init_enclave_wrapper;
    use std::fs::File;
    use std::io::Read;
    use std::path::PathBuf;
    use sgx_types::*;
    use std::process::Command;
    use crate::wasm_u::wasm;
    use std::str::from_utf8;
    use crate::km_u::tests::instantiate_encryption_key;
    use crate::km_u::tests::{exchange_keys, serial_and_encrypt_args};
    use super::ContractAddress;
    use enigma_tools_u::common_u::Sha256;
    use self::ring::rand::*;
    use self::ethabi::{Token};
    use wasm_u::wasm::rustc_hex::ToHex;

    pub fn generate_address() -> ContractAddress {
        let mut address = [0u8; 32];
        SystemRandom::new().fill(&mut address).unwrap();
        address
    }


    fn compile_and_deploy_wasm_contract(eid: sgx_enclave_id_t, test_path: &str, address: ContractAddress) -> (Box<[u8]>, [u8;65]) {
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

        let (pubkey, _, _, _) = exchange_keys(eid);
        wasm::deploy(eid, &wasm_code, &[], address, &pubkey, 100_000).expect("Deploy Failed")
    }

    #[test]
    fn test_print_simple() {
        let enclave = init_enclave_wrapper().unwrap();
        let address = generate_address();
        instantiate_encryption_key(&[address], enclave.geteid());
        let (contract_code, _) = compile_and_deploy_wasm_contract(enclave.geteid(), "../../examples/eng_wasm_contracts/simplest", address);
        let (pubkey, key, _, _) = exchange_keys(enclave.geteid());
        let args = [Token::Uint(17.into()), Token::Uint(22.into())];
        let encrypted_args = serial_and_encrypt_args(&key, &args, None);
        let result = wasm::execute(enclave.geteid(),&contract_code, "print_test(uint256,uint256)", &encrypted_args, &pubkey, &address, 100_000).expect("Execution failed");

        enclave.destroy();
        assert_eq!(from_utf8(&result.output).unwrap(), "22");
    }

    #[test]
    fn test_write_simple() {
        let enclave = init_enclave_wrapper().unwrap();
        let address = generate_address();
        instantiate_encryption_key(&[address], enclave.geteid());
        let (contract_code, _) = compile_and_deploy_wasm_contract(enclave.geteid(), "../../examples/eng_wasm_contracts/simplest", address);
        let (pubkey, _, _, _) = exchange_keys(enclave.geteid());
        let args : &[u8] = &[];
        let result = wasm::execute(enclave.geteid(), &contract_code, "write()", args, &pubkey, &address, 100_000).expect("Execution failed");
        enclave.destroy();
        assert_eq!(from_utf8(&result.output).unwrap(), "\"157\"");
    }

    // address is defined in our protocol as ethereum's H256/bytes32
    #[test]
    fn test_address_simple() {
        let enclave = init_enclave_wrapper().unwrap();
        let address = generate_address();
        instantiate_encryption_key(&[address], enclave.geteid());
        let (contract_code, _) = compile_and_deploy_wasm_contract(enclave.geteid(), "../../examples/eng_wasm_contracts/simplest", address);

        //defining the arguments, serializing them and encrypting them -
        let (pubkey, key, _, _) = exchange_keys(enclave.geteid());
        let addr: Token = Token::FixedBytes(generate_address().to_vec());
        let encrypted_args = serial_and_encrypt_args(&key, &[addr.clone()], None);

        let result = wasm::execute(enclave.geteid(), &contract_code, "get_address(bytes32)", &encrypted_args, &pubkey, &address, 100_000).expect("Execution failed");
        enclave.destroy();
        assert_eq!(from_utf8(&result.output).unwrap(), format!("{:?}",addr.to_fixed_bytes().unwrap().to_hex()));
    }

    #[test]
    fn test_addresses_simple() {
        let enclave = init_enclave_wrapper().unwrap();
        let address = generate_address();
        instantiate_encryption_key(&[address], enclave.geteid());
        let (contract_code, _) = compile_and_deploy_wasm_contract(enclave.geteid(), "../../examples/eng_wasm_contracts/simplest", address);

        //defining the arguments, serializing them and encrypting them -
        let (pubkey, key, _, _) = exchange_keys(enclave.geteid());
        let addr1: Token = Token::FixedBytes(generate_address().to_vec());
        let addr2: Token = Token::FixedBytes(generate_address().to_vec());
        let encrypted_args = serial_and_encrypt_args(&key, &[addr1, addr2.clone()], None);

        let result = wasm::execute(enclave.geteid(), &contract_code, "get_addresses(bytes32,bytes32)", &encrypted_args, &pubkey, &address, 100_000).expect("Execution failed");
        enclave.destroy();
        assert_eq!(from_utf8(&result.output).unwrap(), format!("{:?}",addr2.to_fixed_bytes().unwrap().to_hex()));
    }
//
//    #[test]
//    fn test_add_erc20() {
//        let enclave = init_enclave();
//        let contract_code = compile_and_deploy_wasm_contract(enclave.geteid(), "../../examples/eng_wasm_contracts/erc20");
//        // args must be solidity abi serialized and encrypted: 0x5ed8cee6b63b1c6afce3ad7c92f4fd7e1b8fad9f,0x07
//        let arg : &[u8] = &[38, 69, 69, 163, 224, 68, 24, 62, 147, 1, 82, 167, 210, 98, 196, 109, 211, 173, 17, 125, 129, 42, 102, 47, 253, 82, 70, 120, 218, 116, 119, 36, 102, 106, 46, 227, 128, 132, 183, 241, 25, 162, 23, 4, 192, 231, 147, 7, 242, 85, 161, 62, 241, 193, 32, 170, 123, 51, 34, 222, 36, 58, 140, 16, 132, 229, 33, 83, 242, 58, 112, 32, 106, 28, 159, 142, 169, 210, 251, 187, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];
//        let result = wasm::execute(enclave.geteid(), &contract_code, "add_to_balance(address,uint256)", arg, 100_000).expect("Execution failed");
//        enclave.destroy();
//        assert_eq!(from_utf8(&result.output).unwrap(), "7");
//    }
//
//    // todo: need to add an initial state in order to test the functionality of transfer
////    #[test]
////    fn test_transfer_erc20() {
////        let enclave = init_enclave();
////        let contract_code = compile_and_deploy_wasm_contract(enclave.geteid(), "../../examples/eng_wasm_contracts/erc20");
//////         args before encryption and solidity abi serialization: ["5ed8cee6b63b1c6afce3ad7c92f4fd7e1b8fad9f","de0b295669a9fd93d5f28d9ec85e40f4cb697bae",0x03]
////        let rlp_args_transfer = &[38, 69, 69, 163, 224, 68, 24, 62, 147, 1, 82, 167, 210, 98, 196, 109, 211, 173, 17, 125, 129, 42, 102, 47, 253, 82, 70, 120, 218, 116, 119, 36, 102, 106, 46, 227, 128, 132, 183, 241, 25, 162, 23, 4, 30, 236, 186, 81, 155, 252, 92, 173, 36, 51, 173, 52, 179, 109, 98, 42, 239, 83, 247, 185, 177, 170, 21, 230, 102, 118, 94, 128, 129, 231, 172, 10, 30, 250, 148, 100, 106, 120, 76, 210, 247, 41, 176, 128, 89, 69, 95, 13, 135, 132, 164, 48, 197, 153, 96, 169, 17, 120, 160, 226, 23, 195, 27, 165, 169, 4, 69, 141, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];
////        let res_addr_account = wasm::execute(enclave.geteid(), &contract_code, "transfer(string,string,uint256)", rlp_args_transfer, 100_000_000).expect("Execution failed");
////        enclave.destroy();
////
////        assert_eq!(from_utf8(&res_addr_account.output).unwrap(), "3");
////    }

    #[test]
    fn test_eth_bridge() {
        let enclave = init_enclave_wrapper().unwrap();
        let address = generate_address();
        instantiate_encryption_key(&[address], enclave.geteid());
        let (contract_code, _) = compile_and_deploy_wasm_contract(enclave.geteid(), "../../examples/eng_wasm_contracts/contract_with_eth_calls", address);
        let (pubkey, _, _, _) = exchange_keys(enclave.geteid());

        let arg: &[u8] = &[];
        let result = wasm::execute(enclave.geteid(), &contract_code, "test()", arg, &pubkey, &address, 100_000).expect("Execution failed");
        enclave.destroy();
    }

    #[ignore]
    #[test]
    pub fn test_contract() {
        let mut f = File::open(
            "../../examples/eng_wasm_contracts/simplest/target/wasm32-unknown-unknown/release/contract.wasm",
        )
        .unwrap();
        let mut wasm_code = Vec::new();
        f.read_to_end(&mut wasm_code).unwrap();
        println!("Bytecode size: {}KB\n", wasm_code.len() / 1024);
        let enclave = init_enclave_wrapper().unwrap();

        let address = b"Enigma".sha256();
        instantiate_encryption_key(&[address], enclave.geteid());

        let (pubkey, _, _, _) = exchange_keys(enclave.geteid());
        let (contract_code, _) =
            wasm::deploy(enclave.geteid(), &wasm_code, &[], b"enigma".sha256(), &pubkey, 100_000)
                .expect("Deploy Failed");
        let (pubkey, _, _, _) = exchange_keys(enclave.geteid());
        let result = wasm::execute(enclave.geteid(),&contract_code, "call", &[],  &pubkey, &address,100_000).expect("Execution failed");
        assert_eq!(from_utf8(&result.output).unwrap(), "157");
    }
}
