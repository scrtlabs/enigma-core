#![allow(dead_code)]
extern crate sgx_types;
extern crate sgx_urts;
extern crate rustc_hex;

use crate::common_u::errors::EnclaveFailError;
use crate::db::{DeltaKey, Stype};
use crate::km_u::{ContractAddress, PubKey};
use enigma_types::traits::SliceCPtr;
use enigma_types::{EnclaveReturn, ExecuteResult};
use failure::Error;
use sgx_types::*;

extern "C" {
    fn ecall_deploy(eid: sgx_enclave_id_t, retval: *mut EnclaveReturn,
                    bytecode: *const u8, bytecode_len: usize,
                    constructor: *const u8, constructor_len: usize,
                    args: *const u8, args_len: usize,
                    address: &ContractAddress, user_key: &PubKey,
                    gas_limit: *const u64, output_ptr: *mut u64, sig: &mut [u8; 65]) -> sgx_status_t;

    fn ecall_execute(eid: sgx_enclave_id_t, retval: *mut EnclaveReturn,
                     bytecode: *const u8, bytecode_len: usize, callable: *const u8,
                     callable_len: usize, callable_args: *const u8, callable_args_len: usize,
                     user_key: &PubKey, contract_address: &ContractAddress,
                     gas_limit: *const u64, result: &mut ExecuteResult ) -> sgx_status_t;
}

const MAX_EVM_RESULT: usize = 100_000;
pub fn deploy(eid: sgx_enclave_id_t,  bytecode: &[u8], constructor: &str, args: &[u8],
              contract_address: ContractAddress, user_pubkey: &PubKey, gas_limit: u64)-> Result<(Box<[u8]>, [u8;65]), Error> {
    let mut retval = EnclaveReturn::Success;

    let mut output_ptr: u64 = 0;
    let mut signature = [0u8; 65];

    let status = unsafe {
        ecall_deploy(eid,
                     &mut retval,
                     bytecode.as_c_ptr(),
                     bytecode.len(),
                     constructor.as_c_ptr() as *const u8,
                     constructor.len(),
                     args.as_c_ptr(),
                     args.len(),
                     &contract_address,
                     &user_pubkey,
                     &gas_limit as *const u64,
                     &mut output_ptr as *mut u64,
        &mut signature)
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


pub fn execute(eid: sgx_enclave_id_t,  bytecode: &[u8], callable: &str, args: &[u8],
               user_pubkey: &PubKey, address: &ContractAddress, gas_limit: u64)-> Result<WasmResult,Error>{
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
    extern crate ethabi;

    use crate::esgx::general::init_enclave_wrapper;
    use crate::km_u::tests::{exchange_keys, serial_and_encrypt_args};
    use crate::km_u::tests::instantiate_encryption_key;
    use crate::wasm_u::wasm;
    use self::ring::rand::*;
    use self::ethabi::{Token};
    use super::{ContractAddress, PubKey};
    use enigma_tools_u::common_u::Sha256;
    use sgx_types::*;
    use std::fs::File;
    use std::io::Read;
    use std::path::PathBuf;
    use std::process::Command;
    use std::str::from_utf8;
    use wasm_u::wasm::rustc_hex::ToHex;

    pub fn generate_address() -> ContractAddress {
        let mut address = [0u8; 32];
        SystemRandom::new().fill(&mut address).unwrap();
        address
    }


    fn compile_and_deploy_wasm_contract(eid: sgx_enclave_id_t, test_path: &str, address: ContractAddress, constructor: &str, args: &[u8],  user_pubkey: &PubKey) -> (Box<[u8]>, [u8;65]) {
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


        wasm::deploy(eid, &wasm_code, constructor, args, address, &user_pubkey, 100_000).expect("Deploy Failed")
    }

    #[test]
    fn test_print_simple() {
        let enclave = init_enclave_wrapper().unwrap();
        let address = generate_address();
        instantiate_encryption_key(&[address], enclave.geteid());
        let (pubkey, key, _, _) = exchange_keys(enclave.geteid());
        let test_constr_arg: Token = Token::Uint(17.into());
        let encrypted_args = serial_and_encrypt_args(&key, &[test_constr_arg.clone()], None);

        let (contract_code, _) = compile_and_deploy_wasm_contract(enclave.geteid(), "../../examples/eng_wasm_contracts/simplest", address, "construct(uint)", &encrypted_args, &pubkey);
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
        let (pubkey, key, _, _) = exchange_keys(enclave.geteid());
        let test_constr_arg: Token = Token::Uint(17.into());
        let encrypted_args = serial_and_encrypt_args(&key, &[test_constr_arg.clone()], None);

        let (contract_code, _) = compile_and_deploy_wasm_contract(enclave.geteid(), "../../examples/eng_wasm_contracts/simplest", address, "construct(uint)", &encrypted_args, &pubkey);
        let (pubkey, key, _, _) = exchange_keys(enclave.geteid());
        let args : &[u8] = &[];
        let result = wasm::execute(enclave.geteid(), &contract_code, "write()", args, &pubkey, &address, 100_000).expect("Execution failed");
        enclave.destroy();
        assert_eq!(from_utf8(&result.output).unwrap(), "\"157\"");
    }

    // address is defined in our protocol as ethereum's H256/bytes32
    #[test]
    fn test_single_address() {
        let enclave = init_enclave_wrapper().unwrap();
        let address = generate_address();
        instantiate_encryption_key(&[address], enclave.geteid());
        let (pubkey, key, _, _) = exchange_keys(enclave.geteid());
        let test_constr_arg: Token = Token::Uint(100.into());
        let encrypted_args = serial_and_encrypt_args(&key, &[test_constr_arg.clone()], None);
        let (contract_code, _) = compile_and_deploy_wasm_contract(enclave.geteid(), "../../examples/eng_wasm_contracts/simplest", address, "construct(uint)", &encrypted_args, &pubkey);

        //defining the arguments, serializing them and encrypting them -
        let (pubkey, key, _, _) = exchange_keys(enclave.geteid());
        let addr: Token = Token::FixedBytes(generate_address().to_vec());
        let encrypted_args = serial_and_encrypt_args(&key, &[addr.clone()], None);

        let result = wasm::execute(enclave.geteid(), &contract_code, "check_address(bytes32)", &encrypted_args, &pubkey, &address, 100_000).expect("Execution failed");
        enclave.destroy();
        assert_eq!(from_utf8(&result.output).unwrap(), format!("{:?}",addr.to_fixed_bytes().unwrap().to_hex()));
    }

    #[test]
    fn test_multiple_addresses() {
        let enclave = init_enclave_wrapper().unwrap();
        let address = generate_address();
        instantiate_encryption_key(&[address], enclave.geteid());
        let (pubkey, key, _, _) = exchange_keys(enclave.geteid());
        let test_constr_arg: Token = Token::Uint(1025.into());
        let encrypted_args = serial_and_encrypt_args(&key, &[test_constr_arg.clone()], None);
        let (contract_code, _) = compile_and_deploy_wasm_contract(enclave.geteid(), "../../examples/eng_wasm_contracts/simplest", address, "construct(uint)", &encrypted_args, &pubkey);

        // defining the arguments, serializing them and encrypting them
        let (pubkey, key, _, _) = exchange_keys(enclave.geteid());
        let addr1: Token = Token::FixedBytes(generate_address().to_vec());
        let addr2: Token = Token::FixedBytes(generate_address().to_vec());
        let encrypted_args = serial_and_encrypt_args(&key, &[addr1, addr2.clone()], None);

        let result = wasm::execute(enclave.geteid(), &contract_code, "check_addresses(bytes32,bytes32)", &encrypted_args, &pubkey, &address, 100_000).expect("Execution failed");
        enclave.destroy();
        assert_eq!(from_utf8(&result.output).unwrap(), format!("{:?}",addr2.to_fixed_bytes().unwrap().to_hex()));
    }

    #[test]
    fn test_mint_erc20() {
        let enclave = init_enclave_wrapper().unwrap();
        let address = generate_address();
        instantiate_encryption_key(&[address], enclave.geteid());
        let (pubkey, _, _, _) = exchange_keys(enclave.geteid());
        let (contract_code, _) = compile_and_deploy_wasm_contract(enclave.geteid(), "../../examples/eng_wasm_contracts/erc20", address, "construct()", &[], &pubkey);

        // defining the arguments, serializing them and encrypting them
        let (pubkey, key, _, _) = exchange_keys(enclave.geteid());
        let addr: Token = Token::FixedBytes(generate_address().to_vec());
        let amount: Token = Token::Uint(50.into());
        let encrypted_args = serial_and_encrypt_args(&key, &[addr, amount.clone()], None);
        let result = wasm::execute(enclave.geteid(), &contract_code, "mint(bytes32,uint256)", &encrypted_args, &pubkey, &address, 100_000_000).expect("Execution failed");
        let (pubkey, _, _, _) = exchange_keys(enclave.geteid());
        let result = wasm::execute(enclave.geteid(), &contract_code, "total_supply()", &[], &pubkey, &address, 100_000_000).expect("Execution failed");
        enclave.destroy();
        // deserialization of result
        let res: Token = ethabi::decode(&[ethabi::ParamType::Uint(256)], &result.output).unwrap().pop().unwrap();
        assert_eq!(res, amount);
    }


    #[test]
    fn test_transfer_erc20() {
        let enclave = init_enclave_wrapper().unwrap();
        let address = generate_address();
        instantiate_encryption_key(&[address], enclave.geteid());
        let (pubkey_deploy, _, _, _) = exchange_keys(enclave.geteid());
        let (contract_code, _) = compile_and_deploy_wasm_contract(enclave.geteid(), "../../examples/eng_wasm_contracts/erc20", address, "construct()", &[], &pubkey_deploy);
        // defining the arguments, serializing them and encrypting them
        let (pubkey_m, key_m, _, _) = exchange_keys(enclave.geteid());
        let addr: Token = Token::FixedBytes(generate_address().to_vec());
        let mint_amount: Token = Token::Uint(17.into());
        let mint_args = serial_and_encrypt_args(&key_m, &[addr.clone(), mint_amount.clone()], None);

        let result_mint = wasm::execute(enclave.geteid(), &contract_code, "mint(bytes32,uint256)", &mint_args, &pubkey_m, &address, 100_000_000).expect("Execution failed");

        let (pubkey_t, key_t, _, _) = exchange_keys(enclave.geteid());
        let addr_to = Token::FixedBytes(generate_address().to_vec());
        let transfer_amount: Token = Token::Uint(8.into());
        let transfer_args = serial_and_encrypt_args(&key_t, &[addr, addr_to.clone(), transfer_amount.clone()], None);

        let result_transfer = wasm::execute(enclave.geteid(), &contract_code, "transfer(bytes32,bytes32,uint256)", &transfer_args, &pubkey_t, &address, 100_000_000).expect("Execution failed");
        let (pubkey_b, key_b, _, _) = exchange_keys(enclave.geteid());
        let balance_args = serial_and_encrypt_args(&key_b, &[addr_to], None);
        let result_balance = wasm::execute(enclave.geteid(), &contract_code, "balance_of(bytes32)", &balance_args, &pubkey_b, &address, 100_000_000).expect("Execution failed");
        enclave.destroy();
        let res: Token = ethabi::decode(&[ethabi::ParamType::Uint(256)], &result_balance.output).unwrap().pop().unwrap();
        assert_eq!(res, transfer_amount);
    }

    #[test]
    fn test_allow_and_transfer_erc20() {
        let enclave = init_enclave_wrapper().unwrap();
        let address = generate_address();
        instantiate_encryption_key(&[address], enclave.geteid());
        let (pubkey_deploy, _, _, _) = exchange_keys(enclave.geteid());
        let (contract_code, _) = compile_and_deploy_wasm_contract(enclave.geteid(), "../../examples/eng_wasm_contracts/erc20", address, "construct()", &[], &pubkey_deploy);

        // defining the arguments, serializing them and encrypting them
        let (pubkey_m, key_m, _, _) = exchange_keys(enclave.geteid());
        let owner: Token = Token::FixedBytes(generate_address().to_vec());
        let mint_amount: Token = Token::Uint(40.into());
        let mint_args = serial_and_encrypt_args(&key_m, &[owner.clone(), mint_amount.clone()], None);

        let result_mint = wasm::execute(enclave.geteid(), &contract_code, "mint(bytes32,uint256)", &mint_args, &pubkey_m, &address, 100_000_000).expect("Execution failed");

        let (pubkey_a, key_a, _, _) = exchange_keys(enclave.geteid());
        let spender: Token = Token::FixedBytes(generate_address().to_vec());
        let approved_amount: Token = Token::Uint(20.into());
        let approve_args = serial_and_encrypt_args(&key_a, &[owner.clone(), spender.clone(), approved_amount.clone()], None);

        let result_approve = wasm::execute(enclave.geteid(), &contract_code, "approve(bytes32,bytes32,uint256)", &approve_args, &pubkey_a, &address, 100_000_000).expect("Execution failed");

        let (pubkey_t, key_t, _, _) = exchange_keys(enclave.geteid());
        let addr_to: Token = Token::FixedBytes(generate_address().to_vec());
        let transfer_amount: Token = Token::Uint(12.into());
        let transfer_args = serial_and_encrypt_args(&key_t, &[owner.clone(), spender.clone(), addr_to.clone(), transfer_amount.clone()], None);

        let result_transfer = wasm::execute(enclave.geteid(), &contract_code, "transfer_from(bytes32,bytes32,bytes32,uint256)", &transfer_args, &pubkey_t, &address, 100_000_000).expect("Execution failed");

        let (pubkey_b, key_b, _, _) = exchange_keys(enclave.geteid());
        let balance_args = serial_and_encrypt_args(&key_b, &[addr_to], None);

        let result_balance = wasm::execute(enclave.geteid(), &contract_code, "balance_of(bytes32)", &balance_args, &pubkey_b, &address, 100_000_000).expect("Execution failed");
        let res_balance: Token = ethabi::decode(&[ethabi::ParamType::Uint(256)], &result_balance.output).unwrap().pop().unwrap();


        let (pubkey_al, key_al, _, _) = exchange_keys(enclave.geteid());
        let allowance_args = serial_and_encrypt_args(&key_al, &[owner, spender], None);

        let result_allowance = wasm::execute(enclave.geteid(), &contract_code, "allowance(bytes32,bytes32)", &allowance_args, &pubkey_al, &address, 100_000_000).expect("Execution failed");
        let res_allowance: Token = ethabi::decode(&[ethabi::ParamType::Uint(256)], &result_allowance.output).unwrap().pop().unwrap();

        enclave.destroy();
        assert_eq!(res_balance, transfer_amount);
        assert_eq!(res_allowance, Token::Uint(8.into()));

    }

    #[test]
    fn test_eth_bridge() {
        let enclave = init_enclave_wrapper().unwrap();
        let address = generate_address();
        let (pubkey, _, _, _) = exchange_keys(enclave.geteid());
        instantiate_encryption_key(&[address], enclave.geteid());
        let (contract_code, _) = compile_and_deploy_wasm_contract(enclave.geteid(), "../../examples/eng_wasm_contracts/contract_with_eth_calls", address, "construct()", &[], &pubkey);
        let (pubkey, key, _, _) = exchange_keys(enclave.geteid());
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
            wasm::deploy(enclave.geteid(), &wasm_code, "construct()", &[], b"enigma".sha256(), &pubkey, 100_000)
                .expect("Deploy Failed");
        let (pubkey, _, _, _) = exchange_keys(enclave.geteid());
        let result = wasm::execute(enclave.geteid(),&contract_code, "call", &[],  &pubkey, &address,100_000).expect("Execution failed");
        assert_eq!(from_utf8(&result.output).unwrap(), "157");
    }
}
