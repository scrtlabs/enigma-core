extern crate sgx_types;
extern crate sgx_urts;
extern crate rustc_hex;

use crate::common_u::errors::EnclaveFailError;
use enigma_types::{ContractAddress, PubKey};
use super::WasmResult;
use std::convert::TryInto;
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
                    gas_limit: *const u64, result: &mut ExecuteResult) -> sgx_status_t;

    fn ecall_execute(eid: sgx_enclave_id_t, retval: *mut EnclaveReturn,
                     bytecode: *const u8, bytecode_len: usize, callable: *const u8,
                     callable_len: usize, callable_args: *const u8, callable_args_len: usize,
                     user_key: &PubKey, contract_address: &ContractAddress,
                     gas_limit: *const u64, result: &mut ExecuteResult ) -> sgx_status_t;
}

const MAX_EVM_RESULT: usize = 100_000;
pub fn deploy(eid: sgx_enclave_id_t,  bytecode: &[u8], constructor: &[u8], args: &[u8],
              contract_address: ContractAddress, user_pubkey: &PubKey, gas_limit: u64)-> Result<WasmResult, Error> {
    let mut retval = EnclaveReturn::Success;
    let mut result = ExecuteResult::default();

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
                     &mut result)
    };
    if retval != EnclaveReturn::Success || status != sgx_status_t::SGX_SUCCESS {
        Err(EnclaveFailError { err: retval, status }.into())
    } else {
        result.try_into()
    }
}


pub fn execute(eid: sgx_enclave_id_t,  bytecode: &[u8], callable: &[u8], args: &[u8],
               user_pubkey: &PubKey, address: &ContractAddress, gas_limit: u64)-> Result<WasmResult,Error> {
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
        Err(EnclaveFailError { err: retval, status }.into())
    } else {
        result.try_into()
    }
}

#[cfg(test)]
pub mod tests {
    extern crate ring;
    extern crate ethabi;

    use crate::esgx::general::init_enclave_wrapper;
    use crate::km_u::tests::{exchange_keys, serial_and_encrypt_input};
    use crate::km_u::tests::instantiate_encryption_key;
    use crate::wasm_u::wasm;
    use self::ring::rand::*;
    use self::ethabi::{Token};
    use enigma_types::{ContractAddress, PubKey};
    use sgx_types::*;
    use std::fs::File;
    use std::io::Read;
    use std::path::PathBuf;
    use std::process::Command;
    use std::str::from_utf8;
    use wasm_u::{WasmResult, wasm::{rustc_hex::ToHex}};

    pub fn generate_address() -> ContractAddress {
        let mut address = ContractAddress::default();
        SystemRandom::new().fill(address.as_mut()).unwrap();
        address
    }

    fn compile_and_deploy_wasm_contract(eid: sgx_enclave_id_t, test_path: &str, address: ContractAddress, constructor: &[u8], args: &[u8],  user_pubkey: &PubKey) -> WasmResult {
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

    fn compile_deploy_execute(test_path: &str,
                              address: ContractAddress,
                              constructor: &str,
                              constructor_arguments: &[Token],
                              func: &str,
                              func_args: &[Token]) -> (sgx_urts::SgxEnclave, Box<[u8]>, WasmResult) {
        let enclave = init_enclave_wrapper().unwrap();
        instantiate_encryption_key(&[address], enclave.geteid());

        let (pubkey, key, _, _) = exchange_keys(enclave.geteid());
        let (encrypted_construct, encrypted_args) = serial_and_encrypt_input(&key, constructor, &constructor_arguments, None);

        let deploy_res = compile_and_deploy_wasm_contract(enclave.geteid(), test_path, address, &encrypted_construct, &encrypted_args, &pubkey);
        let exe_code = deploy_res.output;
        let (pubkey, key, _, _) = exchange_keys(enclave.geteid());
        let (encrypted_callable, encrypted_args) = serial_and_encrypt_input(&key, func, &func_args, None);
        let result = wasm::execute(enclave.geteid(), &exe_code, &encrypted_callable, &encrypted_args, &pubkey, &address, 100_000).expect("Execution failed");

        (enclave, exe_code, result)
    }

    #[test]
    fn test_print_simple() {
        let (enclave, _, result) = compile_deploy_execute("../../examples/eng_wasm_contracts/simplest",
                                                          generate_address(),
                                                          "construct(uint)",
                                                          &[Token::Uint(17.into())],
                                                          "print_test(uint256,uint256)",
                                                          &[Token::Uint(17.into()), Token::Uint(22.into())]
        );
        enclave.destroy();
        assert_eq!(from_utf8(&result.output).unwrap(), "22");
    }

    #[test]
    fn test_write_simple() {
        let (enclave, _, result) = compile_deploy_execute("../../examples/eng_wasm_contracts/simplest",
                                                          generate_address(),
                                                          "construct(uint)",
                                                          &[Token::Uint(17.into())],
                                                          "write()",
                                                          &[]);
        enclave.destroy();
        assert_eq!(from_utf8(&result.output).unwrap(), "\"157\"");
    }

    // address is defined in our protocol as ethereum's H256/bytes32
    #[test]
    fn test_single_address() {
        let addr = Token::FixedBytes(generate_address().to_vec());
        let (enclave, _, result) = compile_deploy_execute("../../examples/eng_wasm_contracts/simplest",
                                                          generate_address(),
                                                          "construct(uint)",
                                                          &[Token::Uint(100.into())],
                                                          "check_address(bytes32)",
                                                          &[addr.clone()]);
        enclave.destroy();
        assert_eq!(from_utf8(&result.output).unwrap(), format!("{:?}",addr.to_fixed_bytes().unwrap().to_hex()));
    }

    #[test]
    fn test_rand_u8() {
        let (enclave, _, result) = compile_deploy_execute("../../examples/eng_wasm_contracts/simplest",
                                                          generate_address(),
                                                          "construct(uint)",
                                                          &[Token::Uint(100.into())],
                                                          "choose_rand_color()",
                                                          &[]);

        enclave.destroy();
        let colors = vec!["\"green\"", "\"yellow\"", "\"red\"", "\"blue\"", "\"white\"", "\"black\"", "\"orange\"", "\"purple\""];
        let res_output = result.output;
        let res_str = from_utf8(&res_output).unwrap();
        let res = match colors.into_iter().find(|&x|{x==res_str}) {
            Some(color) => color,
            None => "test_failed"
        };
        assert_eq!(res_str, res);
    }

    #[test]
    fn test_shuffling() {
        let (enclave, _, result) = compile_deploy_execute("../../examples/eng_wasm_contracts/simplest",
                                                          generate_address(),
                                                          "construct(uint)",
                                                          &[Token::Uint(100.into())],
                                                          "get_scrambled_vec()",
                                                          &[]);

        enclave.destroy();
        let zeros: Box<[u8]> = Box::new([0u8; 10]);
        assert_eq!(result.output.len(), 10);
        assert_ne!(result.output, zeros);
    }

    #[test]
    fn test_multiple_addresses() {
        let addr2 = Token::FixedBytes(generate_address().to_vec());
        let (enclave, _, result) = compile_deploy_execute("../../examples/eng_wasm_contracts/simplest",
                                            generate_address(),
                                            "construct(uint)",
                                            &[Token::Uint(1025.into())],
                                            "check_addresses(bytes32,bytes32)",
                                            &[Token::FixedBytes(generate_address().to_vec()), addr2.clone()]);
        enclave.destroy();
        assert_eq!(from_utf8(&result.output).unwrap(), format!("{:?}",addr2.to_fixed_bytes().unwrap().to_hex()));
    }

    #[test]
    fn test_mint_erc20() {
        let amount: Token = Token::Uint(50.into());
        let address = generate_address();
        let (enclave, contract_code, _) = compile_deploy_execute("../../examples/eng_wasm_contracts/erc20",
                                            address.clone(),
                                            "construct()",
                                            &[],
                                            "mint(bytes32,uint256)",
                                            &[Token::FixedBytes(generate_address().to_vec()), amount.clone()]);

        let (pubkey, key, _, _) = exchange_keys(enclave.geteid());
        let (encrypted_callable, encrypted_args) = serial_and_encrypt_input(&key, "total_supply()", &[], None);
        let result = wasm::execute(enclave.geteid(), &contract_code, &encrypted_callable, &encrypted_args, &pubkey, &address, 100_000_000).expect("Execution failed");
        enclave.destroy();
        // deserialization of result
        let res: Token = ethabi::decode(&[ethabi::ParamType::Uint(256)], &result.output).unwrap().pop().unwrap();
        assert_eq!(res, amount);
    }

    #[test]
    fn test_transfer_erc20() {
        let address = generate_address();
        let addr: Token = Token::FixedBytes(generate_address().to_vec());
        let transfer_amount: Token = Token::Uint(8.into());
        let (enclave, contract_code, _) = compile_deploy_execute(
            "../../examples/eng_wasm_contracts/erc20",
            address.clone(),
            "construct()",
            &[],
            "mint(bytes32,uint256)",
            &[addr.clone(), Token::Uint(17.into())]);

        let (pubkey_t, key_t, _, _) = exchange_keys(enclave.geteid());
        let addr_to = Token::FixedBytes(generate_address().to_vec());
        let (encrypted_callable, transfer_args) = serial_and_encrypt_input(&key_t, "transfer(bytes32,bytes32,uint256)", &[addr, addr_to.clone(), transfer_amount.clone()], None);
        wasm::execute(enclave.geteid(), &contract_code, &encrypted_callable, &transfer_args, &pubkey_t, &address, 100_000_000).expect("Execution failed");

        let (pubkey_b, key_b, _, _) = exchange_keys(enclave.geteid());
        let (encrypted_callable, balance_args) = serial_and_encrypt_input(&key_b, "balance_of(bytes32)", &[addr_to], None);
        let result_balance = wasm::execute(enclave.geteid(), &contract_code, &encrypted_callable, &balance_args, &pubkey_b, &address, 100_000_000).expect("Execution failed");

        enclave.destroy();
        let res: Token = ethabi::decode(&[ethabi::ParamType::Uint(256)], &result_balance.output).unwrap().pop().unwrap();
        assert_eq!(res, transfer_amount);
    }

    #[test]
    fn test_allow_and_transfer_erc20() {
        let address = generate_address();
        let owner: Token = Token::FixedBytes(generate_address().to_vec());
        let spender: Token = Token::FixedBytes(generate_address().to_vec());
        let addr_to: Token = Token::FixedBytes(generate_address().to_vec());
        let transfer_amount: Token = Token::Uint(12.into());
        let (enclave, contract_code, _) = compile_deploy_execute("../../examples/eng_wasm_contracts/erc20",
                                                                 address.clone(),
                                                                 "construct()",
                                                                 &[],
                                                                 "mint(bytes32,uint256)",
                                                                 &[owner.clone(), Token::Uint(40.into())]);

        let (pubkey_a, key_a, _, _) = exchange_keys(enclave.geteid());
        let (encrypted_callable, approve_args) = serial_and_encrypt_input(&key_a, "approve(bytes32,bytes32,uint256)", &[owner.clone(), spender.clone(), Token::Uint(20.into())], None);
        wasm::execute(enclave.geteid(), &contract_code, &encrypted_callable, &approve_args, &pubkey_a, &address, 100_000_000).expect("Execution failed");

        let (pubkey_t, key_t, _, _) = exchange_keys(enclave.geteid());
        let (encrypted_callable, transfer_args) = serial_and_encrypt_input(&key_t, "transfer_from(bytes32,bytes32,bytes32,uint256)", &[owner.clone(), spender.clone(), addr_to.clone(), transfer_amount.clone()], None);
        wasm::execute(enclave.geteid(), &contract_code, &encrypted_callable, &transfer_args, &pubkey_t, &address, 100_000_000).expect("Execution failed");

        let (pubkey_b, key_b, _, _) = exchange_keys(enclave.geteid());
        let (encrypted_callable, balance_args) = serial_and_encrypt_input(&key_b, "balance_of(bytes32)", &[addr_to], None);
        let result_balance = wasm::execute(enclave.geteid(), &contract_code, &encrypted_callable, &balance_args, &pubkey_b, &address, 100_000_000).expect("Execution failed");

        let (pubkey_al, key_al, _, _) = exchange_keys(enclave.geteid());
        let (encrypted_callable, allowance_args) = serial_and_encrypt_input(&key_al, "allowance(bytes32,bytes32)", &[owner, spender], None);
        let result_allowance = wasm::execute(enclave.geteid(), &contract_code, &encrypted_callable, &allowance_args, &pubkey_al, &address, 100_000_000).expect("Execution failed");

        let res_allowance: Token = ethabi::decode(&[ethabi::ParamType::Uint(256)], &result_allowance.output).unwrap().pop().unwrap();
        let res_balance: Token = ethabi::decode(&[ethabi::ParamType::Uint(256)], &result_balance.output).unwrap().pop().unwrap();

        enclave.destroy();
        assert_eq!(res_balance, transfer_amount);
        assert_eq!(res_allowance, Token::Uint(8.into()));
    }

    #[test]
    fn test_eth_bridge(){
        let (enclave, contract_code, _) = compile_deploy_execute(
            "../../examples/eng_wasm_contracts/contract_with_eth_calls",
            generate_address(),
            "construct()",
            &[],
            "test()",
            &[]);

        enclave.destroy();
    }
}
