

use crate::common_u::errors::EnclaveFailError;
use enigma_types::{ContractAddress, EnclaveReturn, ExecuteResult, PubKey, RawPointer, traits::SliceCPtr};
use super::WasmResult;
use crate::db::DB;
use std::convert::TryInto;
use failure::Error;
use sgx_types::*;

extern "C" {
    fn ecall_deploy(eid: sgx_enclave_id_t, retval: *mut EnclaveReturn,
                    bytecode: *const u8, bytecode_len: usize,
                    constructor: *const u8, constructor_len: usize,
                    args: *const u8, args_len: usize,
                    address: &ContractAddress, user_key: &PubKey,
                    gas_limit: *const u64, db_ptr: *const RawPointer,
                    result: &mut ExecuteResult) -> sgx_status_t;

    fn ecall_execute(eid: sgx_enclave_id_t, retval: *mut EnclaveReturn,
                     bytecode: *const u8, bytecode_len: usize,
                     callable: *const u8, callable_len: usize,
                     args: *const u8, args_len: usize,
                     user_key: &[u8; 64], contract_address: &ContractAddress,
                     gas_limit: *const u64, db_ptr: *const RawPointer, result: &mut ExecuteResult ) -> sgx_status_t;
}

#[logfn(DEBUG)]
pub fn deploy(db: &mut DB, eid: sgx_enclave_id_t,  bytecode: &[u8], constructor: &[u8], args: &[u8],
              contract_address: &ContractAddress, user_pubkey: &PubKey, gas_limit: u64)-> Result<WasmResult, Error> {
    let mut retval = EnclaveReturn::Success;
    let mut result = ExecuteResult::default();
    let db_ptr = unsafe { RawPointer::new_mut(db) };

    let status = unsafe {
        ecall_deploy(eid,
                     &mut retval,
                     bytecode.as_c_ptr(),
                     bytecode.len(),
                     constructor.as_c_ptr() as *const u8,
                     constructor.len(),
                     args.as_c_ptr(),
                     args.len(),
                     contract_address,
                     &user_pubkey,
                     &gas_limit as *const u64,
                     &db_ptr as *const RawPointer,
                     &mut result)
    };
    if retval != EnclaveReturn::Success || status != sgx_status_t::SGX_SUCCESS {
        Err(EnclaveFailError { err: retval, status }.into())
    } else {
        (result, *contract_address).try_into()
    }
}

#[logfn(DEBUG)]
pub fn execute(db: &mut DB, eid: sgx_enclave_id_t,  bytecode: &[u8], callable: &[u8], args: &[u8],
               user_pubkey: &PubKey, contract_address: &ContractAddress, gas_limit: u64)-> Result<WasmResult,Error> {
    let mut retval = EnclaveReturn::Success;
    let mut result = ExecuteResult::default();
    let db_ptr = unsafe { RawPointer::new_mut(db) };

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
                      contract_address,
                      &gas_limit as *const u64,
                      &db_ptr as *const RawPointer,
                      &mut result)
    };

    if retval != EnclaveReturn::Success || status != sgx_status_t::SGX_SUCCESS {
        Err(EnclaveFailError { err: retval, status }.into())
    } else {
        (result, *contract_address).try_into()
    }
}

#[cfg(test)]
mod tests {
    extern crate ethabi;
    extern crate cross_test_utils;

    use self::cross_test_utils::{generate_contract_address, sign_message, generate_user_address, get_bytecode_from_path};
    use crate::esgx::general::init_enclave_wrapper;
    use crate::km_u::tests::exchange_keys;
    use crate::km_u::tests::instantiate_encryption_key;
    use crate::db::{DB, tests::create_test_db};
    use crate::wasm_u::wasm;
    use self::ethabi::{Token};
    use enigma_types::{ContractAddress, DhKey, PubKey};
    use enigma_crypto::symmetric;
    use sgx_types::*;
    use wasm_u::{WasmResult};

    pub const GAS_LIMIT: u64 = 100_000_000;

    fn compile_and_deploy_wasm_contract(db: &mut DB, eid: sgx_enclave_id_t, test_path: &str, contract_address: ContractAddress, constructor: &[u8], args: &[u8],  user_pubkey: &PubKey) -> WasmResult {
        let wasm_code = get_bytecode_from_path(test_path);
        println!("Bytecode size: {}KB\n", wasm_code.len() / 1024);

        wasm::deploy(db, eid, &wasm_code, constructor, args, &contract_address, &user_pubkey, GAS_LIMIT).expect("Deploy Failed")
    }

    fn compile_deploy_execute(db: &mut DB,
                              test_path: &str,
                              contract_address: ContractAddress,
                              constructor: &str,
                              constructor_arguments: &[Token],
                              func: &str,
                              func_args: &[Token]) -> (sgx_urts::SgxEnclave, Box<[u8]>, WasmResult, DhKey) {
        let enclave = init_enclave_wrapper().unwrap();
        instantiate_encryption_key(vec![contract_address], enclave.geteid());

        let (keys, shared_key, _, _) = exchange_keys(enclave.geteid());
        let encrypted_construct = symmetric::encrypt(constructor.as_bytes(), &shared_key).unwrap();
        let encrypted_args = symmetric::encrypt(&ethabi::encode(&constructor_arguments), &shared_key).unwrap();

        let deploy_res = compile_and_deploy_wasm_contract(
            db,
            enclave.geteid(),
            test_path,
            contract_address,
            &encrypted_construct,
            &encrypted_args,
            &keys.get_pubkey()
        );

        let exe_code = deploy_res.output;
        let (keys, shared_key, _, _) = exchange_keys(enclave.geteid());
        let encrypted_callable = symmetric::encrypt(func.as_bytes(), &shared_key).unwrap();
        let encrypted_args = symmetric::encrypt(&ethabi::encode(&func_args), &shared_key).unwrap();

        let result = wasm::execute(
            db,
            enclave.geteid(),
            &exe_code,
            &encrypted_callable,
            &encrypted_args,
            &keys.get_pubkey(),
            &contract_address,
            GAS_LIMIT
        ).expect("Execution failed");

        (enclave, exe_code, result, shared_key)
    }

    #[test]
    fn test_print_simple() {
        let (mut db, _dir) = create_test_db();

        compile_deploy_execute(
            &mut db,
            "../../examples/eng_wasm_contracts/simplest",
            generate_contract_address(),
            "construct(uint)",
            &[Token::Uint(17.into())],
            "print_test(uint256,uint256)",
            &[Token::Uint(17.into()), Token::Uint(22.into())]
        );
    }

    #[test]
    fn test_write_simple() {
        let (mut db, _dir) = create_test_db();

        let (_, _, result, shared_key) = compile_deploy_execute(
            &mut db,
            "../../examples/eng_wasm_contracts/simplest",
            generate_contract_address(),
            "construct(uint)",
            &[Token::Uint(17.into())],
            "write()",
            &[]
        );

        let encoded_output = symmetric::decrypt(&result.output, &shared_key).unwrap();
        let decoded_output = &(ethabi::decode(&[ethabi::ParamType::Bytes], &encoded_output).unwrap())[0];
        assert_eq!(&(decoded_output.clone().to_bytes().unwrap())[..], b"157");
    }

    // address is defined in our protocol as ethereum's H256/bytes32
    #[test]
    fn test_single_address() {
        let (mut db, _dir) = create_test_db();
        let addr = generate_user_address().0;
        let (_, _, result, shared_key) = compile_deploy_execute(
            &mut db,
            "../../examples/eng_wasm_contracts/simplest",
            generate_contract_address(),
            "construct(uint)",
            &[Token::Uint(100.into())],
            "check_address(bytes32)",
            &[Token::FixedBytes(addr.to_vec())]
        );

        assert_eq!(symmetric::decrypt(&result.output, &shared_key).unwrap(), *addr);
    }

    #[test]
    fn test_rand_u8() {
        let (mut db, _dir) = create_test_db();
        let (_, _, result, shared_key) = compile_deploy_execute(
            &mut db,
            "../../examples/eng_wasm_contracts/simplest",
            generate_contract_address(),
            "construct(uint)",
            &[Token::Uint(100.into())],
            "choose_rand_color()",
            &[]
        );

        let colors: Vec<&[u8]> = vec![b"green", b"yellow", b"red", b"blue", b"white", b"black", b"orange", b"purple"];
        let encoded_output = symmetric::decrypt(&result.output, &shared_key).unwrap();
        let decoded_output = &(ethabi::decode(&[ethabi::ParamType::Bytes], &encoded_output).unwrap())[0];
        let output = decoded_output.clone().to_bytes().unwrap();
        let res = match colors.into_iter().find(|x|{x==&&output[..]}) {
            Some(color) => color,
            None => b"test_failed"
        };

        assert_eq!(output, res);
    }

    #[test]
    fn test_shuffling() {
        let (mut db, _dir) = create_test_db();

        let (_, _, result, shared_key) = compile_deploy_execute(
            &mut db,
            "../../examples/eng_wasm_contracts/simplest",
            generate_contract_address(),
            "construct(uint)",
            &[Token::Uint(100.into())],
            "get_scrambled_vec()",
            &[]
        );
        let zeros: Box<[u8]> = Box::new([0u8; 10]);
        let res_output = symmetric::decrypt(&result.output, &shared_key).unwrap();
        assert_eq!(res_output.len(), 10);
        assert_ne!(&res_output[..], &(*zeros));
    }

    #[test]
    fn test_multiple_addresses() {
        let (mut db, _dir) = create_test_db();
        let addr1 = generate_user_address().0;
        let addr2 = generate_user_address().0;
        let addresses = [Token::FixedBytes(addr1.to_vec()), Token::FixedBytes(addr2.to_vec())];
        let (_, _, result, shared_key) = compile_deploy_execute(
            &mut db,
            "../../examples/eng_wasm_contracts/simplest",
            generate_contract_address(),
            "construct(uint)",
            &[Token::Uint(1025.into())],
            "check_addresses(bytes32,bytes32)",
            &addresses
        );

        let encoded_output = symmetric::decrypt(&result.output, &shared_key).unwrap();
        let decoded_output = &(ethabi::decode(&[ethabi::ParamType::Array(Box::new(ethabi::ParamType::FixedBytes(32)))], &encoded_output).unwrap())[0];
        let expected_output = Token::Array(addresses.to_vec());
        assert_eq!(decoded_output,&expected_output);
    }

    #[test]
    fn test_mint_erc20() {
        let (mut db, _dir) = create_test_db();
        let amount: Token = Token::Uint(50.into());
        let address = generate_contract_address();

        let (enclave, contract_code, _, _) = compile_deploy_execute(
            &mut db,
            "../../examples/eng_wasm_contracts/erc20",
            address,
            "construct()",
            &[],
            "mint(bytes32,uint256)",
            &[Token::FixedBytes(generate_user_address().0.to_vec()), amount.clone()]
        );

        let (keys, shared_key, _, _) = exchange_keys(enclave.geteid());
        let encrypted_callable = symmetric::encrypt(b"total_supply()", &shared_key).unwrap();
        let encrypted_args = symmetric::encrypt(&ethabi::encode(&[]), &shared_key).unwrap();
        let result = wasm::execute(
            &mut db,
            enclave.geteid(),
            &contract_code,
            &encrypted_callable,
            &encrypted_args,
            &keys.get_pubkey(),
            &address,
            GAS_LIMIT
        ).expect("Execution failed");

        // deserialization of result
        let res: Token = ethabi::decode(&[ethabi::ParamType::Uint(256)], &symmetric::decrypt(&result.output,&shared_key).unwrap()).unwrap().pop().unwrap();
        assert_eq!(res, amount);
    }

    #[test]
    fn test_transfer_erc20() {
        let (mut db, _dir) = create_test_db();
        let address = generate_contract_address();
        let (user_addr, addr_keys) = generate_user_address();
        let addr: Token = Token::FixedBytes(user_addr.to_vec());

        let (enclave, contract_code, _, _) = compile_deploy_execute(
            &mut db,
            "../../examples/eng_wasm_contracts/erc20",
            address,
            "construct()",
            &[],
            "mint(bytes32,uint256)",
            &[addr.clone(), Token::Uint(17.into())]
        );
        let (keys, shared_key, _, _) = exchange_keys(enclave.geteid());
        let addr_to = generate_user_address().0;
        let transfer_amount: u64 = 8;
        let the_sig = sign_message(addr_keys, addr_to, transfer_amount).to_vec();
        let sig = Token::Bytes(the_sig);
        let encrypted_callable = symmetric::encrypt(b"transfer(bytes32,bytes32,uint256, bytes)", &shared_key).unwrap();
        let args = [addr, Token::FixedBytes(addr_to.to_vec()), Token::Uint(transfer_amount.into()), sig];
        let encrypted_args = symmetric::encrypt(&ethabi::encode(&args), &shared_key).unwrap();

        wasm::execute(
            &mut db,
            enclave.geteid(),
            &contract_code,
            &encrypted_callable,
            &encrypted_args,
            &keys.get_pubkey(),
            &address,
            GAS_LIMIT
        ).expect("Execution failed");

        let (keys, shared_key, _, _) = exchange_keys(enclave.geteid());
        let encrypted_callable = symmetric::encrypt(b"balance_of(bytes32)", &shared_key).unwrap();
        let encrypted_args = symmetric::encrypt(&ethabi::encode(&[Token::FixedBytes(addr_to.to_vec())]), &shared_key).unwrap();

        let result_balance = wasm::execute(
            &mut db,
            enclave.geteid(),
            &contract_code,
            &encrypted_callable,
            &encrypted_args,
            &keys.get_pubkey(),
            &address,
            GAS_LIMIT
        ).expect("Execution failed");

        let result_balance_decrypted = symmetric::decrypt(&result_balance.output, &shared_key).unwrap();

        let res: Token = ethabi::decode(&[ethabi::ParamType::Uint(256)], &result_balance_decrypted).unwrap().pop().unwrap();
        assert_eq!(res, Token::Uint(transfer_amount.into()));
    }

    #[test]
    fn test_allow_and_transfer_erc20() {
        let (mut db, _dir) = create_test_db();
        let address = generate_contract_address();
        let (owner, owner_keys) = generate_user_address();
        let (spender, spender_keys) = generate_user_address();
        let addr_to = generate_user_address().0;
        let transfer_amount: u64 = 12;

        let (enclave, contract_code, _, _) = compile_deploy_execute(
            &mut db,
            "../../examples/eng_wasm_contracts/erc20",
            address,
            "construct()",
            &[],
            "mint(bytes32,uint256)",
            &[Token::FixedBytes(owner.to_vec()), Token::Uint(40.into())]

        );
        let eid = enclave.geteid();
        let (keys, shared_key, _, _) = exchange_keys(eid);
        let the_sig = sign_message(owner_keys, spender, 20).to_vec();
        let sig = Token::Bytes(the_sig);
        let encrypted_callable = symmetric::encrypt(b"approve(bytes32,bytes32,uint256,bytes)", &shared_key).unwrap();
        let args = [Token::FixedBytes(owner.to_vec()), Token::FixedBytes(spender.to_vec()), Token::Uint(20.into()), sig];
        let encrypted_args = symmetric::encrypt(&ethabi::encode(&args), &shared_key).unwrap();
        wasm::execute(
            &mut db,
            eid,
            &contract_code,
            &encrypted_callable,
            &encrypted_args,
            &keys.get_pubkey(),
            &address,
            GAS_LIMIT
        ).expect("Execution failed");

        let (keys, shared_key, _, _) = exchange_keys(eid);
        let sig = sign_message(spender_keys, addr_to, transfer_amount).to_vec();
        let encrypted_callable = symmetric::encrypt(b"transfer_from(bytes32,bytes32,bytes32,uint256,bytes)", &shared_key).unwrap();
        let args = [Token::FixedBytes(owner.to_vec()), Token::FixedBytes(spender.to_vec()),
            Token::FixedBytes(addr_to.to_vec()), Token::Uint(transfer_amount.into()), Token::Bytes(sig)];
        let encrypted_args = symmetric::encrypt(&ethabi::encode(&args), &shared_key).unwrap();

        wasm::execute(
            &mut db,
            eid,
            &contract_code,
            &encrypted_callable,
            &encrypted_args,
            &keys.get_pubkey(),
            &address,
            GAS_LIMIT
        ).expect("Execution failed");

        let (keys, shared_key, _, _) = exchange_keys(eid);
        let encrypted_callable = symmetric::encrypt(b"balance_of(bytes32)", &shared_key).unwrap();
        let encrypted_args = symmetric::encrypt(&ethabi::encode(&[Token::FixedBytes(addr_to.to_vec())]), &shared_key).unwrap();
        let result_balance = wasm::execute(
            &mut db,
            eid,
            &contract_code,
            &encrypted_callable,
            &encrypted_args,
            &keys.get_pubkey(),
            &address,
            GAS_LIMIT
        ).expect("Execution failed");

        let result_balance_decrypted = symmetric::decrypt(&result_balance.output, &shared_key).unwrap();

        let (keys, shared_key, _, _) = exchange_keys(eid);
        let encrypted_callable = symmetric::encrypt(b"allowance(bytes32,bytes32)", &shared_key).unwrap();
        let args = [Token::FixedBytes(owner.to_vec()), Token::FixedBytes(spender.to_vec())];
        let encrypted_args = symmetric::encrypt(&ethabi::encode(&args), &shared_key).unwrap();
        let result_allowance = wasm::execute(
            &mut db,
            eid,
            &contract_code,
            &encrypted_callable,
            &encrypted_args,
            &keys.get_pubkey(),
            &address,
            GAS_LIMIT
        ).expect("Execution failed");

        let result_allowance_decrypted = symmetric::decrypt(&result_allowance.output, &shared_key).unwrap();
        let res_allowance: Token = ethabi::decode(&[ethabi::ParamType::Uint(256)], &result_allowance_decrypted).unwrap().pop().unwrap();
        let res_balance: Token = ethabi::decode(&[ethabi::ParamType::Uint(256)], &result_balance_decrypted).unwrap().pop().unwrap();

        assert_eq!(res_balance,  Token::Uint(transfer_amount.into()));
        assert_eq!(res_allowance, Token::Uint(8.into()));
    }

    #[test]
    fn test_eth_bridge(){
        let (mut db, _dir) = create_test_db();

        compile_deploy_execute(
            &mut db,
            "../../examples/eng_wasm_contracts/contract_with_eth_calls",
            generate_contract_address(),
            "construct()",
            &[],
            "test()",
            &[]
        );
    }
}
