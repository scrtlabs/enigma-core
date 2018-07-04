use std::str::FromStr;
use bigint::{Gas, Address, U256, M256, H256};
use sputnikvm::{HeaderParams, Context, VM, VMStatus, AccountCommitment, RequireError, SeqContextVM};
use std::rc::Rc;
use std::boxed::Box;
use std::vec::Vec;
use sputnikvm_network_classic::MainnetFrontierPatch;
use std::ops::DerefMut;
use evm_t::EvmResult;
use common::utils_t::{ToHex, FromHex};


fn handle_fire_without_rpc(vm: &mut VM) {
    loop {
        match vm.fire() {
            Ok(()) => break,
            Err(RequireError::Account(address)) => {
                vm.commit_account(AccountCommitment::Nonexist(address)).unwrap();
            }
            Err(RequireError::AccountStorage(address, index)) => {
                vm.commit_account(AccountCommitment::Storage {
                    address: address,
                    index: index,
                    value: M256::zero(),
                }).unwrap();
            }
            Err(RequireError::AccountCode(address)) => {
                vm.commit_account(AccountCommitment::Nonexist(address)).unwrap();
            }
            Err(RequireError::Blockhash(number)) => {
                vm.commit_blockhash(number, H256::default()).unwrap();
            }
        }
    }
}


pub fn call_sputnikvm(code: &Vec<u8>, data: Vec<u8>) -> (u8, Vec<u8>){
    let caller = Address::from_str("0x0000000000000000000000000000000000000000").unwrap();
    let address = Address::from_str("0x0000000000000000000000000000000000000000").unwrap();
    let gas_limit = Gas::from_str("0x2540be400").unwrap();
    let value = U256::from_str("0x0").unwrap();
    let gas_price = Gas::from_str("0x0").unwrap();
    let block_number = "0x0";

    let block = HeaderParams {
        beneficiary: Address::default(),
        timestamp: 0,
        number: U256::from_str(block_number).unwrap(),
        difficulty: U256::zero(),
        gas_limit: Gas::zero(),
    };

    let mut vm: Box<VM> = {
        let context = Context {
            address,
            caller,
            gas_limit,
            gas_price,
            value,
            code: Rc::new(code.to_vec() ),
            data: Rc::new(data),
            origin: caller,
            apprent_value: value,
            is_system: false,
            is_static: false,
        };
        Box::new(SeqContextVM::<MainnetFrontierPatch>::new(context, block))
    };

    handle_fire_without_rpc(vm.deref_mut());
    //println!("VM returned: {:?}", vm.status());
    //println!("VM out: {:?}", vm.out().to_hex());
    for account in vm.accounts() {
        println!("{:?}", account);
    }
    let vm_status: u8 = match vm.status() {
        VMStatus::ExitedOk => EvmResult::SUCCESS as u8,
        _ => EvmResult::FAULT as u8,
    };
    (vm_status, vm.out().to_vec())
}
