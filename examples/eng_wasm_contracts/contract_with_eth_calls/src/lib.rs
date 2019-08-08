#![no_std]
#![allow(unused_attributes)] // TODO: Remove on future nightly https://github.com/rust-lang/rust/issues/60050


extern crate eng_wasm;
extern crate eng_wasm_derive;

use eng_wasm::*;
use eng_wasm_derive::pub_interface;
use eng_wasm_derive::eth_contract;

use eng_wasm::String;

#[eth_contract("Test.json")]
struct EthContract;

#[pub_interface]
pub trait ContractInterface{
    fn write();
    fn print_test(x: U256, y: U256);
    fn test();
    fn construct();
}

pub struct Contract;

impl ContractInterface for Contract {
    /// Writes value to state and reads it.
    /// As a temporary solution the value is converted to a stream of bytes.
    /// Later as part of runtime there will be created a macros for writing and reading any type.
    #[no_mangle]
    fn write() {
        let mut a = String::new();
        a.push_str("157");
        let key = "code";
        eprint!("{}", a);
        write_state!(key => &a);
        let read_val: String = read_state!(key).unwrap();

        assert_eq!(read_val, a);
    }

    #[no_mangle]
    fn print_test(x: U256, y: U256) {
        eprint!("{:?} {:?}", x.as_u64(), y.as_u64());
    }

    #[no_mangle]
    fn test() {
        let c = EthContract::new("0x123f681646d4a755815f9cb19e1acc8565a0c2ac");
        c.getBryn(U256::from(1), Vec::new());
    }

    #[no_mangle]
    fn construct(){
        let mut a = String::new();
        a.push_str("69");
        let key = "code";
        eprint!("{}", a);
        write_state!(key => &a);
    }
}
