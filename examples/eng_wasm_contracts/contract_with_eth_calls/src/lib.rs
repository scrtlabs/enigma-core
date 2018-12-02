#![no_std]
#![feature(proc_macro_gen)]
#![feature(proc_macro_non_items)]

extern crate proc_macro2;
extern crate eng_wasm;
extern crate eng_wasm_dispatch;
extern crate syn;

use eng_wasm::*;
use eng_wasm_dispatch::dispatch;
use eng_wasm_dispatch::eth_contract;

use eng_wasm::String;

#[eth_contract("Test.json")]
struct EthContract;

#[dispatch]
pub trait ContractInterface{
    fn write();
    fn print_test(U256,U256);
    fn test();
}

pub struct Contract;
use pwasm_abi::types::*;
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
        let read_val: String = read_state!(key);

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
}

#[no_mangle]
pub fn deploy() {
    let mut a = String::new();
    a.push_str("69");
    let key = "code";
    eprint!("{}", a);
    write_state!(key => &a);
}
