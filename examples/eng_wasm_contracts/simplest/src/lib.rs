#![no_std]
#![feature(proc_macro_gen)]
#![feature(proc_macro_non_items)]

extern crate eng_wasm;
extern crate eng_wasm_derive;

use eng_wasm::*;
use eng_wasm_derive::pub_interface;

use eng_wasm::String;

#[pub_interface]
pub trait ContractInterface{
    fn write();
    fn print_test(x: U256, y: U256) ;
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
        let read_val: String = read_state!(key);

        assert_eq!(read_val, a);
    }

    #[no_mangle]
    fn print_test(x: U256, y: U256) {
        eprint!("{:?} {:?}", x.as_u64(), y.as_u64());
        write_state!("x" => x.as_u64(), "y" => y.as_u64());
        let x: u64 = read_state!("x");
        let y: u64 = read_state!("y");
    }
}

#[no_mangle]
pub fn deploy() {}
