#![no_std]
#![feature(proc_macro_gen)]
#![feature(proc_macro_non_items)]

extern crate eng_wasm;
extern crate eng_wasm_derive;
extern crate rustc_hex as hex;

use eng_wasm::*;
use eng_wasm_derive::pub_interface;

use eng_wasm::String;
use hex::ToHex;

#[pub_interface]
pub trait ContractInterface{
    fn write();
    fn get_address(addr: Address);
    fn get_addresses(from: Address, to: Address);
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
        write_state!(key => &a);
        let read_val: String = read_state!(key).unwrap();

        assert_eq!(read_val, a);
    }

    #[no_mangle]
    fn get_address(addr: Address) {

        write_state!("addr" => addr.to_hex());
        let read_val: String = read_state!("addr").unwrap();

        assert_eq!(read_val, addr.to_hex());
    }

    #[no_mangle]
    fn get_addresses(from: Address, to: Address) {
        write_state!("from" => from.to_hex());
        write_state!("to" => to.to_hex());

        let read_from: String = read_state!("from").unwrap();
        let read_to: String = read_state!("to").unwrap();

        assert_eq!(read_from, from.to_hex());
        assert_eq!(read_to, to.to_hex());
    }

    #[no_mangle]
    fn print_test(x: U256, y: U256) {
        eprint!("{:?} {:?}", x.as_u64(), y.as_u64());
        write_state!("x" => x.as_u64(), "y" => y.as_u64());
        let x: u64 = read_state!("x").unwrap();
        let y: u64 = read_state!("y").unwrap();
    }
}

#[no_mangle]
pub fn deploy() {}
