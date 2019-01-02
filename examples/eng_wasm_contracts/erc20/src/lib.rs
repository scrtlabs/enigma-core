#![no_std]
#![feature(proc_macro_gen)]
#![feature(proc_macro_non_items)]


extern crate eng_wasm;
extern crate eng_wasm_derive;
extern crate rustc_hex as hex;

use eng_wasm::*;
use eng_wasm_derive::pub_interface;
use eng_wasm::String;
use eng_wasm::from_utf8;
use hex::ToHex;

#[pub_interface]
pub trait Erc20Interface{
    // Vec<u8> is a temporary substitution for Address
    fn addition(addr: Vec<u8>, tokens: U256);
//    fn balance_of(Address) -> U256;
    fn transfer(from: Vec<u8>, to: Vec<u8>, tokens: U256);
//    fn transfer_from(Address, Address, U256);
//    fn approve(Address, U256);
}

pub struct Contract;
impl Erc20Interface for Contract {
    /// Writes value to state and reads it.
    /// As a temporary solution the value is converted to a stream of bytes.
    /// Later as part of runtime there will be created a macros for writing and reading any type.
    #[no_mangle]
    fn addition(addr: Vec<u8>, tokens: U256) {
        let address = from_utf8(&addr).unwrap();
        write_state!(&address => tokens.as_u64());
        let read_val: u64 = read_state!(&address);
        eprint!("read_val: {:?}, tokens: {:?}",read_val, tokens.as_u64());
        assert_eq!(read_val, tokens.as_u64());
    }

//    #[no_mangle]
//    fn balance_of(token_owner: Address) -> U256{}

    #[no_mangle]
    fn transfer(from: Vec<u8>, to: Vec<u8>, tokens: U256) {
        let from_str = from_utf8(&from).unwrap();
        let to_str = from_utf8(&to).unwrap();

        let sum_from: u64 = read_state!(&from_str);
        let sum_to: u64 = read_state!(&to_str);

        write_state!(&from_str => (sum_from - tokens.as_u64()), &to_str => (sum_to + tokens.as_u64()))

    }
//
//    #[no_mangle]
//    fn transfer_from(from: Address, to: Address, tokens: U256){}
//
//    #[no_mangle]
//    fn approve(spender: Address, tokens: U256){}
}

#[no_mangle]
pub fn deploy() {}
