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
    fn add_to_balance(addr: Address, tokens: U256);
//    fn balance_of(Address) -> U256;
    fn transfer(from: Address, to: Address, tokens: U256);
//    fn transfer_from(Address, Address, U256);
//    fn approve(Address, U256);
}

pub struct Contract;
impl Erc20Interface for Contract {
    /// Writes value to state and reads it.
    /// As a temporary solution the value is converted to a stream of bytes.
    /// Later as part of runtime there will be created a macros for writing and reading any type.
    #[no_mangle]
    fn add_to_balance(addr: Address, tokens: U256) {
        write_state!(&addr.to_hex() => tokens.as_u64());
        let read_val: u64 = read_state!(&addr.to_hex()).unwrap();
        eprint!("read_val: {:?}, tokens: {:?}",read_val, tokens.as_u64());
        assert_eq!(read_val, tokens.as_u64());
    }

//    #[no_mangle]
//    fn balance_of(token_owner: Address) -> U256{}

    #[no_mangle]
    fn transfer(from: Address, to: Address, tokens: U256) {
        let from_str = from.to_hex();
        let to_str = to.to_hex();
        let sum_from: u64 = read_state!(&from_str).expect("User does not own tokens- invalid action");
        let amount_to: u64 = match read_state!(&to_str) {
            Some(amount) => amount,
            None => 0,
        };

        write_state!(&from_str => (sum_from - tokens.as_u64()), &to_str => (amount_to + tokens.as_u64()));
//         for test: check if the amount was updated
        let final_to_sum: u64 = read_state!(&to_str).unwrap();
    }
//
//    #[no_mangle]
//    fn approve(spender: Address, tokens: U256){}
}

#[no_mangle]
pub fn deploy() {}
