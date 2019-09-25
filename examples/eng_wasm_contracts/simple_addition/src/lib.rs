// Rust’s standard library provides a lot of useful functionality,
// but WebAssembly does not support all of it.
// eng_wasm exposes a subset of std.
#![no_std]

// The eng_wasm crate allows to use the Enigma runtime, which provides:
// manipulating state, creation of random, printing and more
extern crate eng_wasm;

// The eng_wasm_derive crate provides the following
//     - Functions exposed by the contract that may be called from the Enigma network
//     - Ability to call functions of ethereum contracts from ESC
extern crate eng_wasm_derive;

use eng_wasm::*;

// For contract-exposed functions first include:
use eng_wasm_derive::pub_interface;

// For contract-exposed functions, declare such functions under the following public trait:
#[pub_interface]
pub trait ContractInterface{
    fn addition(x: U256, y: U256) -> U256 ;
}

// The implementation of the exported ESC functions should be defined in the trait implementation 
// for a new struct. 
pub struct Contract;
impl ContractInterface for Contract {
    fn addition(x: U256, y: U256) -> U256 {
        write_state!("code"=> (x+y).as_u32());
        x + y
    }
}
