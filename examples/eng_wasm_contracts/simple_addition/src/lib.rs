// Rust’s standard library provides a lot of useful functionality, but assumes support for various 
// features of its host system: threads, networking, heap allocation, and others. SGX environments
// do not have these features, so we tell Rust that we don’t want to use the standard library
#![no_std]
#![allow(unused_attributes)] // TODO: Remove on future nightly https://github.com/rust-lang/rust/issues/60050




// The eng_wasm crate allows to use the Enigma runtime, which provides:
//     - Read from state      read_state!(key)        
//     - Write to state       write_state!(key => value)
//     - Print                eprint!(...)
extern crate eng_wasm;

// The eng_wasm_derive crate provides the following
//     - Functions exposed by the contract that may be called from the Enigma network
//     - Ability to call functions of ethereum contracts from ESC
extern crate eng_wasm_derive;

use eng_wasm::*;

// For contract-exposed functions first include:
use eng_wasm_derive::pub_interface;

use eng_wasm::String;

// For contract-exposed functions, declare such functions under the following public trait:
#[pub_interface]
pub trait ContractInterface{
    fn addition(U256, U256) -> U256 ;
}

// The implementation of the exported ESC functions should be defined in the trait implementation 
// for a new struct. 
// #[no_mangle] modifier is required before each function to turn off Rust's name mangling, so that
// it is easier to link to. Sets the symbol for this item to its identifier.
pub struct Contract;
impl ContractInterface for Contract {
    #[no_mangle]
    fn addition(x: U256, y: U256) -> U256 {
        write_state!("code"=> (x+y).as_u32());
        x + y
    }
}
