#![no_std]

use eng_wasm_derive::pub_interface;

struct Contract;

#[pub_interface]
trait MyContract {
    /// constructor
    fn construct(_x: u32);

    /// secret contract method
    fn expand(input: u32) -> u64;
}

impl MyContract for Contract {
    fn construct(_x: u32) {}

    fn expand(input: u32) -> u64 {
        Self::expand_impl(input)
    }
}

impl Contract {
    /// private method, not exported from contract
    fn expand_impl(input: u32) -> u64 {
        input as u64
    }
}
