#![no_std]

use eng_wasm_derive::pub_interface;

struct MyContract;

#[pub_interface]
impl MyContract {
    /// constructor
    pub fn construct(_x: u32) {}

    /// secret contract method
    pub fn expand(input: u32) -> u64 {
        Self::expand_impl(input)
    }

    /// private method, not exported from contract
    fn expand_impl(input: u32) -> u64 {
        input as u64
    }
}
