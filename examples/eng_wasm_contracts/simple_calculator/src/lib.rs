#![no_std]

#![feature(proc_macro_gen)]
#![feature(proc_macro_non_items)]

extern crate eng_wasm;
extern crate eng_wasm_derive;

use eng_wasm::*;
use eng_wasm_derive::pub_interface;

#[pub_interface]
pub trait ContractInterface{
    fn add(a: U256, b: U256) -> U256;
    fn sub(a: U256, b: U256) -> U256;
    fn mul(a: U256, b: U256) -> U256;
    // no floats
    fn div(a: U256, b: U256) -> U256;
    fn construct();

}

pub struct Contract;
impl ContractInterface for Contract {
    #[no_mangle]
    fn add(a: U256, b: U256) -> U256 {
        a + b
    }

    #[no_mangle]
    fn sub(a: U256, b: U256) -> U256 {
        if a < b {
            return U256::zero()
        }
        a - b
    }

    #[no_mangle]
    fn mul(a: U256, b: U256) -> U256 {
        a * b
    }

    #[no_mangle]
    fn div(a: U256, b: U256) -> U256 {
        if b.is_zero() {
            return U256::zero()
        }
        a / b
    }

    #[no_mangle]
    fn construct() {}
}
