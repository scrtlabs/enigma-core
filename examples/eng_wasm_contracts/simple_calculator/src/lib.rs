#![no_std]

extern crate eng_wasm;
extern crate eng_wasm_derive;

use eng_wasm::*;
use eng_wasm_derive::pub_interface;

#[pub_interface]
pub trait ContractInterface{
    fn add(a: U256, b: U256) -> U256;
    fn sub(a: U256, b: U256) -> U256;
    fn mul(a: U256, b: U256) -> U256;
    fn div(a: U256, b: U256) -> U256;
}

pub struct Contract;
impl ContractInterface for Contract {
    fn add(a: U256, b: U256) -> U256 {
        let res = a.checked_add(b);
        match res {
            Some(r) => r,
            None => panic!("addition overflow"),
        }
    }

    fn sub(a: U256, b: U256) -> U256 {
        let res = a.checked_sub(b);
        match res {
            Some(r) => r,
            None => panic!("subtraction overflow"),
        }
    }

    fn mul(a: U256, b: U256) -> U256 {
        let res = a.checked_mul(b);
        match res {
            Some(r) => r,
            None => panic!("multiple overflow"),
        }
    }

    fn div(a: U256, b: U256) -> U256 {
        let res = a.checked_div(b);
        match res {
            Some(r) => r,
            None => panic!("division by zero"),
        }
    }
}
