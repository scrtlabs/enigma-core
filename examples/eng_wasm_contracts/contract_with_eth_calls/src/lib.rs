#![no_std]

extern crate eng_wasm;
extern crate eng_wasm_derive;
extern crate rustc_hex;


use eng_wasm::*;
use eng_wasm_derive::pub_interface;
use eng_wasm_derive::eth_contract;

use eng_wasm::String;
use rustc_hex::ToHex;


#[eth_contract("Test.json")]
struct EthContract;

#[pub_interface]
pub trait ContractInterface{
    fn write();
    fn print_test(x: U256, y: U256);
    fn test();
    fn construct();
    fn sum_and_call(x: U256, y: U256, eth_addr: H160) -> U256;
    fn get_last_sum() -> U256;
}

pub struct Contract;

impl ContractInterface for Contract {
    /// Writes value to state and reads it.
    /// As a temporary solution the value is converted to a stream of bytes.
    /// Later as part of runtime there will be created a macros for writing and reading any type.
    fn write() {
        let mut a = String::new();
        a.push_str("157");
        let key = "code";
        eprint!("{}", a);
        write_state!(key => &a);
        let read_val: String = read_state!(key).unwrap();

        assert_eq!(read_val, a);
    }

    fn print_test(x: U256, y: U256) {
        eprint!("{:?} {:?}", x.as_u64(), y.as_u64());
    }

    fn test() {
        let c = EthContract::new("0x123f681646d4a755815f9cb19e1acc8565a0c2ac");
        c.getBryn(U256::from(1), Vec::new());
    }

    fn construct(){
        let mut a = String::new();
        a.push_str("69");
        let key = "code";
        eprint!("{}", a);
        write_state!(key => &a);
        let sum: u64 = 12;
        write_state!("sum" => sum);
    }

    fn sum_and_call(x: U256, y: U256, eth_addr: H160) -> U256 {
        let sum: u64 = x.as_u64() + y.as_u64();
        write_state!("code" => sum);
        let mut eth_addr_str_0x: String = "0x".to_string();
        let eth_addr_str: String = eth_addr.to_hex();
        eth_addr_str_0x.push_str(&eth_addr_str);
        let c = EthContract::new(&eth_addr_str_0x);
        c.record(sum.into());
        sum.into()
    }

    fn get_last_sum() -> U256 {
        let sum: u64 = read_state!("sum").unwrap_or_default();
        sum.into()
    }
}
