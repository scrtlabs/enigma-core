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
    fn check_address(addr: H256);
    fn check_addresses(addr1: H256, addr2: H256);
    fn choose_rand_color();
    fn get_scrambled_vec();
    fn addition(x: U256, y: U256) -> U256;
    fn get_last_sum() -> U256;
    fn print_test(x: U256, y: U256);
    fn construct(param: U256);
}

pub struct Contract;

impl Contract {
    fn gen_loc(len: usize) -> usize {
        assert!(len > 0);
        let rand: u32 = Rand::gen();
        rand as usize % len
    }
    /// gets an a slice containing any type. running
    /// on a loop in the length of (len(slice) - 1)
    /// it swaps the last element with a random
    /// location in the slice and reduces the length.
    fn shuffle<T>(values: &mut [T]) {
        let mut i = values.len();
        while i >= 2 {
            i -= 1;
            values.swap(i, Contract::gen_loc(i + 1));
        }
    }
}

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
    fn check_address(addr: H256) {

        write_state!("addr" => addr.to_hex());
        let read_val: String = read_state!("addr").unwrap();

        assert_eq!(read_val, addr.to_hex());
    }

    #[no_mangle]
    fn check_addresses(addr1: H256, addr2: H256) {
        write_state!("addr1" => addr1.to_hex());
        write_state!("addr2" => addr2.to_hex());

        let read_addr1: String = read_state!("addr1").unwrap();
        let read_addr2: String = read_state!("addr2").unwrap();

        assert_eq!(read_addr1, addr1.to_hex());
        assert_eq!(read_addr2, addr2.to_hex());
    }

    // tests the random service
    #[no_mangle]
    fn choose_rand_color() {
        let mut colors = Vec::new();
        colors.extend(["green", "yellow", "red", "blue", "white", "black", "orange", "purple"].iter().cloned());
        let random: u8 = Rand::gen();

        let rng_rand = (random as usize) % colors.len();
        write_state!("color" => colors[rng_rand]);
        let color : String = read_state!("color").unwrap();
    }

    // tests the shuffle service on a simple array
    #[no_mangle]
    fn get_scrambled_vec() {
        let mut nums: [u8; 10] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        Self::shuffle(&mut nums);
        unsafe {external::ret(nums.as_ptr(), nums.len() as u32)};
    }

    #[no_mangle]
    fn addition(x: U256, y: U256) -> U256 {
        let sum: u64 = x.as_u64() + y.as_u64();
        write_state!("curr_sum" => sum);
        sum.into()
    }

    #[no_mangle]
    fn get_last_sum() -> U256 {
        let sum: u64 = read_state!("curr_sum").unwrap();
        sum.into()
    }

    #[no_mangle]
    fn print_test(x: U256, y: U256) {
        eprint!("{:?} {:?}", x.as_u64(), y.as_u64());
        write_state!("x" => x.as_u64(), "y" => y.as_u64());
        let x: u64 = read_state!("x").unwrap();
        let y: u64 = read_state!("y").unwrap();
    }

    #[no_mangle]
    fn construct(param: U256){
        write_state!("1" => param.as_u64());
    }
}