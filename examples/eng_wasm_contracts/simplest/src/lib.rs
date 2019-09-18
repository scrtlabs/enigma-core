#![no_std]

extern crate eng_wasm;
extern crate eng_wasm_derive;

use eng_wasm::*;
use eng_wasm_derive::pub_interface;

#[pub_interface]
pub trait ContractInterface{
    fn write() -> Vec<u8>;
    fn check_address(addr: H256) -> H256;
    fn check_addresses(addr1: H256, addr2: H256) -> Vec<H256>;
    fn choose_rand_color() -> Vec<u8>;
    fn get_scrambled_vec();
    fn addition(x: U256, y: U256) -> U256;
    fn get_last_sum() -> U256;
    fn print_test(x: U256, y: U256);
    fn dynamic_types(bytes_arr: Vec<Vec<u8>>, string_arr: Vec<String>, fixed_arr: Vec<H256>);
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
    fn write() -> Vec<u8> {
        let mut a = String::new();
        a.push_str("157");
        let key = "code";
        write_state!(key => &a);
        let read_val: String = read_state!(key).unwrap_or_default();

        assert_eq!(read_val, a);
        read_val.as_bytes().to_vec()
    }

    fn check_address(addr: H256) -> H256{
        write_state!("addr" => addr);
        let read_val: H256 = read_state!("addr").unwrap_or_default();
        assert_eq!(read_val, addr);
        read_val
    }
    fn dynamic_types(bytes_arr: Vec<Vec<u8>>, string_arr: Vec<String>, fixed_arr: Vec<H256>) {
        eprint!("array of bytes: {:?}",bytes_arr);
        eprint!("array of String: {:?}",string_arr);
        eprint!("array of H256: {:?}",fixed_arr);
    }

    fn check_addresses(addr1: H256, addr2: H256) -> Vec<H256> {
        write_state!("addr1" => addr1);
        write_state!("addr2" => addr2);

        let read_addr1: H256 = read_state!("addr1").unwrap_or_default();
        let read_addr2: H256 = read_state!("addr2").unwrap_or_default();

        assert_eq!(read_addr1, addr1);
        assert_eq!(read_addr2, addr2);
        let mut ret = Vec::with_capacity(2);
        ret.push(read_addr1);
        ret.push(read_addr2);
        ret
    }

    // tests the random service
    fn choose_rand_color() -> Vec<u8> {
        let mut colors = Vec::new();
        colors.extend(["green", "yellow", "red", "blue", "white", "black", "orange", "purple"].iter().cloned());
        let random: u8 = Rand::gen();

        let rng_rand = (random as usize) % colors.len();
        write_state!("color" => colors[rng_rand]);
        let color : String = read_state!("color").unwrap_or_default();
        color.as_bytes().to_vec()
    }

    // tests the shuffle service on a simple array
    fn get_scrambled_vec() {
        let mut nums: [u8; 10] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        Self::shuffle(&mut nums);
        unsafe {external::ret(nums.as_ptr(), nums.len() as u32)};
    }

    fn addition(x: U256, y: U256) -> U256 {
        let sum: u64 = x.as_u64() + y.as_u64();
        write_state!("curr_sum" => sum);
        sum.into()
    }

    fn get_last_sum() -> U256 {
        let sum: u64 = read_state!("curr_sum").unwrap_or_default();
        sum.into()
    }

    fn print_test(x: U256, y: U256) {
        eprint!("{:?} {:?}", x.as_u64(), y.as_u64());
    }

    fn construct(param: U256){
        write_state!("1" => param.as_u64());
    }
}