#![no_std]
#![feature(slice_concat_ext)]
/// Enigma implementation of bindings to the Enigma runtime.
/// This crate should be used in contracts.
#[macro_use]
extern crate serde_json;
extern crate serde;
#[macro_use]
extern crate more_asserts;
#[macro_use]
mod internal_std;
mod eng_wasm_errors;
mod ethereum;
pub extern crate pwasm_abi;
#[macro_use] pub extern crate failure;
extern crate syn;
extern crate tiny_keccak;
extern crate ethabi;
extern crate byteorder;

pub use internal_std::*;
pub use eng_wasm_errors::*;
pub use serde_json::Value;
pub use ethereum::short_signature;
pub use pwasm_abi::types::*;
use byteorder::{BigEndian, ReadBytesExt};
use std::io::Cursor;

pub mod external {
    extern "C" {
        pub fn write_state (key: *const u8, key_len: u32, value: *const u8, value_len: u32);
        pub fn read_state (key: *const u8, key_len: u32) -> i32;
        pub fn from_memory(result: *const u8, result_len: i32);
        pub fn eprint(str_ptr: *const u8, str_len: u32);
        pub fn fetch_function_name_length() -> i32;
        pub fn fetch_function_name(name_holder: *const u8);
        pub fn fetch_args_length() -> i32;
        pub fn fetch_args(name_holder: *const u8);
        pub fn fetch_types_length() -> i32;
        pub fn fetch_types(name_holder: *const u8);
        pub fn write_payload(payload: *const u8, payload_len: u32);
        pub fn write_address(address: *const u8);
        pub fn gas(amount: u32);
        pub fn ret(payload: *const u8, payload_len: u32);
        pub fn rand(payload: *const u8, payload_len: u32);
    }
}

#[no_mangle]
pub fn print(msg: &str) -> i32 {
    unsafe { external::eprint(msg.as_ptr(), msg.len() as u32); }
    0
}

#[macro_export]
macro_rules! eprint {
    ( $($arg: tt)* ) => (
    $crate::print( &eformat!( $($arg)* ) )
    );
}

/// Write to state
pub fn write<T>(key: &str, _value: T) where T: serde::Serialize {
    let value = json!(_value);
    let value_vec = serde_json::to_vec(&value).unwrap();
    unsafe { external::write_state(key.as_ptr(), key.len() as u32, value_vec.as_ptr(), value_vec.len() as u32) }
}

/// Read from state
pub fn read<T>(key: &str) -> Option<T> where for<'de> T: serde::Deserialize<'de> {
    let val_len = unsafe { external::read_state(key.as_ptr(), key.len() as u32) };
    let value_holder: Vec<u8> = iter::repeat(0).take(val_len as usize).collect();
    unsafe { external::from_memory(value_holder.as_ptr(), val_len) };
    let value: Value = serde_json::from_slice(&value_holder).map_err(|_| print("failed unwrapping from_slice in read_state")).expect("read_state failed");
    if value.is_null() {
        return None;
    }
    Some(serde_json::from_value(value.clone()).map_err(|_| print("failed unwrapping from_value in read_state")).expect("read_state failed"))
}

pub fn write_ethereum_payload(payload: Vec<u8>){
    unsafe { external::write_payload(payload.as_ptr(), payload.len() as u32) };
}

pub fn write_ethereum_contract_addr(address: &[u8;20]){
    unsafe { external::write_address(address.as_ptr()) };
}

///// get a random vec of bytes in the specified length
//pub fn rand(len: Option<u32>) -> Result<Vec<u8>, WasmError> {
//    unsafe { external::rand(len.unwrap_or(16u32))}
//}

pub struct Rand;


impl Rand {
    pub fn gen_slice(slice: &mut [u8]) {
        unsafe { external::rand(slice.as_ptr(), slice.len() as u32)};
    }
}

pub trait RandTypes<T> {
    /// generate a random number on the trusted side.
    fn gen() -> T;
}

pub trait Shuffle {
    /// returns a random location in the array- used for shuffle.
    fn gen_loc(len: usize) -> usize;
    /// shuffles the elements in the given slice.
    fn shuffle<T>(values: &mut [T]);
}

impl RandTypes<U256> for Rand {
    fn gen() -> U256 {
        let mut r: [u8; 32] = [0u8; 32];
        Self::gen_slice(&mut r);
        U256::from_big_endian(&r)
    }
}

impl RandTypes<u8> for Rand {
    fn gen() -> u8 {
        let mut r: [u8; 1] = [0u8; 1];
        Self::gen_slice(&mut r);
        r[0]
    }
}

impl RandTypes<u16> for Rand {
    fn gen() -> u16 {
        let mut r: [u8; 2] = [0u8; 2];
        Self::gen_slice(&mut r);
        let mut res = Cursor::new(r);
        res.read_u16::<BigEndian>().unwrap()
    }
}

impl RandTypes<u32> for Rand {
    fn gen() -> u32 {
        let mut r: [u8; 4] = [0u8; 4];
        Self::gen_slice(&mut r);
        let mut res = Cursor::new(r);
        res.read_u32::<BigEndian>().unwrap()
    }
}

impl RandTypes<u64> for Rand {
    fn gen() -> u64 {
        let mut r: [u8; 8] = [0u8; 8];
        Self::gen_slice(&mut r);
        let mut res = Cursor::new(r);
        res.read_u64::<BigEndian>().unwrap()
    }
}

impl Shuffle for Rand {
    fn gen_loc(len: usize) -> usize {
        assert_gt!(len, 0);
        let rand: u32 = Self::gen();
        rand as usize % len
    }

    fn shuffle<T>(values: &mut [T]) {
        let mut i = values.len();
        while i >= 2 {
            values.swap(0, Self::gen_loc(i));
            i -= 1;
        }
    }
}

#[macro_export]
 macro_rules! write_state {
     ( $($key: expr => $val: expr),+ ) => {
         {
             $(
                 $crate::write($key, $val);
             )+
         }
     }
 }

#[macro_export]
 macro_rules! read_state {
     ( $key: expr ) => {
         {
             $crate::read($key)
         }
     }
 }

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn what() {
        print("TEST!");
    }
}

