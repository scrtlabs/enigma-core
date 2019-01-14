#![no_std]
#![feature(slice_concat_ext)]
/// Enigma implementation of bindings to the Enigma runtime.
/// This crate should be used in contracts.
#[macro_use]
extern crate serde_json;
extern crate serde;
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

