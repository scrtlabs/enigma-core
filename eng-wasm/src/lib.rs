#![no_std]
#![feature(slice_concat_ext)]
#![deny(unused_extern_crates)]
#![allow(unused_attributes)] // TODO: Remove on future nightly https://github.com/rust-lang/rust/issues/60050


/// Enigma implementation of bindings to the Enigma runtime.
/// This crate should be used in contracts.
#[macro_use]
extern crate serde_json;
extern crate serde;
#[macro_use]
mod internal_std;
mod rand_wasm;
pub mod crypto_wasm;
pub extern crate eng_pwasm_abi;

pub use internal_std::*;
pub use rand_wasm::*;
pub use crypto_wasm::*;
pub use serde_json::Value;
pub use eng_pwasm_abi::types::*;


pub mod external {
    extern "C" {
        pub fn write_state (key: *const u8, key_len: u32, value: *const u8, value_len: u32);
        pub fn read_state_len (key: *const u8, key_len: u32) -> i32;
        pub fn read_state (key: *const u8, key_len: u32, value_holder: *const u8);
        pub fn remove_from_state (key: *const u8, key_len: u32);
        pub fn eprint(str_ptr: *const u8, str_len: u32);
        pub fn fetch_function_name_length() -> i32;
        pub fn fetch_function_name(name_holder: *const u8);
        pub fn fetch_args_length() -> i32;
        pub fn fetch_args(name_holder: *const u8);
        pub fn fetch_types_length() -> i32;
        pub fn fetch_types(name_holder: *const u8);
        pub fn write_eth_bridge(payload: *const u8, payload_len: u32, address: *const u8);
        pub fn gas(amount: u32);
        pub fn ret(payload: *const u8, payload_len: u32);
        pub fn rand(payload: *const u8, payload_len: u32);
        pub fn encrypt_with_nonce(message: *const u8, message_len: u32, key: *const u8, iv: *const u8, payload: *const u8);
        pub fn decrypt(cipheriv: *const u8, cipheriv_len: u32, key: *const u8, payload: *const u8);
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
    let val_len = unsafe { external::read_state_len(key.as_ptr(), key.len() as u32) };
    let value_holder: Vec<u8> = iter::repeat(0).take(val_len as usize).collect();
    unsafe { external::read_state(key.as_ptr(), key.len() as u32, value_holder.as_ptr()) };
    let value: Value = serde_json::from_slice(&value_holder).map_err(|_| print("failed unwrapping from_slice in read_state")).expect("read_state failed");
    if value.is_null() {
        return None;
    }
    Some(serde_json::from_value(value.clone()).map_err(|_| print("failed unwrapping from_value in read_state")).expect("read_state failed"))
}


/// Remove key and value from state
pub fn remove<T>(key: &str) -> Option<T> where for<'de> T: serde::Deserialize<'de> {
    let value = read(key);
    unsafe { external::remove_from_state(key.as_ptr(), key.len() as u32) }
    value
}


pub fn write_ethereum_bridge(payload: &[u8], address: &Address){
    unsafe {
        external::write_eth_bridge(payload.as_ptr(), payload.len() as u32, address.as_ptr())
    };
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

#[macro_export]
macro_rules! remove_from_state {
     ( $key: expr ) => {
         {
             $crate::remove($key)
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

    #[test]
    fn test_encrypt_with_nonce() {
        let enclave = init_enclave_wrapper().unwrap();
        let workers: Vec<[u8; 20]> = vec![
            [156, 26, 193, 252, 165, 167, 191, 244, 251, 126, 53, 154, 158, 14, 64, 194, 164, 48, 231, 179],
        ];
        let stakes: Vec<u64> = vec![90000000000];
        let block_number = 1;
        let worker_params = get_worker_params(block_number, workers, stakes);
        let epoch_state = set_or_verify_worker_params(enclave.geteid(), &worker_params, None).unwrap();
        assert!(epoch_state.confirmed_state.is_none());
        enclave.destroy();
    }
}

