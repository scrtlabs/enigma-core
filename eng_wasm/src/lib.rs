#![no_std]
/// Enigma implementation of bindings to the Enigma runtime.
/// This crate should be used in contracts.
#[macro_use]
extern crate serde_json;
#[macro_use]
mod internal_std;
pub use internal_std::*;
use internal_std::std_macro::*;
pub use serde_json::Value;

use serde_json::{from_value, to_value};

mod external {
    extern "C" {
        pub fn write_state (key: *const u8, key_len: u32, value: *const u8, value_len: u32);
        pub fn read_state (key: *const u8, key_len: u32) -> i32;
        pub fn from_memory(result: *const u8, result_len: i32);
        pub fn eprint(str_ptr: *const u8, str_len: u32);
    }
}

#[no_mangle]
/// Write to state
pub fn write(key: &str, value: &[u8]) {
    unsafe { external::write_state(key.as_ptr(), key.len() as u32, value.as_ptr(), value.len() as u32) }
}

#[no_mangle]
/// Read from state
pub fn read(key: &str) -> Vec<u8> {
    let mut val_len = 0;
    unsafe {
        val_len = external::read_state(key.as_ptr(), key.len() as u32);
    }
    let mut value_holder: Vec<u8> = Vec::with_capacity(val_len as usize);
    unsafe {
        external::from_memory(value_holder.as_ptr(), val_len);
    }
    value_holder
}

#[no_mangle]
pub fn print(msg: &str) -> i32 {
    unsafe { external::eprint(msg.as_ptr(), msg.len() as u32); }
    0
}

#[macro_export]
macro_rules! eprint {
    ( $($arg: tt)* ) => (
    $crate::print(&eformat!($($arg)*))
    );
}



// // TODO: All these macros should be in eng_wasm
// macro_rules! write_state {
//     ( $($key: expr => $val: expr),+ ) => {
//         {
//             $(
//             // TODO: How are we handling errors in wasm?

//                 con.write_key($key, &json!($val)).unwrap();
//             )+
//         }
//     }
// }

// macro_rules! read_state {
//     ( $key: expr ) => {
//         {
//             read($key)
//         }
//     }
// }
