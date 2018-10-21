#![no_std]
/// Enigma implementation of bindings to the Enigma runtime.
/// This crate should be used in contracts.
#[macro_use]
extern crate serde_json;
extern crate serde;

#[macro_use]
mod internal_std;
use internal_std::std_macro::*;

pub use internal_std::*;
pub use serde_json::Value;


mod external {
    extern "C" {
        pub fn write_state (key: *const u8, key_len: u32, value: *const u8, value_len: u32);
        pub fn read_state (key: *const u8, key_len: u32) -> i32;
        pub fn from_memory(result: *const u8, result_len: i32);
        pub fn eprint(str_ptr: *const u8, str_len: u32);
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
pub fn read<T>(key: &str) -> T where for<'de> T: serde::Deserialize<'de> {
    let mut val_len = 0;
    val_len = unsafe { external::read_state(key.as_ptr(), key.len() as u32) };
    let mut value_holder: Vec<u8> = iter::repeat(0).take(val_len as usize).collect();
    unsafe { external::from_memory(value_holder.as_ptr(), val_len) };
    let value: Value = serde_json::from_slice(&value_holder).map_err(|_| print("failed unwrapping from_slice")).unwrap();
    serde_json::from_value(value.clone()).map_err(|_| print("failed unwrapping from_value")).expect("failed")
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

