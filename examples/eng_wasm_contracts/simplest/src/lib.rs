#![no_std]
/// Very simple Rust contract.

#[macro_use]
extern crate eng_wasm;
use eng_wasm::String;

/// Writes value to state and reads it.
/// As a temporary solution the value is converted to a stream of bytes.
/// Later as part of runtime there will be created a macros for writing and reading any type.
#[no_mangle]
pub fn call() {
    let mut a  = String::new();
    a.push_str("Hey");
    let key = "code";

    eng_wasm::write(key, "157".as_bytes());
    let read_val = eng_wasm::read(key);
//    eng_wasm::print(&a);
    eprint!("Hey!");
    eprint!("{}", a);
//    let read_val = eng_wasm::read(key);
//    let value_after = from_utf8(&read_val).unwrap();
//
//    eng_wasm::write(key, value_after.as_bytes());
//    let read_val = eng_wasm::read(key);
//    assert_eq!(value, value_after);

}

#[no_mangle]
pub fn deploy() {}
