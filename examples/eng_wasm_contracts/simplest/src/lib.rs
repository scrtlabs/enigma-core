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
    a.push_str("157");
    let key = "code";
    eprint!("{}", a);
    write_state!(key => &a);
    let read_val: String = read_state!(key);

    assert_eq!(read_val, a);

}

#[no_mangle]
pub fn deploy() {}
