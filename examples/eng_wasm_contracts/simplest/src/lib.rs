/// Very simple Rust contract.

extern crate eng_wasm;

#[no_mangle]
/// Writes value to state and reads it.
/// As a temporary solution the value is converted to a stream of bytes.
/// Later as part of runtime there will be created a macros for writing and reading any type.
pub fn call() {
    let key = "code";
    let value = "157";
    eng_wasm::write(key, value.as_bytes());
    let value1 = eng_wasm::read(key);
}

#[no_mangle]
pub fn deploy() {}
