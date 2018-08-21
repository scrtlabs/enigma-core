extern crate eng_wasm;

#[no_mangle]
pub fn call() -> i32{
    eng_wasm::external_function()
}

#[no_mangle]
pub fn deploy() {}
