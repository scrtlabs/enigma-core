extern crate eng_wasm;

pub struct Error;

#[no_mangle]
pub fn call() {
    let key = "code";
    let value = "157";
    eng_wasm::write(key, value.as_bytes());
    let value1 = eng_wasm::read(key);
}

#[no_mangle]
pub fn deploy() {}

#[no_mangle]
pub fn problem() ->Result<i32, Error>{
    Err(Error)
}
