#![no_std]

mod types;

pub use crate::types::{EnclaveReturn, ResultToEnclaveReturn};

#[no_mangle]
pub extern fn dummy_function() -> EnclaveReturn {
    EnclaveReturn::Other
}




