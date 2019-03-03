#![no_std]
#![crate_type = "lib"]
#![feature(core_intrinsics)]
#![warn(unused_extern_crates)]

extern crate enigma_types;
extern crate enigma_crypto;

#[macro_use]
extern crate sgx_tstd as std;
#[macro_use]
extern crate failure;
extern crate json_patch;
extern crate parity_wasm;
extern crate pwasm_utils;
extern crate rmp_serde;
#[macro_use]
extern crate serde;
extern crate serde_json;
extern crate sgx_trts;
extern crate sgx_tse;
extern crate sgx_tseal;
extern crate sgx_types;

extern crate bigint;
extern crate hexutil;
extern crate rlp;
extern crate wasmi;

#[macro_use]
pub mod macros;

pub mod build_arguments_g;
pub mod common;
pub mod km_primitives;
pub mod quote_t;
pub mod storage_t;

#[cfg(debug_assertions)]
#[no_mangle]
pub extern "C" fn __assert_fail(__assertion: *const u8, __file: *const u8, __line: u32, __function: *const u8) -> ! {
    use core::intrinsics::abort;
    unsafe { abort() }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
