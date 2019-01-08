#![no_std]
#![crate_type = "lib"]
#![feature(core_intrinsics)]

extern crate enigma_types;

#[macro_use]
extern crate sgx_tstd as std;
#[macro_use]
extern crate failure;
extern crate json_patch;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;
extern crate serde;
extern crate rmp_serde;
extern crate sgx_trts;
extern crate sgx_tse;
extern crate sgx_tseal;
extern crate sgx_types;
extern crate parity_wasm;
extern crate pwasm_utils;

extern crate hexutil;
extern crate ring;
extern crate secp256k1;
extern crate tiny_keccak;
extern crate wasmi;
extern crate bigint;
extern crate rlp;
extern crate byteorder;
pub mod common;
pub mod cryptography_t;
pub mod km_primitives;
pub mod quote_t;
pub mod storage_t;
pub mod build_arguments_g;

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
