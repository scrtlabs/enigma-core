#![no_std]
#![crate_type = "lib"]
#![feature(core_intrinsics)]

extern crate enigma_types;

#[macro_use]
extern crate sgx_tstd as std;
#[macro_use]
extern crate failure;
extern crate rmp_serde as rmps;
extern crate json_patch;
extern crate sgx_types;
extern crate sgx_trts;
extern crate sgx_tse;
extern crate sgx_tseal;

extern crate ring;
extern crate tiny_keccak;
extern crate secp256k1;
extern crate wasmi;
extern crate hexutil;

pub mod cryptography_t;
pub mod common;
pub mod quote_t;
pub mod storage_t;


#[cfg(debug_assertions)]
#[no_mangle]
pub extern "C"
fn __assert_fail (__assertion: *const u8, __file: *const u8, __line: u32, __function: *const u8) -> ! {
    use core::intrinsics::abort;
    unsafe {abort()}
}


#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
